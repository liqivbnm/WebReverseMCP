package com.webreverse.mcp.javascript.analysis

/**
 * WASM 深度分析器 v1（ 新增）。
 *
 * 在 WasmParser（结构解析）与 WabtEngine（离屏 wabt 全量反汇编）之间补一个
 * 纯 Kotlin 的「轻量指令级」层——不依赖 wabt 也能做逆向定位：
 * 1. **调用图（CallGraph）**：从 code section 提取 call / call_indirect 指令，
 *    构建 func -> callees 图；间接调用统计 table 引用热度。
 * 2. **字符串提取（Strings）**：data 段 + 自定义段的 UTF-8 可打印字符串
 *    （长度 >= 4），WASM 内嵌的错误信息/密钥名/调试符号直接可见。
 * 3. **导出函数画像**：每个 export 的签名 + 字节数 + 指令数 + 加密评分 +
 *    内部调用数——一屏挑出「最值得反汇编」的目标。
 */
class WasmAnalyzer {

    data class WasmCallGraph(
        val ok: Boolean,
        val error: String = "",
        val totalFuncs: Int = 0,
        val edges: Int = 0,
        val adjacency: Map<Int, List<Int>>,        // callerIdx -> calleeIdx 列表
        val indirectCalls: Map<Int, Int>,          // callerIdx -> call_indirect 次数
        val hotCallees: List<CalleeStat>,          // 被调用最多的函数
        val exportedReachability: Map<String, Int>, // export -> 可达函数数
    )

    data class CalleeStat(val index: Int, val name: String?, val callers: Int, val isExported: Boolean)

    data class WasmStrings(
        val ok: Boolean,
        val count: Int,
        val strings: List<WasmString>,
    )

    data class WasmString(val offset: Int, val section: String, val value: String, val kind: String)

    data class ExportProfile(
        val name: String,
        val funcIndex: Int,
        val params: String,
        val results: String,
        val bodyBytes: Int,
        val instructionCount: Int,
        val cryptoScore: Int,
        val internalCalls: Int,
        val indirectCalls: Int,
        val realName: String?,   // name section 符号
    )

    private val parser = WasmParser()

    // ---------------- 0. 导入边界（静态分析） ----------------
    // 对每个导出函数（以及每个本地函数），沿调用图传递求其「可到达的宿主 imports」，
    // 揭示该 export 在运行时依赖的 DOM / env / wbg 外部世界——逆向 Node 补环境的直接依据。

    data class WasmImportRef(
        val index: Int,          // import 函数索引（0..importedFuncCount-1）
        val module: String,
        val name: String,
        val kind: String,
        val signature: String = "",
    )

    data class ExportBoundary(
        val export: String,
        val funcIndex: Int,
        val reachedImports: List<Int>,
        val importCount: Int,    // 传递可达的 import 函数数（去重）
    )

    data class ImportBoundary(
        val ok: Boolean,
        val error: String = "",
        val imports: List<WasmImportRef> = emptyList(),
        val exportBoundary: List<ExportBoundary> = emptyList(),
        val functionImportMap: Map<Int, List<Int>> = emptyMap(),
        val wbgSemantics: Map<Int, String> = emptyMap(),
    )

    fun importReachability(bytes: ByteArray): ImportBoundary {
        val parsed = parser.parse(bytes)
        if (!parsed.ok) return ImportBoundary(false, parsed.error)
        val importedFuncsList = parsed.imports.filter { it.kind == "func" }
        val importedFuncCount = importedFuncsList.size
        val scan = ScanCallTargets(bytes, importedFuncCount)

        fun reachedImports(start: Int, cap: Int = 20_000): Set<Int> {
            val seen = HashSet<Int>()
            val queue = ArrayDeque<Int>()
            queue.add(start)
            while (queue.isNotEmpty() && seen.size < cap) {
                val cur = queue.removeFirst()
                if (!seen.add(cur)) continue
                scan.adjacency[cur]?.forEach { c ->
                    if (!seen.contains(c)) {
                        if (c < importedFuncCount) seen.add(c) // import 叶节点
                        else queue.add(c)
                    }
                }
            }
            return seen
        }

        val importRefs = importedFuncsList.mapIndexed { i, im ->
            val sig = if (im.typeIndex >= 0) {
                parsed.types.getOrNull(im.typeIndex)?.let {
                    "${it.params.joinToString(",")} -> ${it.results.joinToString(",")}"
                } ?: ""
            } else ""
            WasmImportRef(i, im.module, im.name, im.kind, sig)
        }

        val wbgSem = HashMap<Int, String>()
        importedFuncsList.forEachIndexed { i, im -> wbgSem[i] = wbgSemantic(im.name) }

        val exports = parsed.exports.filter { it.kind == "func" }
        val exportBoundary = exports.map { e ->
            val r = reachedImports(e.index)
            ExportBoundary(e.name, e.index, r.sorted(), r.size)
        }.sortedWith(compareBy<ExportBoundary> { it.importCount }.thenBy { it.export })

        val funcImportMap = HashMap<Int, List<Int>>()
        for (i in importedFuncCount until (importedFuncCount + parsed.codeCount)) {
            funcImportMap[i] = reachedImports(i).sorted()
        }
        return ImportBoundary(
            ok = true,
            imports = importRefs,
            exportBoundary = exportBoundary,
            functionImportMap = funcImportMap,
            wbgSemantics = wbgSem,
        )
    }

    /** wasm-bindgen wbg 导入的 DOM/env 语义标注 */
    private fun wbgSemantic(name: String): String {
        if (!name.startsWith("__wbg_")) return ""
        return when {
            name.contains("document") -> "[DOM] document"
            name.contains("navigator") -> "[DOM] navigator"
            name.contains("window") -> "[DOM] window"
            name.contains("location") -> "[DOM] location"
            name.contains("history") -> "[DOM] history"
            name.contains("fetch") -> "[NET] fetch"
            name.contains("crypto") -> "[CRYPTO] crypto.subtle"
            name.contains("performance") -> "[PERF] performance"
            name.contains("storage") || name.contains("localStorage") -> "[STORAGE] localStorage"
            name.contains("canvas") -> "[DOM] canvas"
            name.contains("querySelector") || name.contains("get_element") -> "[DOM] querySelector"
            name.contains("get_attribute") || name.contains("getAttribute") -> "[DOM] getAttribute"
            name.contains("set_attribute") || name.contains("setAttribute") -> "[DOM] setAttribute"
            name.contains("math") -> "[JS] Math"
            name.contains("array") -> "[JS] Array"
            name.contains("string") -> "[JS] String"
            name.contains("object") -> "[JS] Object"
            name.contains("function") || name.contains("closure") -> "[JS] Function"
            name.contains("now") -> "[TIMER] Date.now/performance"
            name.contains("set_timeout") -> "[TIMER] setTimeout"
            name.contains("queue_microtask") -> "[TIMER] queueMicrotask"
            name.contains("log") || name.contains("warn") || name.contains("error") -> "[CONSOLE] console.*"
            else -> "[wbg] $name"
        }
    }

    // ---------------- 1. 调用图 ----------------

    fun callGraph(bytes: ByteArray): WasmCallGraph {
        val parsed = parser.parse(bytes)
        if (!parsed.ok) return WasmCallGraph(false, parsed.error, 0, 0, emptyMap(), emptyMap(), emptyList(), emptyMap())
        // 重新扫描 code section 提取 call 目标：这里复用 WasmParser 的解析结果不可行
        // （未保留指令流），因此独立做一遍轻量扫描
        val scan = ScanCallTargets(bytes, parsed.imports.count { it.kind == "func" })
        val adjacency = scan.adjacency
        val indirect = scan.indirectCalls
        val exportedFuncs = parsed.exports.filter { it.kind == "func" }.associate { it.index to it.name }

        val callerCount = HashMap<Int, Int>()
        adjacency.values.flatten().forEach { calleeIdx ->
            callerCount[calleeIdx] = (callerCount[calleeIdx] ?: 0) + 1
        }
        val hot = callerCount.entries
            .filter { it.value >= 1 }
            .sortedByDescending { it.value }
            .take(25)
            .map { CalleeStat(it.key, parsed.functionNames[it.key], it.value, exportedFuncs.containsKey(it.key)) }

        // 可达性：从每个 export BFS
        val reach = HashMap<String, Int>()
        exportedFuncs.forEach { (idx, name) ->
            val seen = mutableSetOf<Int>()
            val queue = ArrayDeque<Int>()
            queue.add(idx)
            while (queue.isNotEmpty() && seen.size < 5000) {
                val cur = queue.removeFirst()
                if (!seen.add(cur)) continue
                adjacency[cur]?.forEach { if (it !in seen) queue.add(it) }
            }
            reach[name] = seen.size
        }
        return WasmCallGraph(
            ok = true, totalFuncs = parsed.codeCount,
            edges = adjacency.values.sumOf { it.size },
            adjacency = adjacency, indirectCalls = indirect,
            hotCallees = hot, exportedReachability = reach,
        )
    }

    // ---------------- 2. 字符串提取 ----------------

    fun strings(bytes: ByteArray, minLength: Int = 4, maxCount: Int = 300): WasmStrings {
        val parsed = parser.parse(bytes)
        if (!parsed.ok) return WasmStrings(false, 0, emptyList())
        val out = mutableListOf<WasmString>()
        // data 段：WasmParser 已给出 preview（仅 32B），这里全量重扫
        val scanner = ScanStrings(bytes, minLength)
        scanner.scan().take(maxCount).forEach { out.add(it) }
        return WasmStrings(true, out.size, out)
    }

    // ---------------- 3. 导出函数画像 ----------------

    fun exportProfiles(bytes: ByteArray): List<ExportProfile> {
        val parsed = parser.parse(bytes)
        if (!parsed.ok) return emptyList()
        val importedFuncs = parsed.imports.count { it.kind == "func" }
        val scan = ScanCallTargets(bytes, importedFuncs)
        val callCounts = scan.adjacency.mapValues { it.value.size }
        return parsed.exports.filter { it.kind == "func" }.map { e ->
            val body = parsed.funcBodies.firstOrNull { it.index == e.index }
            val sigIdx = parsed.localFunctions.getOrNull(e.index - importedFuncs)
            val totalInstr = body?.topOpcodes?.sumOf { it.second } ?: 0
            ExportProfile(
                name = e.name,
                funcIndex = e.index,
                params = sigIdx?.params?.joinToString(",") ?: "(imported)",
                results = sigIdx?.results?.joinToString(",") ?: "",
                bodyBytes = body?.bodySize ?: 0,
                instructionCount = totalInstr,
                cryptoScore = body?.cryptoScore ?: 0,
                internalCalls = callCounts[e.index] ?: 0,
                indirectCalls = scan.indirectCalls[e.index] ?: 0,
                realName = parsed.functionNames[e.index],
            )
        }.sortedByDescending { it.cryptoScore * 100 + it.bodyBytes / 100 }
    }

    // ---------------- 扫描器：指令级 call 目标 ----------------

    private class ScanCallTargets(bytes: ByteArray, private val importedFuncs: Int) {
        val adjacency = HashMap<Int, MutableList<Int>>()
        val indirectCalls = HashMap<Int, Int>()
        private val opcodeNames = setOf(
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x1a, 0x1b, 0x1c, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
            0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
            0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
            0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
            0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a,
            0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
            0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74,
            0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81,
            0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
            0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
            0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5,
            0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2,
            0xc3, 0xc4, 0xd0, 0xd1, 0xd2, 0xfb, 0xfc, 0xfd,
        )

        init {
            runCatching { scan(bytes, importedFuncs) }
        }

        private fun scan(bytes: ByteArray, importedFuncs: Int) {
            var pos = 8 // magic + version
            var funcIdx = importedFuncs
            val funcSectionSizes = mutableListOf<Int>()
            while (pos < bytes.size) {
                val secId = bytes[pos].toInt() and 0xff
                pos++
                val (size, lenBytes) = readU32(bytes, pos)
                pos += lenBytes
                val end = pos + size.toInt()
                if (end > bytes.size) break
                if (secId == 3) {
                    // function section: 记录每个本地函数的 type index
                    val (n, nb) = readU32(bytes, pos)
                    pos += nb
                    repeat(n.toInt()) {
                        val (_, tb) = readU32(bytes, pos)
                        pos += tb
                    }
                } else if (secId == 10) {
                    // code section
                    val (n, nb) = readU32(bytes, pos)
                    pos += nb
                    repeat(n.toInt()) {
                        val (bodySize, bb) = readU32(bytes, pos)
                        pos += bb
                        val bodyEnd = pos + bodySize.toInt()
                        scanBody(bytes, pos, bodyEnd, funcIdx)
                        pos = bodyEnd
                        funcIdx++
                    }
                }
                pos = end
            }
            // 防未用警告
            funcSectionSizes.size
        }

        private fun scanBody(bytes: ByteArray, from: Int, bodyEnd: Int, funcIdx: Int) {
            var pos = from
            // locals 声明
            val (groups, gb) = readU32(bytes, pos); pos += gb
            repeat(groups.toInt()) {
                val (_, cb) = readU32(bytes, pos); pos += cb
                pos += 1 // valtype
            }
            val callees = mutableListOf<Int>()
            while (pos < bodyEnd) {
                val op = bytes[pos].toInt() and 0xff
                pos++
                when {
                    op == 0x10 -> { // call funcidx
                        val (target, tb) = readU32(bytes, pos)
                        pos += tb
                        callees.add(target.toInt())
                    }
                    op == 0x11 -> { // call_indirect
                        indirectCalls[funcIdx] = (indirectCalls[funcIdx] ?: 0) + 1
                        pos += u32Len(bytes, pos); pos += u32Len(bytes, pos + u32Len(bytes, pos))
                    }
                    op == 0x02 || op == 0x03 || op == 0x04 || op == 0xd0 -> { // blocktype
                        val v = bytes[pos].toInt() and 0xff
                        if (v == 0x40 || v == 0x7f || v == 0x7e || v == 0x7d || v == 0x7c) pos += 1
                        else { while (pos < bodyEnd && bytes[pos].toInt() and 0x80 != 0) pos++; pos += 1 }
                    }
                    op == 0x0c || op == 0x0d || op == 0x20 || op == 0x21 || op == 0x22 ||
                        op == 0x23 || op == 0x24 || op == 0x25 || op == 0x26 || op == 0xd2 ->
                        pos += u32Len(bytes, pos)
                    op == 0x0e -> { // br_table
                        val (cnt, cb) = readU32(bytes, pos); pos += cb
                        repeat(cnt.toInt() + 1) { pos += u32Len(bytes, pos) }
                    }
                    op == 0x1c -> {
                        val (cnt, cb) = readU32(bytes, pos); pos += cb
                        pos += cnt.toInt()
                    }
                    op in 0x28..0x3e -> { pos += u32Len(bytes, pos); pos += u32Len(bytes, pos) }
                    op == 0x3f || op == 0x40 -> pos += u32Len(bytes, pos)
                    op == 0x41 -> { while (pos < bodyEnd && bytes[pos].toInt() and 0x80 != 0) pos++; pos += 1 }
                    op == 0x42 -> { while (pos < bodyEnd && bytes[pos].toInt() and 0x80 != 0) pos++; pos += 1 }
                    op == 0x43 -> pos += 4
                    op == 0x44 -> pos += 8
                    op == 0xfb || op == 0xfc -> {
                        val (sub, sb) = readU32(bytes, pos); pos += sb
                        when (sub.toInt()) {
                            8, 9, 11, 13, 15 -> pos += u32Len(bytes, pos)
                            10, 12, 14 -> { pos += u32Len(bytes, pos); pos += u32Len(bytes, pos) }
                        }
                    }
                    op == 0xfd -> return // SIMD 放弃
                    op in opcodeNames -> { /* 无 immediate */ }
                    else -> { /* 未知指令：尽力同步（可能漂移，容错） */ }
                }
            }
            if (callees.isNotEmpty()) adjacency[funcIdx] = callees
        }

        private fun readU32(b: ByteArray, from: Int): Pair<Long, Int> {
            var result = 0L; var shift = 0; var i = from
            while (i < b.size) {
                val byte = b[i].toInt() and 0xff
                result = result or ((byte and 0x7f).toLong() shl shift)
                i++
                if (byte and 0x80 == 0) break
                shift += 7
                if (shift > 35) break
            }
            return result to (i - from)
        }

        private fun u32Len(b: ByteArray, from: Int): Int = readU32(b, from).second
    }

    // ---------------- 扫描器：全量字符串 ----------------

    private class ScanStrings(private val bytes: ByteArray, private val minLen: Int) {
        fun scan(): List<WasmString> {
            val out = mutableListOf<WasmString>()
            var run = StringBuilder()
            var runStart = -1
            for (i in 4 until bytes.size) { // 跳过 magic
                val b = bytes[i].toInt() and 0xff
                if (b in 0x20..0x7e) {
                    if (run.isEmpty()) runStart = i
                    run.append(b.toChar())
                } else {
                    flushRun(run, runStart, out)
                    run = StringBuilder()
                }
                if (out.size >= 500) break
            }
            flushRun(run, runStart, out)
            return out
        }

        private fun flushRun(run: StringBuilder, start: Int, out: MutableList<WasmString>) {
            if (run.length >= minLen && start >= 0) {
                val kind = when {
                    run.contains(Regex("""^[\w.$/-]{4,}$""")) && run.contains(Regex("""[/.]""")) -> "path"
                    Regex("""\d+\.\d+\.\d+""").containsMatchIn(run) -> "version"
                    run.contains(Regex("""(?i)(error|fail|invalid|assert)""")) -> "error-msg"
                    run.contains(Regex("""(?i)(key|crypt|sign|hmac|aes|rsa|sha|md5|token|secret)""")) -> "crypto-related"
                    else -> "text"
                }
                out.add(WasmString(start, "binary", run.toString().take(200), kind))
            }
        }
    }

    // ---------------- wasm-bindgen 骨架生成 ----------------

    data class BindgenSkeleton(
        val ok: Boolean,
        val error: String = "",
        val isBindgen: Boolean = false,
        val skeleton: String = "",
        val exports: List<BindgenExport> = emptyList(),
        val imports: List<String> = emptyList(),
    )

    data class BindgenExport(
        val name: String,
        val funcIndex: Int,
        val params: String,
        val results: String,
        val category: String, // constructor / method / free-function / glue / memory
        val hint: String = "",
    )

    /** 生成 wasm-bindgen 调用骨架（Node.js 可运行的启动代码）。
     *  自动识别 wasm-bindgen 模块，列出导出函数分类，生成包含内存分配、字符串传递、
     *  调用模板的完整 JS 骨架，逆向时省去手写胶水代码的时间。 */
    fun bindgenSkeleton(bytes: ByteArray): BindgenSkeleton {
        val parser = WasmParser()
        val parsed = parser.parse(bytes)
        if (!parsed.ok) return BindgenSkeleton(false, parsed.error)

        val importNames = parsed.imports.filter { it.kind == "func" }.map { "${it.module}.${it.name}" }
        val isBindgen = importNames.any { it.contains("__wbindgen_") || it.contains("__wbg_") }
        if (!isBindgen) {
            return BindgenSkeleton(ok = true, isBindgen = false, error = "非 wasm-bindgen 模块（未检测到 __wbindgen_ / __wbg_ 导入）")
        }

        val importedFuncs = parsed.imports.count { it.kind == "func" }

        // 分类导出函数
        val exports = parsed.exports
            .filter { it.kind == "func" }
            .map { e ->
                val sigIdx = e.index - importedFuncs
                val sig = parsed.localFunctions.getOrNull(sigIdx)
                val params = sig?.params?.joinToString(",") ?: "?"
                val results = sig?.results?.joinToString(",") ?: "?"
                val name = e.name
                val (category, hint) = categorizeBindgenExport(name, sig?.params ?: emptyList(), sig?.results ?: emptyList())
                BindgenExport(name, e.index, params, results, category, hint)
            }

        // 生成 JS 骨架代码
        val skeleton = buildString {
            appendLine("// ============================================================")
            appendLine("// WASM Bindgen Call Skeleton (auto-generated by WebReverse MCP)")
            appendLine("// ============================================================")
            appendLine("//")
            appendLine("// 使用方法：")
            appendLine("//   1. 把 WASM 文件路径填到 WASM_PATH")
            appendLine("//   2. 按需要补全 imports 中的环境依赖（DOM/crypto 等）")
            appendLine("//   3. node this_script.js")
            appendLine("//")
            appendLine("const fs = require('fs');")
            appendLine("const path = require('path');")
            appendLine("")
            appendLine("const WASM_PATH = './module.wasm';  // 替换为实际路径")
            appendLine("")
            appendLine("// ---------------- 内存与字符串工具 ----------------")
            appendLine("")
            appendLine("let wasm, memory, heap;")
            appendLine("")
            appendLine("function reallocHeap() {")
            appendLine("  // 同步 heap 视图（内存增长后需重建）")
            appendLine("  memory = wasm.memory;")
            appendLine("  heap = new Uint8Array(memory.buffer);")
            appendLine("}")
            appendLine("")
            appendLine("// 在 WASM 堆上分配字节并写入字符串（UTF-8 编码）")
            appendLine("function allocString(str) {")
            appendLine("  const encoder = new TextEncoder();")
            appendLine("  const bytes = encoder.encode(str);")
            appendLine("  const ptr = wasm.__wbindgen_malloc(bytes.length);")
            appendLine("  reallocHeap();")
            appendLine("  heap.set(bytes, ptr);")
            appendLine("  return [ptr, bytes.length];")
            appendLine("}")
            appendLine("")
            appendLine("// 从 WASM 堆读取字符串（ptr, len 形式）")
            appendLine("function readString(ptr, len) {")
            appendLine("  reallocHeap();")
            appendLine("  const bytes = heap.slice(ptr, ptr + len);")
            appendLine("  const decoder = new TextDecoder();")
            appendLine("  return decoder.decode(bytes);")
            appendLine("}")
            appendLine("")
            appendLine("// 读取 wasm-bindgen 返回的字符串（写入到 [retptr, retptr+4] 的 ptr/length 对）")
            appendLine("function readReturnedString(retptr) {")
            appendLine("  reallocHeap();")
            appendLine("  const view = new DataView(memory.buffer);")
            appendLine("  const ptr = view.getUint32(retptr, true);")
            appendLine("  const len = view.getUint32(retptr + 4, true);")
            appendLine("  return readString(ptr, len);")
            appendLine("}")
            appendLine("")
            appendLine("// ---------------- 环境依赖（按需补全） ----------------")
            appendLine("")
            appendLine("// wasm-bindgen 需要的最小 imports（根据实际模块调整）")
            appendLine("const imports = {")
            appendLine("  wbg: {")

            // 列出所有需要实现的导入
            val wbgImports = parsed.imports.filter { it.kind == "func" && it.module == "wbg" }
            wbgImports.take(30).forEach { imp ->
                val sig = parsed.types.getOrNull(imp.typeIndex)
                val paramStr = sig?.params?.joinToString(", ") { "arg${it}" } ?: "..."
                appendLine("    // ${imp.name}(${paramStr})")
                appendLine("    ${imp.name}: function() { /* TODO: implement */ throw new Error('${imp.name} not implemented'); },")
            }
            if (wbgImports.size > 30) {
                appendLine("    // ... 另有 ${wbgImports.size - 30} 个导入省略")
            }
            appendLine("  },")
            appendLine("  __wbindgen_placeholder__: {")
            appendLine("    __wbindgen_describe: function() {},")
            appendLine("    __wbindgen_throw: function(ptr, len) {")
            appendLine("      throw new Error('WASM panic: ' + readString(ptr, len));")
            appendLine("    },")
            appendLine("  },")
            appendLine("};")
            appendLine("")
            appendLine("// ---------------- 实例化 ----------------")
            appendLine("")
            appendLine("async function main() {")
            appendLine("  const bytes = fs.readFileSync(WASM_PATH);")
            appendLine("  const result = await WebAssembly.instantiate(bytes, imports);")
            appendLine("  wasm = result.instance.exports;")
            appendLine("  reallocHeap();")
            appendLine("")
            appendLine("  // TODO: 在此调用导出函数")
            appendLine("  // 示例：")
            appendLine("  //   const [ptr, len] = allocString('hello');")
            appendLine("  //   const result = wasm.some_function(ptr, len);")
            appendLine("  //   console.log('result:', result);")
            appendLine("}")
            appendLine("")
            appendLine("main().catch(console.error);")
        }

        return BindgenSkeleton(
            ok = true,
            isBindgen = true,
            skeleton = skeleton,
            exports = exports,
            imports = importNames,
        )
    }

    /** 对 wasm-bindgen 导出函数进行分类（用于骨架生成时的提示） */
    private fun categorizeBindgenExport(
        name: String,
        params: List<String>,
        results: List<String>,
    ): Pair<String, String> {
        return when {
            name == "memory" -> "memory" to "WASM 线性内存"
            name == "__wbindgen_malloc" -> "memory" to "内存分配：malloc(len) → ptr"
            name == "__wbindgen_free" -> "memory" to "内存释放：free(ptr, len)"
            name == "__wbindgen_realloc" -> "memory" to "内存重分配：realloc(ptr, old, new) → ptr"
            name == "__wbindgen_add_to_stack_pointer" -> "glue" to "栈指针调整"
            name.startsWith("__wbindgen_export_") -> "glue" to "wasm-bindgen 内部导出"
            name.startsWith("__wbg_") -> "glue" to "JS 端胶水函数"
            name.endsWith("_new") || name.endsWith("_new_with") -> "constructor" to
                "构造函数：创建对象，返回 this 指针"
            name.endsWith("_free") -> "method" to "析构函数：释放对象"
            // 启发式：第一个参数是 i32（this 指针），大概率是方法
            params.size >= 2 && params[0] == "i32" && params[1] == "i32" -> {
                if (name.contains("_")) {
                    "method" to "类方法：第一个 i32 通常是 this 指针"
                } else {
                    "free-function" to "自由函数"
                }
            }
            params.isNotEmpty() && params[0] == "i32" && name.contains("_") -> {
                "method" to "可能是类方法（第一个参数为 this 指针）"
            }
            else -> "free-function" to "自由函数"
        }
    }
}
