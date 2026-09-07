package com.webreverse.mcp.javascript.analysis

/**
 * WASM 内存溯源 + JS↔WASM 统一数据流分析。
 *
 * 目标：回答两个逆向问题
 * - 「某段 WASM 内存（尤其含密钥/常量/结果缓冲）是谁写的、谁读的？」
 * - 「JS 传来的值经过哪些导入/导出、最终落在内存哪个区间？」
 *
 * 实现（纯 Kotlin，不执行 WASM）：
 * 1. **内存访问谱（access profile）**：逐函数扫描 load/store 指令，解析可静态求值的
 *    memarg base（i32.const 立即数 + 前一条取基址），得到「函数 -> {读地址集, 写地址集}」。
 *    用区间合并算法把离散地址聚成连续区间，避免 O(n) 点爆炸。
 * 2. **溯源（provenance）**：对给定目标地址 [addr, addr+len)，沿「写者->读者」反向/正向
 *    两条推链给出来源函数链与去向函数链；结合 data 段静态布局标注「来自 data 段/动态分配」。
 * 3. **JS↔WASM 边界（boundary）**：导入（WASM 调 JS）按 wbg 语义分类；导出中「首参为 i32
 *    且后续出现指针型传导」的标记为内存指针型导出（JS 传 ptr/len 或读回结果缓冲）。
 *    统一数据流：JS 指纹值 -> 导出调用参数（ptr）-> 内存区间 -> 写者/读者函数链。
 */
class WasmMemoryProvenance {

    // ---------------- 区间模型 ----------------

    /** 闭区间 [start, end]（内存字节地址） */
    data class AddrRange(val start: Long, val end: Long) {
        fun overlaps(o: AddrRange): Boolean = start <= o.end && o.start <= end
        fun mergeable(o: AddrRange): Boolean = overlaps(o) || start == o.end + 1 || o.start == end + 1
        fun merged(o: AddrRange): AddrRange = AddrRange(minOf(start, o.start), maxOf(end, o.end))
        val length: Long get() = (end - start + 1).coerceAtLeast(0)
        fun contains(addr: Long): Boolean = addr >= start && addr <= end
        override fun toString(): String = "0x${start.toString(16)}..0x${end.toString(16)}"
    }

    /** 单条内存访问记录 */
    data class MemAccess(
        val funcIndex: Int,
        val funcName: String,
        val addr: Long,
        val width: Int,          // 访问字节宽 1/2/4/8（memarg align 反推，无法判定取 4）
        val isStore: Boolean,    // true=写 false=读
        val opcodeAddr: Int,     // 指令在二进制中的字节偏移（定位用）
        val op: String,          // i32.store / i64.load 等
    )

    /** 函数级内存访问汇总 */
    data class FuncAccess(
        val funcIndex: Int,
        val funcName: String,
        val writes: List<AddrRange> = emptyList(),
        val reads: List<AddrRange> = emptyList(),
        val writeCount: Int = 0,
        val readCount: Int = 0,
    )

    /** 单个地址的溯源结论 */
    data class AddressProvenance(
        val addr: Long,
        val length: Long,
        val writers: List<FuncAccess>,        // 写过该区间的函数（近写优先）
        val readers: List<FuncAccess>,        // 读过该区间的函数
        val dataSegment: Boolean,             // 落在 active data 段静态布局内
        val dataRef: String = "",             // "data segment #i offset=0x.. len=.." 或 ""
        val likelyDynamic: Boolean,           // 无静态 data 段覆盖 => 运行时分配/写入
        val summary: String,
    )

    // ---------------- JS↔WASM 边界 ----------------

    data class BoundaryFunc(
        val export: String,
        val funcIndex: Int,
        val signature: String = "",
        val memoryPointerParam: Boolean = false, // 首参（或仅参）为 i32，疑似内存指针
        val category: String = "",               // constructor/method/free/glue/free-function/memory
        val hint: String = "",
    )

    data class JsWasmBoundary(
        val ok: Boolean,
        val error: String = "",
        val memoryExports: List<String> = emptyList(),       // "memory" 导出
        val pointerExports: List<BoundaryFunc> = emptyList(), // 疑似吃内存指针的导出
        val hostImports: List<Pair<String, String>> = emptyList(), // (module.name, wbg语义)
        val memorySize: Long = 0,                              // pages
    )

    // ---------------- 行为 ----------------

    /** 全量内存访问谱 + JS↔WASM 边界（一次分析两条产出） */
    data class MemoryReport(
        val ok: Boolean,
        val error: String = "",
        val funcs: List<FuncAccess> = emptyList(),
        val totalWrites: Int = 0,
        val totalReads: Int = 0,
        val boundary: JsWasmBoundary = JsWasmBoundary(ok = false),
        val topWriters: List<FuncAccess> = emptyList(),   // 写字节数最多的函数
    )

    fun analyze(bytes: ByteArray): MemoryReport {
        val parser = WasmParser()
        val parsed = parser.parse(bytes)
        if (!parsed.ok) return MemoryReport(false, parsed.error)
        val importedFuncs = parsed.imports.count { it.kind == "func" }

        // 1. 逐函数扫描内存访问
        val accesses = scanAccesses(bytes, parsed, importedFuncs)
        val grouped = accesses.groupBy { it.funcIndex }
        val funcs = grouped.map { (fi, accs) ->
            val name = parsed.functionNames[fi] ?: "func_$fi"
            val writes = accs.filter { it.isStore }
            val reads = accs.filter { !it.isStore }
            FuncAccess(
                funcIndex = fi,
                funcName = name,
                writes = mergeRanges(writes.map { AddrRange(it.addr, it.addr + it.width - 1) }),
                reads = mergeRanges(reads.map { AddrRange(it.addr, it.addr + it.width - 1) }),
                writeCount = writes.size,
                readCount = reads.size,
            )
        }.sortedBy { it.funcIndex }

        // 2. JS↔WASM 边界
        val boundary = buildBoundary(parsed)

        // 3. 按写字节数排序 topWriters
        val topWriters = funcs
            .map { it.copy(writes = it.writes) }
            .sortedByDescending { it.writes.sumOf { r -> r.length } }
            .take(12)

        return MemoryReport(
            ok = true,
            funcs = funcs,
            totalWrites = accesses.count { it.isStore },
            totalReads = accesses.count { !it.isStore },
            boundary = boundary,
            topWriters = topWriters,
        )
    }

    /** 对指定地址做溯源 */
    fun provenance(bytes: ByteArray, addr: Long, length: Long = 4): AddressProvenance {
        val report = analyze(bytes)
        if (!report.ok || addr < 0 || length <= 0) {
            return AddressProvenance(addr, length, emptyList(), emptyList(), false, "", true, "分析失败或非法地址")
        }
        val target = AddrRange(addr, addr + length - 1)
        val writers = report.funcs.filter { f ->
            f.writes.any { it.overlaps(target) }
        }.map { it.copy(writes = it.writes.filter { r -> r.overlaps(target) }) }
        val readers = report.funcs.filter { f ->
            f.reads.any { it.overlaps(target) }
        }.map { it.copy(reads = it.reads.filter { r -> r.overlaps(target) }) }

        // data 段覆盖判定
        var dataRef = ""
        val parser = WasmParser()
        val parsed = parser.parse(bytes)
        if (parsed.ok) {
            parsed.dataSegments.firstOrNull { d ->
                d.mode == "active" && d.offset >= 0 &&
                    AddrRange(d.offset, d.offset + d.length - 1).overlaps(target)
            }?.let { d ->
                dataRef = "data segment @0x${d.offset.toString(16)} len=${d.length}"
            }
        }
        val inData = dataRef.isNotBlank()
        val summary = buildString {
            append("addr 0x").append(addr.toString(16)).append("..0x").append((addr + length - 1).toString(16))
            append("：")
            append(if (inData) "落在静态 data 段（$dataRef）；" else "无静态 data 覆盖（运行时动态写入区）；")
            append("写者 ${writers.size} 个，读者 ${readers.size} 个。")
            if (writers.isNotEmpty()) {
                append("近写源：").append(writers.take(3).joinToString { "${it.funcName}[w${it.writeCount}]" }).append("。")
            }
            if (readers.isNotEmpty()) {
                append("读者链：").append(readers.take(3).joinToString { "${it.funcName}[r${it.readCount}]" }).append("。")
            }
        }
        return AddressProvenance(
            addr, length, writers, readers, inData, dataRef, !inData, summary,
        )
    }

    // ---------------- 内部实现 ----------------

    /** LEB128 读取 */
    private fun u32(b: ByteArray, from: Int): Pair<Long, Int> {
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

    /** 区间合并（按 start 排序，可邻接合并） */
    private fun mergeRanges(ranges: List<AddrRange>): List<AddrRange> {
        if (ranges.isEmpty()) return emptyList()
        val sorted = ranges.sortedBy { it.start }
        val out = mutableListOf<AddrRange>()
        var cur = sorted[0]
        for (r in sorted.drop(1)) {
            if (cur.mergeable(r)) cur = cur.merged(r)
            else { out.add(cur); cur = r }
        }
        out.add(cur)
        return out
    }

    /** load/store opcode 表：opcode -> 宽度字节 */
    private val loadWidth = mapOf(
        0x28 to 4, 0x29 to 8, 0x2a to 4, 0x2b to 8, 0x2c to 4, 0x2d to 8,
        0x2e to 1, 0x2f to 2, 0x30 to 2, 0x31 to 2, 0x32 to 4, 0x33 to 8,
        0x34 to 1, 0x35 to 2,
    )
    private val storeWidth = mapOf(
        0x36 to 4, 0x37 to 8, 0x38 to 4, 0x39 to 8, 0x3a to 4, 0x3b to 8,
        0x3c to 1, 0x3d to 2, 0x3e to 2,
    )

    /** 扫描所有函数的内存访问。对每条 load/store，尝试解析静态基址（i32.const + offset）。 */
    private fun scanAccesses(
        bytes: ByteArray,
        parsed: WasmParser.ParsedWasm,
        importedFuncs: Int,
    ): List<MemAccess> {
        val out = mutableListOf<MemAccess>()
        // 复用 section 遍历定位 code section 内各函数体起止
        var pos = 8
        var funcIndex = importedFuncs
        val dataSegOffsets = parsed.dataSegments.filter { it.mode == "active" && it.offset >= 0 }
            .map { AddrRange(it.offset, it.offset + it.length - 1) }

        while (pos < bytes.size) {
            val secId = bytes[pos].toInt() and 0xff
            pos++
            val (size, sizeLen) = u32(bytes, pos)
            pos += sizeLen.toInt()
            val start = pos
            val end = (pos + size).toInt()
            if (end > bytes.size) break
            if (secId == 10) {
                val (n, nb) = u32(bytes, start)
                var p = start + nb
                repeat(n.toInt()) {
                    val (bodySize, bb) = u32(bytes, p)
                    p += bb
                    val bodyEnd = p + bodySize.toInt()
                    val fname = parsed.functionNames[funcIndex] ?: "func_$funcIndex"
                    try {
                        // 先解析 locals 声明
                        val (groups, gb) = u32(bytes, p)
                        var q = p + gb
                        var stackConsts = ArrayDeque<Long>() // 最近 i32.const 值栈（简化：仅记录最近 8）
                        repeat(groups.toInt()) {
                            val (cnt, cb) = u32(bytes, q); q += cb.toInt()
                            q += 1 // valtype
                        }
                        while (q < bodyEnd) {
                            val op = bytes[q].toInt() and 0xff
                            val opcodeAddr = q
                            q++
                            when {
                                op == 0x41 -> { // i32.const
                                    val (v, lb) = s32(bytes, q); q += lb.toInt()
                                    if (stackConsts.size > 8) stackConsts.removeFirst()
                                    stackConsts.addLast(v)
                                }
                                op in loadWidth -> {
                                    // memarg: align, offset
                                    val (align, ab) = u32(bytes, q); q += ab.toInt()
                                    val (off, ob) = u32(bytes, q); q += ob.toInt()
                                    val base = stackConsts.lastOrNull()
                                    val addr = base?.plus(off) ?: -1L
                                    if (addr >= 0) {
                                        val width = loadWidth[op] ?: 4
                                        out.add(
                                            MemAccess(
                                                funcIndex, fname, addr, width, isStore = false,
                                                opcodeAddr = opcodeAddr, op = "load${width * 8}",
                                            ),
                                        )
                                    }
                                }
                                op in storeWidth -> {
                                    val (align, ab) = u32(bytes, q); q += ab.toInt()
                                    val (off, ob) = u32(bytes, q); q += ob.toInt()
                                    val base = stackConsts.lastOrNull()
                                    val addr = base?.plus(off) ?: -1L
                                    if (addr >= 0) {
                                        val width = storeWidth[op] ?: 4
                                        out.add(
                                            MemAccess(
                                                funcIndex, fname, addr, width, isStore = true,
                                                opcodeAddr = opcodeAddr, op = "store${width * 8}",
                                            ),
                                        )
                                    }
                                }
                            }
                        }
                    } catch (_: Exception) {
                        // 该函数扫描失败，跳过其负载（保持定位）
                    }
                    p = bodyEnd
                    funcIndex++
                }
            }
            pos = end
        }
        // 去抖：数据段内静态常量写入由 init 完成，若函数访问地址与 data 段重叠则标记（供上层判断）
        return out
    }

    /** 有符号 LEB (i32) */
    private fun s32(b: ByteArray, from: Int): Pair<Long, Int> {
        var result = 0L; var shift = 0; var i = from
        while (i < b.size) {
            val byte = b[i].toInt() and 0xff
            result = result or ((byte and 0x7f).toLong() shl shift)
            i++
            shift += 7
            if (byte and 0x80 == 0) {
                if (shift < 64 && byte and 0x40 != 0) result = result or (-1L shl shift)
                break
            }
            if (shift > 35) break
        }
        return result to (i - from)
    }

    private fun buildBoundary(parsed: WasmParser.ParsedWasm): JsWasmBoundary {
        val importedFuncs = parsed.imports.count { it.kind == "func" }
        val memoryExports = parsed.exports.filter { it.kind == "memory" }.map { it.name }
        val memoryPages = (parsed.importedMemories + parsed.memories).firstOrNull()?.initial ?: 0

        // 导出分类 + 内存指针判定（首参 i32）
        val pointerFns = mutableListOf<BoundaryFunc>()
        for (e in parsed.exports.filter { it.kind == "func" }) {
            val sig = parsed.localFunctions.getOrNull(e.index - importedFuncs) ?: continue
            val paramsSig = sig.params
            val ptrLike = paramsSig.size >= 1 && paramsSig[0] == "i32"
            val name = e.name
            val (cat, hint) = categorize(name, ptrLike, paramsSig, sig.results)
            pointerFns.add(
                BoundaryFunc(
                    export = name,
                    funcIndex = e.index,
                    signature = "${paramsSig.joinToString(",")} -> ${sig.results.joinToString(",")}",
                    memoryPointerParam = ptrLike,
                    category = cat,
                    hint = hint,
                ),
            )
        }

        // wbg 导入语义
        val hostImports = parsed.imports
            .filter { it.kind == "func" }
            .map { "${it.module}.${it.name}" to wasmSemantic(it.name) }

        return JsWasmBoundary(
            ok = true,
            memoryExports = memoryExports,
            pointerExports = pointerFns,
            hostImports = hostImports.take(200),
            memorySize = memoryPages,
        )
    }

    private fun categorize(name: String, ptrLike: Boolean, params: List<String>, results: List<String>): Pair<String, String> =
        when {
            name == "__wbindgen_malloc" -> "memory-alloc" to "malloc(len)->ptr"
            name == "__wbindgen_free" -> "memory-free" to "free(ptr,len)"
            name == "__wbindgen_realloc" -> "memory-alloc" to "realloc"
            name.startsWith("__wbindgen_") -> "glue" to "wasm-bindgen 内部"
            name.endsWith("_free") -> "free" to "析构"
            name.endsWith("_new") || name.endsWith("_new_with") -> "constructor" to "构造"
            params.size >= 2 && ptrLike && params[1] == "i32" -> "method" to "类方法(this+ptr)"
            params.size >= 1 && ptrLike && name.contains("_") -> "method" to "方法(this 指针)"
            results.firstOrNull() == "i32" && name.contains("_") && name.contains("alloc") -> "memory-alloc" to "返回指针"
            ptrLike -> "ptr-passing" to "首参为指针"
            else -> "free-function" to "自由函数"
        }

    /** wasm-bindgen / 宿主 wbg 语义（与原 WasmAnalyzer 对齐，微调扩充） */
    private fun wasmSemantic(name: String): String {
        if (name.startsWith("__wbg_")) {
            return when {
                name.contains("crypto") -> "[CRYPTO] WebCrypto"
                name.contains("fetch") -> "[NET] fetch"
                name.contains("log") -> "[CONSOLE] console"
                name.contains("performance") || name.contains("now") -> "[TIMER] performance/time"
                name.contains("document") -> "[DOM] document"
                name.contains("memory") -> "[MEM] wasm memory setPcmData"
                else -> "[wbg] host call"
            }
        }
        if (name.startsWith("__wbindgen_")) return "[glue] wasm-bindgen $name"
        if (name.contains("malloc") || name.contains("free") || name.contains("realloc")) return "[MEM] allocator"
        if (name.contains("memory")) return "[MEM] memory op"
        if (name.contains("env") || name.contains("console")) return "[ENV] $name"
        return "[host] $name"
    }
}