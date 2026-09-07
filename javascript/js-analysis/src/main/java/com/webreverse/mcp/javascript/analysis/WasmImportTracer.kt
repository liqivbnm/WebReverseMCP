package com.webreverse.mcp.javascript.analysis

/**
 * WASM Import 边界观测器 + Data 段字符串提取器（ 新增）。
 *
 * 核心思路：WASM 模块的 import 表是「宿主边界」，
 * 逆向时最关心——
 * 1. **哪些 import 被谁调用**：静态扫全部函数体的 `call N` 指令，
 *    建立 import -> 调用方（函数索引/导出名）-> 调用次数 的反向索引，
 *    顺带暴露「从未被调用的死 import」与「宿主注入函数」清单。
 * 2. **import 分类画像**：Emscripten 运行时（emscripten_*）/
 *    WASI（fd_*、random_get）/ JS 胶水（console、spectest）/
 *    内存与表（env.memory、env.__indirect_function_table）/
 *    加密相关（random_get、crypto）——判断模块的宿主依赖形态。
 * 3. **data 段字符串提取**：密钥/URL/错误信息/算法名常内嵌在 data 段，
 *    提取可打印字符串并分类（URL / hex / base64 / 标识符 / 错误消息），
 *    为 crypto 识别与魔数定位提供入口。
 *
 * 纯 Kotlin、stdlib only；基于 [WasmParser] / [WasmDisassembler] 既有解析能力。
 */
class WasmImportTracer {

    // =========================================================================
    // 数据模型
    // =========================================================================

    /** 一个 import 的完整调用画像 */
    data class ImportUsage(
        val funcIndex: Int,          // import 的全局函数索引
        val module: String,          // import module 名（如 env）
        val name: String,            // import 函数名（如 emscripten_memcpy_big）
        val callCount: Int,          // 静态 call 指令总数
        val callers: List<CallerInfo>, // 调用方（按调用次数降序）
        val category: String,        // 分类（runtime-emscripten / wasi / js-glue / memory / crypto / unknown）
    )

    data class CallerInfo(
        val funcIndex: Int,
        val funcName: String?,       // name section 符号（可能为 null）
        val exportNames: List<String>, // 该函数若是导出函数的导出名
        val calls: Int,              // 该调用方对 import 的调用次数
    )

    /** import 分类统计 */
    data class ImportProfile(
        val totalImports: Int,
        val funcImports: Int,
        val memoryImports: Int,
        val tableImports: Int,
        val globalImports: Int,
        val byCategory: Map<String, Int>,
        val usedImports: List<ImportUsage>,
        val unusedImports: List<ImportUsage>,
        /** 模块形态推断（emscripten/wasi/asm.js 手写） */
        val runtimeGuess: String,
    )

    data class TraceReport(
        val ok: Boolean,
        val error: String = "",
        val profile: ImportProfile? = null,
        val functionsScanned: Int,
        val summary: String,
    )

    /** 一条提取出的字符串 */
    data class WasmString(
        val value: String,
        val segmentIndex: Int,       // 所属 data segment 序号
        val memoryOffset: Long,      // active 段在 wasm 线性内存中的地址（passive 为 -1）
        val length: Int,
        val kind: String,            // url / hex / base64 / identifier / message / printable
    )

    data class StringsReport(
        val ok: Boolean,
        val error: String = "",
        val strings: List<WasmString>,
        val segmentsScanned: Int,
        val bytesScanned: Int,
        val summary: String,
    )

    // =========================================================================
    // Import 边界追踪
    // =========================================================================

    private val parser = WasmParser()
    private val disassembler = WasmDisassembler()

    fun traceImports(bytes: ByteArray, maxFunctions: Int = 500): TraceReport {
        val parsed = parser.parse(bytes)
        if (!parsed.ok) return TraceReport(false, parsed.error, null, 0, "解析失败: ${parsed.error}")

        // ---- 函数型 import：全局索引 = 其在 import 列表中 func 的序号 ----
        val funcImports = mutableListOf<WasmParser.WasmImport>()
        var funcIdx = 0
        parsed.imports.forEach { imp ->
            if (imp.kind == "func") {
                funcImports.add(imp)
                funcIdx++
            }
        }
        val importByIndex = funcImports.withIndex().associate { (i, imp) -> i to imp }

        // ---- 分类统计（全类型 import）----
        val catCount = mutableMapOf<String, Int>()
        parsed.imports.forEach { imp ->
            val cat = categorize(imp)
            catCount[cat] = (catCount[cat] ?: 0) + 1
        }

        // ---- 扫描全部函数体，统计 call N（N < importFuncCount 即 import 调用）----
        val importFuncCount = funcImports.size
        val callCounts = HashMap<Int, Int>()                     // importIdx -> 总次数
        val callerCounts = HashMap<Int, HashMap<Int, Int>>()     // importIdx -> (callerIdx -> 次数)

        var scanned = 0
        for (body in parsed.funcBodies) {
            if (scanned >= maxFunctions) break
            val d = disassembler.disassemble(bytes, body.index, maxInstructions = 4000)
            if (!d.ok) continue
            scanned++
            for (line in d.listing.lineSequence()) {
                val t = line.trim()
                if (!t.startsWith("call ")) continue
                val target = t.removePrefix("call ").trim().toIntOrNull() ?: continue
                if (target in 0 until importFuncCount) {
                    callCounts[target] = (callCounts[target] ?: 0) + 1
                    val m = callerCounts.getOrPut(target) { HashMap() }
                    m[body.index] = (m[body.index] ?: 0) + 1
                }
            }
        }

        // ---- 导出名映射（funcIndex -> exportNames）----
        val exportByFunc = parsed.exports
            .filter { it.kind == "func" }
            .groupBy({ it.index }, { it.name })

        // ---- 组装 ImportUsage ----
        val used = mutableListOf<ImportUsage>()
        val unused = mutableListOf<ImportUsage>()
        for ((idx, imp) in importByIndex) {
            val total = callCounts[idx] ?: 0
            val callers = (callerCounts[idx] ?: emptyMap())
                .map { (callerIdx, calls) ->
                    CallerInfo(
                        funcIndex = callerIdx,
                        funcName = parsed.functionNames[callerIdx],
                        exportNames = exportByFunc[callerIdx] ?: emptyList(),
                        calls = calls,
                    )
                }
                .sortedByDescending { it.calls }
            val usage = ImportUsage(
                funcIndex = idx,
                module = imp.module,
                name = imp.name,
                callCount = total,
                callers = callers.take(10),
                category = categorize(imp),
            )
            if (total > 0) used.add(usage) else unused.add(usage)
        }

        used.sortByDescending { it.callCount }

        val profile = ImportProfile(
            totalImports = parsed.imports.size,
            funcImports = funcImports.size,
            memoryImports = parsed.imports.count { it.kind == "memory" },
            tableImports = parsed.imports.count { it.kind == "table" },
            globalImports = parsed.imports.count { it.kind == "global" },
            byCategory = catCount,
            usedImports = used,
            unusedImports = unused,
            runtimeGuess = guessRuntime(parsed),
        )

        return TraceReport(
            ok = true,
            profile = profile,
            functionsScanned = scanned,
            summary = buildTraceSummary(profile, scanned),
        )
    }

    /** import 分类 */
    private fun categorize(imp: WasmParser.WasmImport): String {
        val n = imp.name
        val m = imp.module
        return when {
            imp.kind != "func" -> imp.kind // memory / table / global
            n.startsWith("emscripten_") || n.startsWith("__emscripten") || n.startsWith("_emscripten") ||
                n.startsWith("__cxa") || n.startsWith("__resume") -> "runtime-emscripten"
            n.startsWith("fd_") || n == "random_get" || n.startsWith("proc_") ||
                n.startsWith("clock_") || n.startsWith("environ") || n.startsWith("args_") ||
                n == "fd_write" || m == "wasi_snapshot_preview1" || m.startsWith("wasi") -> "wasi"
            n.startsWith("console") || n.contains("log") || m == "spectest" || n.startsWith("print") -> "js-glue"
            n.contains("random") || n.contains("crypto") || n.contains("seed") -> "crypto"
            n.startsWith("wbg") || n.startsWith("__wbindgen") -> "rust-wasm-bindgen"
            n.startsWith("a") || n.startsWith("b") || n.length <= 3 -> "minified-glue"
            else -> "unknown"
        }
    }

    /** 模块宿主形态推断 */
    private fun guessRuntime(parsed: WasmParser.ParsedWasm): String {
        val names = parsed.imports.map { it.name }
        val hasEmscripten = names.any { it.startsWith("emscripten_") || it.startsWith("__cxa") }
        val hasWasi = names.any { it.startsWith("fd_") || it.startsWith("proc_") } ||
            parsed.imports.any { it.module.startsWith("wasi") }
        val hasWbindgen = names.any { it.startsWith("wbg") || it.startsWith("__wbindgen") }
        val hasGo = names.any { it == "runtime.ticks" || it.startsWith("go.") } || parsed.imports.any { it.module == "go" }
        return when {
            hasEmscripten -> "Emscripten（C/C++ 编译，含 C++ 异常运行时）"
            hasWasi -> "WASI（WASI 预览版系统接口，独立运行时）"
            hasWbindgen -> "Rust wasm-bindgen（Rust 编译，wbindgen 胶水边界）"
            hasGo -> "Go（tinygo/Golang WASM）"
            parsed.imports.isEmpty() -> "无 import（纯自包含模块，可能手写汇编或全内联）"
            else -> "JS 胶水宿主（手写 wasm 或其他工具链）"
        }
    }

    private fun buildTraceSummary(profile: ImportProfile, scanned: Int): String {
        val sb = StringBuilder()
        sb.appendLine("import 边界画像：${profile.totalImports} 个 import（func×${profile.funcImports} " +
            "memory×${profile.memoryImports} table×${profile.tableImports} global×${profile.globalImports}），" +
            "扫描 ${scanned} 个函数体")
        sb.appendLine("宿主形态推断: ${profile.runtimeGuess}")
        sb.appendLine("分类分布: ${profile.byCategory.entries.joinToString(", ") { "${it.key}×${it.value}" }}")
        val used = profile.usedImports
        if (used.isNotEmpty()) {
            sb.appendLine("热点 import（按调用次数，top ${minOf(10, used.size)}）：")
            used.take(10).forEach { u ->
                sb.appendLine("  ×${u.callCount} $u.category ${u.module}.${u.name} ← " +
                    u.callers.take(3).joinToString(", ") { c ->
                        "f${c.funcIndex}${c.funcName?.let { "($it)" } ?: ""}"
                    })
            }
        } else {
            sb.appendLine("未发现对 import 函数的直接调用（可能经 call_indirect 间接调用或模块尚未分析完整）")
        }
        if (profile.unusedImports.isNotEmpty()) {
            sb.appendLine("从未被调用的 import ×${profile.unusedImports.size}: " +
                profile.unusedImports.take(15).joinToString(", ") { "${it.module}.${it.name}" })
        }
        sb.append("下一步：对热点 import 的调用方执行 wasm.disassemble_func / wasm.ssa；" +
            "宿主注入函数（console/log 类）是 JS 侧断点/拦截的理想位置")
        return sb.toString()
    }

    // =========================================================================
    // Data 段字符串提取
    // =========================================================================

    fun extractStrings(bytes: ByteArray, minLen: Int = 4, maxStrings: Int = 400): StringsReport {
        val parsed = parser.parse(bytes)
        if (!parsed.ok) return StringsReport(false, parsed.error, emptyList(), 0, 0, "解析失败: ${parsed.error}")

        val out = mutableListOf<WasmString>()
        var bytesScanned = 0

        for ((segIdx, seg) in parsed.dataSegments.withIndex()) {
            if (seg.fileOffset < 0 || seg.length <= 0) continue
            val from = seg.fileOffset
            val to = minOf(from + seg.length, bytes.size)
            if (from >= to) continue
            bytesScanned += (to - from)

            // 提取可打印 ASCII 连续段
            val runs = extractPrintableRuns(bytes, from, to, minLen)
            for (run in runs) {
                val s = run.value
                out.add(
                    WasmString(
                        value = s.take(200),
                        segmentIndex = segIdx,
                        memoryOffset = if (seg.offset >= 0) seg.offset + run.relOffset else -1L,
                        length = s.length,
                        kind = classifyString(s),
                    ),
                )
                if (out.size >= maxStrings) break
            }
            if (out.size >= maxStrings) break
        }

        out.sortWith(compareByDescending<WasmString> { it.length })

        return StringsReport(
            ok = true,
            strings = out,
            segmentsScanned = parsed.dataSegments.size,
            bytesScanned = bytesScanned,
            summary = buildStringsSummary(out, parsed.dataSegments.size, bytesScanned),
        )
    }

    private data class Run(val value: String, val relOffset: Int)

    private fun extractPrintableRuns(bytes: ByteArray, from: Int, to: Int, minLen: Int): List<Run> {
        val runs = mutableListOf<Run>()
        val sb = StringBuilder()
        var start = -1
        for (i in from until to) {
            val c = bytes[i].toInt() and 0xff
            val printable = c in 0x20..0x7e || c == '\t'.code || c == '\n'.code
            if (printable) {
                if (start < 0) start = i
                sb.append(c.toChar())
            } else {
                if (sb.length >= minLen && start >= 0) {
                    runs.add(Run(sb.toString().trim(), start - from))
                }
                sb.setLength(0)
                start = -1
            }
        }
        if (sb.length >= minLen && start >= 0) {
            runs.add(Run(sb.toString().trim(), start - from))
        }
        return runs.filter { it.value.length >= minLen }
    }

    /** 字符串分类：url / hex / base64 / identifier / message / printable */
    private fun classifyString(s: String): String = when {
        s.startsWith("http://") || s.startsWith("https://") || s.startsWith("wss://") ||
            s.startsWith("ws://") -> "url"
        Regex("""^0[xX]?[0-9a-fA-F]{16,}$""").matches(s) -> "hex"
        Regex("""^[A-Za-z0-9+/]{16,}={0,2}$""").matches(s) -> "base64"
        Regex("""^[A-Za-z_$][A-Za-z0-9_$]*$""").matches(s) -> "identifier"
        s.contains("error") || s.contains("Error") || s.contains("fail") ||
            s.contains("invalid") || s.contains("assert") -> "message"
        s.length >= 32 && s.all { it.isLetterOrDigit() } -> "opaque-token"
        else -> "printable"
    }

    private fun buildStringsSummary(strings: List<WasmString>, segments: Int, bytesScanned: Int): String {
        if (strings.isEmpty()) {
            return "data 段无可打印字符串（$segments 段 / $bytesScanned 字节）。" +
                "可能是加密 data 段或纯二进制数据；用 wasm.dump_module 查看 data 段 hex 预览。"
        }
        val byKind = strings.groupBy { it.kind }
        val sb = StringBuilder()
        sb.appendLine("从 $segments 个 data 段（$bytesScanned 字节）提取 ${strings.size} 条字符串：" +
            byKind.entries.joinToString(", ") { "${it.key}×${it.value.size}" })
        strings.take(12).forEach { s ->
            val off = if (s.memoryOffset >= 0) "@mem 0x${s.memoryOffset.toString(16)}" else "@seg${s.segmentIndex}"
            sb.appendLine("  [$off] ${s.kind}: ${s.value.take(100)}")
        }
        sb.append("重点关注: url=请求端点, hex/base64=密钥或密文候选, identifier=符号名残留, " +
            "message=算法自检错误信息（含算法名线索）")
        return sb.toString()
    }
}
