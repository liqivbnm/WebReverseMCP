package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import com.webreverse.mcp.javascript.analysis.JsvmpDeepAnalyzer
import com.webreverse.mcp.javascript.analysis.VmpDetector
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * JSVMP 运行时桥接工具（静态 ←→ 运行时打通 第 1 块）。
 *
 * 背景：静态恢复链（VmpDetector → JsvmpDeepAnalyzer → Micro-IR/语义签名）已经很强，
 * 但真实站点上字节码数组几乎总是被 XOR / key 表 / 编码保护——静态 ISA 表描述的是
 * 「解码后」的世界，与页面上「加密态」的字节码数组对不上。
 *
 * jsvmp.bytecode_dump 补上这条通道：
 * 1. 字节码来源三选一：直接 base64 bytes > 页面表达式 bytecodeExpr >
 *    静态分析 bytecodeCandidates 逐个在页面求值探测；
 * 2. 解码：none / 单字节 XOR / key 表达式循环 XOR / auto（枚举 0-255 评分排序）；
 * 3. 对照：把解码候选与静态 ISA opcode 集合做命中率评分，输出每个候选的
 *    熵 / 低值占比 / ISA 命中 / top 值直方图，dump 前 N 条指令流并按 ISA 标注语义。
 *
 * 断点暂停态提示：字节码数组若是 VM 函数局部变量，全局求值不可达——
 * 先 debugger.pause 命中断点，再用 debugger.evaluate_on_call_frame 把数组
 * base64 后经 `bytes` 参数传入（或直接传 `JSON.stringify(Array.from(arr))` 的 base64）。
 */
object JsvmpRuntimeTools {

    private const val ISA_DUMP_WIDTH = 16

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)

        return listOf(
            f.tool(
                "jsvmp.bytecode_dump",
                "JSVMP 字节码运行时解码 dump：从页面拉取（或离线传入）VM 字节码数组，自动/指定解码" +
                    "（单字节 XOR / key 表循环 XOR / auto 枚举 0-255 评分），输出指令流 hex dump + opcode 频率直方图 + " +
                    "与静态 ISA 表（jsvmp.analyze 的 handlers）的命中率对照——把静态恢复语义与真实执行流打通。" +
                    "静态候选自动探测：传 source/scriptId 时自动尝试 bytecodeCandidates 变量名在页面求值",
                ToolCategory.REVERSE,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM, timeoutMs = 120_000,
                inputSchema = Schemas.objectSchema(
                    "source" to Schemas.strSchema("JS 源码（优先；用于静态分析定位字节码变量名 + ISA 对照）"),
                    "scriptId" to Schemas.strSchema("脚本 ID（来自 debugger.list_scripts；与 source 二选一）"),
                    "bytecodeExpr" to Schemas.strSchema("页面内字节码数组表达式（如 _0x3a1f 或 window.__bc；优先于静态候选探测）"),
                    "bytes" to Schemas.strSchema("直接传入字节码（base64 或 hex；离线模式，不经页面）"),
                    "keyExpr" to Schemas.strSchema("解码 key 数组的页面表达式（循环 XOR key；decode=xor_key 时必填）"),
                    "xorKey" to Schemas.intSchema("单字节 XOR key（0-255；decode=xor 时使用）", min = 0, max = 255),
                    "decode" to Schemas.enumSchema(
                        "解码模式：none=原样；xor=单字节 XOR；xor_key=key 表循环 XOR；auto=枚举 identity+256 key 按 ISA 命中评分",
                        "auto", "none", "xor", "xor_key",
                    ),
                    "maxDump" to Schemas.intSchema("指令流 dump 条数上限（默认 256，最多 4096）", min = 1, max = 4096),
                    "maxElements" to Schemas.intSchema("页面拉取数组长度上限（默认 400 万）", min = 1),
                ),
            ) { args ->
                val inlineSource = ToolArgs.str(args, "source")
                val scriptId = ToolArgs.str(args, "scriptId")
                val bytecodeExpr = ToolArgs.str(args, "bytecodeExpr")
                val bytesArg = ToolArgs.str(args, "bytes")
                val keyExpr = ToolArgs.str(args, "keyExpr")
                val xorKey = ToolArgs.int(args, "xorKey", -1)
                val decode = ToolArgs.str(args, "decode", "auto").lowercase()
                val maxDump = ToolArgs.int(args, "maxDump", 256).coerceIn(1, 4096)
                val maxElements = ToolArgs.int(args, "maxElements", 4_000_000)

                val session = deps.activeSession()
                val engine = session.engine

                // ---------- 1) 静态分析（可选）：字节码候选 + ISA opcode 集合 ----------
                var staticSource: String? = null
                var staticUrl = "inline"
                var isaOps: Map<Int, String> = emptyMap() // opcode 值 -> 语义显示
                var staticCandidates: List<String> = emptyList()
                var carrierType = "unknown"
                if (inlineSource.isNotBlank() || scriptId.isNotBlank()) {
                    if (deps.debuggerManager.backend != "cdp" && inlineSource.isBlank()) {
                        val s = deps.activeSession()
                        deps.debuggerManager.attach(s.engine)
                    }
                    val resolved = if (inlineSource.isNotBlank()) {
                        Triple(inlineSource, "inline", "inline")
                    } else {
                        VmpToolsAccess.resolveSource(deps, scriptId)
                    }
                    if (resolved != null) {
                        val (src, _, url) = resolved
                        staticSource = src
                        staticUrl = url
                        val candidates = VmpDetector().detect(src)
                        val candidate = candidates.firstOrNull()
                        if (candidate != null) {
                            val profile = JsvmpDeepAnalyzer().analyze(src, candidate)
                            isaOps = parseIsaOpcodes(profile.handlers.map { it.key to it.kind.display })
                            staticCandidates = profile.variables.bytecodeCandidates
                            carrierType = profile.instructions.carrierType
                        }
                    }
                }

                // ---------- 2) 解析字节数据来源 ----------
                var rawBytes: ByteArray? = null
                var origin = ""
                var pullWarn: String? = null
                when {
                    bytesArg.isNotBlank() -> {
                        rawBytes = decodeBytesArg(bytesArg)
                            ?: return@tool McpToolResult.error(
                                "DECODE_FAILED",
                                "bytes 参数解码失败（仅支持 base64 或 hex 字符串）",
                            )
                        origin = "inline(bytes)"
                    }
                    bytecodeExpr.isNotBlank() -> {
                        val pulled = RuntimeCaptureBridge.pullArrayChunked(engine, bytecodeExpr, maxElements)
                        if (pulled == null) {
                            return@tool McpToolResult.error(
                                "PULL_FAILED",
                                RuntimeCaptureBridge.lastPullError ?: "字节码数组拉取失败",
                            )
                        }
                        rawBytes = pulled.bytes
                        origin = "page:$bytecodeExpr"
                        if (pulled.truncated) pullWarn = "数组被截断到 ${pulled.bytes.size}/${pulled.declaredLength} 元素"
                    }
                    else -> {
                        // 静态候选逐个在页面探测（可达的全局变量 / 闭包泄漏的全局）
                        if (staticCandidates.isEmpty()) {
                            return@tool McpToolResult.error(
                                "NO_SOURCE_OR_EXPR",
                                "未指定 bytecodeExpr/bytes 且静态分析未给出字节码数组候选；" +
                                    "先传 source/scriptId 跑静态分析，或直接给 bytecodeExpr/bytes",
                            )
                        }
                        var lastErr: String? = null
                        for (cand in staticCandidates.take(8)) {
                            val expr = cand.removePrefix("var ").removePrefix("let ").removePrefix("const ")
                                .substringBefore(' ').trim()
                            if (expr.isBlank() || !Regex("^[A-Za-z_$][\\w$]*$").matches(expr)) continue
                            val pulled = RuntimeCaptureBridge.pullArrayChunked(
                                engine,
                                "(typeof $expr !== 'undefined' && $expr && $expr.length !== undefined && " +
                                    "(typeof $expr[0] === 'number' || typeof $expr[0] === 'string') ? $expr : [])",
                                maxElements,
                            )
                            if (pulled != null && pulled.bytes.isNotEmpty()) {
                                rawBytes = pulled.bytes
                                origin = "page:$expr (静态候选探测命中)"
                                if (pulled.truncated) pullWarn = "数组被截断到 ${pulled.bytes.size}/${pulled.declaredLength} 元素"
                                break
                            }
                            lastErr = RuntimeCaptureBridge.lastPullError
                        }
                        if (rawBytes == null) {
                            return@tool McpToolResult.error(
                                "CANDIDATES_UNREACHABLE",
                                "静态候选 ${staticCandidates.take(8)} 在页面全局均不可达（可能是 VM 函数局部变量）。" +
                                    "提示：命中断点后用 debugger_evaluate_on_call_frame 取数组，" +
                                    "把 base64 结果经 bytes 参数传入",
                            )
                        }
                    }
                }
                val bytes0 = rawBytes ?: ByteArray(0)

                // keyExpr：页面拉取 key 表
                var keyTable: IntArray? = null
                if (decode == "xor_key") {
                    if (keyExpr.isBlank()) {
                        return@tool McpToolResult.error("INVALID_ARGS", "decode=xor_key 需要 keyExpr（key 数组的页面表达式）")
                    }
                    val pulled = RuntimeCaptureBridge.pullArrayChunked(engine, keyExpr, 65536)
                        ?: return@tool McpToolResult.error(
                            "KEY_PULL_FAILED",
                            RuntimeCaptureBridge.lastPullError ?: "key 表拉取失败",
                        )
                    keyTable = IntArray(pulled.bytes.size) { pulled.bytes[it].toInt() and 0xFF }
                }

                // ---------- 3) 解码候选生成 ----------
                data class Candidate(
                    val label: String,
                    val bytes: ByteArray,
                    val score: Double,
                    val isaHit: Double,
                    val entropy: Double,
                    val lowValRatio: Double,
                    val top: List<Pair<Int, Int>>, // (value, count)
                )

                fun stats(b: ByteArray): Candidate? {
                    if (b.isEmpty()) return null
                    val hist = IntArray(256)
                    for (x in b) hist[x.toInt() and 0xFF]++
                    var isaHitCnt = 0
                    if (isaOps.isNotEmpty()) {
                        val limit = minOf(b.size, 8192)
                        for (i in 0 until limit) if (isaOps.containsKey(b[i].toInt() and 0xFF)) isaHitCnt++
                    }
                    val isaHit = if (isaOps.isEmpty()) 0.0 else isaHitCnt.toDouble() / limit(b.size)
                    val entropy = shannonEntropy(hist, b.size)
                    val lowVal = hist.indices.filter { it < 0x40 }.sumOf { hist[it] }.toDouble() / b.size
                    val top = hist.withIndex().filter { it.value > 0 }
                        .sortedByDescending { it.value }.take(8)
                        .map { it.index to it.value }
                    val score = isaOps.keys.let { isaHit * 0.6 + lowVal * 0.3 + (1.0 - (entropy / 8.0)) * 0.1 }
                    return Candidate("placeholder", b, score, isaHit, entropy, lowVal, top)
                }

                val candidates = mutableListOf<Candidate>()
                when (decode) {
                    "none" -> stats(bytes0)?.let { candidates += it.copy(label = "identity(原样)") }
                    "xor" -> {
                        if (xorKey !in 0..255) return@tool McpToolResult.error("INVALID_ARGS", "decode=xor 需要 xorKey(0-255)")
                        candidates += stats(xor(bytes0, xorKey))!!.copy(label = "xor(0x${"%02x".format(xorKey)})")
                    }
                    "xor_key" -> candidates += stats(xorKeyTable(bytes0, keyTable!!))!!.copy(label = "xor_key(${keyExpr.take(40)})")
                    else -> { // auto：identity + 全枚举
                        stats(bytes0)?.let { candidates += it.copy(label = "identity(原样)") }
                        for (k in 1..255) {
                            val c = stats(xor(bytes0, k)) ?: continue
                            candidates += c.copy(label = "xor(0x${"%02x".format(k)})")
                        }
                    }
                }
                val ranked = candidates.sortedByDescending { it.score }
                if (ranked.isEmpty()) {
                    return@tool McpToolResult.error("EMPTY_BYTES", "字节码数据为空")
                }
                val best = ranked.first()

                // ---------- 4) 输出：候选对比 + 最佳候选 dump ----------
                val isaLabel: (Int) -> String? = { v -> isaOps[v] }
                McpToolResult.json(
                    buildJsonObject {
                        put("scriptUrl", JsonPrimitive(staticUrl))
                        put("origin", JsonPrimitive(origin))
                        put("carrierType", JsonPrimitive(carrierType))
                        put("byteLength", JsonPrimitive(bytes0.size))
                        if (pullWarn != null) put("warning", JsonPrimitive(pullWarn))
                        if (staticCandidates.isNotEmpty()) {
                            put("staticBytecodeCandidates", JsonArray(staticCandidates.take(8).map { JsonPrimitive(it) }))
                        }
                        put("isaTableSize", JsonPrimitive(isaOps.size))
                        put("decodeMode", JsonPrimitive(decode))
                        put("candidates", JsonArray(
                            ranked.take(if (decode == "auto") 8 else 1).map { c ->
                                buildJsonObject {
                                    put("label", JsonPrimitive(c.label))
                                    put("score", JsonPrimitive((c.score * 1000).toInt() / 1000.0))
                                    put("isaHitRate", JsonPrimitive((c.isaHit * 1000).toInt() / 1000.0))
                                    put("entropy", JsonPrimitive((c.entropy * 1000).toInt() / 1000.0))
                                    put("lowValRatio", JsonPrimitive((c.lowValRatio * 1000).toInt() / 1000.0))
                                    put("topValues", JsonArray(c.top.map { (v, n) ->
                                        buildJsonObject {
                                            put("v", JsonPrimitive(v))
                                            put("hex", JsonPrimitive("0x${"%02x".format(v)}"))
                                            put("n", JsonPrimitive(n))
                                            isaLabel(v)?.let { put("isa", JsonPrimitive(it)) }
                                        }
                                    }))
                                }
                            },
                        ))
                        put("best", buildJsonObject {
                            put("label", JsonPrimitive(best.label))
                            put("hexDump", JsonPrimitive(hexDump(best.bytes, maxDump, isaOps)))
                            put("opcodeHistogram", JsonArray(
                                histogramOf(best.bytes).map { (v, n) ->
                                    buildJsonObject {
                                        put("hex", JsonPrimitive("0x${"%02x".format(v)}"))
                                        put("n", JsonPrimitive(n))
                                        put("pct", JsonPrimitive((n * 10000 / best.bytes.size) / 100.0))
                                        isaLabel(v)?.let { put("isa", JsonPrimitive(it)) }
                                    }
                                },
                            ))
                        })
                        put(
                            "nextSteps",
                            JsonArray(
                                listOf(
                                    "对照 jsvmp.analyze 的 ISA 表核对该候选是否合理（opcode 命中率 >0.3 通常是正确 key）",
                                    "把 dump 的指令流与 jsvmp.ir 的 Micro-IR 归一指令对齐，定位入口 opcode 与 pc 起点",
                                    "确定 key 后可用 decode=xor 固定重放；字节码含操作数时频率直方图会多峰，属正常",
                                ).map { JsonPrimitive(it) }
                            ),
                        )
                    },
                )
            },
        )
    }

    // ---------------- 内部工具 ----------------

    private fun limit(size: Int) = if (size <= 0) 1 else size

    private fun xor(bytes: ByteArray, key: Int): ByteArray {
        val k = key and 0xFF
        val out = ByteArray(bytes.size)
        for (i in bytes.indices) out[i] = (bytes[i].toInt() xor k).toByte()
        return out
    }

    private fun xorKeyTable(bytes: ByteArray, key: IntArray): ByteArray {
        if (key.isEmpty()) return bytes
        val out = ByteArray(bytes.size)
        for (i in bytes.indices) out[i] = (bytes[i].toInt() xor key[i % key.size]).toByte()
        return out
    }

    private fun shannonEntropy(hist: IntArray, total: Int): Double {
        if (total <= 0) return 0.0
        var h = 0.0
        for (c in hist) {
            if (c == 0) continue
            val p = c.toDouble() / total
            h -= p * (Math.log(p) / Math.log(2.0))
        }
        return h
    }

    private fun histogramOf(bytes: ByteArray): List<Pair<Int, Int>> {
        val hist = IntArray(256)
        for (x in bytes) hist[x.toInt() and 0xFF]++
        return hist.withIndex().filter { it.value > 0 }.sortedByDescending { it.value }.map { it.index to it.value }
    }

    /** 解析静态 ISA：handler key（"0x1a"/"26"/"'a'"）-> opcode 值 */
    private fun parseIsaOpcodes(entries: List<Pair<String, String>>): Map<Int, String> {
        val out = mutableMapOf<Int, String>()
        for ((key, display) in entries) {
            val v = key.trim().removePrefix("'").removeSuffix("'").removePrefix("\"").removeSuffix("\"")
            val num = when {
                v.startsWith("0x") || v.startsWith("0X") -> v.removePrefix("0x").removePrefix("0X").toIntOrNull(16)
                v.all { it.isDigit() } -> v.toIntOrNull()
                v.length == 1 -> v[0].code // 字符 opcode（switch('a')）
                else -> null
            } ?: continue
            if (num in 0..255) out.putIfAbsent(num, display)
        }
        return out
    }

    /** hex dump：每行 16 字节，ISA 已知 opcode 用 [] 标注 */
    private fun hexDump(bytes: ByteArray, maxLines: Int, isaOps: Map<Int, String>): String {
        val rows = minOf((bytes.size + ISA_DUMP_WIDTH - 1) / ISA_DUMP_WIDTH, maxLines)
        val sb = StringBuilder()
        for (r in 0 until rows) {
            val start = r * ISA_DUMP_WIDTH
            val end = minOf(start + ISA_DUMP_WIDTH, bytes.size)
            sb.append("%08x".format(start)).append("  ")
            val ascii = StringBuilder()
            for (i in start until end) {
                val v = bytes[i].toInt() and 0xFF
                sb.append("%02x ".format(v))
                ascii.append(if (v in 0x20..0x7e) v.toChar() else '.')
            }
            if (end - start < ISA_DUMP_WIDTH) repeat(ISA_DUMP_WIDTH - (end - start)) { sb.append("   ") }
            // 行尾 ISA 标注（该行内已知 opcode）
            val marks = (start until end).map { bytes[it].toInt() and 0xFF }
                .mapNotNull { v -> isaOps[v]?.let { "0x${"%02x".format(v)}=$it" } }
                .distinct().take(4)
            sb.append(" |").append(ascii).append("|")
            if (marks.isNotEmpty()) sb.append("  [").append(marks.joinToString(", ")).append("]")
            sb.append('\n')
        }
        if (bytes.size > rows * ISA_DUMP_WIDTH) {
            sb.append("... 共 ${bytes.size} 字节，已截断（调大 maxDump 查看更多）")
        }
        return sb.toString()
    }

    private fun decodeBytesArg(arg: String): ByteArray? {
        val s = arg.trim()
        return when {
            s.isEmpty() -> null
            Regex("^[0-9a-fA-F\\s]+$").matches(s) && (s.length % 2 == 0) ->
                s.replace("\\s".toRegex(), "").chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            else -> runCatching { android.util.Base64.decode(s, android.util.Base64.DEFAULT) }.getOrNull()
        }
    }
}

/**
 * 访问 VmpTools 的私有 resolveSource（跨工具复用，避免复制）。
 * Kotlin object 的 private 成员对同文件可见性不足，用 internal 桥接对象中转。
 */
object VmpToolsAccess {
    suspend fun resolveSource(deps: ToolDependencies, scriptId: String): Triple<String, String, String>? {
        if (deps.debuggerManager.backend != "cdp") return null
        val session = deps.activeSession()
        val scripts = deps.debuggerManager.listScripts(session.engine)
            .filter { it.url.isNotBlank() && it.length > 1000 }
        val target = if (scriptId.isNotBlank()) {
            scripts.firstOrNull { it.scriptId == scriptId }
        } else {
            scripts.maxByOrNull { it.length }
        } ?: return null
        val source = deps.debuggerManager.getScriptSource(session.engine, target.scriptId, 4_000_000).getOrNull()
            ?: return null
        return Triple(source, target.scriptId, target.url)
    }
}
