package com.webreverse.mcp.javascript.analysis

import com.webreverse.mcp.core.common.model.TraceEvent
import com.webreverse.mcp.core.common.model.TraceKind
import com.webreverse.mcp.core.common.model.TraceSource

/**
 * 指令级 JS↔WASM provenance 。
 *
 * 目标：将静态 WASM 指令访问、ptr/len 范围、JS TypedArray、运行时 WASM export、
 * ValueFingerprint 和 Network sink 合并成一条可解释因果链。
 *
 * 这是一个保守的分析器：无法证明时返回 uncertain edge，而不是伪造确定性。
 */
class JsWasmProvenanceChain {

    data class Range(val start: Long, val end: Long) {
        val length: Long get() = if (end >= start) end - start + 1 else 0
        fun overlaps(o: Range): Boolean = start <= o.end && o.start <= end
        fun intersect(o: Range): Range? = if (overlaps(o)) Range(maxOf(start, o.start), minOf(end, o.end)) else null
    }

    data class JsTypedArrayRange(
        val variable: String,
        val type: String,
        val byteOffsetExpr: String,
        val byteLengthExpr: String,
        val line: Int,
        val confidence: Double,
        val wasmCalls: List<String> = emptyList(),
    )

    data class WasmInstruction(
        val functionIndex: Int,
        val functionName: String,
        val offset: Int,
        val opcode: Int,
        val mnemonic: String,
        /** WASM memarg offset range; actual runtime address = pointerBase + offset. */
        val memoryRange: Range? = null,
        val callTarget: Int? = null,
        val immediate: Long? = null,
        val evidence: List<String> = emptyList(),
    )

    data class PointerAlias(
        val wasmFunctionIndex: Int,
        val wasmInstructionOffset: Int,
        val range: Range,
        val source: String,
        val relation: String,
        val confidence: Double,
        val evidence: List<String>,
    )

    data class ChainNode(
        val id: String,
        val kind: String,
        val label: String,
        val detail: String = "",
        val confidence: Double = 1.0,
    )

    data class ChainEdge(
        val from: String,
        val to: String,
        val relation: String,
        val confidence: Double,
        val evidence: List<String> = emptyList(),
    )

    data class Chain(
        val nodes: List<ChainNode>,
        val edges: List<ChainEdge>,
        val endpoint: String,
        val status: String,
        val confidence: Double,
        val explanation: String,
    )

    data class Report(
        val ok: Boolean,
        val error: String = "",
        val typedArrays: List<JsTypedArrayRange> = emptyList(),
        val instructions: List<WasmInstruction> = emptyList(),
        val aliases: List<PointerAlias> = emptyList(),
        val chains: List<Chain> = emptyList(),
        val warnings: List<String> = emptyList(),
    )

    fun analyze(jsSource: String, wasmBytes: ByteArray?, events: List<TraceEvent>): Report {
        return runCatching {
            val typed = parseTypedArrays(jsSource)
            val instructions = if (wasmBytes != null && wasmBytes.size >= 8) scanInstructions(wasmBytes) else emptyList()
            val exportEvents = events.filter { it.source == TraceSource.WASM && it.kind == TraceKind.WASM_EXPORT }
            val requestEvents = events.filter { it.source == TraceSource.NETWORK && it.kind == TraceKind.REQUEST }
            val aliases = buildAliases(typed, exportEvents, instructions)
            val chains = buildChains(typed, aliases, exportEvents, requestEvents)
            Report(true, typedArrays = typed, instructions = instructions.take(50_000), aliases = aliases.take(50_000), chains = chains.take(2_000), warnings = warnings(typed, instructions, exportEvents, requestEvents))
        }.getOrElse { Report(false, error = it.message ?: "JS-WASM provenance failed") }
    }

    private fun parseTypedArrays(source: String): List<JsTypedArrayRange> {
        val out = mutableListOf<JsTypedArrayRange>()
        val lines = source.lines()
        val re1 = Regex("(?:const|let|var)\\s+(\\w+)\\s*=\\s*new\\s+(Uint8Array|Uint16Array|Uint32Array|Int8Array|Int16Array|Int32Array|Float32Array|Float64Array)\\s*\\(([^)]*)\\)")
        val re2 = Regex("(\\w+)\\s*=\\s*(\\w+)\\.subarray\\s*\\(([^)]*)\\)")
        lines.forEachIndexed { idx, line ->
            re1.findAll(line).forEach { m ->
                val args = m.groupValues[3].split(',').map { it.trim() }
                val offset = when {
                    args.size >= 2 -> args[1]
                    else -> "0"
                }
                val len = when {
                    args.size >= 3 -> args[2]
                    args.size == 2 -> args[1]
                    else -> args.firstOrNull() ?: "unknown"
                }
                val type = m.groupValues[2]
                out += JsTypedArrayRange(m.groupValues[1], type, offset, len, idx + 1, 0.94)
            }
            re2.findAll(line).forEach { m ->
                val args = m.groupValues[3].split(',').map { it.trim() }
                val start = args.firstOrNull() ?: "0"
                val end = args.getOrNull(1) ?: "length"
                out += JsTypedArrayRange(m.groupValues[1], "subarray(${m.groupValues[2]})", start, end, idx + 1, 0.84)
            }
        }
        val calls = Regex("""(?:\b(?:instance|wasm|exports|module|instance\.exports)\s*\.)?(\w+)\s*\.\s*(\w+)\s*\(([^)]*)\)""")
        return out.distinctBy { "${it.variable}:${it.line}" }.map { t ->
            val names = lines.flatMap { line -> calls.findAll(line).filter { m -> m.groupValues[3].split(',').any { a -> a.trim().startsWith(t.variable) } }.map { it.groupValues[2] }.toList() }.distinct()
            t.copy(wasmCalls = names.take(16))
        }
    }

    private fun buildAliases(
        typed: List<JsTypedArrayRange>,
        exports: List<TraceEvent>,
        instructions: List<WasmInstruction>,
    ): List<PointerAlias> {
        val out = mutableListOf<PointerAlias>()
        for (e in exports) {
            val memStart = e.meta["memoryStart"]?.toLongOrNull()
            val memEnd = e.meta["memoryEnd"]?.toLongOrNull()
            val ptr0 = e.meta["ptr0"]?.toLongOrNull()
            val len0 = e.meta["len0"]?.toLongOrNull()
            val start = memStart ?: ptr0 ?: continue
            val end = memEnd ?: (if (len0 != null && len0 > 0) start + len0 - 1 else null) ?: continue
            val runtimeRange = Range(start, end)
            val matches = instructions.filter { ins -> ins.memoryRange?.let { r -> Range(start + r.start, start + r.end).overlaps(runtimeRange) } == true }.take(256)
            for (ins in matches) {
                val mapped = ins.memoryRange?.let { Range(start + it.start, start + it.end) } ?: runtimeRange
                out += PointerAlias(ins.functionIndex, ins.offset, mapped, e.name, "RUNTIME_EXPORT_TO_INSTRUCTION", 0.94,
                    listOf("runtime memory range", "instruction ${ins.mnemonic} @0x${ins.offset.toString(16)}"))
            }
        }
        if (typed.isNotEmpty()) {
            for (t in typed) {
                out += PointerAlias(-1, -1, Range(0, 0), t.variable, "JS_TYPED_ARRAY_SITE", t.confidence,
                    listOf("TypedArray constructor", "line ${t.line}", "offset=${t.byteOffsetExpr}", "length=${t.byteLengthExpr}"))
            }
        }
        return out
    }

    private fun buildChains(
        typed: List<JsTypedArrayRange>,
        aliases: List<PointerAlias>,
        exports: List<TraceEvent>,
        requests: List<TraceEvent>,
    ): List<Chain> {
        val out = mutableListOf<Chain>()
        for (e in exports) {
            val outputFp = sequenceOf(e.output?.fingerprint.orEmpty(), e.meta["memoryFingerprintAfter"].orEmpty(), e.meta["memoryFingerprint"].orEmpty(), e.meta["memoryFingerprintBefore"].orEmpty()).firstOrNull { it.isNotBlank() }.orEmpty()
            val memoryStart = e.meta["memoryStart"]?.toLongOrNull() ?: e.meta["ptr0"]?.toLongOrNull()
            val memoryEnd = e.meta["memoryEnd"]?.toLongOrNull() ?: e.meta["len0"]?.toLongOrNull()?.let { l -> memoryStart?.plus(l - 1) }
            val nodes = mutableListOf<ChainNode>()
            val edges = mutableListOf<ChainEdge>()
            val exportId = "wasm:${e.seq}"
            nodes += ChainNode(exportId, "WASM_EXPORT", e.name, "seq=${e.seq}", 1.0)
            var bestReq: TraceEvent? = null
            var bestScore = 0.0
            if (!outputFp.isNullOrBlank()) {
                for (r in requests) {
                    val score = requestFingerprintScore(outputFp, r)
                    if (score > bestScore) { bestScore = score; bestReq = r }
                }
            }
            if (bestReq != null) {
                val reqId = "net:${bestReq.seq}"
                nodes += ChainNode(reqId, "NETWORK_SINK", bestReq.name, "${bestReq.meta["method"] ?: ""} ${bestReq.name}", bestScore)
                edges += ChainEdge(exportId, reqId, "OUTPUT_TO_NETWORK", bestScore, listOf("fingerprint match", "time=${kotlin.math.abs(bestReq.ts - e.ts)}ms"))
            }
            val aliasMatches = if (memoryStart != null && memoryEnd != null) aliases.filter { it.range.overlaps(Range(memoryStart, memoryEnd)) } else emptyList()
            for (a in aliasMatches.take(16)) {
                val id = "wasm-ins:${a.wasmFunctionIndex}:${a.wasmInstructionOffset}"
                nodes += ChainNode(id, "WASM_INSTRUCTION", "func${a.wasmFunctionIndex}@0x${a.wasmInstructionOffset.toString(16)}", a.relation, a.confidence)
                edges += ChainEdge(id, exportId, "REACHES_EXPORT_MEMORY", a.confidence, a.evidence)
            }
            if (typed.isNotEmpty()) {
                val ta = typed.minByOrNull { kotlin.math.abs(it.line - e.line).toLong() } ?: typed.first()
                val id = "js-typed:${ta.variable}:${ta.line}"
                nodes += ChainNode(id, "JS_TYPED_ARRAY", ta.variable, "${ta.type} offset=${ta.byteOffsetExpr} len=${ta.byteLengthExpr}; calls=${ta.wasmCalls.joinToString(",")}", ta.confidence)
                val callBoost = if (ta.wasmCalls.any { it == e.name }) 0.96 else minOf(ta.confidence, 0.82)
                edges += ChainEdge(id, exportId, "TYPED_ARRAY_TO_WASM", callBoost, listOf("static JS/WASM boundary", if (ta.wasmCalls.any { it == e.name }) "typed-array passed to export" else "nearest source line"))
            }
            val conf = chainConfidence(edges, bestScore)
            val status = when {
                bestReq == null -> "PARTIAL_WASM_TRACE"
                conf >= 0.90 -> "VALIDATED_CHAIN_CANDIDATE"
                conf >= 0.70 -> "LIKELY_CHAIN"
                else -> "WEAK_CHAIN"
            }
            out += Chain(nodes.distinctBy { it.id }, edges.distinctBy { "${it.from}|${it.to}|${it.relation}" }, bestReq?.name ?: "", status, conf,
                "${e.name} 输出经过 WASM memory provenance，并${if (bestReq != null) "回流到网络请求" else "尚未找到网络 sink"}。")
        }
        return out.sortedByDescending { it.confidence }
    }

    private fun requestFingerprintScore(fp: String, req: TraceEvent): Double {
        if (fp.isBlank()) return 0.0
        val direct = req.values.any { it.fingerprint == fp }
        val header = req.values.firstOrNull { it.label.equals("fpHeaders", true) }
        val body = req.values.firstOrNull { it.label.equals("fpBody", true) }
        val perHeader = req.values.any { it.label.startsWith("fpHeader_", true) && it.fingerprint == fp }
        return when {
            perHeader -> 0.995
            direct -> 0.98
            header?.fingerprint == fp -> 0.99
            body?.fingerprint == fp -> 0.98
            else -> 0.0
        }
    }

    private fun chainConfidence(edges: List<ChainEdge>, reqScore: Double): Double {
        if (edges.isEmpty()) return 0.0
        val avg = edges.map { it.confidence }.average()
        return ((avg * 0.55) + (reqScore * 0.45)).coerceIn(0.0, 1.0)
    }

    private fun warnings(typed: List<JsTypedArrayRange>, instructions: List<WasmInstruction>, exports: List<TraceEvent>, requests: List<TraceEvent>): List<String> = buildList {
        if (typed.isEmpty()) add("未识别明确的 JS TypedArray 构造/切片，建议动态追踪 ArrayBuffer/TypedArray。")
        if (instructions.isEmpty()) add("没有可解析的 WASM 指令；当前链只能依赖 runtime Trace。")
        if (exports.isEmpty()) add("没有 WASM_EXPORT Trace；请在 WASM 实例创建前安装 runtime WASM tracing。")
        if (requests.isEmpty()) add("没有网络请求 Trace；无法完成输出回流到 Network sink。")
        if (exports.isNotEmpty() && requests.isNotEmpty() && exports.none { e -> e.output?.fingerprint?.isNotBlank() == true }) add("WASM export 缺少返回值 fingerprint，网络回流需要补充 runtime output capture。")
    }

    // ---------- WASM instruction scanner ----------

    private fun scanInstructions(bytes: ByteArray): List<WasmInstruction> {
        val p = WasmParser().parse(bytes)
        if (!p.ok) return emptyList()
        val imported = p.imports.count { it.kind == "func" }
        val codeSections = locateCodeBodies(bytes)
        val out = mutableListOf<WasmInstruction>()
        codeSections.forEachIndexed { localIdx, body ->
            val fi = imported + localIdx
            val name = p.functionNames[fi] ?: "func_$fi"
            var pos = body.first
            val locals = readLocalDeclBytes(bytes, pos)
            pos += locals
            while (pos < body.second) {
                val off = pos
                val op = bytes[pos].toInt() and 0xff
                pos++
                val parsed = parseImmediate(bytes, pos, body.second, op)
                pos = parsed.next
                val mnemonic = opcodeName(op)
                val range = parsed.memRange
                out += WasmInstruction(fi, name, off, op, mnemonic, range, parsed.callTarget, parsed.immediate, parsed.evidence)
                if (op == 0x0b && pos >= body.second) break
            }
        }
        return out
    }

    private fun locateCodeBodies(bytes: ByteArray): List<Pair<Int, Int>> {
        var pos = 8
        while (pos < bytes.size) {
            val id = bytes[pos].toInt() and 0xff; pos++
            val (size, len) = readU32(bytes, pos); pos += len
            val end = pos + size.toInt()
            if (end > bytes.size) return emptyList()
            if (id == 10) {
                val (n, nb) = readU32(bytes, pos); var p = pos + nb; val out = mutableListOf<Pair<Int,Int>>()
                repeat(n.toInt()) {
                    val (bs, bb) = readU32(bytes, p); p += bb
                    out += p to (p + bs.toInt()); p += bs.toInt()
                }
                return out
            }
            pos = end
        }
        return emptyList()
    }

    private fun readLocalDeclBytes(bytes: ByteArray, from: Int): Int {
        val (groups, gb) = readU32(bytes, from); var p = from + gb
        repeat(groups.toInt()) { val (_, cb) = readU32(bytes, p); p += cb + 1 }
        return p - from
    }

    private data class ImmediateResult(val next: Int, val memRange: Range? = null, val callTarget: Int? = null, val immediate: Long? = null, val evidence: List<String> = emptyList())

    private fun parseImmediate(b: ByteArray, from: Int, end: Int, op: Int): ImmediateResult {
        var p = from
        fun u(): Long { val r = readU32(b, p); p += r.second; return r.first }
        fun s(): Long { val r = readS64(b, p); p += r.second; return r.first }
        if (op == 0x28 || op == 0x29 || op == 0x2a || op == 0x2b || op == 0x2c || op == 0x2d || op == 0x2e || op == 0x2f || op == 0x30 || op == 0x31 || op == 0x32 || op == 0x33 || op == 0x34 || op == 0x35 || op == 0x36 || op == 0x37 || op == 0x38 || op == 0x39 || op == 0x3a || op == 0x3b || op == 0x3c || op == 0x3d || op == 0x3e) {
            val align = u(); val off = u(); val width = when (op) { 0x2c,0x2d,0x30,0x31,0x3a,0x3c -> 1; 0x2e,0x2f,0x32,0x33,0x3b,0x3d -> 2; 0x34,0x35,0x3e -> 4; 0x29,0x2b,0x37,0x39 -> 8; else -> 4 }
            return ImmediateResult(p, Range(off, off + width - 1), evidence = listOf("align=$align", "memarg.offset=$off"))
        }
        return when (op) {
            0x10 -> { val t = u(); ImmediateResult(p, callTarget=t.toInt(), immediate=t, evidence=listOf("direct call")) }
            0x11 -> { u(); u(); ImmediateResult(p, evidence=listOf("call_indirect")) }
            0x0c,0x0d,0x0e -> { val v=u(); if (op==0x0e) repeat(v.toInt()+1){u()}; ImmediateResult(p, immediate=v) }
            0x20,0x21,0x22,0x23,0x24,0x41 -> { val v = if (op == 0x41) s() else u(); ImmediateResult(p, immediate=v) }
            0x3f,0x40 -> { u(); ImmediateResult(p) }
            0x42 -> { val v=s(); ImmediateResult(p, immediate=v) }
            0x43 -> ImmediateResult((p+4).coerceAtMost(end), immediate=0)
            0x44 -> ImmediateResult((p+8).coerceAtMost(end), immediate=0)
            0x02,0x03,0x04 -> ImmediateResult(p+1)
            0xfc,0xfd,0xfb -> { val sub=u(); ImmediateResult(p, immediate=sub, evidence=listOf("prefixed opcode")) }
            else -> ImmediateResult(p)
        }
    }

    private fun readU32(b: ByteArray, from: Int): Pair<Long, Int> { var v=0L; var shift=0; var i=from; while(i<b.size){ val x=b[i].toInt() and 255; v = v or ((x and 127).toLong() shl shift); i++; if(x and 128==0) break; shift+=7; if(shift>35) break }; return v to (i-from) }
    private fun readS64(b: ByteArray, from: Int): Pair<Long, Int> { var v=0L; var shift=0; var i=from; var x=0; while(i<b.size){ x=b[i].toInt() and 255; v = v or ((x and 127).toLong() shl shift); i++; shift+=7; if(x and 128==0) break; if(shift>63) break }; if(shift<64 && x and 64 != 0) v = v or (-1L shl shift); return v to (i-from) }

    private fun opcodeName(op: Int): String = opcodeNames[op] ?: "unknown_0x${op.toString(16)}"

    private val opcodeNames = mapOf(
        0x00 to "unreachable",0x01 to "nop",0x02 to "block",0x03 to "loop",0x04 to "if",0x05 to "else",0x0b to "end",0x0c to "br",0x0d to "br_if",0x0e to "br_table",0x0f to "return",0x10 to "call",0x11 to "call_indirect",
        0x20 to "local.get",0x21 to "local.set",0x22 to "local.tee",0x23 to "global.get",0x24 to "global.set",
        0x28 to "i32.load",0x29 to "i64.load",0x2a to "f32.load",0x2b to "f64.load",0x2c to "i32.load8_s",0x2d to "i32.load8_u",0x2e to "i32.load16_s",0x2f to "i32.load16_u",0x30 to "i64.load8_s",0x31 to "i64.load8_u",0x32 to "i64.load16_s",0x33 to "i64.load16_u",0x34 to "i64.load32_s",0x35 to "i64.load32_u",
        0x36 to "i32.store",0x37 to "i64.store",0x38 to "f32.store",0x39 to "f64.store",0x3a to "i32.store8",0x3b to "i32.store16",0x3c to "i64.store8",0x3d to "i64.store16",0x3e to "i64.store32",
        0x3f to "memory.size",0x40 to "memory.grow",0x41 to "i32.const",0x42 to "i64.const",0x43 to "f32.const",0x44 to "f64.const"
    )
}
