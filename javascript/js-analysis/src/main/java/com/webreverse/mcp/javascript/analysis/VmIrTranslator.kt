package com.webreverse.mcp.javascript.analysis

/**
 * 通用反虚拟机 IR 翻译器 v1（JSVMP 平台无关指令归一）。
 * 将具体 VM 的 opcode 按其 handler 语义归一到平台无关 IR 助记符
 * （LD/ST/ADD/SUB/XOR/MOV/JMP/CJMP/CALL/RET/PUSH/POP/STR2CHAR 等），
 * 输出等价表、派发矩阵与归一指令流。纯 Kotlin 无新增依赖。
 */
class VmIrTranslator {

    // ---------------- 数据模型 ----------------

    /**
     * 平台无关 IR 指令流元素：`pc`（归一后字节码下标） +
     * `originalOp`（载体原始 opcode 值） + `mnemonic`（IR 助记符） +
     * `operands`（按 opcode arity 切出的内联操作数）。
     */
    data class IrIns(
        val pc: Int,
        val originalOp: Int,
        val mnemonic: String,
        val operands: List<Int>,
    )

    /** 派发矩阵一行：原始 opcode -> 语义 -> IR 助记符 */
    data class DispatchEntry(
        val opcode: String,          // 原始键 "0x1a" / "26" / "'a'"
        val normalizedKey: String,   // 归一键 "26"
        val kind: String,            // HandlerKind.name
        val kindDisplay: String,     // HandlerKind.display
        val irMnemonic: String,      // 归一 IR 助记符
        val confidence: Int,         // 0-100
        val matched: Boolean,        // 该 opcode 是否在字节码流中命中
    )

    data class VmIrResult(
        val ok: Boolean,
        val vmName: String = "JSVMP",
        val irOpcodes: List<IrIns> = emptyList(),
        val dispatchedMatrix: List<DispatchEntry> = emptyList(),
        val equivalenceMap: Map<String, String> = emptyMap(),
        val irListing: String = "",
        val notes: List<String> = emptyList(),
    )

    // ---------------- 入口 ----------------

    /**
     * 归一化翻译：对候选 VM 的全部 handler 分类成 IR 助记符，并把字节码载体
     * 翻译成归一指令流。
     *
     * @param source     JS 源码（含字节码载体）
     * @param candidate  VmpDetector 定位的 dispatch 候选
     * @param profile    JsvmpDeepAnalyzer 分析出的 VM 画像
     */
    fun translate(
        source: String,
        candidate: VmpDetector.VmpCandidate,
        profile: JsvmpDeepAnalyzer.VmProfile,
    ): VmIrResult {
        // 1. 等价表 + 派发矩阵（matched 稍后回填）
        val equivalence = LinkedHashMap<String, String>()   // 归一键 -> IR 助记符
        val dispatchRows = mutableListOf<MutableDispatchEntry>()
        for (h in profile.handlers) {
            val norm = normalizeOpKey(h.key) ?: continue
            val mnem = classifyIr(h.kind, h.snippet)
            equivalence[norm] = mnem
            dispatchRows.add(
                MutableDispatchEntry(
                    opcode = h.key,
                    normalizedKey = norm,
                    kind = h.kind.name,
                    kindDisplay = h.kind.display,
                    irMnemonic = mnem,
                    confidence = h.confidence,
                    matched = false,
                ),
            )
        }

        // 2. 提取全量字节码流（数组/hex/base64）
        val ops = extractStream(source)
        if (ops.isEmpty()) {
            return VmIrResult(
                ok = false,
                vmName = "JSVMP",
                irOpcodes = emptyList(),
                dispatchedMatrix = dispatchRows.map { it.toEntry() },
                equivalenceMap = equivalence,
                irListing = "",
                notes = listOf(
                    "未找到可静态提取的字节码载体（数组/hex/base64 均未命中）。",
                    "该 VM 字节码可能在运行时解密生成——用 debugger.trace_vmp 采样，再配合本等价表把运行时 opcode 归一为 IR。",
                ),
            )
        }

        // 3. arity 感知切分 -> 归一指令流
        val arity = buildArityMap(profile)
        val irOps = mutableListOf<IrIns>()
        val usedKeys = mutableSetOf<String>()
        var i = 0
        while (i < ops.size && irOps.size < maxIrIns) {
            val op = ops[i]
            val key = op.toString()
            val ar = (arity[key] ?: 0).coerceIn(0, 4)
            val operands = if (i + ar < ops.size) ops.subList(i + 1, i + 1 + ar).toList() else emptyList()
            val mnem = equivalence[key] ?: "UNKNOWN_0x${op.toString(16)}"
            irOps.add(IrIns(irOps.size, op, mnem, operands))
            usedKeys.add(key)
            i += 1 + ar
        }
        // 回填 matched
        dispatchRows.forEach { it.matched = it.normalizedKey in usedKeys }

        // 4. 渲染归一 listing
        val listing = render(candidate, ops.size, irOps, equivalence, usedKeys)

        // 5. 观察笔记
        val notes = buildNotes(ops, irOps, equivalence, dispatchRows)

        return VmIrResult(
            ok = true,
            vmName = "JSVMP",
            irOpcodes = irOps,
            dispatchedMatrix = dispatchRows.map { it.toEntry() },
            equivalenceMap = equivalence,
            irListing = listing,
            notes = notes,
        )
    }

    // ---------------- HandlerKind / snippet -> IR 助记符 ----------------

    /**
     * 把 HandlerKind + case 体差分出平台无关 IR 助记符。
     * ARITH 进一步细分（Math.imul->MUL / -=SUB / ^=XOR / |=OR / &=AND / <<=SHL / >>=SHR）；
     * BRANCH 二分条件/无条件；STACK 二分 push/pop；字符串还原归一到 STR2CHAR。
     */
    internal fun classifyIr(kind: JsvmpDeepAnalyzer.HandlerKind, snippet: String): String = when (kind) {
        JsvmpDeepAnalyzer.HandlerKind.RETURN -> "RET"
        JsvmpDeepAnalyzer.HandlerKind.CALL -> "CALL"
        JsvmpDeepAnalyzer.HandlerKind.BRANCH ->
            if (isConditionalJump(snippet)) "CJMP" else "JMP"
        JsvmpDeepAnalyzer.HandlerKind.ARITH -> classifyArith(snippet)
        JsvmpDeepAnalyzer.HandlerKind.LOAD_CONST -> "PUSH"
        JsvmpDeepAnalyzer.HandlerKind.STACK_OP ->
            if (Regex("""\.\s*(pop|shift)\s*[.(]""").containsMatchIn(snippet)) "POP" else "PUSH"
        JsvmpDeepAnalyzer.HandlerKind.LOAD_LOCAL ->
            if (isRegMove(snippet)) "MOV" else "LD_LOCAL"
        JsvmpDeepAnalyzer.HandlerKind.STORE_LOCAL ->
            if (isRegMove(snippet)) "MOV" else "ST_LOCAL"
        JsvmpDeepAnalyzer.HandlerKind.MEMBER -> "GETMEMBER"
        JsvmpDeepAnalyzer.HandlerKind.STRING_OP ->
            if (Regex("""fromCharCode|charCodeAt|codePointAt""").containsMatchIn(snippet)) "STR2CHAR" else "STRING"
        JsvmpDeepAnalyzer.HandlerKind.ENV_OP -> "ENV"
        JsvmpDeepAnalyzer.HandlerKind.COMPARE -> "CMP"
        JsvmpDeepAnalyzer.HandlerKind.UNKNOWN -> "UNKNOWN"
    }

    private fun classifyArith(snippet: String): String = when {
        Regex("""Math\.imul|Math\.mul|\*""").containsMatchIn(snippet) -> "MUL"
        snippet.contains("^") -> "XOR"
        Regex("""\|(?!\|)""").containsMatchIn(snippet) -> "OR"
        Regex("""&(?!&)""").containsMatchIn(snippet) -> "AND"
        snippet.contains("<<") -> "SHL"
        snippet.contains(">>") -> "SHR"
        snippet.contains("-") -> "SUB"
        snippet.contains("+") -> "ADD"
        else -> "ARITH"
    }

    /** 条件跳转特征：三元 `?` 或比较运算符（==/>=/</>） */
    private fun isConditionalJump(snippet: String): Boolean =
        snippet.contains("?") ||
            Regex("""[=!]==|[<>]=""").containsMatchIn(snippet) ||
            Regex("""[<>](?!=)""").containsMatchIn(snippet)

    /** 寄存器/局部拷贝（无算术、赋值右端为标识符/下标引用） -> MOV */
    private fun isRegMove(snippet: String): Boolean {
        if (Regex("""[+\-*/%^&|]""").containsMatchIn(snippet)) return false
        return Regex("""[A-Za-z_$][\w$]{0,12}(?:\[[^\]]+\])?\s*=\s*[A-Za-z_$][\w$]{0,12}(?:\[[^\]]+\])?\b""")
            .containsMatchIn(snippet)
    }

    // ---------------- 全量字节码流提取（数组/hex/base64） ----------------

    private fun extractStream(source: String): List<Int> {
        // 1) 大整数数组载体
        val arrayRe = Regex(
            """(?:var|let|const)\s+[A-Za-z_$][\w$]{0,15}\s*=\s*\[\s*\d{1,10}\s*(?:,\s*\d{1,10}\s*){15,}\]""",
        )
        arrayRe.findAll(source).take(30).forEach { m ->
            val bracket = m.value.substringAfter('[').substringBefore(']')
            val nums = Regex("""\d{1,10}""").findAll(bracket).map { it.value.toInt() }.toList()
            if (nums.size >= 16) return nums
        }
        // 2) hex 字符串
        val hex = Regex("""['"]([0-9a-fA-F]{60,})['"]""").findAll(source)
            .maxByOrNull { it.groupValues[1].length }
        hex?.let {
            val h = it.groupValues[1]
            if (h.length % 2 == 0) return h.chunked(2).map { it.toInt(16) }
        }
        // 3) base64
        val b64 = Regex("""['"]([A-Za-z0-9+/=]{150,})['"]""").findAll(source)
            .maxByOrNull { it.groupValues[1].length }
        b64?.let {
            val bytes = runCatching {
                java.util.Base64.getMimeDecoder().decode(it.groupValues[1])
            }.getOrNull()
            if (bytes != null && bytes.size >= 30) return bytes.map { b -> b.toInt() and 0xff }
        }
        return emptyList()
    }

    // ---------------- arity ----------------

    /** opcode 归一键 -> 操作数字长：优先 pc 推进量推断，否则 HandlerKind 默认 */
    private fun buildArityMap(profile: JsvmpDeepAnalyzer.VmProfile): Map<String, Int> {
        val inferred = VmpDecompiler().inferAritiesFromPcDelta(profile.handlers, profile.variables.pcCandidates)
        val out = HashMap<String, Int>()
        profile.handlers.forEach { h ->
            val norm = normalizeOpKey(h.key) ?: return@forEach
            out[norm] = inferred[norm] ?: defaultArity(h.kind)
        }
        return out
    }

    private fun defaultArity(kind: JsvmpDeepAnalyzer.HandlerKind): Int = when (kind) {
        JsvmpDeepAnalyzer.HandlerKind.LOAD_CONST -> 1
        JsvmpDeepAnalyzer.HandlerKind.LOAD_LOCAL -> 1
        JsvmpDeepAnalyzer.HandlerKind.STORE_LOCAL -> 1
        JsvmpDeepAnalyzer.HandlerKind.BRANCH -> 1
        JsvmpDeepAnalyzer.HandlerKind.CALL -> 2
        JsvmpDeepAnalyzer.HandlerKind.ARITH -> 1
        JsvmpDeepAnalyzer.HandlerKind.COMPARE -> 1
        JsvmpDeepAnalyzer.HandlerKind.MEMBER -> 1
        JsvmpDeepAnalyzer.HandlerKind.STRING_OP -> 1
        JsvmpDeepAnalyzer.HandlerKind.ENV_OP -> 1
        JsvmpDeepAnalyzer.HandlerKind.RETURN -> 0
        JsvmpDeepAnalyzer.HandlerKind.STACK_OP -> 0
        JsvmpDeepAnalyzer.HandlerKind.UNKNOWN -> 0
    }

    // ---------------- listing 渲染 ----------------

    private fun render(
        candidate: VmpDetector.VmpCandidate,
        totalOps: Int,
        irOps: List<IrIns>,
        equivalence: Map<String, String>,
        usedKeys: Set<String>,
    ): String {
        val sb = StringBuilder()
        sb.appendLine("; vmir: vm=JSVMP 候选@L${candidate.line}:C${candidate.column}, dispatch=${candidate.dispatchStyle} " +
            "carrier_total=$totalOps ir_insns=${irOps.size}")
        sb.appendLine("; 等价表（opcode -> IR 助记符，used=命中）:")
        equivalence.entries.sortedBy { it.key.toIntOrNull() ?: 0 }.forEach { (k, mnem) ->
            sb.appendLine(";   ${k.padStart(4)} -> $mnem${if (k in usedKeys) "  [used]" else ""}")
        }
        sb.appendLine()
        irOps.take(maxIrIns).forEach { ins ->
            val opsTag = if (ins.operands.isEmpty()) "" else " " + ins.operands.joinToString(",")
            val charTag = if (ins.mnemonic == "STR2CHAR") {
                ins.operands.firstOrNull()?.let { " ; '${it.toChar()}'" } ?: ""
            } else ""
            sb.appendLine("${ins.pc.toString().padStart(4)}  ${ins.mnemonic.padEnd(10)}$opsTag  ; op=${if (ins.originalOp <= 0xff) "0x%02x" else "0x%x"}".format(ins.originalOp) + charTag)
        }
        if (irOps.size > maxIrIns) {
            sb.appendLine("; ...（其余 ${irOps.size - maxIrIns} 条省略）")
        }
        sb.appendLine()
        sb.appendLine("; 提示：equivalenceMap 即平台无关 ISA 投影——与其他 VM 的等价表 diff 即可定位逻辑差异；")
        sb.appendLine("; 热点 IR（CALL/STR2CHAR 密集）= 签名/加密区段；CJMP 目标可重建控制流。")
        return sb.toString()
    }

    // ---------------- 观察笔记 ----------------

    private fun buildNotes(
        ops: List<Int>,
        irOps: List<IrIns>,
        equivalence: Map<String, String>,
        dispatchRows: List<MutableDispatchEntry>,
    ): List<String> {
        val notes = mutableListOf<String>()
        notes.add("载体共 ${ops.size} 个字节，归一化为 ${irOps.size} 条 IR 指令")
        notes.add("等价表映射 ${equivalence.size} 个 opcode 到 ${equivalence.values.distinct().size} 种 IR 助记符，命中 ${dispatchRows.count { it.matched }} 个")
        val hit = dispatchRows.filter { it.matched }
        val usedMnems = hit.map { it.irMnemonic }.toSet()
        notes.add("实际执行到的 IR 集合: ${usedMnems.sorted().joinToString(",")}")
        if (irOps.any { it.mnemonic == "STR2CHAR" }) notes.add("存在字符串还原原语 STR2CHAR——字符表在运行时逐字符解码（签名/常量热点）")
        if (irOps.any { it.mnemonic == "CALL" }) notes.add("存在 CALL——VM 可回调宿主函数（可能做宿主环境校验/加密）")
        val unresolved = irOps.count { it.mnemonic.startsWith("UNKNOWN") }
        if (unresolved > 0) notes.add("$unresolved 条指令未映射到等价表（运行时解密 or 未捕获 handler）——用 debugger.trace_vmp 补采样")
        return notes
    }

    private companion object {
        const val maxIrIns = 500
    }

    // ---------------- 内部辅助 ----------------

    private class MutableDispatchEntry(
        val opcode: String,
        val normalizedKey: String,
        val kind: String,
        val kindDisplay: String,
        val irMnemonic: String,
        val confidence: Int,
        var matched: Boolean,
    ) {
        fun toEntry() = DispatchEntry(opcode, normalizedKey, kind, kindDisplay, irMnemonic, confidence, matched)
    }

    /** "0x1a" -> "26"；"26" -> "26"；"'a'" -> "97"；其余 null */
    private fun normalizeOpKey(key: String): String? {
        val k = key.trim()
        return when {
            k.startsWith("0x") || k.startsWith("0X") -> k.substring(2).toIntOrNull(16)?.toString()
            k.toIntOrNull() != null -> k.toIntOrNull().toString()
            k.length >= 3 && k.startsWith("'") && k.endsWith("'") -> k[1].code.toString()
            else -> null
        }
    }
}