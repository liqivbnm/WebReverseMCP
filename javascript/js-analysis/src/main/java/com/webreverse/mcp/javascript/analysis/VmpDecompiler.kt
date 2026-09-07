package com.webreverse.mcp.javascript.analysis

/**
 * JSVMP 反编译器 v1（ 新增）。
 *
 * 逆向 JSVMP 的「临门一脚」：JsvmpDeepAnalyzer 已重建 ISA（opcode -> 语义），
 * 本类在此之上把字节码载体的 opcode 序列翻译为人类可读的伪代码：
 *
 * 1. **全量指令流提取**：从数组/hex/base64 载体取完整 opcode 序列（非预览截断）。
 * 2. **操作数感知遍历**：按 HandlerKind 的默认 arity 消费内联操作数
 *    （LLM 可通过 arityOverride 精修，迭代逼近真实指令编码）。
 * 3. **基本块划分**：BRANCH 指令切块，绝对目标地址生成 `L<n>:` 标签；
 *    回边（target < 当前）标记循环。
 * 4. **伪代码渲染**：`push imm 26` / `ld r3` / `call argc=2` / `br -> L17`。
 *
 * 输出与 jsvmp.snapshot（运行时 pc/sp 快照）配合：伪代码行号 + 运行时 pc 对齐
 * 即可锁定签名区段。
 */
class VmpDecompiler {

    // ---------------- 数据模型 ----------------

    data class Decompiled(
        val ok: Boolean,
        val error: String = "",
        val carrierType: String = "",          // array / hex / base64
        val carrierName: String = "",
        val totalInstructions: Int = 0,        // 载体总元素数
        val decodedInstructions: Int = 0,      // 成功解释的指令数
        val isaUsed: Map<String, String>,      // opcode -> 语义 display（参与反编译的部分）
        val arityUsed: Map<String, Int>,       // opcode -> 实际使用的 arity
        val unresolvedOpcodes: List<String>,   // ISA 之外的 opcode
        val blocks: Int = 0,
        val loopBacks: Int = 0,                // 回边（循环）数
        val listing: String,                   // 伪代码全文
        val runtimeNeeded: Boolean = false,    // true = 无静态载体，需运行时 trace opcode
        // P1-6：decode 公式（判别式非直通时的 byte->opcode 映射）
        val decodeFormula: String = "",        // 提取的公式描述（空 = 直通无映射）
        val decodeTableUsed: Int = 0,          // 经公式映射命中的指令数
        // P0-3：arity 来源标注（inferred=pc 推进量推断 / override / default）
        val aritySource: Map<String, String> = emptyMap(),
        // P2-11：LLM 命名提示包（已知语义表 + UNKNOWN case 体，喂给调用方 Agent 命名后回传）
        val namingHints: String = "",
    )

    // ---------------- 入口 ----------------

    /**
     * @param arityOverride LLM 精修的操作数字段：opcode 键 -> arity
     *        （如 {"0x1a": 1, "0x05": 2}）；未覆盖的按 HandlerKind 默认值
     */
    fun decompile(
        source: String,
        candidate: VmpDetector.VmpCandidate,
        arityOverride: Map<String, Int> = emptyMap(),
        maxInstructions: Int = 500,
    ): Decompiled {
        val profile = JsvmpDeepAnalyzer().analyze(source, candidate)

        // ISA: 规范化 opcode 键 -> 语义
        val isa = buildIsa(profile.handlers)

        // 全量指令流
        val stream = extractFullStream(source)
        if (stream == null || stream.ops.isEmpty()) {
            return Decompiled(
                ok = false,
                error = "未找到静态字节码载体（数组/hex/base64 均未命中）。" +
                    "该 VM 字节码可能在运行时解密生成——用 debugger.trace_vmp 采样后配合本工具的 isa 映射人工重建，" +
                    "或用 jsvmp.snapshot 在断点暂停态读取字节码数组变量后回传 source",
                isaUsed = isa.mapValues { it.value.display },
                arityUsed = emptyMap(),
                unresolvedOpcodes = emptyList(),
                listing = "",
                runtimeNeeded = true,
                namingHints = buildNamingHints(profile.handlers),
            )
        }

        // P1-6：decode 公式提取与 byte->opcode 建表
        val caseKeys = isa.keys.mapNotNull { it.toIntOrNull() }.toSet()
        val decoder = DecodeFormula.extract(profile.variables.dispatchExpr, caseKeys)
        val effectiveOps = decoder.map(stream.ops)

        // P0-3：pc 推进量静态推断 arity（优先级低于 override）
        val inferred = inferAritiesFromPcDelta(profile.handlers, profile.variables.pcCandidates)

        // 遍历 + 基本块
        val (listing, blocks, loopBacks, decoded, unresolved, arities, aritySrc) =
            render(effectiveOps, isa, arityOverride, inferred, maxInstructions, stream.type)

        return Decompiled(
            ok = true,
            carrierType = stream.type,
            carrierName = stream.name,
            totalInstructions = stream.ops.size,
            decodedInstructions = decoded,
            isaUsed = isa.entries.associate { (k, v) -> k to v.display },
            arityUsed = arities,
            unresolvedOpcodes = unresolved,
            blocks = blocks,
            loopBacks = loopBacks,
            listing = listing,
            decodeFormula = decoder.description,
            decodeTableUsed = decoder.mappedCount,
            aritySource = aritySrc,
            namingHints = buildNamingHints(profile.handlers),
        )
    }

    // ---------------- P0-3：pc 推进量推断 arity ----------------

    /**
     * 从 case 体统计 pc 变量推进量，得出确定性操作数字长。
     * 规则：
     * - `pc++` / `++pc`：+1
     * - `pc += N`：+N（N 为字面量）
     * - `bc[pc++]` 读取：+1（该模式本身就是操作数消费）
     * - `pc = X`（绝对赋值）：跳转类，arity 由 BRANCH 默认处理
     * dispatch 自身已消费 1 个 opcode 单元，operand_units = 总推进 - 判别式消耗。
     */
    fun inferAritiesFromPcDelta(
        handlers: List<JsvmpDeepAnalyzer.HandlerInfo>,
        pcCandidates: List<String>,
    ): Map<String, Int> {
        val out = HashMap<String, Int>()
        val pcNames = (pcCandidates + listOf("pc", "ip")).filter { it.isNotBlank() }.distinct()
        handlers.forEach { h ->
            val key = normalizeKey(h.key) ?: return@forEach
            val body = h.snippet
            var delta = 0L
            var hasAbsoluteJump = false
            pcNames.forEach { pc ->
                val esc = Regex.escape(pc)
                // pc++ / ++pc（排除 +=）
                Regex("""(?:$esc\s*\+\+|\+\+\s*$esc)\b""").findAll(body).forEach { delta += 1 }
                // pc += N
                Regex("""$esc\s*\+=\s*(0x[0-9a-fA-F]{1,6}|\d{1,6})""").findAll(body).forEach { m ->
                    delta += parseNum(m.groupValues[1])
                }
                // pc = <非 pc 表达式>：绝对跳转
                Regex("""$esc\s*=\s*(?!$esc)""").findAll(body).forEach { hasAbsoluteJump = true }
            }
            // case 体内无 pc 推进且无跳转 -> 操作数为 0（纯栈操作）
            // 有推进 -> 推进量即操作数单元数（判别式的 pc++ 不在 case 体内，无需减 1）
            val arity = when {
                hasAbsoluteJump -> -1   // 跳转类：交给 BRANCH 默认/override
                delta in 1..4 -> delta.toInt()
                else -> 0
            }
            if (arity >= 0) out[key] = arity
        }
        return out
    }

    private fun parseNum(s: String): Long =
        if (s.startsWith("0x") || s.startsWith("0X")) s.substring(2).toLongOrNull(16) ?: 0
        else s.toLongOrNull() ?: 0

    // ---------------- P2-11：LLM 命名提示包 ----------------

    /**
     * 生成供调用方 LLM 命名 UNKNOWN handler 的提示包：
     * - 已命名 handler 的语义表（few-shot 参照）
     * - UNKNOWN/低置信 handler 的 case 体片段
     * Agent 命名后可将结果写入 arityOverride 同款 JSON 回传重跑。
     */
    internal fun buildNamingHints(handlers: List<JsvmpDeepAnalyzer.HandlerInfo>): String {
        if (handlers.isEmpty()) return ""
        val sb = StringBuilder()
        sb.appendLine("== LLM 命名任务（UNKNOWN handler -> 助记名）==")
        sb.appendLine("已命名语义参照（命名风格：大写助记符）：")
        handlers.filter { it.kind != JsvmpDeepAnalyzer.HandlerKind.UNKNOWN }
            .take(15).forEach { h ->
                sb.appendLine("  ${h.key} -> ${it_kindName(h.kind)}   ; ${h.snippet.replace("\n", " ").take(90)}")
            }
        val unknowns = handlers.filter { it.kind == JsvmpDeepAnalyzer.HandlerKind.UNKNOWN }
        if (unknowns.isNotEmpty()) {
            sb.appendLine("待命名（输出 JSON：{\"opKey\": \"助记名\", ...}）：")
            unknowns.take(20).forEach { h ->
                sb.appendLine("  ${h.key}: ${h.snippet.replace("\n", " ").take(120)}")
            }
        } else {
            sb.appendLine("全部 handler 已有语义命名，无需 LLM 参与。")
        }
        sb.appendLine("提示：命名后可通过 arityOverride + 命名表回传增强反编译输出。")
        return sb.toString().take(4000)
    }

    private fun it_kindName(kind: JsvmpDeepAnalyzer.HandlerKind): String = kind.name

    // ---------------- ISA 规范化 ----------------

    /** handler 键（"0x1a"/"26"/"'a'"）-> 规范化（"26"）-> HandlerKind */
    private fun buildIsa(handlers: List<JsvmpDeepAnalyzer.HandlerInfo>): Map<String, JsvmpDeepAnalyzer.HandlerKind> {
        val out = HashMap<String, JsvmpDeepAnalyzer.HandlerKind>()
        handlers.forEach { h ->
            normalizeKey(h.key)?.let { out[it] = h.kind }
        }
        return out
    }

    /** "0x1a" -> "26"；"26" -> "26"；"'a'" -> "97"；其他原样 */
    private fun normalizeKey(key: String): String? {
        val k = key.trim()
        return when {
            k.startsWith("0x") || k.startsWith("0X") ->
                k.substring(2).toIntOrNull(16)?.toString()
            k.toIntOrNull() != null -> k.toIntOrNull().toString()
            k.length >= 3 && k.startsWith("'") && k.endsWith("'") ->
                k[1].code.toString()
            else -> null
        }
    }

    // ---------------- 全量指令流 ----------------

    private data class Stream(val type: String, val name: String, val ops: List<Int>)

    private fun extractFullStream(source: String): Stream? {
        // 1) 大整数数组
        val arrayRe = Regex(
            """(?:var|let|const)\s+([A-Za-z_$][\w$]{0,15})\s*=\s*\[\s*(\d{1,10})\s*(?:,\s*\d{1,10}\s*){15,}\]""",
        )
        arrayRe.findAll(source).take(30).forEach { m ->
            // 只在 [...] 括号内提取数字（避免把 _0xbc 之类变量名中的数字算进指令流）
            val bracket = m.value.substringAfter('[').substringBefore(']')
            val nums = Regex("""\d{1,10}""").findAll(bracket).map { it.value.toInt() }.toList()
            if (nums.size >= 16) return Stream("array", m.groupValues[1], nums)
        }
        // 2) hex 字符串
        val hex = Regex("""['"]([0-9a-fA-F]{60,})['"]""").findAll(source)
            .maxByOrNull { it.groupValues[1].length }
        hex?.let {
            val h = it.groupValues[1]
            if (h.length % 2 == 0) return Stream("hex", "<inline>", h.chunked(2).map { it.toInt(16) })
        }
        // 3) base64
        val b64 = Regex("""['"]([A-Za-z0-9+/=]{150,})['"]""").findAll(source)
            .maxByOrNull { it.groupValues[1].length }
        b64?.let {
            val bytes = runCatching {
                java.util.Base64.getMimeDecoder().decode(it.groupValues[1])
            }.getOrNull()
            if (bytes != null && bytes.size >= 30) return Stream("base64", "<inline>", bytes.map { b -> b.toInt() and 0xff })
        }
        return null
    }

    // ---------------- 遍历与渲染 ----------------

    /** HandlerKind -> 默认操作数个数（操作数紧随 opcode 内联编码） */
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

    private fun mnemonic(kind: JsvmpDeepAnalyzer.HandlerKind, operands: List<Int>, pc: Int): String {
        val o = operands
        return when (kind) {
            JsvmpDeepAnalyzer.HandlerKind.LOAD_CONST ->
                if (o.isNotEmpty() && o[0] in 32..126) "push imm ${o[0]}   ; '${o[0].toChar()}'" else "push imm ${o.joinToString(" ")}"
            JsvmpDeepAnalyzer.HandlerKind.LOAD_LOCAL -> "ld r${o.getOrElse(0) { "?" }}"
            JsvmpDeepAnalyzer.HandlerKind.STORE_LOCAL -> "st r${o.getOrElse(0) { "?" }}"
            JsvmpDeepAnalyzer.HandlerKind.ARITH -> "arith op=${o.getOrElse(0) { "?" }}"
            JsvmpDeepAnalyzer.HandlerKind.COMPARE -> "cmp op=${o.getOrElse(0) { "?" }}"
            JsvmpDeepAnalyzer.HandlerKind.BRANCH -> {
                val t = o.getOrElse(0) { 0 }
                "br -> L$t   ; (rel ${if (t >= pc) "+" else ""}${t - pc})"
            }
            JsvmpDeepAnalyzer.HandlerKind.CALL -> "call argc=${o.getOrElse(0) { "?" }} target=${o.getOrElse(1) { "?" }}"
            JsvmpDeepAnalyzer.HandlerKind.MEMBER -> "getmember ${o.getOrElse(0) { "?" }}"
            JsvmpDeepAnalyzer.HandlerKind.STRING_OP -> "strop op=${o.getOrElse(0) { "?" }}"
            JsvmpDeepAnalyzer.HandlerKind.ENV_OP -> "env ${o.getOrElse(0) { "?" }}"
            JsvmpDeepAnalyzer.HandlerKind.STACK_OP -> "stackop"
            JsvmpDeepAnalyzer.HandlerKind.RETURN -> "ret"
            JsvmpDeepAnalyzer.HandlerKind.UNKNOWN -> "unknown"
        }
    }

    private data class RenderResult(
        val listing: String,
        val blocks: Int,
        val loopBacks: Int,
        val decoded: Int,
        val unresolved: List<String>,
        val arities: Map<String, Int>,
        val aritySource: Map<String, String>,
    )

    private fun render(
        ops: List<Int>,
        isa: Map<String, JsvmpDeepAnalyzer.HandlerKind>,
        arityOverride: Map<String, Int>,
        inferred: Map<String, Int>,
        maxInstructions: Int,
        carrierType: String,
    ): RenderResult {
        // 归一化 override 键
        val overrides = arityOverride.mapNotNull { (k, v) ->
            normalizeKey(k)?.let { it to v }
        }.toMap()

        // 第一遍：确定每条指令的 kind/arity 与块边界
        // 优先级：override > pc 推进量推断 > HandlerKind 默认
        data class Ins(val pc: Int, val op: Int, val kind: JsvmpDeepAnalyzer.HandlerKind?, val operands: List<Int>)
        val instructions = mutableListOf<Ins>()
        val branchTargets = mutableSetOf<Int>()
        var i = 0
        val arityUsed = HashMap<String, Int>()
        val aritySrc = HashMap<String, String>()
        while (i < ops.size && instructions.size < maxInstructions) {
            val op = ops[i]
            val opKey = op.toString()
            val kind = isa[opKey]
            val arity: Int
            if (kind != null) {
                arity = when {
                    opKey in overrides -> {
                        aritySrc[opKey] = "override"; overrides[opKey]!!
                    }
                    opKey in inferred -> {
                        aritySrc[opKey] = "inferred(pc-delta)"; inferred[opKey]!!
                    }
                    else -> {
                        aritySrc[opKey] = "default"; defaultArity(kind)
                    }
                }.coerceIn(0, 4)
            } else {
                arity = 0
            }
            if (kind != null) arityUsed[opKey] = arity
            val operands = if (i + arity < ops.size) ops.subList(i + 1, i + 1 + arity) else emptyList()
            instructions.add(Ins(instructions.size, op, kind, operands.toList()))
            if (kind == JsvmpDeepAnalyzer.HandlerKind.BRANCH && operands.isNotEmpty()) {
                branchTargets.add(operands[0])
            }
            i += 1 + arity
        }

        val unresolved = instructions.filter { it.kind == null }.map { "0x${it.op.toString(16)}" }.distinct().take(20)

        // 第二遍：渲染（带标签 + 循环回边标记 + BRANCH 后缩进重置）
        val sb = StringBuilder()
        sb.appendLine("; carrier=$carrierType total=${ops.size} decoded=${instructions.size} " +
            "blocks≈${branchTargets.size + 1} unresolved=${unresolved.size}")
        val inferredCount = aritySrc.values.count { it.startsWith("inferred") }
        val overrideCount = aritySrc.values.count { it == "override" }
        sb.appendLine("; arity 来源：pc推进量推断 $inferredCount / 人工override $overrideCount / 默认 " +
            (aritySrc.size - inferredCount - overrideCount) + " 条")
        sb.appendLine()
        var loopBacks = 0
        var currentIndent = 0
        instructions.forEach { ins ->
            if (ins.pc in branchTargets) {
                if (sb.isNotEmpty()) sb.appendLine()
                sb.appendLine("L${ins.pc}:")
                currentIndent = 0
            }
            val pad = "  ".repeat(currentIndent.coerceIn(0, 6))
            val kind = ins.kind
            if (kind == null) {
                sb.appendLine("$pad${ins.pc.toString().padStart(4)}  op_0x${ins.op.toString(16)}")
            } else {
                sb.appendLine("$pad${ins.pc.toString().padStart(4)}  ${mnemonic(kind, ins.operands, ins.pc)}")
                when (kind) {
                    JsvmpDeepAnalyzer.HandlerKind.BRANCH -> {
                        val t = ins.operands.getOrElse(0) { ins.pc }
                        if (t < ins.pc) loopBacks++
                        currentIndent = 0
                    }
                    JsvmpDeepAnalyzer.HandlerKind.RETURN -> currentIndent = (currentIndent - 1).coerceAtLeast(0)
                    else -> if (currentIndent < 6) currentIndent++
                }
            }
        }
        sb.appendLine()
        sb.appendLine("; 提示：CALL 密集区 + 字符串原语区 = 签名/加密热点；")
        sb.appendLine("; 回边(L${"<target"}<当前) 即循环；配合 jsvmp.snapshot 的运行时 pc 可定位执行区段")
        return RenderResult(
            listing = sb.toString(),
            blocks = branchTargets.size + 1,
            loopBacks = loopBacks,
            decoded = instructions.size,
            unresolved = unresolved,
            arities = arityUsed,
            aritySource = aritySrc,
        )
    }
}
