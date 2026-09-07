package com.webreverse.mcp.javascript.analysis

/**
 * JSVMP 语义恢复引擎 v3（AST 化符号栈版）。
 *
 * 取代 v2 的「Regex → pushCount/popCount 计数」微观语义恢复：对 dispatch switch 的每个
 * case 体**先做 AST 化程序切片**（复用 [JsAstParser] / [JsAst]），再在**符号栈**上做
 * 数据流求值，产出真正的符号化依赖关系，而非常规的计数器。
 *
 * 典型数据流（a=pop; b=pop; push(a^b)）：
 * ```
 * S0=[A, B]
 * C = A XOR B          // 符号栈数据流链
 * S1=[C]
 * opcode 0x17: XOR(stack[-2]=B, stack[-1]=A)->C   // 精确语义签名
 * ```
 *
 * 相对 v2 的改进：
 * 1. stackIn/stackOut 由符号栈读写事件驱动（真实槽位数），并记录符号来源形成数据流链；
 * 2. arity 拆分为四字段 [OperandInfo.operandCount/operandWidth/operandEncoding/pcDelta]；
 * 3. 语句切片基于 AST（switch-case 的 case 体、三元、逗号复合、嵌套调用均可正确递归），
 *    不再用 `;{` 整段 regex 切。
 *
 * 兼容性：保留 v2 的公开 API（[recover]/[recoverOne]/[validateHypothesis]/[HandlerSemantics]），
 * [recoverOne] 内部优先走 [JsvmpAstSlicer] AST 路径，AST 解析失败时回退到 v2 regex 路径。
 * 纯 Kotlin / stdlib，零第三方依赖。
 */
class JsvmpSemanticRecovery {

    // ---------------- 数据模型 ----------------

    /** 操作数信息（替代原启发式 arity 的四字段拆解） */
    data class OperandInfo(
        val operandCount: Int,     // 独立操作数字段数（读到的不同 bc[pc+n] 偏移数）
        val operandWidth: Int,     // 操作数字宽（max 偏移 n）
        val operandEncoding: String, // varint/u8le | u16le | u32le | u8
        val pcDelta: Int,          // pc 推进量
    )

    /** 单个 handler 的恢复结果 */
    data class HandlerSemantics(
        val key: String,               // opcode 键（0x17 / 26）
        val mnemonic: String,          // 助记符（XOR / ADD / PUSH_IMM / LOAD_REG / CALL ...）
        val signature: String,         // 语义签名（XOR(stack[-1]=A, stack[-2]=B)->C）
        val arity: Int,                // 向后兼容：等价 operandCount
        val stackIn: Int,              // 栈输入槽位数（符号栈实际读取的顶部槽位数）
        val stackOut: Int,             // 栈输出槽位数（符号栈写入的槽位数）
        val regReads: List<String>,    // 寄存器/ctx 读槽位（如 ctx[3]）
        val regWrites: List<String>,   // 寄存器/ctx 写槽位
        val readsBytecode: Boolean,    // 是否读字节码数组（操作数来自指令流）
        val branchTarget: Boolean,     // 是否写 pc（跳转/分支）
        val callsHost: Boolean,        // 是否调用宿主函数
        val confidence: Int,           // 0-100
        val ops: List<MicroOp>,        // 微操作序列（调试/LLM 透视）
        val snippet: String,
        /** 新增：四字段操作数信息（AST 路径） */
        val operandInfo: OperandInfo? = null,
        /** 新增：符号栈数据流描述（S0=[A,B]; C=A XOR B; S1=[C]） */
        val symbolicStack: List<String> = emptyList(),
    )

    /** 语句微操作 */
    data class MicroOp(
        val op: String,          // PUSH / POP / REG_WRITE / REG_READ / PC_SET / CALL / CONST / EVAL / OTHER
        val detail: String,      // 人读描述
    )

    /** 全部 handler 的恢复画像 */
    data class RecoveryReport(
        val handlers: List<HandlerSemantics>,
        val mnemonicHistogram: Map<String, Int>,
        val improvedOverRegex: Int,   // 比 HandlerKind 分类细化/修正的数量
        val isaTable: String,         // LLM 友好的 ISA 表
        val notes: List<String>,
    )

    /** 动态假设验证结果 */
    data class HypothesisVerdict(
        val opcode: String,
        val candidates: List<String>,          // 参与验证的候选语义
        val winner: String,                    // 唯一匹配者（可能为空）
        val confirmed: Boolean,
        val confidence: Double,                // 0-1
        val samplesUsed: Int,
        val evidence: List<String>,            // 每条验证记录
    )

    // ---------------- 入口 1：静态语义恢复 ----------------

    fun recover(
        handlers: List<JsvmpDeepAnalyzer.HandlerInfo>,
        variables: JsvmpDeepAnalyzer.VmVariables,
    ): RecoveryReport {
        val out = handlers.map { recoverOne(it, variables) }
        val hist = out.groupingBy { it.mnemonic }.eachCount()
        val improved = out.count { it.mnemonic != "UNKNOWN" && it.mnemonic != "OTHER" }
        return RecoveryReport(
            handlers = out,
            mnemonicHistogram = hist,
            improvedOverRegex = improved,
            isaTable = buildIsaTable(out),
            notes = buildNotes(out, variables),
        )
    }

    /** 单 handler 恢复：优先 AST 符号栈路径，失败回退 v2 regex 路径 */
    fun recoverOne(
        h: JsvmpDeepAnalyzer.HandlerInfo,
        variables: JsvmpDeepAnalyzer.VmVariables,
    ): HandlerSemantics {
        val slicer = JsvmpAstSlicer(h, variables)
        val ast = slicer.analyze()
        if (ast != null) return handlerFromAst(h, ast)
        return recoverOneRegex(h, variables)
    }

    // ---------------- AST 路径：结果 → HandlerSemantics ----------------

    private fun handlerFromAst(h: JsvmpDeepAnalyzer.HandlerInfo, ast: JsvmpAstSlicer.AstSliceResult): HandlerSemantics {
        return HandlerSemantics(
            key = h.key,
            mnemonic = ast.mnemonic,
            signature = ast.signature,
            arity = ast.operandInfo.operandCount,
            stackIn = ast.stackIn,
            stackOut = ast.stackOut,
            regReads = ast.regReads,
            regWrites = ast.regWrites,
            readsBytecode = ast.readsBytecode,
            branchTarget = ast.branchTarget,
            callsHost = ast.callsHost,
            confidence = ast.confidence,
            ops = ast.ops.take(20),
            snippet = h.snippet.take(160),
            operandInfo = ast.operandInfo,
            symbolicStack = ast.symbolicStack,
        )
    }

    // ---------------- 入口 2：符号栈数据流报告（供上层 MCP 工具展示） ----------------

    /**
     * 对每个 handler 产出符号栈数据流图，形如：
     * `opcode 0x17: S0=[A, B]; C = A XOR B; S1=[C]`
     */
    fun produceSymbolicReport(
        handlers: List<JsvmpDeepAnalyzer.HandlerInfo>,
        variables: JsvmpDeepAnalyzer.VmVariables,
    ): List<String> {
        return handlers.map { h ->
            val slicer = JsvmpAstSlicer(h, variables)
            val ast = slicer.analyze()
            if (ast != null && ast.symbolicStack.isNotEmpty()) {
                val flow = ast.symbolicStack.joinToString("; ")
                "opcode ${h.key}: $flow"
            } else {
                "opcode ${h.key}: <AST 解析不可用，回退 regex 路径，无符号栈数据流>"
            }
        }
    }

    // ---------------- v2 正则回退路径（recoverOneRegex） ----------------

    private fun recoverOneRegex(
        h: JsvmpDeepAnalyzer.HandlerInfo,
        variables: JsvmpDeepAnalyzer.VmVariables,
    ): HandlerSemantics {
        val pcNames = variables.pcCandidates + listOf("pc", "ip")
        val spNames = variables.spCandidates + listOf("sp")
        val ctxNames = variables.ctxCandidates
        val bcNames = variables.bytecodeCandidates

        val stmts = sliceStatements(h.snippet)
        val ops = mutableListOf<MicroOp>()

        // --- 栈效果 ---
        var pushCount = 0
        var popCount = 0
        val pushExprs = mutableListOf<String>()   // push 进栈的表达式（按序）
        val popTargets = mutableListOf<String>()  // pop 出栈的落点（按序）

        // --- 寄存器读写 ---
        val regReads = mutableListOf<String>()
        val regWrites = mutableListOf<String>()

        // --- 其他特征 ---
        var readsBytecode = false
        var pcDelta = 0L
        var pcAbsoluteSet = false
        var callsHost = false
        val arithOps = mutableListOf<String>()    // 表达式中出现的运算符（按出现序）
        val constLoads = mutableListOf<String>()

        for (stmt in stmts) {
            val s = stmt.trim()
            if (s.isEmpty()) continue

            // X.push(expr) —— push 效果
            val pushM = Regex("""^([\w$]{1,13})(?:\.[\w$]+)*\.push\s*\((.*)\)""").find(s)
                ?: Regex("""^([A-Za-z_$][\w$]{0,12})\.push\s*\((.*)\)""").find(s)
            if (pushM != null) {
                pushCount++
                pushExprs.add(pushM.groupValues[2].take(80))
                ops.add(MicroOp("PUSH", "${pushM.groupValues[1]}.push(${pushM.groupValues[2].take(50)})"))
                collectArith(pushM.groupValues[2], arithOps)
                continue
            }
            // X.pop() —— pop 效果（var r = X.pop() / r = X.pop()）
            val popM = Regex("""(?:var|let|const)?\s*([\w$]{1,13})\s*=\s*([\w$]{1,13})\.pop\s*\(\s*\)""").find(s)
            if (popM != null) {
                popCount++
                popTargets.add(popM.groupValues[1])
                ops.add(MicroOp("POP", "${popM.groupValues[1]} = ${popM.groupValues[2]}.pop()"))
                continue
            }
            // X.shift() 也算 pop
            if (Regex("""\.shift\s*\(\s*\)""").containsMatchIn(s)) {
                popCount++
                ops.add(MicroOp("POP", s.take(60)))
                continue
            }
            // 栈顶读写：X[X.length - 1] / X[sp] / X[--sp] = / = X[sp++]
            val stackTopWrite = Regex("""([\w$]{1,13})\s*\[\s*(?:\1\s*\.\s*length\s*-\s*1|\-\-?\s*\w+)\s*\]\s*=""").find(s)
            if (stackTopWrite != null) {
                pushCount++
                pushExprs.add(s.substringAfter('=').take(80))
                ops.add(MicroOp("PUSH", "stackTop <- ${s.substringAfter('=').take(50)}"))
                collectArith(s, arithOps)
                continue
            }
            val stackTopRead = Regex("""=\s*([\w$]{1,13})\s*\[\s*\1\s*\.\s*length\s*-\s*(1|2)\s*\]""").find(s)
            if (stackTopRead != null) {
                val depth = stackTopRead.groupValues[2].toIntOrNull() ?: 1
                repeat(depth) { popCount++ }
                popTargets.add(stackTopRead.groupValues[1] + "[top-" + (depth - 1) + "]")
                ops.add(MicroOp("POP", "stackTop$depth -> ${s.substringBefore('=').trim().take(30)}"))
                continue
            }
            // = X[sp++] / X[sp--] 形式的出栈
            val spPop = Regex("""=\s*([\w$]{1,13})\s*\[\s*(\w+)\s*(?:\+\+|--)\s*\]""").find(s)
            if (spPop != null && spPop.groupValues[1] in bcNames) {
                readsBytecode = true
                pcDelta += 1
                ops.add(MicroOp("LOAD_IMM", "imm <- ${s.take(60)}"))
                continue
            }

            // 寄存器/ctx 写：ctx[i] = / ctx[i+j] =
            val regW = Regex("""([\w$]{1,13})\s*\[\s*([\w$]{1,13})\s*(?:\+\s*(0x[0-9a-fA-F]+|\d+))?\s*\]\s*=""").find(s)
            if (regW != null && regW.groupValues[1] in ctxNames) {
                val slot = regW.groupValues[2] +
                    (if (regW.groupValues[3].isNotEmpty()) "+${regW.groupValues[3]}" else "")
                regWrites.add("${regW.groupValues[1]}[$slot]")
                ops.add(MicroOp("REG_WRITE", "${regW.groupValues[1]}[$slot] = ..."))
                collectArith(s.substringAfter('='), arithOps)
                continue
            }
            // 寄存器/ctx 读：r = ctx[i]（含在更大表达式中）
            for (ctx in ctxNames) {
                val esc = Regex.escape(ctx)
                if (Regex("""$esc\s*\[""").containsMatchIn(s) && s.contains('=') &&
                    !Regex("""$esc\s*\[[^\]]*\]\s*=""").containsMatchIn(s)
                ) {
                    val m = Regex("""$esc\s*\[\s*([\w$]{1,13})\s*(?:\+\s*(0x[0-9a-fA-F]+|\d+))?\s*\]""").find(s)
                    if (m != null) {
                        val slot = m.groupValues[1] +
                            (if (m.groupValues[2].isNotEmpty()) "+${m.groupValues[2]}" else "")
                        regReads.add("$ctx[$slot]")
                    }
                    break
                }
            }

            // pc 操作
            for (pc in pcNames) {
                val esc = Regex.escape(pc)
                when {
                    Regex("""(?:$esc\s*\+\+|\+\+\s*$esc)\b""").containsMatchIn(s) -> { pcDelta += 1; ops.add(MicroOp("PC_ADV", "$pc++")) }
                    Regex("""$esc\s*\+=\s*(0x[0-9a-fA-F]{1,6}|\d{1,6})""").containsMatchIn(s) -> {
                        val m = Regex("""$esc\s*\+=\s*(0x[0-9a-fA-F]{1,6}|\d{1,6})""").find(s)!!
                        pcDelta += parseNum(m.groupValues[1]); ops.add(MicroOp("PC_ADV", "$pc += ${m.groupValues[1]}"))
                    }
                    Regex("""$esc\s*=\s*(?!$esc)""").containsMatchIn(s) && !s.contains("==") -> {
                        pcAbsoluteSet = true; ops.add(MicroOp("PC_SET", s.take(60)))
                    }
                }
            }

            // 字节码读取：bc[pc+1] / bc[pc]
            for (bc in bcNames) {
                val esc = Regex.escape(bc)
                if (Regex("""$esc\s*\[""").containsMatchIn(s)) {
                    readsBytecode = true
                    // bc[pc + n] 模式：n 即操作数字段跨度提示
                    val m = Regex("""$esc\s*\[\s*[\w$]{1,13}\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\]""").find(s)
                    if (m != null) {
                        val n = parseNum(m.groupValues[1]).toInt()
                        if (n > 0) pcDelta = maxOf(pcDelta, (n + 1).toLong())
                    }
                }
            }

            // 宿主调用
            if (Regex("""\.apply\s*\(|\.call\s*\(|\bReflect\.""").containsMatchIn(s)) {
                callsHost = true
                ops.add(MicroOp("CALL", s.take(60)))
            }

            // 常量加载
            val constM = Regex("""=\s*(0x[0-9a-fA-F]{1,8}|-?\d{1,10}|'[^']{0,30}'|"[^"]{0,30}")\s*;?$""").find(s)
            if (constM != null) {
                constLoads.add(constM.groupValues[1])
                ops.add(MicroOp("CONST", constM.groupValues[1]))
            }

            // 运算符收集（表达式里凡有算术/位运算都记）
            collectArith(s, arithOps)
        }

        // --- 操作数推断：pc 推进量（减去判别式消耗 1）---
        val arity = when {
            pcAbsoluteSet -> 0                       // 跳转类：目标一般内联（按 1 处理过宽，保守 0）
            pcDelta <= 1 -> 0                        // 判别式只消费 opcode 自身
            else -> (pcDelta - 1).toInt().coerceIn(0, 4)
        }

        // --- 助记符与语义签名 ---
        val (mnemonic, signature, confidence) = buildSemantics(
            arithOps, pushCount, popCount, pushExprs, popTargets,
            regReads, regWrites, readsBytecode, pcAbsoluteSet, callsHost,
            constLoads, arity, ctxNames, bcNames,
        )

        return HandlerSemantics(
            key = h.key,
            mnemonic = mnemonic,
            signature = signature,
            arity = arity,
            stackIn = popCount,
            stackOut = pushCount,
            regReads = regReads.distinct().take(8),
            regWrites = regWrites.distinct().take(8),
            readsBytecode = readsBytecode,
            branchTarget = pcAbsoluteSet,
            callsHost = callsHost,
            confidence = confidence,
            ops = ops.take(20),
            snippet = h.snippet.take(160),
            operandInfo = OperandInfo(
                operandCount = arity,
                operandWidth = arity,
                operandEncoding = inferEncodingFrom(h.snippet),
                pcDelta = pcDelta.toInt(),
            ),
        )
    }

    /** 编码推断：字节码数组类型 → 编码名（number[] 默认 varint/u8le） */
    private fun inferEncodingFrom(snippet: String): String = when {
        snippet.contains("Uint32Array") -> "u32le"
        snippet.contains("Uint16Array") -> "u16le"
        snippet.contains("Uint8ClampedArray") || snippet.contains("Uint8Array") -> "u8"
        else -> "varint/u8le"
    }

    // ---------------- 语义合成（v2 正则回退用） ----------------

    private fun buildSemantics(
        arithOps: List<String>,
        pushCount: Int,
        popCount: Int,
        pushExprs: List<String>,
        popTargets: List<String>,
        regReads: List<String>,
        regWrites: List<String>,
        readsBytecode: Boolean,
        pcAbsoluteSet: Boolean,
        callsHost: Boolean,
        constLoads: List<String>,
        arity: Int,
        ctxNames: List<String>,
        bcNames: List<String>,
    ): Triple<String, String, Int> {
        // 优先级：宿主调用 > 跳转 > 寄存器 > 栈算术 > 常量 > 字节码读取 > 其他
        val op = arithOps.firstOrNull()

        return when {
            callsHost -> Triple(
                "CALL",
                "CALL(${(0 until popCount).joinToString(", ") { "arg${it + 1}=stack[-${popCount - it}]" }}) -> stack[-1]" +
                    if (pushCount > 0) "" else " (结果不回栈)",
                88,
            )

            pcAbsoluteSet -> Triple(
                "JMP",
                if (popCount > 0) "CJMP(stack[-1], target=${if (arity > 0) "imm" else "expr"})" else "JMP(target)",
                80,
            )

            // 双目位/算术运算：pop2 -> 算 -> push1
            popCount >= 2 && pushCount >= 1 && op != null -> {
                val mn = arithMnemonic(op)
                Triple(
                    mn,
                    "$mn(stack[-2], stack[-1]) -> stack[-1]",
                    90,
                )
            }

            // 单目运算：pop1 -> 算 -> push1
            popCount == 1 && pushCount >= 1 && op != null && isUnary(op) -> {
                val mn = arithMnemonic(op)
                Triple(mn, "$mn(stack[-1]) -> stack[-1]", 85)
            }

            // pop N push 1 且无运算符：聚合（concat/select/getter）
            popCount >= 2 && pushCount == 1 -> Triple(
                "AGGREGATE",
                "AGG(${(0 until popCount).joinToString(", ") { "stack[-${popCount - it}]" }}) -> stack[-1]",
                65,
            )

            // 寄存器写
            regWrites.isNotEmpty() && popCount == 1 && op == null -> Triple(
                "ST_REG",
                "store ${regWrites.first()} <- stack[-1]" + if (popCount == 1 && pushCount == 0) "" else "",
                85,
            )

            // 寄存器读
            regReads.isNotEmpty() && pushCount == 1 && popCount == 0 && op == null -> Triple(
                "LD_REG",
                "load stack <- ${regReads.first()}",
                85,
            )

            // 常量加载
            constLoads.isNotEmpty() && pushCount >= 1 && popCount == 0 && op == null -> Triple(
                "PUSH_IMM",
                "push ${constLoads.first().take(20)}" + if (arity > 0) " (+$arity imm)" else "",
                90,
            )

            // 字节码读取 + push（LOAD_IMM/LOAD_LOCAL）
            readsBytecode && pushCount >= 1 && popCount == 0 -> Triple(
                "LOAD_BC",
                "push bc[pc+${if (arity > 0) "1..$arity" else "0"}]" + if (arity > 0) " (+$arity imm)" else "",
                82,
            )

            // 栈交换/复制（pop2 push2 / pop1 push2）
            popCount == 1 && pushCount == 2 -> Triple("DUP", "DUP(stack[-1]) -> stack[-1], stack[-2]", 70)
            popCount == 2 && pushCount == 2 -> Triple("SWAP", "SWAP(stack[-1], stack[-2])", 70)

            // pop 后丢弃（drop/比较跳转条件）
            popCount > 0 && pushCount == 0 && op == null -> {
                val cmp = arithOps.firstOrNull { it in listOf("==", "!=", "<", ">", "<=", ">=", "===") }
                if (cmp != null) Triple("CMP", "compare(stack[-2], stack[-1]) by $cmp -> flag", 75)
                else Triple("DROP", "drop stack[-$popCount]", 60)
            }

            // 纯寄存器搬运
            regReads.isNotEmpty() && regWrites.isNotEmpty() -> Triple(
                "MOV",
                "MOV(${regWrites.first()} <- ${regReads.first()})",
                80,
            )

            else -> {
                // 兜底：保留可观测特征
                val sb = StringBuilder()
                if (pushCount > 0) sb.append("push×$pushCount ")
                if (popCount > 0) sb.append("pop×$popCount ")
                if (readsBytecode) sb.append("readBC ")
                if (arithOps.isNotEmpty()) sb.append("ops=${arithOps.distinct().joinToString(",")}")
                Triple("OTHER", sb.toString().trim().ifEmpty { "无可用特征" }, 40)
            }
        }
    }

    /** 运算符 → 助记符 */
    private fun arithMnemonic(op: String): String = when (op) {
        "+" -> "ADD"; "-" -> "SUB"; "*" -> "MUL"; "/" -> "DIV"; "%" -> "MOD"
        "^" -> "XOR"; "&" -> "AND"; "|" -> "OR"
        "<<" -> "SHL"; ">>" -> "SHR"; ">>>" -> "SHRU"
        "~" -> "NOT"; "!" -> "LNOT"; "neg" -> "NEG"
        "==" , "===" -> "EQ"; "!=", "!==" -> "NE"; "<" -> "LT"; ">" -> "GT"; "<=" -> "LE"; ">=" -> "GE"
        "imul" -> "MUL"; "rotl" -> "ROTL"; "rotr" -> "ROTR"
        "floor" -> "FLOOR"; "ceil" -> "CEIL"; "abs" -> "ABS"; "pow" -> "POW"
        else -> "OP_$op"
    }

    private fun isUnary(op: String) = op in listOf("~", "!", "neg", "floor", "ceil", "abs")

    /** 从表达式中收集运算符（按优先序，可多次出现） */
    private fun collectArith(expr: String, out: MutableList<String>) {
        // 位运算与移位（先查双字符避免误配）
        for (tok in listOf(">>>", "<<", ">>")) {
            if (expr.contains(tok)) out.add(tok)
        }
        // Math.* 映射
        if (expr.contains("Math.imul")) out.add("imul")
        if (expr.contains("Math.floor")) out.add("floor")
        if (expr.contains("Math.ceil")) out.add("ceil")
        if (expr.contains("Math.abs")) out.add("abs")
        if (expr.contains("Math.pow")) out.add("pow")
        // charCodeAt/fromCharCode → 字符串原语
        if (expr.contains("charCodeAt")) out.add("charAt")
        if (expr.contains("fromCharCode")) out.add("fromCharCode")
        // 单字符位运算（排除 && || 与比较）
        val bitOps = Regex("""(?<![&|<>=!+\-*/%&|^])([&|^])(?![&|])""").findAll(expr)
        bitOps.forEach { out.add(it.groupValues[1]) }
        // 单目取反/取负
        if (Regex("""[=(,]\s*~""").containsMatchIn(expr)) out.add("~")
        // 算术（保守：只在与栈操作相关的表达式里统计，避免 switch 判别式噪声）
        if (Regex("""[\w)\]]\s*[+\-*/%]\s*[\w(]""").containsMatchIn(expr)) {
            Regex("""[\w)\]]\s*([+\-*/%])\s*[\w(]""").findAll(expr).forEach { out.add(it.groupValues[1]) }
        }
        // 比较
        Regex("""[=!]==?|!==?|<=|>=|[<>](?!=)""").findAll(expr).forEach { out.add(it.value) }
    }

    // ---------------- 语句切片（v2 正则回退用） ----------------

    /** case 体切分为语句（; 与 { } 边界；容忍 minified 无分号） */
    private fun sliceStatements(snippet: String): List<String> {
        val out = mutableListOf<String>()
        val sb = StringBuilder()
        var depth = 0
        var i = 0
        while (i < snippet.length) {
            val c = snippet[i]
            when {
                c == '{' -> { depth++; sb.append(c) }
                c == '}' -> {
                    depth--
                    sb.append(c)
                    if (depth <= 0 && sb.isNotBlank()) { out.add(sb.toString()); sb.clear(); depth = 0 }
                }
                c == ';' && depth <= 0 -> {
                    if (sb.isNotBlank()) out.add(sb.toString())
                    sb.clear()
                }
                c == '\'' || c == '"' -> {
                    // 字符串字面量整段吞
                    val quote = c
                    sb.append(c)
                    i++
                    while (i < snippet.length && snippet[i] != quote) {
                        if (snippet[i] == '\\') { sb.append(snippet[i]); i++ }
                        sb.append(snippet[i]); i++
                    }
                    if (i < snippet.length) sb.append(snippet[i])
                }
                else -> sb.append(c)
            }
            i++
        }
        if (sb.isNotBlank()) out.add(sb.toString())
        return out
    }

    private fun parseNum(s: String): Long =
        if (s.startsWith("0x") || s.startsWith("0X")) s.substring(2).toLongOrNull(16) ?: 0
        else s.toLongOrNull() ?: 0

    // ---------------- 入口 2：动态假设验证 ----------------

    /**
     * 静态分析给出多候选语义（如 ARITH: ADD? XOR? SUB?）时，用运行时 (输入, 输出)
     * 样本自动裁决——Semantic Hypothesis → Runtime Validation。
     *
     * @param samples 每条形如 {"a":123,"b":456,"out":579}（键名任意，取前两个数值为输入）
     * @param candidates 候选语义列表（默认 ADD/SUB/XOR/OR/AND/MUL/SHL/SHR/ROTL）
     */
    fun validateHypothesis(
        opcode: String,
        samples: List<Map<String, String>>,
        candidates: List<String> = listOf("ADD", "SUB", "XOR", "OR", "AND", "MUL", "SHL", "SHR", "ROTL", "MOD"),
    ): HypothesisVerdict {
        val evidence = mutableListOf<String>()
        if (samples.isEmpty()) {
            return HypothesisVerdict(opcode, candidates, "", false, 0.0, 0, listOf("无样本"))
        }
        // 解析数值样本：找前两个数值键作为输入、最后一个数值键作为输出
        val parsed = samples.mapNotNull { m ->
            val nums = m.entries.filter { it.value.toDoubleOrNull() != null }
            if (nums.size < 3) null
            else Triple(
                nums[0].value.toDouble().toLong(),
                nums[1].value.toDouble().toLong(),
                nums[nums.size - 1].value.toDouble().toLong(),
            )
        }
        if (parsed.isEmpty()) {
            return HypothesisVerdict(
                opcode, candidates, "", false, 0.0, samples.size,
                listOf("样本数值字段不足（需 >= 3 个数值字段：输入a/输入b/输出out）"),
            )
        }

        fun eval(op: String, a: Long, b: Long): Long? = when (op) {
            "ADD" -> a + b
            "SUB" -> a - b
            "XOR" -> a xor b
            "OR" -> a or b
            "AND" -> a and b
            "MUL" -> a * b
            "SHL" -> a shl (b.toInt() and 63)
            "SHR" -> a shr (b.toInt() and 63)
            "SHRU" -> a.toLong() ushr (b.toInt() and 63)
            "ROTL" -> java.lang.Long.rotateLeft(a, (b.toInt() and 63))
            "ROTR" -> java.lang.Long.rotateRight(a, (b.toInt() and 63))
            "MOD" -> if (b != 0L) a % b else null
            else -> null
        }

        val survivors = candidates.toMutableList()
        for ((a, b, out) in parsed) {
            val iter = survivors.toList()
            for (cand in iter) {
                val v = eval(cand, a, b)
                if (v == null || v != out) {
                    survivors.remove(cand)
                    evidence.add("$cand ✗  ($a, $b) != $out")
                }
            }
            if (survivors.isEmpty()) break
        }
        evidence.addAll(0, parsed.take(5).map { (a, b, o) -> "样本: ($a, $b) -> $o" })

        val winner = if (survivors.size == 1) survivors[0] else ""
        val confidence = when {
            survivors.size == 1 && parsed.size >= 3 -> 0.95 + (parsed.size.coerceAtMost(10) - 3) * 0.005
            survivors.size == 1 -> 0.85
            survivors.isEmpty() -> 0.0
            else -> 0.5  // 多个候选存活（样本不足区分，如 AND/XOR 小数值场景）
        }
        if (survivors.size > 1) {
            evidence.add("多候选存活（样本不足以区分）：${survivors.joinToString("/")}——建议补充大数值/边界样本")
        }
        return HypothesisVerdict(
            opcode = opcode,
            candidates = candidates,
            winner = winner,
            confirmed = survivors.size == 1,
            confidence = (confidence.coerceIn(0.0, 0.99)),
            samplesUsed = parsed.size,
            evidence = evidence.take(30),
        )
    }

    // ---------------- ISA 表渲染 ----------------

    private fun buildIsaTable(handlers: List<HandlerSemantics>): String {
        val sb = StringBuilder()
        sb.appendLine("VM ISA（语义恢复版，${handlers.size} opcodes）：")
        sb.appendLine("opcode | 助记符 | arity | stackIn/Out | 语义签名 | 置信")
        sb.appendLine("-------|--------|-------|-------------|----------|------")
        handlers.take(150).forEach { h ->
            sb.appendLine(
                "${h.key} | ${h.mnemonic} | ${h.arity} | ${h.stackIn}/${h.stackOut} | ${h.signature.take(90)} | ${h.confidence}%",
            )
        }
        return sb.toString()
    }

    private fun buildNotes(handlers: List<HandlerSemantics>, variables: JsvmpDeepAnalyzer.VmVariables): List<String> {
        val notes = mutableListOf<String>()
        val callCount = handlers.count { it.callsHost }
        if (callCount > 0) notes.add("存在 $callCount 个宿主调用 handler（VM 可执行外部回调）")
        val branchCount = handlers.count { it.branchTarget }
        if (branchCount > 0) notes.add("存在 $branchCount 个跳转 handler（控制流由 VM 自管理）")
        val arith = handlers.filter { it.mnemonic in listOf("ADD", "SUB", "MUL", "XOR", "AND", "OR", "SHL", "SHR", "SHRU", "ROTL", "ROTR") }
        if (arith.isNotEmpty()) {
            notes.add("算术/位运算 handler：${arith.joinToString(", ") { "${it.key}=${it.mnemonic}" }.take(300)}")
            notes.add("这些 opcode 可用 jsvmp.validate 喂运行时 (a,b,out) 样本做自动裁决")
        }
        val lowConf = handlers.count { it.confidence < 60 }
        if (lowConf > 0) notes.add("$lowConf 个低置信 handler 建议结合 trace_vmp 采样复核")
        if (variables.pcCandidates.isEmpty()) notes.add("pc 变量未识别——arity 推断可能偏低，建议先 jsvmp.analyze 校准变量")
        return notes
    }
}

// ============================================================================
// 以下为 AST 化切片引擎 + 符号栈（纯 Kotlin，无第三方依赖）
// ============================================================================

/**
 * 符号值：符号栈栈槽承载的符号化表达式。
 *
 * - 来自 `bc[pc+n]` 的操作数常量索引（如 notated="bc[pc+1]"）；
 * - 从 push 进来的表达式回收的符号（赋值/二元运算结果，如 "A XOR B"）；
 * - 虚拟寄存器/上下文名（如 "ctx[3]"）。
 *
 * 数据流链通过 [op]/[leftId]/[rightId]/[leftDepth]/[rightDepth] 表达：
 * `C = A XOR B` 表示 readDepth=1 的 A 与 readDepth=2 的 B 经 XOR 产出 C。
 */
class JsvmpSym(
    val id: String,                 // 短符号 id：A / B / C ...
    val notated: String,            // 人读表达式："A"、"bc[pc+1]"、"A XOR B"
    val op: String? = null,         // 产出该符号的运算符（XOR / ADD ...）
    val leftId: String? = null,     // 左操作数 id
    val rightId: String? = null,    // 右操作数 id
    var readDepth: Int? = null,     // 若从符号栈读取：1 基自顶向下深度
    val leftDepth: Int? = null,     // 左操作数读取深度
    val rightDepth: Int? = null,    // 右操作数读取深度
) {
    override fun toString() = notated
}

/**
 * 符号栈：模拟 VM 操作数栈，push/pop 时记录符号来源，形成数据流链。
 * 由此得出 stackIn（实际读取的顶部槽位数）、stackOut（写入槽位数）、S0/S1。
 */
class JsvmpSymbolicStack {
    /** 栈槽（bottom -> top） */
    val slots = mutableListOf<JsvmpSym>()
    /** 读取事件：(sym, 读取时自顶向下深度) —— 用于 stackIn 与 S0 */
    val reads = mutableListOf<Pair<JsvmpSym, Int>>()
    /** 写入事件 —— 用于 stackOut 与 S1 */
    val writes = mutableListOf<JsvmpSym>()

    val stackIn: Int get() = reads.size
    val stackOut: Int get() = writes.size
    val size: Int get() = slots.size

    fun push(s: JsvmpSym) {
        slots.add(s)
        writes.add(s)
    }

    fun pop(): JsvmpSym? {
        if (slots.isEmpty()) return null
        val idx = slots.size - 1
        val s = slots.removeAt(idx)
        val depth = slots.size + 1
        s.readDepth = depth
        reads.add(s to depth)
        return s
    }

    fun peek(depthFromTop: Int): JsvmpSym? {
        val idx = slots.size - depthFromTop
        if (idx < 0 || idx >= slots.size) return null
        val s = slots[idx]
        s.readDepth = depthFromTop
        reads.add(s to depthFromTop)
        return s
    }

    fun setTop(s: JsvmpSym): Boolean {
        if (slots.isEmpty()) return false
        slots[slots.size - 1] = s
        writes.add(s)
        return true
    }

    /** S0：按读取顺序去重的被消费符号 */
    fun consumed(): List<JsvmpSym> {
        val seen = mutableSetOf<String>()
        val out = mutableListOf<JsvmpSym>()
        for ((s, _) in reads) {
            if (seen.add(s.id)) out.add(s)
        }
        return out
    }
}

/**
 * AST 化切片引擎：把 case 体源码以 [JsAstParser] 解析为 Program，再对每条语句
 * 递归做 AST 级求值，在 [JsvmpSymbolicStack] 上生成符号数据流，
 * 并结构化识别栈操作/寄存器访问/字节码操作数字段。
 */
class JsvmpAstSlicer(
    private val h: JsvmpDeepAnalyzer.HandlerInfo,
    private val vars: JsvmpDeepAnalyzer.VmVariables,
) {

    /** 一次 handler 的 AST 恢复结果 */
    data class AstSliceResult(
        val mnemonic: String,
        val signature: String,
        val operandInfo: JsvmpSemanticRecovery.OperandInfo,
        val stackIn: Int,
        val stackOut: Int,
        val regReads: List<String>,
        val regWrites: List<String>,
        val readsBytecode: Boolean,
        val branchTarget: Boolean,
        val callsHost: Boolean,
        val confidence: Int,
        val ops: List<JsvmpSemanticRecovery.MicroOp>,
        val symbolicStack: List<String>,
    )

    private val pcNames = vars.pcCandidates.toSet() + setOf("pc", "ip")
    private val spNames = vars.spCandidates.toSet() + setOf("sp", "sp")
    private val ctxNames = vars.ctxCandidates.toSet()
    private val bcNames = vars.bytecodeCandidates.toSet()

    /** 已识别的栈数组名（sp 候选 + 在 case 体中用 push/pop 的目标） */
    private val stackNames = spNames.toMutableSet()

    private val varEnv = HashMap<String, JsvmpSym>()
    private val stack = JsvmpSymbolicStack()
    private val regReadsSrc = mutableListOf<String>()
    private val regWritesSrc = mutableListOf<String>()
    private val dataflowSteps = mutableListOf<String>()
    private val ops = mutableListOf<JsvmpSemanticRecovery.MicroOp>()

    private var idCounter = 0
    private val operandOffsets = sortedSetOf<Int>()
    private var readsBc = false
    private var pcAdvance = 0L
    private var pcAbs = false
    private var hostCall = false
    private var stringOp = false
    private var mainComputed: JsvmpSym? = null

    // ------------------------------------------------------------------
    // 入口：解析并求值；无可观测效果/解析失败返回 null（供上层回退 regex）
    // ------------------------------------------------------------------
    fun analyze(): AstSliceResult? {
        val parsed: List<Stmt> = try {
            parseAndSlice()
        } catch (e: Exception) {
            return null
        }
        if (parsed.isEmpty()) return null

        try {
            for (s in parsed) executeStatement(s)
        } catch (e: Exception) {
            // 局部失败不致命：尽可能保留已求值结果
        }

        val stackIn = stack.stackIn
        val stackOut = stack.stackOut
        val observable = stackIn > 0 || stackOut > 0 ||
            regReadsSrc.isNotEmpty() || regWritesSrc.isNotEmpty() ||
            pcAdvance != 0L || pcAbs || hostCall || readsBc ||
            mainComputed != null || operandOffsets.isNotEmpty()
        if (!observable) return null

        return buildResult(stackIn, stackOut)
    }

    // ------------------------------------------------------------------
    // 1. 归一化 + AST 切分
    // ------------------------------------------------------------------
    private fun parseAndSlice(): List<Stmt> {
        val norm = normalizeCaseSnippet(h.snippet)
        if (norm.isBlank()) return emptyList()
        val frags = splitTopLevelFragments(norm)
        if (frags.isEmpty()) return emptyList()
        val parser = JsAstParser()
        val out = mutableListOf<Stmt>()
        for (f in frags) {
            val prog = try {
                parser.parse(f)
            } catch (_: Exception) {
                continue
            }
            for (tl in prog.body) {
                if (tl is TopLevel.Statement) out.add(tl.stmt)
            }
        }
        return out
    }

    private fun normalizeCaseSnippet(raw: String): String {
        var s = raw.trim()
        val caseM = Regex("""^(?:case\s+[^:]{0,80}:|default:)\s*""", RegexOption.IGNORE_CASE).find(s)
        if (caseM != null) s = s.substring(caseM.range.last + 1)
        s = s.removePrefix(":").trim().removePrefix("?").trim()
        // 解包外层 { }
        if (s.startsWith("{") && s.endsWith("}") && balancedBraces(s)) {
            s = s.substring(1, s.length - 1).trim()
        }
        return s
    }

    private fun balancedBraces(s: String): Boolean {
        var d = 0
        for (c in s) when (c) {
            '{' -> d++
            '}' -> d--
        }
        return d == 0
    }

    /** 顶层 `;` 切分（尊重 ()[]{} 与字符串） */
    private fun topLevelSegments(src: String): List<String> {
        val out = mutableListOf<String>()
        val sb = StringBuilder()
        var depth = 0
        var i = 0
        var strip = '\u0000'
        while (i < src.length) {
            val c = src[i]
            if (strip != '\u0000') {
                sb.append(c)
                if (c == '\\') { i++; if (i < src.length) sb.append(src[i]) }
                else if (c == strip) strip = '\u0000'
            } else {
                when {
                    c == '"' || c == '\'' -> { strip = c; sb.append(c) }
                    c == '(' || c == '[' || c == '{' -> { depth++; sb.append(c) }
                    c == ')' || c == ']' || c == '}' -> { depth = maxOf(0, depth - 1); sb.append(c) }
                    c == ';' && depth == 0 -> { if (sb.isNotBlank()) out.add(sb.toString()); sb.clear() }
                    else -> sb.append(c)
                }
            }
            i++
        }
        if (sb.isNotBlank()) out.add(sb.toString())
        return out
    }

    /** 顶层声明 `var a=1,b=2` 按顶层逗号炸开，规避 parser 只取首声明符的缺陷 */
    private fun splitTopLevelFragments(src: String): List<String> {
        val res = mutableListOf<String>()
        for (seg in topLevelSegments(src)) {
            val t = seg.trimStart()
            val m = Regex("^(var|let|const)\\b").find(t)
            if (m != null) {
                val kw = m.groupValues[1]
                val rest = t.substring(t.indexOf(kw) + kw.length)
                for (part in topLevelCommaParts(rest)) {
                    val joined = "$kw $part".trim()
                    if (joined.isNotBlank()) res.add(joined)
                }
            } else if (seg.isNotBlank()) res.add(seg)
        }
        return res
    }

    private fun topLevelCommaParts(s: String): List<String> {
        val out = mutableListOf<String>()
        val sb = StringBuilder()
        var depth = 0
        var i = 0
        var strip = '\u0000'
        while (i < s.length) {
            val c = s[i]
            if (strip != '\u0000') {
                sb.append(c)
                if (c == '\\') { i++; if (i < s.length) sb.append(s[i]) }
                else if (c == strip) strip = '\u0000'
            } else {
                when {
                    c == '"' || c == '\'' -> { strip = c; sb.append(c) }
                    c == '(' || c == '[' || c == '{' -> { depth++; sb.append(c) }
                    c == ')' || c == ']' || c == '}' -> { depth = maxOf(0, depth - 1); sb.append(c) }
                    c == ',' && depth == 0 -> { if (sb.isNotBlank()) out.add(sb.toString().trim()); sb.clear() }
                    else -> sb.append(c)
                }
            }
            i++
        }
        if (sb.isNotBlank()) out.add(sb.toString().trim())
        return out
    }

    // ------------------------------------------------------------------
    // 2. 语句级求值
    // ------------------------------------------------------------------
    private fun executeStatement(s: Stmt) {
        when (s) {
            is Stmt.VarDecl -> {
                val sym = if (s.init != null) evalExpr(s.init) else JsvmpSym(nextId(), "?")
                varEnv[s.name] = sym
            }
            is Stmt.ExprStmt -> evalExpr(s.expr)
            is Stmt.Return -> if (s.arg != null) evalExpr(s.arg)
            else -> { /* 控制流语句忽略 */ }
        }
    }

    // ------------------------------------------------------------------
    // 3. 表达式递归求值
    // ------------------------------------------------------------------
    private fun evalExpr(e: Expr): JsvmpSym {
        return when (e) {
            is Expr.Number -> JsvmpSym(nextId(), e.value)
            is Expr.StringLit -> JsvmpSym(nextId(), "\"${e.value}\"")
            is Expr.BoolLit -> JsvmpSym(nextId(), e.value.toString())
            is Expr.NullLit -> JsvmpSym(nextId(), "null")
            is Expr.UndefinedLit -> JsvmpSym(nextId(), "undefined")
            is Expr.ThisRef -> JsvmpSym(nextId(), "this")
            is Expr.Identifier -> varEnv[e.name] ?: JsvmpSym(nextId(), e.name)
            is Expr.FunctionExpr -> JsvmpSym(nextId(), "fn")
            is Expr.ArrayLit -> JsvmpSym(nextId(), renderOf(e))
            is Expr.ObjectLit -> JsvmpSym(nextId(), renderOf(e))

            is Expr.Unary -> {
                if (e.op == "++" || e.op == "--") {
                    val target = memberRoot(e.operand)
                    if (target != null && target in pcNames) pcAdvance++
                    return JsvmpSym(nextId(), renderOf(e))
                }
                val inner = evalExpr(e.operand)
                when (e.op) {
                    "~" -> computeUnary("~", inner)
                    "!" -> computeUnary("!", inner)
                    "-" -> computeUnary("neg", inner)
                    "+" -> inner
                    "typeof" -> JsvmpSym(nextId(), "typeof ${inner.id}")
                    else -> inner
                }
            }

            is Expr.Binary -> {
                if (e.op == "&&" || e.op == "||") {
                    val l = evalExpr(e.left)
                    return JsvmpSym(nextId(), "${l.id} ${e.op} ?")
                }
                val l = evalExpr(e.left)
                val r = evalExpr(e.right)
                computeBinary(e.op, l, r)
            }

            is Expr.Member -> evalMember(e)
            is Expr.Call -> evalCall(e)
            is Expr.Assign -> evalAssign(e)

            is Expr.Conditional -> {
                evalExpr(e.test)
                evalExpr(e.consequent)
                evalExpr(e.alternate)
                JsvmpSym(nextId(), renderOf(e))
            }

            is Expr.TemplateLit -> {
                e.exprs.forEach { evalExpr(it) }
                JsvmpSym(nextId(), renderOf(e))
            }

            is Expr.TaggedTemplate -> {
                e.template.exprs.forEach { evalExpr(it) }
                JsvmpSym(nextId(), renderOf(e))
            }

            is Expr.Sequence -> {
                var last: JsvmpSym = JsvmpSym(nextId(), "seq")
                for (x in e.exprs) last = evalExpr(x)
                last
            }

            is Expr.New -> {
                e.args.forEach { evalExpr(it) }
                JsvmpSym(nextId(), "new ${renderOf(e.callee)}")
            }

            is Expr.AwaitExpr -> {
                evalExpr(e.arg)
                JsvmpSym(nextId(), "await")
            }

            is Expr.YieldExpr -> {
                e.arg?.let { evalExpr(it) }
                JsvmpSym(nextId(), "yield")
            }

            is Expr.Spread -> evalExpr(e.arg)
        }
    }

    private fun evalMember(e: Expr.Member): JsvmpSym {
        val objName = memberRoot(e.obj) ?: return JsvmpSym(nextId(), renderOf(e))
        val computed = e.computed ?: return JsvmpSym(nextId(), renderOf(e))

        // bc[pc+n] —— 操作数读取
        if (objName in bcNames) {
            readsBc = true
            val n = operandOffsetFrom(computed, objName)
            if (n != null && n > 0) operandOffsets.add(n)
            return JsvmpSym(nextId(), "bc[pc${if (n != null && n > 0) "+$n" else ""}]")
        }

        // 符号栈读取（.length - n / sp - k / sp）
        if (objName in stackNames) {
            val depth = stackDepthOf(computed, objName)
            if (depth != null) {
                val sym = stack.peek(depth) ?: JsvmpSym(nextId(), "?")
                ops.add(JsvmpSemanticRecovery.MicroOp("STACK_READ", "${renderOf(e)} -> stack[-$depth]"))
                return sym
            }
        }

        // 寄存器/上下文读取：r = ctx[i]
        if (objName in ctxNames) {
            val slot = renderOf(computed)
            regReadsSrc.add("$objName[$slot]")
            ops.add(JsvmpSemanticRecovery.MicroOp("REG_READ", "$objName[$slot] -> ?"))
            return JsvmpSym(nextId(), "$objName[$slot]")
        }

        return JsvmpSym(nextId(), renderOf(e))
    }

    private fun evalCall(e: Expr.Call): JsvmpSym {
        val callee = e.callee
        if (callee is Expr.Member) {
            val objName = memberRoot(callee.obj)
            val prop = callee.property
            if (objName != null && objName in bcNames && !"apply".equals(prop, true) && !"call".equals(prop, true) && !"length".equals(prop, true)) {
                // 保留：bc 装载经下标读取已在 evalMember 处理；这里处理 bc<..> 型不需要
            }
            when (prop) {
                "push" -> {
                    if (objName != null) claimStack(objName)
                    for (a in e.args) {
                        val s = evalExpr(a)
                        pushToStack(s)
                    }
                    ops.add(JsvmpSemanticRecovery.MicroOp("PUSH", "${objName ?: "?"}.push(${e.args.joinToString(",") { renderOf(it) }}→)"))
                    return JsvmpSym(nextId(), "~push")
                }
                "pop", "shift" -> {
                    if (objName != null) claimStack(objName)
                    val popped = stack.pop() ?: JsvmpSym(nextId(), "?")
                    ops.add(JsvmpSemanticRecovery.MicroOp("POP", "top -> ${popped.id}"))
                    return popped
                }
                "call", "apply" -> {
                    if (objName != null && !(objName in bcNames)) hostCall = true
                    ops.add(JsvmpSemanticRecovery.MicroOp("CALL", renderOf(e)))
                    return JsvmpSym(nextId(), "call(...)")
                }
            }
        }
        if (callee is Expr.Member && memberRoot(callee.obj) == "Reflect") {
            hostCall = true
            ops.add(JsvmpSemanticRecovery.MicroOp("CALL", renderOf(e)))
        }
        // Math.* / 其他原生调用：求值参数即可（副作用经子表达式回收）
        val args = e.args.map { evalExpr(it) }
        val name = (callee as? Expr.Member)?.property ?: memberRoot(callee) ?: "call"
        val lbl = when (name) {
            "imul", "floor", "ceil", "abs", "pow", "rotl", "rotr",
            // 字符串原语（算法实现里高频的 hex/base64/字符码拼接）
            "fromCharCode", "charCodeAt", "charAt", "codePointAt", "atob", "btoa",
            "toString", "join", "concat", "substring", "substr", "slice",
            -> {
                val opSym = computeCallPrim(name, args)
                // Math.* 调用通常是表达式内嵌，返回值进入后续运算
                return opSym
            }
            else -> name
        }
        return JsvmpSym(nextId(), "$lbl(...)")
    }

    private fun evalAssign(e: Expr.Assign): JsvmpSym {
        val valSym = evalExpr(e.value)
        val target = e.target
        when {
            target is Expr.Identifier -> {
                if (target.name in pcNames) {
                    handlePcWrite(e)
                } else {
                    varEnv[target.name] = valSym
                }
            }
            target is Expr.Member -> {
                val objName = memberRoot(target.obj)
                val computed = target.computed
                when {
                    objName != null && objName in ctxNames -> {
                        val slot = renderOf(computed ?: Expr.Number("?", e.pos))
                        regWritesSrc.add("$objName[$slot]")
                        ops.add(JsvmpSemanticRecovery.MicroOp("REG_WRITE", "$objName[$slot] = ${valSym.id}"))
                    }
                    objName != null && objName in stackNames -> {
                        val depth = stackDepthOf(computed ?: Expr.Number("?", e.pos), objName)
                        if (depth == 1) {
                            stack.setTop(valSym)
                        } else {
                            pushToStack(valSym)
                        }
                        recordComputedIfAny(valSym)
                    }
                    objName != null && objName in bcNames -> { /* 写字节码数组：忽略 */ }
                    else -> {
                        varEnv[target.property ?: "?"] = valSym
                    }
                }
            }
            else -> { /* target 是 Call 等复杂左值，忽略 */ }
        }
        return valSym
    }

    private fun handlePcWrite(e: Expr.Assign) {
        val v = e.value
        val delta = when (v) {
            is Expr.Binary ->
                if (v.op == "+" && (memberRoot(v.left) in pcNames)) constValue(v.right) else null
            else -> null
        }
        if (delta != null && delta > 0) {
            pcAdvance += delta
            ops.add(JsvmpSemanticRecovery.MicroOp("PC_ADV", "pc += $delta"))
        } else if (e.op == "=") {
            pcAbs = true
            ops.add(JsvmpSemanticRecovery.MicroOp("PC_SET", "pc = ${renderOf(v)}"))
        }
    }

    // ------------------------------------------------------------------
    // 4. 符号栈 / 数据流操作
    // ------------------------------------------------------------------
    private fun claimStack(name: String) { stackNames.add(name) }

    private fun pushToStack(s: JsvmpSym) {
        stack.push(s)
        recordComputedIfAny(s)
    }

    private fun recordComputedIfAny(s: JsvmpSym) {
        if (s.op != null) {
            mainComputed = s
            dataflowSteps.add("${s.id} = ${s.notated}")
        }
    }

    private fun computeBinary(op: String, l: JsvmpSym, r: JsvmpSym): JsvmpSym {
        val id = nextId()
        val lb = if (l.readDepth != null) l.id else l.notated.take(24)
        val rb = if (r.readDepth != null) r.id else r.notated.take(24)
        return JsvmpSym(id, "$lb ${opLabel(op)} $rb", op, l.id, r.id, leftDepth = l.readDepth, rightDepth = r.readDepth)
    }

    private fun computeUnary(op: String, x: JsvmpSym): JsvmpSym {
        val id = nextId()
        val xb = if (x.readDepth != null) x.id else x.notated.take(24)
        return JsvmpSym(id, "${opLabel(op)} $xb", op, x.id, null, leftDepth = x.readDepth)
    }

    private fun computeCallPrim(name: String, args: List<JsvmpSym>): JsvmpSym {
        val id = nextId()
        val lb = if (args.size >= 1 && args[0].readDepth != null) args[0].id else (args.getOrNull(0)?.notated?.take(20) ?: "?")
        val rb = if (args.size >= 2 && args[1].readDepth != null) args[1].id else (args.getOrNull(1)?.notated?.take(20) ?: "?")
        // 字符串原语标记——用于 classify 归类 STRING_OP
        if (name in STRING_PRIMS) stringOp = true
        return JsvmpSym(id, when (name) {
            "imul" -> "$lb MUL $rb"
            "floor" -> "FLOOR $lb"
            "ceil" -> "CEIL $lb"
            "abs" -> "ABS $lb"
            "pow" -> "$lb POW $rb"
            "rotl" -> "ROTL($lb, $rb)"
            "rotr" -> "ROTR($lb, $rb)"
            "fromCharCode" -> "STR_FROM_CHARCODE($lb)"
            "charCodeAt" -> "STR_CHARCODE_AT($lb)"
            "charAt" -> "STR_CHAR_AT($lb)"
            "codePointAt" -> "STR_CODEPOINT_AT($lb)"
            "atob" -> "BASE64_DECODE($lb)"
            "btoa" -> "BASE64_ENCODE($lb)"
            "toString" -> "STR_TOSTRING($lb)"
            "join" -> "STR_JOIN($lb)"
            "concat" -> "STR_CONCAT($lb, $rb)"
            "substring" -> "STR_SUBSTR($lb, $rb)"
            "substr" -> "STR_SUBSTR($lb, $rb)"
            "slice" -> "STR_SLICE($lb, $rb)"
            else -> "$name($lb, $rb)"
        }, name, args.getOrNull(0)?.id, args.getOrNull(1)?.id, leftDepth = args.getOrNull(0)?.readDepth, rightDepth = args.getOrNull(1)?.readDepth)
    }

    private companion object {
        val STRING_PRIMS = setOf(
            "fromCharCode", "charCodeAt", "charAt", "codePointAt", "atob", "btoa",
            "toString", "join", "concat", "substring", "substr", "slice",
        )
    }

    // ------------------------------------------------------------------
    // 5. 结构化特征提取
    // ------------------------------------------------------------------
    /** 从 `bc[pc+n]` / `bc[pc]` 的 computed 下标提取操作数偏移 n */
    private fun operandOffsetFrom(computed: Expr, objName: String): Int? {
        return when (computed) {
            is Expr.Binary -> {
                if (computed.op == "+" || computed.op == "-") {
                    constValue(computed.right)?.toInt()
                } else null
            }
            is Expr.Identifier -> {
                if (computed.name in pcNames) 0 else null
            }
            else -> null
        }
    }

    /** 栈槽深度（1 基自顶向下）：`.length-k`→k；`sp-k`→k；裸 `sp`→1；数值→自身 */
    private fun stackDepthOf(computed: Expr, objName: String): Int? {
        return when (computed) {
            is Expr.Number -> computed.value.toIntOrNull()
            is Expr.Identifier -> if (computed.name in spNames) 1 else null
            is Expr.Unary -> { // sp++ / --sp 等指针游标：近似按栈顶
                if (memberRoot(computed.operand) in spNames) 1 else null
            }
            is Expr.Binary -> {
                val rightN = constValue(computed.right)?.toInt() ?: return null
                val leftTxt = renderOf(computed.left)
                when {
                    computed.op == "-" && leftTxt.endsWith(".length") -> rightN
                    computed.op == "-" && leftTxt in spNames -> rightN
                    leftTxt in spNames -> 1
                    else -> null
                }
            }
            else -> null
        }
    }

    /** 常量求值：十进制 / 0x 十六进制 / 负数 */
    private fun constValue(v: Expr): Long? = when (v) {
        is Expr.Number -> v.value.toLongOrNull(10)
            ?: if (v.value.startsWith("0x") || v.value.startsWith("0X")) v.value.substring(2).toLongOrNull(16) else null
        else -> null
    }

    /** 成员/调用链根的标识符名：a.b.c -> a ；a[i].x -> a */
    private fun memberRoot(e: Expr): String? = when (e) {
        is Expr.Identifier -> e.name
        is Expr.Member -> memberRoot(e.obj)
        else -> null
    }

    private fun renderOf(e: Expr?): String = if (e != null) AstRender.expr(e) else "?"

    private fun opLabel(op: String): String = when (op) {
        "+" -> "ADD"; "-" -> "SUB"; "*" -> "MUL"; "/" -> "DIV"; "%" -> "MOD"
        "^" -> "XOR"; "&" -> "AND"; "|" -> "OR"
        "<<" -> "SHL"; ">>" -> "SHR"; ">>>" -> "SHRU"
        "~" -> "NOT"; "!" -> "LNOT"; "neg" -> "NEG"
        "==", "===" -> "EQ"; "!=", "!==" -> "NE"; "<" -> "LT"; ">" -> "GT"; "<=" -> "LE"; ">=" -> "GE"
        // 字符串原语助记符
        "fromCharCode" -> "STR_FROM_CHARCODE"; "charCodeAt" -> "STR_CHARCODE_AT"
        "charAt" -> "STR_CHAR_AT"; "codePointAt" -> "STR_CODEPOINT_AT"
        "atob" -> "BASE64_DECODE"; "btoa" -> "BASE64_ENCODE"
        "toString" -> "STR_TOSTRING"; "join" -> "STR_JOIN"; "concat" -> "STR_CONCAT"
        "substring" -> "STR_SUBSTR"; "substr" -> "STR_SUBSTR"; "slice" -> "STR_SLICE"
        else -> op
    }

    private fun nextId(): String {
        val n = idCounter++
        return when {
            n < 26 -> ('A' + n).toString()
            else -> ('A' + (n % 26)) + (n / 26).toString()
        }
    }

    private fun inferEncoding(): String = when {
        h.snippet.contains("Uint32Array") -> "u32le"
        h.snippet.contains("Uint16Array") -> "u16le"
        h.snippet.contains("Uint8ClampedArray") || h.snippet.contains("Uint8Array") -> "u8"
        else -> "varint/u8le"
    }

    // ------------------------------------------------------------------
    // 6. 结果合成
    // ------------------------------------------------------------------
    private fun buildResult(stackIn: Int, stackOut: Int): AstSliceResult {
        val opSym = mainComputed
        val (mnemonic, signature, confidence) = classify(opSym, stackIn, stackOut)

        val operandCount = operandOffsets.size
        val operandWidth = operandOffsets.maxOrNull() ?: 0
        val pcDelta = if (readsBc && pcAdvance == 0L) operandWidth.toLong() else pcAdvance
        val operandInfo = JsvmpSemanticRecovery.OperandInfo(
            operandCount = operandCount,
            operandWidth = operandWidth,
            operandEncoding = inferEncoding(),
            pcDelta = pcDelta.toInt(),
        )

        val symbolicStack = buildSymbolicStackLines(stackOut)

        return AstSliceResult(
            mnemonic = mnemonic,
            signature = signature,
            operandInfo = operandInfo,
            stackIn = stackIn,
            stackOut = stackOut,
            regReads = regReadsSrc.distinct().take(8),
            regWrites = regWritesSrc.distinct().take(8),
            readsBytecode = readsBc,
            branchTarget = pcAbs,
            callsHost = hostCall,
            confidence = confidence,
            ops = ops.take(20),
            symbolicStack = symbolicStack,
        )
    }

    private fun classify(opSym: JsvmpSym?, stackIn: Int, stackOut: Int): Triple<String, String, Int> {
        if (hostCall) {
            val args = (0 until stackIn).joinToString(", ") { "arg${it + 1}" }
            return Triple(
                "CALL",
                "CALL($args) -> ${if (stackOut > 0) "stack[-1]" else "(结果不回栈)"}",
                88,
            )
        }
        if (pcAbs) {
            return Triple(
                if (stackIn > 0) "CJMP" else "JMP",
                if (stackIn > 0) "CJMP(stack[-1], target)" else "JMP(target)",
                80,
            )
        }
        // 字符串原语优先于通用算术归类（fromCharCode/charCodeAt/atob 等）
        if (stringOp && opSym != null && opSym.op != null) {
            return Triple(opLabel(opSym.op), unarySig(opSym), 84)
        }
        if (opSym != null && opSym.op != null && opSym.leftId != null && opSym.rightId != null) {
            return Triple(opLabel(opSym.op), binarySig(opSym), 90)
        }
        if (opSym != null && opSym.op != null) {
            return Triple(opLabel(opSym.op), unarySig(opSym), 85)
        }
        if (stackIn >= 2 && stackOut >= 1) {
            return Triple("AGGREGATE", aggregateSig(), 65)
        }
        if (regWritesSrc.isNotEmpty() && stackIn >= 1) {
            return Triple("ST_REG", "store ${regWritesSrc.first()} <- stack[-1]", 85)
        }
        if (regReadsSrc.isNotEmpty() && stackOut >= 1 && stackIn == 0) {
            return Triple("LD_REG", "load stack <- ${regReadsSrc.first()}", 85)
        }
        if (readsBc && stackOut >= 1 && stackIn == 0) {
            val w = operandOffsets.maxOrNull() ?: 0
            return Triple("LOAD_BC", "push bc[pc+${if (w > 0) "1..$w" else "0"}]", 82)
        }
        if (stackIn == 1 && stackOut == 2) return Triple("DUP", "DUP(stack[-1]) -> stack[-1], stack[-2]", 70)
        if (stackIn == 2 && stackOut == 2) return Triple("SWAP", "SWAP(stack[-1], stack[-2])", 70)
        if (stackIn > 0 && stackOut == 0) return Triple("DROP", "drop stack[-$stackIn]", 60)
        if (regReadsSrc.isNotEmpty() && regWritesSrc.isNotEmpty()) {
            return Triple("MOV", "MOV(${regWritesSrc.first()} <- ${regReadsSrc.first()})", 80)
        }
        val sb = StringBuilder()
        if (stackOut > 0) sb.append("push×$stackOut ")
        if (stackIn > 0) sb.append("pop×$stackIn ")
        if (readsBc) sb.append("readBC ")
        return Triple("OTHER", sb.toString().trim().ifEmpty { "无可用特征" }, 40)
    }

    private fun binarySig(opSym: JsvmpSym): String {
        val ld = opSym.leftDepth?.let { "stack[-$it]=${opSym.leftId}" } ?: "${opSym.leftId ?: "?"}"
        val rd = opSym.rightDepth?.let { "stack[-$it]=${opSym.rightId}" } ?: "${opSym.rightId ?: "?"}"
        return "${opLabel(opSym.op!!)}($ld, $rd)->${opSym.id}"
    }

    private fun unarySig(opSym: JsvmpSym): String {
        val xd = opSym.leftDepth?.let { "stack[-$it]=${opSym.leftId}" } ?: "${opSym.leftId ?: "?"}"
        return "${opLabel(opSym.op!!)}($xd)->${opSym.id}"
    }

    private fun aggregateSig(): String {
        val ordered = stack.reads.distinctBy { it.first.id }.sortedByDescending { it.second }
        val parts = ordered.joinToString(", ") { (s, d) -> "stack[-$d]=${s.id}" }
        val res = stack.writes.firstOrNull()
        return "AGG($parts)->${res?.id ?: "?"}"
    }

    private fun buildSymbolicStackLines(stackOut: Int): List<String> {
        val lines = mutableListOf<String>()
        val consumed = stack.consumed()
        lines.add("S0=[${consumed.joinToString(", ") { it.id }}]")
        lines.addAll(dataflowSteps.distinct())
        val outSym = stack.writes.distinctBy { it.id }
        lines.add("S1=[${outSym.joinToString(", ") { it.id }}]")
        return lines
    }
}