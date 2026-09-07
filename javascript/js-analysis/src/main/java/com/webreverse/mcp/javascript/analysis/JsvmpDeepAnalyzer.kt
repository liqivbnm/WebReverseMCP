package com.webreverse.mcp.javascript.analysis

/**
 * JSVMP 深度分析器 v1（ 新增）。
 *
 * 在 VmpDetector（定位 dispatch 循环）之上补齐逆向 JSVMP 的结构化能力：
 * 1. **Handler 语义分类**：对 dispatch switch 的每个 case 体做特征识别，
 *    归类为 load/store/arith/compare/branch/call/member/stack/return 等
 *    VM 原语语义——LLM 拿到「opcode -> 语义」映射表即可重建 VM ISA。
 * 2. **VM 状态变量识别**：从 dispatch 判别式与 case 体推断 pc/sp/ctx/寄存器
 *    数组等关键变量名，直接喂给 trace 表达式。
 * 3. **指令流提取**：识别字节码载体（大整数数组/base64/hex 字符串），
 *    输出前 N 条指令的 opcode 序列（配合运行时 trace 对齐静态静态语义）。
 * 4. **VM 结构画像**：入口函数、解释器函数、上下文对象、跳转表布局的
 *    整体结构摘要。
 */
class JsvmpDeepAnalyzer {

    // ---------------- 数据模型 ----------------

    /** case handler 的语义分类 */
    enum class HandlerKind(val display: String) {
        LOAD_CONST("常量加载: push immediate/string"),
        LOAD_LOCAL("局部加载: ctx/reg 数组读取"),
        STORE_LOCAL("局部存储: ctx/reg 数组写入"),
        ARITH("算术: +/-/*/Math.imul/位运算"),
        COMPARE("比较: ==/!=/</>/instanceof"),
        BRANCH("跳转: pc 赋值/条件跳转"),
        CALL("调用: fn.apply/call/()调用"),
        MEMBER("成员访问: obj[key]/property"),
        STACK_OP("栈操作: push/pop/shift"),
        RETURN("返回: return"),
        STRING_OP("字符串操作: fromCharCode/charCodeAt/slice/replace"),
        ENV_OP("环境: window/document/navigator 访问"),
        UNKNOWN("未识别"),
    }

    data class HandlerInfo(
        val key: String,             // opcode 键（0x1a / 26 / 'a'）
        val kind: HandlerKind,
        val confidence: Int,         // 0-100
        val evidence: List<String>,  // 命中的特征
        val snippet: String,         // case 体（截断 200）
        val line: Int,
        val column: Int,
    )

    data class VmVariables(
        val pcCandidates: List<String>,     // 程序计数器变量
        val spCandidates: List<String>,     // 栈指针
        val ctxCandidates: List<String>,    // 上下文/寄存器组
        val bytecodeCandidates: List<String>, // 字节码数组
        val dispatchExpr: String,           // switch 判别式
    )

    data class InstructionStream(
        val carrierType: String,        // array / base64 / hex / unknown
        val carrierName: String,
        val instructionCount: Int,
        val opcodePreview: List<String>, // 前 100 条
        val distinctOpcodes: Int,
    )

    data class VmProfile(
        val candidateCount: Int,
        val handlers: List<HandlerInfo>,
        val kindHistogram: Map<String, Int>,
        val variables: VmVariables,
        val instructions: InstructionStream,
        val isaSummary: String,          // 人类可读 ISA 摘要
        val entryHints: List<String>,    // VM 入口提示
    )

    // ---------------- 入口 ----------------

    fun analyze(source: String, candidate: VmpDetector.VmpCandidate): VmProfile {
        val handlers = candidate.handlers.map { classifyHandler(it) }
        val hist = handlers.groupingBy { it.kind.display }.eachCount()
        val vars = identifyVariables(source, candidate)
        val ins = extractInstructions(source, candidate)
        return VmProfile(
            candidateCount = candidate.caseCount,
            handlers = handlers,
            kindHistogram = hist,
            variables = vars,
            instructions = ins,
            isaSummary = buildIsaSummary(handlers, hist),
            entryHints = findEntryHints(source, candidate),
        )
    }

    // ---------------- 1. Handler 语义分类 ----------------

    private val classifyRules: List<Pair<HandlerKind, List<Regex>>> = listOf(
        HandlerKind.RETURN to listOf(
            Regex("""\breturn\b"""),
        ),
        HandlerKind.CALL to listOf(
            Regex("""\.apply\s*\("""),
            Regex("""\.call\s*\("""),
            Regex("""\bReflect\s*\."""),
            Regex("""\)\s*\(\s*\)"""),
        ),
        HandlerKind.BRANCH to listOf(
            Regex("""=\s*\w+\s*\+\s*\d"""),            // pc = pc + n
            Regex("""\[\w+\s*\+\s*(0x)?\d+\]"""),      // 跳转表 [pc+n]
            Regex("""\?\s*[^:]{1,60}:"""),
        ),
        HandlerKind.COMPARE to listOf(
            Regex("""[=!]==?\s"""),
            Regex("""[<>]=?\s"""),
            Regex("""\binstanceof\b"""),
        ),
        HandlerKind.STRING_OP to listOf(
            Regex("""fromCharCode|charCodeAt"""),
            Regex("""\.charAt|\.charCodeAt|\.codePointAt"""),
            Regex("""\.replace\(|\.slice\(|\.substr\(|\.split\("""),
            Regex("""atob|btoa|String\.fromCharCode"""),
        ),
        HandlerKind.MEMBER to listOf(
            Regex("""\[\s*\w+\s*\+\s*\(?(0x)?\d+"""),
            Regex("""\.length\b"""),
            Regex("""Object\.(?:defineProperty|getOwnProperty)"""),
        ),
        HandlerKind.ARITH to listOf(
            Regex("""\bMath\.imul\b"""),
            Regex("""\bMath\.(?:floor|ceil|abs|pow)\b"""),
            Regex("""[+\-*/%]=?\s"""),
            Regex("""<<|>>|>>>|&|\||\^"""),
        ),
        HandlerKind.STACK_OP to listOf(
            Regex("""\.push\("""),
            Regex("""\.pop\(\)"""),
            Regex("""\.shift\(\)"""),
            Regex("""\.splice\("""),
        ),
        HandlerKind.LOAD_CONST to listOf(
            Regex("""=\s*(0x[0-9a-fA-F]+|\d{1,10}|'[^']{0,40}'|"[^"]{0,40}")\s*;"""),
        ),
        HandlerKind.LOAD_LOCAL to listOf(
            Regex("""\[\s*_?0x[0-9a-fA-F]+\s*\+"""),  // reg[pc+1]
            Regex("""=\s*\w{1,3}\[\w+\]"""),
        ),
        HandlerKind.STORE_LOCAL to listOf(
            Regex("""\w{1,3}\[\w+\s*(?:\+\s*\d+)?\]\s*="""),
        ),
        HandlerKind.ENV_OP to listOf(
            Regex("""\b(?:window|document|navigator|location|globalThis)\b"""),
        ),
    )

    private fun classifyHandler(h: VmpDetector.OpHandler): HandlerInfo {
        var bestKind = HandlerKind.UNKNOWN
        var bestScore = 0
        var bestEvidence = listOf<String>()
        for ((kind, rules) in classifyRules) {
            val hits = rules.filter { it.containsMatchIn(h.snippet) }.map { it.pattern.take(40) }
            val score = hits.size * 100 / rules.size
            if (hits.isNotEmpty() && score > bestScore) {
                bestKind = kind
                bestScore = maxOf(score, 30)
                bestEvidence = hits
            }
        }
        // return 单独豁免：很多 handler 尾部有 return，不能仅凭 return 分类
        if (bestKind == HandlerKind.RETURN && h.snippet.length > 40) {
            bestKind = HandlerKind.UNKNOWN; bestScore = 0; bestEvidence = emptyList()
            for ((kind, rules) in classifyRules.filter { it.first != HandlerKind.RETURN }) {
                val hits = rules.filter { it.containsMatchIn(h.snippet) }.map { it.pattern.take(40) }
                val score = hits.size * 100 / rules.size
                if (hits.isNotEmpty() && score > bestScore) {
                    bestKind = kind; bestScore = maxOf(score, 30); bestEvidence = hits
                }
            }
        }
        return HandlerInfo(h.key, bestKind, bestScore, bestEvidence, h.snippet, h.line, h.column)
    }

    // ---------------- 2. VM 状态变量识别 ----------------

    /** 通用标识符（覆盖 _0x 混淆名）：真实 JSVMP 变量几乎全是 _0x 前缀 */
    private val ident = "[A-Za-z_$][\\w$]{0,12}"
    private val vmKeywords = setOf(
        "case", "switch", "break", "continue", "return", "var", "let", "const",
        "new", "function", "typeof", "length", "push", "pop", "shift", "splice",
        "String", "Math", "Object", "window", "document", "globalThis", "this",
    )

    private fun identifyVariables(source: String, c: VmpDetector.VmpCandidate): VmVariables {
        val window = source.substring(
            (offsetOf(source, c.switchLine, c.switchColumn) - 400).coerceAtLeast(0),
            (offsetOf(source, c.switchLine, c.switchColumn) + 600).coerceAtMost(source.length),
        )
        // switch 判别式：switch (X[Y++]) / switch (X) 等
        val dispMatch = Regex("""switch\s*\(\s*([^)]{1,80})\)""").find(window)
        // P1-5：decision-tree 风格时从 if 条件提取判别式（无 switch 可匹配）
        val treeMatch = Regex("""if\s*\(\s*([A-Za-z_$][\w$.\[\]+]{1,60}?)\s*(?:={2,3}|!==?)""").find(window)
        val dispatchExpr = when {
            dispMatch != null -> dispMatch.groupValues[1]
            treeMatch != null -> treeMatch.groupValues[1]
            else -> ""
        }

        val pcCands = linkedSetOf<String>()
        val spCands = linkedSetOf<String>()
        val ctxCands = linkedSetOf<String>()
        val bcCands = linkedSetOf<String>()

        fun addIfVar(name: String, target: MutableSet<String>) {
            if (name.isNotBlank() && name !in vmKeywords && name.length <= 13) target.add(name)
        }

        // 判别式 X[Y...]：X 是字节码数组，Y 是 pc（允许 Y 后跟 ++ 等运算）
        Regex("($ident)\\s*\\[\\s*($ident)").findAll(dispatchExpr).forEach { m ->
            addIfVar(m.groupValues[1], bcCands)
            addIfVar(m.groupValues[2], pcCands)
        }
        // case 体特征（通用标识符，覆盖 _0x 名）
        val body = c.handlers.joinToString(";") { it.snippet }
        Regex("\\b($ident)\\s*\\+\\+").findAll(body).forEach { addIfVar(it.groupValues[1], pcCands) }
        Regex("\\b($ident)\\s*\\+=\\s*\\d").findAll(body).forEach { addIfVar(it.groupValues[1], pcCands) }
        Regex("\\b($ident)\\s*=\\s*$ident\\s*\\+\\s*\\d").findAll(body).forEach { addIfVar(it.groupValues[1], pcCands) }
        // 栈指针：X.push / X.pop
        Regex("\\b($ident)\\s*\\.\\s*(?:push|pop|shift)\\s*[(.]").findAll(body).forEach { addIfVar(it.groupValues[1], spCands) }
        // 寄存器组/上下文：X[Y + n] 形式且 X 不是字节码数组
        Regex("\\b($ident)\\s*\\[\\s*$ident\\s*\\+\\s*\\d").findAll(body).forEach { m ->
            if (m.groupValues[1] !in bcCands) addIfVar(m.groupValues[1], ctxCands)
        }
        // 语义命名：包含 ctx/regs/frame/stack/sp/pc 的标识符
        Regex("\\b($ident)\\b").findAll(body).forEach { m ->
            val n = m.groupValues[1]
            val lower = n.lowercase()
            when {
                lower.contains("ctx") || lower.contains("context") -> addIfVar(n, ctxCands)
                lower.contains("reg") || lower.contains("frame") -> addIfVar(n, ctxCands)
                lower.endsWith("sp") || lower.contains("stack") -> addIfVar(n, spCands)
                lower.endsWith("pc") || lower.contains("bytecode") || lower.contains("opcode") -> {
                    addIfVar(n, if (lower.endsWith("pc")) pcCands else bcCands)
                }
            }
        }
        // VmpDetector 已识别的疑似数组变量直接并入
        c.suggestedOps.forEach { bcCands.add(it) }
        return VmVariables(
            pcCandidates = pcCands.toList().take(6),
            spCandidates = spCands.toList().take(4),
            ctxCandidates = ctxCands.toList().take(6),
            bytecodeCandidates = bcCands.toList().take(6),
            dispatchExpr = dispatchExpr.take(80),
        )
    }

    private fun offsetOf(source: String, line: Int, column: Int): Int {
        var cur = 1
        var i = 0
        while (i < source.length && cur < line) {
            if (source[i] == '\n') cur++
            i++
        }
        return i + column - 1
    }

    // ---------------- 3. 指令流提取 ----------------

    private fun extractInstructions(source: String, c: VmpDetector.VmpCandidate): InstructionStream {
        // 1) 大整数数组载体：var X = [123, 45, 67, ...]（元素 >= 30 个且多为数值）
        val arrayRe = Regex("""(?:var|let|const)\s+([A-Za-z_$][\w$]{0,15})\s*=\s*\[\s*(\d{1,10})\s*(?:,\s*\d{1,10}\s*){20,}\]""")
        for (m in arrayRe.findAll(source).take(50)) {
            // 只在 [...] 括号内提取数字（避免变量名中的数字混入指令流）
            val bracket = m.value.substringAfter('[').substringBefore(']')
            val nums = Regex("""\d{1,10}""").findAll(bracket).map { it.value }.toList()
            if (nums.size >= 20) {
                return InstructionStream(
                    "array", m.groupValues[1], nums.size,
                    nums.take(100), nums.distinct().size,
                )
            }
        }
        // 2) base64 载体：长 base64 字符串（解码后为字节码）
        val b64 = Regex("""['"]([A-Za-z0-9+/=]{200,})['"]""").find(source)
        if (b64 != null) {
            val decoded = runCatching {
                // java.util.Base64：JVM 单测与 Android 26+ 双端可用（Mime 宽松模式容忍换行）
                java.util.Base64.getMimeDecoder().decode(b64.groupValues[1])
            }.getOrNull()
            if (decoded != null && decoded.size >= 40) {
                return InstructionStream(
                    "base64", "<inline>", decoded.size,
                    decoded.take(100).map { "%02x".format(it) },
                    decoded.distinct().size,
                )
            }
        }
        // 3) hex 载体：'1a2b3c...' 形式
        val hex = Regex("""['"]([0-9a-fA-F]{100,})['"]""").find(source)
        if (hex != null) {
            val h = hex.groupValues[1]
            val ops = h.chunked(2).take(100)
            return InstructionStream("hex", "<inline>", h.length / 2, ops, ops.distinct().size)
        }
        return InstructionStream("unknown", "", 0, emptyList(), 0)
    }

    // ---------------- 4. ISA 摘要 ----------------

    private fun buildIsaSummary(handlers: List<HandlerInfo>, hist: Map<String, Int>): String {
        val sb = StringBuilder()
        sb.append("VM ISA 概览：共 ${handlers.size} 个 opcode handler，语义分布：\n")
        hist.entries.sortedByDescending { it.value }.forEach { (k, v) ->
            sb.append("  $k × $v\n")
        }
        sb.append("\nopcode -> 语义映射（按分类分组）：\n")
        HandlerKind.entries.filter { k -> handlers.any { it.kind == k } }.forEach { k ->
            val keys = handlers.filter { it.kind == k }.joinToString(", ") { it.key }
            sb.append("  [${k.name}] $keys\n")
        }
        return sb.toString()
    }

    private fun findEntryHints(source: String, c: VmpDetector.VmpCandidate): List<String> {
        val hints = mutableListOf<String>()
        // 解释器函数名：dispatch 循环外层函数名
        val fnRe = Regex("""(?:function\s+([A-Za-z_$][\w$]*)|(?:var|const|let)\s+([A-Za-z_$][\w$]*)\s*=\s*function)""")
        val head = source.substring(0, offsetOf(source, c.switchLine, c.switchColumn).coerceAtMost(source.length))
        val lastFn = fnRe.findAll(head).lastOrNull()
        lastFn?.let {
            val name = it.groupValues[1].ifBlank { it.groupValues[2] }
            if (name.isNotBlank()) hints.add("解释器疑似函数: $name()（dispatch 所在函数）")
        }
        if (c.handlers.any { it.snippet.contains("apply") }) hints.add("存在函数调用原语（CALL handler）——VM 可执行宿主回调")
        if (c.handlers.any { it.snippet.contains("fromCharCode") }) hints.add("存在字符串解密原语——字符串在运行时还原")
        hints.add("下一步建议：debugger.trace_vmp 对 dispatch 判别式采样，配合本 ISA 映射重建执行流")
        return hints
    }
}
