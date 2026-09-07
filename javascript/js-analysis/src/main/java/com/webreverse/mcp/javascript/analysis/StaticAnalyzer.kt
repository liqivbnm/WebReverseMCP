package com.webreverse.mcp.javascript.analysis

/**
 * 静态深度分析器 v1（ 新增）。
 *
 * 面向逆向场景的函数级静态分析，补齐 JsParser（正则级）之上的结构化能力：
 * 1. **函数调用图（CallGraph）**：函数 -> 被调用函数集合，支持按入口反查调用链（callers），
 *    逆向时"谁调用了签名函数"一步定位。
 * 2. **圈复杂度 + 结构统计**：每个函数的 if/for/while/switch/try/&&/||/?. 计数，
 *    高复杂度 + 短命名 + 高熵 = 混淆核心逻辑的定位信号。
 * 3. **字符串解密链（DecryptChain）**：识别「字符串数组 + 解码函数 + 引用点」三件套——
 *    javascript-obfuscator 系混淆的标准布局，输出每个引用点的可还原字符串。
 * 4. **敏感数据流（SensitiveFlow）**：定位 cookie/token/localStorage/密码的读写点，
 *    便于配合 hook 做动态验证。
 */
class StaticAnalyzer {

    // ---------------- 数据模型 ----------------

    data class FuncStat(
        val name: String,
        val line: Int,
        val params: Int,
        val bodyLength: Int,
        val cyclomatic: Int,          // 圈复杂度（1 + 分支数）
        val branches: Int,            // if/for/while/switch-case/&&/|| 总数
        val loops: Int,
        val switchCount: Int,
        val tryCount: Int,
        val async: Boolean,
        val calls: List<String>,      // 直接调用的函数名（去重）
        val isSuspect: Boolean,       // 疑似混淆核心（高复杂度 + 高熵特征）
        val suspectReasons: List<String>,
    )

    data class CallGraph(
        val functions: Int,
        val edges: Int,
        val adjacency: Map<String, List<String>>,   // caller -> callees
        val callers: Map<String, List<String>>,     // callee -> callers（反查）
        val hotspots: List<String>,                 // 被调用次数最多的函数（>1 个调用者）
        val orphans: List<String>,                  // 无人调用的函数（可能是入口/死代码）
    )

    data class DecryptChain(
        val found: Boolean,
        val arrayName: String,
        val arraySize: Int,
        val arrayPreview: List<String>,    // 前 30 个元素
        val decoderName: String,
        val decoderBody: String,           // 解码函数体（截断）
        val decodeCallSites: List<DecodeSite>,
        val offsetsPattern: Boolean,       // 是否含偏移自解（shuffle + IIFE 还原）
        // 完整原始声明（供本地模拟与页面沙箱重执行，不做压缩截断）
        val arrayDecl: String = "",        // 如 "var _0xabc = ['s1','s2',...];"
        val decoderDecl: String = "",      // 如 "function _0xdef(a,b){...}"（完整）
    )

    data class DecodeSite(val line: Int, val expression: String, val decodedGuess: String)

    data class SensitiveFlow(
        val reads: List<FlowPoint>,
        val writes: List<FlowPoint>,
    )

    data class FlowPoint(val kind: String, val line: Int, val context: String)

    data class StaticReport(
        val funcStats: List<FuncStat>,
        val callGraph: CallGraph,
        val decryptChain: DecryptChain,
        val sensitiveFlow: SensitiveFlow,
        val totalLines: Int,
    )

    // ---------------- 入口 ----------------

    fun analyze(source: String): StaticReport {
        val funcs = extractFunctionStats(source)
        val graph = buildCallGraph(funcs)
        val chain = findDecryptChain(source)
        val flow = findSensitiveFlow(source)
        return StaticReport(funcs, graph, chain, flow, source.count { it == '\n' } + 1)
    }

    // ---------------- 1. 函数统计 + 复杂度 ----------------

    private val funcRe = Regex(
        """(?:function\s+\*?\s*([A-Za-z_$][\w$]*)|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>))\s*\(?\s*([^)]{0,200})""",
    )

    private fun extractFunctionStats(source: String): List<FuncStat> {
        val lineStarts = buildLineIndex(source)
        val results = mutableListOf<FuncStat>()
        for (m in funcRe.findAll(source)) {
            val name = (m.groupValues[1].ifBlank { m.groupValues[2] })
            if (name.isBlank()) continue
            val body = extractBalancedBody(source, m.range.first)
            if (body.isBlank()) continue
            val line = offsetToLine(lineStarts, m.range.first)
            val params = m.groupValues[3].count { it == ',' } + m.groupValues[3].trim().let { if (it.isBlank()) 0 else 1 }
            results.add(statOf(name, line, params, body, source))
            if (results.size >= 800) break // 上限保护
        }
        return results
    }

    private fun statOf(name: String, line: Int, params: Int, body: String, whole: String): FuncStat {
        val ifC = Regex("""\bif\s*\(""").findAll(body).count()
        val forC = Regex("""\bfor\s*\(""").findAll(body).count()
        val whileC = Regex("""\bwhile\s*\(""").findAll(body).count()
        val caseC = Regex("""\bcase\s+[\w'"]+\s*:""").findAll(body).count()
        val tryC = Regex("""\btry\s*\{""").findAll(body).count()
        val andC = Regex("""&&""").findAll(body).count()
        val orC = Regex("""\|\|""").findAll(body).count()
        val optC = Regex("""\?\.""").findAll(body).count()
        val ternaryC = Regex("""\?[^?:]{1,80}:""").findAll(body).count()
        val branches = ifC + forC + whileC + caseC + andC + orC + ternaryC
        val loops = forC + whileC

        // 调用提取：callee( 形式，排除关键字
        val keywords = setOf("if", "for", "while", "switch", "catch", "return", "function", "typeof", "new", "await", "void")
        val calls = Regex("""(?:([A-Za-z_$][\w$]*)\s*\(|\.([A-Za-z_$][\w$]*)\s*\()""")
            .findAll(body)
            .map { it.groupValues[1].ifBlank { it.groupValues[2] } }
            .filter { it.isNotBlank() && it !in keywords }
            .distinct()
            .take(40)
            .toList()

        // 疑似混淆核心判定
        val reasons = mutableListOf<String>()
        var suspect = false
        val shortName = name.replace(Regex("""^_+"""), "").length <= 3 && name.any { it.isDigit() || it == '$' }
        if (branches >= 25) { suspect = true; reasons.add("分支密度极高($branches)") }
        if (caseC >= 20) { suspect = true; reasons.add("switch-case 数量异常($caseC)") }
        if (shortName && branches >= 10) { suspect = true; reasons.add("机器命名+复杂逻辑") }
        if (Regex("""\\x[0-9a-f]{2}""").findAll(body).count() >= 10) { suspect = true; reasons.add("十六进制转义密集") }
        if (Regex("""fromCharCode|charCodeAt""").findAll(body).count() >= 3) { reasons.add("字符码操作") }

        return FuncStat(
            name = name, line = line, params = params, bodyLength = body.length,
            cyclomatic = 1 + branches, branches = branches, loops = loops,
            switchCount = caseC, tryCount = tryC, async = body.contains("await") || name.startsWith("async"),
            calls = calls, isSuspect = suspect, suspectReasons = reasons,
        )
    }

    /** 从 offset 起提取平衡花括号体（找 '{' 后配对 '}'） */
    private fun extractBalancedBody(source: String, from: Int): String {
        val open = source.indexOf('{', from)
        if (open < 0) return ""
        var depth = 0
        var i = open
        var inStr: Char? = null
        while (i < source.length) {
            val c = source[i]
            if (inStr != null) {
                if (c == '\\') i++
                else if (c == inStr) inStr = null
            } else when (c) {
                '\'', '"', '`' -> inStr = c
                '{' -> depth++
                '}' -> {
                    depth--
                    if (depth == 0) return source.substring(open + 1, i)
                }
            }
            i++
        }
        return ""
    }

    /** 完整平衡块（含首尾花括号），从 from 起到配对 '}'：用于可重执行的原始声明 */
    private fun extractBalancedFull(source: String, from: Int): String {
        val open = source.indexOf('{', from)
        if (open < 0) return ""
        var depth = 0
        var i = open
        var inStr: Char? = null
        while (i < source.length) {
            val c = source[i]
            if (inStr != null) {
                if (c == '\\') i++
                else if (c == inStr) inStr = null
            } else when (c) {
                '\'', '"', '`' -> inStr = c
                '{' -> depth++
                '}' -> {
                    depth--
                    if (depth == 0) return source.substring(from, i + 1)
                }
            }
            i++
        }
        return ""
    }

    // ---------------- 2. 调用图 ----------------

    private fun buildCallGraph(funcs: List<FuncStat>): CallGraph {
        val known = funcs.map { it.name }.toSet()
        val adjacency = funcs.associate { f -> f.name to f.calls.filter { it in known } }
        val edges = adjacency.values.sumOf { it.size }
        val callers = HashMap<String, MutableList<String>>()
        adjacency.forEach { (caller, callees) ->
            callees.forEach { ce ->
                callers.getOrPut(ce) { mutableListOf() }.add(caller)
            }
        }
        val hotspots = callers.entries
            .filter { it.value.size >= 2 }
            .sortedByDescending { it.value.size }
            .take(30)
            .map { it.key }
        val called = adjacency.values.flatten().toSet()
        val orphans = funcs.map { it.name }.filter { it !in called && (adjacency[it]?.isEmpty() ?: true) }
            .take(50)
        return CallGraph(funcs.size, edges, adjacency, callers, hotspots, orphans)
    }

    /** 反查调用链：从入口沿 callers 递归（深度限制防环） */
    fun traceCallers(graph: CallGraph, target: String, maxDepth: Int = 5): List<String> {
        val out = mutableListOf<String>()
        val visited = mutableSetOf(target)
        fun walk(fn: String, depth: Int, path: String) {
            if (depth > maxDepth) return
            graph.callers[fn]?.forEach { caller ->
                if (caller !in visited) {
                    visited.add(caller)
                    val p = "$path <- $caller"
                    out.add(p)
                    walk(caller, depth + 1, p)
                }
            }
        }
        walk(target, 1, target)
        return out.take(40)
    }

    // ---------------- 3. 字符串解密链 ----------------

    /**
     * 识别 javascript-obfuscator 布局：
     *   const _0xabc = ['str1', 'str2', ...];          <- 字符串数组
     *   function _0xdef(a, b) { ... _0xabc ... }        <- 解码函数（引用数组 + 做运算）
     *   var _0x123 = function(a,b){...}(_0xdef, 0x1a4); <- 偏移自解
     *   调用点: _0xdef(0x1, 0x2) / _0x123(0x0)
     */
    private fun findDecryptChain(source: String): DecryptChain {
        val lineStarts = buildLineIndex(source)

        // 字符串数组：以 >= 8 个字符串字面量的数组赋值开头
        val arrayDeclRe = Regex(
            """(?:var|let|const)\s+(_[0-9a-zA-Z$]{2,12}|[a-zA-Z_$][\w$]{0,8})\s*=\s*\[\s*(['"`])""",
        )
        var bestArray: MatchResult? = null
        var bestCount = 0
        for (m in arrayDeclRe.findAll(source).take(500)) {
            val start = m.range.first
            val close = source.indexOf(']', start)
            if (close < 0 || close - start > 200_000) continue
            val seg = source.substring(start, close)
            val count = Regex("""['"`]""").findAll(seg).count() / 2
            if (count > bestCount) { bestCount = count; bestArray = m }
        }
        if (bestArray == null || bestCount < 8) {
            return DecryptChain(false, "", 0, emptyList(), "", "", emptyList(), false)
        }
        val arrayName = bestArray.groupValues[1]
        val arrayStart = bestArray.range.first
        val arrayEnd = source.indexOf(']', arrayStart)
        val arrayBody = source.substring(arrayStart, arrayEnd)
        val elements = Regex("""(['"`])((?:\\.|(?!\1).)*)\1""")
            .findAll(arrayBody).map { it.groupValues[2] }.take(30).toList()

        // 解码函数：引用该数组且含运算/charCodeAt/atob 特征的函数
        val refRe = Regex("""\b${Regex.escape(arrayName)}\b""")
        val decoderRe = Regex("""function\s+(_[0-9a-zA-Z$]{2,12}|[a-zA-Z_$][\w$]{0,8})\s*\(""")
        var decoderName = ""
        var decoderBody = ""
        var decoderDecl = ""
        for (m in decoderRe.findAll(source).take(300)) {
            val body = extractBalancedBody(source, m.range.first)
            if (body.isBlank()) continue
            if (refRe.containsMatchIn(body) &&
                (body.contains("charCodeAt") || body.contains("atob") || body.contains("parseInt") || body.contains("fromCharCode"))
            ) {
                decoderName = m.groupValues[1]
                decoderBody = body.replace(Regex("""\s+"""), " ").take(500)
                decoderDecl = extractBalancedFull(source, m.range.first)
                break
            }
        }
        val arrayDecl = source.substring(arrayStart, (arrayEnd + 1).coerceAtMost(source.length))

        // 偏移自解：IIFE 包裹解码函数 + 立即数
        val offsetsPattern = Regex(
            Regex.escape(decoderName.ifBlank { arrayName }) + """,\s*(0x[0-9a-fA-F]+|\d+)\)"""
        ).containsMatchIn(source)

        // 调用点 + 猜测解码值（静态近似：若 decoder 未运行则只报告表达式）
        val sites = mutableListOf<DecodeSite>()
        if (decoderName.isNotBlank()) {
            val callRe = Regex(Regex.escape(decoderName) + """\s*\(\s*(0x[0-9a-fA-F]+|\d+)\s*(?:,\s*(0x[0-9a-fA-F]+|\d+))?\s*\)""")
            for (cm in callRe.findAll(source).take(200)) {
                // decodeInt 自行处理 0x 十六进制；toIntOrNull 会把 "0x105" 误判为无效而跳过
                val idx = decodeInt(cm.groupValues[1])
                if (idx < 0) continue
                val guess = elements.getOrNull(idx) ?: "?"
                sites.add(DecodeSite(offsetToLine(lineStarts, cm.range.first), cm.value, guess))
                if (sites.size >= 60) break
            }
        }

        return DecryptChain(
            found = true, arrayName = arrayName, arraySize = bestCount,
            arrayPreview = elements, decoderName = decoderName, decoderBody = decoderBody,
            decodeCallSites = sites, offsetsPattern = offsetsPattern,
            arrayDecl = arrayDecl.take(300_000), decoderDecl = decoderDecl.take(150_000),
        )
    }

    private fun decodeInt(s: String): Int =
        if (s.startsWith("0x") || s.startsWith("0X")) s.substring(2).toIntOrNull(16) ?: -1
        else s.toIntOrNull() ?: -1

    // ---------------- 4. 敏感数据流 ----------------

    private fun findSensitiveFlow(source: String): SensitiveFlow {
        val lineStarts = buildLineIndex(source)
        val patterns = mapOf(
            "document.cookie" to Regex("""document\.cookie"""),
            "localStorage" to Regex("""localStorage\.(?:getItem|setItem|removeItem)\s*\(\s*['"]([^'"]{0,60})['"]"""),
            "sessionStorage" to Regex("""sessionStorage\.(?:getItem|setItem|removeItem)\s*\(\s*['"]([^'"]{0,60})['"]"""),
            "token" to Regex("""['"]?(\w*[Tt]oken\w*)['"]?\s*[:=]"""),
            "password" to Regex("""['"]?(\w*[Pp]assw\w*)['"]?\s*[:=]"""),
            "authorization" to Regex("""['"]?[Aa]uthorization['"]?\s*[:,]"""),
        )
        val reads = mutableListOf<FlowPoint>()
        val writes = mutableListOf<FlowPoint>()
        for ((kind, re) in patterns) {
            for (m in re.findAll(source).take(80)) {
                val line = offsetToLine(lineStarts, m.range.first)
                val ctx = source.substring(
                    (m.range.first - 60).coerceAtLeast(0),
                    (m.range.last + 60).coerceAtMost(source.length),
                ).replace(Regex("""\s+"""), " ")
                val isWrite = ctx.substringBefore(m.value).takeLast(1).let { it == "=" || it == ":" } ||
                    m.value.contains("setItem") || kind == "authorization"
                val point = FlowPoint(kind, line, "…$ctx…".take(160))
                if (isWrite) writes.add(point) else reads.add(point)
            }
        }
        return SensitiveFlow(reads.take(40), writes.take(40))
    }

    // ---------------- 工具 ----------------

    private fun buildLineIndex(source: String): IntArray = buildList {
        add(0)
        var i = 0
        while (i < source.length) {
            if (source[i] == '\n' && i + 1 < source.length) add(i + 1)
            i++
        }
    }.toIntArray()

    private fun offsetToLine(lineStarts: IntArray, offset: Int): Int {
        var lo = 0; var hi = lineStarts.size - 1
        while (lo < hi) {
            val mid = (lo + hi + 1) / 2
            if (lineStarts[mid] <= offset) lo = mid else hi = mid - 1
        }
        return lo + 1
    }
}
