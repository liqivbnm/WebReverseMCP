package com.webreverse.mcp.javascript.analysis

import kotlinx.serialization.Serializable

/**
 * 脚本拦截改写的转换结果。
 */
@Serializable
data class ScriptTransformResult(
    val transformed: String,
    val originalHash: String = "",
    val transformedHash: String = "",
    val debuggerNeutralized: Int = 0,
    val transformRules: List<String> = emptyList(),
    val sriCompatibility: SriCompatibility = SriCompatibility.NONE,
    val notes: List<String> = emptyList(),
)

/** SRI（Subresource Integrity）兼容策略（报告 §37） */
@Serializable
enum class SriCompatibility {
    /** 未处理 SRI */
    NONE,

    /** 检测到脚本被改写，可能违反 HTML 中声明的 integrity——需提示仅实验模式使用 */
    PATCHED_VIOLATES_SRI,
}

/**
 * 脚本拦截器 / 执行前改写器（ScriptTransformer，报告 §7）。
 *
 * 目标：在 JS 被浏览器执行前，对响应 body 做"执行前拦截改写"——
 * 中和 debugger 语句/构造器/定时器循环，而不只是事后 Debugger.resume 或
 * 正则替换字符串（报告 §4/§5/§9 强调的唯一可靠路径）。
 *
 * 词法感知升级（报告 §11）：
 * 旧实现按"整行是否含引号"决定是否替换——字符串行里的真实 debugger 语句
 * 漏报、花括号正则 Pass 可能改坏对象字面量。现改为 [LexicalDebuggerSanitizer]
 * 字符级状态机（字符串/模板/注释/正则全感知），只移除【代码态】的独立
 * debugger 语句词，并把 Function("debugger") / x.constructor("debugger")
 * 构造调用替换为无害表达式。
 *
 * 安全约束：
 *  - 仅中和调试类结构，绝不做破坏性全局改写（报告 §34"Never globally rewrite"）。
 *  - 词法感知：字符串值/注释/正则/对象键中的 "debugger" 一概不动。
 *  - 记录 originalHash/transformedHash，供 Evidence Graph 溯源。
 *  - SRI 场景标记兼容性风险（脚本被改写后，若 HTML 声明了 integrity，浏览器可能拒绝执行）。
 */
class ScriptInterceptor {

    private val sanitizer = LexicalDebuggerSanitizer()

    private fun sha256(input: String): String {
        return try {
            val md = java.security.MessageDigest.getInstance("SHA-256")
            md.digest(input.toByteArray(Charsets.UTF_8))
                .joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            ""
        }
    }

    /**
     * 中和反调试：返回处理后的脚本。
     *
     * 处理策略（ 全部词法感知）：
     *  1. [词法状态机] 移除代码态的独立 `debugger` 语句词（含可选分号；
     *     字符串/模板/注释/正则/对象键/属性访问 `.debugger` 中的字面量不动）
     *  2. 将 `Function("debugger")` / `new Function('debugger')` 替换为无害空函数
     *  3. 将 `x.constructor("debugger")()` 构造调用链替换为无害表达式
     *  4. `eval("debugger")` 内联字面量兜底（字符串参数为字面量时才替换）
     *
     * 不处理：字符串值、注释、属性名、正则字面量中的 "debugger" 文本。
     */
    fun transform(source: String): ScriptTransformResult {
        val originalHash = sha256(source)
        val notes = mutableListOf<String>()
        val rules = mutableListOf<String>()
        var debuggerRemoved = 0

        // ---- 单遍词法处理（报告 §14：移除全部 post-lex 全局正则） ----
        // 独立 debugger 语句、Function()/new Function()/eval()/.constructor() 内嵌
        // debugger 全部在【同一个字符级状态机】内、仅于"代码态"中和——字符串/注释/
        // 正则/模板一概原样保留，从根上消除旧 Pass 2/3/4 全局正则重新进入字符串、
        // 注释、正则字面量等区域而改坏源码的问题（P0-4）。
        val lexResult = sanitizer.sanitize(source)
        var out = lexResult.output
        debuggerRemoved += lexResult.removed

        if (debuggerRemoved > 0) {
            rules.add("lexical_debugger_neutralization")
            notes.add("词法感知中和 $debuggerRemoved 处调试语句（执行前拦截改写，字符串/注释安全）")
        } else {
            notes.add("未发现需要中和的 debugger 语句（词法扫描完成，非盲目正则替换）")
        }

        // ---- 标记最终产物存在（用于 distinct 后的防重复注入） ----
        val marker = "__WRMCP_SCRIPT_PATCHED__"
        if (debuggerRemoved > 0 && !out.contains(marker)) {
            out += "\n(globalThis.__WRMCP_SCRIPT_PATCHED__ = (globalThis.__WRMCP_SCRIPT_PATCHED__||0)+1);"
        }

        val transformedHash = sha256(out)

        return ScriptTransformResult(
            transformed = out,
            originalHash = originalHash,
            transformedHash = transformedHash,
            debuggerNeutralized = debuggerRemoved,
            transformRules = rules,
            sriCompatibility = if (debuggerRemoved > 0) SriCompatibility.PATCHED_VIOLATES_SRI else SriCompatibility.NONE,
            notes = notes,
        )
    }

    /**
     * 判断是否为可拦截的 JS 内容类型（脚本响应：text/javascript / application/javascript / application/x-javascript）。
     */
    fun isJavaScriptMime(mimeType: String?): Boolean {
        val m = mimeType?.substringBefore(';')?.trim()?.lowercase() ?: return false
        return m == "text/javascript" ||
            m == "application/javascript" ||
            m == "application/x-javascript" ||
            m.endsWith("/javascript") ||
            m.endsWith("+json") && false // 明确排除 json
    }

    /**
     * SRI 风险提示：当脚本被改写且响应声明了 integrity 时，浏览器可能因哈希失配拒绝执行。
     * 返回一段 JSON 兼容的说明（供 MCP 工具返回）。
     */
    fun sriWarning(integrityHeader: String?, result: ScriptTransformResult): String? {
        if (integrityHeader.isNullOrBlank()) return null
        if (result.sriCompatibility != SriCompatibility.PATCHED_VIOLATES_SRI) return null
        return "脚本已被改写，但响应携带 SRI integrity（$integrityHeader）。浏览器可能因哈希失配拒绝执行——" +
            "实验/逆向模式可同时拦截 HTML 剥离对应 <script integrity>，或禁用 SRI 校验。"
    }
}

/**
 * 词法感知的 debugger 语句中和扫描器（报告 §11）。
 *
 * 逐字符状态机遍历源码，正确区分词法环境：
 * - 单/双引号字符串（含转义）
 * - 模板串（含 ${ } 插值嵌套，整体视为串——插值内代码极少含 debugger，保守不动）
 * - 行注释 / 块注释
 * - 正则字面量（依据 `/` 前一有效 token 消歧：右值结尾=除法，运算符/语句边界=正则）
 * - 代码态：仅移除【独立语句词】的 debugger（token 边界完整 + 非属性访问/对象键）
 *
 * 相比旧"整行含引号则跳过"方案：
 * - 漏报修复：`var s = "x"; debugger;`（同行含引号但 debugger 是真语句）现在会被中和
 * - 误报修复：注释/字符串里的 debugger 文本不再被改写（旧方案在无引号行会误改注释）
 * - 结构安全：不再使用跨内容的花括号正则（旧 Pass 4 可能把对象字面量拼坏）
 */
class LexicalDebuggerSanitizer {

    data class Result(val output: String, val removed: Int)

    /** `/` 前是这些字符 → 视为正则字面量开始（左值/运算符/语句边界） */
    private val regexBefore = "(:,=!&|?[{;+-*%<>~^".toSet()

    /** `/` 前是这些关键字结尾 → 正则开始（return /re/ 、typeof /re/ 等） */
    private val regexKeywords = arrayOf(
        "return", "typeof", "instanceof", "in", "of", "new", "delete", "void",
        "case", "do", "else", "yield", "await",
    )

    private fun isIdentPart(c: Char): Boolean =
        c.isLetterOrDigit() || c == '_' || c == '$'

    fun sanitize(source: String): Result {
        val sb = StringBuilder(source.length + 16)
        var i = 0
        val n = source.length
        var removed = 0
        // 前一个有效字符（代码态），初始 ';' 视为语句边界
        var prev: Char = ';'

        while (i < n) {
            val c = source[i]

            when {
                // ---- 行注释：原样保留 ----
                c == '/' && i + 1 < n && source[i + 1] == '/' -> {
                    var j = i
                    while (j < n && source[j] != '\n') j++
                    sb.append(source, i, j)
                    i = j
                }

                // ---- 块注释：原样保留 ----
                c == '/' && i + 1 < n && source[i + 1] == '*' -> {
                    var j = i + 2
                    while (j < n - 1 && !(source[j] == '*' && source[j + 1] == '/')) j++
                    val end = if (j < n - 1) j + 2 else n
                    sb.append(source, i, end)
                    i = end
                    prev = ';'
                }

                // ---- 单/双引号字符串：整段原样保留 ----
                c == '\'' || c == '"' -> {
                    var j = i + 1
                    while (j < n) {
                        if (source[j] == '\\') {
                            j += 2
                            continue
                        }
                        if (source[j] == c) {
                            j++
                            break
                        }
                        if (source[j] == '\n') break // 未闭合兜底
                        j++
                    }
                    j = j.coerceAtMost(n)
                    sb.append(source, i, j)
                    i = j
                    prev = ')'
                }

                // ---- 模板串（含 ${} 嵌套）：整段原样保留 ----
                c == '`' -> {
                    var j = i + 1
                    var depth = 0
                    while (j < n) {
                        val t = source[j]
                        if (t == '\\') {
                            j += 2
                            continue
                        }
                        if (depth == 0 && t == '`') {
                            j++
                            break
                        }
                        if (t == '$' && j + 1 < n && source[j + 1] == '{') {
                            depth++
                            j += 2
                            continue
                        }
                        if (depth > 0 && t == '}') depth--
                        j++
                    }
                    j = j.coerceAtMost(n)
                    sb.append(source, i, j)
                    i = j
                    prev = ')'
                }

                // ---- 正则字面量：整段原样保留（防止内部引号/文本破坏后续词法） ----
                c == '/' && isRegexStart(source, i, prev) -> {
                    var j = i + 1
                    var inClass = false
                    while (j < n) {
                        val t = source[j]
                        if (t == '\\') {
                            j += 2
                            continue
                        }
                        if (t == '\n') break // 未闭合兜底
                        if (t == '[') inClass = true
                        else if (t == ']') inClass = false
                        else if (t == '/' && !inClass) {
                            j++
                            while (j < n && source[j].isLetter()) j++ // flags
                            break
                        }
                        j++
                    }
                    j = j.coerceAtMost(n)
                    sb.append(source, i, j)
                    i = j
                    prev = ')'
                }

                // ---- 代码态：debugger 构造器中和 + 独立 debugger 语句移除（同遍完成） ----
                else -> {
                    val ctorEnd = matchDebuggerConstructor(source, i, prev, n)
                    when {
                        // Function("debugger") / new Function('debugger') / eval("debugger")
                        // / .constructor("debugger")()：词法态检测，绝不触碰字符串/注释
                        ctorEnd > 0 -> {
                            val repl =
                                if (source[i] == 'F') "function(){ return undefined; }"
                                else "(function(){ return undefined; })()"
                            sb.append(repl)
                            removed++
                            i = ctorEnd
                            prev = ')'
                        }

                        // 独立 debugger 语句词：移除（词 + 可选空格 + 可选分号）
                        c == 'd' && source.startsWith("debugger", i) &&
                            (i + 8 >= n || !isIdentPart(source[i + 8])) &&
                            !isIdentPart(prev) && prev != '.' -> {
                            // 对象键防御：{ debugger: 1 } / { a: 1, debugger: 2 } 中的 debugger 是键名
                            val after = skipSpaces(source, i + 8)
                            val isObjectKey = (prev == '{' || prev == ',') && after < n && source[after] == ':'
                            if (isObjectKey) {
                                sb.append(source, i, i + 8)
                                i += 8
                                prev = 'r'
                            } else {
                                var j = i + 8
                                while (j < n && (source[j] == ' ' || source[j] == '\t')) j++
                                if (j < n && source[j] == ';') j++
                                removed++
                                i = j
                                prev = ';'
                            }
                        }

                        // 其余字符：追加并跟踪 prev
                        else -> {
                            sb.append(c)
                            if (!c.isWhitespace()) prev = c
                            i++
                        }
                    }
                }
            }
        }
        return Result(sb.toString(), removed)
    }

    /** `/` 消歧：前一有效 token 是运算符/边界/关键字 → 正则开始；右值结尾 → 除法 */
    private fun isRegexStart(source: String, slashIdx: Int, prev: Char): Boolean {
        if (prev in regexBefore) return true
        if (isIdentPart(prev)) {
            // 检查是否处于关键字结尾（return/typeof/case...）
            val start = (slashIdx - 12).coerceAtLeast(0)
            val before = source.substring(start, slashIdx)
            for (kw in regexKeywords) {
                if (before.endsWith(kw)) {
                    // 关键词前必须是非标识符字符（避免 myreturn/ 之类）
                    val kwStart = before.length - kw.length - 1
                    if (kwStart < 0 || !isIdentPart(before[kwStart])) return true
                }
            }
            return false
        }
        // prev 是 ')' ']' '`' '"' 等 → 除法
        return false
    }

    private fun skipSpaces(s: String, from: Int): Int {
        var j = from
        while (j < s.length && (s[j] == ' ' || s[j] == '\t')) j++
        return j
    }

    /**
     * 代码态检测 debugger 构造器模式（P0-4）：
     *   `Function("debugger")` / `new Function('debugger')` / `eval("debugger")`
     *   / `.constructor("debugger")()`
     * 命中返回整段结束下标（不含），否则 -1。仅在[代码态]调用——此时已越过
     * 字符串/模板/注释/正则区域，因此不会误伤它们内部的同类文本。
     * @param prev 前一个非空白代码字符（用于词边界判断）
     */
    private fun matchDebuggerConstructor(source: String, i: Int, prev: Char, n: Int): Int {
        val wordStart = !isIdentPart(prev)

        if (wordStart && source.startsWith("Function", i) && (i + 8 >= n || !isIdentPart(source[i + 8]))) {
            val p = skipSpaces(source, i + 8)
            if (p < n && source[p] == '(') {
                val e = debuggerCallEnd(source, p, requireTrailingCall = false)
                if (e > 0) return e
            }
        }

        if (wordStart && source.startsWith("eval", i) && (i + 4 >= n || !isIdentPart(source[i + 4]))) {
            val p = skipSpaces(source, i + 4)
            if (p < n && source[p] == '(') {
                val e = debuggerCallEnd(source, p, requireTrailingCall = false)
                if (e > 0) return e
            }
        }

        if (source[i] == '.' && source.startsWith(".constructor", i) && (i + 12 >= n || !isIdentPart(source[i + 12]))) {
            val p = skipSpaces(source, i + 12)
            if (p < n && source[p] == '(') {
                val e = debuggerCallEnd(source, p, requireTrailingCall = true)
                if (e > 0) return e
            }
        }
        return -1
    }

    /**
     * 检查 `( "..." )`（+可选 `()`）是否为"单一字符串参数且内容含 debugger"的调用形态。
     * @return 整段结束下标（不含），不匹配返回 -1
     */
    private fun debuggerCallEnd(source: String, parenIdx: Int, requireTrailingCall: Boolean): Int {
        var j = skipSpaces(source, parenIdx + 1)
        if (j >= source.length || (source[j] != '\'' && source[j] != '"')) return -1
        val quote = source[j]
        val contentStart = j + 1
        var k = contentStart
        while (k < source.length) {
            val c = source[k]
            if (c == '\\') {
                k += 2
                continue
            }
            if (c == quote) break
            if (c == '\n') return -1 // 未闭合兜底
            k++
        }
        if (k >= source.length) return -1
        val content = source.substring(contentStart, k)
        if (!content.contains("debugger")) return -1
        var m = skipSpaces(source, k + 1)
        if (m >= source.length || source[m] != ')') return -1
        m = m + 1
        if (!requireTrailingCall) return m
        // .constructor("debugger")() 还需紧跟一对 () 调用
        m = skipSpaces(source, m)
        if (m >= source.length || source[m] != '(') return -1
        var end = m + 1
        while (end < source.length && source[end] != ')') end++
        return if (end < source.length) end + 1 else -1
    }
}
