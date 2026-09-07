package com.webreverse.mcp.javascript.parser

/**
 * JavaScript 代码格式化器（ 新增）。
 *
 * 面向 AI 阅读未压缩（minified/打包/混淆）JS 的场景：
 * - 真正的词法扫描：字符串 / 模板字面量（含嵌套 ${}）/ 正则字面量 / 注释 全部按 token 处理，
 *   不会像朴素字符级 beautify 那样把注释或正则里的 `{ } ; ,` 当代码破坏掉
 * - 结构化排版：语句后换行、块缩进、关键字与二元运算符空格、for(;;) 头部分号不换行
 * - 混淆代码增强：可把 javascript-obfuscator 风格的 `_0x4a3f` 标识符批量重命名为 v1/v2/...
 *   （只在 token 层重命名，字符串内容不受影响），并输出映射表
 * - 防御式设计：任何异常都不抛出，退化为原样返回（degraded=true）
 *
 * 该实现只做「在安全位置插入空白」——不删字符、不改 token 内容，
 * 因此不会改变代码语义（ASI 依赖的换行只增不减：return/throw 后不插换行）。
 */
class JsFormatter(
    private val indentSize: Int = 2,
    private val renameObfuscated: Boolean = false,
    private val maxOutputChars: Int = 200_000,
) {

    data class Result(
        val formatted: String,
        val originalChars: Int,
        val formattedChars: Int,
        val lineCount: Int,
        val renameMap: Map<String, String> = emptyMap(),
        val truncated: Boolean = false,
        val degraded: Boolean = false,
        /** 每个格式化输出行（1-based → 下标-1）首 token 在原始源码中的偏移；空数组表示不可用（降级路径） */
        val lineStartOffsets: IntArray = IntArray(0),
    ) {
        /**
         * 原始源码偏移 → 格式化输出行号（1-based）。
         * 供 js.format aroundLine/aroundColumn 把 search_in_content 的原始坐标
         * 映射到格式化结果中的可读位置。无法映射时返回 0。
         */
        fun formattedLineFor(originalOffset: Int): Int {
            if (lineStartOffsets.isEmpty() || originalOffset < 0) return 0
            var lo = 0
            var hi = lineStartOffsets.size - 1
            var ans = 0
            while (lo <= hi) {
                val mid = (lo + hi) ushr 1
                if (lineStartOffsets[mid] <= originalOffset) { ans = mid; lo = mid + 1 } else { hi = mid - 1 }
            }
            return ans + 1
        }
    }

    private enum class T { IDENT, KW, NUM, STR, TPL, REGEX, LINE_COMMENT, BLOCK_COMMENT, PUNCT }

    private class Tok(val type: T, val text: String, val nlBefore: Boolean, val start: Int)

    companion object {
        private val KEYWORDS = setOf(
            "var", "let", "const", "function", "return", "if", "else", "for", "while",
            "do", "switch", "case", "break", "continue", "new", "this", "typeof", "instanceof",
            "in", "of", "try", "catch", "finally", "throw", "class", "extends", "super",
            "import", "export", "default", "async", "await", "yield", "delete", "void",
            "null", "true", "false", "undefined", "debugger", "static", "get", "set",
        )

        /** 字面量类关键字：作为操作数出现，前后按操作数规则取空格 */
        private val LITERAL_KW = setOf("this", "null", "true", "false", "undefined", "super")

        /** 关键字后接 `(` 不加空格（调用形而非语句形） */
        private val NO_SPACE_BEFORE_PAREN_KW = setOf("this", "super")

        /** `}` 后接这些关键字表示新语句开始 → 换行 */
        private val STMT_START_KW = setOf(
            "var", "let", "const", "function", "class", "if", "for", "while", "switch",
            "try", "return", "throw", "import", "export", "async", "do",
        )

        /** `}` 后接这些关键字是同一语句延续 → 空格不换行（`} else {` / `do{}while()`） */
        private val CONTINUATION_KW = setOf("else", "catch", "finally", "while", "in", "of", "instanceof")

        /** 二元运算符（两侧空格）；`+ - * /` 的单目形态由「前一 token 是否操作数」判定；`?` 为三元 */
        private val BINARY_OPS = setOf(
            "=", "==", "===", "!=", "!==", "<=", ">=", "&&", "||", "??", "=>", "?",
            "+", "-", "*", "/", "%", "<", ">", "+=", "-=", "*=", "/=", "%=",
            "&=", "|=", "^=", "<<", ">>", "**", ">>>", "<<=", ">>=", ">>>=", "**=",
            "&&=", "||=", "??=",
        )

        /** javascript-obfuscator 风格混淆标识符：_0x + 十六进制 */
        private val OBFUSCATED_IDENT = Regex("^_0x[0-9a-fA-F]{1,10}$")

        /** 多字符 punctuator，按长度优先匹配 */
        private val PUNCTUATORS = listOf(
            ">>>=", "...", "===", "!==", "**=", "<<=", ">>=", ">>>", "&&=", "||=", "??=",
            "=>", "==", "!=", "<=", ">=", "&&", "||", "??", "?.", "++", "--",
            "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<", ">>", "**",
        )
    }

    /** 格式化入口：异常时退化为原文返回（不抛出） */
    fun format(source: String): Result = try {
        formatInternal(source)
    } catch (t: Throwable) {
        Result(
            formatted = source,
            originalChars = source.length,
            formattedChars = source.length,
            lineCount = source.count { it == '\n' } + 1,
            degraded = true,
        )
    }

    private fun formatInternal(source: String): Result {
        val toks = tokenize(source)

        // ---- 混淆标识符重命名（token 层，字符串内容不受影响） ----
        val renameMap = HashMap<String, String>()
        if (renameObfuscated) {
            val taken = HashSet<String>(KEYWORDS)
            for (tok in toks) if (tok.type == T.IDENT) taken.add(tok.text)
            var counter = 0
            for (tok in toks) {
                if (tok.type == T.IDENT && OBFUSCATED_IDENT.matches(tok.text) && tok.text !in renameMap) {
                    var candidate = "v${++counter}"
                    while (candidate in taken) candidate = "${candidate}_"
                    taken.add(candidate)
                    renameMap[tok.text] = candidate
                }
            }
        }

        val out = StringBuilder(minOf(source.length * 2 + 64, maxOutputChars + 1024))
        // 记录每个格式化行首 token 的原始偏移，供原始坐标 → 格式化行号映射
        val lineStarts = ArrayList<Int>(1024)
        emit(toks, renameMap, out, lineStarts)

        val full = out.toString()
        val truncated = full.length > maxOutputChars
        val formatted = if (truncated) full.substring(0, maxOutputChars) else full
        return Result(
            formatted = formatted,
            originalChars = source.length,
            formattedChars = formatted.length,
            lineCount = formatted.count { it == '\n' } + 1,
            renameMap = renameMap,
            truncated = truncated,
            lineStartOffsets = lineStarts.toIntArray(),
        )
    }

    // ============================ 词法扫描 ============================

    private fun tokenize(src: String): MutableList<Tok> {
        val toks = mutableListOf<Tok>()
        var i = 0
        val n = src.length
        var prev: Tok? = null
        var nlBefore = false

        fun push(type: T, text: String, start: Int) {
            val t = Tok(type, text, nlBefore, start)
            toks.add(t)
            prev = t
            nlBefore = false
        }

        while (i < n) {
            val c = src[i]
            when {
                c == '\n' -> { nlBefore = true; i++ }
                c == '\r' || c == ' ' || c == '\t' -> i++
                c == '#' && toks.isEmpty() && i == 0 -> { // hashbang 保留
                    val start = i
                    while (i < n && src[i] != '\n') i++
                    push(T.LINE_COMMENT, src.substring(start, i), start)
                }
                c == '/' && i + 1 < n && src[i + 1] == '/' -> {
                    val start = i
                    while (i < n && src[i] != '\n') i++
                    push(T.LINE_COMMENT, src.substring(start, i), start)
                }
                c == '/' && i + 1 < n && src[i + 1] == '*' -> {
                    val start = i
                    i += 2
                    while (i < n && !(src[i] == '*' && i + 1 < n && src[i + 1] == '/')) i++
                    i = if (i < n) i + 2 else n
                    push(T.BLOCK_COMMENT, src.substring(start, i.coerceAtMost(n)), start)
                }
                c == '"' || c == '\'' -> {
                    val start = i
                    i++
                    while (i < n) {
                        if (src[i] == '\\') { i += 2; continue }
                        if (src[i] == c || src[i] == '\n') { if (src[i] == c) i++; break }
                        i++
                    }
                    push(T.STR, src.substring(start, i.coerceAtMost(n)), start)
                }
                c == '`' -> {
                    val start = i
                    i = scanTemplateEnd(src, i + 1, n)
                    push(T.TPL, src.substring(start, i), start)
                }
                isIdentStart(c) -> {
                    val start = i
                    i++
                    while (i < n && isIdentPart(src[i])) i++
                    val word = src.substring(start, i)
                    push(if (word in KEYWORDS) T.KW else T.IDENT, word, start)
                }
                c.isDigit() || (c == '.' && i + 1 < n && src[i + 1].isDigit()) -> {
                    val start = i
                    if (c == '0' && i + 1 < n && (src[i + 1] == 'x' || src[i + 1] == 'X' ||
                            src[i + 1] == 'b' || src[i + 1] == 'B' || src[i + 1] == 'o' || src[i + 1] == 'O')
                    ) {
                        i += 2
                        while (i < n && (src[i].isLetterOrDigit() || src[i] == '_')) i++
                    } else {
                        while (i < n && (src[i].isDigit() || src[i] == '_' || src[i] == '.' ||
                                src[i] == 'e' || src[i] == 'E' ||
                                ((src[i] == '+' || src[i] == '-') && i > start &&
                                    (src[i - 1] == 'e' || src[i - 1] == 'E')))
                        ) i++
                        if (i < n && src[i] == 'n') i++ // BigInt 后缀
                    }
                    push(T.NUM, src.substring(start, i), start)
                }
                c == '/' -> {
                    if (regexAllowed(prev)) {
                        val start = i
                        i = scanRegexEnd(src, i + 1, n)
                        push(T.REGEX, src.substring(start, i), start)
                    } else {
                        val end = matchPunct(src, i, n)
                        if (end != null) {
                            push(T.PUNCT, src.substring(i, end), i)
                            i = end
                        } else {
                            push(T.PUNCT, "/", i)
                            i++
                        }
                    }
                }
                else -> {
                    val end = matchPunct(src, i, n)
                    if (end != null) {
                        push(T.PUNCT, src.substring(i, end), i)
                        i = end
                    } else {
                        push(T.PUNCT, c.toString(), i) // 未知字符原样保留
                        i++
                    }
                }
            }
        }
        return toks
    }

    /** 正则出现位置判定：前一显著 token 为空/运算符/非字面量关键字 → 正则；否则除法 */
    private fun regexAllowed(prev: Tok?): Boolean {
        val p = prev ?: return true
        return when (p.type) {
            T.IDENT, T.NUM, T.STR, T.TPL, T.REGEX -> false
            T.KW -> p.text !in LITERAL_KW
            T.PUNCT -> p.text !in setOf(")", "]", "}", "++", "--")
            else -> true
        }
    }

    /** 扫描正则字面量结尾（含字符类 [...] 与转义），返回结束下标（含 flags） */
    private fun scanRegexEnd(src: String, from: Int, n: Int): Int {
        var i = from
        var inClass = false
        while (i < n) {
            val c = src[i]
            when {
                c == '\\' -> i += 2
                c == '[' -> { inClass = true; i++ }
                c == ']' -> { inClass = false; i++ }
                c == '/' && !inClass -> {
                    i++
                    while (i < n && src[i].isLetter()) i++
                    return i
                }
                c == '\n' -> return i // 异常输入防御：未闭合正则按普通文本处理
                else -> i++
            }
        }
        return n
    }

    /** 扫描模板字面量结尾（含嵌套 ${}、插值内字符串与嵌套模板），返回结束下标 */
    private fun scanTemplateEnd(src: String, from: Int, n: Int): Int {
        var i = from
        var depth = 0 // >0 = 位于 ${} 插值内
        while (i < n) {
            val c = src[i]
            when {
                depth == 0 -> when {
                    c == '\\' -> i += 2
                    c == '`' -> return i + 1
                    c == '$' && i + 1 < n && src[i + 1] == '{' -> { depth = 1; i += 2 }
                    else -> i++
                }
                else -> when {
                    c == '\\' -> i += 2
                    c == '{' -> { depth++; i++ }
                    c == '}' -> { depth--; i++ }
                    c == '"' || c == '\'' -> { // 插值内字符串原样跳过
                        val q = c
                        i++
                        while (i < n) {
                            if (src[i] == '\\') { i += 2; continue }
                            if (src[i] == q) { i++; break }
                            if (src[i] == '\n') break
                            i++
                        }
                    }
                    c == '`' -> i = scanTemplateEnd(src, i + 1, n) // 嵌套模板
                    else -> i++
                }
            }
        }
        return n
    }

    /** 匹配当前位置的多字符 punctuator；命中返回结束下标 */
    private fun matchPunct(src: String, i: Int, n: Int): Int? {
        for (p in PUNCTUATORS) {
            val len = p.length
            if (i + len <= n && src.regionMatches(i, p, 0, len)) {
                // `?.` 与 `? .5`（三元 + 小数）区分
                if (p == "?." && i + 2 < n && src[i + 2].isDigit()) continue
                return i + len
            }
        }
        return null
    }

    private fun isIdentStart(c: Char) = c.isLetter() || c == '_' || c == '$'
    private fun isIdentPart(c: Char) = c.isLetterOrDigit() || c == '_' || c == '$'

    // ============================ 排版输出 ============================

    private fun emit(toks: List<Tok>, renameMap: Map<String, String>, out: StringBuilder, lineStarts: MutableList<Int>) {
        var indent = 0
        var parenDepth = 0
        // 三元嵌套深度跟踪：用于区分三元 `:`（前留空格）与对象字面量/标签 `:`（紧贴）。
        // 进入 ( [ { 时压栈并清零，离开时恢复——保证括号内的三元不污染外层判断
        var ternaryDepth = 0
        val bracketTernary = ArrayDeque<Int>()
        var prev: Tok? = null
        var justNewlined = true
        var forceNewlineBeforeNext = false

        fun currentIndent() {
            repeat(indent * indentSize) { out.append(' ') }
        }

        fun trimTrailingSpaces() {
            while (out.isNotEmpty() && out.last() == ' ') out.deleteCharAt(out.length - 1)
        }

        fun doNewline() {
            trimTrailingSpaces()
            out.append('\n')
            currentIndent()
            justNewlined = true
        }

        fun isOperand(t: Tok?): Boolean = when (t?.type) {
            T.IDENT, T.NUM, T.STR, T.TPL, T.REGEX -> true
            T.KW -> t.text in LITERAL_KW
            T.PUNCT -> t.text == ")" || t.text == "]"
            else -> false
        }

        for (idx in toks.indices) {
            val tok = toks[idx]
            val p = prev
            val text = if (tok.type == T.IDENT) renameMap[tok.text] ?: tok.text else tok.text
            val isBraceOpen = tok.type == T.PUNCT && tok.text == "{"
            val isBraceClose = tok.type == T.PUNCT && tok.text == "}"

            // `}` 先降缩进再决定换行，保证收尾花括号与块头对齐
            if (isBraceClose) indent = (indent - 1).coerceAtLeast(0)

            // ---------- 是否换行 ----------
            var wantNewline = false
            if (!justNewlined && p != null) {
                wantNewline = when {
                    p.type == T.LINE_COMMENT -> true
                    p.text == ";" && parenDepth == 0 -> true
                    // 块头 { 后换行；紧贴的 } 除外（空对象 {} 不拆行）
                    p.text == "{" && !isBraceClose -> true
                    // 块尾：新语句开始（标识符/字面量/语句关键字）
                    p.text == "}" && !isBraceClose && (
                        tok.type == T.IDENT || tok.type == T.NUM || tok.type == T.STR ||
                            tok.type == T.TPL || tok.type == T.REGEX ||
                            (tok.type == T.KW && tok.text in STMT_START_KW)
                        ) -> true
                    // `}` 自身：前一行有内容时换行（空块 {} 除外）
                    isBraceClose && p.text != "{" -> true
                    else -> false
                }
                // 保留源码原有换行（for 头部内的分号后除外）
                if (!wantNewline && tok.nlBefore && !(p.text == ";" && parenDepth > 0)) {
                    wantNewline = true
                }
            }
            if (forceNewlineBeforeNext && !justNewlined) wantNewline = true
            forceNewlineBeforeNext = false
            if (wantNewline) doNewline()

            // ---------- 是否空格 ----------
            var wantSpace = false
            if (!justNewlined && p != null) {
                wantSpace = when (tok.type) {
                    T.PUNCT -> when {
                        // 关键字后接 (：if ( / for ( / function (；但 this( 不加
                        tok.text == "(" && p.type == T.KW && p.text !in NO_SPACE_BEFORE_PAREN_KW -> true
                        // 二元运算符后接 (：a * (b)
                        tok.text == "(" && p.type == T.PUNCT && p.text in BINARY_OPS -> true
                        // 关键字后接 [：in [ / of [ / return [
                        tok.text == "[" && p.type == T.KW &&
                            p.text in setOf("in", "of", "return", "typeof", "case", "delete", "void", "new", "yield", "await") -> true
                        // 三元 `:` 前留空格（a ? b : c）；对象字面量/标签冒号紧贴（{a: 1}）
                        tok.text == ":" -> ternaryDepth > 0
                        // 块头 { 与前文留空格（紧跟开括号/单目运算符/成员访问除外）
                        tok.text == "{" -> p.text !in setOf("(", "[", "!", "~", ".", "?.")
                        // 二元运算符（前操作数存在）：两侧空格；单目（++/--/!/~）与前缀符不空格
                        tok.text in BINARY_OPS -> isOperand(p)
                        else -> false
                    }
                    T.IDENT, T.NUM, T.STR, T.TPL, T.REGEX -> when {
                        p.text == "." || p.text == "?." || p.text == "!" || p.text == "~" ||
                            p.text == "++" || p.text == "--" || p.text == "#" -> false
                        p.type == T.PUNCT && p.text in BINARY_OPS -> true
                        p.text == "," || p.text == ":" || p.text == ";" -> true
                        isOperand(p) -> true
                        p.type == T.KW -> true // return x / var a / new F / a in b
                        p.type == T.BLOCK_COMMENT -> true
                        else -> false
                    }
                    T.KW -> when {
                        p.text == "." || p.text == "?." -> false
                        p.text == "(" || p.text == "[" || p.text == "," || p.text == ";" -> false
                        // 二元运算符后的关键字：= function / => async / + new
                        p.type == T.PUNCT && p.text in BINARY_OPS -> true
                        // 块尾延续/新起关键字：} else { / } while ( / } catch (
                        p.text == "}" -> true
                        isOperand(p) || p.type == T.KW -> true
                        else -> false
                    }
                    else -> true // 行/块注释：行内有内容则留空格
                }
            }
            if (wantSpace) out.append(' ')

            // ---------- 写出 ----------
            // 行首 token：记录其原始偏移（供原始坐标 → 格式化行号映射）
            if (justNewlined) lineStarts.add(tok.start)
            when {
                isBraceOpen -> {
                    out.append('{')
                    indent++
                }
                isBraceClose -> out.append('}')
                tok.type == T.LINE_COMMENT -> {
                    out.append(text)
                    forceNewlineBeforeNext = true
                }
                else -> out.append(text)
            }
            if (tok.type == T.PUNCT) {
                when (tok.text) {
                    "(", "[", "{" -> {
                        if (tok.text == "(") parenDepth++
                        bracketTernary.addLast(ternaryDepth)
                        ternaryDepth = 0
                    }
                    ")", "]", "}" -> {
                        if (tok.text == ")") parenDepth = (parenDepth - 1).coerceAtLeast(0)
                        if (bracketTernary.isNotEmpty()) ternaryDepth = bracketTernary.removeLast()
                    }
                    "?" -> ternaryDepth++
                    ":" -> if (ternaryDepth > 0) ternaryDepth--
                }
            }
            justNewlined = false
            prev = tok
        }
        trimTrailingSpaces()
    }
}
