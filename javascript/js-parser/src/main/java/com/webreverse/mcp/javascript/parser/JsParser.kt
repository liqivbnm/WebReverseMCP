package com.webreverse.mcp.javascript.parser

import kotlinx.serialization.Serializable

/** 词法 Token */
@Serializable
data class JsToken(
    val type: TokenType,
    val value: String,
    val start: Int,
    val end: Int,
    val line: Int,
)

@Serializable
enum class TokenType {
    IDENTIFIER, KEYWORD, STRING, NUMBER, PUNCTUATOR, COMMENT, REGEX, TEMPLATE, WHITESPACE
}

/** 提取结果 */
@Serializable
data class JsExtraction(
    val strings: List<String> = emptyList(),
    val identifiers: List<String> = emptyList(),
    val urls: List<String> = emptyList(),
    val functionNames: List<String> = emptyList(),
    val callExpressions: List<CallExpressionInfo> = emptyList(),
    val memberExpressions: List<String> = emptyList(),
    val variables: List<String> = emptyList(),
    val constants: List<String> = emptyList(),
)

@Serializable
data class CallExpressionInfo(
    val callee: String,
    val arguments: List<String> = emptyList(),
    val line: Int = 0,
)

/** import 单项说明符：`{ imported as local }`；无别名时 [local] == [imported] */
@Serializable
data class NamedSpecifier(
    val imported: String,
    val local: String,
)

/* * import 语句结构化结果（ 新增） */
@Serializable
data class ImportDescriptor(
    val module: String = "",
    val defaultName: String? = null,
    val namespace: String? = null,
    val namedImports: List<NamedSpecifier> = emptyList(),
    val sideEffectOnly: Boolean = false,
)

/* * export 语句结构化结果（ 新增）
 *  [kind] 取值：named / default / all / all_as / declaration */
@Serializable
data class ExportDescriptor(
    val kind: String,
    val names: List<NamedSpecifier> = emptyList(),
    val module: String = "",
    val expression: String = "",
    val isDefault: Boolean = false,
)

/** 源码位置 */
@Serializable
data class SourceLocation(
    val file: String = "",
    val line: Int = 0,
    val column: Int = 0,
)

/** 函数信息 */
@Serializable
data class FunctionInfo(
    val name: String,
    val params: List<String> = emptyList(),
    val body: String = "",
    val line: Int = 0,
    val isAnonymous: Boolean = false,
    val isArrow: Boolean = false,
)

/** 模式检测结果 */
@Serializable
data class PatternMatch(
    val pattern: String,
    val matches: List<PatternOccurrence> = emptyList(),
)

@Serializable
data class PatternOccurrence(
    val value: String,
    val line: Int = 0,
    val context: String = "",
)

/**
 * 轻量级 JavaScript 解析器 / 分析器。
 * 提供 Tokenize、字符串/标识符/URL/函数/调用表达式提取、模式检测、美化、混淆检测。
 */
class JsParser {

    private val keywords = setOf(
        "var", "let", "const", "function", "return", "if", "else", "for", "while",
        "do", "switch", "case", "break", "continue", "new", "this", "typeof", "instanceof",
        "in", "of", "try", "catch", "finally", "throw", "class", "extends", "super",
        "import", "export", "default", "async", "await", "yield", "delete", "void",
        "null", "true", "false", "undefined", "debugger", "static", "get", "set",
    )

    private val stringPattern = Regex("\"([^\"\\\\]|\\\\.)*\"|'([^'\\\\]|\\\\.)*'|`([^`\\\\]|\\\\.)*`")
    private val urlPattern = Regex("""(https?://[^\s"'`)\]]+|//[^\s"'`)\]]+|/api/[^\s"'`)\]]+|wss?://[^\s"'`)\]]+)""")
    private val identifierPattern = Regex("[A-Za-z_$][A-Za-z0-9_$]*")
    private val numberPattern = Regex("\\b(0[xX][0-9a-fA-F]+|0[bB][01]+|0[oO][0-7]+|\\d+\\.?\\d*([eE][+-]?\\d+)?)\\b")

    fun tokenize(source: String): List<JsToken> {
        val tokens = mutableListOf<JsToken>()
        var i = 0
        var line = 1
        val n = source.length
        // 正则字面量上下文启发（报14/15）：此前是操作符/开括号/关键字时，"/"可能起正则
        var regexAllowed = true
        while (i < n) {
            val c = source[i]
            when {
                c == '\n' -> { line++; i++ }
                c.isWhitespace() -> {
                    val start = i
                    while (i < n && source[i].isWhitespace()) i++
                    tokens.add(JsToken(TokenType.WHITESPACE, source.substring(start, i), start, i, line))
                }
                c == '/' && i + 1 < n && source[i + 1] == '/' -> {
                    val start = i
                    while (i < n && source[i] != '\n') i++
                    tokens.add(JsToken(TokenType.COMMENT, source.substring(start, i), start, i, line))
                }
                c == '/' && i + 1 < n && source[i + 1] == '*' -> {
                    val start = i
                    i += 2
                    while (i + 1 < n && !(source[i] == '*' && source[i + 1] == '/')) {
                        if (source[i] == '\n') line++
                        i++
                    }
                    i = minOf(i + 2, n)
                    tokens.add(JsToken(TokenType.COMMENT, source.substring(start, i), start, i, line))
                }
                c == '/' && regexAllowed -> {
                    // 正则字面量 /.../g（支持字符类 [..] 与转义；扫描失败回退为普通 '/'）
                    val start = i
                    var j = i + 1
                    var inClass = false
                    while (j < n) {
                        val ch = source[j]
                        if (ch == '\\') { j = minOf(j + 2, n); continue }
                        if (ch == '[') inClass = true
                        else if (ch == ']') inClass = false
                        else if (ch == '/' && !inClass) { j++; break }
                        if (ch == '\n') line++
                        j++
                    }
                    if (j <= start + 1) {
                        tokens.add(JsToken(TokenType.PUNCTUATOR, "/", start, start + 1, line))
                        i = start + 1
                    } else {
                        tokens.add(JsToken(TokenType.REGEX, source.substring(start, minOf(j, n)), start, minOf(j, n), line))
                        i = j
                    }
                    regexAllowed = false
                }
                c == '"' || c == '\'' || c == '`' -> {
                    val start = i
                    val quote = c
                    i++
                    while (i < n && source[i] != quote) {
                        if (source[i] == '\\') i = minOf(i + 2, n)
                        else { if (source[i] == '\n') line++; i++ }
                    }
                    i = minOf(i + 1, n)
                    tokens.add(JsToken(if (quote == '`') TokenType.TEMPLATE else TokenType.STRING, source.substring(start, i), start, i, line))
                    regexAllowed = false
                }
                c.isDigit() -> {
                    val start = i
                    val m = numberPattern.find(source, i)
                    if (m != null && m.range.first == i) {
                        i = m.range.last + 1
                        tokens.add(JsToken(TokenType.NUMBER, m.value, start, i, line))
                    } else i++
                    regexAllowed = false
                }
                c.isLetter() || c == '_' || c == '$' -> {
                    val start = i
                    while (i < n && (source[i].isLetterOrDigit() || source[i] == '_' || source[i] == '$')) i++
                    val word = source.substring(start, i)
                    tokens.add(JsToken(if (word in keywords) TokenType.KEYWORD else TokenType.IDENTIFIER, word, start, i, line))
                    // return/typeof/in/of/case/delete/void/new/do/else/yield/await/throw 之后可能起正则
                    regexAllowed = word in setOf(
                        "return", "typeof", "instanceof", "in", "of", "case", "delete",
                        "void", "new", "do", "else", "yield", "await", "throw",
                    )
                }
                else -> {
                    val start = i
                    val two = if (i + 1 < n) source.substring(i, i + 2) else ""
                    if (two in setOf("=>", "==", "===", "!=", "!==", "<=", ">=", "&&", "||", "++", "--", "+=", "-=", "*=", "/=", "**", "??", "?.", "?:")) {
                        tokens.add(JsToken(TokenType.PUNCTUATOR, two, start, i + 2, line))
                        i += 2
                    } else {
                        tokens.add(JsToken(TokenType.PUNCTUATOR, c.toString(), start, i + 1, line))
                        i++
                    }
                    // 操作符/开括号/逗号/分号/冒号后允许正则；闭括号/点号/引号后不允许
                    regexAllowed = when (c) {
                        ')', ']', '}', '.', '\'', '"', '`', '#' -> false
                        else -> true
                    }
                }
            }
        }
        return tokens
    }

    /** 提取字符串字面量 */
    fun extractStrings(source: String): List<String> {
        return stringPattern.findAll(source).map { it.value.trim('"', '\'', '`') }.toList()
    }

    /** 提取 URL */
    fun extractUrls(source: String): List<String> {
        return urlPattern.findAll(source).map { it.value.trim('"', '\'', '`') }.distinct().toList()
    }

    /** 提取正则字面量（报告14/15：/.../g、含字符类与转义） */
    fun extractRegexes(source: String): List<String> {
        return tokenize(source).filter { it.type == TokenType.REGEX }.map { it.value }.distinct().toList()
    }

    /** 提取标识符 */
    fun extractIdentifiers(source: String): List<String> {
        return identifierPattern.findAll(source).map { it.value }.filterNot { it in keywords }.toList()
    }

    /** 提取函数定义 */
    fun extractFunctions(source: String): List<FunctionInfo> {
        val functions = mutableListOf<FunctionInfo>()
        // function name(params) { ... }
        val funcRegex = Regex("""\bfunction\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)\s*\{""")
        funcRegex.findAll(source).forEach { m ->
            val name = m.groupValues[1]
            val params = m.groupValues[2].split(",").map { it.trim() }.filter { it.isNotEmpty() }
            val line = source.substring(0, m.range.first).count { it == '\n' } + 1
            functions.add(FunctionInfo(name = name, params = params, line = line, body = m.value))
        }
        // const name = (params) => { ... }
        val arrowRegex = Regex("""(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?(?:\(([^)]*)\)|([A-Za-z_$][A-Za-z0-9_$]*))\s*=>\s*\{""")
        arrowRegex.findAll(source).forEach { m ->
            val name = m.groupValues[1]
            val params = (m.groupValues[2] + "," + m.groupValues[3]).split(",").map { it.trim() }.filter { it.isNotEmpty() }
            val line = source.substring(0, m.range.first).count { it == '\n' } + 1
            functions.add(FunctionInfo(name = name, params = params, line = line, body = m.value, isArrow = true))
        }
        // 匿名函数
        val anonRegex = Regex("""\bfunction\s*\(([^)]*)\)\s*\{""")
        anonRegex.findAll(source).forEach { m ->
            val params = m.groupValues[1].split(",").map { it.trim() }.filter { it.isNotEmpty() }
            val line = source.substring(0, m.range.first).count { it == '\n' } + 1
            functions.add(FunctionInfo(name = "(anonymous)", params = params, line = line, body = m.value, isAnonymous = true))
        }
        return functions
    }

    /** 提取调用表达式 */
    fun extractCallExpressions(source: String): List<CallExpressionInfo> {
        val calls = mutableListOf<CallExpressionInfo>()
        val regex = Regex("""([A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)\s*\(([^)]{0,200})\)""")
        regex.findAll(source).forEach { m ->
            val callee = m.groupValues[1]
            val args = splitArguments(m.groupValues[2])
            val line = source.substring(0, m.range.first).count { it == '\n' } + 1
            calls.add(CallExpressionInfo(callee = callee, arguments = args, line = line))
        }
        return calls
    }

    /** 提取成员表达式 */
    fun extractMemberExpressions(source: String): List<String> {
        val regex = Regex("""[A-Za-z_$][A-Za-z0-9_$]*\.[A-Za-z_$][A-Za-z0-9_$]*""")
        return regex.findAll(source).map { it.value }.distinct().toList()
    }

    /** 提取变量声明 */
    fun extractVariables(source: String): List<String> {
        val regex = Regex("""\b(?:var|let|const)\s+([A-Za-z_$][A-Za-z0-9_$]*(?:\s*,\s*[A-Za-z_$][A-Za-z0-9_$]*)*)""")
        return regex.findAll(source).flatMap { m ->
            m.groupValues[1].split(",").map { it.trim() }.filter { it.isNotEmpty() }
        }.toList()
    }

    /** 提取常量 */
    fun extractConstants(source: String): List<String> {
        val regex = Regex("""\bconst\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*([^;,\n]{0,100})""")
        return regex.findAll(source).map { "${it.groupValues[1]} = ${it.groupValues[2].trim()}" }.toList()
    }

    // ---------------- ：ES Module import/export 结构化提取 ----------------

    private class TokPos(val type: TokenType, val value: String)

    /** 过滤空白/注释后的有效 token 流（用于结构化语法扫描） */
    private fun sigTokens(source: String): List<TokPos> =
        tokenize(source)
            .filter { it.type != TokenType.WHITESPACE && it.type != TokenType.COMMENT }
            .map { TokPos(it.type, it.value) }

    private fun trimStr(s: String): String = s.trim('\'', '"')

    /** 结构化提取所有 import 语句 */
    fun extractImports(source: String): List<ImportDescriptor> {
        val toks = sigTokens(source)
        val out = mutableListOf<ImportDescriptor>()
        var i = 0
        while (i < toks.size) {
            val t = toks[i]
            if (t.type == TokenType.KEYWORD && t.value == "import") {
                val nextT = toks.getOrNull(i + 1)
                if (nextT != null && nextT.value == "(") { i++; continue } // 动态 import()
                var j = i + 1
                while (j < toks.size && toks[j].value != ";") j++
                val body = toks.subList(i + 1, minOf(j, toks.size))
                out.add(parseImportBody(body))
                i = j + 1
            } else i++
        }
        return out
    }

    private fun parseImportBody(body: List<TokPos>): ImportDescriptor {
        var defaultName: String? = null
        var namespace: String? = null
        val named = mutableListOf<NamedSpecifier>()
        val fromIndex = body.indexOfFirst { it.value == "from" }
        if (fromIndex >= 0) {
            val module = body.drop(fromIndex + 1).firstOrNull { it.type == TokenType.STRING }
                ?.value?.let { trimStr(it) } ?: ""
            parseImportSpec(body.take(fromIndex)) { d, ns, n ->
                if (d != null) defaultName = d
                if (ns != null) namespace = ns
                named += n
            }
            return ImportDescriptor(module, defaultName, namespace, named, sideEffectOnly = false)
        }
        // 无 from：副作用导入
        val strings = body.filter { it.type == TokenType.STRING }
        // 仅单字符串 => 副作用导入
        if (strings.size == 1 && body.all { it.type == TokenType.STRING }) {
            return ImportDescriptor(module = trimStr(strings[0].value), sideEffectOnly = true)
        }
        // 其余按包裹说明符尝试（尽量恢复）
        parseImportSpec(body) { d, ns, n ->
            if (d != null) defaultName = d
            if (ns != null) namespace = ns
            named += n
        }
        val module = strings.firstOrNull()?.value?.let { trimStr(it) } ?: ""
        return ImportDescriptor(module, defaultName, namespace, named, sideEffectOnly = false)
    }

    private inline fun parseImportSpec(
        region: List<TokPos>,
        emit: (String?, String?, List<NamedSpecifier>) -> Unit,
    ) {
        var idx = 0
        var defaultName: String? = null
        var namespace: String? = null
        val named = mutableListOf<NamedSpecifier>()
        while (idx < region.size) {
            val t = region[idx]
            when {
                t.value == "{" -> {
                    idx++
                    while (idx < region.size && region[idx].value != "}") {
                        var imported = ""
                        val ct = region[idx]
                        if (ct.type == TokenType.IDENTIFIER || ct.type == TokenType.STRING ||
                            (ct.type == TokenType.KEYWORD && ct.value == "default")
                        ) {
                            imported = trimStr(ct.value); idx++
                        } else { idx++; continue }
                        var local = imported
                        if (idx + 1 < region.size && region[idx].value == "as") {
                            idx++
                            val at = region.getOrNull(idx)
                            if (at != null && (at.type == TokenType.IDENTIFIER || at.type == TokenType.STRING)) {
                                local = trimStr(at.value); idx++
                            }
                        }
                        named.add(NamedSpecifier(imported, local))
                        if (idx < region.size && region[idx].value == ",") idx++
                    }
                    idx++ // 跳过 }
                }
                t.value == "*" -> {
                    idx++
                    if (idx + 1 < region.size && region[idx].value == "as" && region[idx + 1].type == TokenType.IDENTIFIER) {
                        namespace = region[idx + 1].value
                        idx += 2
                    }
                }
                (t.type == TokenType.IDENTIFIER && t.value !in setOf("as")) ||
                    (t.type == TokenType.KEYWORD && t.value == "default") -> {
                    if (defaultName == null) defaultName = t.value
                    idx++
                }
                t.value == "as" -> idx++
                t.value == "," -> idx++
                else -> idx++
            }
        }
        emit(defaultName, namespace, named)
    }

    /** 结构化提取所有 export 语句 */
    fun extractExports(source: String): List<ExportDescriptor> {
        val toks = sigTokens(source)
        val out = mutableListOf<ExportDescriptor>()
        var i = 0
        while (i < toks.size) {
            val t = toks[i]
            if (t.type == TokenType.KEYWORD && t.value == "export") {
                var j = i + 1
                while (j < toks.size && toks[j].value != ";") j++
                val body = toks.subList(i + 1, minOf(j, toks.size))
                out.add(parseExportBody(body))
                i = j + 1
            } else i++
        }
        return out
    }

    private fun parseExportBody(body: List<TokPos>): ExportDescriptor {
        val first = body.firstOrNull()
        // export default <expr>;
        if (first != null && first.value == "default") {
            val expr = body.drop(1).joinToString(" ") { v -> w(v) }.take(120)
            return ExportDescriptor(kind = "default", expression = expr, isDefault = true)
        }
        // 命名导出 { a, b as c } [from 'm'];
        if (first != null && first.value == "{") {
            val fromIndex = body.indexOfFirst { it.value == "from" }
            val regEnd = if (fromIndex >= 0) fromIndex else body.size
            val names = parseExportNames(body.subList(0, regEnd))
            val mod = if (fromIndex >= 0) body.drop(fromIndex + 1).firstOrNull { it.type == TokenType.STRING }
                ?.value?.let { trimStr(it) } ?: "" else ""
            return ExportDescriptor(kind = "named", names = names, module = mod)
        }
        // export * [as ns] from 'm';
        if (first != null && first.value == "*") {
            var nsAlias: String? = null
            var idx = 1
            if (idx + 1 < body.size && body[idx].value == "as") {
                nsAlias = body[idx + 1].value; idx += 2
            }
            val fi = body.indexOfFirst { it.value == "from" }
            val mod = if (fi >= 0) body.drop(fi + 1).firstOrNull { it.type == TokenType.STRING }
                ?.value?.let { trimStr(it) } ?: "" else ""
            val names = if (nsAlias != null) listOf(NamedSpecifier("*", nsAlias)) else emptyList()
            return ExportDescriptor(
                kind = if (nsAlias != null) "all_as" else "all",
                names = names,
                module = mod,
            )
        }
        // export function/class/const/let/var ...
        val snippet = body.joinToString(" ") { v -> w(v) }.take(120)
        return ExportDescriptor(kind = "declaration", expression = snippet)
    }

    private fun parseExportNames(region: List<TokPos>): List<NamedSpecifier> {
        val out = mutableListOf<NamedSpecifier>()
        var k = 0
        if (region.isNotEmpty() && region[0].value == "{") k = 1
        while (k < region.size && region[k].value != "}") {
            var local = ""
            val ct = region[k]
            if (ct.type == TokenType.IDENTIFIER || ct.type == TokenType.STRING ||
                (ct.type == TokenType.KEYWORD && ct.value == "default")
            ) { local = trimStr(ct.value); k++ } else { k++; continue }
            var exported: String? = null
            if (k + 1 < region.size && region[k].value == "as") {
                k++
                val at = region.getOrNull(k)
                if (at != null && (at.type == TokenType.IDENTIFIER || at.type == TokenType.STRING)) {
                    exported = trimStr(at.value); k++
                }
            }
            out.add(NamedSpecifier(local, exported ?: local))
            if (k < region.size && region[k].value == ",") k++
        }
        return out
    }

    private fun w(t: TokPos): String =
        if (t.type == TokenType.STRING) "\"${trimStr(t.value)}\"" else t.value

    /** 完整提取 */
    fun extractAll(source: String): JsExtraction = JsExtraction(
        strings = extractStrings(source),
        identifiers = extractIdentifiers(source),
        urls = extractUrls(source),
        functionNames = extractFunctions(source).map { it.name },
        callExpressions = extractCallExpressions(source),
        memberExpressions = extractMemberExpressions(source),
        variables = extractVariables(source),
        constants = extractConstants(source),
    )

    /**
     * 把字符串/模板串/注释/正则字面量的内容替换为等长空白（保留换行与位置），
     * 使模式/危险模式检测不会命中字符串或注释里的"伪代码"（报告14/15）。
     */
    private fun maskLiterals(source: String): String {
        val out = source.toCharArray()
        val n = source.length
        var i = 0
        while (i < n) {
            val c = source[i]
            when {
                c == '/' && i + 1 < n && source[i + 1] == '/' -> {
                    var j = i
                    while (j < n && source[j] != '\n') { if (!source[j].isWhitespace()) out[j] = ' '; j++ }
                    i = j
                }
                c == '/' && i + 1 < n && source[i + 1] == '*' -> {
                    var j = i
                    while (j + 1 < n && !(source[j] == '*' && source[j + 1] == '/')) { if (!source[j].isWhitespace()) out[j] = ' '; j++ }
                    out[j] = ' '
                    if (j + 1 < n) { out[j + 1] = ' '; j++ }
                    i = j
                }
                c == '"' || c == '\'' || c == '`' -> {
                    val q = c
                    var j = i + 1
                    while (j < n && source[j] != q) {
                        if (source[j] == '\\') {
                            if (j + 1 < n) { if (!source[j + 1].isWhitespace()) out[j + 1] = ' ' }
                            out[j] = ' '
                            j += 2
                        } else {
                            if (!source[j].isWhitespace()) out[j] = ' '
                            j++
                        }
                    }
                    if (j < n) { out[j] = q; j++ }
                    i = j
                }
                else -> i++
            }
        }
        return String(out)
    }

    /** 模式检测（在去掉字符串/注释/正则内容的掩码上扫描，避免"伪代码"误报，报告14/15） */
    fun detectPatterns(source: String, patterns: List<String>): List<PatternMatch> {
        val masked = maskLiterals(source)
        return patterns.map { pattern ->
            val regex = Regex(Regex.escape(pattern))
            val matches = regex.findAll(masked).map { m ->
                val line = source.substring(0, m.range.first).count { it == '\n' } + 1
                val start = maxOf(0, m.range.first - 40)
                val end = minOf(source.length, m.range.last + 60)
                PatternOccurrence(
                    value = pattern,
                    line = line,
                    context = source.substring(start, end).replace("\n", " "),
                )
            }.toList()
            PatternMatch(pattern, matches)
        }
    }

    /** 检测危险/动态模式 */
    fun detectDangerousPatterns(source: String): List<PatternMatch> = detectPatterns(
        source,
        listOf(
            "eval(", "new Function(", "Function(", "setTimeout(\"", "setInterval(\"",
            "document.write(", "atob(", "btoa(", "decodeURIComponent(", "String.fromCharCode(",
            "WebAssembly.instantiate", "WebAssembly.compile", "new Proxy(", "Reflect.",
            "debugger", "console.log", "window.location", "document.cookie",
        ),
    )

    /** 美化（基础缩进格式化） */
    fun beautify(source: String): String {
        val sb = StringBuilder()
        var indent = 0
        var i = 0
        val n = source.length
        var inString: Char? = null
        var inTemplate = false
        while (i < n) {
            val c = source[i]
            if (inString != null) {
                sb.append(c)
                if (c == '\\' && i + 1 < n) { sb.append(source[i + 1]); i += 2; continue }
                if (c == inString) inString = null
                i++
                continue
            }
            when {
                c == '"' || c == '\'' -> { inString = c; sb.append(c); i++ }
                c == '`' -> { inTemplate = !inTemplate; sb.append(c); i++ }
                c == '{' -> {
                    sb.append(" {\n")
                    indent++
                    repeat(indent) { sb.append("  ") }
                    i++
                }
                c == '}' -> {
                    sb.append("\n")
                    indent = maxOf(0, indent - 1)
                    repeat(indent) { sb.append("  ") }
                    sb.append("}")
                    i++
                }
                c == ';' -> {
                    sb.append(";\n")
                    repeat(indent) { sb.append("  ") }
                    i++
                }
                c == '\n' -> { sb.append('\n'); repeat(indent) { sb.append("  ") }; i++ }
                c == ',' -> { sb.append(", "); i++ }
                else -> { sb.append(c); i++ }
            }
        }
        return sb.toString()
    }

    /** 压缩检测 */
    fun isMinified(source: String): Boolean {
        if (source.length < 200) return false
        val lines = source.lines().filter { it.isNotBlank() }
        if (lines.size <= 3) return true
        val avgLineLength = source.length / lines.size.toDouble()
        return avgLineLength > 200
    }

    private fun splitArguments(args: String): List<String> {
        if (args.isBlank()) return emptyList()
        val result = mutableListOf<String>()
        var depth = 0
        var current = StringBuilder()
        var inString: Char? = null
        for (c in args) {
            if (inString != null) {
                current.append(c)
                if (c == inString) inString = null
                continue
            }
            when (c) {
                '"', '\'', '`' -> { inString = c; current.append(c) }
                '(', '[', '{' -> { depth++; current.append(c) }
                ')', ']', '}' -> { depth--; current.append(c) }
                ',' -> if (depth == 0) { result.add(current.toString().trim()); current = StringBuilder() } else current.append(c)
                else -> current.append(c)
            }
        }
        if (current.isNotBlank()) result.add(current.toString().trim())
        return result
    }
}
