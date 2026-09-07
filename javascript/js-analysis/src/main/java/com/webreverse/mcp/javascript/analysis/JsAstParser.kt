package com.webreverse.mcp.javascript.analysis

/**
 * 递归下降 JavaScript 解析器（ 全面升级：真实 JS Parser 路线）。
 *
 * 输出与 [JsAst.kt] 匹配的 [Program]（[TopLevel] 序列）。
 * 已覆盖语法：
 *  - 函数：`function 声明/表达式`、`箭头函数`（含 async/单参/解构参数/默认值）、`生成器`
 *  - 声明：`var/let/const`、**解构声明**（对象/数组模式）
 *  - 流程：`if/else`、`for`（含 for-await）、`for-in/of`、`while`、`do-while`、
 *    `switch-case`、`try/catch/finally`、`return`、标签语句
 *  - 类：`class 声明/表达式`、`extends`、静态/私有字段、方法/getter/setter
 *  - 表达式：调用、成员访问（`.` / `[]` / **`?.` 可选链**）、**`new`**、赋值（含复合/逻辑）、
 *    二元/一元运算、**`??` 空值合并**、数组/对象字面量（含 **spread**、方法简写、getter/setter）、
 *    **模板字面量（含 `${}` 插值）**、**标签模板**、**序列（逗号）表达式**、`await`/`yield*`
 *  - 模块：`import` / `export`（尽力恢复）
 *
 * 纯 Kotlin、零依赖；遇无法识别的方言时采用「尽量恢复」策略（跳过括号到可恢复点），
 * 不追求 100% 合规，面向逆向足够稳定。
 */
class JsAstParser {

    // ---------------- 词法 ----------------

    private enum class Tk { IDENT, NUMBER, STRING, TEMPLATE, OP, EOF }

    private data class Tok(val kind: Tk, val text: String, val line: Int, val col: Int, val off: Int)

    private val keywords = setOf(
        "var", "let", "const", "function", "return", "if", "else", "for", "while",
        "do", "switch", "case", "default", "break", "continue", "new", "this", "typeof",
        "in", "of", "instanceof", "try", "catch", "finally", "throw", "class", "extends", "super",
        "import", "export", "async", "await", "yield", "delete", "void", "null", "true", "false",
        "undefined", "debugger", "static", "get", "set", "from", "as", "default",
    )

    private val multiOps = listOf(
        ">>>=", "===", "!==", ">>>", "<<=", ">>=", "**=", "&&=", "||=", "??=",
        "=>", "==", "!=", "<=", ">=", "&&", "||", "++", "--", "+=", "-=", "*=", "/=",
        "**", "??", "?.", "<<", ">>", "&=", "|=", "^=", "%=", "...",
    )

    private fun tokenize(source: String): List<Tok> {
        val out = mutableListOf<Tok>()
        var i = 0
        var line = 1
        var col = 1
        val n = source.length
        while (i < n) {
            val c = source[i]
            when {
                c == '\n' -> { i++; line++; col = 1 }
                c.isWhitespace() -> { i++; col++ }
                c == '/' && i + 1 < n && source[i + 1] == '/' -> {
                    while (i < n && source[i] != '\n') { i++; col++ }
                }
                c == '/' && i + 1 < n && source[i + 1] == '*' -> {
                    i += 2; col += 2
                    while (i + 1 < n && !(source[i] == '*' && source[i + 1] == '/')) {
                        if (source[i] == '\n') { line++; col = 1 } else col++
                        i++
                    }
                    if (i + 1 < n) { i += 2; col += 2 }
                }
                c == '/' && i + 1 < n && (source[i + 1] == '=' ) -> {
                    // /= 复合除赋值（在 multiOps 之前处理避免误判注释后的除赋值）
                    out.add(Tok(Tk.OP, "/=", line, col, i)); i += 2; col += 2
                }
                c == '"' || c == '\'' -> {
                    val sep = c
                    val startOff = i; val startLine = line; val startCol = col
                    i++; col++
                    val sb = StringBuilder()
                    while (i < n && source[i] != sep) {
                        if (source[i] == '\\' && i + 1 < n) {
                            sb.append(source[i]).append(source[i + 1]); i += 2; col += 2
                        } else {
                            if (source[i] == '\n') { line++; col = 1 } else col++
                            sb.append(source[i]); i++
                        }
                    }
                    if (i < n) { i++; col++ }
                    out.add(Tok(Tk.STRING, sb.toString(), startLine, startCol, startOff))
                }
                // 模板字面量：收集到反引号闭合，保留原始内容（含 ${} 结构）
                c == '`' -> {
                    val startOff = i; val startLine = line; val startCol = col
                    i++; col++
                    val sb = StringBuilder()
                    while (i < n && source[i] != '`') {
                        if (source[i] == '\\' && i + 1 < n) {
                            sb.append(source[i]).append(source[i + 1]); i += 2; col += 2
                        } else {
                            if (source[i] == '\n') { line++; col = 1 } else col++
                            sb.append(source[i]); i++
                        }
                    }
                    if (i < n) { i++; col++ }
                    out.add(Tok(Tk.TEMPLATE, sb.toString(), startLine, startCol, startOff))
                }
                // 正则字面量：/pattern/flags（启发式：上一 token 不是值结尾时视为正则）
                c == '/' && isRegexPosition(out) -> {
                    val startOff = i; val startLine = line; val startCol = col
                    i++; col++
                    val sb = StringBuilder()
                    var inClass = false
                    while (i < n) {
                        val rc = source[i]
                        if (rc == '\\' && i + 1 < n) { sb.append(rc).append(source[i + 1]); i += 2; col += 2; continue }
                        if (rc == '\n') break
                        if (rc == '[') inClass = true
                        if (rc == ']') inClass = false
                        if (rc == '/' && !inClass) break
                        sb.append(rc); i++; col++
                    }
                    if (i < n && source[i] == '/') { i++; col++ }
                    // flags
                    while (i < n && (source[i].isLetter())) { sb.append(source[i]); i++; col++ }
                    out.add(Tok(Tk.STRING, "/${sb}/", startLine, startCol, startOff))
                }
                c.isLetter() || c == '_' || c == '$' || c == '#' -> {
                    val startOff = i; val startLine = line; val startCol = col
                    val sb = StringBuilder()
                    while (i < n && (source[i].isLetterOrDigit() || source[i] == '_' || source[i] == '$' || source[i] == '#')) {
                        sb.append(source[i]); i++; col++
                    }
                    out.add(Tok(Tk.IDENT, sb.toString(), startLine, startCol, startOff))
                }
                c.isDigit() || (c == '.' && i + 1 < n && source[i + 1].isDigit()) -> {
                    val startOff = i; val startLine = line; val startCol = col
                    val sb = StringBuilder()
                    while (i < n && (source[i].isDigit() || source[i] == '.' ||
                                source[i].let { it in 'a'..'f' || it in 'A'..'F' || it == 'x' || it == 'X' || it == 'b' || it == 'B' || it == 'o' || it == 'O' || it == 'e' || it == 'E' || it == 'n' || it == '_' })
                    ) { sb.append(source[i]); i++; col++ }
                    out.add(Tok(Tk.NUMBER, sb.toString(), startLine, startCol, startOff))
                }
                else -> {
                    // 运算符 / 标点
                    var matched = false
                    for (op in multiOps) {
                        if (source.startsWith(op, i)) {
                            out.add(Tok(Tk.OP, op, line, col, i))
                            i += op.length; col += op.length
                            matched = true
                            break
                        }
                    }
                    if (!matched) {
                        out.add(Tok(Tk.OP, c.toString(), line, col, i))
                        i++; col++
                    }
                }
            }
        }
        out.add(Tok(Tk.EOF, "", line, col, n))
        return out
    }

    /** 除号 vs 正则字面量判定：上一 token 是 IDENT/NUMBER/STRING/`)`/`]`/`}` 之外时视为正则 */
    private fun isRegexPosition(out: List<Tok>): Boolean {
        val last = out.lastOrNull() ?: return true
        if (last.kind != Tk.OP) return false
        return last.text !in setOf(")", "]", "}", "++", "--")
    }

    // ---------------- 解析器 ----------------

    private inner class Parser(private val toks: List<Tok>, private val source: String) {
        private var p = 0

        fun peek() = toks[p]
        fun peek2(): Tok = if (p + 1 < toks.size) toks[p + 1] else toks.last()
        fun next(): Tok {
            val i = p.coerceAtMost(toks.size - 1)
            p++
            return toks[i]
        }
        fun at(text: String): Boolean = peek().text == text
        fun eat(text: String): Boolean = if (at(text)) { next(); true } else false

        fun expect(text: String): Tok {
            if (!at(text)) throw IllegalStateException("期望 '$text'，实际 '${peek().text}' @${peek().line}")
            return next()
        }

        fun pos(t: Tok) = SourcePos(t.line, t.col, t.off)

        // ---- 顶层 ----
        fun parseProgram(): Program {
            val items = mutableListOf<TopLevel>()
            while (peek().kind != Tk.EOF) {
                val tl = try {
                    parseTopLevel()
                } catch (e: Exception) {
                    recoverStatement()
                    null
                }
                if (tl != null) items.add(tl)
            }
            return Program(items, source)
        }

        private fun recoverStatement() {
            // 跳过到下一个可恢复点（; 或成对闭合的 }）
            var depth = 0
            while (peek().kind != Tk.EOF) {
                val t = next()
                when (t.text) {
                    "{", "(", "[" -> depth++
                    "}", ")", "]" -> if (depth > 0) depth-- else { p--; return }
                    ";" -> if (depth == 0) return
                }
            }
        }

        private fun parseTopLevel(): TopLevel {
            if (at("function")) {
                val fn = parseFunctionDecl()
                return TopLevel.Function(fn, fn.pos)
            }
            if (at("async") && peek2().text == "function") {
                val fn = parseFunctionDecl()
                return TopLevel.Function(fn, fn.pos)
            }
            if (at("export")) {
                val d = parseExport()
                return TopLevel.Statement(d, d.pos)
            }
            val stmt = parseStatement()
            return TopLevel.Statement(stmt, stmt.pos)
        }

        private fun skipToSemi() {
            while (peek().kind != Tk.EOF && !at(";")) next()
            eat(";")
        }

        // ---- ：ES Module import/export 结构化精确解析 ----

        /**
         * import 声明：`import 'm'`（副作用）/
         * `import d from 'm'` / `import * as ns from 'm'` /
         * `import {a, b as c, default as d} from 'm'` /
         * `import d, {a} from 'm'` / `import d, * as ns from 'm'`
         */
        fun parseImportDecl(): Stmt.ImportDecl {
            val start = pos(peek())
            next() // 'import'
            val specs = mutableListOf<ImportSpecifier>()
            var module = ""
            var finished = false
            while (!finished && peek().kind != Tk.EOF) {
                when {
                    at(",") || at("from") -> next()
                    peek().kind == Tk.STRING -> { module = next().text; finished = true }
                    at("{") -> specs += parseImportNameSpecifiers()
                    at("*") -> {
                        next()
                        if (eat("as") && peek().kind == Tk.IDENT) {
                            val nm = next()
                            specs.add(ImportSpecifier(nm.text, "*", ImportSpecifierKind.NAMESPACE, pos(nm)))
                        }
                    }
                    peek().kind == Tk.IDENT -> {
                        // 默认导入绑定：import d [, ...] from 'm'
                        val nm = next()
                        specs.add(ImportSpecifier(nm.text, "default", ImportSpecifierKind.DEFAULT, pos(nm)))
                    }
                    at(";") -> { finished = true }
                    peek().kind == Tk.EOF -> finished = true
                    else -> next()
                }
            }
            eat(";")
            return Stmt.ImportDecl(module, start, specs.distinctBy { it.local })
        }

        /** `{ a, b as c, "x" as y, default as d }` 命名导入说明符列表 */
        private fun parseImportNameSpecifiers(): List<ImportSpecifier> {
            expect("{")
            val out = mutableListOf<ImportSpecifier>()
            while (!at("}") && peek().kind != Tk.EOF) {
                val epos = pos(peek())
                var imported = ""
                when {
                    peek().kind == Tk.IDENT -> imported = next().text
                    peek().kind == Tk.STRING -> imported = next().text.trim('\'', '"')
                    else -> next()
                }
                var local = imported
                if (eat("as") && peek().kind == Tk.IDENT) local = next().text
                val kind = if (imported == "default") ImportSpecifierKind.DEFAULT else ImportSpecifierKind.NAMED
                out.add(ImportSpecifier(local, imported, kind, epos))
                if (at("}")) break
                eat(",")
            }
            expect("}")
            return out
        }

        /**
         * export 声明：`export default expr/function/class`、
         * `export {a, b as c}` / `export {...} from 'm'`、
         * `export * from 'm'` / `export * as ns from 'm'`、
         * `export function/class/const/let/var ...`
         */
        fun parseExport(): Stmt.ExportDecl {
            val start = pos(peek())
            next() // 'export'
            return when {
                at("default") -> {
                    next()
                    val clause = ExportClause(isDefault = true, pos = start)
                    val inner: Stmt = when {
                        at("function") -> {
                            val fn = parseFunctionDecl()
                            Stmt.ExprStmt(Expr.FunctionExpr(fn.name.ifEmpty { null }, fn.params, fn.body, false, fn.pos, fn.isAsync, fn.isGenerator), fn.pos)
                        }
                        at("class") -> parseClassDecl()
                        at(";") -> { next(); Stmt.EmptyStmt(start) }
                        else -> {
                            val e = if (at(";")) { next(); Expr.UndefinedLit(start) } else parseExpr().also { eat(";") }
                            Stmt.ExprStmt(e, e.pos)
                        }
                    }
                    Stmt.ExportDecl(inner, start, clause)
                }
                at("{") -> {
                    val named = parseExportNameSpecifiers()
                    var from = ""
                    if (eat("from")) { if (peek().kind == Tk.STRING) from = next().text.trim('\'', '"') }
                    eat(";")
                    Stmt.ExportDecl(null, start, ExportClause(named = named, from = from.ifBlank { null }, pos = start))
                }
                at("*") -> {
                    next()
                    var nsAlias: String? = null
                    if (eat("as") && peek().kind == Tk.IDENT) nsAlias = next().text
                    var from = ""
                    if (eat("from")) { if (peek().kind == Tk.STRING) from = next().text.trim('\'', '"') }
                    eat(";")
                    Stmt.ExportDecl(null, start, ExportClause(from = from.ifBlank { null }, isAll = nsAlias == null, namespaceAlias = nsAlias, pos = start))
                }
                at("import") || at("export") -> {
                    // 兼容异常写法：尽力跳到分号，保底为占位导出
                    skipToSemi()
                    Stmt.ExportDecl(null, start, ExportClause(pos = start))
                }
                else -> {
                    val inner = parseStatement()
                    Stmt.ExportDecl(inner, start, ExportClause(pos = start))
                }
            }
        }

        /** `{ a, b as c, default, "x" as y }` 命名导出说明符列表 */
        private fun parseExportNameSpecifiers(): List<ExportNamedSpecifier> {
            expect("{")
            val out = mutableListOf<ExportNamedSpecifier>()
            while (!at("}") && peek().kind != Tk.EOF) {
                val epos = pos(peek())
                var local = ""
                when {
                    peek().kind == Tk.IDENT -> local = next().text
                    peek().kind == Tk.STRING -> local = next().text.trim('\'', '"')
                    else -> next()
                }
                var exported: String? = null
                if (eat("as")) {
                    if (peek().kind == Tk.IDENT) exported = next().text
                    else if (peek().kind == Tk.STRING) exported = next().text.trim('\'', '"')
                }
                out.add(ExportNamedSpecifier(local, exported, isDefault = local == "default", epos))
                if (at("}")) break
                eat(",")
            }
            expect("}")
            return out
        }

        fun parseFunctionDecl(): JsFunction {
            val start = pos(peek())
            var isAsync = false
            if (eat("async")) isAsync = true
            expect("function")
            var isGenerator = false
            if (eat("*")) isGenerator = true
            val name = if (peek().kind == Tk.IDENT) next().text else ""
            val params = parseParams()
            val body = parseBlock()
            return JsFunction(name, params, body, start, isArrow = false, isAsync = isAsync, isGenerator = isGenerator)
        }

        /** 参数列表：支持标识符、解构模式、默认值、rest */
        private fun parseParams(): List<String> {
            expect("(")
            val out = mutableListOf<String>()
            while (!at(")")) {
                when {
                    peek().kind == Tk.IDENT -> out.add(next().text)
                    at("...") -> { next(); if (peek().kind == Tk.IDENT) out.add(next().text) }
                    at("{") || at("[") -> out.addAll(parseBindingPattern())
                    else -> if (peek().kind != Tk.EOF) next() // 跳过 default 值等干扰
                }
                // 默认值：= expr
                if (eat("=")) parseAssign()
                if (!eat(",")) break
            }
            expect(")")
            return out
        }

        /** 解构模式：收集绑定名（忽略嵌套结构），不消费 = 之后内容 */
        private fun parseBindingPattern(): List<String> {
            val names = mutableListOf<String>()
            val open = peek().text
            if (open != "{" && open != "[") return names
            next() // { 或 [
            val closer = if (open == "{") "}" else "]"
            while (!at(closer) && peek().kind != Tk.EOF) {
                when {
                    peek().kind == Tk.IDENT -> names.add(next().text)
                    at("...") -> { next(); if (peek().kind == Tk.IDENT) names.add(next().text) }
                    at("{") || at("[") -> names.addAll(parseBindingPattern())
                    at(":") -> { next() } // 对象模式中的 值位置
                    at(",") -> next()
                    else -> if (peek().kind != Tk.EOF) next()
                }
                // 默认值
                if (eat("=")) parseAssign()
                if (at(",")) next() else if (!at(closer) && peek().kind != Tk.EOF) continue else break
            }
            expect(closer)
            return names
        }

        private fun parseBlock(): Stmt.Block {
            val bpos = pos(peek())
            expect("{")
            val stmts = mutableListOf<Stmt>()
            while (!at("}")) {
                if (peek().kind == Tk.EOF) break
                try {
                    stmts.add(parseStatement())
                } catch (e: Exception) {
                    recoverStatement()
                }
            }
            expect("}")
            return Stmt.Block(stmts, bpos)
        }

        // ---- 语句 ----
        fun parseStatement(): Stmt {
            val t = peek()
            return when {
                at(";") -> { next(); Stmt.EmptyStmt(pos(t)) }
                at("{") -> parseBlock()
                at("var") || at("let") || at("const") -> parseVarDecl()
                at("function") -> {
                    val fn = parseFunctionDecl()
                    Stmt.ExprStmt(Expr.FunctionExpr(fn.name.ifEmpty { null }, fn.params, fn.body, false, fn.pos, fn.isAsync, fn.isGenerator), fn.pos)
                }
                at("class") -> parseClassDecl()
                at("if") -> parseIf()
                at("for") -> parseFor()
                at("while") -> parseWhile()
                at("do") -> parseDoWhile()
                at("switch") -> parseSwitch()
                at("return") -> parseReturn()
                at("try") -> parseTryCatch()
                at("throw") -> { val r = next(); val arg = if (at(";") || at("}")) null else parseExpr(); eat(";"); Stmt.Throw(arg, pos(r)) }
                at("break") -> { next(); eat(";"); Stmt.Break(pos(t)) }
                at("continue") -> { next(); eat(";"); Stmt.Continue(pos(t)) }
                at("debugger") -> { next(); eat(";"); Stmt.EmptyStmt(pos(t)) }
                at("import") -> {
                    // 静态 import 声明；动态 import('...') 走表达式
                    if (peek2().text == "(") {
                        val e = parseExpr()
                        eat(";")
                        Stmt.ExprStmt(e, e.pos)
                    } else {
                        parseImportDecl()
                    }
                }
                at("export") -> parseExport()
                at("async") && peek2().text == "function" -> {
                    val fn = parseFunctionDecl()
                    Stmt.ExprStmt(Expr.FunctionExpr(fn.name.ifEmpty { null }, fn.params, fn.body, false, fn.pos, fn.isAsync, fn.isGenerator), fn.pos)
                }
                // 标签语句：IDENT ':'（非三元 —— 三元的 ? 在表达式层处理，: 不会出现在此）
                peek().kind == Tk.IDENT && peek2().text == ":" && t.text !in keywords -> {
                    next(); next() // label :
                    val inner = parseStatement()
                    inner
                }
                else -> {
                    val e = parseExpr()
                    eat(";")
                    Stmt.ExprStmt(e, e.pos)
                }
            }
        }

        /** try {} catch(e)? {} finally? {} */
        private fun parseTryCatch(): Stmt {
            val start = pos(peek())
            expect("try")
            val block = parseBlock()
            var catchParam: String? = null
            var catchBody: Stmt.Block? = null
            if (eat("catch")) {
                if (eat("(")) {
                    catchParam = if (peek().kind == Tk.IDENT) next().text else "?"
                    if (at("{") || at("[")) parseBindingPattern()
                    expect(")")
                }
                catchBody = parseBlock()
            }
            val finallyBody = if (eat("finally")) parseBlock() else null
            return Stmt.TryCatch(block, catchParam, catchBody, finallyBody, start)
        }

        /** class 声明/表达式 */
        fun parseClassDecl(): Stmt.ClassDecl {
            val start = pos(peek())
            expect("class")
            var name = ""
            if (peek().kind == Tk.IDENT && peek().text != "extends") name = next().text
            var superClass: String? = null
            if (eat("extends")) {
                superClass = if (peek().kind == Tk.IDENT) next().text else "?"
                // extends 表达式（成员链）
                while (at(".") && peek2().kind == Tk.IDENT) { next(); superClass += "." + next().text }
            }
            expect("{")
            val members = mutableListOf<ClassMember>()
            while (!at("}") && peek().kind != Tk.EOF) {
                try {
                    parseClassMember(members)
                } catch (e: Exception) {
                    recoverStatement()
                }
            }
            expect("}")
            return Stmt.ClassDecl(name, superClass, members, start)
        }

        private fun parseClassMember(out: MutableList<ClassMember>) {
            val start = pos(peek())
            var isStatic = false
            var kind = "method"
            var isAsync = false
            var isGenerator = false

            if (at("static") && peek2().text != "(" && peek2().text != "=" && peek2().text != ";") {
                next(); isStatic = true
            }
            if (at("async") && peek2().text != "(" && peek2().text != "=" && peek2().text != ";" && peek2().text != ")") {
                next(); isAsync = true
            }
            if (at("*")) { next(); isGenerator = true }

            // 方法名：constructor / #private / [computed] / name
            var name = ""
            var computed = false
            when {
                at("[") -> { next(); parseExpr(); expect("]"); name = "[computed]"; computed = true }
                at("#") || peek().kind == Tk.IDENT -> name = next().text
                peek().kind == Tk.STRING -> name = next().text
                else -> name = next().text
            }

            // getter / setter
            if ((name == "get" || name == "set") && !at("(") && !at("=") && !at(";") && !at("}")) {
                kind = name
                name = if (peek().kind == Tk.IDENT) next().text else "?"
                if (at("[") && !computed) { next(); parseExpr(); expect("]") }
            }
            if (name == "constructor") kind = "ctor"

            when {
                at("(") -> {
                    // 方法
                    val params = parseParams()
                    val body = parseBlock()
                    out.add(ClassMember(name, params, body, isStatic, kind, null, isAsync, isGenerator, start))
                }
                at("=") -> {
                    // 字段初始化
                    next()
                    val init = parseAssign()
                    eat(";")
                    out.add(ClassMember(name, emptyList(), Stmt.Block(emptyList(), start), isStatic, "field", init, false, false, start))
                }
                else -> {
                    // 无初始化字段
                    eat(";")
                    out.add(ClassMember(name, emptyList(), Stmt.Block(emptyList(), start), isStatic, "field", null, false, false, start))
                }
            }
        }

        private fun parseVarDecl(): Stmt {
            val kindTok = next() // var/let/const
            val kind = kindTok.text
            val vpos = pos(kindTok)
            // 解构声明：{...} = expr 或 [...] = expr
            if (at("{") || at("[")) {
                val startPos = pos(peek())
                val bindings = mutableListOf<DestructureBinding>()
                val names = parseDestructureBindings(bindings)
                if (eat("=")) {
                    val init = parseAssign()
                    skipRestDeclarators()
                    eat(";")
                    // 构造 DestructureDecl + 附件（第二个声明符若存在已被跳过）
                    return Stmt.DestructureDecl(kind, bindings, init, vpos)
                }
                // 无初始化解构：罕见（语法错误），降级为单变量声明
                skipRestDeclarators()
                eat(";")
                return Stmt.VarDecl(kind, names.firstOrNull() ?: "?", null, vpos).let { _ ->
                    Stmt.DestructureDecl(kind, bindings, null, startPos)
                }
            }
            // 常规单声明符
            val name = if (peek().kind == Tk.IDENT) next().text else "?"
            var init: Expr? = null
            if (eat("=")) init = parseAssign()
            // 多声明符：合并为序列近似（首个绑定保留，其余跳过但记录）
            var extraDecls = mutableListOf<Stmt>()
            while (eat(",")) {
                if (at("{") || at("[")) {
                    val bindings = mutableListOf<DestructureBinding>()
                    if (eat("=")) {
                        val init2 = parseAssign()
                        extraDecls.add(Stmt.DestructureDecl(kind, bindings, init2, vpos))
                    }
                } else if (peek().kind == Tk.IDENT) {
                    val n2 = next().text
                    if (eat("=")) {
                        val init2 = parseAssign()
                        extraDecls.add(Stmt.VarDecl(kind, n2, init2, vpos))
                    } else {
                        extraDecls.add(Stmt.VarDecl(kind, n2, null, vpos))
                    }
                }
            }
            eat(";")
            val first = Stmt.VarDecl(kind, name, init, vpos)
            // 多声明符场景：返回 Block（首个 + 额外），保证 DFG 完整性
            return if (extraDecls.isEmpty()) first else Stmt.Block(listOf(first) + extraDecls, vpos)
        }

        /** 解构绑定收集（含默认值），返回扁平名字列表 */
        private fun parseDestructureBindings(bindings: MutableList<DestructureBinding>): List<String> {
            val names = mutableListOf<String>()
            val open = peek().text
            if (open != "{" && open != "[") return names
            next()
            val closer = if (open == "{") "}" else "]"
            while (!at(closer) && peek().kind != Tk.EOF) {
                when {
                    at("...") -> {
                        next()
                        if (peek().kind == Tk.IDENT) {
                            val t = next()
                            names.add(t.text)
                            bindings.add(DestructureBinding(t.text, null, pos(t)))
                        }
                    }
                    at("{") || at("[") -> names.addAll(parseDestructureBindings(bindings))
                    peek().kind == Tk.IDENT -> {
                        val t = next()
                        names.add(t.text)
                        bindings.add(DestructureBinding(t.text, null, pos(t)))
                    }
                    at(":") -> {
                        next()
                        if (at("{") || at("[") || peek().kind == Tk.IDENT) {
                            if (at("{") || at("[")) names.addAll(parseDestructureBindings(bindings))
                            else { val t2 = next(); names.add(t2.text); bindings.add(DestructureBinding(t2.text, null, pos(t2))) }
                        }
                    }
                    at(",") -> next()
                    else -> if (peek().kind != Tk.EOF) next()
                }
                // 默认值 = expr
                if (eat("=")) {
                    val d = parseAssign()
                    if (bindings.isNotEmpty()) {
                        val last = bindings.removeAt(bindings.size - 1)
                        bindings.add(last.copy(defaultValue = d))
                    }
                }
                if (at(",")) next()
            }
            expect(closer)
            return names
        }

        /** 跳过多声明符剩余部分 */
        private fun skipRestDeclarators() {
            while (at(",")) {
                next()
                if (at("{") || at("[")) { parseBindingPattern(); if (eat("=")) parseAssign() }
                else if (peek().kind == Tk.IDENT) { next(); if (eat("=")) parseAssign() }
            }
        }

        private fun parseIf(): Stmt {
            val start = pos(peek())
            expect("if")
            expect("(")
            val cond = parseExpr()
            expect(")")
            val thenBody = parseStatement()
            var elseBody: Stmt? = null
            if (eat("else")) elseBody = parseStatement()
            return Stmt.If(cond, thenBody, elseBody, start)
        }

        private fun parseFor(): Stmt {
            val start = pos(peek())
            expect("for")
            var isAwait = false
            if (eat("await")) isAwait = true
            expect("(")
            // for-in/of
            if (at("var") || at("let") || at("const")) {
                val saved = p
                next()
                if (at("{") || at("[")) {
                    // for (const [k, v] of ...)：解构 for-of
                    val bindings = mutableListOf<DestructureBinding>()
                    val names = parseDestructureBindings(bindings)
                    if (at("in") || at("of")) {
                        val op = next().text
                        val obj = parseExpr()
                        expect(")")
                        val body = parseStatement()
                        val left = Expr.Identifier(names.firstOrNull() ?: "?", start)
                        return Stmt.ForEach(left, obj, body, of = op == "of", pos = start, isAwait = isAwait)
                    }
                    p = saved
                } else if (peek().kind == Tk.IDENT) {
                    next()
                    if (at("in") || at("of")) {
                        val op = next().text
                        p = saved
                        next() // var/let/const
                        val lname = next().text
                        val left = Expr.Identifier(lname, pos(toks[p - 1]))
                        next() // 消费 in/of
                        val obj = parseExpr()
                        expect(")")
                        val body = parseStatement()
                        return Stmt.ForEach(left, obj, body, of = op == "of", pos = start, isAwait = isAwait)
                    }
                    p = saved
                } else {
                    p = saved
                }
            }
            var init: Stmt? = null
            if (!at(";")) {
                init = if (at("var") || at("let") || at("const")) parseVarDecl() else {
                    val e = parseExpr()
                    Stmt.ExprStmt(e, e.pos)
                }
            }
            eat(";")
            var cond: Expr? = null
            if (!at(";")) cond = parseExpr()
            expect(";")
            var update: Expr? = null
            if (!at(")")) update = parseExpr()
            expect(")")
            val body = parseStatement()
            return Stmt.For(init, cond, update, body, start, isAwait = isAwait)
        }

        private fun parseWhile(): Stmt {
            val start = pos(peek())
            expect("while")
            expect("(")
            val cond = parseExpr()
            expect(")")
            val body = parseStatement()
            return Stmt.While(cond, body, start)
        }

        private fun parseDoWhile(): Stmt {
            val start = pos(peek())
            expect("do")
            val body = parseStatement()
            expect("while")
            expect("(")
            val cond = parseExpr()
            expect(")")
            eat(";")
            return Stmt.DoWhile(body, cond, start)
        }

        private fun parseSwitch(): Stmt {
            val start = pos(peek())
            expect("switch")
            expect("(")
            val disc = parseExpr()
            expect(")")
            val cases = mutableListOf<SwitchCase>()
            var cpos = pos(peek())
            expect("{")
            var current = mutableListOf<Stmt>()
            while (!at("}")) {
                if (peek().kind == Tk.EOF) break
                if (at("case")) {
                    val c = next()
                    cases.add(SwitchCase(parseExpr(), current.toList(), cpos))
                    current = mutableListOf()
                    expect(":")
                    cpos = pos(toks[p - 1])
                } else if (at("default")) {
                    val c = next()
                    cases.add(SwitchCase(null, current.toList(), cpos))
                    current = mutableListOf()
                    expect(":")
                    cpos = pos(c)
                } else {
                    try {
                        current.add(parseStatement())
                    } catch (e: Exception) {
                        recoverStatement()
                    }
                }
            }
            cases.add(SwitchCase(null, current.toList(), cpos))
            expect("}")
            return Stmt.Switch(disc, cases, start)
        }

        private fun parseReturn(): Stmt {
            val start = pos(peek())
            expect("return")
            var arg: Expr? = null
            if (!at(";") && !at("}") && peek().kind != Tk.EOF) arg = parseExpr()
            eat(";")
            return Stmt.Return(arg, start)
        }

        // ---- 表达式（优先级爬升）----
        fun parseExpr() = parseAssign()

        /** 序列（逗号）表达式：语句位置/for 头使用 */
        fun parseSequence(): Expr {
            val first = parseAssign()
            if (!at(",")) return first
            val exprs = mutableListOf(first)
            while (eat(",")) exprs.add(parseAssign())
            return Expr.Sequence(exprs, first.pos)
        }

        fun parseAssign(): Expr {
            val left = parseConditional()
            val t = peek()
            val assignOps = setOf("=", "+=", "-=", "*=", "/=", "%=", "**=", "<<=", ">>=", ">>>=", "&=", "|=", "^=", "&&=", "||=", "??=")
            if (t.kind == Tk.OP && t.text in assignOps) {
                next()
                val right = parseAssign()
                return Expr.Assign(left, t.text, right, left.pos)
            }
            return left
        }

        private fun parseConditional(): Expr {
            val c = parseNullish()
            if (at("?")) {
                next()
                val t = parseAssign()
                expect(":")
                val f = parseAssign()
                return Expr.Conditional(c, t, f, c.pos)
            }
            return c
        }

        /** ?? 与 || 同级（规范如此，不可无括号混用） */
        private fun parseNullish(): Expr {
            val left = parseAnd()
            if (at("||") || at("??")) { val op = next().text; return Expr.Binary(left, op, parseNullish(), left.pos) }
            return left
        }

        private fun parseAnd(): Expr {
            val left = parseBitOr()
            if (at("&&")) { next(); return Expr.Binary(left, "&&", parseAnd(), left.pos) }
            return left
        }

        private fun parseBitOr(): Expr {
            var left = parseBitXor()
            while (at("|")) { next(); val r = parseBitXor(); left = Expr.Binary(left, "|", r, left.pos) }
            return left
        }

        private fun parseBitXor(): Expr {
            var left = parseBitAnd()
            while (at("^")) { next(); val r = parseBitAnd(); left = Expr.Binary(left, "^", r, left.pos) }
            return left
        }

        private fun parseBitAnd(): Expr {
            var left = parseEquality()
            while (at("&")) { next(); val r = parseEquality(); left = Expr.Binary(left, "&", r, left.pos) }
            return left
        }

        private fun parseEquality(): Expr {
            var left = parseRelational()
            while (at("==") || at("!=") || at("===") || at("!==")) { val op = next().text; val r = parseRelational(); left = Expr.Binary(left, op, r, left.pos) }
            return left
        }

        private fun parseRelational(): Expr {
            var left = parseShift()
            while (at("<") || at(">") || at("<=") || at(">=") || at("instanceof") || at("in")) {
                val op = next().text; val r = parseShift(); left = Expr.Binary(left, op, r, left.pos)
            }
            return left
        }

        private fun parseShift(): Expr {
            var left = parseAdditive()
            while (at("<<") || at(">>") || at(">>>")) { val op = next().text; val r = parseAdditive(); left = Expr.Binary(left, op, r, left.pos) }
            return left
        }

        private fun parseAdditive(): Expr {
            var left = parseMultiplicative()
            while (at("+") || at("-")) { val op = next().text; val r = parseMultiplicative(); left = Expr.Binary(left, op, r, left.pos) }
            return left
        }

        private fun parseMultiplicative(): Expr {
            var left = parseUnary()
            while (at("*") || at("/") || at("%")) { val op = next().text; val r = parseUnary(); left = Expr.Binary(left, op, r, left.pos) }
            return left
        }

        private fun parseUnary(): Expr {
            val unaryOps = setOf("!", "~", "+", "-", "typeof", "void", "delete", "++", "--")
            val t = peek()
            if (t.kind == Tk.OP && t.text in unaryOps) {
                next()
                val operand = parseUnary()
                return Expr.Unary(t.text, operand, pos(t))
            }
            if (t.kind == Tk.IDENT && t.text in unaryOps) {
                next()
                val operand = parseUnary()
                return Expr.Unary(t.text, operand, pos(t))
            }
            if (t.kind == Tk.IDENT && t.text == "await") {
                next()
                return Expr.AwaitExpr(parseUnary(), pos(t))
            }
            if (t.kind == Tk.IDENT && t.text == "yield") {
                next()
                val delegate = eat("*")
                val arg = if (at(";") || at("}") || at(")") || at(",") || at("]") || peek().kind == Tk.EOF) null else parseAssign()
                return Expr.YieldExpr(arg, delegate, pos(t))
            }
            if (t.kind == Tk.IDENT && t.text == "new") {
                return parseNew()
            }
            return parsePostfix()
        }

        /** new 表达式：new Callee(args) —— Callee 为成员链（不再递归 new），之后继续后缀 */
        private fun parseNew(): Expr {
            val start = pos(peek())
            expect("new")
            if (at("new")) {
                // new new A()()：递归
                val inner = parseNew()
                val args = if (at("(")) parseArgs() else emptyList()
                return Expr.New(inner, args, start)
            }
            // 构造成员链（不含调用）
            var callee = parsePrimary()
            while (true) {
                when {
                    at(".") -> {
                        next()
                        val prop = if (peek().kind == Tk.IDENT || peek().kind == Tk.NUMBER) next().text else if (peek().kind == Tk.STRING) next().text else ""
                        callee = Expr.Member(callee, prop, null, callee.pos)
                    }
                    at("[") -> {
                        next()
                        val idx = parseExpr()
                        expect("]")
                        callee = Expr.Member(callee, null, idx, callee.pos)
                    }
                    else -> break
                }
            }
            val args = if (at("(")) parseArgs() else emptyList()
            val newExpr = Expr.New(callee, args, start)
            // new Foo().bar() / new Foo()[i]：继续后缀
            return continuePostfix(newExpr)
        }

        private fun parsePostfix(): Expr {
            var left = parsePrimary()
            return continuePostfix(left)
        }

        /** 后缀循环：.prop / [expr] / (args) / ?. / ?.() / ++ / --（含箭头函数头检测） */
        private fun continuePostfix(initial: Expr): Expr {
            var left = initial
            // 单参数箭头函数 x => ...
            if (left is Expr.Identifier && at("=>")) {
                next() // =>
                val body = if (at("{")) parseBlock() else Stmt.Block(listOf(Stmt.Return(parseAssign(), left.pos)), left.pos)
                return Expr.FunctionExpr(null, listOf(left.name), body, true, left.pos)
            }
            while (true) {
                when {
                    at(".") -> {
                        next()
                        val prop = when {
                            peek().kind == Tk.IDENT -> next().text
                            peek().kind == Tk.NUMBER -> next().text
                            peek().kind == Tk.STRING -> next().text
                            peek().kind != Tk.EOF -> next().text
                            else -> ""
                        }
                        left = Expr.Member(left, prop, null, left.pos)
                    }
                    at("?.") -> {
                        next()
                        when {
                            at("(") -> {
                                val args = parseArgs()
                                left = Expr.Call(left, args, left.pos, optional = true)
                            }
                            at("[") -> {
                                next()
                                val idx = parseExpr()
                                expect("]")
                                left = Expr.Member(left, null, idx, left.pos, optional = true)
                            }
                            peek().kind == Tk.IDENT -> {
                                val prop = next().text
                                left = Expr.Member(left, prop, null, left.pos, optional = true)
                            }
                            peek().kind == Tk.TEMPLATE -> {
                                val tmpl = parseTemplate()
                                left = Expr.TaggedTemplate(left, tmpl, left.pos)
                            }
                            else -> left = Expr.Member(left, "", null, left.pos, optional = true)
                        }
                    }
                    at("[") -> {
                        next()
                        val idx = parseExpr()
                        expect("]")
                        left = Expr.Member(left, null, idx, left.pos)
                    }
                    at("(") -> {
                        val args = parseArgs()
                        left = Expr.Call(left, args, left.pos)
                    }
                    peek().kind == Tk.TEMPLATE -> {
                        // 标签模板 tag`...`
                        val tmpl = parseTemplate()
                        left = Expr.TaggedTemplate(left, tmpl, left.pos)
                    }
                    at("++") || at("--") -> {
                        val op = next().text
                        left = Expr.Unary(op, left, left.pos)
                    }
                    else -> return left
                }
            }
        }

        private fun parseArgs(): List<Expr> {
            expect("(")
            val out = mutableListOf<Expr>()
            while (!at(")")) {
                if (peek().kind == Tk.EOF) break
                if (at("...")) {
                    val sp = next()
                    val inner = parseAssign()
                    out.add(Expr.Spread(inner, pos(sp)))
                } else {
                    try {
                        out.add(parseAssign())
                    } catch (e: Exception) {
                        recoverToCommaOrParen()
                    }
                }
                if (eat(",")) continue else break
            }
            expect(")")
            return out
        }

        private fun recoverToCommaOrParen() {
            var depth = 0
            while (peek().kind != Tk.EOF) {
                val t = next()
                when (t.text) {
                    "(", "[", "{" -> depth++
                    "]", "}" -> if (depth > 0) depth-- else return
                    "," -> if (depth == 0) return
                    ")" -> if (depth == 0) { p--; return }
                }
            }
        }

        /** 前瞻：自 p（已消费 '('）起，判断以 ')' 收尾且紧跟 '=>'，即为箭头函数形参 */
        private fun looksLikeArrowParams(): Boolean {
            var i = p
            if (i >= toks.size || toks[i].kind == Tk.EOF) return false
            var depth = 0
            while (i < toks.size) {
                val tk = toks[i]
                when (tk.text) {
                    "(", "[", "{" -> depth++
                    "}", "]" -> if (depth > 0) depth--
                    ")" -> {
                        if (depth == 0) {
                            val nxt = if (i + 1 < toks.size) toks[i + 1].text else ""
                            return nxt == "=>"
                        }
                        if (depth > 0) depth--
                    }
                    else -> { /* 继续 */ }
                }
                if (depth < 0) return false
                i++
            }
            return false
        }

        /** async 箭头前瞻：async x => / async (...) => */
        private fun looksLikeAsyncArrow(): Boolean {
            if (peek2().text == "=>") return true // async x =>
            if (peek2().text == "(") {
                // 找到配对 ) 后是否紧跟 =>
                var i = p + 2
                var depth = 0
                while (i < toks.size) {
                    val tk = toks[i]
                    when (tk.text) {
                        "(" -> depth++
                        ")" -> {
                            if (depth == 0) {
                                return i + 1 < toks.size && toks[i + 1].text == "=>"
                            }
                            depth--
                        }
                    }
                    if (tk.kind == Tk.EOF) return false
                    i++
                }
            }
            return false
        }

        /** 解析模板字面量（已确认当前 token 为 TEMPLATE） */
        private fun parseTemplate(): Expr.TemplateLit {
            val t = expectBacktick()
            val raw = t.text
            val quasis = mutableListOf<String>()
            val exprs = mutableListOf<Expr>()
            var sb = StringBuilder()
            var i = 0
            val n = raw.length
            while (i < n) {
                val c = raw[i]
                if (c == '$' && i + 1 < n && raw[i + 1] == '{') {
                    // 进入插值：括号深度扫描
                    quasis.add(sb.toString())
                    sb = StringBuilder()
                    var depth = 1
                    i += 2
                    val exprStart = i
                    while (i < n && depth > 0) {
                        val rc = raw[i]
                        when (rc) {
                            '{', '(', '[' -> depth++
                            '}', ')', ']' -> depth--
                            '`' -> {
                                // 嵌套模板：跳到闭合反引号
                                i++
                                while (i < n && raw[i] != '`') {
                                    if (raw[i] == '\\') i++
                                    i++
                                }
                            }
                            '\\' -> i++
                        }
                        if (depth > 0) i++
                    }
                    val exprSrc = raw.substring(exprStart, i.coerceAtMost(n))
                    exprs.add(parseFragment(exprSrc, t.line))
                    i++ // 跳过收尾 }
                } else {
                    if (c == '\\' && i + 1 < n) { sb.append(c); i++ }
                    sb.append(raw[i])
                    i++
                }
            }
            quasis.add(sb.toString())
            return Expr.TemplateLit(quasis, exprs, pos(t))
        }

        private fun expectBacktick(): Tok {
            val t = peek()
            if (t.kind != Tk.TEMPLATE) throw IllegalStateException("期望模板字面量 @${t.line}")
            return next()
        }

        /** 片段表达式解析：对 ${} 内的源码子解析 */
        private fun parseFragment(src: String, line: Int): Expr {
            if (src.isBlank()) return Expr.UndefinedLit(SourcePos(line, 1, -1))
            return try {
                val sub = Parser(tokenize(src), src)
                sub.parseAssign()
            } catch (e: Exception) {
                Expr.Identifier("__frag__", SourcePos(line, 1, -1))
            }
        }

        private fun parsePrimary(): Expr {
            val t = peek()
            return when (t.kind) {
                Tk.NUMBER -> { next(); Expr.Number(t.text, pos(t)) }
                Tk.STRING -> { next(); Expr.StringLit(t.text, pos(t)) }
                Tk.TEMPLATE -> parseTemplate()
                Tk.IDENT -> {
                    next()
                    when (t.text) {
                        "true" -> Expr.BoolLit(true, pos(t))
                        "false" -> Expr.BoolLit(false, pos(t))
                        "null" -> Expr.NullLit(pos(t))
                        "undefined" -> Expr.UndefinedLit(pos(t))
                        "this" -> Expr.ThisRef(pos(t))
                        "super" -> Expr.Identifier("super", pos(t))
                        "function" -> {
                            var isAsync = false
                            var isGenerator = false
                            val name = if (peek().kind == Tk.IDENT) next().text else ""
                            val params = parseParams()
                            val body = parseBlock()
                            Expr.FunctionExpr(name.ifEmpty { null }, params, body, false, pos(t), isAsync, isGenerator)
                        }
                        "class" -> {
                            // 类表达式
                            val cd = parseClassDecl()
                            Expr.FunctionExpr(cd.name.ifEmpty { null }, emptyList(), Stmt.Block(emptyList(), cd.pos), false, cd.pos)
                        }
                        "async" -> {
                            // async 箭头函数 async x => / async (...) =>
                            if (looksLikeAsyncArrow()) {
                                val params = mutableListOf<String>()
                                if (peek().kind == Tk.IDENT) {
                                    params.add(next().text)
                                } else if (at("(")) {
                                    params.addAll(parseParams())
                                }
                                expect("=>")
                                val body = if (at("{")) parseBlock() else Stmt.Block(listOf(Stmt.Return(parseAssign(), pos(t))), pos(t))
                                Expr.FunctionExpr(null, params, body, true, pos(t), isAsync = true)
                            } else {
                                Expr.Identifier(t.text, pos(t))
                            }
                        }
                        else -> Expr.Identifier(t.text, pos(t))
                    }
                }
                Tk.OP -> {
                    when (t.text) {
                        "(" -> {
                            next() // 消费 (
                            if (looksLikeArrowParams()) {
                                // 箭头函数形参 (a, b) => {...}
                                val params = mutableListOf<String>()
                                while (!at(")")) {
                                    when {
                                        peek().kind == Tk.IDENT -> params.add(next().text)
                                        at("...") -> { next(); if (peek().kind == Tk.IDENT) params.add(next().text) }
                                        at("{") || at("[") -> params.addAll(parseBindingPattern())
                                        peek().kind != Tk.EOF -> next()
                                    }
                                    if (eat("=")) parseAssign()
                                    if (!eat(",")) break
                                }
                                expect(")")
                                if (at("=>")) {
                                    next()
                                    val body = if (at("{")) parseBlock() else Stmt.Block(listOf(Stmt.Return(parseAssign(), pos(t))), pos(t))
                                    Expr.FunctionExpr(null, params, body, true, pos(t))
                                } else Expr.UndefinedLit(pos(t))
                            } else {
                                // 括号表达式或序列
                                val inner = mutableListOf(parseAssign())
                                while (eat(",")) inner.add(parseAssign())
                                expect(")")
                                if (inner.size == 1) inner[0] else Expr.Sequence(inner, pos(t))
                            }
                        }
                        "[" -> {
                            next()
                            val elems = mutableListOf<Expr>()
                            while (!at("]")) {
                                if (peek().kind == Tk.EOF) break
                                if (at("...")) {
                                    val sp = next()
                                    elems.add(Expr.Spread(parseAssign(), pos(sp)))
                                } else {
                                    // 数组洞 [,]：空位
                                    if (at(",")) { elems.add(Expr.UndefinedLit(pos(peek()))) } else {
                                        try { elems.add(parseAssign()) } catch (e: Exception) { recoverToCommaOrParen() }
                                    }
                                }
                                if (!eat(",")) break
                            }
                            expect("]")
                            Expr.ArrayLit(elems, pos(t))
                        }
                        "{" -> {
                            next()
                            val props = mutableListOf<ObjectProperty>()
                            while (!at("}")) {
                                if (peek().kind == Tk.EOF) break
                                when {
                                    at("...") -> {
                                        val sp = next()
                                        val v = parseAssign()
                                        props.add(ObjectProperty("", v, pos(sp), isSpread = true))
                                    }
                                    at("[") -> {
                                        // 计算属性键 [expr]: value
                                        next()
                                        val keyExpr = parseAssign()
                                        expect("]")
                                        var value: Expr? = null
                                        var isMethod = false
                                        if (at("(")) {
                                            isMethod = true
                                            val params = parseParams()
                                            val body = parseBlock()
                                            value = Expr.FunctionExpr(null, params, body, false, sp0(t))
                                        } else if (eat(":")) {
                                            value = parseAssign()
                                        }
                                        props.add(ObjectProperty("[computed]", value, pos(t), computed = keyExpr, isMethod = isMethod))
                                    }
                                    at("get") && peek2().text != ":" && peek2().text != "(" && peek2().text != "," && peek2().text != "}" -> {
                                        val g = next()
                                        val key = if (peek().kind == Tk.IDENT || peek().kind == Tk.STRING || peek().kind == Tk.NUMBER) next().text else "?"
                                        val params = parseParams()
                                        val body = parseBlock()
                                        props.add(ObjectProperty(key, Expr.FunctionExpr(null, params, body, false, pos(g)), pos(g), isGet = true))
                                    }
                                    at("set") && peek2().text != ":" && peek2().text != "(" && peek2().text != "," && peek2().text != "}" -> {
                                        val s = next()
                                        val key = if (peek().kind == Tk.IDENT || peek().kind == Tk.STRING || peek().kind == Tk.NUMBER) next().text else "?"
                                        val params = parseParams()
                                        val body = parseBlock()
                                        props.add(ObjectProperty(key, Expr.FunctionExpr(null, params, body, false, pos(s)), pos(s), isSet = true))
                                    }
                                    at("async") && peek2().text != ":" && peek2().text != "(" && peek2().text != "," && peek2().text != "}" -> {
                                        val a = next()
                                        val key = if (peek().kind == Tk.IDENT || peek().kind == Tk.STRING || peek().kind == Tk.NUMBER) next().text else "?"
                                        val params = parseParams()
                                        val body = parseBlock()
                                        props.add(ObjectProperty(key, Expr.FunctionExpr(null, params, body, false, pos(a), isAsync = true), pos(a), isMethod = true, isAsync = true))
                                    }
                                    else -> {
                                        val keyTok = peek()
                                        val key = when (keyTok.kind) {
                                            Tk.IDENT, Tk.STRING, Tk.NUMBER -> next().text
                                            else -> "?"
                                        }
                                        var value: Expr? = null
                                        var isMethod = false
                                        var isAsync = false
                                        var isGenerator = false
                                        when {
                                            at("(") -> {
                                                isMethod = true
                                                val params = parseParams()
                                                val body = parseBlock()
                                                value = Expr.FunctionExpr(null, params, body, false, pos(keyTok))
                                            }
                                            at("*") -> {
                                                next()
                                                isMethod = true
                                                isGenerator = true
                                                val params = parseParams()
                                                val body = parseBlock()
                                                value = Expr.FunctionExpr(null, params, body, false, pos(keyTok), isGenerator = true)
                                            }
                                            eat(":") -> value = parseAssign()
                                            else -> {
                                                // 简写 {a}
                                                value = Expr.Identifier(key, pos(keyTok))
                                            }
                                        }
                                        props.add(ObjectProperty(key, value, pos(keyTok), isMethod = isMethod, isAsync = isAsync, isGenerator = isGenerator))
                                    }
                                }
                                if (!eat(",")) break
                            }
                            expect("}")
                            Expr.ObjectLit(props, pos(t))
                        }
                        else -> { next(); Expr.Identifier("?", pos(t)) }
                    }
                }
                Tk.EOF -> Expr.UndefinedLit(pos(t))
            }
        }

        private fun sp0(t: Tok): SourcePos = pos(t)
    }

    // ---------------- 入口 ----------------

    fun parse(source: String): Program {
        val toks = tokenize(source)
        return Parser(toks, source).parseProgram()
    }

    /** 解析单个表达式片段（供 ${} 插值/工具复用） */
    fun parseExpressionFragment(source: String): Expr {
        val toks = tokenize(source)
        return Parser(toks, source).parseAssign()
    }
}
