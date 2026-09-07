package com.webreverse.mcp.javascript.analysis

/**
 * JS Frontend 质量分析 。
 * 对源码做轻量词法平衡/现代语法画像，帮助 Agent 判断“AST 结果可不可以信”。
 *
 * 新增 import/export 解析覆盖率量化指标：
 * 借助 [JsAstParser] 对 ES Module 声明做结构化解析，统计「可被精确解组成
 * 具体说明符/子句」的占比，供 Agent 判断模块级逆向的可信度。
 */
class JsParserQualityAnalyzer {

    /* * import/export 解析覆盖率量化指标（ 新增） */
    data class ImportExportMetrics(
        val importStatements: Int = 0,    // 源码中静态 import 语句数（不含动态 import()）
        val exportStatements: Int = 0,    // 源码中 export 语句数
        val structuredImports: Int = 0,   // 结构化成具体说明符的 import 数
        val structuredExports: Int = 0,   // 结构化成具体子句的 export 数
        val importCoverage: Double = 0.0, // structuredImports / importStatements
        val exportCoverage: Double = 0.0, // structuredExports / exportStatements
    )

    data class Report(
        val balanced: Boolean,
        val dialects: Set<String>,
        val suspiciousConstructs: List<String>,
        val lexicalErrors: List<String>,
        val score: Double,
        val importExport: ImportExportMetrics = ImportExportMetrics(),
    )

    fun analyze(source: String): Report {
        var brace = 0; var bracket = 0; var paren = 0
        var line = 1
        var quote: Char? = null
        var template = false
        var escaped = false
        val errors = mutableListOf<String>()
        var i = 0
        while (i < source.length) {
            val c = source[i]
            if (c == '\n') line++
            if (escaped) { escaped = false; i++; continue }
            if (quote != null || template) {
                if (c == '\\') { escaped = true; i++; continue }
                if (quote != null && c == quote) quote = null
                else if (template && c == '`') template = false
                i++; continue
            }
            if (c == '\'' || c == '"') quote = c
            else if (c == '`') template = true
            else when (c) {
                '{' -> brace++; '}' -> { brace--; if (brace < 0) { errors += "line $line: unmatched }"; brace = 0 } }
                '[' -> bracket++; ']' -> { bracket--; if (bracket < 0) { errors += "line $line: unmatched ]"; bracket = 0 } }
                '(' -> paren++; ')' -> { paren--; if (paren < 0) { errors += "line $line: unmatched )"; paren = 0 } }
            }
            i++
        }
        if (quote != null) errors += "unterminated string literal"
        if (template) errors += "unterminated template literal"
        if (brace != 0) errors += "unbalanced braces=$brace"
        if (bracket != 0) errors += "unbalanced brackets=$bracket"
        if (paren != 0) errors += "unbalanced parens=$paren"

        val dialects = linkedSetOf<String>()
        val suspicious = mutableListOf<String>()
        fun hit(tag: String, re: Regex) { if (re.containsMatchIn(source)) { dialects += tag; suspicious += tag } }
        hit("ES modules", Regex("\\b(?:import|export)\\b"))
        hit("classes", Regex("\\bclass\\s+[A-Za-z_$]"))
        hit("optional chaining", Regex("\\?\\."))
        hit("nullish", Regex("\\?\\?"))
        hit("destructuring", Regex("(?:const|let|var)\\s*[\\{\\[]"))
        hit("private fields", Regex("#[A-Za-z_$]"))
        hit("BigInt", Regex("\\b\\d+n\\b|BigInt\\s*\\("))
        hit("top-level await", Regex("(?m)^\\s*await\\b"))
        hit("dynamic import", Regex("\\bimport\\s*\\("))
        hit("TypeScript", Regex("\\b(?:interface|type|enum|namespace|implements)\\b"))
        hit("JSX", Regex("<([A-Z][A-Za-z0-9_]*)[^>]*>"))
        hit("decorators", Regex("(?m)^\\s*@[A-Za-z_$]"))
        hit("WebAssembly", Regex("\\bWebAssembly\\b|\\.wasm\\b"))
        hit("dynamic-code", Regex("\\b(?:eval|Function)\\s*\\("))
        val score = (9.9 - errors.size * 0.9 - dialects.count { it in setOf("TypeScript", "JSX", "decorators") } * 0.2).coerceIn(0.0, 9.9)
        return Report(errors.isEmpty(), dialects, suspicious.distinct(), errors, score, computeImportExportCoverage(source))
    }

    /** 统计 import/export 的结构化解析覆盖率 */
    private fun computeImportExportCoverage(source: String): ImportExportMetrics {
        if (source.isBlank()) return ImportExportMetrics()
        // 静态 import 语句（排除动态 import( 与 import.meta）
        val staticImport = Regex("""\bimport(?:\s+|\{|\*|['"])""").findAll(source).count()
        // import() 动态导入数量
        val dynamicImport = Regex("""\bimport\s*\(|\bimport\.meta""").findAll(source).count()
        val importTotal = (staticImport - dynamicImport).coerceAtLeast(0)
        val exportTotal = Regex("""\bexport\b""").findAll(source).count()

        var importDecl = 0
        var exportDecl = 0
        var structuredImports = 0
        var structuredExports = 0
        try {
            val program = JsAstParser().parse(source)
            fun walk(st: Stmt?) {
                if (st == null) return
                when (st) {
                    is Stmt.ImportDecl -> {
                        importDecl++
                        if (st.specifiers.isNotEmpty()) structuredImports++
                    }
                    is Stmt.ExportDecl -> {
                        exportDecl++
                        val c = st.clause
                        if (c != null && (c.named.isNotEmpty() || c.from != null || c.isDefault || c.isAll || c.namespaceAlias != null)) {
                            structuredExports++
                        } else if (st.decl != null) {
                            structuredExports++ // export function/class/const 也视为结构化
                        }
                    }
                    is Stmt.Block -> st.stmts.forEach { walk(it) }
                    is Stmt.If -> { walk(st.thenBody); walk(st.elseBody) }
                    else -> {}
                }
            }
            program.body.forEach { tl ->
                when (tl) {
                    is TopLevel.Statement -> walk(tl.stmt)
                    else -> {}
                }
            }
        } catch (_: Exception) {
            // 解析失败时仅给出 0 覆盖率，不影响整体画像
        }
        val raster = importTotal.coerceAtLeast(importDecl)
        val rastExp = exportTotal.coerceAtLeast(exportDecl)
        return ImportExportMetrics(
            importStatements = raster,
            exportStatements = rastExp,
            structuredImports = structuredImports,
            structuredExports = structuredExports,
            importCoverage = if (raster > 0) structuredImports.toDouble() / raster else 0.0,
            exportCoverage = if (rastExp > 0) structuredExports.toDouble() / rastExp else 0.0,
        )
    }
}
