package com.webreverse.mcp.javascript.analysis

/**
 * 基于 AST 的浏览器环境依赖扫描器（替代纯 token/正则匹配）。
 *
 * 用 [JsAstParser] 把源码解析成 [Program]，再遍历 AST 提取：
 *  - 成员访问链（含 `.prop` 与 `['str']` 两种形式），如 `window.crypto.subtle`
 *  - 根标识符（可能引用浏览器全局），如 `window` / `crypto` / `navigator`
 *  - 调用根标识符（用于网络能力推断），如 `fetch` / `XMLHttpRequest`
 *
 * 相比正则扫描的优势：
 *  - 不会命中注释/字符串里的伪代码（消除误报）
 *  - 支持 `window['crypto']['subtle']` 括号访问（消除漏报）
 *  - 支持连续链式访问 `window.crypto.subtle.digest`（还原完整路径）
 *
 * 解析失败时返回空结果，由调用方回退到正则通道（见 BrowserEnvironmentSynthesizer.infer）。
 */
class BrowserEnvAstScanner {

    /** 扫描结果（去重、保序） */
    data class ScanResult(
        /** 是否成功完成 AST 解析（false 表示解析整体失败，调用方应回退正则通道） */
        val parsed: Boolean = false,
        val memberPaths: List<String> = emptyList(),
        val rootIdentifiers: Set<String> = emptySet(),
        val callRoots: Set<String> = emptySet(),
    )

    fun scan(source: String): ScanResult {
        val paths = LinkedHashSet<String>()
        val roots = LinkedHashSet<String>()
        val calls = LinkedHashSet<String>()
        val program = try {
            JsAstParser().parse(source)
        } catch (e: Exception) {
            return ScanResult(parsed = false)
        }
        program.body.forEach { tl ->
            when (tl) {
                is TopLevel.Function -> walkStmt(tl.fn.body, paths, roots, calls)
                is TopLevel.Statement -> walkStmt(tl.stmt, paths, roots, calls)
            }
        }
        return ScanResult(parsed = true, memberPaths = paths.toList(), rootIdentifiers = roots, callRoots = calls)
    }

    private fun walkStmt(s: Stmt, paths: MutableSet<String>, roots: MutableSet<String>, calls: MutableSet<String>) {
        when (s) {
            is Stmt.VarDecl -> s.init?.let { walkExpr(it, paths, roots, calls) }
            is Stmt.ExprStmt -> walkExpr(s.expr, paths, roots, calls)
            is Stmt.If -> {
                walkExpr(s.cond, paths, roots, calls)
                walkStmt(s.thenBody, paths, roots, calls)
                s.elseBody?.let { walkStmt(it, paths, roots, calls) }
            }
            is Stmt.For -> {
                s.init?.let { walkStmt(it, paths, roots, calls) }
                s.cond?.let { walkExpr(it, paths, roots, calls) }
                s.update?.let { walkExpr(it, paths, roots, calls) }
                walkStmt(s.body, paths, roots, calls)
            }
            is Stmt.ForEach -> {
                walkExpr(s.left, paths, roots, calls)
                walkExpr(s.obj, paths, roots, calls)
                walkStmt(s.body, paths, roots, calls)
            }
            is Stmt.While -> {
                walkExpr(s.cond, paths, roots, calls)
                walkStmt(s.body, paths, roots, calls)
            }
            is Stmt.DoWhile -> {
                walkStmt(s.body, paths, roots, calls)
                walkExpr(s.cond, paths, roots, calls)
            }
            is Stmt.Switch -> {
                walkExpr(s.disc, paths, roots, calls)
                s.cases.forEach { c ->
                    c.test?.let { walkExpr(it, paths, roots, calls) }
                    c.body.forEach { walkStmt(it, paths, roots, calls) }
                }
            }
            is Stmt.Return -> s.arg?.let { walkExpr(it, paths, roots, calls) }
            is Stmt.Block -> s.stmts.forEach { walkStmt(it, paths, roots, calls) }
            is Stmt.Throw -> s.arg?.let { walkExpr(it, paths, roots, calls) }
            else -> { /* Break/Continue/EmptyStmt 无表达式 */ }
        }
    }

    private fun walkExpr(e: Expr, paths: MutableSet<String>, roots: MutableSet<String>, calls: MutableSet<String>) {
        when (e) {
            is Expr.Member -> {
                // 还原整条链（如 window.crypto.subtle），并继续下钻 obj 收集子链
                memberChain(e)?.let { if (it.length >= 2) paths.add(it) }
                walkExpr(e.obj, paths, roots, calls)
                e.computed?.let { walkExpr(it, paths, roots, calls) }
            }
            is Expr.Call -> {
                rootOf(e.callee)?.let {
                    roots.add(it)
                    calls.add(it)
                }
                walkExpr(e.callee, paths, roots, calls)
                e.args.forEach { walkExpr(it, paths, roots, calls) }
            }
            is Expr.Identifier -> roots.add(e.name)
            is Expr.Assign -> {
                walkExpr(e.target, paths, roots, calls)
                walkExpr(e.value, paths, roots, calls)
            }
            is Expr.Binary -> {
                walkExpr(e.left, paths, roots, calls)
                walkExpr(e.right, paths, roots, calls)
            }
            is Expr.Conditional -> {
                walkExpr(e.test, paths, roots, calls)
                walkExpr(e.consequent, paths, roots, calls)
                walkExpr(e.alternate, paths, roots, calls)
            }
            is Expr.Unary -> walkExpr(e.operand, paths, roots, calls)
            is Expr.ArrayLit -> e.elements.forEach { walkExpr(it, paths, roots, calls) }
            is Expr.ObjectLit -> e.props.forEach { p -> p.value?.let { walkExpr(it, paths, roots, calls) } }
            is Expr.FunctionExpr -> walkStmt(e.body, paths, roots, calls)
            else -> { /* 字面量/this 无成员链 */ }
        }
    }

    /**
     * 把成员访问表达式还原成 dotted path。
     * 支持 `.prop`、`['str']`、`[ident]`；遇到动态下标（非字面量）返回 null。
     */
    private fun memberChain(e: Expr): String? {
        val parts = mutableListOf<String>()
        var cur: Expr = e
        while (true) {
            when (cur) {
                is Expr.Member -> {
                    val seg = when {
                        cur.property != null -> cur.property
                        cur.computed is Expr.StringLit -> cur.computed.value
                        cur.computed is Expr.Identifier -> cur.computed.name
                        else -> return null
                    }
                    parts.add(0, seg)
                    cur = cur.obj
                }
                is Expr.Identifier -> {
                    parts.add(0, cur.name)
                    break
                }
                is Expr.ThisRef -> {
                    parts.add(0, "this")
                    break
                }
                else -> return null
            }
        }
        return parts.joinToString(".")
    }

    /** 调用/成员表达式的根标识符（如 fetch(...) → fetch；window.crypto(...) → window） */
    private fun rootOf(e: Expr): String? = when (e) {
        is Expr.Identifier -> e.name
        is Expr.Member -> rootOf(e.obj)
        else -> null
    }
}
