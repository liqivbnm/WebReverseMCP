package com.webreverse.mcp.javascript.analysis

/**
 * JS 数据流分析器（DFG）：def-use + 敏感数据污点传播。
 *
 * 基于 [JsAstParser] 产出的 [Program]，对每个函数/顶层作用域：
 * 1. **def-use**：变量定义点（参数/声明/赋值）与使用点，以及 def->use 数据对；
 * 2. **敏感数据污点（Taint）**：从 cookie/localStorage/token/password/atob 等源出发，
 *    沿赋值/运算/调用参数传播，到 eval/fetch/XMLHttpRequest.send/innerHTML 等汇点，
 *    输出 source -> sink 的污点路径——逆向中最关心的数据流线索。
 *
 * 纯 Kotlin、零依赖；为可读性采用顺序近似的过程内前向传播（忽略分支精度）。
 */
class JsDfgAnalyzer {

    // ---------------- 数据模型 ----------------

    data class DefSite(val variable: String, val line: Int, val kind: String) // kind: param/decl/assign
    data class UseSite(val variable: String, val line: Int, val context: String)
    data class DefUsePair(val variable: String, val defLine: Int, val useLine: Int)

    data class FunctionDfg(
        val name: String,
        val params: List<String>,
        val defs: List<DefSite>,
        val uses: List<UseSite>,
        val defUsePairs: List<DefUsePair>,
        val taintFlows: List<TaintFlow>,
    )

    data class TaintFlow(val source: String, val line: Int, val sink: String, val path: List<String>)

    data class JsDfgReport(
        val functions: List<FunctionDfg>,
        val taintFlows: List<TaintFlow>,
        val sensitiveCount: Int,
    )

    // ---------------- 敏感源/汇 规则 ----------------

    private val sourceNameRe = Regex("(?i)(token|passw|secret|authoriz|cookie|api[_-]?key|credential|sessionid|pwd|privkey|access[_-]?key)")

    private fun isSensitiveName(name: String): Boolean = sourceNameRe.containsMatchIn(name)

    private fun taintSource(e: Expr): String? = when (e) {
        is Expr.Identifier -> if (isSensitiveName(e.name)) e.name else null
        is Expr.Member -> {
            val r = AstRender.expr(e).lowercase()
            if (r.contains("cookie") || r.contains("localstorage") || r.contains("sessionstorage") ||
                r.contains("token") || r.contains("password") || r.contains("authorization")
            ) r.take(48) else null
        }
        is Expr.Call -> {
            val r = AstRender.expr(e).lowercase()
            if (r.contains("atob(") || r.contains("fromcharcode") || r.contains("storag") && r.contains("getitem")) r.take(48) else null
        }
        else -> null
    }

    private fun sinkOf(call: Expr.Call): String? {
        val c = AstRender.expr(call.callee).lowercase()
        return when {
            c == "eval" || c.endsWith("eval") -> "eval"
            c == "function" || c.endsWith(".function") -> "new Function"
            c.contains("fetch") || c.endsWith("request") -> "fetch"
            c.contains("xmlhttprequest") -> "XHR"
            c.contains(".send") || c.endsWith("send") -> "XHR.send"
            c.contains("postmessage") -> "postMessage"
            c.contains("document.write") -> "document.write"
            c.contains("setrequestheader") -> "setRequestHeader"
            c.contains("location") || c.contains("location.href") -> "location.href"
            c.contains("innerhtml") || c.contains("outerhtml") -> "innerHTML"
            c.contains("indexeddb") -> "IndexedDB"
            c.contains("websocket") -> "WebSocket"
            else -> null
        }
    }

    private fun memberSinkName(m: Expr): String? {
        val r = AstRender.expr(m).lowercase()
        return when {
            r.contains("innerhtml") || r.contains("outerhtml") -> "innerHTML/outerHTML 写入"
            r.contains("document.cookie") -> "document.cookie 写入"
            r.contains("location.href") || r.contains("location") -> "location 跳转"
            r.contains("img.src") || r.contains("script.src") -> "外部资源 src"
            else -> null
        }
    }

    // ---------------- 作用域分析 ----------------

    private class Scope(val name: String, val params: List<String>) {
        val defs = mutableListOf<DefSite>()
        val uses = mutableListOf<UseSite>()
        val taintFlows = mutableListOf<TaintFlow>()
        /** 变量 -> 最近污点源标记 */
        val tainted = mutableMapOf<String, String>()
    }

    // ---------------- 入口 ----------------

    fun analyze(source: String): JsDfgReport {
        val program = JsAstParser().parse(source)
        val scopes = mutableListOf<Scope>()
        val global = Scope("(global)", emptyList())
        // 嵌套函数注册回调
        fun register(fn: JsFunction) {
            if (fn.body.stmts.isEmpty()) return
            val s = Scope(fn.name.ifBlank { "(anonymous)@${fn.pos.offset}" }, fn.params)
            s.defs.addAll(fn.params.mapIndexed { i, p -> DefSite(p, fn.pos.line + i, "param") })
            walkStmts(fn.body.stmts, s, ::register)
            scopes.add(s)
        }

        for (tl in program.body) {
            when (tl) {
                is TopLevel.Function -> register(tl.fn)
                is TopLevel.Statement -> walkStmts(listOf(tl.stmt), global, ::register)
            }
        }
        scopes.add(global)

        val funcs = scopes.map { toFunctionDfg(it) }
        val allFlows = funcs.flatMap { it.taintFlows }
        return JsDfgReport(funcs, allFlows.sortedBy { it.line }, allFlows.size)
    }

    private fun walkStmts(stmts: List<Stmt>, scope: Scope, register: (JsFunction) -> Unit) {
        stmts.forEach { walkStmt(it, scope, register) }
    }

    private fun walkStmt(s: Stmt, scope: Scope, register: (JsFunction) -> Unit) {
        when (s) {
            is Stmt.VarDecl -> {
                val init = s.init
                if (init is Expr.FunctionExpr) {
                    register(JsFunction(s.name, init.params, init.body, init.pos, init.isArrow))
                    scope.defs.add(DefSite(s.name, s.pos.line, "decl"))
                } else {
                    if (init != null) {
                        walkExpr(init, scope, register)
                        val src = sourceOfValue(init, scope)
                        if (src != null) scope.tainted[s.name] = src else scope.tainted.remove(s.name)
                    }
                    scope.defs.add(DefSite(s.name, s.pos.line, "decl"))
                }
            }
            is Stmt.ExprStmt -> walkExpr(s.expr, scope, register)
            is Stmt.Return -> s.arg?.let { walkExpr(it, scope, register) }
            is Stmt.Throw -> s.arg?.let { walkExpr(it, scope, register) }
            is Stmt.Block -> walkStmts(s.stmts, scope, register)
            is Stmt.If -> {
                walkExpr(s.cond, scope, register)
                walkStmt(s.thenBody, scope, register)
                s.elseBody?.let { walkStmt(it, scope, register) }
            }
            is Stmt.For -> {
                s.init?.let { walkStmt(it, scope, register) }
                s.cond?.let { walkExpr(it, scope, register) }
                s.update?.let { walkExpr(it, scope, register) }
                walkStmt(s.body, scope, register)
            }
            is Stmt.ForEach -> { walkExpr(s.obj, scope, register); walkStmt(s.body, scope, register) }
            is Stmt.While -> { walkExpr(s.cond, scope, register); walkStmt(s.body, scope, register) }
            is Stmt.DoWhile -> { walkStmt(s.body, scope, register); walkExpr(s.cond, scope, register) }
            is Stmt.Switch -> {
                walkExpr(s.disc, scope, register)
                s.cases.forEach { c -> walkStmts(c.body, scope, register) }
            }
            else -> {}
        }
    }

    private fun walkExpr(e: Expr, scope: Scope, register: (JsFunction) -> Unit) {
        when (e) {
            is Expr.Identifier -> scope.uses.add(UseSite(e.name, e.pos.line, e.name))
            is Expr.FunctionExpr -> register(JsFunction(e.name ?: "(anonymous)@${e.pos.offset}", e.params, e.body, e.pos, e.isArrow))
            is Expr.Assign -> walkAssign(e, scope, register)
            is Expr.Call -> walkCall(e, scope, register)
            is Expr.Member -> { walkExpr(e.obj, scope, register); e.computed?.let { walkExpr(it, scope, register) } }
            is Expr.Binary -> { walkExpr(e.left, scope, register); walkExpr(e.right, scope, register) }
            is Expr.Conditional -> { walkExpr(e.test, scope, register); walkExpr(e.consequent, scope, register); walkExpr(e.alternate, scope, register) }
            is Expr.Unary -> walkExpr(e.operand, scope, register)
            is Expr.ArrayLit -> e.elements.forEach { walkExpr(it, scope, register) }
            is Expr.ObjectLit -> e.props.forEach { it.value?.let { v -> walkExpr(v, scope, register) } }
            else -> {}
        }
    }

    private fun walkAssign(e: Expr.Assign, scope: Scope, register: (JsFunction) -> Unit) {
        walkExpr(e.value, scope, register)
        when (val t = e.target) {
            is Expr.Identifier -> {
                val src = sourceOfValue(e.value, scope)
                if (src != null) scope.tainted[t.name] = src else scope.tainted.remove(t.name)
                scope.defs.add(DefSite(t.name, t.pos.line, "assign"))
            }
            is Expr.Member -> {
                // 读取并记录对象基
                if (t.obj is Expr.Identifier) scope.uses.add(UseSite(t.obj.name, t.pos.line, AstRender.expr(e)))
                t.computed?.let { walkExpr(it, scope, register) }
                val sink = memberSinkName(t)
                val src = sourceOfValue(e.value, scope)
                if (sink != null) {
                    if (src != null) {
                        scope.taintFlows.add(TaintFlow(src, t.pos.line, sink, listOf(src, "→ $sink")))
                    } else if (t.obj is Expr.Identifier && scope.tainted.containsKey(t.obj.name)) {
                        scope.taintFlows.add(TaintFlow(scope.tainted[t.obj.name] ?: "?", t.pos.line, sink, listOf("${t.obj.name}(${scope.tainted[t.obj.name] ?: "?"})", "→ $sink")))
                    }
                }
                // 成员写入将污点传播到基对象标识符
                if (src != null && t.obj is Expr.Identifier) scope.tainted[t.obj.name] = src
            }
            else -> {}
        }
    }

    private fun walkCall(e: Expr.Call, scope: Scope, register: (JsFunction) -> Unit) {
        // 读取 callee 基
        when (val c = e.callee) {
            is Expr.Identifier -> scope.uses.add(UseSite(c.name, c.pos.line, AstRender.expr(e)))
            is Expr.Member -> {
                if (c.obj is Expr.Identifier) scope.uses.add(UseSite(c.obj.name, c.pos.line, AstRender.expr(e)))
                c.computed?.let { walkExpr(it, scope, register) }
            }
            else -> walkExpr(c, scope, register)
        }
        // 参数（收集实参……嵌套函数注册）
        val argSources = mutableMapOf<Int, String>()
        e.args.forEachIndexed { i, a ->
            if (a is Expr.FunctionExpr) register(JsFunction(a.name ?: "(anonymous)@${a.pos.offset}", a.params, a.body, a.pos, a.isArrow))
            else {
                walkExpr(a, scope, register)
                val src = sourceOfValue(a, scope)
                if (src != null) argSources[i] = src
            }
        }
        // 污点 -> 汇点
        val sink = sinkOf(e)
        if (sink != null && argSources.isNotEmpty()) {
            val src = argSources.values.first()
            val detail = e.args.firstOrNull { sourceOfValue(it, scope) != null }?.let { AstRender.expr(it).take(40) } ?: ""
            scope.taintFlows.add(TaintFlow(src, e.pos.line, sink, listOf(src, if (detail.isNotBlank()) detail else "…", "→ $sink")))
        }
        // 同步处理 callee 作为一个 FunctionExpr 时（如 (function(){...})()）
        if (e.callee is Expr.FunctionExpr) walkExpr(e.callee, scope, register)
    }

    /** 计算一个表达式的污点源（若命中敏感源或 tainted 变量读） */
    private fun sourceOfValue(e: Expr, scope: Scope): String? {
        val direct = taintSource(e)
        if (direct != null) return direct
        val src = when (e) {
            is Expr.Identifier -> scope.tainted[e.name]
            is Expr.Member -> e.computed?.let { sourceOfValue(it, scope) } ?: scope.tainted[baseName(e.obj)]
            is Expr.Binary -> sourceOfValue(e.left, scope) ?: sourceOfValue(e.right, scope)
            is Expr.Unary -> sourceOfValue(e.operand, scope)
            is Expr.Conditional -> sourceOfValue(e.test, scope) ?: sourceOfValue(e.consequent, scope) ?: sourceOfValue(e.alternate, scope)
            is Expr.ArrayLit -> e.elements.firstNotNullOfOrNull { sourceOfValue(it, scope) }
            is Expr.ObjectLit -> e.props.firstNotNullOfOrNull { it.value?.let { v -> sourceOfValue(v, scope) } }
            is Expr.Call -> {
                // 含敏感参数/主体的调用视为污点
                e.args.firstNotNullOfOrNull { sourceOfValue(it, scope) } ?: e.args.firstNotNullOfOrNull { taintSource(it) }
            }
            else -> null
        }
        if (src != null) seedTaint(e, scope, src)
        return src
    }

    private fun baseName(e: Expr): String? = if (e is Expr.Identifier) e.name else null

    /** 将污点标记广播到表达式内的标识符叶子（保证后续引用可见） */
    private fun seedTaint(e: Expr, scope: Scope, src: String) {
        when (e) {
            is Expr.Identifier -> scope.tainted[e.name] = src
            is Expr.Member -> seedTaint(e.obj, scope, src)
            is Expr.Binary -> { seedTaint(e.left, scope, src); seedTaint(e.right, scope, src) }
            is Expr.Unary -> seedTaint(e.operand, scope, src)
            is Expr.Conditional -> { seedTaint(e.test, scope, src); seedTaint(e.consequent, scope, src); seedTaint(e.alternate, scope, src) }
            is Expr.ArrayLit -> e.elements.forEach { seedTaint(it, scope, src) }
            is Expr.ObjectLit -> e.props.forEach { it.value?.let { v -> seedTaint(v, scope, src) } }
            else -> {}
        }
    }

    // ---------------- 输出构造 ----------------

    private fun toFunctionDfg(scope: Scope): FunctionDfg {
        val uses = scope.uses.sortedBy { it.line }
        val defs = scope.defs.sortedBy { it.line }
        val pairs = mutableListOf<DefUsePair>()
        for (u in uses) {
            val candidate = defs.lastOrNull { it.variable == u.variable && it.line <= u.line }
            if (candidate != null && defs.count { it.variable == u.variable && it.line > candidate.line && it.line <= u.line } == 0) {
                pairs.add(DefUsePair(u.variable, candidate.line, u.line))
            }
        }
        return FunctionDfg(
            name = scope.name,
            params = scope.params,
            defs = defs,
            uses = uses,
            defUsePairs = pairs.take(300),
            taintFlows = scope.taintFlows,
        )
    }
}