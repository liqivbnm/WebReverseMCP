package com.webreverse.mcp.javascript.analysis

/**
 * JS 控制流图（CFG）构建器。
 *
 * 基于 [JsAstParser] 产出的 [Program]，为每个函数构建基本块 + 有向边，
 * 并计算支配关系、循环（回边）与圈复杂度——逆向定位混淆控制流扁平化、
 * switch 分发器的核心信号。
 *
 * 数据模型：
 * - [CfgBlock]：基本块（块号 + 语句标签列表 + 起始行）
 * - [CfgEdge]：有向边（from -> to + 类型 true/false/jump/loop/break/case/join）
 * - [FunctionCfg]：单函数视图（块/边/支配/回边/圈复杂度）
 * - [JsCfgReport]：全量报告
 */
class JsCfgBuilder {

    // ---------------- 数据模型 ----------------

    data class CfgBlock(val id: Int, val stmts: List<String>, val line: Int)

    data class CfgEdge(val from: Int, val to: Int, val kind: String)

    data class FunctionCfg(
        val name: String,
        val params: List<String>,
        val entry: Int,
        val blocks: List<CfgBlock>,
        val edges: List<CfgEdge>,
        val nodes: Int,
        val edgeCount: Int,
        /** node -> 支配者集合（含自身） */
        val dominators: Map<Int, List<Int>>,
        /** node -> 直接支配者（entry 为 null） */
        val immediateDominators: Map<Int, Int?>,
        /** 回边（循环）：from -> to，其中 to 支配 from */
        val backEdges: List<CfgEdge>,
        val cyclomatic: Int,
    )

    data class JsCfgReport(
        val functions: List<FunctionCfg>,
        val totalFunctions: Int,
        val totalBlocks: Int,
        val totalEdges: Int,
    )

    // ---------------- 入口 ----------------

    fun build(source: String): JsCfgReport {
        val program = JsAstParser().parse(source)
        val funcs = collectFunctions(program)
        val cfgs = funcs.map { buildFunction(it) }
        return JsCfgReport(
            functions = cfgs,
            totalFunctions = cfgs.size,
            totalBlocks = cfgs.sumOf { it.nodes },
            totalEdges = cfgs.sumOf { it.edgeCount },
        )
    }

    // ---------------- 函数收集 ----------------

    /** 收集所有命名/具名函数（顶层声明 + 嵌套声明 + 绑定到 var/const 的匿名函数） */
    private fun collectFunctions(program: Program): List<JsFunction> {
        val out = mutableListOf<JsFunction>()
        val seen = mutableSetOf<String>()
        for (tl in program.body) {
            when (tl) {
                is TopLevel.Function -> push(out, seen, tl.fn)
                is TopLevel.Statement -> collectStmt(tl.stmt, out, seen)
            }
        }
        return out
    }

    private fun push(out: MutableList<JsFunction>, seen: MutableSet<String>, fn: JsFunction) {
        if (fn.body.stmts.isEmpty()) return
        val key = fn.name.ifBlank { "@${fn.pos.offset}" }
        if (seen.add(key)) out.add(fn)
        nestBody(fn.body, out, seen)
    }

    private fun nestBody(body: Stmt.Block, out: MutableList<JsFunction>, seen: MutableSet<String>) {
        body.stmts.forEach { collectStmt(it, out, seen) }
    }

    private fun collectStmt(s: Stmt, out: MutableList<JsFunction>, seen: MutableSet<String>) {
        when (s) {
            is Stmt.VarDecl -> {
                val init = s.init
                if (init is Expr.FunctionExpr) {
                    push(out, seen, JsFunction(s.name, init.params, init.body, init.pos, init.isArrow))
                } else if (init != null) {
                    collectExpr(init, out, seen)
                }
            }
            is Stmt.ExprStmt -> collectExpr(s.expr, out, seen)
            is Stmt.Block -> s.stmts.forEach { collectStmt(it, out, seen) }
            is Stmt.If -> {
                collectExpr(s.cond, out, seen)
                collectStmt(s.thenBody, out, seen)
                s.elseBody?.let { collectStmt(it, out, seen) }
            }
            is Stmt.For -> {
                s.init?.let { collectStmt(it, out, seen) }
                s.cond?.let { collectExpr(it, out, seen) }
                s.update?.let { collectExpr(it, out, seen) }
                collectStmt(s.body, out, seen)
            }
            is Stmt.ForEach -> {
                collectExpr(s.obj, out, seen)
                collectStmt(s.body, out, seen)
            }
            is Stmt.While -> { collectExpr(s.cond, out, seen); collectStmt(s.body, out, seen) }
            is Stmt.DoWhile -> { collectStmt(s.body, out, seen); collectExpr(s.cond, out, seen) }
            is Stmt.Switch -> {
                collectExpr(s.disc, out, seen)
                s.cases.forEach { c -> c.body.forEach { collectStmt(it, out, seen) } }
            }
            is Stmt.Return -> s.arg?.let { collectExpr(it, out, seen) }
            is Stmt.Throw -> s.arg?.let { collectExpr(it, out, seen) }
            else -> {}
        }
    }

    private fun collectExpr(e: Expr, out: MutableList<JsFunction>, seen: MutableSet<String>) {
        when (e) {
            is Expr.FunctionExpr -> if (e.name.isNullOrBlank()) {
                nestBody(e.body, out, seen)
            } else {
                push(out, seen, JsFunction(e.name, e.params, e.body, e.pos, e.isArrow))
            }
            is Expr.Call -> { collectExpr(e.callee, out, seen); e.args.forEach { collectExpr(it, out, seen) } }
            is Expr.Member -> collectExpr(e.obj, out, seen)
            is Expr.Assign -> collectExpr(e.value, out, seen)
            is Expr.Binary -> { collectExpr(e.left, out, seen); collectExpr(e.right, out, seen) }
            is Expr.Conditional -> { collectExpr(e.test, out, seen); collectExpr(e.consequent, out, seen); collectExpr(e.alternate, out, seen) }
            is Expr.Unary -> collectExpr(e.operand, out, seen)
            is Expr.ArrayLit -> e.elements.forEach { collectExpr(it, out, seen) }
            is Expr.ObjectLit -> e.props.forEach { it.value?.let { v -> collectExpr(v, out, seen) } }
            else -> {}
        }
    }

    // ---------------- 单函数 CFG ----------------

    private fun buildFunction(fn: JsFunction): FunctionCfg {
        val cfg = Graph(fn.name)
        cfg.leaves = mutableSetOf(cfg.newBlock(fn.pos.line))
        cfg.entry = cfg.leaves.first()
        fn.body.stmts.forEach { cfg.buildStmt(it) }

        val blocks = cfg.finalizeBlocks()
        val entry = cfg.entry
        val dom = computeDominators(entry, cfg.edges, blocks)
        val idom = computeIdom(dom)
        val back = cfg.edges.filter { dom[it.from]?.contains(it.to) == true }
        val nodes = blocks.size
        val e = cfg.edges.size
        val cyclomatic = (e - nodes + 2).coerceAtLeast(1)

        return FunctionCfg(
            name = fn.name.ifBlank { "(anonymous)" },
            params = fn.params,
            entry = entry,
            blocks = blocks,
            edges = cfg.edges,
            nodes = nodes,
            edgeCount = e,
            dominators = dom,
            immediateDominators = idom,
            backEdges = back,
            cyclomatic = cyclomatic,
        )
    }

    // ---------------- 支配计算 ----------------

    private fun computeDominators(entry: Int, edges: List<CfgEdge>, blocks: List<CfgBlock>): Map<Int, List<Int>> {
        val nodes = blocks.map { it.id }.toSet()
        val preds = edges.groupBy { it.to }.mapValues { (_, v) -> v.map { it.from }.toSet() }
        val all = nodes.toSet()
        val dom = mutableMapOf<Int, Set<Int>>()
        for (n in nodes) dom[n] = if (n == entry) setOf(entry) else all
        var changed = true
        var guard = 0
        while (changed && guard++ < 1000) {
            changed = false
            for (n in nodes) {
                if (n == entry) continue
                val ps = preds[n] ?: emptySet()
                if (ps.isEmpty()) continue
                val intersect = ps.map { dom[it] ?: all }.reduce { a, b -> a.intersect(b) }
                val newSet = intersect + n
                if (newSet != dom[n]) { dom[n] = newSet; changed = true }
            }
        }
        return dom.mapValues { it.value.sorted().toList() }
    }

    private fun computeIdom(dom: Map<Int, List<Int>>): Map<Int, Int?> {
        val out = mutableMapOf<Int, Int?>()
        for ((n, doms) in dom) {
            val strict = doms.filter { it != n }
            if (strict.isEmpty()) { out[n] = null; continue }
            // idom = strict 支配者中支配其余所有 strict 支配者的那一个
            val candidate = strict.firstOrNull { d -> strict.all { s -> (dom[s] ?: emptyList()).contains(d) } }
            out[n] = candidate
        }
        return out
    }

    // ---------------- CFG 构建内部类 ----------------

    private class Graph(private val name: String) {
        val blocks = mutableListOf<CfgBlock>()
        val edges = mutableListOf<CfgEdge>()
        val preds = mutableMapOf<Int, MutableList<Int>>()
        private val stmts = mutableMapOf<Int, MutableList<String>>()
        private val line = mutableMapOf<Int, Int>()
        private var nextId = 0
        var leaves = mutableSetOf<Int>()
        var entry = 0
        private val breakStack = mutableListOf<Int>()
        private val continueStack = mutableListOf<Int>()

        fun newBlock(l: Int): Int {
            val id = nextId++
            stmts[id] = mutableListOf()
            line[id] = l
            return id
        }

        fun connect(f: Int, t: Int, kind: String) {
            edges.add(CfgEdge(f, t, kind))
            preds.getOrPut(t) { mutableListOf() }.add(f)
        }

        private fun appendText(text: String, l: Int) {
            if (leaves.isEmpty()) return // 不可达语句
            for (leaf in leaves) {
                stmts[leaf]!!.add(text)
                if (line[leaf] == 0 || l < line[leaf]!!) line[leaf] = l
            }
        }

        fun finalizeBlocks(): List<CfgBlock> {
            blocks.clear()
            for (id in 0 until nextId) {
                val list = stmts[id]!!
                blocks.add(CfgBlock(id, if (list.isEmpty()) listOf("—") else list.toList(), line[id] ?: 0))
            }
            return blocks
        }

        fun buildStmt(s: Stmt) {
            when (s) {
                is Stmt.VarDecl -> appendText(AstRender.stmt(s), s.pos.line)
                is Stmt.ExprStmt -> appendText(AstRender.stmt(s), s.pos.line)
                is Stmt.Return -> {
                    appendText(AstRender.stmt(s), s.pos.line)
                    leaves = mutableSetOf() // 终端
                }
                is Stmt.Throw -> {
                    appendText(AstRender.stmt(s), s.pos.line)
                    leaves = mutableSetOf()
                }
                is Stmt.EmptyStmt -> appendText(";", s.pos.line)
                is Stmt.Break -> {
                    if (breakStack.isNotEmpty()) {
                        val target = breakStack.last()
                        for (l in leaves) connect(l, target, "break")
                        leaves = mutableSetOf()
                    } else appendText("break", s.pos.line)
                }
                is Stmt.Continue -> {
                    if (continueStack.isNotEmpty()) {
                        val target = continueStack.last()
                        for (l in leaves) connect(l, target, "continue")
                        leaves = mutableSetOf()
                    } else appendText("continue", s.pos.line)
                }
                is Stmt.Block -> s.stmts.forEach { buildStmt(it) }
                is Stmt.If -> buildIf(s)
                is Stmt.While -> buildWhile(s)
                is Stmt.DoWhile -> buildDoWhile(s)
                is Stmt.For -> buildFor(s)
                is Stmt.ForEach -> buildWhile(Stmt.While(s.obj, s.body, s.pos))
                is Stmt.Switch -> buildSwitch(s)
                is Stmt.TryCatch -> {
                    // 近似：try 块顺序构建，catch/finally 顺序接续
                    buildStmt(s.block)
                    s.catchBody?.let { buildStmt(it) }
                    s.finallyBody?.let { buildStmt(it) }
                }
                is Stmt.ClassDecl -> appendText(AstRender.stmt(s), s.pos.line)
                is Stmt.DestructureDecl -> appendText(AstRender.stmt(s), s.pos.line)
                is Stmt.ImportDecl -> appendText("import", s.pos.line)
                is Stmt.ExportDecl -> s.decl?.let { buildStmt(it) }
            }
        }

        private fun mergeInto(ends: Set<Int>, join: Int) {
            for (x in ends) connect(x, join, "join")
        }

        private fun buildIf(s: Stmt.If) {
            val srcLeaves = leaves.toList()
            // 每个源叶分支出 then/else
            val thenLeaves = mutableSetOf<Int>()
            val elseLeaves = mutableSetOf<Int>()
            for (l in srcLeaves) {
                appendTo(l, "if (${AstRender.expr(s.cond)})", s.pos.line)
                val tb = newBlock(s.pos.line); val eb = newBlock(s.pos.line)
                connect(l, tb, "true"); connect(l, eb, "false")
                thenLeaves.add(tb); elseLeaves.add(eb)
            }
            leaves = thenLeaves
            buildStmt(s.thenBody)
            val endThen = leaves
            leaves = elseLeaves
            if (s.elseBody != null) buildStmt(s.elseBody)
            val endElse = leaves
            if (endThen.isEmpty() && endElse.isEmpty()) {
                leaves = mutableSetOf()
            } else if (endThen.isEmpty()) {
                leaves = endElse
            } else if (endElse.isEmpty()) {
                leaves = endThen
            } else {
                val join = newBlock(s.pos.line)
                mergeInto(endThen, join)
                mergeInto(endElse, join)
                leaves = mutableSetOf(join)
            }
        }

        private fun appendTo(block: Int, text: String, l: Int) {
            stmts[block]!!.add(text)
            if (line[block] == 0 || l < line[block]!!) line[block] = l
        }

        private fun buildWhile(s: Stmt.While) {
            val srcLeaves = leaves.toList()
            val header = newBlock(s.pos.line)
            val bodyStart = newBlock(s.pos.line)
            val exit = newBlock(s.pos.line)
            for (l in srcLeaves) connect(l, header, "jump")
            appendTo(header, "while (${AstRender.expr(s.cond)})", s.pos.line)
            connect(header, bodyStart, "true")
            connect(header, exit, "false")
            breakStack.add(exit); continueStack.add(header)
            leaves = mutableSetOf(bodyStart)
            buildStmt(s.body)
            val bodyEnd = leaves
            for (x in bodyEnd) connect(x, header, "loop")
            breakStack.removeLast(); continueStack.removeLast()
            leaves = mutableSetOf(exit)
        }

        private fun buildDoWhile(s: Stmt.DoWhile) {
            val srcLeaves = leaves.toList()
            val bodyStart = newBlock(s.pos.line)
            val header = newBlock(s.pos.line)
            val exit = newBlock(s.pos.line)
            for (l in srcLeaves) connect(l, bodyStart, "jump")
            breakStack.add(exit); continueStack.add(header)
            leaves = mutableSetOf(bodyStart)
            buildStmt(s.body)
            val bodyEnd = leaves
            for (x in bodyEnd) connect(x, header, "loop")
            appendTo(header, "while (${AstRender.expr(s.cond)})", s.pos.line)
            connect(header, bodyStart, "true")
            connect(header, exit, "false")
            breakStack.removeLast(); continueStack.removeLast()
            leaves = mutableSetOf(exit)
        }

        private fun buildFor(s: Stmt.For) {
            if (s.init != null) buildStmt(s.init)
            val srcLeaves = leaves.toList()
            val header = newBlock(s.pos.line)
            val bodyStart = newBlock(s.pos.line)
            val updateB = newBlock(s.pos.line)
            val exit = newBlock(s.pos.line)
            for (l in srcLeaves) connect(l, header, "jump")
            val condText = s.cond?.let { "for (${AstRender.expr(it)})" } ?: "for (;;)"
            appendTo(header, condText, s.pos.line)
            if (s.cond != null) { connect(header, bodyStart, "true"); connect(header, exit, "false") }
            else { connect(header, bodyStart, "jump") }
            breakStack.add(exit); continueStack.add(updateB)
            leaves = mutableSetOf(bodyStart)
            buildStmt(s.body)
            val bodyEnd = leaves
            for (x in bodyEnd) connect(x, updateB, "loop")
            s.update?.let { appendTo(updateB, AstRender.expr(it), s.pos.line) }
            connect(updateB, header, "jump")
            breakStack.removeLast(); continueStack.removeLast()
            leaves = mutableSetOf(exit)
        }

        private fun buildSwitch(s: Stmt.Switch) {
            val srcLeaves = leaves.toList()
            val exit = newBlock(s.pos.line)
            breakStack.add(exit)
            val caseBlocks = s.cases.map { it to newBlock(s.pos.line) }
            for (l in srcLeaves) {
                appendTo(l, "switch (${AstRender.expr(s.disc)})", s.pos.line)
                for ((_, b) in caseBlocks) connect(l, b, "case")
            }
            // 每个 case 独立分支，各自回到 exit（近似，忽略 fallthrough 细节）
            for ((cs, b) in caseBlocks) {
                leaves = mutableSetOf(b)
                cs.body.forEach { buildStmt(it) }
                val end = leaves
                for (x in end) connect(x, exit, "jump")
            }
            breakStack.removeLast()
            leaves = mutableSetOf(exit)
        }
    }
}