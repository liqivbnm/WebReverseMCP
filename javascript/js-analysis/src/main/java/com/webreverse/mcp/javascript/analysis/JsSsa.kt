package com.webreverse.mcp.javascript.analysis

import java.util.IdentityHashMap
import java.util.ArrayDeque

/**
 * JS SSA（Static Single Assignment）构建器 —— 统一数据流引擎的地基。
 *
 * 把 [JsAstParser] 产出的 AST 编译为「指令级 CFG + SSA」中间表示：
 * 1. **函数索引**：收集全部函数（顶层/嵌套/箭头/类方法/对象方法），建立父子作用域关系；
 * 2. **指令级 CFG**：if/for/while/do/switch/try/break/continue 全量展开为基本块 + 有向边；
 * 3. **支配树 + 支配边界**：Cooper-Harvey-Kennedy 迭代算法（RPO + intersect）；
 * 4. **Phi 插入 + 版本重命名**：Cytron 经典算法，每个 def 得到唯一版本号；
 * 5. **调用点抽取**：每个函数内所有 Call/New 表达式（含嵌套），供调用图与污点引擎消费。
 *
 * 相比旧 [JsDfgAnalyzer] 的「顺序近似」，SSA 提供：
 * - 精确 def-use 链（同名变量多版本不混淆）；
 * - 循环携带变量（Phi）显式化；
 * - 分支汇合点的值来源合并（Phi incoming）；
 * - 为 0-CFA 调用图与跨函数污点传播提供可迭代的数据结构。
 *
 * 纯 Kotlin、零第三方依赖。防护：超大函数/超大块数自动跳过并计入 stats。
 */
class JsSsaBuilder {

    companion object {
        /** 单函数语句数超过该值跳过 SSA（防 OOM） */
        const val MAX_STMTS_PER_FUNCTION = 6000

        /** 单函数基本块数上限 */
        const val MAX_BLOCKS_PER_FUNCTION = 4096

        /** 单函数 Phi 数量上限 */
        const val MAX_PHIS_PER_FUNCTION = 2048
    }

    // ---------------- SSA 数据模型 ----------------

    /** SSA 变量：函数内唯一（name+version），funcId 保证跨函数不冲突；version=-1 表示自由变量（闭包/全局引用） */
    data class SsaVar(val name: String, val version: Int, val funcId: Int) {
        override fun toString() = if (version < 0) "$name^free" else "$name.$version"
        val key: String get() = "$funcId::$name.$version"
        val isFree: Boolean get() = version < 0
    }

    /** 指令操作类别 */
    enum class SsaOp { COPY, CALL, NEW, FUNC, RET, THROW, PHI, STORE, LOAD, TEST, OTHER }

    /** SSA 指令：构建期填 [useNames]/[defName]，重命名后填 [uses]/[result] */
    class SsaInstr(
        val op: SsaOp,
        var result: SsaVar?,
        var uses: List<SsaVar>,
        val useNames: List<String>,
        val defName: String?,
        val label: String,
        val line: Int,
        val blockId: Int,
        val funcId: Int,
        val expr: Expr? = null,
    ) {
        var idx: Int = -1
        var litFuncId: Int = -1
        var pendingLit: Expr.FunctionExpr? = null

        /** 是否定义了变量 */
        val hasDef: Boolean get() = defName != null
    }

    /** Phi：join 点的值合并 */
    class SsaPhi(
        val varName: String,
        val blockId: Int,
        val funcId: Int,
        val line: Int,
    ) {
        var result: SsaVar? = null
        /** pred blockId -> 到达该 pred 末尾时的版本（-1 = 自由变量） */
        val incoming = LinkedHashMap<Int, Int>()
        val incomingVars = LinkedHashMap<Int, SsaVar>()
    }

    /** 终结符 */
    sealed class Term {
        data class Jump(val to: Int) : Term()
        data class Branch(val condNames: List<String>, val thenTo: Int, val elseTo: Int) : Term() {
            var condVars: List<SsaVar> = emptyList()
        }

        data class Ret(val valName: String?) : Term() {
            var retVal: SsaVar? = null
        }

        data class Throw(val valName: String?) : Term() {
            var throwVal: SsaVar? = null
        }
    }

    /** 基本块 */
    class SsaBlock(
        val id: Int,
        val funcId: Int,
    ) {
        val instrs = mutableListOf<SsaInstr>()
        val phis = mutableListOf<SsaPhi>()
        var term: Term? = null
        /** 额外后继（try→catch 异常近似边） */
        val extraSuccs = mutableListOf<Int>()
        var preds: List<Int> = emptyList()

        val succs: List<Int>
            get() {
                val t = term
                val base = when (t) {
                    is Term.Jump -> listOf(t.to)
                    is Term.Branch -> listOf(t.thenTo, t.elseTo)
                    else -> emptyList()
                }
                return if (extraSuccs.isEmpty()) base else base + extraSuccs
            }
    }

    /** 函数元信息 */
    class SsaFunctionInfo(
        val id: Int,
        val name: String,
        val params: List<String>,
        val body: List<Stmt>,
        val isArrow: Boolean,
        val isAsync: Boolean,
        val isGenerator: Boolean,
        val parent: Int,
        val pos: SourcePos,
        /** 成员归属（如 "Obj.method"），供成员调用解析 */
        val qualName: String = "",
    )

    /** 单函数 SSA 结果 */
    class SsaFunctionResult(
        val info: SsaFunctionInfo,
        val blocks: List<SsaBlock>,
        val entry: Int,
        val byId: Map<Int, SsaBlock>,
        /** SsaVar -> 定义指令 */
        val defInstr: Map<SsaVar, SsaInstr>,
        /** SsaVar -> 函数 id（当 def 为函数字面量） */
        val funcLitDefs: Map<SsaVar, Int>,
        val instrCount: Int,
        val phiCount: Int,
        /** 自由变量名集合（闭包引用，供跨函数污点/调用图解析） */
        val freeVars: Set<String>,
        val callSites: List<CallSiteInfo>,
        /** return 值的候选 SSA 变量（供污点 return 传播） */
        val retVars: List<SsaVar>,
    )

    /** 调用点信息（从指令表达式抽取） */
    data class CallSiteInfo(
        val funcId: Int,
        val blockId: Int,
        val instrIdx: Int,
        val line: Int,
        val calleeExpr: Expr,
        val calleeDisplay: String,
        val args: List<Expr>,
        val isNew: Boolean,
        var calleeVar: SsaVar? = null,
    )

    /** 整个程序的 SSA 结果 */
    class SsaProgram(
        val source: String,
        val functions: List<SsaFunctionResult>,
        val global: SsaFunctionResult,
        val funcById: Map<Int, SsaFunctionResult>,
        /** 全程序属性名 -> 函数 id 列表（成员调用解析索引） */
        val propIndex: Map<String, List<Int>>,
        /** 顶层唯一函数名 -> ids（函数声明） */
        val topLevelFuncs: Map<String, List<Int>>,
        /** 函数名 -> ids（含嵌套命名函数） */
        val funcsByName: Map<String, List<Int>>,
        val stats: SsaStats,
    )

    data class SsaStats(
        val totalFunctions: Int,
        val totalBlocks: Int,
        val totalInstrs: Int,
        val totalPhis: Int,
        val skippedOversized: Int,
        val parseMs: Long,
        val ssaMs: Long,
    )

    // ---------------- 入口 ----------------

    fun build(source: String): SsaProgram {
        val t0 = System.currentTimeMillis()
        val program = JsAstParser().parse(source)
        val tParse = System.currentTimeMillis() - t0

        val t1 = System.currentTimeMillis()
        val infos = mutableListOf<SsaFunctionInfo>()
        val litMap = IdentityHashMap<Expr.FunctionExpr, Int>()
        val propIndex = mutableMapOf<String, MutableList<Int>>()

        var nextId = 0
        fun register(
            name: String,
            params: List<String>,
            body: List<Stmt>,
            isArrow: Boolean,
            isAsync: Boolean,
            isGenerator: Boolean,
            parent: Int,
            pos: SourcePos,
            qualName: String,
        ): Int {
            val id = nextId++
            infos.add(SsaFunctionInfo(id, name, params, body, isArrow, isAsync, isGenerator, parent, pos, qualName))
            return id
        }

        // ---- pass1: 全局伪函数 + 嵌套函数收集（DFS，父先于子） ----
        val globalBody = mutableListOf<Stmt>()
        for (tl in program.body) {
            when (tl) {
                is TopLevel.Function -> globalBody.add(
                    Stmt.VarDecl(
                        "function", tl.fn.name,
                        Expr.FunctionExpr(tl.fn.name, tl.fn.params, tl.fn.body, tl.fn.isArrow, tl.fn.pos, tl.fn.isAsync, tl.fn.isGenerator),
                        tl.fn.pos,
                    )
                )
                is TopLevel.Statement -> globalBody.add(tl.stmt)
            }
        }
        register("(global)", emptyList(), globalBody, false, false, false, -1, SourcePos.NONE, "")

        // Kotlin 局部函数禁止前向引用，而 walkExpr ↔ walkStmt 相互递归 => 晚绑定函数引用
        var walkStmtFn: ((Stmt, Int, String) -> Unit)? = null

        fun walkExpr(e: Expr, parent: Int, prefix: String, hint: String) {
            when (e) {
                is Expr.FunctionExpr -> {
                    val nm = e.name ?: hint.ifBlank { null } ?: "(anon)@${e.pos.offset}"
                    val id = register(nm, e.params, e.body.stmts, e.isArrow, e.isAsync, e.isGenerator, parent, e.pos, prefix)
                    litMap[e] = id
                    val q2 = if (prefix.isBlank()) nm else "$prefix.$nm"
                    e.body.stmts.forEach { walkStmtFn?.invoke(it, id, q2) }
                }
                is Expr.Member -> {
                    walkExpr(e.obj, parent, prefix, "")
                    e.computed?.let { walkExpr(it, parent, prefix, "") }
                }
                is Expr.Call -> {
                    walkExpr(e.callee, parent, prefix, "")
                    e.args.forEach { walkExpr(it, parent, prefix, "") }
                }
                is Expr.New -> {
                    walkExpr(e.callee, parent, prefix, "")
                    e.args.forEach { walkExpr(it, parent, prefix, "") }
                }
                is Expr.Assign -> {
                    walkExpr(e.value, parent, prefix, "")
                    walkExpr(e.target, parent, prefix, "")
                }
                is Expr.Binary -> {
                    walkExpr(e.left, parent, prefix, "")
                    walkExpr(e.right, parent, prefix, "")
                }
                is Expr.Unary -> walkExpr(e.operand, parent, prefix, "")
                is Expr.Conditional -> {
                    walkExpr(e.test, parent, prefix, "")
                    walkExpr(e.consequent, parent, prefix, "")
                    walkExpr(e.alternate, parent, prefix, "")
                }
                is Expr.ArrayLit -> e.elements.forEach { walkExpr(it, parent, prefix, "") }
                is Expr.ObjectLit -> e.props.forEach { p ->
                    val v = p.value
                    if (v != null && (v is Expr.FunctionExpr || p.isMethod || p.isGet || p.isSet)) {
                        val fe = v as? Expr.FunctionExpr
                        val nm = fe?.name ?: p.key
                        val q = if (prefix.isBlank()) p.key else "$prefix.${p.key}"
                        val id = register(nm, fe?.params ?: emptyList(), fe?.body?.stmts ?: emptyList(), false, p.isAsync, p.isGenerator, parent, v.pos, q)
                        if (fe != null) litMap[fe] = id
                        propIndex.getOrPut(p.key) { mutableListOf() }.add(id)
                    } else {
                        v?.let { walkExpr(it, parent, prefix, "") }
                        p.computed?.let { walkExpr(it, parent, prefix, "") }
                    }
                }
                is Expr.TemplateLit -> e.exprs.forEach { walkExpr(it, parent, prefix, "") }
                is Expr.TaggedTemplate -> {
                    walkExpr(e.tag, parent, prefix, "")
                    e.template.exprs.forEach { walkExpr(it, parent, prefix, "") }
                }
                is Expr.Sequence -> e.exprs.forEach { walkExpr(it, parent, prefix, "") }
                is Expr.AwaitExpr -> walkExpr(e.arg, parent, prefix, "")
                is Expr.YieldExpr -> e.arg?.let { walkExpr(it, parent, prefix, "") }
                is Expr.Spread -> walkExpr(e.arg, parent, prefix, "")
                else -> {}
            }
        }

        fun walkStmt(s: Stmt, parent: Int, prefix: String) {
            when (s) {
                is Stmt.VarDecl -> s.init?.let { walkExpr(it, parent, prefix, s.name) }
                is Stmt.DestructureDecl -> {
                    s.init?.let { walkExpr(it, parent, prefix, "") }
                    s.bindings.forEach { bd -> bd.defaultValue?.let { walkExpr(it, parent, prefix, "") } }
                }
                is Stmt.ExprStmt -> walkExpr(s.expr, parent, prefix, "")
                is Stmt.Return -> s.arg?.let { walkExpr(it, parent, prefix, "") }
                is Stmt.Throw -> s.arg?.let { walkExpr(it, parent, prefix, "") }
                is Stmt.Block -> s.stmts.forEach { walkStmt(it, parent, prefix) }
                is Stmt.If -> {
                    walkExpr(s.cond, parent, prefix, "")
                    walkStmt(s.thenBody, parent, prefix)
                    s.elseBody?.let { walkStmt(it, parent, prefix) }
                }
                is Stmt.For -> {
                    s.init?.let { walkStmt(it, parent, prefix) }
                    s.cond?.let { walkExpr(it, parent, prefix, "") }
                    s.update?.let { walkExpr(it, parent, prefix, "") }
                    walkStmt(s.body, parent, prefix)
                }
                is Stmt.ForEach -> {
                    walkExpr(s.obj, parent, prefix, "")
                    walkStmt(s.body, parent, prefix)
                }
                is Stmt.While -> {
                    walkExpr(s.cond, parent, prefix, "")
                    walkStmt(s.body, parent, prefix)
                }
                is Stmt.DoWhile -> {
                    walkStmt(s.body, parent, prefix)
                    walkExpr(s.cond, parent, prefix, "")
                }
                is Stmt.Switch -> {
                    walkExpr(s.disc, parent, prefix, "")
                    s.cases.forEach { c ->
                        c.test?.let { walkExpr(it, parent, prefix, "") }
                        c.body.forEach { walkStmt(it, parent, prefix) }
                    }
                }
                is Stmt.TryCatch -> {
                    s.block.stmts.forEach { walkStmt(it, parent, prefix) }
                    s.catchBody?.let { cb -> cb.stmts.forEach { walkStmt(it, parent, prefix) } }
                    s.finallyBody?.let { fb -> fb.stmts.forEach { walkStmt(it, parent, prefix) } }
                }
                is Stmt.ClassDecl -> s.members.forEach { m ->
                    if (m.kind != "field") {
                        val q = if (prefix.isBlank()) "${s.name}.${m.name}" else "$prefix.${m.name}"
                        val mid = register(m.name, m.params, m.body.stmts, false, m.isAsync, m.isGenerator, parent, m.pos, q)
                        propIndex.getOrPut(m.name) { mutableListOf() }.add(mid)
                    }
                    m.init?.let { walkExpr(it, parent, prefix, "") }
                }
                is Stmt.ExportDecl -> s.decl?.let { walkStmt(it, parent, prefix) }
                else -> {}
            }
        }

        walkStmtFn = { s, p, q -> walkStmt(s, p, q) }
        globalBody.forEach { walkStmt(it, 0, "") }

        // ---- pass2: x.prop = function(){} 属性索引补充 ----
        indexMemberAssignFunctions(program, litMap, propIndex)

        // ---- pass3: 逐函数构建 SSA ----
        val results = mutableListOf<SsaFunctionResult>()
        var skipped = 0
        for (info in infos) {
            if (info.body.size > MAX_STMTS_PER_FUNCTION) {
                skipped++
                continue
            }
            try {
                results.add(buildFunction(info, litMap))
            } catch (_: Throwable) {
                skipped++
            }
        }

        val tSsa = System.currentTimeMillis() - t1
        val funcById = results.associateBy { it.info.id }
        val topLevelFuncs = mutableMapOf<String, MutableList<Int>>()
        val funcsByName = mutableMapOf<String, MutableList<Int>>()
        for (r in results) {
            val nm = r.info.name
            if (!nm.startsWith("(")) {
                funcsByName.getOrPut(nm) { mutableListOf() }.add(r.info.id)
                if (r.info.parent == 0) {
                    topLevelFuncs.getOrPut(nm) { mutableListOf() }.add(r.info.id)
                }
            }
        }

        return SsaProgram(
            source = source,
            functions = results,
            global = funcById[0] ?: results.first(),
            funcById = funcById,
            propIndex = propIndex,
            topLevelFuncs = topLevelFuncs,
            funcsByName = funcsByName,
            stats = SsaStats(
                totalFunctions = results.size,
                totalBlocks = results.sumOf { it.blocks.size },
                totalInstrs = results.sumOf { it.instrCount },
                totalPhis = results.sumOf { it.phiCount },
                skippedOversized = skipped,
                parseMs = tParse,
                ssaMs = tSsa,
            )
        )
    }

    /** x.prop = function(){} 的属性名 → 函数 id 索引 */
    private fun indexMemberAssignFunctions(
        program: Program,
        litMap: IdentityHashMap<Expr.FunctionExpr, Int>,
        propIndex: MutableMap<String, MutableList<Int>>,
    ) {
        fun walkExpr(e: Expr) {
            when (e) {
                is Expr.Assign -> {
                    val t = e.target
                    if (t is Expr.Member && !t.property.isNullOrBlank()) {
                        val v = e.value
                        if (v is Expr.FunctionExpr) {
                            litMap[v]?.let { id -> propIndex.getOrPut(t.property!!) { mutableListOf() }.add(id) }
                        }
                    }
                    walkExpr(e.value)
                    walkExpr(e.target)
                }
                is Expr.Member -> {
                    walkExpr(e.obj)
                    e.computed?.let { walkExpr(it) }
                }
                is Expr.Call -> {
                    walkExpr(e.callee)
                    e.args.forEach { walkExpr(it) }
                }
                is Expr.New -> {
                    walkExpr(e.callee)
                    e.args.forEach { walkExpr(it) }
                }
                is Expr.Binary -> {
                    walkExpr(e.left)
                    walkExpr(e.right)
                }
                is Expr.Unary -> walkExpr(e.operand)
                is Expr.Conditional -> {
                    walkExpr(e.test)
                    walkExpr(e.consequent)
                    walkExpr(e.alternate)
                }
                is Expr.ArrayLit -> e.elements.forEach { walkExpr(it) }
                is Expr.ObjectLit -> e.props.forEach { p -> p.value?.let { walkExpr(it) } }
                is Expr.Sequence -> e.exprs.forEach { walkExpr(it) }
                else -> {}
            }
        }
        fun walkStmt(s: Stmt) {
            when (s) {
                is Stmt.VarDecl -> s.init?.let { walkExpr(it) }
                is Stmt.DestructureDecl -> s.init?.let { walkExpr(it) }
                is Stmt.ExprStmt -> walkExpr(s.expr)
                is Stmt.Return -> s.arg?.let { walkExpr(it) }
                is Stmt.Throw -> s.arg?.let { walkExpr(it) }
                is Stmt.Block -> s.stmts.forEach { walkStmt(it) }
                is Stmt.If -> {
                    walkExpr(s.cond)
                    walkStmt(s.thenBody)
                    s.elseBody?.let { walkStmt(it) }
                }
                is Stmt.For -> {
                    s.init?.let { walkStmt(it) }
                    s.cond?.let { walkExpr(it) }
                    s.update?.let { walkExpr(it) }
                    walkStmt(s.body)
                }
                is Stmt.ForEach -> {
                    walkExpr(s.obj)
                    walkStmt(s.body)
                }
                is Stmt.While -> {
                    walkExpr(s.cond)
                    walkStmt(s.body)
                }
                is Stmt.DoWhile -> {
                    walkStmt(s.body)
                    walkExpr(s.cond)
                }
                is Stmt.Switch -> {
                    walkExpr(s.disc)
                    s.cases.forEach { c -> c.body.forEach { walkStmt(it) } }
                }
                is Stmt.TryCatch -> {
                    s.block.stmts.forEach { walkStmt(it) }
                    s.catchBody?.stmts?.forEach { walkStmt(it) }
                    s.finallyBody?.stmts?.forEach { walkStmt(it) }
                }
                is Stmt.ClassDecl -> s.members.forEach { m -> m.init?.let { walkExpr(it) } }
                is Stmt.ExportDecl -> s.decl?.let { walkStmt(it) }
                else -> {}
            }
        }
        for (tl in program.body) {
            when (tl) {
                is TopLevel.Function -> walkStmt(tl.fn.body)
                is TopLevel.Statement -> walkStmt(tl.stmt)
            }
        }
    }

    // ---------------- 单函数 SSA 构建 ----------------

    private fun buildFunction(
        info: SsaFunctionInfo,
        litMap: IdentityHashMap<Expr.FunctionExpr, Int>,
    ): SsaFunctionResult {
        val b = FnBuilder(info)
        for (p in info.params) {
            b.emit(SsaInstr(SsaOp.LOAD, null, emptyList(), emptyList(), p, "param $p", info.pos.line, b.cur.id, info.id))
        }
        b.stmts(info.body)
        b.finish()

        val allBlocks = b.blocks
        val reachable = computeReachable(allBlocks, b.entry)
        val liveBlocks = allBlocks.filter { reachable[it.id] }
        renumberAndLink(liveBlocks)

        val dom = computeDominators(liveBlocks, b.entry)
        val df = computeDominanceFrontiers(liveBlocks, dom.idoms)
        val phiCount = insertPhis(liveBlocks, df, info.id)
        rename(liveBlocks, dom.domChildren, b.entry, info.id)

        // 函数字面量解析
        for (blk in liveBlocks) {
            for (ins in blk.instrs) {
                val lit = ins.pendingLit
                if (lit != null) ins.litFuncId = litMap[lit] ?: -1
            }
        }

        val byId = liveBlocks.associateBy { it.id }
        val defInstr = HashMap<SsaVar, SsaInstr>()
        val funcLitDefs = HashMap<SsaVar, Int>()
        val callSites = mutableListOf<CallSiteInfo>()
        val freeVars = mutableSetOf<String>()
        val retVars = mutableListOf<SsaVar>()
        var idx = 0
        for (blk in liveBlocks) {
            for (phi in blk.phis) {
                phi.result?.let { rv ->
                    defInstr[rv] = SsaInstr(SsaOp.PHI, rv, emptyList(), emptyList(), phi.varName, "φ ${phi.varName}", phi.line, blk.id, info.id)
                    if (rv.isFree) freeVars.add(rv.name)
                }
                phi.incomingVars.clear()
                for ((pred, ver) in phi.incoming) {
                    val v = SsaVar(phi.varName, ver, info.id)
                    phi.incomingVars[pred] = v
                    if (v.isFree) freeVars.add(v.name)
                }
            }
            for (ins in blk.instrs) {
                ins.idx = idx++
                ins.result?.let { rv ->
                    defInstr[rv] = ins
                    if (rv.isFree) freeVars.add(rv.name)
                }
                if (ins.litFuncId >= 0) ins.result?.let { funcLitDefs[it] = ins.litFuncId }
                ins.uses.filter { it.isFree }.forEach { freeVars.add(it.name) }
                extractCallSites(ins, info.id, callSites)
            }
            when (val t = blk.term) {
                is Term.Branch -> t.condVars.filter { it.isFree }.forEach { freeVars.add(it.name) }
                is Term.Ret -> t.retVal?.let { rv ->
                    retVars.add(rv)
                    if (rv.isFree) freeVars.add(rv.name)
                }
                else -> {}
            }
        }
        for (cs in callSites) {
            val callee = cs.calleeExpr
            if (callee is Expr.Identifier) {
                val ins = byId[cs.blockId]?.instrs?.firstOrNull { it.idx == cs.instrIdx }
                cs.calleeVar = ins?.uses?.lastOrNull { it.name == callee.name }
            }
        }

        return SsaFunctionResult(
            info = info,
            blocks = liveBlocks,
            entry = b.entry,
            byId = byId,
            defInstr = defInstr,
            funcLitDefs = funcLitDefs,
            instrCount = idx,
            phiCount = phiCount,
            freeVars = freeVars,
            callSites = callSites,
            retVars = retVars,
        )
    }

    /** 语句级 CFG 构建器 */
    private inner class FnBuilder(val info: SsaFunctionInfo) {
        val blocks = mutableListOf<SsaBlock>()
        var cur: SsaBlock
        val entry: Int
        private var nextId = 0
        private val loopStack = ArrayDeque<Pair<Int, Int?>>()

        init {
            val blk = newBlock()
            cur = blk
            entry = blk.id
        }

        fun newBlock(): SsaBlock {
            if (blocks.size > MAX_BLOCKS_PER_FUNCTION) throw IllegalStateException("too many blocks")
            val blk = SsaBlock(nextId++, info.id)
            blocks.add(blk)
            return blk
        }

        fun emit(instr: SsaInstr) {
            if (instr.pendingLit != null) {
                // FUNC 指令：op 强制 FUNC
            }
            cur.instrs.add(instr)
        }

        fun finish() {
            if (cur.term == null) cur.term = Term.Ret(null)
        }

        fun stmts(list: List<Stmt>) = list.forEach { stmt(it) }

        fun stmt(s: Stmt) {
            when (s) {
                is Stmt.VarDecl -> {
                    val init = s.init
                    if (init is Expr.FunctionExpr) {
                        emit(
                            SsaInstr(SsaOp.FUNC, null, emptyList(), emptyList(), s.name, "fn ${s.name} = function", s.pos.line, cur.id, info.id, expr = init)
                                .also { it.pendingLit = init }
                        )
                    } else if (init != null) {
                        val uses = collectUseNames(init)
                        val op = if (containsCall(init)) SsaOp.CALL else SsaOp.COPY
                        emit(SsaInstr(op, null, emptyList(), uses, s.name, "${s.kind} ${s.name} = ${AstRender.expr(init).take(80)}", s.pos.line, cur.id, info.id, expr = init))
                    } else {
                        emit(SsaInstr(SsaOp.OTHER, null, emptyList(), emptyList(), s.name, "${s.kind} ${s.name}", s.pos.line, cur.id, info.id))
                    }
                }
                is Stmt.DestructureDecl -> s.init?.let { e ->
                    val uses = collectUseNames(e)
                    for (bnd in s.bindings) {
                        emit(SsaInstr(SsaOp.COPY, null, emptyList(), uses, bnd.name, "destructure ${bnd.name}", s.pos.line, cur.id, info.id, expr = e))
                    }
                }
                is Stmt.ExprStmt -> exprStmt(s)
                is Stmt.Block -> stmts(s.stmts)
                is Stmt.If -> ifStmt(s)
                is Stmt.For -> forStmt(s)
                is Stmt.ForEach -> forEachStmt(s)
                is Stmt.While -> whileStmt(s)
                is Stmt.DoWhile -> doWhileStmt(s)
                is Stmt.Switch -> switchStmt(s)
                is Stmt.TryCatch -> tryStmt(s)
                is Stmt.Return -> {
                    val names = s.arg?.let { collectUseNames(it) } ?: emptyList()
                    emit(SsaInstr(SsaOp.RET, null, emptyList(), names, null, "return ${s.arg?.let { AstRender.expr(it).take(70) } ?: ""}", s.pos.line, cur.id, info.id, expr = s.arg))
                    cur.term = Term.Ret(primaryVarName(s.arg))
                    cur = newBlock()
                }
                is Stmt.Throw -> {
                    val names = s.arg?.let { collectUseNames(it) } ?: emptyList()
                    emit(SsaInstr(SsaOp.THROW, null, emptyList(), names, null, "throw ${s.arg?.let { AstRender.expr(it).take(60) } ?: ""}", s.pos.line, cur.id, info.id, expr = s.arg))
                    cur.term = Term.Throw(primaryVarName(s.arg))
                    cur = newBlock()
                }
                is Stmt.Break -> {
                    loopStack.lastOrNull()?.first?.let { cur.term = Term.Jump(it) }
                    cur = newBlock()
                }
                is Stmt.Continue -> {
                    loopStack.lastOrNull()?.second?.let { cur.term = Term.Jump(it) }
                    cur = newBlock()
                }
                is Stmt.ClassDecl -> emit(SsaInstr(SsaOp.OTHER, null, emptyList(), emptyList(), null, "class ${s.name}", s.pos.line, cur.id, info.id))
                is Stmt.EmptyStmt -> {}
                is Stmt.ImportDecl -> {}
                is Stmt.ExportDecl -> s.decl?.let { stmt(it) }
            }
        }

        private fun exprStmt(s: Stmt.ExprStmt) {
            val e = s.expr
            when (e) {
                is Expr.Assign -> {
                    val uses = collectUseNames(e)
                    when (val t = e.target) {
                        is Expr.Identifier -> emit(
                            SsaInstr(SsaOp.COPY, null, emptyList(), uses, t.name, "${t.name} ${e.op} ${AstRender.expr(e.value).take(70)}", s.pos.line, cur.id, info.id, expr = e)
                        )
                        is Expr.Member -> emit(
                            SsaInstr(SsaOp.STORE, null, emptyList(), uses, primaryVarName(t.obj), "${AstRender.expr(e.target).take(50)} ${e.op} ${AstRender.expr(e.value).take(50)}", s.pos.line, cur.id, info.id, expr = e)
                        )
                        else -> emit(SsaInstr(SsaOp.OTHER, null, emptyList(), uses, null, AstRender.expr(e).take(80), s.pos.line, cur.id, info.id, expr = e))
                    }
                }
                is Expr.Unary -> if (e.op == "++" || e.op == "--") {
                    when (val o = e.operand) {
                        is Expr.Identifier -> emit(SsaInstr(SsaOp.COPY, null, emptyList(), listOf(o.name), o.name, "${o.name}${e.op}", s.pos.line, cur.id, info.id, expr = e))
                        else -> emit(SsaInstr(SsaOp.OTHER, null, emptyList(), collectUseNames(e), null, AstRender.expr(e).take(80), s.pos.line, cur.id, info.id, expr = e))
                    }
                } else {
                    emitExpr(e, s.pos.line)
                }
                else -> emitExpr(e, s.pos.line)
            }
        }

        private fun emitExpr(e: Expr, line: Int) {
            val uses = collectUseNames(e)
            val op = when {
                e is Expr.New -> SsaOp.NEW
                containsCall(e) || e is Expr.AwaitExpr -> SsaOp.CALL
                else -> SsaOp.OTHER
            }
            emit(SsaInstr(op, null, emptyList(), uses, null, AstRender.expr(e).take(90), line, cur.id, info.id, expr = e))
        }

        private fun ifStmt(s: Stmt.If) {
            val condNames = collectUseNames(s.cond)
            emit(SsaInstr(SsaOp.TEST, null, emptyList(), condNames, null, "if (${AstRender.expr(s.cond).take(60)})", s.pos.line, cur.id, info.id, expr = s.cond))
            val thenB = newBlock()
            val elseB = if (s.elseBody != null) newBlock() else null
            val join = newBlock()
            cur.term = Term.Branch(condNames, thenB.id, elseB?.id ?: join.id)
            cur = thenB
            stmt(s.thenBody)
            if (cur.term == null) cur.term = Term.Jump(join.id)
            if (elseB != null) {
                cur = elseB
                stmt(s.elseBody!!)
                if (cur.term == null) cur.term = Term.Jump(join.id)
            }
            cur = join
        }

        private fun whileStmt(s: Stmt.While) {
            val header = newBlock()
            cur.term = Term.Jump(header.id)
            cur = header
            val condNames = collectUseNames(s.cond)
            emit(SsaInstr(SsaOp.TEST, null, emptyList(), condNames, null, "while (${AstRender.expr(s.cond).take(60)})", s.pos.line, cur.id, info.id, expr = s.cond))
            val bodyB = newBlock()
            val exit = newBlock()
            header.term = Term.Branch(condNames, bodyB.id, exit.id)
            loopStack.addLast(exit.id to header.id)
            cur = bodyB
            stmt(s.body)
            if (cur.term == null) cur.term = Term.Jump(header.id)
            loopStack.removeLast()
            cur = exit
        }

        private fun doWhileStmt(s: Stmt.DoWhile) {
            val bodyB = newBlock()
            cur.term = Term.Jump(bodyB.id)
            val exit = newBlock()
            val condB = newBlock()
            loopStack.addLast(exit.id to condB.id)
            cur = bodyB
            stmt(s.body)
            if (cur.term == null) cur.term = Term.Jump(condB.id)
            cur = condB
            val condNames = collectUseNames(s.cond)
            emit(SsaInstr(SsaOp.TEST, null, emptyList(), condNames, null, "do...while (${AstRender.expr(s.cond).take(50)})", s.pos.line, cur.id, info.id, expr = s.cond))
            cur.term = Term.Branch(condNames, bodyB.id, exit.id)
            loopStack.removeLast()
            cur = exit
        }

        private fun forStmt(s: Stmt.For) {
            s.init?.let { stmt(it) }
            val header = newBlock()
            cur.term = Term.Jump(header.id)
            cur = header
            var condNames = emptyList<String>()
            if (s.cond != null) {
                condNames = collectUseNames(s.cond)
                emit(SsaInstr(SsaOp.TEST, null, emptyList(), condNames, null, "for-cond (${AstRender.expr(s.cond).take(50)})", s.pos.line, cur.id, info.id, expr = s.cond))
            }
            val bodyB = newBlock()
            val exit = newBlock()
            val updateB = newBlock()
            header.term = if (s.cond != null) Term.Branch(condNames, bodyB.id, exit.id) else Term.Jump(bodyB.id)
            loopStack.addLast(exit.id to updateB.id)
            cur = bodyB
            stmt(s.body)
            if (cur.term == null) cur.term = Term.Jump(updateB.id)
            cur = updateB
            s.update?.let {
                emit(SsaInstr(SsaOp.OTHER, null, emptyList(), collectUseNames(it), null, "update ${AstRender.expr(it).take(60)}", s.pos.line, cur.id, info.id, expr = it))
            }
            cur.term = Term.Jump(header.id)
            loopStack.removeLast()
            cur = exit
        }

        private fun forEachStmt(s: Stmt.ForEach) {
            val header = newBlock()
            cur.term = Term.Jump(header.id)
            cur = header
            val objNames = collectUseNames(s.obj)
            emit(SsaInstr(SsaOp.TEST, null, emptyList(), objNames, null, "for (${AstRender.expr(s.left)} ${if (s.of) "of" else "in"} ${AstRender.expr(s.obj).take(50)})", s.pos.line, cur.id, info.id, expr = s.obj))
            val bodyB = newBlock()
            val exit = newBlock()
            header.term = Term.Branch(objNames, bodyB.id, exit.id)
            loopStack.addLast(exit.id to header.id)
            cur = bodyB
            val leftName = primaryVarName(s.left)
            if (leftName != null) {
                emit(SsaInstr(SsaOp.COPY, null, emptyList(), objNames, leftName, "iter $leftName", s.pos.line, cur.id, info.id))
            }
            stmt(s.body)
            if (cur.term == null) cur.term = Term.Jump(header.id)
            loopStack.removeLast()
            cur = exit
        }

        private fun switchStmt(s: Stmt.Switch) {
            val discNames = collectUseNames(s.disc)
            emit(SsaInstr(SsaOp.TEST, null, emptyList(), discNames, null, "switch (${AstRender.expr(s.disc).take(50)})", s.pos.line, cur.id, info.id, expr = s.disc))
            val exit = newBlock()
            val bodyBlocks = s.cases.map { newBlock() }
            val defaultIdx = s.cases.indexOfFirst { it.test == null }
            var testFrom = cur
            for ((i, c) in s.cases.withIndex()) {
                if (c.test == null) continue
                val tNames = collectUseNames(c.test)
                emit(SsaInstr(SsaOp.TEST, null, emptyList(), tNames, null, "case ${AstRender.expr(c.test).take(40)}", c.pos.line, testFrom.id, info.id, expr = c.test))
                val nextTest = newBlock()
                testFrom.term = Term.Branch(tNames, bodyBlocks[i].id, nextTest.id)
                testFrom = nextTest
                cur = nextTest
            }
            testFrom.term = Term.Jump(if (defaultIdx >= 0) bodyBlocks[defaultIdx].id else exit.id)
            loopStack.addLast(exit.id to null)
            for ((i, c) in s.cases.withIndex()) {
                cur = bodyBlocks[i]
                stmts(c.body)
                if (cur.term == null && i + 1 < s.cases.size) cur.term = Term.Jump(bodyBlocks[i + 1].id)
            }
            loopStack.removeLast()
            if (cur.term == null) cur.term = Term.Jump(exit.id)
            cur = exit
        }

        private fun tryStmt(s: Stmt.TryCatch) {
            val tryB = newBlock()
            cur.term = Term.Jump(tryB.id)
            cur = tryB
            stmts(s.block.stmts)
            val tryEnd = cur
            val join = newBlock()
            if (cur.term == null) cur.term = Term.Jump(join.id)
            if (s.catchBody != null) {
                val catchB = newBlock()
                tryEnd.extraSuccs.add(catchB.id) // 异常近似边
                cur = catchB
                s.catchParam?.let { p ->
                    emit(SsaInstr(SsaOp.LOAD, null, emptyList(), emptyList(), p, "catch $p", s.pos.line, cur.id, info.id))
                }
                stmts(s.catchBody.stmts)
                if (cur.term == null) cur.term = Term.Jump(join.id)
            }
            cur = join
            s.finallyBody?.let { stmts(it.stmts) }
        }
    }

    // ---------------- SSA 核心算法 ----------------

    private fun computeReachable(blocks: List<SsaBlock>, entry: Int): BooleanArray {
        val maxId = blocks.maxOf { it.id }
        val reach = BooleanArray(maxId + 1)
        val byId = blocks.associateBy { it.id }
        val stack = ArrayDeque<Int>()
        stack.addLast(entry)
        reach[entry] = true
        while (stack.isNotEmpty()) {
            val bid = stack.removeLast()
            byId[bid]?.let { blk ->
                for (succ in blk.succs) {
                    if (succ in 0..maxId && !reach[succ]) {
                        reach[succ] = true
                        stack.addLast(succ)
                    }
                }
            }
        }
        return reach
    }

    private fun renumberAndLink(liveBlocks: List<SsaBlock>) {
        val byId = liveBlocks.associateBy { it.id }
        val preds = HashMap<Int, MutableList<Int>>()
        for (blk in liveBlocks) {
            for (succ in blk.succs) {
                preds.getOrPut(succ) { mutableListOf() }.add(blk.id)
            }
        }
        for (blk in liveBlocks) {
            blk.preds = preds[blk.id] ?: emptyList()
        }
        byId // 抑制未用警告
    }

    private class DomInfo(val idoms: Map<Int, Int>, val domChildren: Map<Int, List<Int>>)

    /** Cooper-Harvey-Kennedy 迭代支配树 */
    private fun computeDominators(blocks: List<SsaBlock>, entry: Int): DomInfo {
        val byId = blocks.associateBy { it.id }
        val ids = blocks.map { it.id }.toSet()

        // RPO：迭代 DFS 后序再反转
        val post = mutableListOf<Int>()
        val visited = mutableSetOf(entry)
        val stack = ArrayDeque<Pair<Int, Iterator<Int>>>()
        stack.addLast(entry to (byId[entry]?.succs?.filter { it in ids } ?: emptyList()).iterator())
        while (stack.isNotEmpty()) {
            val (bid, it) = stack.last()
            if (it.hasNext()) {
                val s = it.next()
                if (s in ids && s !in visited) {
                    visited.add(s)
                    stack.addLast(s to (byId[s]?.succs?.filter { x -> x in ids } ?: emptyList()).iterator())
                }
            } else {
                post.add(bid)
                stack.removeLast()
            }
        }
        val rpo = post.asReversed()
        val rpoIndex = rpo.withIndex().associate { (i, b) -> b to i }

        val idoms = HashMap<Int, Int>()
        idoms[entry] = entry
        var changed = true
        while (changed) {
            changed = false
            for (bid in rpo) {
                if (bid == entry) continue
                val preds = byId[bid]?.preds ?: emptyList()
                val ready = preds.filter { it in idoms && it != bid }
                var newIdom = ready.minByOrNull { rpoIndex[it] ?: Int.MAX_VALUE } ?: continue
                for (p in ready) {
                    if (p == newIdom) continue
                    newIdom = intersect(p, newIdom, idoms, rpoIndex)
                }
                if (idoms[bid] != newIdom) {
                    idoms[bid] = newIdom
                    changed = true
                }
            }
        }

        val children = HashMap<Int, MutableList<Int>>()
        for ((bid, d) in idoms) {
            if (bid != entry) {
                children.getOrPut(d) { mutableListOf() }.add(bid)
            }
        }
        return DomInfo(idoms, children)
    }

    private fun intersect(a: Int, b: Int, idoms: Map<Int, Int>, rpoIndex: Map<Int, Int>): Int {
        var x = a
        var y = b
        var guard = 0
        while (x != y && guard++ < 100_000) {
            while (x != y && (rpoIndex[x] ?: 0) > (rpoIndex[y] ?: 0)) x = idoms[x] ?: y
            while (x != y && (rpoIndex[y] ?: 0) > (rpoIndex[x] ?: 0)) y = idoms[y] ?: x
            if (x != y) {
                x = idoms[x] ?: y
                if (x != y) y = idoms[y] ?: x
            }
        }
        return x
    }

    private fun computeDominanceFrontiers(blocks: List<SsaBlock>, idoms: Map<Int, Int>): Map<Int, Set<Int>> {
        val df = HashMap<Int, MutableSet<Int>>()
        for (blk in blocks) {
            if (blk.preds.size >= 2) {
                for (p in blk.preds) {
                    var runner = p
                    var guard = 0
                    while (runner != idoms[blk.id] && runner != blk.id && guard++ < 10_000) {
                        df.getOrPut(runner) { mutableSetOf() }.add(blk.id)
                        runner = idoms[runner] ?: break
                    }
                }
            }
        }
        return df
    }

    private fun insertPhis(blocks: List<SsaBlock>, df: Map<Int, Set<Int>>, funcId: Int): Int {
        val defBlocks = HashMap<String, MutableSet<Int>>()
        for (blk in blocks) {
            for (ins in blk.instrs) {
                val dn = ins.defName ?: continue
                defBlocks.getOrPut(dn) { mutableSetOf() }.add(blk.id)
            }
        }
        val byId = blocks.associateBy { it.id }
        var phiCount = 0
        for ((v, defs) in defBlocks) {
            val worklist = ArrayDeque(defs.toList())
            val phiPlaced = mutableSetOf<Int>()
            while (worklist.isNotEmpty() && phiCount < MAX_PHIS_PER_FUNCTION) {
                val bid = worklist.removeFirst()
                for (y in df[bid] ?: emptySet()) {
                    if (y !in phiPlaced) {
                        phiPlaced.add(y)
                        val blk = byId[y] ?: continue
                        blk.phis.add(SsaPhi(v, y, funcId, blk.instrs.firstOrNull()?.line ?: 0))
                        phiCount++
                        worklist.addLast(y)
                    }
                }
            }
        }
        return phiCount
    }

    private fun rename(blocks: List<SsaBlock>, domChildren: Map<Int, List<Int>>, entry: Int, funcId: Int) {
        val byId = blocks.associateBy { it.id }
        val versions = HashMap<String, Int>()
        val stacks = HashMap<String, ArrayDeque<Int>>()

        fun currentVersion(name: String): Int = stacks[name]?.lastOrNull() ?: -1

        fun newVersion(name: String): SsaVar {
            val v = (versions[name] ?: 0) + 1
            versions[name] = v
            stacks.getOrPut(name) { ArrayDeque() }.addLast(v)
            return SsaVar(name, v, funcId)
        }

        fun renameBlock(bid: Int) {
            val blk = byId[bid] ?: return
            val pushed = mutableListOf<String>()
            for (phi in blk.phis) {
                phi.result = newVersion(phi.varName)
                pushed.add(phi.varName)
            }
            for (ins in blk.instrs) {
                ins.uses = ins.useNames.map { SsaVar(it, currentVersion(it), funcId) }
                val dn = ins.defName
                if (dn != null) {
                    ins.result = newVersion(dn)
                    pushed.add(dn)
                }
            }
            when (val t = blk.term) {
                is Term.Branch -> t.condVars = t.condNames.map { SsaVar(it, currentVersion(it), funcId) }
                is Term.Ret -> t.retVal = t.valName?.let { SsaVar(it, currentVersion(it), funcId) }
                is Term.Throw -> t.throwVal = t.valName?.let { SsaVar(it, currentVersion(it), funcId) }
                else -> {}
            }
            for (succ in blk.succs) {
                byId[succ]?.let { sb ->
                    for (phi in sb.phis) {
                        phi.incoming[blk.id] = currentVersion(phi.varName)
                    }
                }
            }
            for (child in domChildren[bid] ?: emptyList()) renameBlock(child)
            for (name in pushed) stacks[name]?.removeLast()
        }

        renameBlock(entry)
    }

    // ---------------- 表达式辅助 ----------------

    /** 收集表达式内使用的标识符名（成员基 + 计算属性 + 变量） */
    private fun collectUseNames(e: Expr): List<String> {
        val out = LinkedHashSet<String>()
        collectUseNames(e, out)
        return out.toList()
    }

    private fun collectUseNames(e: Expr, out: LinkedHashSet<String>) {
        when (e) {
            is Expr.Identifier -> out.add(e.name)
            is Expr.Member -> {
                collectUseNames(e.obj, out)
                e.computed?.let { collectUseNames(it, out) }
            }
            is Expr.Call -> {
                collectUseNames(e.callee, out)
                e.args.forEach { collectUseNames(it, out) }
            }
            is Expr.New -> {
                collectUseNames(e.callee, out)
                e.args.forEach { collectUseNames(it, out) }
            }
            is Expr.Assign -> {
                when (val t = e.target) {
                    is Expr.Identifier -> if (isCompoundOp(e.op)) out.add(t.name)
                    is Expr.Member -> {
                        collectUseNames(t.obj, out)
                        t.computed?.let { collectUseNames(it, out) }
                    }
                    else -> {}
                }
                collectUseNames(e.value, out)
            }
            is Expr.Binary -> {
                collectUseNames(e.left, out)
                collectUseNames(e.right, out)
            }
            is Expr.Unary -> collectUseNames(e.operand, out)
            is Expr.Conditional -> {
                collectUseNames(e.test, out)
                collectUseNames(e.consequent, out)
                collectUseNames(e.alternate, out)
            }
            is Expr.ArrayLit -> e.elements.forEach { collectUseNames(it, out) }
            is Expr.ObjectLit -> e.props.forEach { p ->
                p.value?.let { collectUseNames(it, out) }
                p.computed?.let { collectUseNames(it, out) }
            }
            is Expr.TemplateLit -> e.exprs.forEach { collectUseNames(it, out) }
            is Expr.TaggedTemplate -> {
                collectUseNames(e.tag, out)
                e.template.exprs.forEach { collectUseNames(it, out) }
            }
            is Expr.Sequence -> e.exprs.forEach { collectUseNames(it, out) }
            is Expr.AwaitExpr -> collectUseNames(e.arg, out)
            is Expr.YieldExpr -> e.arg?.let { collectUseNames(it, out) }
            is Expr.Spread -> collectUseNames(e.arg, out)
            else -> {}
        }
    }

    private fun containsCall(e: Expr): Boolean {
        var found = false
        fun walk(x: Expr) {
            if (found) return
            when (x) {
                is Expr.Call, is Expr.New -> {
                    found = true
                    return
                }
                is Expr.Member -> walk(x.obj)
                is Expr.Assign -> {
                    walk(x.value)
                    if (x.target is Expr.Member) walk((x.target as Expr.Member).obj)
                }
                is Expr.Binary -> {
                    walk(x.left)
                    walk(x.right)
                }
                is Expr.Unary -> walk(x.operand)
                is Expr.Conditional -> {
                    walk(x.test)
                    walk(x.consequent)
                    walk(x.alternate)
                }
                is Expr.ArrayLit -> x.elements.forEach { walk(it) }
                is Expr.ObjectLit -> x.props.forEach { p -> p.value?.let { walk(it) } }
                is Expr.TemplateLit -> x.exprs.forEach { walk(it) }
                is Expr.TaggedTemplate -> x.template.exprs.forEach { walk(it) }
                is Expr.Sequence -> x.exprs.forEach { walk(it) }
                is Expr.AwaitExpr -> walk(x.arg)
                is Expr.Spread -> walk(x.arg)
                else -> {}
            }
        }
        walk(e)
        return found
    }

    /** 表达式的主要定值变量（return/throw 的值来源） */
    private fun primaryVarName(e: Expr?): String? = when (e) {
        null -> null
        is Expr.Identifier -> e.name
        is Expr.Member -> primaryVarName(e.obj)
        is Expr.Assign -> primaryVarName(e.value)
        else -> null
    }

    private fun isCompoundOp(op: String): Boolean = op != "="

    /** 从指令表达式抽取全部调用点（含嵌套调用） */
    private fun extractCallSites(ins: SsaInstr, funcId: Int, out: MutableList<CallSiteInfo>) {
        val expr = ins.expr ?: return
        fun walk(x: Expr) {
            when (x) {
                is Expr.Call -> {
                    out.add(
                        CallSiteInfo(
                            funcId = funcId,
                            blockId = ins.blockId,
                            instrIdx = ins.idx,
                            line = x.pos.line,
                            calleeExpr = x.callee,
                            calleeDisplay = AstRender.expr(x.callee),
                            args = x.args,
                            isNew = false,
                        )
                    )
                    walk(x.callee)
                    x.args.forEach { walk(it) }
                }
                is Expr.New -> {
                    out.add(
                        CallSiteInfo(
                            funcId = funcId,
                            blockId = ins.blockId,
                            instrIdx = ins.idx,
                            line = x.pos.line,
                            calleeExpr = x.callee,
                            calleeDisplay = "new ${AstRender.expr(x.callee)}",
                            args = x.args,
                            isNew = true,
                        )
                    )
                    x.args.forEach { walk(it) }
                }
                is Expr.Member -> {
                    walk(x.obj)
                    x.computed?.let { walk(it) }
                }
                is Expr.Assign -> walk(x.value)
                is Expr.Binary -> {
                    walk(x.left)
                    walk(x.right)
                }
                is Expr.Unary -> walk(x.operand)
                is Expr.Conditional -> {
                    walk(x.test)
                    walk(x.consequent)
                    walk(x.alternate)
                }
                is Expr.ArrayLit -> x.elements.forEach { walk(it) }
                is Expr.ObjectLit -> x.props.forEach { p -> p.value?.let { walk(it) } }
                is Expr.TemplateLit -> x.exprs.forEach { walk(it) }
                is Expr.TaggedTemplate -> x.template.exprs.forEach { walk(it) }
                is Expr.Sequence -> x.exprs.forEach { walk(it) }
                is Expr.AwaitExpr -> walk(x.arg)
                is Expr.Spread -> walk(x.arg)
                else -> {}
            }
        }
        walk(expr)
    }
}
