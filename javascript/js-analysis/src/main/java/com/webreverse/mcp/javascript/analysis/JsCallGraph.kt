package com.webreverse.mcp.javascript.analysis

/**
 * JS 调用图构建器（0-CFA 近似）—— 统一数据流引擎组件。
 *
 * 基于 [JsSsaBuilder] 的 SSA 结果，把全程序调用点解析为 caller -> callee 边：
 *
 * 解析策略（按精度从高到低）：
 * 1. **SSA 值传播（0-CFA）**：函数值（function literal）沿 def-use 链流动——
 *    `var f = function(){}` 后 `f()` 精确解析；参数传递（回调注入）迭代传播至不动点；
 * 2. **属性索引**：`obj.m()` 通过全程序属性名索引（对象方法/类方法/x.m=function 赋值）解析；
 * 3. **名称回退**：自由变量/同名函数声明/导入绑定按名字匹配（含嵌套作用域近似）。
 *
 * 附加产出：
 * - 调用者/被调用者倒排索引（逆向定位「谁调用了这个加密函数」）;
 * - 递归环检测（Tarjan SCC 精简版）；
 * - 热点函数排行（入度统计，定位核心算法）；
 * - 未解析调用点统计（提示动态分发/原生 API）。
 */
class JsCallGraphBuilder {

    companion object {
        /** 0-CFA 迭代上限（防不终止） */
        const val MAX_ITERATIONS = 12
    }

    // ---------------- 数据模型 ----------------

    /** 调用图边：caller -> callee（聚合同一函数对的多处调用点） */
    data class CgEdge(
        val from: Int,
        val to: Int,
        val count: Int,
        val lines: List<Int>,
        /** 解析方式：ssa/prop/index/name/new */
        val via: String,
    )

    data class CgStats(
        val totalCallSites: Int,
        val resolvedCallSites: Int,
        val unresolvedCallSites: Int,
        val edges: Int,
        val recursiveComponents: Int,
        val iterations: Int,
    )

    data class CallGraphResult(
        val edges: List<CgEdge>,
        /** caller funcId -> 出边 */
        val callsOf: Map<Int, List<CgEdge>>,
        /** callee funcId -> 入边（谁调用了它） */
        val callersOf: Map<Int, List<CgEdge>>,
        /** 递归环成员 */
        val recursiveFunctions: Set<Int>,
        /** 入度 Top 热点（核心算法定位） */
        val hotspots: List<Pair<Int, Int>>,
        /** 名称回退仍无法解析的调用点样例 */
        val unresolvedSamples: List<UnresolvedCall>,
        val stats: CgStats,
    )

    data class UnresolvedCall(
        val callerName: String,
        val calleeDisplay: String,
        val line: Int,
        val reason: String,
    )

    // ---------------- 入口 ----------------

    fun build(ssa: JsSsaBuilder.SsaProgram): CallGraphResult {
        val funcById = ssa.funcById
        // 0-CFA 值集：SsaVar -> 可能的函数 id 集合
        val fnSets = HashMap<JsSsaBuilder.SsaVar, MutableSet<Int>>()
        // 参数传播记录：funcId -> paramIndex -> arg vars 集合
        val paramArgs = HashMap<Int, MutableList<MutableList<JsSsaBuilder.SsaVar>>>()

        // 初始化参数槽位
        for (fn in ssa.functions) {
            if (fn.info.params.isEmpty()) continue
            val slots = fn.info.params.map { mutableListOf<JsSsaBuilder.SsaVar>() }.toMutableList()
            paramArgs[fn.info.id] = slots
        }

        // 种子：函数字面量 def
        for (fn in ssa.functions) {
            for ((v, fid) in fn.funcLitDefs) {
                fnSets.getOrPut(v) { mutableSetOf() }.add(fid)
            }
        }

        // 参数初始版本（param def var）——版本 1
        fun paramVar(fnId: Int, idx: Int): JsSsaBuilder.SsaVar? {
            val fn = funcById[fnId] ?: return null
            val name = fn.info.params.getOrNull(idx) ?: return null
            // param def 是该函数内该名字的第一个 def：从 defInstr 找最低版本
            return fn.defInstr.keys.filter { it.name == name && !it.isFree }.minByOrNull { it.version }
        }

        // 迭代传播至不动点
        var iteration = 0
        var changed = true
        while (changed && iteration < MAX_ITERATIONS) {
            changed = false
            iteration++
            for (fn in ssa.functions) {
                // 1) 参数槽位 → 参数变量
                val slots = paramArgs[fn.info.id]
                if (slots != null) {
                    slots.forEachIndexed { i, args ->
                        val pv = paramVar(fn.info.id, i) ?: return@forEachIndexed
                        val set = fnSets.getOrPut(pv) { mutableSetOf() }
                        for (a in args) {
                            val s = fnSets[a]
                            if (s != null && set.addAll(s)) changed = true
                        }
                    }
                }
                // 2) copy 传播：result <- uses 的函数集并
                for (blk in fn.blocks) {
                    for (ins in blk.instrs) {
                        val r = ins.result ?: continue
                        if (ins.litFuncId >= 0) continue // FUNC 指令已有精确值
                        val set = fnSets.getOrPut(r) { mutableSetOf() }
                        val before = set.size
                        for (u in ins.uses) {
                            fnSets[u]?.let { set.addAll(it) }
                        }
                        if (set.size != before) changed = true
                    }
                    for (phi in blk.phis) {
                        val pr = phi.result ?: continue
                        val set = fnSets.getOrPut(pr) { mutableSetOf() }
                        val before = set.size
                        for ((_, iv) in phi.incomingVars) {
                            fnSets[iv]?.let { set.addAll(it) }
                        }
                        if (set.size != before) changed = true
                    }
                }
                // 3) 调用点：实参 SSA 变量 -> 被调函数参数槽
                for (cs in fn.callSites) {
                    val resolved = resolve(ssa, fn, cs, fnSets)
                    val calleeIds = resolved.first
                    for (calleeId in calleeIds) {
                        val slots = paramArgs[calleeId] ?: continue
                        cs.args.forEachIndexed { i, arg ->
                            val argVars = argVarsOf(fn, cs, i)
                            if (argVars != null) {
                                val slot = slots.getOrNull(i) ?: return@forEachIndexed
                                for (av in argVars) {
                                    if (slot.none { it == av }) {
                                        slot.add(av)
                                        changed = true
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 边聚合
        val edgeMap = LinkedHashMap<String, MutableCgEdge>()
        val unresolved = mutableListOf<UnresolvedCall>()
        var totalSites = 0
        var resolvedSites = 0
        for (fn in ssa.functions) {
            for (cs in fn.callSites) {
                totalSites++
                val (calleeIds, via, reason) = resolve(ssa, fn, cs, fnSets)
                if (calleeIds.isEmpty()) {
                    if (unresolved.size < 200) {
                        unresolved.add(UnresolvedCall(fn.info.name, cs.calleeDisplay, cs.line, reason))
                    }
                    continue
                }
                resolvedSites++
                for (calleeId in calleeIds) {
                    val key = "${fn.info.id}->$calleeId"
                    val e = edgeMap.getOrPut(key) { MutableCgEdge(fn.info.id, calleeId) }
                    e.count++
                    if (e.lines.size < 32) e.lines.add(cs.line)
                    if (via == "ssa" || via == "prop") e.via = "ssa"
                }
            }
        }

        val edges = edgeMap.values.map {
            CgEdge(it.from, it.to, it.count, it.lines.toList(), it.via)
        }
        val callsOf = edges.groupBy { it.from }
        val callersOf = edges.groupBy { it.to }
        val recursive = findRecursive(edges, funcById)
        val hotspots = callersOf.entries
            .map { it.key to it.value.sumOf { e -> e.count } }
            .sortedByDescending { it.second }
            .take(50)

        return CallGraphResult(
            edges = edges,
            callsOf = callsOf,
            callersOf = callersOf,
            recursiveFunctions = recursive,
            hotspots = hotspots,
            unresolvedSamples = unresolved,
            stats = CgStats(
                totalCallSites = totalSites,
                resolvedCallSites = resolvedSites,
                unresolvedCallSites = totalSites - resolvedSites,
                edges = edges.size,
                recursiveComponents = recursive.size,
                iterations = iteration,
            ),
        )
    }

    private class MutableCgEdge(val from: Int, val to: Int) {
        var count = 0
        val lines = mutableListOf<Int>()
        var via = "index"
    }

    // ---------------- 调用点解析 ----------------

    /**
     * 解析单个调用点的目标函数集合。
     * @return Triple(目标函数 ids, 解析方式, 未解析原因)
     */
    private fun resolve(
        ssa: JsSsaBuilder.SsaProgram,
        fn: JsSsaBuilder.SsaFunctionResult,
        cs: JsSsaBuilder.CallSiteInfo,
        fnSets: Map<JsSsaBuilder.SsaVar, Set<Int>>,
    ): Triple<Set<Int>, String, String> {
        val callee = cs.calleeExpr

        // 1) 标识符 callee：SSA 值集
        if (callee is Expr.Identifier) {
            val v = cs.calleeVar
            if (v != null) {
                val set = fnSets[v]
                if (!set.isNullOrEmpty()) return Triple(set.toSet(), "ssa", "")
                // FUNC def 直接解析
                fn.funcLitDefs[v]?.let { return Triple(setOf(it), "ssa", "") }
            }
            // 2) 名称回退：顶层声明 → 嵌套同名 → 全局属性名
            val tl = ssa.topLevelFuncs[callee.name]
            if (!tl.isNullOrEmpty()) return Triple(tl.toSet(), "name", "")
            val nested = ssa.funcsByName[callee.name]
            if (!nested.isNullOrEmpty()) return Triple(nested.toSet(), "name", "")
            val prop = ssa.propIndex[callee.name]
            if (!prop.isNullOrEmpty()) return Triple(prop.toSet(), "index", "")
            // 自由变量：外层作用域（父链）名称解析
            if (callee.name in fn.freeVars) {
                val parentChain = parentChain(ssa, fn.info.id)
                for (pid in parentChain) {
                    val pfn = ssa.funcById[pid] ?: continue
                    if (callee.name in pfn.freeVars) continue
                    val pTl = ssa.topLevelFuncs[callee.name]
                    if (!pTl.isNullOrEmpty()) return Triple(pTl.toSet(), "name", "")
                    val pNested = ssa.funcsByName[callee.name]
                    if (!pNested.isNullOrEmpty()) return Triple(pNested.toSet(), "name", "")
                }
            }
            return Triple(emptySet(), "none", "identifier '${callee.name}' 无函数定义")
        }

        // 3) 成员 callee：属性索引
        if (callee is Expr.Member && callee.property != null) {
            val prop = ssa.propIndex[callee.property]
            if (!prop.isNullOrEmpty()) return Triple(prop.toSet(), "index", "")
            return Triple(emptySet(), "none", "成员方法 '${callee.property}' 未索引（动态/原生）")
        }

        // 4) 计算 callee（(expr)(...) / a[i]()）
        if (callee is Expr.Member && callee.computed != null) {
            return Triple(emptySet(), "none", "计算成员调用")
        }
        if (callee is Expr.Call || callee is Expr.FunctionExpr) {
            return Triple(emptySet(), "none", "返回值调用/立即调用")
        }
        return Triple(emptySet(), "none", "动态 callee")
    }

    /** 父作用域链（不含自身） */
    private fun parentChain(ssa: JsSsaBuilder.SsaProgram, funcId: Int): List<Int> {
        val chain = mutableListOf<Int>()
        var cur = ssa.funcById[funcId]?.info?.parent ?: return chain
        var guard = 0
        while (cur >= 0 && guard++ < 64) {
            chain.add(cur)
            cur = ssa.funcById[cur]?.info?.parent ?: -1
        }
        return chain
    }

    /** 实参的 SSA 变量（取该调用点指令上与实参表达式匹配的 use） */
    private fun argVarsOf(
        fn: JsSsaBuilder.SsaFunctionResult,
        cs: JsSsaBuilder.CallSiteInfo,
        argIdx: Int,
    ): List<JsSsaBuilder.SsaVar>? {
        val arg = cs.args.getOrNull(argIdx) ?: return null
        return when (arg) {
            is Expr.Identifier -> {
                val ins = fn.byId[cs.blockId]?.instrs?.firstOrNull { it.idx == cs.instrIdx }
                ins?.uses?.filter { it.name == arg.name }?.takeIf { it.isNotEmpty() }
            }
            is Expr.FunctionExpr -> {
                // 直接传入函数字面量：该字面量的函数 id 由污点/调用图在 FUNC def 处理；这里返回 null（已由 calleeVar 处理）
                null
            }
            else -> null
        }
    }

    /** 递归环检测（Tarjan 精简：DFS 找环成员） */
    private fun findRecursive(edges: List<CgEdge>, funcById: Map<Int, *>): Set<Int> {
        val adj = edges.groupBy { it.from }.mapValues { (_, v) -> v.map { it.to }.toSet() }
        val inCycle = mutableSetOf<Int>()
        val state = HashMap<Int, Int>() // 0=unvisited 1=in-stack 2=done
        fun dfs(node: Int, path: MutableList<Int>) {
            state[node] = 1
            path.add(node)
            for (next in adj[node] ?: emptySet()) {
                if (next !in funcById) continue
                when (state[next]) {
                    1 -> {
                        // 环：path 中 next 之后全部入环
                        val idx = path.indexOf(next)
                        if (idx >= 0) {
                            for (i in idx until path.size) inCycle.add(path[i])
                        }
                    }
                    0 -> dfs(next, path)
                    else -> {}
                }
            }
            path.removeAt(path.size - 1)
            state[node] = 2
        }
        for (f in funcById.keys) {
            if (state[f] == null || state[f] == 0) dfs(f, mutableListOf())
        }
        return inCycle
    }
}
