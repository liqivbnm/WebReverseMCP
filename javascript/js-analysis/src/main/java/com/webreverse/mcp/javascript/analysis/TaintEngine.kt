package com.webreverse.mcp.javascript.analysis

/**
 * 统一污点分析引擎（Taint Engine）—— 核心。
 *
 * 基于 [JsSsaBuilder]（SSA def-use）+ [JsCallGraphBuilder]（调用图），实现：
 * 1. **Source 规则库**：document.cookie / localStorage / location.* / navigator.* /
 *    atob / responseText / message.data / 敏感命名变量……（输入面）；
 * 2. **Transform 规则库**：atob/btoa/JSON.parse/stringify/encodeURIComponent/fromCharCode/replace……
 *    （污点经过时记录转换链，逆向时即「算法处理步骤」）；
 * 3. **Sink 规则库**：eval/new Function/fetch/XHR.send/WebSocket/innerHTML/location.href/
 *    setRequestHeader/localStorage.setItem……（输出面），分级 severity；
 * 4. **传播**：SSA 指令 def-use（过程内精确）+ Phi 合并 + 参数/返回跨函数（0-CFA 调用边）
 *    + 闭包自由变量名字近似；
 * 5. **溯源路径**：污点变量记录父节点，回溯重建 source → … → sink 完整链（含跨函数跳变）。
 *
 * 相比 [JsDfgAnalyzer] 的顺序近似：同名变量版本隔离、分支/循环经 Phi 合并、
 * 跨函数经调用图传播、路径可回溯到具体 SSA 版本。
 */
class TaintEngine {

    companion object {
        /** 全局迭代上限 */
        const val MAX_GLOBAL_ITERATIONS = 8

        /** 每函数内部迭代上限 */
        const val MAX_LOCAL_ITERATIONS = 8

        /** 输出 flow 上限 */
        const val MAX_FLOWS = 400

        /** 路径步数上限 */
        const val MAX_PATH_STEPS = 64
    }

    // ---------------- 数据模型 ----------------

    data class TaintOrigin(val label: String, val line: Int, val funcName: String) {
        val id: String get() = "$label@$line#$funcName"
    }

    data class TaintStep(
        val funcName: String,
        val line: Int,
        val desc: String,
        val varName: String,
        /** 跨函数跳变标记（参数传入/返回传出） */
        val hop: String = "",
    )

    enum class Severity { CRITICAL, HIGH, MEDIUM, LOW }

    data class TaintFlow(
        val sourceLabel: String,
        val sourceLine: Int,
        val sourceFunc: String,
        val sinkLabel: String,
        val sinkLine: Int,
        val sinkFunc: String,
        val path: List<TaintStep>,
        val crossFunction: Boolean,
        val severity: Severity,
        /** 污点经过的转换操作（算法线索） */
        val transforms: List<String>,
    )

    data class TaintReport(
        val flows: List<TaintFlow>,
        val sourceCount: Int,
        val sinkCount: Int,
        val taintedVarCount: Int,
        val iterations: Int,
    )

    // ---------------- 规则库 ----------------

    /** Source：输入面（含逆向关注的敏感数据源） */
    private val sourceNameRe = Regex("(?i)(token|passw|secret|authoriz|cookie|api[_-]?key|credential|sessionid|pwd|privkey|access[_-]?key|nonce|sign|captcha|otp|verify)")

    /** 匹配 Source（返回 label） */
    fun matchSource(text: String): String? {
        val t = text.lowercase()
        return when {
            t.contains("document.cookie") -> "document.cookie"
            t.contains("localstorage.getitem") || t.contains("sessionstorage.getitem") -> "storage.getItem"
            t.contains("indexeddb") -> "IndexedDB"
            t.contains("location.search") -> "location.search"
            t.contains("location.hash") -> "location.hash"
            t.contains("location.href") || t.contains("location.pathname") -> "location"
            t.contains("navigator.useragent") -> "navigator.userAgent"
            t.contains("navigator.webdriver") -> "navigator.webdriver"
            t.contains("navigator.platform") -> "navigator.platform"
            t.contains("window.name") -> "window.name"
            t.contains("atob(") -> "atob"
            t.contains("fromcharcode") -> "String.fromCharCode"
            t.contains("urlsearchparams") || t.contains("searchparams") -> "URLSearchParams"
            t.contains("responsetext") || t.contains("responsejson") || t.contains(".json()") || t.contains(".text()") -> "network.response"
            t.contains("message.data") || t.contains("event.data") || t.contains("postmessage") -> "message.data"
            t.contains("crypto.subtle") || t.contains("getrandomvalues") -> "crypto"
            t.contains("getallresponseheaders") -> "response.headers"
            else -> null
        }
    }

    /** Transform：污点流经的转换（算法步骤线索） */
    private val transformRules = listOf(
        "atob", "btoa", "json.parse", "json.stringify", "encodeuricomponent", "decodeuricomponent",
        "escape(", "unescape", "fromcharcode", "charcodeat", "tostring", "parseint", "parsefloat",
        ".replace", ".split", ".join", ".concat", ".slice", ".substr", ".substring", ".padstart",
        ".tolowercase", ".touppercase", ".reverse", ".map", ".flat", "number(", "string(",
    )

    /** Sink：输出面（返回 label + severity） */
    fun matchSink(text: String): Pair<String, Severity>? {
        val t = text.lowercase()
        return when {
            t.contains("eval(") || t.endsWith("eval") -> "eval" to Severity.CRITICAL
            t.contains("new function") || t.contains("function(") && t.contains("return") -> "new Function" to Severity.CRITICAL
            t.contains("settimeout(") || t.contains("setinterval(") -> "setTimeout/setInterval" to Severity.HIGH
            t.contains("fetch(") -> "fetch" to Severity.HIGH
            t.contains(".send(") || t.contains("xmlhttprequest") -> "XHR.send" to Severity.HIGH
            t.contains("sendbeacon") -> "sendBeacon" to Severity.HIGH
            t.contains("websocket") -> "WebSocket" to Severity.HIGH
            t.contains("importscripts") || t.contains("webassembly.instantiate") -> "dynamic import" to Severity.HIGH
            t.contains("innerhtml") || t.contains("outerhtml") || t.contains("insertadjacenthtml") || t.contains("document.write") -> "DOM 注入" to Severity.HIGH
            t.contains("location.href") || t.contains("location.assign") || t.contains("window.open") -> "location 跳转" to Severity.MEDIUM
            t.contains("setrequestheader") -> "setRequestHeader" to Severity.HIGH
            t.contains("localstorage.setitem") || t.contains("sessionstorage.setitem") -> "storage.setItem" to Severity.MEDIUM
            t.contains("postmessage") -> "postMessage" to Severity.MEDIUM
            else -> null
        }
    }

    // ---------------- 引擎状态 ----------------

    private class EngineState(val ssa: JsSsaBuilder.SsaProgram) {
        /** 污点变量 -> 源集合 */
        val tainted = HashMap<JsSsaBuilder.SsaVar, MutableSet<TaintOrigin>>()

        /** 污点变量 -> 父变量（路径回溯） */
        val parents = HashMap<JsSsaBuilder.SsaVar, MutableList<JsSsaBuilder.SsaVar>>()

        /** 参数变量缓存：funcId -> paramIndex -> var */
        val paramVars = HashMap<Int, List<JsSsaBuilder.SsaVar?>>()

        fun paramVar(fnId: Int, idx: Int): JsSsaBuilder.SsaVar? {
            val list = paramVars.getOrPut(fnId) {
                val fn = ssa.funcById[fnId] ?: return null
                fn.info.params.map { p ->
                    fn.defInstr.keys.filter { it.name == p && !it.isFree }.minByOrNull { it.version }
                }
            }
            return list.getOrNull(idx)
        }

        fun addTaint(v: JsSsaBuilder.SsaVar, origin: TaintOrigin): Boolean {
            val set = tainted.getOrPut(v) { mutableSetOf() }
            return set.add(origin)
        }

        fun addParent(child: JsSsaBuilder.SsaVar, parent: JsSsaBuilder.SsaVar) {
            val list = parents.getOrPut(child) { mutableListOf() }
            if (list.size < 16 && parent != child && list.none { it == parent }) list.add(parent)
        }
    }

    // ---------------- 入口 ----------------

    fun analyze(ssa: JsSsaBuilder.SsaProgram, callGraph: JsCallGraphBuilder.CallGraphResult): TaintReport {
        val st = EngineState(ssa)
        var iteration = 0
        var changed = true
        while (changed && iteration < MAX_GLOBAL_ITERATIONS) {
            changed = false
            iteration++
            // 1) 闭包名字近似种子：全局污点名 -> 自由变量使用
            val taintedNames = st.tainted.keys.filter { !it.isFree }.map { it.name }.toSet()
            for (fn in ssa.functions) {
                for (blk in fn.blocks) {
                    for (ins in blk.instrs) {
                        for (u in ins.uses) {
                            if (u.isFree && u.name in taintedNames) {
                                val origin = TaintOrigin("closure:${u.name}", ins.line, fn.info.name)
                                if (st.addTaint(u, origin)) changed = true
                            }
                        }
                    }
                }
            }
            // 2) Source 种子：表达式子树匹配
            for (fn in ssa.functions) {
                for (blk in fn.blocks) {
                    for (ins in blk.instrs) {
                        val seeds = sourceSeeds(ins)
                        for (seed in seeds) {
                            val r = ins.result ?: continue
                            if (st.addTaint(r, TaintOrigin(seed, ins.line, fn.info.name))) changed = true
                        }
                        // 敏感命名变量 def
                        val dn = ins.defName
                        if (dn != null && sourceNameRe.containsMatchIn(dn) && ins.result != null) {
                            if (st.addTaint(ins.result!!, TaintOrigin("var:$dn", ins.line, fn.info.name))) changed = true
                        }
                    }
                }
            }
            // 3) 过程内传播（每函数本地迭代）
            for (fn in ssa.functions) {
                var localChanged = true
                var localIter = 0
                while (localChanged && localIter < MAX_LOCAL_ITERATIONS) {
                    localChanged = false
                    localIter++
                    for (blk in fn.blocks) {
                        for (phi in blk.phis) {
                            val pr = phi.result ?: continue
                            var hit = false
                            for ((_, iv) in phi.incomingVars) {
                                val org = st.tainted[iv]
                                if (org != null) {
                                    for (o in org) if (st.addTaint(pr, o)) { localChanged = true; changed = true }
                                    st.addParent(pr, iv)
                                    hit = true
                                }
                            }
                            if (hit) changed = true
                        }
                        for (ins in blk.instrs) {
                            val r = ins.result ?: continue
                            if (ins.op == JsSsaBuilder.SsaOp.FUNC || ins.op == JsSsaBuilder.SsaOp.LOAD) continue
                            val parUses = mutableListOf<JsSsaBuilder.SsaVar>()
                            for (u in ins.uses) {
                                val org = st.tainted[u] ?: continue
                                for (o in org) if (st.addTaint(r, o)) { localChanged = true; changed = true }
                                parUses.add(u)
                            }
                            parUses.forEach { st.addParent(r, it) }
                        }
                    }
                }
            }
            // 4) 跨函数传播（调用边）：实参污点 -> 形参；返回污点 -> 调用结果
            for (fn in ssa.functions) {
                for (cs in fn.callSites) {
                    val calleeIds = resolveCallees(ssa, callGraph, fn, cs)
                    val callInstr = fn.byId[cs.blockId]?.instrs?.firstOrNull { it.idx == cs.instrIdx }
                    for (calleeId in calleeIds) {
                        val callee = ssa.funcById[calleeId] ?: continue
                        // 参数：不仅支持 foo(x)，也支持 foo(x + key)、foo(obj.token)、foo(cond ? a : b)。
                        // SSA 指令已经收集了当前 callsite 的变量使用集合；按每个实参里的 Identifier 名称
                        // 过滤对应版本即可在不重建完整 expression-SSA 映射的前提下实现“按实参”跨函数传播。
                        cs.args.forEachIndexed { i, arg ->
                            val names = identifierNames(arg)
                            val argVars = callInstr?.uses
                                ?.filter { it.name in names }
                                ?.groupBy { it.name }
                                ?.values
                                ?.mapNotNull { vars -> vars.maxByOrNull { it.version } }
                                .orEmpty()
                            if (argVars.isEmpty()) return@forEachIndexed

                            val pv = st.paramVar(calleeId, i) ?: return@forEachIndexed
                            for (argVar in argVars) {
                                val org = st.tainted[argVar] ?: continue
                                for (o in org) if (st.addTaint(pv, o)) changed = true
                                st.addParent(pv, argVar)
                            }
                        }
                        // 返回值
                        val retTainted = callee.retVars.firstNotNullOfOrNull { st.tainted[it] }
                        if (retTainted != null && callInstr?.result != null) {
                            for (o in retTainted) if (st.addTaint(callInstr.result!!, o)) changed = true
                            callee.retVars.forEach { rv ->
                                if (st.tainted[rv] != null) st.addParent(callInstr.result!!, rv)
                            }
                        }
                    }
                }
            }
        }

        // 5) Sink 检测与 Flow 生成
        val flows = mutableListOf<TaintFlow>()
        val seen = mutableSetOf<String>()
        var sinkCount = 0
        for (fn in ssa.functions) {
            for (blk in fn.blocks) {
                for (ins in blk.instrs) {
                    val sinkMatch = sinkMatchOf(ins)
                    if (sinkMatch == null) continue
                    sinkCount++
                    val (sinkLabel, severity) = sinkMatch
                    // (a) 数据流路径：uses 污点
                    val useOrigins = ins.uses.mapNotNull { u -> st.tainted[u]?.let { u to it } }
                    for ((u, origins) in useOrigins) {
                        for (origin in origins) {
                            val key = "${origin.id}|$sinkLabel|${ins.line}"
                            if (key !in seen) {
                                seen.add(key)
                                flows.add(buildFlow(origin, sinkLabel, ins, fn, u, st, ssa, severity))
                            }
                        }
                    }
                    // (b) 直接路径：sink 表达式参数内含 Source
                    val direct = sourceSeeds(ins)
                    for (srcLabel in direct) {
                        val key = "$srcLabel@${ins.line}|$sinkLabel|${ins.line}"
                        if (key !in seen) {
                            seen.add(key)
                            val origin = TaintOrigin(srcLabel, ins.line, fn.info.name)
                            flows.add(
                                TaintFlow(
                                    sourceLabel = origin.label,
                                    sourceLine = origin.line,
                                    sourceFunc = origin.funcName,
                                    sinkLabel = sinkLabel,
                                    sinkLine = ins.line,
                                    sinkFunc = fn.info.name,
                                    path = listOf(
                                        TaintStep(fn.info.name, ins.line, "source $srcLabel", "—"),
                                        TaintStep(fn.info.name, ins.line, "→ $sinkLabel", "—"),
                                    ),
                                    crossFunction = false,
                                    severity = severity,
                                    transforms = transformsOf(ins),
                                )
                            )
                        }
                    }
                    if (flows.size >= MAX_FLOWS) break
                }
                if (flows.size >= MAX_FLOWS) break
            }
            if (flows.size >= MAX_FLOWS) break
        }

        return TaintReport(
            flows = flows.sortedWith(compareByDescending<TaintFlow> { it.severity }.thenBy { it.sinkLine }),
            sourceCount = st.tainted.values.sumOf { it.size },
            sinkCount = sinkCount,
            taintedVarCount = st.tainted.size,
            iterations = iteration,
        )
    }

    // ---------------- 辅助 ----------------

    /** 收集表达式中的 Identifier 名称，用于跨函数按实参传播污点。 */
    private fun identifierNames(expr: Expr?): Set<String> {
        if (expr == null) return emptySet()
        val out = LinkedHashSet<String>()
        fun walk(x: Expr?) {
            when (x) {
                null -> Unit
                is Expr.Identifier -> out += x.name
                is Expr.Member -> {
                    walk(x.obj)
                    x.computed?.let(::walk)
                }
                is Expr.Call -> {
                    walk(x.callee); x.args.forEach(::walk)
                }
                is Expr.New -> {
                    walk(x.callee); x.args.forEach(::walk)
                }
                is Expr.Assign -> {
                    walk(x.target); walk(x.value)
                }
                is Expr.Binary -> {
                    walk(x.left); walk(x.right)
                }
                is Expr.Unary -> walk(x.operand)
                is Expr.Conditional -> {
                    walk(x.test); walk(x.consequent); walk(x.alternate)
                }
                is Expr.ArrayLit -> x.elements.forEach(::walk)
                is Expr.ObjectLit -> x.props.forEach { p -> p.computed?.let(::walk); p.value?.let(::walk) }
                is Expr.TemplateLit -> x.exprs.forEach(::walk)
                is Expr.TaggedTemplate -> { walk(x.tag); x.template.exprs.forEach(::walk) }
                is Expr.Sequence -> x.exprs.forEach(::walk)
                is Expr.AwaitExpr -> walk(x.arg)
                is Expr.YieldExpr -> walk(x.arg)
                is Expr.Spread -> walk(x.arg)
                else -> Unit
            }
        }
        walk(expr)
        return out
    }

    /** 调用点解析复用：调用图边（无则按名称回退） */
    private fun resolveCallees(
        ssa: JsSsaBuilder.SsaProgram,
        cg: JsCallGraphBuilder.CallGraphResult,
        fn: JsSsaBuilder.SsaFunctionResult,
        cs: JsSsaBuilder.CallSiteInfo,
    ): Set<Int> {
        cg.callsOf[fn.info.id]
            ?.filter { it.lines.contains(cs.line) }
            ?.map { it.to }
            ?.toSet()
            ?.takeIf { it.isNotEmpty() }
            ?.let { return it }
        // 名称回退
        val callee = cs.calleeExpr
        if (callee is Expr.Identifier) {
            ssa.topLevelFuncs[callee.name]?.toSet()?.let { return it }
            ssa.funcsByName[callee.name]?.toSet()?.let { return it }
        }
        if (callee is Expr.Member && callee.property != null) {
            ssa.propIndex[callee.property]?.toSet()?.let { return it }
        }
        return emptySet()
    }

    /** 指令表达式中的 Source 子表达式（跳过赋值目标，只走值位置） */
    private fun sourceSeeds(ins: JsSsaBuilder.SsaInstr): List<String> {
        val expr = ins.expr ?: return emptyList()
        val out = mutableListOf<String>()
        fun walk(x: Expr?) {
            if (x == null || out.size >= 8) return
            val label = matchSource(AstRender.expr(x))
            if (label != null) out.add(label)
            when (x) {
                is Expr.Assign -> walk(x.value)
                is Expr.Member -> {
                    walk(x.obj)
                    x.computed?.let { walk(it) }
                }
                is Expr.Call -> {
                    walk(x.callee)
                    x.args.forEach { walk(it) }
                }
                is Expr.New -> {
                    walk(x.callee)
                    x.args.forEach { walk(it) }
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
                is Expr.Sequence -> x.exprs.forEach { walk(it) }
                is Expr.AwaitExpr -> walk(x.arg)
                is Expr.Spread -> walk(x.arg)
                else -> {}
            }
        }
        walk(expr)
        return out.distinct()
    }

    /** 指令的 Sink 匹配（表达式文本） */
    private fun sinkMatchOf(ins: JsSsaBuilder.SsaInstr): Pair<String, Severity>? {
        val expr = ins.expr ?: return null
        return matchSink(AstRender.expr(expr))
    }

    /** 指令流经的转换操作 */
    private fun transformsOf(ins: JsSsaBuilder.SsaInstr): List<String> {
        val expr = ins.expr ?: return emptyList()
        val text = AstRender.expr(expr).lowercase()
        return transformRules.filter { text.contains(it) }.take(8)
    }

    /** 回溯污点路径（parents 链，BFS 最短） */
    private fun buildFlow(
        origin: TaintOrigin,
        sinkLabel: String,
        ins: JsSsaBuilder.SsaInstr,
        fn: JsSsaBuilder.SsaFunctionResult,
        sinkUse: JsSsaBuilder.SsaVar,
        st: EngineState,
        ssa: JsSsaBuilder.SsaProgram,
        severity: Severity,
    ): TaintFlow {
        // BFS 回溯
        val prev = HashMap<JsSsaBuilder.SsaVar, JsSsaBuilder.SsaVar?>()
        val queue = ArrayDeque<JsSsaBuilder.SsaVar>()
        queue.add(sinkUse)
        prev[sinkUse] = null
        var root: JsSsaBuilder.SsaVar = sinkUse
        var steps = 0
        while (queue.isNotEmpty() && steps < MAX_PATH_STEPS) {
            val v = queue.removeFirst()
            steps++
            val orgs = st.tainted[v]
            if (orgs != null && orgs.contains(origin)) {
                root = v
                break
            }
            for (p in st.parents[v] ?: emptyList()) {
                if (p !in prev) {
                    prev[p] = v
                    queue.add(p)
                }
            }
        }
        // 重建链
        val chain = mutableListOf<JsSsaBuilder.SsaVar>()
        var cur: JsSsaBuilder.SsaVar? = root
        var guard = 0
        while (cur != null && guard++ < MAX_PATH_STEPS) {
            chain.add(cur)
            cur = prev[cur]
        }
        chain.reverse()

        val path = mutableListOf<TaintStep>()
        val transforms = mutableListOf<String>()
        path.add(TaintStep(origin.funcName, origin.line, "◎ source ${origin.label}", origin.label))
        for (v in chain) {
            val ownerFn = ssa.funcById[v.funcId]
            val defI = ownerFn?.defInstr?.get(v)
            val hop = if (v.funcId != sinkUse.funcId && v.funcId != chain.first().funcId) "跨函数" else ""
            if (defI != null) {
                path.add(TaintStep(ownerFn?.info?.name ?: "?", defI.line, defI.label.take(80), v.toString(), hop))
                transformsOf(defI).forEach { transforms.add(it) }
            } else if (v.isFree) {
                path.add(TaintStep(ownerFn?.info?.name ?: "?", 0, "自由变量 ${v.name}（闭包/全局）", v.toString(), hop))
            }
        }
        path.add(TaintStep(fn.info.name, ins.line, "▶ sink $sinkLabel（${AstRender.expr(ins.expr).take(60)}）", sinkUse.toString()))

        return TaintFlow(
            sourceLabel = origin.label,
            sourceLine = origin.line,
            sourceFunc = origin.funcName,
            sinkLabel = sinkLabel,
            sinkLine = ins.line,
            sinkFunc = fn.info.name,
            path = path,
            crossFunction = chain.any { it.funcId != sinkUse.funcId },
            severity = severity,
            transforms = transforms.distinct().take(10),
        )
    }

    // ---------------- 运行时污点标签桥接入口（不影响既有静态主路径） ----------------

    /**
     * 组合入口：先跑既有静态传播 [analyze]，再用 [RuntimeTaintBridge] 把运行时
     * 污点标签输入 [runtime] 并入静态结果。仅新增方法，不改动任何既有公开签名、
     * 不改动静态传播主路径。
     *
     * @param runtime js-runtime 上报的运行时就地标签（来源→中间→汇）。
     */
    fun analyzeBridged(
        ssa: JsSsaBuilder.SsaProgram,
        callGraph: JsCallGraphBuilder.CallGraphResult,
        runtime: RuntimeTaintBridge.Input,
        severity: Severity = Severity.HIGH,
    ): TaintReport {
        val base = analyze(ssa, callGraph)
        return RuntimeTaintBridge().merge(base, runtime, severity)
    }
}
