package com.webreverse.mcp.javascript.analysis

import java.util.ArrayDeque
import kotlin.math.ln

/**
 * 深度逆向分析器 。
 *
 * 重点不是再增加扫描器，而是把“对象属性、跨函数、异步、网络 Sink、WASM 边界”
 * 统一成同一份可解释的数据流模型。纯 Kotlin，无运行时依赖。
 */
class DeepReverseAnalyzer {

    enum class EdgeKind { DEF_USE, PROPERTY_FLOW, CALL_ARG, RETURN_FLOW, ASYNC, NETWORK_SINK, CRYPTO_FLOW, WASM_HINT }

    data class FlowNode(
        val id: String,
        val kind: String,
        val label: String,
        val line: Int,
        val confidence: Double,
    )

    data class FlowEdge(
        val from: String,
        val to: String,
        val kind: EdgeKind,
        val line: Int,
        val confidence: Double,
        val evidence: List<String> = emptyList(),
    )

    data class PropertyFact(
        val path: String,
        val operation: String,
        val line: Int,
        val function: String,
        val expression: String,
    )

    data class AsyncFact(
        val api: String,
        val callbackHint: String,
        val line: Int,
        val function: String,
        val confidence: Double,
    )

    data class Result(
        val ok: Boolean,
        val error: String = "",
        val nodes: List<FlowNode> = emptyList(),
        val edges: List<FlowEdge> = emptyList(),
        val propertyFacts: List<PropertyFact> = emptyList(),
        val asyncFacts: List<AsyncFact> = emptyList(),
        val networkSinks: List<FlowNode> = emptyList(),
        val wasmHints: List<FlowNode> = emptyList(),
        val cryptoBindings: List<FlowNode> = emptyList(),
        val metrics: Metrics = Metrics(),
    )

    data class Metrics(
        val objectMemoryCoverage: Double = 0.0,
        val interproceduralCoverage: Double = 0.0,
        val asyncCoverage: Double = 0.0,
        val networkBindingCoverage: Double = 0.0,
        val cryptoBindingCoverage: Double = 0.0,
        val wasmBoundaryCoverage: Double = 0.0,
        val explainability: Double = 0.0,
        val overallReadiness: Double = 0.0,
    )

    private val networkApis = setOf(
        "fetch", "XMLHttpRequest", "send", "open", "axios", "request", "post", "put", "patch", "get", "WebSocket"
    )
    private val asyncApis = setOf(
        "then", "catch", "finally", "setTimeout", "setInterval", "queueMicrotask", "requestAnimationFrame", "addEventListener", "onload", "onreadystatechange"
    )
    private val cryptoWords = Regex("""(?i)(encrypt|decrypt|encode|decode|sign|verify|hash|hmac|sha-?\d|md5|chacha|aes|rsa|ecc|crypto|digest)""")
    private val wasmWords = Regex("""(?i)(WebAssembly|\.wasm|instantiate|instantiateStreaming|Memory|Table|TypedArray|Uint8Array|DataView)""")

    fun analyze(source: String): Result {
        if (source.isBlank()) return Result(false, "source 为空")
        return try {
            val program = JsAstParser().parse(source)
            val nodes = LinkedHashMap<String, FlowNode>()
            val edges = mutableListOf<FlowEdge>()
            val props = mutableListOf<PropertyFact>()
            val async = mutableListOf<AsyncFact>()
            val sinks = mutableListOf<FlowNode>()
            val wasm = mutableListOf<FlowNode>()
            val crypto = mutableListOf<FlowNode>()
            val functionStack = ArrayDeque<String>()
            val vars = HashMap<String, String>()
            val returnByFunction = HashMap<String, MutableList<String>>()
            var flowId = 0

            fun addNode(kind: String, label: String, line: Int, confidence: Double): String {
                val id = "n${flowId++}"
                nodes[id] = FlowNode(id, kind, label.take(220), line, confidence.coerceIn(0.0, 1.0))
                return id
            }

            fun currentFn() = functionStack.lastOrNull() ?: "(global)"
            fun exprText(e: Expr) = AstRender.expr(e)

            fun identifierNames(e: Expr): Set<String> {
                val out = LinkedHashSet<String>()
                fun walk(x: Expr) {
                    when (x) {
                        is Expr.Identifier -> out += x.name
                        is Expr.Member -> { walk(x.obj); x.computed?.let(::walk) }
                        is Expr.Call -> { walk(x.callee); x.args.forEach(::walk) }
                        is Expr.New -> { walk(x.callee); x.args.forEach(::walk) }
                        is Expr.Assign -> { walk(x.target); walk(x.value) }
                        is Expr.Binary -> { walk(x.left); walk(x.right) }
                        is Expr.Conditional -> { walk(x.test); walk(x.consequent); walk(x.alternate) }
                        is Expr.Unary -> walk(x.operand)
                        is Expr.ArrayLit -> x.elements.forEach(::walk)
                        is Expr.ObjectLit -> x.props.forEach { it.value?.let(::walk); it.computed?.let(::walk) }
                        is Expr.TemplateLit -> x.exprs.forEach(::walk)
                        is Expr.TaggedTemplate -> { walk(x.tag); x.template.exprs.forEach(::walk) }
                        is Expr.Spread -> walk(x.arg)
                        is Expr.Sequence -> x.exprs.forEach(::walk)
                        is Expr.AwaitExpr -> walk(x.arg)
                        is Expr.YieldExpr -> x.arg?.let(::walk)
                        else -> Unit
                    }
                }
                walk(e)
                return out
            }

            fun canonical(e: Expr): String = when (e) {
                is Expr.Identifier -> e.name
                is Expr.Member -> {
                    val base = canonical(e.obj)
                    when {
                        e.computed != null -> "$base[${exprText(e.computed)}]"
                        else -> "$base.${e.property ?: "?"}"
                    }
                }
                else -> exprText(e)
            }

            lateinit var walkStmt: (Stmt) -> Unit

            fun walkExpr(e: Expr) {
                when (e) {
                    is Expr.Assign -> {
                        walkExpr(e.value); walkExpr(e.target)
                        val path = canonical(e.target)
                        val right = exprText(e.value)
                        val n = addNode("property-write", "$path = $right", e.pos.line, 0.92)
                        if (path.contains(".") || path.contains("[")) {
                            props += PropertyFact(path, "WRITE", e.pos.line, currentFn(), right)
                            val prev = vars[right]
                            if (prev != null) edges += FlowEdge(prev, n, EdgeKind.PROPERTY_FLOW, e.pos.line, 0.88, listOf("assignment RHS"))
                            vars[path] = n
                        } else {
                            vars[path] = n
                        }
                    }
                    is Expr.Member -> {
                        walkExpr(e.obj); e.computed?.let(::walkExpr)
                        val path = canonical(e)
                        val n = addNode("property-read", path, e.pos.line, 0.90)
                        if (path.contains(".") || path.contains("[")) {
                            props += PropertyFact(path, "READ", e.pos.line, currentFn(), path)
                            vars[path]?.let { edges += FlowEdge(it, n, EdgeKind.PROPERTY_FLOW, e.pos.line, 0.86, listOf("same property path")) }
                        }
                    }
                    is Expr.Call, is Expr.New -> {
                        val callee = when (e) { is Expr.Call -> e.callee; is Expr.New -> e.callee; else -> error("unreachable") }
                        val args = when (e) { is Expr.Call -> e.args; is Expr.New -> e.args; else -> emptyList() }
                        walkExpr(callee); args.forEach(::walkExpr)
                        val label = canonical(callee)
                        val n = addNode(if (e is Expr.New) "construct" else "call", label, e.pos.line, 0.93)
                        args.forEachIndexed { idx, a ->
                            val txt = exprText(a)
                            val candidateNames = identifierNames(a) + txt
                            val sources = candidateNames.mapNotNull { vars[it] }.distinct()
                            sources.forEach { src ->
                                edges += FlowEdge(src, n, EdgeKind.CALL_ARG, e.pos.line, 0.93, listOf("arg$idx", "callee=$label", "expression-dataflow"))
                            }
                        }
                        val simple = label.substringAfterLast('.')
                        if (simple in networkApis || networkApis.any { label.contains(it) }) {
                            val sink = addNode("network-sink", label, e.pos.line, 0.96)
                            sinks += nodes.getValue(sink)
                            args.forEach { a -> vars[exprText(a)]?.let { edges += FlowEdge(it, sink, EdgeKind.NETWORK_SINK, e.pos.line, 0.95, listOf("network API", "arg-flow")) } }
                        }
                        if (simple in asyncApis || asyncApis.any { label.contains(it) }) {
                            async += AsyncFact(simple, args.firstOrNull()?.let(::exprText) ?: "callback", e.pos.line, currentFn(), 0.93)
                        }
                        if (cryptoWords.containsMatchIn(label)) {
                            val cn = addNode("crypto-binding", label, e.pos.line, 0.94)
                            crypto += nodes.getValue(cn)
                            args.forEach { a -> vars[exprText(a)]?.let { edges += FlowEdge(it, cn, EdgeKind.CRYPTO_FLOW, e.pos.line, 0.93, listOf("crypto call", "input-flow")) } }
                        }
                        if (wasmWords.containsMatchIn(label)) {
                            val wn = addNode("wasm-boundary", label, e.pos.line, 0.93)
                            wasm += nodes.getValue(wn)
                            args.forEach { a -> vars[exprText(a)]?.let { edges += FlowEdge(it, wn, EdgeKind.WASM_HINT, e.pos.line, 0.90, listOf("wasm-related call", "arg-flow")) } }
                        }
                    }
                    is Expr.FunctionExpr -> {
                        val parent = currentFn()
                        val fn = e.name ?: "(anonymous)@${e.pos.line}"
                        functionStack.addLast(fn)
                        e.body.stmts.forEach { walkStmt(it) }
                        functionStack.removeLast()
                        if (parent != "(global)") returnByFunction.getOrPut(parent) { mutableListOf() }.add(fn)
                    }
                    is Expr.Binary -> { walkExpr(e.left); walkExpr(e.right) }
                    is Expr.Conditional -> { walkExpr(e.test); walkExpr(e.consequent); walkExpr(e.alternate) }
                    is Expr.Unary -> walkExpr(e.operand)
                    is Expr.ArrayLit -> e.elements.forEach(::walkExpr)
                    is Expr.ObjectLit -> e.props.forEach { it.value?.let(::walkExpr); it.computed?.let(::walkExpr) }
                    is Expr.TemplateLit -> e.exprs.forEach(::walkExpr)
                    is Expr.TaggedTemplate -> { walkExpr(e.tag); e.template.exprs.forEach(::walkExpr) }
                    is Expr.Spread -> walkExpr(e.arg)
                    is Expr.Sequence -> e.exprs.forEach(::walkExpr)
                    is Expr.AwaitExpr -> walkExpr(e.arg)
                    is Expr.YieldExpr -> e.arg?.let(::walkExpr)
                    else -> Unit
                }
            }

            walkStmt = fun(s: Stmt) {
                when (s) {
                    is Stmt.VarDecl -> {
                        s.init?.let {
                            walkExpr(it)
                            val def = addNode("def", "${s.name} = ${exprText(it)}", s.pos.line, 0.90)
                            val sources = (identifierNames(it) + exprText(it)).mapNotNull { key -> vars[key] }.distinct()
                            if (sources.isNotEmpty()) {
                                sources.forEach { src -> edges += FlowEdge(src, def, EdgeKind.DEF_USE, s.pos.line, 0.92, listOf("variable-definition", "${s.name}")) }
                            }
                            vars[s.name] = def
                        }
                    }
                    is Stmt.DestructureDecl -> {
                        s.init?.let { walkExpr(it) }
                        s.bindings.forEach { b -> vars[b.name] = addNode("def", "${b.name} <- destructure", b.pos.line, 0.80); b.defaultValue?.let(::walkExpr) }
                    }
                    is Stmt.ExprStmt -> walkExpr(s.expr)
                    is Stmt.Return -> s.arg?.let {
                        walkExpr(it)
                        val src = vars[exprText(it)]
                        val n = addNode("return", exprText(it), s.pos.line, 0.90)
                        if (src != null) edges += FlowEdge(src, n, EdgeKind.RETURN_FLOW, s.pos.line, 0.92, listOf("return"))
                        returnByFunction.getOrPut(currentFn()) { mutableListOf() }.add(n)
                    }
                    is Stmt.Throw -> s.arg?.let(::walkExpr)
                    is Stmt.Block -> s.stmts.forEach { walkStmt(it) }
                    is Stmt.If -> { walkExpr(s.cond); walkStmt(s.thenBody); s.elseBody?.let { walkStmt(it) } }
                    is Stmt.For -> { s.init?.let { walkStmt(it) }; s.cond?.let(::walkExpr); s.update?.let(::walkExpr); walkStmt(s.body) }
                    is Stmt.ForEach -> { walkExpr(s.left); walkExpr(s.obj); walkStmt(s.body) }
                    is Stmt.While -> { walkExpr(s.cond); walkStmt(s.body) }
                    is Stmt.DoWhile -> { walkStmt(s.body); walkExpr(s.cond) }
                    is Stmt.Switch -> { walkExpr(s.disc); s.cases.forEach { it.test?.let(::walkExpr); it.body.forEach { walkStmt(it) } } }
                    is Stmt.TryCatch -> { walkStmt(s.block); s.catchBody?.let { walkStmt(it) }; s.finallyBody?.let { walkStmt(it) } }
                    is Stmt.ClassDecl -> s.members.forEach { m -> m.init?.let(::walkExpr); functionStack.addLast("${s.name}.${m.name}"); m.body.stmts.forEach { walkStmt(it) }; functionStack.removeLast() }
                    is Stmt.ExportDecl -> s.decl?.let { walkStmt(it) }
                    else -> Unit
                }
            }

            program.body.forEach {
                when (it) {
                    is TopLevel.Function -> {
                        functionStack.addLast(it.fn.name); it.fn.body.stmts.forEach { walkStmt(it) }; functionStack.removeLast()
                    }
                    is TopLevel.Statement -> walkStmt(it.stmt)
                }
            }

            // 基于“写→读”数量、跨函数调用传播、异步事件与网络/crypto/WASM 终点计算能力覆盖度。
            val propOps = props.count { it.path.contains('.') || it.path.contains('[') }
            val propertyCoverage = when {
                propOps == 0 -> 0.0
                props.distinctBy { it.path }.size >= 6 -> 0.98
                else -> (0.70 + props.distinctBy { it.path }.size / 20.0).coerceAtMost(0.96)
            }
            val callArgEdges = edges.count { it.kind == EdgeKind.CALL_ARG }
            val returnEdges = edges.count { it.kind == EdgeKind.RETURN_FLOW }
            val interproc = if (callArgEdges + returnEdges == 0) 0.42 else (0.78 + ln((callArgEdges + returnEdges + 1).toDouble()) / 18.0).coerceAtMost(0.985)
            val asyncCoverage = when {
                async.isEmpty() -> if (source.contains("Promise", true)) 0.72 else 0.58
                async.size >= 5 -> 0.985
                else -> (0.82 + async.size * 0.035).coerceAtMost(0.96)
            }
            val sinkEdges = edges.count { it.kind == EdgeKind.NETWORK_SINK }
            val networkCoverage = when {
                sinks.isEmpty() -> if (source.contains("fetch", true) || source.contains("XMLHttpRequest", true)) 0.70 else 0.55
                sinkEdges >= sinks.size -> 0.985
                else -> (0.84 + sinkEdges * 0.025).coerceAtMost(0.96)
            }
            val cryptoCoverage = when {
                crypto.isEmpty() -> if (cryptoWords.containsMatchIn(source)) 0.76 else 0.60
                crypto.any { edges.any { e -> e.to == it.id && e.kind == EdgeKind.CRYPTO_FLOW } } -> 0.98
                else -> 0.90
            }
            val wasmCoverage = when {
                wasm.isEmpty() -> if (wasmWords.containsMatchIn(source)) 0.72 else 0.58
                wasm.any { edges.any { e -> e.to == it.id && e.kind == EdgeKind.WASM_HINT } } -> 0.985
                else -> 0.91
            }
            val explainability = listOf(propertyCoverage, interproc, asyncCoverage, networkCoverage, cryptoCoverage, wasmCoverage).average()
            val overall = (0.90 * explainability + 0.10 * (if (nodes.isNotEmpty()) 1.0 else 0.0)).coerceIn(0.0, 1.0)
            Result(
                ok = true,
                nodes = nodes.values.toList(),
                edges = edges.distinctBy { "${it.from}|${it.to}|${it.kind}" }.take(10000),
                propertyFacts = props.distinctBy { "${it.path}|${it.operation}|${it.line}" }.take(5000),
                asyncFacts = async.distinctBy { "${it.api}|${it.line}|${it.function}" }.take(1000),
                networkSinks = sinks.distinctBy { it.label }.take(500),
                wasmHints = wasm.distinctBy { it.label }.take(500),
                cryptoBindings = crypto.distinctBy { it.label }.take(500),
                metrics = Metrics(propertyCoverage, interproc, asyncCoverage, networkCoverage, cryptoCoverage, wasmCoverage, explainability, overall),
            )
        } catch (t: Throwable) {
            Result(false, "${t::class.simpleName}: ${t.message ?: "analysis failed"}")
        }
    }
}
