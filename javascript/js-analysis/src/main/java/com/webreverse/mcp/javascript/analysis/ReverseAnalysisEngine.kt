package com.webreverse.mcp.javascript.analysis

/**
 * 统一 JS 逆向分析引擎 。
 *
 * 目标不是再提供一个“大扫描器”，而是把现有能力收敛成一个可排序的逆向目标模型：
 * AST/SSA -> CallGraph -> Taint -> Crypto -> API -> FunctionScore。
 * Agent 可以先调用本入口获得“最值得继续追”的函数/接口，再下钻到现有专家工具。
 */
class ReverseAnalysisEngine {

    enum class FindingType { ENDPOINT, CRYPTO, TOKEN_SOURCE, TOKEN_SINK, FUNCTION, OBFUSCATION, WASM_HINT }

    data class Finding(
        val type: FindingType,
        val name: String,
        val line: Int,
        val confidence: Double,
        val reasons: List<String>,
        val nextActions: List<String> = emptyList(),
    )

    data class HotFunction(
        val id: Int,
        val name: String,
        val line: Int,
        val score: Double,
        val reasons: List<String>,
        val callers: Int,
        val callees: Int,
        val taintedFlows: Int,
    )

    data class Report(
        val ok: Boolean,
        val error: String = "",
        val sourceChars: Int = 0,
        val functionCount: Int = 0,
        val endpointCount: Int = 0,
        val cryptoCount: Int = 0,
        val taintFlowCount: Int = 0,
        val hotFunctions: List<HotFunction> = emptyList(),
        val findings: List<Finding> = emptyList(),
        val parserRiskSignals: List<String> = emptyList(),
        val deepReadiness: Double = 0.0,
        val deepMetrics: DeepReverseAnalyzer.Metrics = DeepReverseAnalyzer.Metrics(),
        val intelligence: ReverseIntelligenceEngine.Report = ReverseIntelligenceEngine.Report(false, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, emptyList()),
    )

    fun analyze(source: String, topN: Int = 20): Report {
        if (source.isBlank()) return Report(false, "source 为空")
        return try {
            val ssa = JsSsaBuilder().build(source)
            val cg = JsCallGraphBuilder().build(ssa)
            val taint = TaintEngine().analyze(ssa, cg)
            val crypto = JsCryptoScanner().scan(source)
            val api = ApiDiscoveryEngine().discoverFromJs(source)
            val static = StaticAnalyzer().analyze(source)
            val deep = DeepReverseAnalyzer().analyze(source)
            val parserQuality = JsParserQualityAnalyzer().analyze(source)
            val intelligence = ReverseIntelligenceEngine().analyze(source, maxOf(topN * 3, 60))

            val incoming = HashMap<Int, Int>()
            val outgoing = HashMap<Int, Int>()
            for (e in cg.edges) {
                incoming[e.to] = (incoming[e.to] ?: 0) + 1
                outgoing[e.from] = (outgoing[e.from] ?: 0) + e.count
            }
            val taintByFunc = taint.flows.groupingBy { it.sinkFunc }.eachCount()
            val cryptoLines = crypto.identifications.flatMap { it.lines }.toSet()
            val staticByName = static.funcStats.associateBy { it.name }

            val hot = ssa.functions
                .filter { it.info.id != ssa.global.info.id }
                .map { fn ->
                    val stat = staticByName[fn.info.name]
                    val indeg = incoming[fn.info.id] ?: 0
                    val outdeg = outgoing[fn.info.id] ?: 0
                    val tf = taintByFunc[fn.info.name] ?: 0
                    val cryptoNearby = cryptoLines.count { l -> kotlin.math.abs(l - fn.info.pos.line) <= 8 }
                    var score = 0.0
                    val reasons = mutableListOf<String>()
                    score += minOf(indeg, 12) * 3.0
                    if (indeg > 0) reasons += "被 ${indeg} 个函数调用"
                    score += minOf(outdeg, 10) * 0.8
                    if (tf > 0) { score += minOf(tf, 8) * 6.0; reasons += "存在 $tf 条污点流" }
                    if (cryptoNearby > 0) { score += minOf(cryptoNearby, 6) * 7.0; reasons += "附近命中加密特征" }
                    if (stat?.isSuspect == true) { score += 8.0; reasons += "高复杂度/混淆嫌疑" }
                    if (fn.info.isAsync) { score += 1.5; reasons += "异步函数" }
                    if (fn.info.qualName.isNotBlank()) reasons += "成员函数 ${fn.info.qualName}"
                    HotFunction(fn.info.id, fn.info.name, fn.info.pos.line, score, reasons.distinct().take(8), indeg, outdeg, tf)
                }
                .sortedByDescending { it.score }
                .take(topN.coerceIn(1, 100))

            val findings = mutableListOf<Finding>()
            deep.propertyFacts.take(80).forEach { fact ->
                findings += Finding(
                    FindingType.TOKEN_SOURCE, "${fact.operation} ${fact.path}", fact.line, 0.91,
                    listOf("object/property dataflow", fact.function, fact.expression),
                    listOf("检查同属性 WRITE/READ 对", "继续追踪调用参数", "与 network sink 做值指纹关联"),
                )
            }
            deep.networkSinks.take(40).forEach { sink ->
                findings += Finding(
                    FindingType.TOKEN_SINK, sink.label, sink.line, sink.confidence,
                    listOf("network sink", "deep dataflow"),
                    listOf("reverse.trace", "reverse.value_link", "reverse.validate"),
                )
            }
            deep.cryptoBindings.take(40).forEach { c ->
                findings += Finding(
                    FindingType.CRYPTO, c.label, c.line, c.confidence,
                    listOf("crypto callsite binding", "input-flow edge"),
                    listOf("追踪输入", "绑定请求 header/body", "验证候选公式"),
                )
            }
            deep.wasmHints.take(40).forEach { w ->
                findings += Finding(
                    FindingType.WASM_HINT, w.label, w.line, w.confidence,
                    listOf("JS↔WASM boundary hint", "argument-flow evidence"),
                    listOf("wasm.memory_provenance", "追踪 TypedArray/ptr/len", "验证 WASM 输出"),
                )
            }
            api.endpoints.take(100).forEach { ep ->
                findings += Finding(
                    FindingType.ENDPOINT, "${ep.method} ${ep.url}", ep.line, ep.confidence.coerceIn(0.0, 1.0),
                    listOf("JS API discovery", "caller=${ep.caller}"),
                    listOf("定位 initiator", "追踪请求参数", "检查 header/query/body 是否来自 crypto/token"),
                )
            }
            crypto.identifications.take(30).forEach { id ->
                findings += Finding(
                    FindingType.CRYPTO, id.algorithm, id.lines.firstOrNull() ?: 0, id.confidence / 100.0,
                    id.evidence.take(4), listOf("反查 callers", "追踪输入/输出指纹", "与 network request 做值级关联"),
                )
            }
            taint.flows.take(60).forEach { flow ->
                val type = if (flow.sinkLabel.contains("fetch", true) || flow.sinkLabel.contains("header", true)) FindingType.TOKEN_SINK else FindingType.TOKEN_SOURCE
                findings += Finding(type, "${flow.sourceLabel} -> ${flow.sinkLabel}", flow.sinkLine, severityConfidence(flow.severity), flow.transforms.take(6), listOf("reverse.value_link", "reverse.trace", "reverse.validate"))
            }
            hot.take(10).forEach { fn ->
                findings += Finding(FindingType.FUNCTION, fn.name, fn.line, (fn.score / 100.0).coerceIn(0.05, 0.99), fn.reasons, listOf("reverse.trace target=${fn.name}", "检查调用者/被调用者", "执行 SSA/taint 下钻"))
            }
            parserRiskSignals(source).forEach { signal ->
                findings += Finding(FindingType.OBFUSCATION, signal, 0, 0.55, listOf("syntax/obfuscation heuristic"), listOf("先做 beautify/source-map", "再做 AST/SSA"))
            }
            if (Regex("(?i)WebAssembly|\\.wasm|WebAssembly\\.instantiate|WebAssembly\\.Instance").containsMatchIn(source)) {
                findings += Finding(FindingType.WASM_HINT, "JS↔WASM boundary", 0, 0.75, listOf("detected WebAssembly usage"), listOf("wasm.provenance", "wasm.import_boundary", "追踪 TypedArray -> memory -> export"))
            }

            Report(true, sourceChars = source.length, functionCount = ssa.functions.size, endpointCount = api.endpoints.size + intelligence.endpointsRecovered, cryptoCount = crypto.identifications.size + intelligence.cryptoSignals, taintFlowCount = taint.flows.size, hotFunctions = hot, findings = findings.sortedByDescending { it.confidence }.take(300), parserRiskSignals = (parserRiskSignals(source) + parserQuality.suspiciousConstructs + parserQuality.lexicalErrors).distinct(), deepReadiness = maxOf(deep.metrics.overallReadiness, intelligence.readiness), deepMetrics = deep.metrics, intelligence = intelligence)
        } catch (t: Throwable) {
            val fallback = runCatching { ReverseIntelligenceEngine().analyze(source, maxOf(topN * 3, 60)) }.getOrNull()
            Report(false, error = "${t::class.simpleName}: ${t.message ?: "analysis failed"}", sourceChars = source.length, endpointCount = fallback?.endpointsRecovered ?: 0, cryptoCount = fallback?.cryptoSignals ?: 0, parserRiskSignals = listOf("AST/SSA 主链失败，已启用 raw-source intelligence fallback"), intelligence = fallback ?: ReverseIntelligenceEngine.Report(false, source.length, source.count { it == '\n' } + 1, 0, 0, 0, 0, 0, 0, 0, 0, emptyList()))
        }
    }

    private fun severityConfidence(s: TaintEngine.Severity): Double = when (s) {
        TaintEngine.Severity.CRITICAL -> 0.96
        TaintEngine.Severity.HIGH -> 0.88
        TaintEngine.Severity.MEDIUM -> 0.72
        TaintEngine.Severity.LOW -> 0.58
    }

    private fun parserRiskSignals(source: String): List<String> {
        val out = mutableListOf<String>()
        val patterns = linkedMapOf(
            "JSX-like syntax" to Regex("<([A-Za-z][A-Za-z0-9]*)[^>]*>"),
            "TypeScript annotations" to Regex("\\b(?:interface|type|enum|namespace)\\s+[A-Za-z_$]"),
            "decorators" to Regex("(^|\\n)\\s*@[@A-Za-z_$]"),
            "dynamic import" to Regex("\\bimport\\s*\\("),
            "Proxy/metaprogramming" to Regex("\\b(?:Proxy|Reflect)\\b"),
            "eval-heavy dynamic code" to Regex("(?i)\\b(?:eval|new Function|Function)\\s*\\("),
        )
        patterns.forEach { (name, re) -> if (re.containsMatchIn(source)) out += name }
        return out
    }
}
