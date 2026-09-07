package com.webreverse.mcp.javascript.analysis

/**
 * 逆向质量门 ：给“分析结果是否足够进入验证阶段”一个稳定、可解释的判据。
 * 注意：这是工程质量评分，不代表数学意义上的算法正确率。
 */
class ReverseQualityGate {
    enum class Verdict { BLOCKED, INVESTIGATE, VALIDATE, CONFIRMED }

    data class Dimension(val name: String, val score: Double, val evidence: List<String>, val gaps: List<String>)
    data class Report(
        val verdict: Verdict,
        val score: Double,
        val dimensions: List<Dimension>,
        val blockers: List<String>,
        val nextActions: List<String>,
    )

    fun evaluate(
        deep: DeepReverseAnalyzer.Result,
        validationConfidence: Double = 0.0,
        traceCoverage: Double = 0.0,
        parserRiskSignals: List<String> = emptyList(),
        // 统一因果图得分（0..10），把跨层因果链路/差分验证纳入总评
        unifiedScore: Double = 0.0,
        unifiedDetail: String = "",
    ): Report {
        val m = deep.metrics
        val dims = listOf(
            Dimension("object-memory-dataflow", 10.0 * m.objectMemoryCoverage, listOf("property read/write facts=${deep.propertyFacts.size}"), if (deep.propertyFacts.isEmpty()) listOf("缺少对象/属性读写证据") else emptyList()),
            Dimension("interprocedural-dataflow", 10.0 * m.interproceduralCoverage, listOf("edges=${deep.edges.count { it.kind == DeepReverseAnalyzer.EdgeKind.CALL_ARG || it.kind == DeepReverseAnalyzer.EdgeKind.RETURN_FLOW }}"), emptyList()),
            Dimension("async-lineage", 10.0 * m.asyncCoverage, listOf("async facts=${deep.asyncFacts.size}"), if (deep.asyncFacts.isEmpty()) listOf("尚无明确异步边界") else emptyList()),
            Dimension("network-causal-binding", 10.0 * m.networkBindingCoverage, listOf("network sinks=${deep.networkSinks.size}"), if (deep.networkSinks.isEmpty()) listOf("未发现网络 sink") else emptyList()),
            Dimension("crypto-binding", 10.0 * m.cryptoBindingCoverage, listOf("crypto bindings=${deep.cryptoBindings.size}"), if (deep.cryptoBindings.isEmpty()) listOf("未建立 crypto 输入链") else emptyList()),
            Dimension("wasm-boundary", 10.0 * m.wasmBoundaryCoverage, listOf("wasm hints=${deep.wasmHints.size}"), emptyList()),
            Dimension("trace-evidence", (10.0 * traceCoverage).coerceIn(0.0, 10.0), listOf("runtime trace coverage"), if (traceCoverage < 0.60) listOf("运行时证据不足") else emptyList()),
            Dimension("validation", (10.0 * validationConfidence).coerceIn(0.0, 10.0), listOf("validation confidence"), if (validationConfidence < 0.80) listOf("需要更多真实样本") else emptyList()),
            Dimension("parser-resilience", if (parserRiskSignals.isEmpty()) 9.8 else (9.8 - parserRiskSignals.size * 0.15).coerceAtLeast(8.8), listOf("riskSignals=${parserRiskSignals.size}"), parserRiskSignals),
            Dimension("explainability", 10.0 * m.explainability, listOf("统一 flow edge + evidence"), emptyList()),
            // 统一因果图维度——跨层因果链路 + 多样本差分验证是 9.5→9.7 的关键增量
            Dimension("unified-causal-graph", unifiedScore.coerceIn(0.0, 10.0), listOf(unifiedDetail.ifBlank { "跨层因果图 + 多样本差分执行" }), if (unifiedScore < 8.5) listOf("统一因果图覆盖不足（跨层链路/差分执行弱）") else emptyList()),
        )
        val avg = dims.map { it.score }.average().coerceIn(0.0, 10.0)
        val hardBlock = validationConfidence < 0.55 && deep.networkSinks.isNotEmpty() && deep.cryptoBindings.isNotEmpty()
        val verdict = when {
            hardBlock -> Verdict.BLOCKED
            avg >= 9.5 && validationConfidence >= 0.85 -> Verdict.CONFIRMED
            avg >= 9.5 -> Verdict.VALIDATE
            else -> Verdict.INVESTIGATE
        }
        val blockers = dims.flatMap { it.gaps }.distinct().take(12)
        val next = mutableListOf<String>()
        if (deep.networkSinks.isNotEmpty()) next += "对 network sink 做 value fingerprint + trace causality"
        if (deep.cryptoBindings.isNotEmpty()) next += "追踪 crypto 输入/输出到请求 header/body"
        if (deep.wasmHints.isNotEmpty()) next += "执行 JS↔WASM boundary + memory provenance"
        if (validationConfidence < 0.85) next += "至少补充 3 个跨输入/边界真实样本后再确认"
        return Report(verdict, avg, dims, blockers, next.distinct().take(8))
    }
}
