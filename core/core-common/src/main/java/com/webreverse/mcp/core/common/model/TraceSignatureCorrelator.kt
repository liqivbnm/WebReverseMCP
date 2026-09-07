package com.webreverse.mcp.core.common.model

/**
 * Request↔签名候选关联器 。
 *
 * 以值指纹为硬证据、上下文/父子关系/crypto 命名为软证据，替代“只看时间窗”的签名定位。
 * 输出 top-K 假设，不会错误地把第二候选删除，供后续真实验证收敛。
 */
object TraceSignatureCorrelator {
    data class Candidate(
        val requestSeq: Long,
        val signerSeq: Long,
        val requestName: String,
        val signerName: String,
        val score: Double,
        val evidence: List<String>,
        val matchedFingerprints: List<String>,
        val gapMs: Long,
    )

    data class Report(
        val requests: Int,
        val candidates: List<Candidate>,
        val requestCoverage: Double,
        val strongCoverage: Double,
    )

    fun analyze(events: List<TraceEvent>, endpointContains: String = "", topKPerRequest: Int = 5): Report {
        val ordered = events.sortedBy { it.ts }
        val requests = ordered.filter { it.source == TraceSource.NETWORK && it.kind == TraceKind.REQUEST &&
            (endpointContains.isBlank() || it.name.contains(endpointContains, ignoreCase = true)) }
        val sourceEvents = ordered.filter { it.source != TraceSource.NETWORK && it.values.isNotEmpty() }
        val out = mutableListOf<Candidate>()
        var covered = 0
        var strong = 0
        for (r in requests) {
            val rfp = r.fingerprints
            if (rfp.isEmpty()) continue
            val candidates = sourceEvents.asSequence()
                .filter { it.seq != r.seq && it.ts <= r.ts }
                .mapNotNull { s -> score(s, r) }
                .sortedByDescending { it.score }
                .take(topKPerRequest.coerceIn(1, 10))
                .toList()
            if (candidates.isNotEmpty()) {
                covered++
                if (candidates.first().score >= 0.82) strong++
                out += candidates
            }
        }
        val denom = requests.size.coerceAtLeast(1)
        return Report(requests.size, out.sortedByDescending { it.score }, covered.toDouble() / denom, strong.toDouble() / denom)
    }

    private fun score(source: TraceEvent, request: TraceEvent): Candidate? {
        val common = source.fingerprints.intersect(request.fingerprints)
        if (common.isEmpty()) return null
        val gap = (request.ts - source.ts).coerceAtLeast(0L)
        if (gap > 30_000L) return null
        var score = 0.65
        val evidence = mutableListOf("fingerprint-exact")
        if (source.output?.fingerprint in common) { score += 0.12; evidence += "signer-output-matches-request" }
        if (sameContext(source, request)) { score += 0.10; evidence += "same-context" }
        if (source.parentEventId >= 0 && source.parentEventId == request.parentEventId) { score += 0.04; evidence += "same-parent" }
        if (source.asyncChainId.isNotBlank() && source.asyncChainId == request.asyncChainId) { score += 0.05; evidence += "same-async-chain" }
        if (source.name.contains(Regex("(?i)(sign|signature|encrypt|hash|digest|hmac|crypto|cipher|token)"))) { score += 0.07; evidence += "crypto-name" }
        val timeFactor = (1.0 - gap / 30_000.0).coerceIn(0.0, 1.0)
        score += 0.02 * timeFactor
        return Candidate(request.seq, source.seq, request.name, source.name, score.coerceAtMost(0.995), evidence, common.toList(), gap)
    }

    private fun sameContext(a: TraceEvent, b: TraceEvent): Boolean =
        (a.tabId.isNotBlank() && a.tabId == b.tabId) ||
            (a.frameId.isNotBlank() && a.frameId == b.frameId) ||
            (a.executionContextId.isNotBlank() && a.executionContextId == b.executionContextId)
}
