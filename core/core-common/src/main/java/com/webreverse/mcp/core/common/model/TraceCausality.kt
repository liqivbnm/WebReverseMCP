package com.webreverse.mcp.core.common.model

/**
 * Trace 因果推理 。
 *
 * 把“事件时间线”提升为“有证据等级的因果图”：
 * - parentEventId：显式父子关系；
 * - fingerprint：值级同源关系；
 * - asyncChainId：异步链内时序关系；
 * - executionContext/tab/frame：现场一致性；
 * - stackTop/scriptUrl：调用现场一致性。
 *
 * 该类不修改原始 TraceEvent，只产生可供 EvidenceStore/MCP 消费的解释结果。
 */
object TraceCausality {

    enum class Relation { PARENT, VALUE_FLOW, ASYNC_CONTINUATION, CONTEXT, CALLSITE }

    data class Edge(
        val fromSeq: Long,
        val toSeq: Long,
        val relation: Relation,
        val score: Double,
        val evidence: List<String>,
    )

    data class Path(
        val rootSeq: Long,
        val leafSeq: Long,
        val events: List<TraceEvent>,
        val edges: List<Edge>,
        val confidence: Double,
        val explanation: String,
    )

    fun build(events: List<TraceEvent>, maxEdges: Int = 5000): List<Edge> {
        if (events.size < 2) return emptyList()
        val bySeq = events.associateBy { it.seq }
        val result = ArrayList<Edge>(minOf(maxEdges, events.size * 2))
        val ordered = events.sortedBy { it.seq }

        // 1) 显式 parent 优先级最高。
        for (e in ordered) {
            val p = bySeq[e.parentEventId] ?: continue
            result += Edge(p.seq, e.seq, Relation.PARENT, 1.0, listOf("parentEventId"))
            if (result.size >= maxEdges) return result
        }

        // 2) 同指纹值流：只连接最近的前一个事件，避免 O(n²)。
        val lastByFp = HashMap<String, TraceEvent>()
        for (e in ordered) {
            for (fp in e.fingerprints) {
                val prev = lastByFp[fp]
                if (prev != null && prev.seq != e.seq && prev.ts <= e.ts) {
                    val evidence = mutableListOf("fingerprint:$fp")
                    if (sameContext(prev, e)) evidence += "same-context"
                    if (prev.asyncChainId.isNotBlank() && prev.asyncChainId == e.asyncChainId) evidence += "same-async-chain"
                    val score = (0.72 + (if (sameContext(prev, e)) 0.13 else 0.0) + (if (prev.asyncChainId.isNotBlank() && prev.asyncChainId == e.asyncChainId) 0.10 else 0.0)).coerceAtMost(0.98)
                    result += Edge(prev.seq, e.seq, Relation.VALUE_FLOW, score, evidence)
                    if (result.size >= maxEdges) return result
                }
                lastByFp[fp] = e
            }
        }

        // 3) 异步链续接：只连相邻事件；时间倒序不产生边。
        val lastByChain = HashMap<String, TraceEvent>()
        for (e in ordered) {
            val chain = e.asyncChainId
            if (chain.isBlank()) continue
            val prev = lastByChain[chain]
            if (prev != null && prev.seq != e.seq && prev.ts <= e.ts) {
                val evidence = mutableListOf("asyncChainId:$chain")
                if (e.asyncTrigger != AsyncTrigger.NONE) evidence += "trigger:${e.asyncTrigger.name}"
                result += Edge(prev.seq, e.seq, Relation.ASYNC_CONTINUATION, 0.78, evidence)
                if (result.size >= maxEdges) return result
            }
            lastByChain[chain] = e
        }

        // 4) 同现场调用关联：只连接非常接近的事件，作为 supporting edge。
        for (i in 1 until ordered.size) {
            val a = ordered[i - 1]
            val b = ordered[i]
            if (b.ts < a.ts || b.ts - a.ts > 250) continue
            if (!sameContext(a, b)) continue
            if (a.stackTop.isBlank() || b.stackTop.isBlank()) continue
            val sameScript = a.scriptUrl.isNotBlank() && a.scriptUrl == b.scriptUrl
            val sameFrame = a.frameId.isNotBlank() && a.frameId == b.frameId
            if (sameScript || sameFrame) {
                val score = if (sameScript && sameFrame) 0.64 else 0.52
                result += Edge(a.seq, b.seq, Relation.CALLSITE, score, listOf("close-time", "same-context", if (sameScript) "same-script" else "same-frame"))
                if (result.size >= maxEdges) return result
            }
        }
        return result
    }

    @Synchronized
    fun findPaths(events: List<TraceEvent>, targetSeq: Long, maxDepth: Int = 24): List<Path> {
        val bySeq = events.associateBy { it.seq }
        val target = bySeq[targetSeq] ?: return emptyList()
        val edges = build(events)
        val incoming = edges.groupBy { it.toSeq }
        val result = mutableListOf<Path>()
        val visited = HashSet<Long>()

        fun dfs(cur: TraceEvent, pathEvents: MutableList<TraceEvent>, pathEdges: MutableList<Edge>) {
            if (pathEvents.size > maxDepth || !visited.add(cur.seq)) return
            val incomingEdges = incoming[cur.seq].orEmpty()
            if (incomingEdges.isEmpty()) {
                val confidence = pathEdges.fold(1.0) { acc, e -> acc * e.score }.pow(1.0 / maxOf(1, pathEdges.size))
                result += Path(
                    rootSeq = cur.seq,
                    leafSeq = target.seq,
                    events = pathEvents.asReversed(),
                    edges = pathEdges.asReversed(),
                    confidence = confidence,
                    explanation = explain(pathEdges),
                )
                visited.remove(cur.seq)
                return
            }
            for (edge in incomingEdges.sortedByDescending { it.score }.take(6)) {
                val prev = bySeq[edge.fromSeq] ?: continue
                pathEvents.add(prev)
                pathEdges.add(edge)
                dfs(prev, pathEvents, pathEdges)
                pathEdges.removeAt(pathEdges.lastIndex)
                pathEvents.removeAt(pathEvents.lastIndex)
            }
            visited.remove(cur.seq)
        }

        dfs(target, mutableListOf(target), mutableListOf())
        return result.sortedByDescending { it.confidence }.take(8)
    }

    private fun explain(edges: List<Edge>): String {
        if (edges.isEmpty()) return "单点事件，无可回溯因果边"
        val parts = edges.groupingBy { it.relation }.eachCount().entries
            .sortedByDescending { it.value }
            .joinToString(" + ") { "${it.key.name.lowercase()}×${it.value}" }
        return "因果路径由 $parts 组成；优先信任 parent/fingerprint 边，时间窗仅作为辅助。"
    }

    private fun sameContext(a: TraceEvent, b: TraceEvent): Boolean {
        val tab = a.tabId.isNotBlank() && b.tabId.isNotBlank() && a.tabId == b.tabId
        val frame = a.frameId.isNotBlank() && b.frameId.isNotBlank() && a.frameId == b.frameId
        val exec = a.executionContextId.isNotBlank() && b.executionContextId.isNotBlank() && a.executionContextId == b.executionContextId
        return tab || frame || exec
    }

    private fun Double.pow(exp: Double): Double = kotlin.math.exp(kotlin.math.ln(coerceAtLeast(1e-12)) * exp)
}
