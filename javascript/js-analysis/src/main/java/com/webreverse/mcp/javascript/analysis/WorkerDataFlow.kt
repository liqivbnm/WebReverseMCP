package com.webreverse.mcp.javascript.analysis

/** Worker/iframe/ServiceWorker 跨上下文数据流 + 运行时 Trace lineage 归并。 */
class WorkerDataFlow {
    enum class ContextKind { PAGE, DEDICATED_WORKER, SHARED_WORKER, SERVICE_WORKER, IFRAME, UNKNOWN }
    enum class ChannelKind { POST_MESSAGE, MESSAGE_PORT, SERVICE_WORKER, CLIENTS, BROADCAST_CHANNEL, IMPORT_SCRIPTS }

    data class Context(val id: String, val kind: ContextKind, val script: String = "", val line: Int = 0)
    data class Channel(val from: String, val to: String, val kind: ChannelKind, val label: String, val line: Int, val confidence: Double)
    data class Flow(val from: String, val to: String, val value: String, val line: Int, val confidence: Double, val evidence: List<String>)
    data class Report(val ok: Boolean, val contexts: List<Context> = emptyList(), val channels: List<Channel> = emptyList(), val flows: List<Flow> = emptyList(), val precision: Double = 0.0, val warnings: List<String> = emptyList(), val error: String = "")

    fun analyze(source: String): Report {
        val contexts = mutableListOf(Context("page", ContextKind.PAGE))
        val channels = mutableListOf<Channel>()
        val flows = mutableListOf<Flow>()
        val lines = source.lines()
        lines.forEachIndexed { i, raw ->
            val line = raw.trim()
            when {
                Regex("new\\s+Worker\\(").containsMatchIn(line) -> {
                    val id = "worker${contexts.count { it.kind == ContextKind.DEDICATED_WORKER } + 1}"
                    val url = Regex("new\\s+Worker\\(\\s*[\\\"']([^\\\"']+)").find(line)?.groupValues?.getOrNull(1).orEmpty()
                    contexts += Context(id, ContextKind.DEDICATED_WORKER, url, i + 1)
                }
                Regex("new\\s+SharedWorker\\(").containsMatchIn(line) -> contexts += Context("shared${contexts.count { it.kind == ContextKind.SHARED_WORKER } + 1}", ContextKind.SHARED_WORKER, line, i + 1)
                Regex("serviceWorker\\.register\\(").containsMatchIn(line) -> contexts += Context("sw${contexts.count { it.kind == ContextKind.SERVICE_WORKER } + 1}", ContextKind.SERVICE_WORKER, line, i + 1)
                Regex("<iframe|createElement\\(\\s*[\\\"']iframe", RegexOption.IGNORE_CASE).containsMatchIn(line) -> contexts += Context("iframe${contexts.count { it.kind == ContextKind.IFRAME } + 1}", ContextKind.IFRAME, line, i + 1)
            }
            if (line.contains("postMessage(")) {
                val dst = if (line.contains("window.parent") || line.contains("parent.postMessage")) "page" else contexts.lastOrNull { it.kind != ContextKind.PAGE }?.id ?: "unknown"
                channels += Channel("page", dst, ChannelKind.POST_MESSAGE, line.take(140), i + 1, 0.88)
                val value = Regex("postMessage\\(\\s*([^,\\)]+)").find(line)?.groupValues?.getOrNull(1)
                if (!value.isNullOrBlank()) flows += Flow("page", dst, value, i + 1, 0.86, listOf("postMessage argument"))
            }
            if (Regex("onmessage\\s*=|addEventListener\\(\\s*[\\\"']message").containsMatchIn(line)) {
                val dst = contexts.lastOrNull { it.kind != ContextKind.PAGE }?.id ?: "page"
                flows += Flow("message", dst, "event.data", i + 1, 0.84, listOf("message event data"))
            }
            if (line.contains("navigator.serviceWorker.controller") || line.contains("clients.matchAll")) {
                channels += Channel("service-worker", "page", ChannelKind.SERVICE_WORKER, line.take(140), i + 1, 0.82)
            }
            if (line.contains("new BroadcastChannel(")) channels += Channel("broadcast", "broadcast", ChannelKind.BROADCAST_CHANNEL, line.take(140), i + 1, 0.86)
            if (line.contains("importScripts(")) channels += Channel("worker", "worker", ChannelKind.IMPORT_SCRIPTS, line.take(140), i + 1, 0.95)
        }
        if (contexts.size == 1 && channels.isEmpty()) return Report(true, contexts, precision = 1.0)
        val precision = (channels.map { it.confidence }.average().takeIf { !it.isNaN() } ?: 1.0) * 0.8 + 0.2
        return Report(true, contexts, channels.distinct(), flows.distinct(), precision.coerceIn(0.0, 1.0),
            warnings = listOfNotNull(if (flows.any { it.from == "message" }) "message event 的生产者需要 runtime parentEventId/fingerprint 才能完成确定性绑定" else null))
    }

    fun mergeRuntimeLineage(events: List<com.webreverse.mcp.core.common.model.TraceEvent>, maxDepth: Int = 32): List<Flow> {
        val bySeq = events.associateBy { it.seq }
        val out = mutableListOf<Flow>()
        for (e in events) {
            if (e.kind != com.webreverse.mcp.core.common.model.TraceKind.CUSTOM && e.kind != com.webreverse.mcp.core.common.model.TraceKind.CALL) continue
            if (e.parentEventId < 0 && e.asyncChainId.isBlank()) continue
            val parent = bySeq[e.parentEventId]
            if (parent != null) {
                val shared = parent.fingerprints.intersect(e.fingerprints)
                val conf = if (shared.isNotEmpty()) 0.98 else if (parent.asyncChainId.isNotBlank() && parent.asyncChainId == e.asyncChainId) 0.86 else 0.68
                out += Flow(parent.name, e.name, shared.firstOrNull().orEmpty(), e.line, conf, listOf("parentEventId", "asyncChainId"))
            }
            var cur = e
            var d = 0
            while (cur.parentEventId >= 0 && d++ < maxDepth) {
                val p = bySeq[cur.parentEventId] ?: break
                val shared = p.fingerprints.intersect(cur.fingerprints)
                if (shared.isNotEmpty()) out += Flow(p.name, e.name, shared.first(), e.line, 0.995, listOf("multi-hop fingerprint chain"))
                cur = p
            }
        }
        return out.distinctBy { listOf(it.from, it.to, it.value, it.line) }.sortedByDescending { it.confidence }
    }
}
