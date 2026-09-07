package com.webreverse.mcp.workspace.core

import com.webreverse.mcp.core.common.event.BrowserEvent
import com.webreverse.mcp.core.common.event.ConsoleEvent
import com.webreverse.mcp.core.common.event.DebuggerEvent
import com.webreverse.mcp.core.common.event.Event
import com.webreverse.mcp.core.common.event.EventBus
import com.webreverse.mcp.core.common.event.HookEvent
import com.webreverse.mcp.core.common.event.NetworkEvent
import com.webreverse.mcp.core.common.model.TraceEventBuffer
import com.webreverse.mcp.core.common.model.TraceEventParser
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * 证据来源
 */
enum class EvidenceSource(val display: String) {
    NETWORK("Network"),
    HOOK("Hook"),
    DEBUGGER("Debugger"),
    CONSOLE("Console"),
    BROWSER("Browser"),
    SCRIPT("Script"),
    WEBSOCKET("WebSocket"),
    SNAPSHOT("Runtime Snapshot"),
    MANUAL("Manual"),
    PIPELINE("Pipeline"),
}

/** 图谱节点类型（逆向关注对象） */
enum class GraphNodeType(val display: String) {
    PAGE("页面"),
    SCRIPT("脚本"),
    FUNCTION("函数"),
    ENDPOINT("接口"),
    TOKEN("令牌"),
    CRYPTO("加密操作"),
    STORAGE("本地存储"),
    COOKIE("Cookie"),
    WEBSOCKET("WebSocket"),
    UNKNOWN("未知"),
}

/** 图谱边类型（对象间关系） */
enum class GraphEdgeType(val display: String) {
    CONTAINS("包含"),
    CALLS("调用"),
    REQUESTS("发起请求"),
    GENERATES("生成"),
    CONSUMES("消费"),
    READS("读取"),
    WRITES("写入"),
    TRIGGERS("触发"),
    REFERENCES("引用"),
    SIGNS("参与签名/加密"),
    FLOW("流向"),
}

/** 一条证据：某时某地发生的可追溯事实 */
data class Evidence(
    val id: String,
    val timestamp: Long,
    val source: EvidenceSource,
    val tabId: String,
    val kind: String,
    val title: String,
    val data: Map<String, String> = emptyMap(),
    /** P0-5 隔离维度：来源 MCP 会话（缺省全局） */
    val sessionId: String = "",
    /** P0-5 隔离维度：归属工作区 */
    val workspaceId: String = "",
    /* * 证据等级：判定可信度（值指纹=DIRECT 强于 时间窗=WEAK） */
    val grade: EvidenceGrade = EvidenceGrade.SUPPORTING,
    /* * 值指纹集合：该证据涉及流动的值（值哈希关联） */
    val fingerprints: List<String> = emptyList(),
)

/**
 * 证据等级：回答「这条证据多可信」。
 * 逆向结论的置信度传播依赖证据等级：值指纹匹配（A）> 调用栈/执行上下文（B）
 * > 时间窗+字段启发（C）> 纯时间近似（D）。
 */
enum class EvidenceGrade(val display: String, val weight: Double) {
    DIRECT("值级直接证据", 1.0),
    STRONG("强关联证据", 0.75),
    SUPPORTING("支持性证据", 0.5),
    WEAK("弱近似证据", 0.25),
}

/** 图谱节点（不可变，更新时整体替换，weight 即命中/出现次数） */
data class GraphNode(
    val key: String,
    val type: GraphNodeType,
    val label: String,
    val url: String = "",
    val line: Int = 0,
    val weight: Int = 1,
    val firstSeen: Long,
    val lastSeen: Long,
    val sessionId: String = "",
    val workspaceId: String = "",
)

/** 图谱边 */
data class GraphEdge(
    val from: String,
    val to: String,
    val type: GraphEdgeType,
    val weight: Int = 1,
    val evidenceId: String = "",
    val firstSeen: Long,
    val lastSeen: Long,
    val sessionId: String = "",
    val workspaceId: String = "",
)

/**
 * 证据库 + 逆向图谱（ 核心架构）。
 *
 * 实现 "Reverse Graph + Evidence Store"：
 * - 被动层：订阅 EventBus，把网络/Hook/断点/控制台/页面事件自动沉淀为证据与图谱节点，
 *   并做时间窗关联（加密 Hook 命中 ↔ 附近网络请求 => SIGNS 边）；
 * - 主动层：MCP 工具与分析流水线调用 record/addNode/addEdge 写入主动采集的深度数据
 *   （initiator 调用栈、脚本源码搜索、存储快照、运行时暂停现场）。
 *
 * 会话级内存存储（对齐 DevTools 语义），重要结论由流水线写入 Workspace Finding 持久化。
 */
class EvidenceStore(private val eventBus: EventBus) {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val idSeq = AtomicLong(0)

    private val evidenceDeque = ArrayDeque<Evidence>()
    private val nodeMap = ConcurrentHashMap<String, GraphNode>()
    private val edgeMap = ConcurrentHashMap<String, GraphEdge>()

    /* * 邻接索引：nodeKey -> 边 key（out/in 双向），edgesOf/neighborhood O(度) 而非 O(E) */
    private val adjOut = ConcurrentHashMap<String, MutableSet<String>>()
    private val adjIn = ConcurrentHashMap<String, MutableSet<String>>()

    /* * 值指纹倒排索引：fingerprint -> evidence ids（值级关联查询） */
    private val fpEvidence = ConcurrentHashMap<String, java.util.concurrent.CopyOnWriteArrayList<String>>()
    /* * 值指纹 -> 图节点 key（值在哪些节点间流动） */
    private val fpNodes = ConcurrentHashMap<String, MutableSet<String>>()
    /* * 指纹 -> 最早/最晚出现时间（值生命周期） */
    private val fpSpan = ConcurrentHashMap<String, Pair<Long, Long>>()

    /* * 统一追踪事件缓冲（DynamicTracer/WASM/Hook 推送的增量事件留存回放） */
    val traceBuffer = TraceEventBuffer()

    /** 近期加密命中（时间窗关联用）：ts -> (tabId, label, nodeKey) */
    private val recentCrypto = ArrayDeque<Pair<Long, Triple<String, String, String>>>()
    /** 近期请求完成（时间窗关联用）：ts -> (tabId, endpointKey) */
    private val recentRequests = ArrayDeque<Pair<Long, Pair<String, String>>>()

    @Volatile
    private var started = false

    // ---------------- 生命周期 ----------------

    fun start() {
        if (started) return
        started = true
        scope.launch {
            eventBus.events.collect { onEvent(it) }
        }
    }

    // ---------------- 主动写入 API（工具/流水线调用） ----------------

    /**
     * 记录一条证据（自动裁剪超限历史）；可标注归属会话/工作区（P0-5 隔离维度）。
     * [fingerprints] 登记值指纹（值哈希关联），[grade] 标注证据等级。
     */
    fun record(
        source: EvidenceSource,
        tabId: String,
        kind: String,
        title: String,
        data: Map<String, String> = emptyMap(),
        sessionId: String = "",
        workspaceId: String = "",
        grade: EvidenceGrade = EvidenceGrade.SUPPORTING,
        fingerprints: List<String> = emptyList(),
    ): Evidence {
        val ev = Evidence(
            id = "ev-${idSeq.incrementAndGet()}",
            timestamp = System.currentTimeMillis(),
            source = source,
            tabId = tabId,
            kind = kind,
            title = title.take(300),
            data = data.mapValues { it.value.take(400) },
            sessionId = sessionId,
            workspaceId = workspaceId,
            grade = grade,
            fingerprints = fingerprints,
        )
        synchronized(evidenceDeque) {
            evidenceDeque.addLast(ev)
            while (evidenceDeque.size > MAX_EVIDENCE) evidenceDeque.removeFirst()
        }
        for (fp in fingerprints) indexFingerprint(fp, ev.id, ev.timestamp)
        return ev
    }

    /** 登记值指纹出现（evidence 关联 + 生命周期跨度） */
    private fun indexFingerprint(fp: String, evidenceId: String, now: Long) {
        if (fp.isBlank()) return
        fpEvidence.computeIfAbsent(fp) { java.util.concurrent.CopyOnWriteArrayList() }.let {
            if (it.size < 512) it.addIfAbsent(evidenceId)
        }
        fpSpan.compute(fp) { _, old ->
            if (old == null) now to now else minOf(old.first, now) to maxOf(old.second, now)
        }
    }

    /** 声明值指纹流经某图节点（供值级 FLOW 边推理） */
    fun linkFingerprintToNode(fp: String, nodeKey: String) {
        if (fp.isBlank() || nodeKey.isBlank()) return
        fpNodes.getOrPut(fp) { ConcurrentHashMap.newKeySet() }.add(nodeKey)
        // 同指纹流经的节点两两建 FLOW 边（增量：只与已见节点建边，控制 O(n²) 爆炸）
        val peers = fpNodes[fp] ?: return
        for (peer in peers) {
            if (peer != nodeKey) addEdge(peer, nodeKey, GraphEdgeType.FLOW)
        }
    }

    /** 值指纹查询：哪些证据涉及该值 */
    fun evidenceByFingerprint(fp: String): List<Evidence> {
        val ids = fpEvidence[fp] ?: return emptyList()
        val idSet = ids.toHashSet()
        return synchronized(evidenceDeque) { evidenceDeque.filter { it.id in idSet } }
    }

    /** 值指纹查询：哪些图节点流过该值 */
    fun nodesByFingerprint(fp: String): List<GraphNode> =
        fpNodes[fp]?.mapNotNull { nodeMap[it] } ?: emptyList()

    /** 值指纹生命周期（最早/最晚出现时间戳） */
    fun fingerprintSpan(fp: String): Pair<Long, Long>? = fpSpan[fp]

    /** 活跃值指纹 Top（出现证据最多的值 = 关键中间数据） */
    fun topFingerprints(limit: Int = 20): List<Pair<String, Int>> =
        fpEvidence.entries.asSequence()
            .sortedByDescending { it.value.size }
            .take(limit)
            .map { it.key to it.value.size }
            .toList()

    /** 摄取统一追踪事件 JSON（DynamicTracer collectTraceEvents 的输出）到回放缓冲 */
    fun ingestTraceEvents(json: String): Int {
        return try {
            val events = TraceEventParser.parseList(json)
            traceBuffer.appendAll(events)
            // 事件中的指纹顺手登记到图谱索引（值流经函数节点）
            for (ev in events) {
                val fnKey = "fn:${ev.name}"
                for (vr in ev.values) {
                    if (vr.hasFingerprint) linkFingerprintToNode(vr.fingerprint, fnKey)
                }
            }
            events.size
        } catch (_: Throwable) {
            0
        }
    }

    /** 添加/强化节点；可标注归属会话/工作区 */
    fun addNode(
        type: GraphNodeType,
        label: String,
        url: String = "",
        line: Int = 0,
        key: String? = null,
        now: Long = System.currentTimeMillis(),
        sessionId: String = "",
        workspaceId: String = "",
    ): GraphNode {
        val k = key ?: defaultKey(type, label, url, line)
        val fresh = GraphNode(k, type, label.take(200), url, line, 1, now, now, sessionId, workspaceId)
        val node = nodeMap.compute(k) { _, old ->
            old?.copy(weight = old.weight + 1, lastSeen = now) ?: fresh
        } ?: fresh
        trimNodes()
        return node
    }

    /**
     * 添加/强化边；端点节点缺失时自动建 UNKNOWN 占位节点，
     * 保证手动补边（graph.link）与流水线乱序写入不丢关系。
     * 同步维护邻接索引（adjOut/adjIn）。
     */
    fun addEdge(
        fromKey: String,
        toKey: String,
        type: GraphEdgeType,
        evidenceId: String = "",
        now: Long = System.currentTimeMillis(),
        sessionId: String = "",
        workspaceId: String = "",
    ): GraphEdge? {
        if (fromKey == toKey || fromKey.isBlank() || toKey.isBlank()) return null
        ensurePlaceholder(fromKey, now)
        ensurePlaceholder(toKey, now)
        val k = edgeKey(fromKey, toKey, type)
        val fresh = GraphEdge(fromKey, toKey, type, 1, evidenceId, now, now, sessionId, workspaceId)
        val edge = edgeMap.compute(k) { _, old ->
            old?.copy(weight = old.weight + 1, lastSeen = now) ?: fresh
        } ?: fresh
        adjOut.getOrPut(fromKey) { ConcurrentHashMap.newKeySet() }.add(k)
        adjIn.getOrPut(toKey) { ConcurrentHashMap.newKeySet() }.add(k)
        trimEdges()
        return edge
    }

    private fun ensurePlaceholder(key: String, now: Long) {
        if (!nodeMap.containsKey(key)) {
            nodeMap.computeIfAbsent(key) {
                GraphNode(key, GraphNodeType.UNKNOWN, key.removePrefix(keyPrefixOf(key)), firstSeen = now, lastSeen = now)
            }
        }
    }

    // ---------------- 查询 API ----------------

    /** 证据查询：来源/关键词/时间窗过滤 */
    fun queryEvidence(
        source: EvidenceSource? = null,
        keyword: String? = null,
        sinceMs: Long? = null,
        limit: Int = 100,
    ): List<Evidence> = synchronized(evidenceDeque) {
        evidenceDeque.asReversed().asSequence()
            .filter { source == null || it.source == source }
            .filter { sinceMs == null || it.timestamp >= sinceMs }
            .filter {
                keyword.isNullOrBlank() ||
                    it.title.contains(keyword, ignoreCase = true) ||
                    it.data.values.any { v -> v.contains(keyword, ignoreCase = true) }
            }
            .take(limit.coerceIn(1, 500))
            .toList()
    }

    /** 最近证据（时间线） */
    fun timeline(limit: Int = 50): List<Evidence> =
        queryEvidence(limit = limit)

    /** 按会话/工作区过滤证据（P0-5 隔离视图：Investigation/Agent 各自只看到自己的现场） */
    fun evidenceFor(
        sessionId: String? = null,
        workspaceId: String? = null,
        keyword: String? = null,
        limit: Int = 100,
    ): List<Evidence> = synchronized(evidenceDeque) {
        evidenceDeque.asReversed().asSequence()
            .filter { sessionId.isNullOrBlank() || it.sessionId == sessionId }
            .filter { workspaceId.isNullOrBlank() || it.workspaceId == workspaceId }
            .filter {
                keyword.isNullOrBlank() ||
                    it.title.contains(keyword, ignoreCase = true) ||
                    it.data.values.any { v -> v.contains(keyword, ignoreCase = true) }
            }
            .take(limit.coerceIn(1, 500))
            .toList()
    }

    /** 各会话证据量分布（隔离视图一眼可见） */
    fun evidenceCountBySession(): Map<String, Int> = synchronized(evidenceDeque) {
        evidenceDeque.groupingBy { it.sessionId.ifBlank { "global" } }.eachCount()
    }

    /** 节点查询：类型/关键词过滤，按 weight 降序 */
    fun queryNodes(type: GraphNodeType? = null, keyword: String? = null, limit: Int = 100): List<GraphNode> =
        nodeMap.values.asSequence()
            .filter { type == null || it.type == type }
            .filter {
                keyword.isNullOrBlank() ||
                    it.label.contains(keyword, ignoreCase = true) ||
                    it.url.contains(keyword, ignoreCase = true)
            }
            .sortedByDescending { it.weight }
            .take(limit.coerceIn(1, 500))
            .toList()

    fun node(key: String): GraphNode? = nodeMap[key]

    /* * 某节点的邻接边（both 双向）； 走邻接索引 O(度) */
    fun edgesOf(key: String, direction: String = "both"): List<GraphEdge> {
        val edgeKeys = when (direction) {
            "out" -> adjOut[key] ?: emptySet()
            "in" -> adjIn[key] ?: emptySet()
            else -> (adjOut[key] ?: emptySet()) + (adjIn[key] ?: emptySet())
        }
        return edgeKeys.mapNotNull { edgeMap[it] }
            .sortedByDescending { it.weight }
    }

    /* * N 度邻域子图（供 graph.query 展示局部链路）； 邻接索引 BFS */
    fun neighborhood(key: String, depth: Int = 1): Pair<List<GraphNode>, List<GraphEdge>> {
        val visited = mutableSetOf(key)
        var frontier = setOf(key)
        val subEdgeKeys = mutableSetOf<String>()
        repeat(depth.coerceIn(1, 3)) {
            val next = mutableSetOf<String>()
            for (k in frontier) {
                for (ek in (adjOut[k] ?: emptySet()) + (adjIn[k] ?: emptySet())) {
                    val e = edgeMap[ek] ?: continue
                    subEdgeKeys.add(ek)
                    next.add(e.from)
                    next.add(e.to)
                }
            }
            frontier = next - visited
            visited += frontier
        }
        val nodes = visited.mapNotNull { nodeMap[it] }
        return nodes to subEdgeKeys.mapNotNull { edgeMap[it] }
    }

    /** 全库统计（key 全部为 String，可直接序列化为 JSON） */
    fun stats(): Map<String, Any> {
        val evidenceBySource = synchronized(evidenceDeque) {
            evidenceDeque.groupingBy { it.source.name }.eachCount()
        }
        return mapOf(
            "evidenceCount" to evidenceCount(),
            "evidenceBySource" to evidenceBySource,
            "nodeCount" to nodeMap.size,
            "nodesByType" to nodeMap.values.groupingBy { it.type.name }.eachCount(),
            "edgeCount" to edgeMap.size,
            "edgesByType" to edgeMap.values.groupingBy { it.type.name }.eachCount(),
            "firstEvidenceAt" to (synchronized(evidenceDeque) { evidenceDeque.firstOrNull()?.timestamp ?: 0L }),
            "lastEvidenceAt" to (synchronized(evidenceDeque) { evidenceDeque.lastOrNull()?.timestamp ?: 0L }),
        )
    }

    fun evidenceCount(): Int = synchronized(evidenceDeque) { evidenceDeque.size }

    /** 高权重枢纽节点（逆向最有价值的入口） */
    fun topNodes(limit: Int = 20): List<GraphNode> =
        nodeMap.values.sortedByDescending { it.weight }.take(limit)

    fun topEdges(limit: Int = 20): List<GraphEdge> =
        edgeMap.values.sortedByDescending { it.weight }.take(limit)

    fun clear() {
        synchronized(evidenceDeque) {
            evidenceDeque.clear()
            recentCrypto.clear()
            recentRequests.clear()
        }
        nodeMap.clear()
        edgeMap.clear()
        adjOut.clear()
        adjIn.clear()
        fpEvidence.clear()
        fpNodes.clear()
        fpSpan.clear()
        traceBuffer.clear()
    }

    // ---------------- 被动事件沉淀 ----------------

    private fun onEvent(event: Event) {
        runCatching {
            when (event) {
                is NetworkEvent.RequestStarted -> rememberRequestStart(event.tabId, event.url)
                is NetworkEvent.RequestCompleted -> onRequestCompleted(event)
                is NetworkEvent.RequestFailed -> onRequestFailed(event)
                is NetworkEvent.WebSocketFrame -> onWsFrame(event)
                is HookEvent.Triggered -> onHookTriggered(event)
                is DebuggerEvent.BreakpointHit -> onBreakpointHit(event)
                is DebuggerEvent.Paused -> onPaused(event)
                is DebuggerEvent.ScriptParsed -> onScriptParsed(event)
                is ConsoleEvent.Exception -> onConsoleException(event)
                is ConsoleEvent.Message -> onConsoleMessage(event)
                is BrowserEvent.PageFinished -> onPageFinished(event)
                else -> Unit
            }
        }
    }

    private fun rememberRequestStart(tabId: String, url: String) {
        // 关联用：请求开始时刻（completed 事件缺发起时刻，加密命中发生在此之前）
        if (ignoreUrl(url)) return
        synchronized(recentRequests) {
            recentRequests.addLast(Pair(System.currentTimeMillis(), Pair(tabId, endpointKeyOf(url))))
            while (recentRequests.size > CORRELATION_RING) recentRequests.removeFirst()
        }
    }

    private fun onRequestCompleted(e: NetworkEvent.RequestCompleted) {
        if (ignoreUrl(e.url)) return
        val key = endpointKeyOf(e.url)
        addNode(GraphNodeType.ENDPOINT, endpointLabelOf(e.url), url = e.url, key = key)
        record(
            EvidenceSource.NETWORK, e.tabId, "request",
            "请求完成 ${e.url.take(160)} → ${e.status} (${e.durationMs}ms)",
            mapOf("url" to e.url, "status" to e.status.toString(), "durationMs" to e.durationMs.toString()),
        )
        correlateCrypto(e.tabId, key, System.currentTimeMillis())
        synchronized(recentRequests) {
            recentRequests.addLast(Pair(System.currentTimeMillis(), Pair(e.tabId, key)))
            while (recentRequests.size > CORRELATION_RING) recentRequests.removeFirst()
        }
    }

    private fun onRequestFailed(e: NetworkEvent.RequestFailed) {
        if (ignoreUrl(e.url)) return
        record(EvidenceSource.NETWORK, e.tabId, "request_failed", "请求失败 ${e.url.take(160)}: ${e.error}", mapOf("url" to e.url, "error" to e.error))
    }

    private fun onWsFrame(e: NetworkEvent.WebSocketFrame) {
        val key = "ws:${normalizeUrl(e.url)}"
        addNode(GraphNodeType.WEBSOCKET, e.url.take(120), url = e.url, key = key)
        record(
            EvidenceSource.WEBSOCKET, e.tabId, "ws_frame",
            "WS ${e.direction} ${e.url.take(100)}",
            mapOf("direction" to e.direction, "payload" to e.payload.take(400)),
        )
    }

    private fun onHookTriggered(e: HookEvent.Triggered) {
        val text = "${e.ruleName} ${e.target}".lowercase()
        val ev = record(
            EvidenceSource.HOOK, "", "hook_hit",
            "Hook 命中 ${e.ruleName}: ${e.target.take(120)}",
            mapOf("rule" to e.ruleName, "target" to e.target, "payload" to e.payload.take(400)),
        )
        val now = System.currentTimeMillis()
        when {
            isCryptoHint(text) -> {
                val label = e.target.ifBlank { e.ruleName }
                val key = "crypto:${label}"
                addNode(GraphNodeType.CRYPTO, label, key = key, now = now)
                // 时间窗关联：HookEvent 无 tabId，±3s 内任意 Tab 的请求 => SIGNS 边
                // （单 WebView 场景下跨 Tab 误报率极低，命中顺序无关）
                synchronized(recentRequests) {
                    recentRequests.toList().forEach { (ts, req) ->
                        if (kotlin.math.abs(ts - now) <= CORRELATION_WINDOW_MS) {
                            addEdge(key, req.second, GraphEdgeType.SIGNS, ev.id, now)
                        }
                    }
                }
                synchronized(recentCrypto) {
                    recentCrypto.addLast(Pair(now, Triple("", label, key)))
                    while (recentCrypto.size > CORRELATION_RING) recentCrypto.removeFirst()
                }
            }
            isStorageHint(text) -> {
                val label = e.target.ifBlank { e.ruleName }
                val type = if (text.contains("cookie")) GraphNodeType.COOKIE else GraphNodeType.STORAGE
                val key = (if (type == GraphNodeType.COOKIE) "ck:" else "sto:") + label
                addNode(type, label, key = key, now = now)
                addNode(GraphNodeType.FUNCTION, e.target.ifBlank { e.ruleName }, key = "fn:${e.target.ifBlank { e.ruleName }}", now = now)
                addEdge("fn:${e.target.ifBlank { e.ruleName }}", key, GraphEdgeType.WRITES, ev.id, now)
            }
            else -> {
                addNode(GraphNodeType.FUNCTION, e.target.ifBlank { e.ruleName }, key = "fn:${e.target.ifBlank { e.ruleName }}", now = now)
            }
        }
    }

    private fun onBreakpointHit(e: DebuggerEvent.BreakpointHit) {
        val ev = record(
            EvidenceSource.DEBUGGER, e.tabId, "breakpoint_hit",
            "断点命中 ${e.url.take(120)}:${e.line}",
            mapOf("breakpointId" to e.breakpointId, "url" to e.url, "line" to e.line.toString()),
        )
        val now = System.currentTimeMillis()
        val scriptKey = "js:${normalizeUrl(e.url)}"
        addNode(GraphNodeType.SCRIPT, scriptName(e.url), url = e.url, key = scriptKey, now = now)
        if (e.url.isNotBlank()) {
            val fnKey = "fn:@${normalizeUrl(e.url)}:${e.line}"
            addNode(GraphNodeType.FUNCTION, "${scriptName(e.url)}:${e.line}", url = e.url, line = e.line, key = fnKey, now = now)
            addEdge(scriptKey, fnKey, GraphEdgeType.CONTAINS, ev.id, now)
        }
    }

    private fun onPaused(e: DebuggerEvent.Paused) {
        record(
            EvidenceSource.DEBUGGER, e.tabId, "paused",
            "执行暂停 (${e.reason})",
            mapOf("reason" to e.reason, "callFrames" to e.callFrames.take(400)),
        )
    }

    private fun onScriptParsed(e: DebuggerEvent.ScriptParsed) {
        if (e.url.isBlank() || ignoreUrl(e.url)) return
        addNode(GraphNodeType.SCRIPT, scriptName(e.url), url = e.url, key = "js:${normalizeUrl(e.url)}")
    }

    private fun onConsoleException(e: ConsoleEvent.Exception) {
        record(
            EvidenceSource.CONSOLE, e.tabId, "exception",
            "JS 异常: ${e.message.take(160)}",
            mapOf("message" to e.message.take(400), "stack" to e.stack.take(400)),
        )
    }

    private fun onConsoleMessage(e: ConsoleEvent.Message) {
        // 只沉淀 error/warn，避免日志噪声淹没证据库
        if (e.level.lowercase() !in setOf("error", "warning", "warn")) return
        record(EvidenceSource.CONSOLE, e.tabId, "log_${e.level.lowercase()}", "[${e.level}] ${e.text.take(200)}", mapOf("text" to e.text.take(400)))
    }

    private fun onPageFinished(e: BrowserEvent.PageFinished) {
        if (ignoreUrl(e.url)) return
        val key = "page:${normalizeUrl(e.url)}"
        addNode(GraphNodeType.PAGE, e.url.take(120), url = e.url, key = key)
        record(EvidenceSource.BROWSER, e.tabId, "page_load", "页面加载完成 ${e.url.take(160)}", mapOf("url" to e.url))
    }

    /** 请求完成时刻反向关联近期加密命中（双向都查，避免先后顺序问题） */
    private fun correlateCrypto(tabId: String, endpointKey: String, now: Long) {
        val hits = synchronized(recentCrypto) { recentCrypto.toList() }
        hits.forEach { (ts, info) ->
            // HookEvent 无 tabId（记 ""）：时间窗内即关联，不区分 Tab
            if ((info.first.isBlank() || info.first == tabId) && kotlin.math.abs(ts - now) <= CORRELATION_WINDOW_MS) {
                addEdge(info.third, endpointKey, GraphEdgeType.SIGNS)
            }
        }
    }

    // ---------------- 工具函数 ----------------

    private fun trimNodes() {
        if (nodeMap.size > MAX_NODES) {
            nodeMap.values.sortedBy { it.weight }
                .take(nodeMap.size - MAX_NODES)
                .forEach { nodeMap.remove(it.key) }
        }
    }

    private fun trimEdges() {
        if (edgeMap.size > MAX_EDGES) {
            edgeMap.values.sortedBy { it.weight }
                .take(edgeMap.size - MAX_EDGES)
                .forEach { edgeMap.remove(edgeKey(it.from, it.to, it.type)) }
        }
    }

    private fun ignoreUrl(url: String): Boolean =
        url.isBlank() ||
            url.startsWith("data:") ||
            url.startsWith("blob:") ||
            url.startsWith("about:")

    private fun defaultKey(type: GraphNodeType, label: String, url: String, line: Int): String = when (type) {
        GraphNodeType.ENDPOINT -> "ep:$label"
        GraphNodeType.SCRIPT -> "js:${normalizeUrl(url.ifBlank { label })}"
        GraphNodeType.FUNCTION ->
            if (url.isBlank()) "fn:$label" else "fn:$label@${normalizeUrl(url)}:$line"
        GraphNodeType.PAGE -> "page:${normalizeUrl(url.ifBlank { label })}"
        GraphNodeType.TOKEN -> "tok:$label"
        GraphNodeType.CRYPTO -> "crypto:$label"
        GraphNodeType.STORAGE -> "sto:$label"
        GraphNodeType.COOKIE -> "ck:$label"
        GraphNodeType.WEBSOCKET -> "ws:${normalizeUrl(url.ifBlank { label })}"
        GraphNodeType.UNKNOWN -> "uk:$label"
    }

    private fun keyPrefixOf(key: String): String =
        if (key.contains(':')) "${key.substringBefore(':')}:" else ""

    /** 端点 key：URL 归一（去 query），method 不参与 key——
     *  同 path 不同 method 视为同一节点，方法差异体现在证据文本中 */
    private fun endpointKeyOf(url: String): String = "ep:${normalizeUrl(url)}"

    private fun endpointLabelOf(url: String): String {
        val base = normalizeUrl(url)
        return base.take(160)
    }

    /** 去掉 query/fragment，保留 path（端点归一：同 path 不同 query 视为同一节点） */
    private fun normalizeUrl(url: String): String {
        var u = url.substringBefore('#')
        u = u.substringBefore('?')
        return u.ifBlank { url }
    }

    private fun scriptName(url: String): String =
        url.substringAfterLast('/').ifBlank { url }.take(100)

    private fun isCryptoHint(text: String): Boolean =
        listOf("crypto", "encrypt", "decrypt", "sign", "aes", "rsa", "md5", "sha", "hmac", "digest", "subtle").any { it in text }

    private fun isStorageHint(text: String): Boolean =
        listOf("storage", "localstorage", "sessionstorage", "cookie", "indexeddb").any { it in text }

    private fun edgeKey(from: String, to: String, type: GraphEdgeType): String = "$from\u0000$to\u0000$type"

    companion object {
        private const val MAX_EVIDENCE = 4000
        private const val MAX_NODES = 5000
        private const val MAX_EDGES = 8000
        private const val CORRELATION_RING = 300
        private const val CORRELATION_WINDOW_MS = 3000L
    }
}
