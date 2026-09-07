package com.webreverse.mcp.devtools.network

import android.util.Base64
import com.webreverse.mcp.browser.engine.BrowserEngine
import com.webreverse.mcp.devtools.protocol.cdp.CdpEvent
import com.webreverse.mcp.devtools.protocol.cdp.CdpHub
import com.webreverse.mcp.devtools.protocol.cdp.CdpSession
import com.webreverse.mcp.devtools.protocol.cdp.CdpTransport
import com.webreverse.mcp.devtools.protocol.cdp.RawWebSocket
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/**
 * CDP 网络监控（DevTools Network 面板语义）。
 *
 * 与注入式 Hook（fetch/XHR monkey patch）的差别：
 * - 覆盖所有请求（图片/字体/脚本/beacon/service worker），不仅是 JS 发起的
 * - 可回取任意已完成请求的响应体（Network.getResponseBody），含跨域资源
 * - 记录 fromCache / remoteIPAddress / 协议等元数据
 *
 * 连接策略：优先经 CDP 复用枢纽，与 CdpDebuggerSession 等进程内 MCP 会话
 * 共享同一条后端 CDP 会话——调试与网络监控同时接入同一页面互不踢线；
 * 枢纽不可用时回退直连（独立会话，Chromium 支持同 target 多客户端）。
 */
object CdpNetworkMonitor {

    /* * ：幂等 CDP 命令（Network.enable/Network.setCacheDisabled）的瞬时超时重试次数 */
    private const val CDP_RETRIES = 2

    /** 单条 CDP 网络请求 */
    data class CdpRequestInfo(
        val requestId: String,
        val url: String,
        val method: String = "",
        val resourceType: String = "",
        val status: Int = 0,
        val mimeType: String = "",
        val requestHeaders: Map<String, String> = emptyMap(),
        val responseHeaders: Map<String, String> = emptyMap(),
        val postData: String? = null,
        val finished: Boolean = false,
        val failed: Boolean = false,
        val errorText: String? = null,
        val size: Long = 0,
        val fromCache: Boolean = false,
        val remoteAddress: String? = null,
        val initiatorUrl: String = "",
        // CDP 原生 initiator（Network.requestWillBeSent.initiator）
        val initiatorType: String = "",
        val initiatorStack: String = "",
        // 发起链构建要素——栈顶帧脚本 URL（script 发起时指向加载脚本本体）、
        // 重定向原始 URL（redirectResponse，链上标注跳转来源）
        val initiatorScriptUrl: String = "",
        val redirectedFromUrl: String = "",
        // CDP ResourceTiming（Network.responseReceived.response.timing）——
        // 供 network.timing 在传入 CDP requestId 时回退，避免 ENTRY_NOT_FOUND。
        // 跨域/缓存/附加过晚时 CDP 只暴露部分字段，hasData=false 时上层按“无时序”提示。
        val timing: CdpTiming = CdpTiming(),
        // 协议版本透传（Network.responseReceived.response.protocol）——
        // http/1.1 / h2 / h3，让 AI 直接识别请求走的 HTTP 版本（含 QUIC/HTTP3）。
        val protocol: String = "",
        // gRPC 识别（响应头 Content-Type: application/grpc）——
        // gRPC 走 HTTP/2 二进制通道，标记后便于针对性解析 protobuf 帧。
        val isGrpc: Boolean = false,
    )

    /**
     * CDP ResourceTiming → 与注入式 [com.webreverse.mcp.core.common.model.Timing]
     * 同构的毫秒序列。CDP 语义：`requestTime` 为基准（秒），其余阶段字段是相对该
     * 基准的秒级 delta；同源请求才有完整数据，跨域/缓存命中往往为 0。
     */
    data class CdpTiming(
        val dns: Long = 0,
        val connect: Long = 0,
        val ssl: Long = 0,
        val ttfb: Long = 0,
        val download: Long = 0,
        val total: Long = 0,
        val hasData: Boolean = false,
    ) {
        companion object {
            fun parse(timing: JsonObject?): CdpTiming {
                timing ?: return CdpTiming()
                fun rel(name: String): Double =
                    timing[name]?.jsonPrimitive?.contentOrNull?.toDoubleOrNull() ?: 0.0
                val dnsS = rel("dnsStart"); val dnsE = rel("dnsEnd")
                val conS = rel("connectStart"); val conE = rel("connectEnd")
                val sslS = rel("sslStart"); val sslE = rel("sslEnd")
                val sendS = rel("sendStart"); val sendE = rel("sendEnd")
                val recvE = rel("receiveHeadersEnd")
                fun ms(delta: Double) = (delta * 1000).toLong().coerceAtLeast(0L)
                val has = recvE > 0 && (sendE > 0 || sendS > 0)
                return CdpTiming(
                    dns = if (dnsE > dnsS) ms(dnsE - dnsS) else 0,
                    connect = if (conE > conS) ms(conE - conS) else 0,
                    ssl = if (sslE > sslS) ms(sslE - sslS) else 0,
                    ttfb = if (recvE > sendS) ms(recvE - sendS) else 0,
                    total = if (recvE > 0) ms(recvE) else 0, // 起始终端到响应头完成
                    download = if (recvE > 0) 0 else 0,       // CDP 无下载阶段，置 0 由上层提示
                    hasData = has,
                )
            }
        }
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    @Volatile
    private var session: CdpSession? = null

    private var collector: kotlinx.coroutines.Job? = null

    private val _requests = MutableStateFlow<List<CdpRequestInfo>>(emptyList())
    val requests: StateFlow<List<CdpRequestInfo>> = _requests.asStateFlow()

    // ================= Fetch 域请求拦截 =================

    /** 被拦截暂停中的请求（Fetch.requestPaused，等待 continue/mock/abort 决策） */
    data class PausedRequest(
        val fetchId: String,
        val networkRequestId: String,
        val url: String,
        val method: String,
        val headers: Map<String, String>,
        val postData: String?,
        val resourceType: String,
        val pausedAt: Long = System.currentTimeMillis(),
    )

    private val _pausedRequests = MutableStateFlow<List<PausedRequest>>(emptyList())
    val pausedRequests: StateFlow<List<PausedRequest>> = _pausedRequests.asStateFlow()

    // ================= WebSocket 帧捕获 =================

    /** 一条 WS 数据帧（opcode 1=文本原样 / 2=二进制 payload 为 base64） */
    data class WsFrame(
        val requestId: String,
        val url: String,
        val direction: String, // send / receive
        val opcode: Int,
        val payload: String,
        val timestamp: Long = System.currentTimeMillis(),
    )

    /**
     * WS 二进制帧三视图（对齐桌面 DevTools 的 HEX / base64 / UTF-8 展示）。
     * CDP 对二进制帧（opcode 2）以 base64 形式下发 payloadData，本视图把它还原为
     * 十六进制、原始 base64、UTF-8 文本三种可读形态，供 AI 直接阅读二进制协议。
     */
    data class WsBinaryView(
        val hex: String,
        val base64: String,
        val utf8: String,
        val length: Int,
    )

    /** 解码 WS 二进制帧 payload（base64: 前缀）为三视图；非 base64 或解码失败返回 null */
    fun decodeWsBinary(payload: String): WsBinaryView? {
        val b64 = payload.removePrefix("base64:")
        val bytes = runCatching { Base64.decode(b64, Base64.DEFAULT) }.getOrNull() ?: return null
        val hex = bytes.joinToString(" ") { "%02X".format(it) }
        val utf8 = String(bytes, Charsets.UTF_8)
            .map { c -> if (c.code < 0x20 || c.code == 0x7F) '.' else c }
            .joinToString("")
        return WsBinaryView(hex = hex, base64 = b64, utf8 = utf8, length = bytes.size)
    }

    /** requestId -> WS URL（webSocketCreated 登记，closed 移除） */
    private val wsUrls = java.util.concurrent.ConcurrentHashMap<String, String>()

    private val _wsFrames = MutableStateFlow<List<WsFrame>>(emptyList())
    val wsFrames: StateFlow<List<WsFrame>> = _wsFrames.asStateFlow()

    // ================= SSE / WS 连接级信息 =================

    /** 一条 SSE（EventSource）推送消息（Network.eventSourceMessageReceived） */
    data class SseMessage(
        val requestId: String,
        val url: String,
        val eventName: String,
        val eventId: String,
        val data: String,
        val timestamp: Long = System.currentTimeMillis(),
    )

    /** 一条 WS 连接（握手请求/响应头 + 关闭码/原因，webSocketCreated 起维护） */
    data class WsConnection(
        val requestId: String,
        val url: String,
        val requestHeaders: Map<String, String> = emptyMap(),
        val status: Int = 0,
        val statusText: String = "",
        val responseHeaders: Map<String, String> = emptyMap(),
        val closeCode: Int = 0,
        val closeReason: String = "",
        val createdAt: Long = System.currentTimeMillis(),
    )

    private val _sseMessages = MutableStateFlow<List<SseMessage>>(emptyList())
    val sseMessages: StateFlow<List<SseMessage>> = _sseMessages.asStateFlow()

    /** requestId -> WS 连接信息（created 建、handshake/closed 更新，保留供查询） */
    private val wsConnections = java.util.concurrent.ConcurrentHashMap<String, WsConnection>()

    /** 查询 SSE 消息（urlFilter 子串过滤，最新在前） */
    fun listSseMessages(urlFilter: String = "", limit: Int = 50): List<SseMessage> =
        _sseMessages.value
            .filter { urlFilter.isBlank() || it.url.contains(urlFilter, ignoreCase = true) }
            .asReversed()
            .take(limit)

    /** 查询 WS 连接（含握手头/关闭原因；urlFilter 子串过滤，最新在前） */
    fun listWsConnections(urlFilter: String = "", limit: Int = 50): List<WsConnection> =
        wsConnections.values
            .filter { urlFilter.isBlank() || it.url.contains(urlFilter, ignoreCase = true) }
            .sortedByDescending { it.createdAt }
            .take(limit)

    /**
     * WS 帧分析——尝试把文本帧按 JSON 解析并结构化，供 AI 直接读
     * 实时签名/推送协议（常见于 JSON-RPC / 自定义 envelope）。
     * 二进制帧（opcode 2）同样纳入——附 HEX/base64/UTF-8 三视图，
     * 并按 UTF-8 解码结果尝试 JSON 解析（部分二进制帧实为 UTF-8 JSON）。
     * @param keyword 帧内容关键字过滤（子串，忽略大小写）
     * @param jsonOnly 仅返回可解析为 JSON 的帧
     * @param limit 返回条数（最新在前）
     */
    fun analyzeWsFrames(urlFilter: String = "", keyword: String = "", jsonOnly: Boolean = false, limit: Int = 50): List<Map<String, Any?>> {
        val frames = _wsFrames.value
            .filter { urlFilter.isBlank() || it.url.contains(urlFilter, ignoreCase = true) }
            .filter { keyword.isBlank() || it.payload.contains(keyword, ignoreCase = true) }
            .asReversed()
            .take(limit * 3)
        val out = ArrayList<Map<String, Any?>>()
        for (f in frames) {
            if (f.opcode == 2) {
                // 二进制帧：三视图 + 按 UTF-8 尝试 JSON 解析
                val view = decodeWsBinary(f.payload) ?: continue
                val json = runCatching {
                    kotlinx.serialization.json.Json.parseToJsonElement(view.utf8).toString()
                }.getOrNull()
                if (jsonOnly && json == null) continue
                out.add(
                    linkedMapOf(
                        "url" to f.url,
                        "direction" to f.direction,
                        "timestamp" to f.timestamp,
                        "opcode" to 2,
                        "isBinary" to true,
                        "isJson" to (json != null),
                        "length" to view.length,
                        "hex" to view.hex.take(2000),
                        "base64" to view.base64.take(2000),
                        "utf8" to view.utf8.take(2000),
                        "payload" to (json ?: view.utf8.take(2000)),
                    ),
                )
                if (out.size >= limit) break
                continue
            }
            val raw = f.payload.removePrefix("base64:")
            val json = runCatching {
                kotlinx.serialization.json.Json.parseToJsonElement(raw).toString()
            }.getOrNull()
            if (jsonOnly && json == null) continue
            out.add(
                linkedMapOf(
                    "url" to f.url,
                    "direction" to f.direction,
                    "timestamp" to f.timestamp,
                    "opcode" to 1,
                    "isBinary" to false,
                    "isJson" to (json != null),
                    "payload" to (json ?: raw.take(2000)),
                ),
            )
            if (out.size >= limit) break
        }
        return out
    }

    /**
     * 列出 WS 二进制帧（DevTools 风格 HEX/base64/UTF-8 三视图，最新在前）。
     * 对齐桌面浏览器 DevTools 的 binary message 查看方式，供 AI 直接阅读二进制协议。
     */
    fun listBinaryWsFrames(urlFilter: String = "", limit: Int = 50): List<Map<String, Any?>> {
        val out = ArrayList<Map<String, Any?>>()
        for (f in _wsFrames.value.asReversed()) {
            if (f.opcode != 2) continue
            if (urlFilter.isNotBlank() && !f.url.contains(urlFilter, ignoreCase = true)) continue
            val view = decodeWsBinary(f.payload) ?: continue
            out.add(
                linkedMapOf(
                    "url" to f.url,
                    "direction" to f.direction,
                    "timestamp" to f.timestamp,
                    "length" to view.length,
                    "hex" to view.hex,
                    "base64" to view.base64,
                    "utf8" to view.utf8,
                ),
            )
            if (out.size >= limit) break
        }
        return out
    }

    /** 附加页面的 tabId（attach 时记录，供事件转发） */
    @Volatile
    var attachedTabId: String? = null
        private set

    /**
     * 请求事件回调（宿主注册转发 EventBus → event.wait network.request 对
     * CDP 抓取的请求同样可用；requestId 即 network.initiator/cdp_requests 里的 ID，
     * AI 可从事件直接跳到调用栈查询）。
     */
    @Volatile
    var requestSink: ((tabId: String, requestId: String, url: String, method: String) -> Unit)? = null

    /**
     * WS 帧事件回调（宿主注册转发 EventBus → event.wait network.websocket 可用；
     * 未注册时仅内部列表，network.cdp_ws_frames 查询）。
     * 回调增加 opcode（1=文本 / 2=二进制），供实时事件区分二进制帧。
     */
    @Volatile
    var wsFrameSink: ((tabId: String, url: String, direction: String, payload: String, opcode: Int) -> Unit)? = null

    /**
     * SSE 消息事件回调（宿主注册转发 EventBus → event.wait network.sse 可用；
     * 未注册时仅内部列表，network.cdp_sse_messages 查询）。
     */
    @Volatile
    var sseMessageSink: ((tabId: String, url: String, eventName: String, data: String) -> Unit)? = null

    /** 查询 WS 帧（urlFilter 子串过滤，最新在前） */
    fun listWsFrames(urlFilter: String = "", limit: Int = 50): List<WsFrame> =
        _wsFrames.value
            .filter { urlFilter.isBlank() || it.url.contains(urlFilter, ignoreCase = true) }
            .asReversed()
            .take(limit)

    @Volatile
    private var intercepting = false

    /** 是否已开启拦截 */
    val isIntercepting: Boolean get() = intercepting && isAttached

    /**
     * 开启请求拦截（Fetch.enable）。
     * 匹配的请求在发出前暂停（不发网络），由 AI 决策：查看参数/改参数/模拟响应/放行。
     * @param urlPattern URL 通配（空=全部请求），如 通配符 "/api/sign"
     */
    suspend fun enableInterception(urlPattern: String = ""): Boolean {
        val s = session ?: return false
        val pattern = buildJsonObject {
            if (urlPattern.isNotBlank()) put("urlPattern", urlPattern)
            put("requestStage", "Request")
        }
        val ok = s.call(
            "Fetch.enable",
            buildJsonObject { put("patterns", kotlinx.serialization.json.JsonArray(listOf(pattern))) },
        ) != null
        if (ok) intercepting = true
        return ok
    }

    /** 关闭拦截（先放行全部暂停中的请求） */
    suspend fun disableInterception() {
        // 逐一放行，避免页面悬挂
        _pausedRequests.value.forEach { resumePaused(it.fetchId) }
        session?.call("Fetch.disable")
        intercepting = false
    }

    /** 放行指定暂停请求（可改写 url/headers/postData/method 后再放行） */
    suspend fun resumePaused(
        fetchId: String,
        url: String? = null,
        method: String? = null,
        headers: Map<String, String>? = null,
        postData: String? = null,
    ): Boolean {
        val s = session ?: return false
        val params = buildJsonObject {
            put("requestId", fetchId)
            url?.takeIf { it.isNotBlank() }?.let { put("url", it) }
            method?.takeIf { it.isNotBlank() }?.let { put("method", it) }
            headers?.let {
                put(
                    "headers",
                    kotlinx.serialization.json.buildJsonObject {
                        it.forEach { (k, v) -> put(k, v) }
                    },
                )
            }
            postData?.let { put("postData", it) }
        }
        val ok = s.call("Fetch.continueRequest", params) != null
        if (ok) _pausedRequests.value = _pausedRequests.value.filterNot { it.fetchId == fetchId }
        return ok
    }

    /** 以自定义响应直接回给页面（不发网络，Mock 服务器语义） */
    suspend fun mockPausedResponse(
        fetchId: String,
        body: String,
        status: Int = 200,
        mimeType: String = "application/json",
        headers: Map<String, String> = emptyMap(),
    ): Boolean {
        val s = session ?: return false
        val encoded = Base64.encodeToString(body.toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
        val params = buildJsonObject {
            put("requestId", fetchId)
            put("responseCode", status)
            put(
                "responseHeaders",
                kotlinx.serialization.json.JsonArray(
                    (if (headers.containsKey("Content-Type")) headers else headers + ("Content-Type" to mimeType))
                        .map { (k, v) ->
                            buildJsonObject { put("name", k); put("value", v) }
                        },
                ),
            )
            put("body", encoded)
        }
        val ok = s.call("Fetch.fulfillRequest", params) != null
        if (ok) _pausedRequests.value = _pausedRequests.value.filterNot { it.fetchId == fetchId }
        return ok
    }

    /** 中止暂停请求（模拟失败） */
    suspend fun abortPaused(fetchId: String): Boolean {
        val s = session ?: return false
        val ok = s.call(
            "Fetch.failRequest",
            buildJsonObject {
                put("requestId", fetchId)
                put("errorReason", "Aborted")
            },
        ) != null
        if (ok) _pausedRequests.value = _pausedRequests.value.filterNot { it.fetchId == fetchId }
        return ok
    }

    // ================= 请求级仿真控制（ Emulation/Network 域） =================

    /** UA 覆盖（Emulation.setUserAgentOverride）：立即生效于 navigator.userAgent 与后续请求头 */
    suspend fun setUserAgentOverride(userAgent: String, acceptLanguage: String = "", platform: String = ""): Boolean {
        val s = session ?: return false
        val params = buildJsonObject {
            put("userAgent", userAgent)
            if (acceptLanguage.isNotBlank()) put("acceptLanguage", acceptLanguage)
            if (platform.isNotBlank()) put("platform", platform)
        }
        return s.call("Emulation.setUserAgentOverride", params) != null
    }

    /** 全局附加请求头（Network.setExtraHTTPHeaders）：空表清除。签名接口测试常用（注入 trace/debug 头观察服务端差异） */
    suspend fun setExtraHeaders(headers: Map<String, String>): Boolean {
        val s = session ?: return false
        return s.call(
            "Network.setExtraHTTPHeaders",
            buildJsonObject {
                put("headers", buildJsonObject { headers.forEach { (k, v) -> put(k, v) } })
            },
        ) != null
    }

    /** 禁用缓存（Network.setCacheDisabled）：true=强制走网络，分析时防缓存干扰（响应/请求才是真服务端数据） */
    suspend fun setCacheDisabled(disabled: Boolean): Boolean {
        val s = session ?: return false
        // 幂等命令，瞬时超时重试 1 次（会话故障由 CdpSession fail-closed 兜底）
        val setParams = buildJsonObject { put("cacheDisabled", disabled) }
        val call = s.call("Network.setCacheDisabled", setParams, null, CDP_RETRIES)
        return call != null
    }

    val isAttached: Boolean get() = session?.isConnected == true

    /** 附加到当前页面：Network.enable 后开始收集请求事件 */
    suspend fun attach(engine: BrowserEngine): Boolean {
        detach()
        clear()
        val pages = CdpTransport.listPages()
        if (pages == null) {
            if (CdpTransport.lastError == null) CdpTransport.lastError = "无法获取 DevTools 页面列表"
            return false
        }
        val targetUrl = engine.currentUrl()
        val pageCandidates = pages.filter { it.type == "page" }
        if (pageCandidates.isEmpty()) {
            CdpTransport.lastError = "DevTools 已连接但无 page 目标（页面可能尚未加载完成，稍后重试）"
            return false
        }
        val page = pageCandidates.firstOrNull { p ->
            !targetUrl.isNullOrBlank() && p.url.isNotBlank() &&
                (p.url == targetUrl || p.url.substringBefore('#').trimEnd('/').lowercase() ==
                    targetUrl.substringBefore('#').trimEnd('/').lowercase())
        } ?: pageCandidates.firstOrNull { p ->
            val host = targetUrl?.substringAfter("//")?.substringBefore('/').orEmpty()
            host.length > 3 && p.url.contains(host)
        } ?: pageCandidates.first()

        // 优先经 CDP 复用枢纽：与 CdpDebuggerSession 等进程内 MCP 会话共享
        // 同一条后端 CDP 会话，事件流互通不互踢；
        // 枢纽不可用时回退直连 unix socket（独立会话）
        val wsPath = CdpTransport.wsPathOf(page)
        val ws: RawWebSocket? = CdpHub.connectViaHub(wsPath)
            ?: CdpTransport.connectWebSocket(wsPath = wsPath)
        if (ws == null) {
            if (CdpTransport.lastError == null) CdpTransport.lastError = "WebSocket 升级失败"
            return false
        }
        val s = CdpSession(ws, scope)
        // 先启动接收循环再发域启用命令：CdpSession.isConnected 依赖 active 标志，
        // start 之前调用 send 会直接抛"CDP 会话未连接"（ 修复：
        // 此前 Network.enable 在 start() 之前调用，attach_cdp 恒失败）
        s.start()
        // （P0-4 修复）：先订阅事件流，再启用 Network 域。
        // Network.enable 响应返回前后端可能立即补发进行中请求的
        // requestWillBeSent 事件；SharedFlow(replay=0) 若晚于 enable 订阅，
        // 这批事件将被永久丢弃，进行中请求整批从列表中缺失。
        collector?.cancel()
        collector = scope.launch { s.events.collect { onEvent(it) } }
        // Network.enable 为幂等命令，页面主线程瞬时阻塞时首条命令常超时；
        // 加一次重试，配合 CdpSession 连续超时 fail-closed。
        var enableResult = s.callDetailed("Network.enable", kotlinx.serialization.json.JsonObject(emptyMap()), null, CDP_RETRIES)
        if (enableResult.isFailure) {
            enableResult = s.callDetailed("Network.enable", kotlinx.serialization.json.JsonObject(emptyMap()), null, CDP_RETRIES)
        }
        if (enableResult.isFailure) {
            CdpTransport.lastError = "Network.enable 失败: ${enableResult.exceptionOrNull()?.message}"
            collector?.cancel()
            collector = null
            s.close()
            return false
        }
        session = s
        attachedTabId = engine.tabId
        CdpTransport.lastError = null
        return true
    }

    fun detach() {
        collector?.cancel()
        collector = null
        session?.close()
        session = null
        intercepting = false
        _pausedRequests.value = emptyList()
        wsUrls.clear()
        wsConnections.clear()
        _wsFrames.value = emptyList()
        _sseMessages.value = emptyList()
        attachedTabId = null
    }

    fun clear() {
        _requests.value = emptyList()
    }

    /** 仅清空 WS 帧缓冲 */
    fun clearWsFrames() {
        _wsFrames.value = emptyList()
    }

    fun list(urlFilter: String = "", limit: Int = 50): List<CdpRequestInfo> =
        _requests.value
            .filter { urlFilter.isBlank() || it.url.contains(urlFilter, ignoreCase = true) }
            .asReversed() // 插入序倒排 = 最新在前
            .take(limit)

    /* * ：按 requestId 精确查找（network.get/initiator 的 CDP 回退入口） */
    fun findByRequestId(requestId: String): CdpRequestInfo? =
        _requests.value.lastOrNull { it.requestId == requestId }

    /**
     * 发起链节点（DevTools Initiator 面板 "Request initiator chain" 树的一层）：
     * 该请求从哪来（via = parser/script/redirect/navigation）。
     */
    data class InitiatorHop(
        val url: String,
        val requestId: String,
        val via: String,
        val isTarget: Boolean = false,
    )

    /**
     * 构建发起链（DevTools Initiator 面板同款）。
     *
     * 回溯逻辑与 DevTools 一致：
     * - script 发起 → 栈顶帧脚本 URL，在请求列表里找加载该脚本的请求，向上回溯
     * - parser 发起（HTML 解析出的子资源/iframe）→ initiator.url 指向的文档请求
     * - redirect → 注入重定向原始 URL 一跳
     * - 到主文档（无父）或 data:/内存脚本为止，最多 12 层防循环
     *
     * @return 根（主文档）在前、目标请求在后的链；目标节点带 isTarget 标记
     */
    fun initiatorChain(requestId: String, maxDepth: Int = 12): List<InitiatorHop> {
        val hops = ArrayList<InitiatorHop>()
        var current = findByRequestId(requestId)
        var depth = 0
        while (current != null && depth < maxDepth) {
            hops.add(
                InitiatorHop(
                    url = current.url,
                    requestId = current.requestId,
                    via = current.initiatorType.ifBlank { "navigation" },
                ),
            )
            if (current.redirectedFromUrl.isNotBlank() && current.redirectedFromUrl != current.url) {
                hops.add(InitiatorHop(current.redirectedFromUrl, current.requestId, "redirect"))
            }
            // 父节点定位：script 栈顶脚本 > parser 文档 > initiator.url 兜底
            val parentUrl = when {
                current.initiatorType == "script" && current.initiatorScriptUrl.isNotBlank() -> current.initiatorScriptUrl
                current.initiatorUrl.isNotBlank() -> current.initiatorUrl
                current.initiatorScriptUrl.isNotBlank() -> current.initiatorScriptUrl
                else -> null
            }
            current = parentUrl?.let { p ->
                // 同 URL 可能命中多条（重试/去重），取非自身、最后出现的一条
                _requests.value.filter { it.url == p && it.requestId != requestId }.lastOrNull()
            }
            depth++
        }
        // 反转：根文档在前，目标请求在后；末位打目标标记
        val chain = hops.asReversed()
        return if (chain.isEmpty()) chain else chain.dropLast(1) + chain.last().copy(isTarget = true)
    }

    /** 回取响应体（DevTools Network 面板 Preview/Response 的能力） */
    suspend fun getResponseBody(requestId: String, maxChars: Int = 50_000): JsonObject? {
        val s = session ?: return null
        val info = _requests.value.firstOrNull { it.requestId == requestId }
        val result = s.call(
            "Network.getResponseBody",
            buildJsonObject { put("requestId", requestId) },
        )
        val body = result?.get("body")?.jsonPrimitive?.contentOrNull
            ?: return buildJsonObject {
                put("requestId", requestId)
                put("url", info?.url ?: "")
                put("error", "响应体不可用（可能已被丢弃或非缓存资源），可尝试在请求完成后尽早获取")
            }
        val isBase64 = result["base64Encoded"]?.jsonPrimitive?.contentOrNull == "true"
        val decoded = if (isBase64) {
            runCatching { String(Base64.decode(body, Base64.DEFAULT), Charsets.UTF_8) }.getOrDefault(body)
        } else {
            body
        }
        // 默认截断从 500K 降到 50K（AI 上下文保护），超长时打标引导分段获取
        val limit = maxChars.coerceIn(1_000, 200_000)
        return buildJsonObject {
            put("requestId", requestId)
            put("url", info?.url ?: "")
            put("status", info?.status ?: 0)
            put("mimeType", info?.mimeType ?: "")
            put("encoding", if (isBase64) "base64->utf8" else "utf8")
            put("length", decoded.length)
            if (decoded.length > limit) put("truncated", true)
            put("body", decoded.take(limit))
        }
    }

    // ---------------- 事件处理 ----------------

    private fun onEvent(event: CdpEvent) {
        when (event.method) {
            "Network.requestWillBeSent" -> onRequestWillBeSent(event.params)
            "Network.responseReceived" -> onResponseReceived(event.params)
            "Network.loadingFinished" -> onLoadingFinished(event.params)
            "Network.loadingFailed" -> onLoadingFailed(event.params)
            "Fetch.requestPaused" -> onRequestPaused(event.params)
            "Fetch.authRequired" -> onRequestAuthRequired(event.params)
            "Network.webSocketCreated" -> {
                val requestId = event.params["requestId"]?.jsonPrimitive?.contentOrNull ?: return
                val url = event.params["url"]?.jsonPrimitive?.contentOrNull ?: ""
                if (url.isNotBlank()) wsUrls[requestId] = url
                // 登记 WS 连接信息（供握手头/关闭原因查询）
                wsConnections[requestId] = WsConnection(requestId = requestId, url = url)
            }
            "Network.webSocketHandshakeRequestReceived" -> onWsHandshakeRequest(event.params)
            "Network.webSocketHandshakeResponseReceived" -> onWsHandshakeResponse(event.params)
            "Network.webSocketFrameSent" -> onWsFrame(event.params, "send")
            "Network.webSocketFrameReceived" -> onWsFrame(event.params, "receive")
            "Network.webSocketClosed" -> onWsClosed(event.params)
            "Network.eventSourceMessageReceived" -> onSseMessage(event.params)
        }
    }

    /** WS 握手请求头（webSocketHandshakeRequestReceived） */
    private fun onWsHandshakeRequest(params: JsonObject) {
        val requestId = params["requestId"]?.jsonPrimitive?.contentOrNull ?: return
        val request = params["request"]?.jsonObject ?: return
        val url = wsUrls[requestId] ?: ""
        wsConnections.computeIfPresent(requestId) { _, conn ->
            conn.copy(requestHeaders = headersOf(request["headers"]?.jsonObject))
        }
        // 握手请求可能先于 webSocketCreated 到达，兜底建条目
        if (!wsConnections.containsKey(requestId)) {
            wsConnections[requestId] = WsConnection(requestId = requestId, url = url, requestHeaders = headersOf(request["headers"]?.jsonObject))
        }
    }

    /** WS 握手响应（webSocketHandshakeResponseReceived）：状态码 + 响应头 */
    private fun onWsHandshakeResponse(params: JsonObject) {
        val requestId = params["requestId"]?.jsonPrimitive?.contentOrNull ?: return
        val response = params["response"]?.jsonObject ?: return
        val url = wsUrls[requestId] ?: ""
        val status = response["status"]?.jsonPrimitive?.contentOrNull?.toIntOrNull() ?: 0
        val statusText = response["statusText"]?.jsonPrimitive?.contentOrNull ?: ""
        val respHeaders = headersOf(response["headers"]?.jsonObject)
        wsConnections.computeIfPresent(requestId) { _, conn ->
            conn.copy(status = status, statusText = statusText, responseHeaders = respHeaders)
        }
        if (!wsConnections.containsKey(requestId)) {
            wsConnections[requestId] = WsConnection(requestId = requestId, url = url, status = status, statusText = statusText, responseHeaders = respHeaders)
        }
    }

    /** WS 关闭（webSocketClosed）：记录关闭码/原因，保留连接信息供查询 */
    private fun onWsClosed(params: JsonObject) {
        val requestId = params["requestId"]?.jsonPrimitive?.contentOrNull ?: return
        val code = params["code"]?.jsonPrimitive?.contentOrNull?.toIntOrNull() ?: 0
        val reason = params["reason"]?.jsonPrimitive?.contentOrNull ?: ""
        wsConnections.computeIfPresent(requestId) { _, conn ->
            conn.copy(closeCode = code, closeReason = reason)
        }
        wsUrls.remove(requestId)
    }

    /** SSE 推送消息（Network.eventSourceMessageReceived） */
    private fun onSseMessage(params: JsonObject) {
        val requestId = params["requestId"]?.jsonPrimitive?.contentOrNull ?: return
        val data = params["data"]?.jsonPrimitive?.contentOrNull ?: return
        if (data.isBlank()) return
        val url = wsUrls[requestId] ?: _requests.value.firstOrNull { it.requestId == requestId }?.url ?: ""
        val msg = SseMessage(
            requestId = requestId,
            url = url,
            eventName = params["eventName"]?.jsonPrimitive?.contentOrNull ?: "message",
            eventId = params["eventId"]?.jsonPrimitive?.contentOrNull ?: "",
            data = data.take(4096),
            timestamp = params["timestamp"]?.jsonPrimitive?.contentOrNull?.toLongOrNull() ?: System.currentTimeMillis(),
        )
        _sseMessages.value = (_sseMessages.value + msg).takeLast(300)
        val tab = attachedTabId
        if (tab != null) sseMessageSink?.invoke(tab, url, msg.eventName, msg.data)
    }

    /** WS 数据帧入列 + 转发（opcode 1 文本原样 / 2 二进制 base64；跳过 ping/pong/close 控制帧） */
    private fun onWsFrame(params: JsonObject, direction: String) {
        val requestId = params["requestId"]?.jsonPrimitive?.contentOrNull ?: return
        val response = params["response"]?.jsonObject ?: return
        val opcode = response["opcode"]?.jsonPrimitive?.intOrNull ?: 1
        if (opcode != 1 && opcode != 2) return
        val payload = response["payloadData"]?.jsonPrimitive?.contentOrNull ?: ""
        if (payload.isBlank()) return
        val url = wsUrls[requestId] ?: ""
        val stored = if (opcode == 2 && !payload.startsWith("base64:")) "base64:$payload" else payload
        val frame = WsFrame(requestId, url, direction, opcode, stored.take(4096))
        _wsFrames.value = (_wsFrames.value + frame).takeLast(300)
        val tab = attachedTabId
        if (tab != null) wsFrameSink?.invoke(tab, url, direction, frame.payload, frame.opcode)
    }

    /** 请求被拦截：入暂停表等待决策（AI 查看 → continue/mock/abort） */
    private fun onRequestPaused(params: JsonObject) {
        val fetchId = params["requestId"]?.jsonPrimitive?.contentOrNull ?: return
        val request = params["request"]?.jsonObject ?: return
        val url = request["url"]?.jsonPrimitive?.contentOrNull ?: return
        val paused = PausedRequest(
            fetchId = fetchId,
            networkRequestId = params["networkId"]?.jsonPrimitive?.contentOrNull ?: "",
            url = url,
            method = request["method"]?.jsonPrimitive?.contentOrNull ?: "GET",
            headers = headersOf(request["headers"]?.jsonObject),
            postData = request["postData"]?.jsonPrimitive?.contentOrNull,
            resourceType = params["resourceType"]?.jsonPrimitive?.contentOrNull ?: "",
        )
        // （P1-5 修复）：暂停表满时不再静默丢弃最旧条目——被移出列表的
        // 请求在浏览器侧仍处于暂停态（既无法 resume 也无法被 disableInterception
        // 救回，形成页面请求黑洞）。溢出时自动放行最旧请求。
        val current = _pausedRequests.value
        if (current.size >= 50) {
            current.firstOrNull()?.let { oldest ->
                scope.launch { runCatching { resumePaused(oldest.fetchId) } }
            }
        }
        _pausedRequests.value = (current + paused).takeLast(50)
    }

    /** 拦截触发的认证要求：默认不带凭据放行（保持流程可观察） */
    private fun onRequestAuthRequired(params: JsonObject) {
        val fetchId = params["requestId"]?.jsonPrimitive?.contentOrNull ?: return
        scope.launch {
            session?.call(
                "Fetch.continueWithAuth",
                buildJsonObject {
                    put("requestId", fetchId)
                    // （P2-6 修复）：原 "ProvideCredentials" 不带 username/password
                    // 会让被拦截的 401 接口以空凭据直接失败。"Default" 表示交给浏览器
                    // 默认行为（复用已有凭据/正常失败），保持流程可观察且不误伤。
                    put("authChallengeResponse", buildJsonObject { put("response", "Default") })
                },
            )
        }
    }

    private fun onRequestWillBeSent(params: JsonObject) {
        val requestId = params["requestId"]?.jsonPrimitive?.contentOrNull ?: return
        val request = params["request"]?.jsonObject ?: return
        val url = request["url"]?.jsonPrimitive?.contentOrNull ?: return
        // 提取 CDP 原生 initiator——type（script/parser/preload/other…）与
        // stack.callFrames（JS 发起的请求带真实调用栈，DevTools Network 面板 Initiator
        // 列同源数据）。此前只取了 initiator.url，调用栈被丢弃，导致"CDP 获取启动器
        // 调用堆栈"功能实际不可用（注入式 hook 又只有 js:fetch 类型、栈为空）。
        val initiator = params["initiator"]?.jsonObject
        val initiatorType = initiator?.get("type")?.jsonPrimitive?.contentOrNull ?: ""
        val stackObj = initiator?.get("stack")?.jsonObject
        val initiatorStack = formatCallStack(stackObj)
        // 栈顶帧的脚本 URL（script 发起时 = 发起脚本本体的网络请求，
        // 发起链逐级回溯的父节点；DevTools Initiator 面板 chain 树同源逻辑）
        val initiatorScriptUrl = stackObj?.get("callFrames")?.jsonArray
            ?.firstOrNull()?.jsonObject?.get("url")?.jsonPrimitive?.contentOrNull?.takeIf { it.isNotBlank() } ?: ""
        // 重定向来源（同一 requestId 复用，redirectResponse 携带上一跳 URL）
        val redirectFromUrl = params["redirectResponse"]?.jsonObject?.get("url")?.jsonPrimitive?.contentOrNull
        val info = CdpRequestInfo(
            requestId = requestId,
            url = url,
            method = request["method"]?.jsonPrimitive?.contentOrNull ?: "GET",
            resourceType = params["type"]?.jsonPrimitive?.contentOrNull ?: "",
            requestHeaders = headersOf(request["headers"]?.jsonObject),
            postData = request["postData"]?.jsonPrimitive?.contentOrNull,
            initiatorUrl = initiator?.get("url")?.jsonPrimitive?.contentOrNull ?: "",
            initiatorType = initiatorType,
            initiatorStack = initiatorStack,
            initiatorScriptUrl = initiatorScriptUrl,
        )
        val isNew = _requests.value.none { it.requestId == requestId }
        merge(requestId) { existing ->
            if (existing == null) info
            else existing.copy(
                url = url,
                method = info.method,
                resourceType = info.resourceType,
                requestHeaders = info.requestHeaders,
                postData = info.postData,
                initiatorUrl = info.initiatorUrl,
                // redirect 链复用 requestId 再次触发 requestWillBeSent：保留首次 initiator
                // （根因发起点），不覆盖；重定向保留最初来源 URL
                initiatorType = existing.initiatorType.ifBlank { initiatorType },
                initiatorStack = existing.initiatorStack.ifBlank { initiatorStack },
                initiatorScriptUrl = existing.initiatorScriptUrl.ifBlank { initiatorScriptUrl },
                redirectedFromUrl = existing.redirectedFromUrl.ifBlank { redirectFromUrl ?: existing.url },
            )
        }
        // 新请求转发事件总线（每条只发一次；redirect 续传不重复发）
        if (isNew) {
            val tab = attachedTabId
            if (tab != null) {
                runCatching { requestSink?.invoke(tab, requestId, url, info.method) }
            }
        }
    }

    /**
     * CDP Runtime.CallFrame[] → 可读调用栈文本（DevTools Initiator 面板 Request call
     * stack 同款形态）：每帧 `at 函数名 (文件名:行:列)`；行/列 0 基转 1 基展示。
     *
     * 对齐 DevTools 展示：帧行用短文件名（URL 末段），同一脚本首次出现时
     * 才附完整 URL（eval 脚本无 URL 时回退 scriptId）——深栈（webpack chunk 数十帧）
     * 不再因每行带全 URL 而提前截断；async 栈的 parent 链以 `Promise.then`（或
     * Task/then 等）边界标注，逐层缩进，与 DevTools 的异步分段一致。
     */
    private fun formatCallStack(
        stack: JsonObject?,
        depth: Int = 0,
        seenScripts: MutableSet<String> = mutableSetOf(),
    ): String {
        if (stack == null || depth > 6) return ""
        val frames = stack["callFrames"]?.jsonArray ?: return ""
        val sb = StringBuilder()
        for (frame in frames) {
            val f = frame.jsonObject
            val fn = f["functionName"]?.jsonPrimitive?.contentOrNull?.ifBlank { "(anonymous)" } ?: "(anonymous)"
            val scriptUrl = f["url"]?.jsonPrimitive?.contentOrNull ?: ""
            val line = (f["lineNumber"]?.jsonPrimitive?.intOrNull ?: -1) + 1
            val col = (f["columnNumber"]?.jsonPrimitive?.intOrNull ?: -1) + 1
            val location = if (scriptUrl.isBlank()) {
                "script#${f["scriptId"]?.jsonPrimitive?.contentOrNull ?: "?"}"
            } else {
                val short = "${scriptUrl.substringAfterLast('/')}:$line:$col"
                // 同一脚本仅首次出现附完整 URL，控制深栈体积
                if (seenScripts.add(scriptUrl)) "$short  ($scriptUrl)" else short
            }
            sb.append("  ".repeat(depth)).append("at ").append(fn).append(" (").append(location).append(")\n")
            if (sb.length > 8000) break
        }
        // async 调用链：DevTools 以 Promise.then 等边界分段，此处同样标注后接上层异步栈
        stack["parent"]?.jsonObject?.let { parent ->
            sb.append("  ".repeat(depth)).append("[async] Promise.then →\n")
            sb.append(formatCallStack(parent, depth + 1, seenScripts))
        }
        return sb.toString().trim().take(8000)
    }

    private fun onResponseReceived(params: JsonObject) {
        val requestId = params["requestId"]?.jsonPrimitive?.contentOrNull ?: return
        val response = params["response"]?.jsonObject ?: return
        // 协议版本透传（http/1.1 / h2 / h3）+ gRPC 识别（Content-Type: application/grpc）
        val protocol = response["protocol"]?.jsonPrimitive?.contentOrNull ?: ""
        val respHeaders = headersOf(response["headers"]?.jsonObject)
        val isGrpc = respHeaders.entries.any { (k, v) ->
            k.equals("content-type", ignoreCase = true) && v.contains("application/grpc", ignoreCase = true)
        }
        merge(requestId) { existing ->
            val base = existing ?: CdpRequestInfo(requestId = requestId, url = response["url"]?.jsonPrimitive?.contentOrNull ?: "")
            base.copy(
                url = response["url"]?.jsonPrimitive?.contentOrNull ?: base.url,
                status = response["status"]?.jsonPrimitive?.contentOrNull?.toIntOrNull() ?: base.status,
                mimeType = response["mimeType"]?.jsonPrimitive?.contentOrNull ?: base.mimeType,
                responseHeaders = respHeaders,
                fromCache = response["fromDiskCache"]?.jsonPrimitive?.contentOrNull == "true" ||
                    response["fromPrefetchCache"]?.jsonPrimitive?.contentOrNull == "true",
                remoteAddress = response["remoteIPAddress"]?.jsonPrimitive?.contentOrNull,
                resourceType = base.resourceType.ifBlank { params["type"]?.jsonPrimitive?.contentOrNull ?: "" },
                // ResourceTiming（同源请求才有完整字段）
                timing = runCatching { CdpTiming.parse(response["timing"]?.jsonObject) }.getOrDefault(CdpTiming()),
                // 协议版本 + gRPC 标记
                protocol = protocol.ifBlank { base.protocol },
                isGrpc = isGrpc || base.isGrpc,
            )
        }
    }

    private fun onLoadingFinished(params: JsonObject) {
        val requestId = params["requestId"]?.jsonPrimitive?.contentOrNull ?: return
        val size = params["encodedDataLength"]?.jsonPrimitive?.contentOrNull?.toLongOrNull() ?: 0L
        merge(requestId) { existing ->
            (existing ?: CdpRequestInfo(requestId = requestId, url = "")).copy(finished = true, size = size)
        }
    }

    private fun onLoadingFailed(params: JsonObject) {
        val requestId = params["requestId"]?.jsonPrimitive?.contentOrNull ?: return
        val error = params["errorText"]?.jsonPrimitive?.contentOrNull ?: "failed"
        val canceled = params["canceled"]?.jsonPrimitive?.contentOrNull == "true"
        merge(requestId) { existing ->
            (existing ?: CdpRequestInfo(requestId = requestId, url = ""))
                .copy(failed = true, errorText = if (canceled) "canceled" else error)
        }
    }

    private fun headersOf(headers: JsonObject?): Map<String, String> {
        headers ?: return emptyMap()
        val out = LinkedHashMap<String, String>()
        for ((k, v) in headers) {
            out[k] = v.jsonPrimitive.contentOrNull ?: v.toString()
        }
        return out
    }

    private fun merge(requestId: String, reducer: (CdpRequestInfo?) -> CdpRequestInfo) {
        val current = _requests.value.toList()
        val existing = current.firstOrNull { it.requestId == requestId }
        // 防重复（同一 redirect 链会复用 requestId 多次 requestWillBeSent）
        val updated = reducer(existing)
        val next = if (existing == null) {
            (current + updated).takeLast(MAX_ENTRIES)
        } else {
            current.map { if (it.requestId == requestId) updated else it }
        }
        _requests.value = next
    }

    private const val MAX_ENTRIES = 500
}
