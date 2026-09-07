package com.webreverse.mcp.mcp.server

import android.content.Context
import com.webreverse.mcp.core.logging.AppLogger
import com.webreverse.mcp.core.logging.LogCategory
import com.webreverse.mcp.devtools.protocol.cdp.CdpHub
import io.ktor.http.ContentType
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.embeddedServer
import io.ktor.server.cio.CIO
import io.ktor.server.response.respondText
import io.ktor.server.request.*
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.server.websocket.*
import io.ktor.websocket.CloseReason
import io.ktor.websocket.Frame
import io.ktor.websocket.close
import io.ktor.websocket.readText
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.IOException
import java.net.ServerSocket
import kotlin.time.Duration.Companion.seconds

/**
 * CDP 多路复用代理（ 起为纯内部基础设施，不再托管 DevTools 前端）。
 *
 * 原理：WebView.setWebContentsDebuggingEnabled(true) 后，Chromium 在进程内暴露
 * abstract unix socket `webview_devtools_remote_<pid>`（HTTP 发现 + CDP WebSocket），
 * 但该 socket 只能进程内访问。进程内多个组件（CdpDebuggerSession / CdpNetworkMonitor）
 * 各自直连同一 target 时，Chromium 可能"后连踢前连"，导致会话互相打断。
 *
 * 本服务在 127.0.0.1 上起 Ktor 服务器做一件事：
 * 将 /devtools/page/{id} 的 WebSocket 双向中继到 unix socket 上的 CDP 会话，
 * 并按 target 建立复用枢纽（[CdpHubSession]）——同一页面的所有 MCP 客户端共享
 * 一条后端 CDP 连接，断点/暂停/网络事件在会话间广播，互不踢线。
 */
class CdpProxyServer(
    @Suppress("unused") private val context: Context,
    private val logger: AppLogger,
) {
    companion object {
        /** 默认端口（与 Chrome 远程调试惯例一致），占用时向后尝试 */
        private const val DEFAULT_PORT = 9222
        private const val PORT_ATTEMPTS = 10
    }

    private var server: EmbeddedServer<*, *>? = null
    private var actualPort: Int = -1
    private val mutex = Mutex()

    /**
     * CDP 复用枢纽表：targetId → [CdpHubSession]。
     * 进程内 MCP 工具接入同一 target 时共享同一条后端 CDP 连接。
     */
    private val hubs = java.util.concurrent.ConcurrentHashMap<String, CdpHubSession>()

    /** 枢纽生命周期作用域（后端读循环、空闲关闭计时），随 [stop] 取消 */
    private val hubScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /** 当前实际监听端口（未启动时为 -1） */
    val port: Int get() = actualPort

    /** 是否正在运行 */
    val isRunning: Boolean get() = server != null && actualPort > 0

    /**
     * 确保服务已启动（幂等）。返回实际监听端口。
     * 默认从 9222 开始尝试，端口被占时依次后移。
     */
    suspend fun ensureStarted(): Int = mutex.withLock {
        if (server != null && actualPort > 0) return actualPort
        for (p in DEFAULT_PORT until DEFAULT_PORT + PORT_ATTEMPTS) {
            if (isPortInUse(p)) continue
            try {
                val srv = embeddedServer(CIO, port = p, host = "127.0.0.1") {
                    cdpProxyModule()
                }.start(wait = false)
                server = srv
                actualPort = p
                // 注册 CDP 复用枢纽端点：进程内 MCP 工具（CdpDebuggerSession /
                // CdpNetworkMonitor）经 TcpWebSocket 回环接入共享后端会话
                CdpHub.onStarted("127.0.0.1:$p")
                // 联动状态上报（mcp.status 读取）：跨模块经 CdpHub 静态注册
                CdpHub.statusProvider = { linkageStatus() }
                // 放行入口（App UI 暂停提示条调用）：恢复所有暂停中的枢纽会话
                CdpHub.resumeProvider = { resumePaused() }
                logger.i(LogCategory.MCP, "CDP 多路复用代理已启动: 127.0.0.1:$p")
                return p
            } catch (e: Exception) {
                logger.w(LogCategory.MCP, "CDP 代理端口 $p 启动失败: ${e.message}，尝试下一端口")
            }
        }
        throw IOException("CDP 代理端口 $DEFAULT_PORT~${DEFAULT_PORT + PORT_ATTEMPTS - 1} 均不可用")
    }

    /** 停止服务 */
    suspend fun stop() = mutex.withLock {
        hubs.values.forEach { it.closeBackendOnly("server stopped") }
        hubs.clear()
        hubScope.cancel()
        CdpHub.onProxyStopped()
        server?.let {
            runCatching { it.stop(300, 800) }
        }
        server = null
        actualPort = -1
    }

    /**
     * CDP 枢纽状态：各枢纽的客户端连接数、暂停态。
     * 供 mcp.status 展示（AI 可据此判断共享会话情况）。
     */
    fun linkageStatus(): List<Map<String, Any>> =
        hubs.map { (pageId, hub) ->
            mapOf(
                "target" to pageId,
                "connected" to hub.isConnected,
                "externalClients" to hub.externalClientCount,
                "mcpClients" to hub.mcpClientCount,
                "paused" to hub.isPaused,
                "clients" to hub.clientCount,
            )
        }

    /**
     * 恢复所有暂停中的枢纽会话（放行）。
     * 断点命中（MCP 设置）页面暂停后，手机上无 DevTools 前端可操作，
     * App 暂停提示条经 CdpHub.resumePausedSessions 调到这里一键恢复。
     * @return 实际恢复的会话数
     */
    fun resumePaused(): Int {
        var resumed = 0
        hubs.values.forEach { if (it.resumeIfPaused()) resumed++ }
        return resumed
    }

    // ==================== 服务模块 ====================

    private fun Application.cdpProxyModule() {
        install(WebSockets) {
            pingPeriod = 20.seconds
            // CDP 单条消息可达数十 MB（getResponseBody/截图 base64），超时给足余量；
            // 真实空闲检测由 pingPeriod 兜底，避免大帧处理期间误判超时断连
            timeout = 300.seconds
            // 注意：不能用 Long.MAX_VALUE——Ktor Netty 引擎把该值传给
            // Netty WebSocketServerHandshaker（int 参数）时溢出为 -1，
            // 会导致帧解码异常、连接被关闭。显式给安全上限 512MB。
            maxFrameSize = 512L * 1024 * 1024
        }
        routing {
            // ---- CDP WebSocket 中继（复用枢纽：多客户端共享一条后端会话）----
            // ?client=mcp：进程内 MCP 工具（CdpDebuggerSession 等）回环接入标记；
            // 无参数 = 外部客户端（如经 adb 端口转发接入的桌面调试器）。
            // 枢纽据此区分断开语义（外部客户端离开撤销其断点并自动恢复暂停，
            // MCP 离开仅撤销自己的断点）
            webSocket("/devtools/page/{id}") {
                val pageId = call.parameters["id"]
                if (pageId.isNullOrBlank()) {
                    close(CloseReason(CloseReason.Codes.CANNOT_ACCEPT, "missing page id"))
                } else {
                    val kind = if (call.request.queryParameters["client"] == "mcp") {
                        CdpHubSession.ClientKind.MCP
                    } else {
                        CdpHubSession.ClientKind.EXTERNAL
                    }
                    relayViaHub(pageId, kind)
                }
            }

            get("/health") {
                call.respondText("""{"status":"ok","service":"cdp-proxy"}""", ContentType.Application.Json)
            }
        }
    }

    /**
     * 获取或创建 target 的 CDP 复用枢纽。
     *
     * 同一 pageId 的所有客户端进入同一 [CdpHubSession]，共享一条后端 CDP
     * 连接：断点/暂停/网络事件双向广播，多个 MCP 会话不互踢。
     *
     * @param pageId 客户端 URL 携带的 CDP target id
     * @return 枢纽；后端不可用返回 null
     */
    private suspend fun hubFor(pageId: String): CdpHubSession? {
        hubs[pageId]?.let { if (it.isConnected) return it }
        val hub = CdpHubSession(logger, hubScope, pageId) { dead ->
            val it2 = hubs.entries.iterator()
            while (it2.hasNext()) {
                if (it2.next().value === dead) it2.remove()
            }
        }
        if (!hub.startBackend("/devtools/page/$pageId")) {
            logger.w(LogCategory.MCP, "CDP WS 枢纽: 后端连接失败 pageId=$pageId")
            return null
        }
        hubs[pageId] = hub
        logger.i(LogCategory.MCP, "CDP WS 枢纽建立: /devtools/page/$pageId")
        return hub
    }

    /**
     * CDP WebSocket 中继（复用枢纽模式）：本 WS 会话作为枢纽的一个客户端接入。
     *
     * MCP 工具（CdpDebuggerSession / CdpNetworkMonitor）经 TcpWebSocket 接入
     * 同一枢纽时共享后端会话——调试器与网络监视器并存互不打断。
     *
     * @param pageId 连接时的 CDP target id
     */
    private suspend fun WebSocketServerSession.relayViaHub(
        pageId: String,
        kind: CdpHubSession.ClientKind,
    ) {
        val hub = hubFor(pageId)
        if (hub == null) {
            close(CloseReason(CloseReason.Codes.CANNOT_ACCEPT, "backend unavailable"))
            return
        }

        var clientToBeBytes = 0L
        var beToClientBytes = 0L
        val startAt = System.currentTimeMillis()

        // 枢纽客户端实现：后端消息 → 本 WS 帧
        val client = object : CdpHubSession.Client {
            override suspend fun send(text: String): Boolean = try {
                beToClientBytes += text.length
                outgoing.send(Frame.Text(text))
                true
            } catch (e: Exception) {
                false
            }

            override fun onBackendClosed(reason: String) {
                // 后端断开 → 主动关闭本会话（避免半开连接，客户端能立即感知）
                launch {
                    runCatching {
                        close(CloseReason(CloseReason.Codes.GOING_AWAY, "backend closed: $reason"))
                    }
                }
            }
        }
        val clientKey = hub.addClient(client, kind)
        try {
            // 客户端 → 枢纽（Text 与 Binary 帧都透传，CDP 两种编码均合法；
            // 请求 id 由枢纽重写为全局唯一后转发后端）
            for (frame in incoming) {
                when (frame) {
                    is Frame.Text -> {
                        val text = frame.readText()
                        if (text.isEmpty()) continue
                        clientToBeBytes += text.length
                        hub.onClientMessage(clientKey, text)
                    }
                    is Frame.Binary -> {
                        val bytes = frame.data
                        if (bytes.isEmpty()) continue
                        clientToBeBytes += bytes.size
                        hub.onClientMessage(clientKey, String(bytes, Charsets.UTF_8))
                    }
                    else -> Unit
                }
            }
        } catch (e: Exception) {
            logger.w(LogCategory.MCP, "CDP WS 中继: 读循环异常 ${e.javaClass.simpleName}: ${e.message}")
        } finally {
            hub.removeClient(clientKey)
            logger.i(
                LogCategory.MCP,
                "CDP WS 中继关闭: pageId=$pageId 存活=${(System.currentTimeMillis() - startAt) / 1000}s " +
                    "client→be=${clientToBeBytes / 1024}KB be→client=${beToClientBytes / 1024}KB",
            )
        }
    }

    private fun isPortInUse(port: Int): Boolean = try {
        ServerSocket().use { s ->
            s.reuseAddress = false
            s.bind(java.net.InetSocketAddress("127.0.0.1", port), 1)
            false
        }
    } catch (e: Exception) {
        true
    }
}
