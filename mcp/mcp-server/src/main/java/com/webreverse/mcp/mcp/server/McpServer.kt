package com.webreverse.mcp.mcp.server

import com.webreverse.mcp.core.common.event.EventBus
import com.webreverse.mcp.core.logging.LogCategory
import com.webreverse.mcp.core.common.model.McpClient
import com.webreverse.mcp.core.common.model.McpServerConfig
import com.webreverse.mcp.core.common.model.McpSession
import com.webreverse.mcp.core.common.model.McpSessionStatus
import com.webreverse.mcp.core.common.util.Ids
import com.webreverse.mcp.core.logging.AppLogger
import com.webreverse.mcp.core.mcp.*
import com.webreverse.mcp.core.security.TokenManager
import com.webreverse.mcp.mcp.prompts.McpPromptProvider
import com.webreverse.mcp.mcp.prompts.Prompts
import com.webreverse.mcp.mcp.resources.BrowserResources
import com.webreverse.mcp.mcp.resources.McpResourceProvider
import com.webreverse.mcp.mcp.tools.InvestigationPersistenceBridge
import com.webreverse.mcp.mcp.tools.NetworkPersistenceBridge
import com.webreverse.mcp.mcp.tools.ToolDependencies
import com.webreverse.mcp.mcp.tools.ToolModule
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.*
import io.ktor.server.plugins.calllogging.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.plugins.statuspages.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.*
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * MCP Server 状态
 */
enum class McpServerState {
    STOPPED, STARTING, RUNNING, STOPPING, ERROR,
}

/**
 * MCP Server 统计
 */
data class McpServerStats(
    val state: McpServerState,
    val uptimeMs: Long = 0,
    val connectionCount: Int = 0,
    val toolCallCount: Int = 0,
    val clientCount: Int = 0,
    val sessionCount: Int = 0,
)

/**
 * MCP Server：基于 Ktor 的 Streamable HTTP 服务。
 * 处理 JSON-RPC 请求、管理会话、认证、Tool/Resource/Prompt 分发。
 *
 * 架构：
 * AI Agent (Claude/GPT/Cursor)  --HTTP POST /mcp-->  MCP Server (Ktor)
 *                                               |
 *                                        ToolRegistry (100+ Tools)
 *                                               |
 *                                        ToolDependencies (Browser/Debugger/Hook/...)
 *                                               |
 *                                        BrowserService (WebView/Chromium)
 */
class McpServer(
    private val deps: ToolDependencies,
    private val tokenManager: TokenManager,
    private val eventBus: EventBus,
    private val logger: AppLogger,
    private val config: McpServerConfig = McpServerConfig(),
    /** serverInfo.version 展示值：由 McpServerManager 从 PackageManager 注入真实版本号 */
    private val serverVersion: String = "1.33.0",
) {
    /**
     * 协议 JSON 实例：
     * - encodeDefaults=true：确保 "jsonrpc":"2.0" 等默认字段一定出现在响应里（MCP 客户端强校验）
     * - explicitNulls=false：null 字段完全不输出。关键点——MCP SDK 用多态反序列化器
     *   区分响应类型，若输出 "error": null，客户端会按错误响应解析并在 RPCError 处崩溃
     * - ignoreUnknownKeys=true：容忍客户端请求中的未知字段
     */
    private val protocolJson = Json {
        encodeDefaults = true
        explicitNulls = false
        ignoreUnknownKeys = true
        isLenient = true
    }

    /** 传输层安全上限与统一脱敏文案（对应 ChatGPT 分析「三十三」） */
    private companion object {
        /** HTTP 请求体最大字节数：防止 POST /mcp 成为内存 DoS 入口 */
        const val MAX_REQUEST_BYTES = 8 * 1024 * 1024
        /** 暴露给 MCP 客户端的通用错误文案：不携带内部文件路径 / 命令 / 类名 / 网络地址 */
        const val INTERNAL_ERROR_MSG = "Internal server error"

        // ---- 已连接 Agent 实时性 ----
        /** HTTP 无状态客户端空闲超时：超过此时长无任何请求即视为离线并从「已连接 Agent」移除（下次请求自动恢复） */
        const val HTTP_CLIENT_IDLE_TIMEOUT_MS = 60_000L
        /** 客户端空闲清理协程周期 */
        const val CLIENT_GC_INTERVAL_MS = 10_000L

        // ---- 响应体积防护（AI 上下文保护） ----
        /** 单个工具响应的总字符预算（content 文本 + structuredContent） */
        const val MAX_TOOL_RESPONSE_CHARS = 400_000
        /** 深度截断时 structuredContent 内单个字符串字段保留的最大长度 */
        const val MAX_JSON_FIELD_CHARS = 20_000

        // ---- MCP 规范合规 ----
        /** 本服务器支持的协议版本（协商优先级从高到低） */
        val SUPPORTED_PROTOCOL_VERSIONS = listOf("2025-06-18", "2025-03-26", "2024-11-05")

        /** 只读类权限 scope：对应 Tool.annotations.readOnlyHint=true（调试/修改类不标只读） */
        val READ_ONLY_SCOPES = setOf(
            com.webreverse.mcp.core.common.permission.PermissionScope.READ_PAGE,
            com.webreverse.mcp.core.common.permission.PermissionScope.READ_DOM,
            com.webreverse.mcp.core.common.permission.PermissionScope.READ_NETWORK,
            com.webreverse.mcp.core.common.permission.PermissionScope.READ_STORAGE,
            com.webreverse.mcp.core.common.permission.PermissionScope.READ_COOKIES,
            com.webreverse.mcp.core.common.permission.PermissionScope.READ_HEADERS,
            com.webreverse.mcp.core.common.permission.PermissionScope.SCREENSHOT,
            com.webreverse.mcp.core.common.permission.PermissionScope.READ_WORKSPACE,
            com.webreverse.mcp.core.common.permission.PermissionScope.READ_FILE,
        )
    }

    private var server: EmbeddedServer<*, *>? = null

    /* * ：客户端空闲清理协程作用域（随服务启停），负责把断开的客户端从「已连接 Agent」剔除 */
    private var gcScope: CoroutineScope? = null
    private val _state = MutableStateFlow(McpServerState.STOPPED)
    val state: StateFlow<McpServerState> = _state.asStateFlow()

    private val clients = ConcurrentHashMap<String, McpClient>()
    private val sessions = ConcurrentHashMap<String, McpSession>()
    private val toolCallCounter = AtomicInteger(0)
    private val connectionCounter = AtomicInteger(0)
    private val mutex = Mutex()
    private var startedAt = 0L

    /** 当前连接的客户端（供 UI 展示） */
    val connectedClients: List<McpClient>
        get() = clients.values.toList()

    // Tool Registry
    // 修复：复用 deps.toolRegistry（AppContainer 全局唯一实例）。
    // 此前这里 new 了一个独立 ToolRegistry，导致设置页的「工具聚合模式」开关
    // 改的是 AppContainer.toolRegistry.hubMode，而 tools/list 读的是本类
    // 私有实例的 hubMode（恒为默认 true），开关因此完全无效。
    val toolRegistry = deps.toolRegistry
    // Resource Provider
    val resourceProvider = McpResourceProvider()
    // Prompt Provider
    val promptProvider = McpPromptProvider()

    /** P0-1 安全守卫：HTTP 入口 Token 认证 + 速率限制 + IP 白名单 */
    private val authGuard by lazy { AuthGuard(tokenManager, config) }

    /** P0-6 网络持久化桥：把 EventBus 网络事件写入 Room */
    private var networkPersistence: NetworkPersistenceBridge? = null

    /** P1-14 调查持久化桥：把内存调查定期同步到 Room（支持重启恢复） */
    private var investigationPersistence: InvestigationPersistenceBridge? = null

    /** 本次绑定是否需强制认证（非回环地址出于安全必须强制） */
    val authRequired: Boolean get() = authGuard.isAuthRequired()

    /**
     * 枚举本机非回环网络接口地址（供 CORS 白名单使用）。
     * 服务器绑定 0.0.0.0 后，浏览器型客户端以 Origin 指向本机 LAN IP 时
     * 需要对应 host 在白名单内才能通过预检。非浏览器客户端（多数 AI Agent）无 Origin 头，不受影响。
     */
    private fun localInterfaceHosts(): List<String> = runCatching {
        NetworkInterface.getNetworkInterfaces().asSequence()
            .filter { it.isUp && !it.isLoopback }
            .flatMap { intf -> intf.inetAddresses.asSequence() }
            .filter { !it.isAnyLocalAddress && !it.isLoopbackAddress }
            .mapNotNull { addr -> addr.hostAddress?.takeIf { it.isNotBlank() } }
            .distinct()
            .toList()
    }.getOrDefault(emptyList())

    /**
     * 统一认证入口。失败时按结果返回对应状态码并发射安全审计事件。
     * 返回 true 表示放行。
     */
    private suspend fun ApplicationCall.authorize(identity: String): Boolean = try {
        when (val result = authGuard.authenticate(request, request.origin.remoteHost, identity)) {
            is AuthGuard.AuthResult.Allowed -> true
            is AuthGuard.AuthResult.Unauthorized -> {
                eventBus.tryEmit(com.webreverse.mcp.core.common.event.McpEvent.AuthFailed(request.origin.remoteHost, result.reason))
                logger.w(LogCategory.MCP, "认证失败: ${result.reason} from ${request.origin.remoteHost}")
                respondText("""{"jsonrpc":"2.0","error":{"code":-32001,"message":"${result.reason}"}}""", ContentType.Application.Json, HttpStatusCode.Unauthorized)
                false
            }
            is AuthGuard.AuthResult.RateLimited -> {
                logger.w(LogCategory.MCP, "速率限制: $identity")
                respondText("""{"error":"rate_limited","retry_after_ms":${result.retryAfterMs}}""", ContentType.Application.Json, HttpStatusCode.TooManyRequests)
                false
            }
            is AuthGuard.AuthResult.Rejected -> {
                eventBus.tryEmit(com.webreverse.mcp.core.common.event.McpEvent.AuthFailed(request.origin.remoteHost, result.reason))
                logger.w(LogCategory.MCP, "请求被拒: ${result.reason}")
                respondText("""{"error":"forbidden"}""", ContentType.Application.Json, HttpStatusCode.Forbidden)
                false
            }
        }
    } catch (e: Exception) {
        logger.e(LogCategory.MCP, "认证异常: ${e.message}")
        respondText("""{"error":"auth_error"}""", ContentType.Application.Json, HttpStatusCode.Unauthorized)
        false
    }

    /** 启动 Server */
    suspend fun start(): Boolean = mutex.withLock {
        if (_state.value == McpServerState.RUNNING) return false
        _state.value = McpServerState.STARTING
        logger.i(LogCategory.MCP, "MCP Server 启动中...")

        try {
            // 注册 Tools
            ToolModule.registerAll(deps, toolRegistry)
            logger.i(LogCategory.MCP, "已注册 ${toolRegistry.count()} 个 Tools")

            // 注册 Resources
            resourceProvider.registerAll(BrowserResources(deps.browserService).all())
            promptsTemplates().forEach { resourceProvider.registerTemplate(it) }
            logger.i(LogCategory.MCP, "已注册 ${resourceProvider.count()} 个 Resources")

            // 注册 Prompts
            promptProvider.registerAll(Prompts.all())
            logger.i(LogCategory.MCP, "已注册 ${promptProvider.count()} 个 Prompts")

            startedAt = System.currentTimeMillis()

            server = embeddedServer(Netty, port = config.port, host = config.host) {
                install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
                install(CallLogging)
                install(StatusPages) {
                    exception<Throwable> { call, cause ->
                        // 报三三-3：完整 stacktrace 只进服务器日志，对客户端仅返回通用文案，避免泄露内部细节
                        logger.e(LogCategory.MCP, "Server error: ${cause.message}", cause)
                        // JSON-RPC 响应以 200 返回（Streamable HTTP 规范）
                        call.respondText(
                            """{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"$INTERNAL_ERROR_MSG"}}""",
                            ContentType.Application.Json,
                            HttpStatusCode.OK,
                        )
                    }
                }
                install(CORS) {
                    // P0-1 安全：不使用 anyHost()。仅允许回环与本机地址访问，避免浏览器被
                    // 恶意页面跨域调用 MCP（可配合「强制 Token 认证」开关共同兜底）。
                    // 绑定 0.0.0.0 时把本机各网络接口 IP 一并放行，
                    // 使 Origin 指向本机 LAN IP 的浏览器型客户端也能正常跨域握手。
                    allowHost("127.0.0.1")
                    allowHost("localhost")
                    allowHost("::1")
                    if (config.host != "0.0.0.0") allowHost(config.host)
                    localInterfaceHosts().forEach { allowHost(it) }
                    allowMethod(HttpMethod.Options)
                    allowMethod(HttpMethod.Post)
                    allowMethod(HttpMethod.Get)
                    allowHeader(HttpHeaders.ContentType)
                    allowHeader(HttpHeaders.Authorization)
                    allowHeader("X-MCP-Token")
                }
                routing {
                    // MCP Streamable HTTP：唯一对外传输入口。
                    // HTTP 是固定能力，不再暴露 Transport 开关，也不注册 WS/SSE 端点。
                    post("/mcp") { handleJsonRpc(call) }
                    // 当前实现不提供服务端主动推送流，GET 按 Streamable HTTP 语义返回 405。
                    get("/mcp") {
                        call.respond(HttpStatusCode.MethodNotAllowed)
                    }

                    // Health check
                    get("/health") {
                        call.respondText(
                            """{"status":"${_state.value.name}","uptime":${System.currentTimeMillis() - startedAt},"tools":${toolRegistry.count()},"clients":${clients.size}}""",
                            ContentType.Application.Json,
                        )
                    }

                    // Stats
                    get("/mcp/stats") {
                        call.respond(stats())
                    }
                }
            }.start(wait = false)

            _state.value = McpServerState.RUNNING
            logger.i(LogCategory.MCP, "MCP Server 已启动: ${config.host}:${config.port}")
            // 启动客户端空闲清理——HTTP 无状态客户端断开后无法感知，
            // 依赖空闲超时剔除，避免「已连接 Agent」列表残留幽灵连接
            gcScope?.cancel()
            gcScope = CoroutineScope(SupervisorJob() + Dispatchers.Default).also { s ->
                s.launch {
                    while (isActive) {
                        delay(CLIENT_GC_INTERVAL_MS)
                        runCatching { evictStaleClients() }
                    }
                }
            }
            // P0-6 启动网络事件 → Room 持久化链路
            networkPersistence = NetworkPersistenceBridge(deps).also { it.start() }
            // P1-14 启动调查内存 → Room 持久化链路
            investigationPersistence = InvestigationPersistenceBridge(deps).also { it.start() }
            eventBus.tryEmit(com.webreverse.mcp.core.common.event.McpEvent.ServerStarted(config.host, config.port))
            true
        } catch (e: Exception) {
            _state.value = McpServerState.ERROR
            logger.e(LogCategory.MCP, "MCP Server 启动失败: ${e.message}", e)
            false
        }
    }

    /** 停止 Server */
    suspend fun stop(): Boolean = mutex.withLock {
        if (_state.value != McpServerState.RUNNING) return false
        _state.value = McpServerState.STOPPING
        logger.i(LogCategory.MCP, "MCP Server 停止中...")

        try {
            // 停止客户端空闲清理协程
            gcScope?.cancel()
            gcScope = null
            // P0-6 停止网络持久化订阅
            networkPersistence?.stop()
            networkPersistence = null
            // P1-14 停止调查持久化
            investigationPersistence?.stop()
            investigationPersistence = null
            server?.stop(500, 1000)
            server = null
            _state.value = McpServerState.STOPPED
            logger.i(LogCategory.MCP, "MCP Server 已停止")
            eventBus.tryEmit(com.webreverse.mcp.core.common.event.McpEvent.ServerStopped())
            true
        } catch (e: Exception) {
            _state.value = McpServerState.ERROR
            logger.e(LogCategory.MCP, "MCP Server 停止失败: ${e.message}", e)
            false
        }
    }

    /** 获取统计 */
    fun stats(): McpServerStats = McpServerStats(
        state = _state.value,
        uptimeMs = if (startedAt > 0) System.currentTimeMillis() - startedAt else 0,
        // 累计连接次数（HTTP initialize 计数）
        connectionCount = connectionCounter.get(),
        toolCallCount = toolCallCounter.get(),
        clientCount = clients.size,
        sessionCount = sessions.size,
    )

    /**
     * 清理空闲 HTTP 客户端，让「已连接 Agent」反映真实在线状态。
     * Streamable HTTP 没有长连接断开事件，只能按最近一次请求时间推断离线。
     */
    fun evictStaleClients(idleTimeoutMs: Long = HTTP_CLIENT_IDLE_TIMEOUT_MS) {
        val now = System.currentTimeMillis()
        val staleKeys = clients.entries
            .filter { (_, client) -> now - client.lastActiveAt > idleTimeoutMs }
            .map { it.key }
        if (staleKeys.isEmpty()) return
        staleKeys.forEach { key ->
            clients.remove(key)
            val staleSessionKeys = sessions.entries
                .filter { it.key == key || it.value.clientId == key }
                .map { it.key }
            staleSessionKeys.forEach { sessions.remove(it) }
        }
        logger.i(LogCategory.MCP, "已清理 ${staleKeys.size} 个空闲 HTTP 客户端（长时间无活动，视为已断开）")
    }

    /** 获取当前配置 */
    fun currentConfig(): McpServerConfig = config

    private fun promptsTemplates(): List<com.webreverse.mcp.core.mcp.ResourceTemplate> = listOf(
        com.webreverse.mcp.core.mcp.ResourceTemplate(
            uriTemplate = "browser://page/{tabId}",
            name = "指定标签页",
            description = "通过 tabId 读取指定标签页信息",
            mimeType = "application/json",
        ),
        com.webreverse.mcp.core.mcp.ResourceTemplate(
            uriTemplate = "browser://network/{tabId}",
            name = "指定标签页网络",
            description = "读取指定标签页的网络请求",
            mimeType = "application/json",
        ),
    )

    // ==================== JSON-RPC 处理 ====================

    private suspend fun handleJsonRpc(call: ApplicationCall) {
        try {
            // 报三三-2：在读取/解析前校验请求体大小，拒绝超大 payload（防内存 DoS）
            val declaredLength = call.request.header(HttpHeaders.ContentLength)?.toLongOrNull()
            if (declaredLength != null && declaredLength > MAX_REQUEST_BYTES) {
                logger.w(LogCategory.MCP, "请求体过大已拒绝: $declaredLength bytes from ${call.request.origin.remoteHost}")
                respondPayloadTooLarge(call)
                return
            }
            val body = call.receiveText()

            // 分块传输时无 Content-Length，读后二次校验长度（纵深防御）
            if (body.length > MAX_REQUEST_BYTES) {
                logger.w(LogCategory.MCP, "请求体超限（读后校验）已拒绝: ${body.length} chars from ${call.request.origin.remoteHost}")
                respondPayloadTooLarge(call)
                return
            }

            // P0-1 认证：在解析/处理之前于传输层统一拒绝未授权请求
            val preRemote = call.request.origin.remoteHost
            val preIdentity = "http:${call.request.header("Mcp-Session-Id") ?: "anon:$preRemote"}"
            if (!call.authorize(preIdentity)) return

            val request = protocolJson.decodeFromString<JsonRpcRequest>(body)

            // 通知类消息（notifications/* 或无 id）：按 MCP Streamable HTTP 规范返回 202 Accepted，无响应体
            if (request.method.startsWith("notifications/") || request.id is JsonNull) {
                call.respond(HttpStatusCode.Accepted)
                return
            }

            val remoteHost = call.request.origin.remoteHost

            // 注册/更新 HTTP 客户端与统计。每个非通知请求都计入：
            // 客户端在服务重启后通常不会重新 initialize，而是带着旧会话头直接调用工具，
            // 若只在 initialize 时注册，连接数/客户端/会话/已连接 Agent 将恒为 0
            val clientKey = registerHttpClient(call, request, remoteHost) ?: "http:$remoteHost"

            val agentName = request.params["clientInfo"]?.let { it as? JsonObject }
                ?.stringField("name")?.ifBlank { null }
                ?: clients[clientKey]?.name ?: "AI Agent"

            val response = processRequest(request, clientKey, agentName)

            eventBus.tryEmit(com.webreverse.mcp.core.common.event.McpEvent.ToolInvoked(request.method, "http", false))

            call.respondText(
                protocolJson.encodeToString(JsonRpcResponse.serializer(), response),
                ContentType.Application.Json,
            )
        } catch (e: Exception) {
            // 报三三-3：完整 stacktrace 只进服务器日志，客户端仅收到通用文案
            logger.e(LogCategory.MCP, "JSON-RPC 处理错误: ${e.message}", e)
            // MCP Streamable HTTP 规范：JSON-RPC 响应（含 error body）以 200 返回；
            // 5xx 会被部分客户端 SDK 当作传输故障直接抛异常，丢失 error body
            call.respondText(
                """{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"$INTERNAL_ERROR_MSG"}}""",
                ContentType.Application.Json,
                HttpStatusCode.OK,
            )
        }
    }

    /**
     * 超大请求体统一响应。此前返回裸 `{"error":"payload_too_large"}`，
     * 非 JSON-RPC 结构，MCP 客户端常将其误报为「JSON 解析失败」。
     * 现按 JSON-RPC 2.0 规范返回结构化错误（-32600 Invalid Request），
     * 并附带体积上限与 file.write 单次 5MB 提示，客户端可读、可关联请求。
     */
    private suspend fun respondPayloadTooLarge(call: ApplicationCall) {
        val maxMb = MAX_REQUEST_BYTES / (1024 * 1024)
        call.respondText(
            """{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Request body too large (max ${maxMb}MB). For large file writes use file.append in batches or terminal.exec"}}""",
            ContentType.Application.Json,
            HttpStatusCode.PayloadTooLarge,
        )
    }

    /**
     * 注册/更新 HTTP 客户端（Streamable HTTP 无状态，按请求跟踪）：
     * - initialize：生成新 sessionId（经 Mcp-Session-Id 响应头返回给客户端）并以此注册，
     *   同时清理同主机残留的旧 HTTP 客户端/会话（服务重启后的过期会话）
     * - 其他请求：优先按客户端回传的 Mcp-Session-Id 请求头识别同一客户端；
     *   未携带时（客户端从未 initialize 或会话已丢失）退化为按来源主机识别
     */
    private fun registerHttpClient(call: ApplicationCall, request: JsonRpcRequest, remoteHost: String): String? {
        val now = System.currentTimeMillis()
        val sessionHeader = call.request.header("Mcp-Session-Id")

        if (request.method == McpMethod.INITIALIZE) {
            val sessionId = Ids.uuid()
            call.response.header("Mcp-Session-Id", sessionId)

            val clientInfo = request.params["clientInfo"] as? JsonObject
            val clientName = clientInfo?.stringField("name")
                ?: request.params.stringField("clientName")
                ?: "Unknown"
            val clientVersion = clientInfo?.stringField("version").orEmpty()
            val displayName = if (clientVersion.isNotEmpty()) "$clientName $clientVersion" else clientName

            // 清理同主机残留的旧 HTTP 客户端与对应会话，避免重复计数
            clients.entries
                .filter { it.value.transport == "HTTP" && it.value.remoteAddress == remoteHost }
                .map { it.key }
                .forEach { key ->
                    clients.remove(key)
                    sessions.remove(key)
                }

            val key = "http:$sessionId"
            clients[key] = McpClient(
                id = sessionId,
                name = displayName,
                transport = "HTTP",
                remoteAddress = remoteHost,
                connectedAt = now,
                lastActiveAt = now,
            )
            connectionCounter.incrementAndGet()
            sessions[key] = McpSession(
                id = sessionId,
                clientId = key,
                clientName = clientName,
                startedAt = now,
            )
            return key
        }

        val identity = sessionHeader ?: remoteHost
        val key = "http:$identity"
        val existing = clients[key]
        if (existing == null) {
            // （P0-3 修复）：HTTP 客户端无界增长兜底。原实现每个新 key
            // 都新建一条 clients/sessions 记录且无 TTL 无上限——客户端伪造不同
            // Mcp-Session-Id 即可无限膨胀两个 Map。超限按 lastActiveAt 淘汰最旧。
            trimHttpClients()
            val userAgent = call.request.header(HttpHeaders.UserAgent)?.takeIf { it.isNotBlank() }
            val displayName = userAgent ?: "HTTP-Client ($remoteHost)"
            clients[key] = McpClient(
                id = identity,
                name = displayName,
                transport = "HTTP",
                remoteAddress = remoteHost,
                connectedAt = now,
                lastActiveAt = now,
            )
            connectionCounter.incrementAndGet()
            sessions[key] = McpSession(
                id = identity,
                clientId = key,
                clientName = displayName,
                startedAt = now,
            )
        } else {
            clients[key] = existing.copy(lastActiveAt = now)
        }
        return key
    }

    /* *（P0-3 修复）：HTTP 无状态客户端超限淘汰（按 lastActiveAt 最旧优先） */
    private fun trimHttpClients(maxHttpClients: Int = 64) {
        val httpClients = clients.entries.filter { it.value.transport == "HTTP" }
        if (httpClients.size <= maxHttpClients) return
        httpClients
            .sortedBy { it.value.lastActiveAt }
            .take(httpClients.size - maxHttpClients)
            .forEach { entry ->
                clients.remove(entry.key)
                sessions.remove(entry.key)
            }
    }

    /** 处理 JSON-RPC 请求 → 分发到 Tools/Resources/Prompts */
    private suspend fun processRequest(
        request: JsonRpcRequest,
        sessionId: String = "unknown",
        agentName: String = "AI Agent",
    ): JsonRpcResponse {
        val id = request.id
        return when (request.method) {
            McpMethod.INITIALIZE -> handleInitialize(request)
            // ping 结果按规范为空对象
            McpMethod.PING -> JsonRpcResponse.success(id, JsonObject(emptyMap()))
            McpMethod.TOOLS_LIST -> handleToolsList(id, request.params)
            McpMethod.TOOLS_CALL -> handleToolsCall(id, request.params, sessionId, agentName)
            McpMethod.RESOURCES_LIST -> handleResourcesList(id)
            McpMethod.RESOURCES_READ -> handleResourcesRead(id, request.params)
            McpMethod.RESOURCES_TEMPLATES_LIST -> handleResourcesTemplatesList(id)
            McpMethod.PROMPTS_LIST -> handlePromptsList(id)
            McpMethod.PROMPTS_GET -> handlePromptsGet(id, request.params)
            McpMethod.COMPLETION_COMPLETE -> handleCompletion(id, request.params)
            McpMethod.LOGGING_SET_LEVEL -> JsonRpcResponse.success(id, JsonObject(emptyMap()))
            McpMethod.NOTIFICATIONS_INITIALIZED -> JsonRpcResponse.success(id, JsonObject(emptyMap()))
            else -> JsonRpcResponse.error(id, JsonRpcErrorCode.METHOD_NOT_FOUND, "Unknown method: ${request.method}")
        }
    }

    private fun handleInitialize(request: JsonRpcRequest): JsonRpcResponse {
        // 客户端注册与会话创建由 registerHttpClient 统一处理
        // 版本协商（MCP 规范）：支持客户端请求的版本则回显；
        // 不支持/未指定时返回服务器最高支持版本，由客户端决定是否断开
        val requested = request.params.stringField("protocolVersion")
        val protocolVersion = if (requested != null && requested in SUPPORTED_PROTOCOL_VERSIONS) {
            requested
        } else {
            SUPPORTED_PROTOCOL_VERSIONS.first()
        }

        // MCP 标准 InitializeResult：protocolVersion + capabilities + serverInfo（必需）
        return JsonRpcResponse.success(
            id = request.id,
            result = buildJsonObject {
                put("protocolVersion", JsonPrimitive(protocolVersion))
                put("capabilities", buildJsonObject {
                    put("tools", buildJsonObject {
                        put("listChanged", JsonPrimitive(true))
                    })
                    put("resources", buildJsonObject {
                        put("listChanged", JsonPrimitive(true))
                        put("subscribe", JsonPrimitive(true))
                    })
                    put("prompts", buildJsonObject {
                        put("listChanged", JsonPrimitive(true))
                    })
                    put("logging", buildJsonObject {})
                })
                put("serverInfo", buildJsonObject {
                    put("name", JsonPrimitive("WebReverseMCP"))
                    put("version", JsonPrimitive(serverVersion))
                })
                put("instructions", JsonPrimitive("WebReverse MCP Server：提供浏览器自动化、页面逆向分析、网络抓包、Hook 等工具集。"))
            },
        )
    }

    /** 从 JsonObject 安全读取字符串字段 */
    private fun JsonObject?.stringField(key: String): String? =
        (this?.get(key) as? JsonPrimitive)?.contentOrNull

    private fun handleToolsList(id: JsonElement, params: JsonObject): JsonRpcResponse {
        // 页上限动态取自当前可见工具总数，始终一页返回全部工具。
        // 历史： 固定 50 导致不跟随 nextCursor 翻页的客户端只见首页；
        // 固定 500 仍是猜出来的魔数。现改为 all.size 自动适配——
        // 无论聚合模式（34 个）还是全量模式（410+），工具数增长也无需改代码。
        // cursor/nextCursor 分页协议保留：客户端显式带 cursor 时按其续页（防越界）。
        val cursor = params["cursor"]?.let { (it as? JsonPrimitive)?.contentOrNull }?.toIntOrNull() ?: 0
        val all = toolRegistry.listMetadata().sortedBy { it.name }
        val from = cursor.coerceIn(0, all.size)
        val pageSize = all.size  // 动态上限：等于总数，即单页全量返回
        val page = all.drop(from).take(pageSize)
        val nextCursor = from + pageSize

        // MCP 标准 Tool 字段：name + description + inputSchema + annotations（可选）
        val tools = page.map { meta ->
            buildJsonObject {
                put("name", JsonPrimitive(meta.name))
                put("description", JsonPrimitive(meta.description))
                put("inputSchema", meta.inputSchema)
                // annotations（可选提示，客户端用于 UI/风控）：按权限与风险等级推导
                put("annotations", buildJsonObject {
                    val readOnly = meta.permission in READ_ONLY_SCOPES
                    put("readOnlyHint", JsonPrimitive(readOnly))
                    if (!readOnly) {
                        put("destructiveHint", JsonPrimitive(meta.riskLevel >= com.webreverse.mcp.core.common.permission.RiskLevel.HIGH))
                    }
                    // 本服务器工具全部操作本地 WebView，不访问外部互联网服务
                    put("openWorldHint", JsonPrimitive(false))
                })
            }
        }
        return JsonRpcResponse.success(
            id = id,
            result = buildJsonObject {
                put("tools", JsonArray(tools))
                if (nextCursor < all.size) {
                    put("nextCursor", JsonPrimitive(nextCursor.toString()))
                }
            },
        )
    }

    private suspend fun handleToolsCall(id: JsonElement, params: JsonObject, sessionId: String, agentName: String): JsonRpcResponse {
        val name = params["name"]?.let { (it as? JsonPrimitive)?.content } ?: ""
        val arguments = params["arguments"] as? JsonObject ?: JsonObject(emptyMap())

        if (name.isBlank()) {
            return JsonRpcResponse.error(id, JsonRpcErrorCode.INVALID_PARAMS, "Missing tool name")
        }

        val tool = toolRegistry.get(name)
        if (tool == null) {
            return JsonRpcResponse.error(id, JsonRpcErrorCode.TOOL_NOT_FOUND, "Tool not found: $name")
        }

        toolCallCounter.incrementAndGet()
        logger.i(LogCategory.MCP, "调用 Tool: $name (session=$sessionId, agent=$agentName)")

        // 构建工具执行上下文：显式 tabId 参数优先（用于「分析指定标签页」类工具），
        // 缺省则为空，由 ToolDependencies.activeSession() 按固定 Tab 绑定/活动 Tab 解析。
        val tabId = (arguments["tabId"] as? JsonPrimitive)?.content
            ?: arguments["targetTabId"]?.let { (it as? JsonPrimitive)?.content }
        val context = com.webreverse.mcp.core.mcp.ToolContext(
            sessionId = sessionId,
            clientId = sessionId,
            tabId = tabId,
            agentName = agentName,
            deadline = System.currentTimeMillis() + tool.metadata.timeoutMs,
        )

        return try {
            val raw = withTimeout(tool.metadata.timeoutMs) {
                tool.execute(context, arguments)
            }
            // 全局响应体积防护。任何工具（含未来新增）返回的文本/结构化内容
            // 超过 MAX_TOOL_RESPONSE_CHARS 时统一截断，防止 MB 级响应把 AI 上下文撑爆
            // （re.analyze_page 曾因 minified 单行 lineContent 返回数 MB 卡死 AI）。
            val result = sanitizeToolResult(raw, name)

            if (result.isError) {
                // 标准 CallToolResult：content + isError（错误详情通过 content 文本传达）
                JsonRpcResponse.success(
                    id = id,
                    result = buildJsonObject {
                        put("isError", JsonPrimitive(true))
                        put("content", JsonArray(result.content.map { c ->
                            buildJsonObject {
                                put("type", JsonPrimitive(c.type))
                                val t = c.text
                                if (t != null) put("text", JsonPrimitive(t))
                                val mt = c.mimeType
                                if (mt != null) put("mimeType", JsonPrimitive(mt))
                                val d = c.data
                                if (d != null) put("data", JsonPrimitive(d))
                            }
                        }))
                    },
                )
            } else {
                JsonRpcResponse.success(
                    id = id,
                    result = buildJsonObject {
                        put("content", JsonArray(result.content.map { c ->
                            buildJsonObject {
                                put("type", JsonPrimitive(c.type))
                                val t = c.text
                                if (t != null) put("text", JsonPrimitive(t))
                                val mt = c.mimeType
                                if (mt != null) put("mimeType", JsonPrimitive(mt))
                                val d = c.data
                                if (d != null) put("data", JsonPrimitive(d))
                            }
                        }))
                        val structured = result.structuredContent
                        if (structured != null) {
                            put("structuredContent", structured)
                        }
                    },
                )
            }
        } catch (e: TimeoutCancellationException) {
            // MCP 规范：工具执行失败（超时/异常）属于"执行错误"而非"协议错误"，
            // 必须以 CallToolResult{isError:true} 返回——JSON-RPC error 会被部分客户端
            // 直接抛异常，AI 看不到失败原因无法自行调整参数重试
            logger.w(LogCategory.MCP, "Tool 执行超时: $name (${tool.metadata.timeoutMs}ms)")
            toolExecutionErrorResult(id, "TIMEOUT", "工具执行超时（${tool.metadata.timeoutMs / 1000}s）：$name")
        } catch (e: Exception) {
            // 报三三-3：完整 stacktrace 只进服务器日志；对客户端仅返回异常类型（不含内部路径/命令报文）
            logger.e(LogCategory.MCP, "Tool 执行失败: $name - ${e.message}", e)
            val detail = e::class.simpleName?.takeIf { it.isNotBlank() } ?: "exception"
            toolExecutionErrorResult(id, "EXECUTION_ERROR", "工具执行失败（$detail）：$name")
        }
    }

    /** 工具执行层错误 → 标准 CallToolResult{isError:true}（内容对 AI 可见，可引导重试） */
    private fun toolExecutionErrorResult(id: JsonElement, code: String, message: String): JsonRpcResponse =
        JsonRpcResponse.success(
            id = id,
            result = buildJsonObject {
                put("isError", JsonPrimitive(true))
                put("content", JsonArray(listOf(
                    buildJsonObject {
                        put("type", JsonPrimitive("text"))
                        put("text", JsonPrimitive("Error [$code]: $message"))
                    },
                )))
            },
        )

    /**
     * 响应体积防护：工具结果超出 [MAX_TOOL_RESPONSE_CHARS] 时截断。
     * - JSON 工具：递归裁剪 structuredContent 超长字符串字段，文本镜像同步替换
     * - 纯文本工具：按剩余预算截断并附加提示（引导 AI 用更小粒度参数分页拉取）
     * 兜底防线：即便某个工具漏了自身的 maxChars/limit 参数，也不会把 MB 级内容发给 AI。
     */
    private fun sanitizeToolResult(raw: McpToolResult, toolName: String): McpToolResult {
        val textTotal = raw.content.sumOf { it.text?.length ?: 0 }
        val structuredTotal = raw.structuredContent?.toString()?.length ?: 0
        val total = textTotal + structuredTotal
        if (total <= MAX_TOOL_RESPONSE_CHARS) return raw

        logger.w(
            LogCategory.MCP,
            "工具 $toolName 响应过大（${total} 字符），已从服务端截断至 $MAX_TOOL_RESPONSE_CHARS 预算内",
        )
        val notice = "\n\n[服务端截断] 原始响应 ${total} 字符超出 ${MAX_TOOL_RESPONSE_CHARS} 上限，" +
            "已截断以保护上下文。请改用更小的 maxChars/limit/maxLines 参数，或分段/按 ID 精确获取。"

        // 1) structuredContent 递归裁剪超长字符串字段
        var structuredChanged = false
        val structured = raw.structuredContent?.let {
            val (tree, changed) = deepTruncateJson(it)
            structuredChanged = changed
            (tree as? JsonObject) ?: it
        }

        // 2) 文本 content：JSON 工具镜像同步替换；纯文本按预算截断（图像 base64 不动）
        var budget = (MAX_TOOL_RESPONSE_CHARS * 0.9).toInt() - notice.length
        val newContent = raw.content.mapIndexed { idx, c ->
            val t = c.text ?: return@mapIndexed c
            when {
                structuredChanged && structured != null && idx == 0 ->
                    c.copy(text = structured.toString() + notice)
                t.length <= budget -> {
                    budget -= t.length
                    c
                }
                else -> {
                    val cut = t.take(budget.coerceAtLeast(0))
                    budget = 0
                    c.copy(text = cut + notice)
                }
            }
        }

        return McpToolResult(
            content = newContent,
            structuredContent = structured ?: raw.structuredContent,
            isError = raw.isError,
            errorCode = raw.errorCode,
            errorMessage = raw.errorMessage,
            details = raw.details,
            progress = raw.progress,
            total = raw.total,
        )
    }

    /** 递归把 JsonObject/JsonArray 中超过 [MAX_JSON_FIELD_CHARS] 的字符串值截断；返回（新树, 是否修改） */
    private fun deepTruncateJson(element: JsonElement): Pair<JsonElement, Boolean> {
        when (element) {
            is JsonObject -> {
                var changed = false
                val newObj = buildJsonObject {
                    for ((k, v) in element) {
                        val s = (v as? JsonPrimitive)?.contentOrNull
                        if (s != null && s.length > MAX_JSON_FIELD_CHARS) {
                            changed = true
                            put(
                                k,
                                JsonPrimitive(
                                    s.take(MAX_JSON_FIELD_CHARS) +
                                        "…[截断：原 ${s.length} 字符，请用更小粒度参数分页获取]",
                                ),
                            )
                        } else if (v !is JsonPrimitive) {
                            val (child, childChanged) = deepTruncateJson(v)
                            if (childChanged) changed = true
                            put(k, child)
                        } else {
                            put(k, v)
                        }
                    }
                    if (changed) put("responseTruncated", JsonPrimitive(true))
                }
                return newObj to changed
            }
            is JsonArray -> {
                var changed = false
                val items = element.map { v ->
                    val (child, childChanged) = deepTruncateJson(v)
                    if (childChanged) changed = true
                    child
                }
                return JsonArray(items) to changed
            }
            else -> return element to false
        }
    }

    private fun handleResourcesList(id: JsonElement): JsonRpcResponse {
        val resources = resourceProvider.list().map { r ->
            buildJsonObject {
                put("uri", JsonPrimitive(r.uri))
                put("name", JsonPrimitive(r.name))
                put("description", JsonPrimitive(r.description))
                put("mimeType", JsonPrimitive(r.mimeType))
            }
        }
        return JsonRpcResponse.success(
            id = id,
            result = buildJsonObject {
                put("resources", JsonArray(resources))
            },
        )
    }

    private suspend fun handleResourcesRead(id: JsonElement, params: JsonObject): JsonRpcResponse {
        val uri = params["uri"]?.let { (it as? JsonPrimitive)?.content } ?: ""
        if (uri.isBlank()) {
            return JsonRpcResponse.error(id, JsonRpcErrorCode.INVALID_PARAMS, "Missing resource uri")
        }

        val resource = resourceProvider.get(uri)
        if (resource == null) {
            return JsonRpcResponse.error(id, JsonRpcErrorCode.RESOURCE_NOT_FOUND, "Resource not found: $uri")
        }

        return try {
            val content = resource.read()
            JsonRpcResponse.success(
                id = id,
                result = buildJsonObject {
                    put("contents", JsonArray(listOf(
                        buildJsonObject {
                            put("uri", JsonPrimitive(content.uri))
                            put("mimeType", JsonPrimitive(content.mimeType))
                            val text = content.text
                            if (text != null) put("text", JsonPrimitive(text))
                            val blob = content.blob
                            if (blob != null) put("blob", JsonPrimitive(blob))
                        },
                    )))
                },
            )
        } catch (e: Exception) {
            logger.e(LogCategory.MCP, "读取资源失败: $uri - ${e.message}", e)
            JsonRpcResponse.error(id, JsonRpcErrorCode.INTERNAL_ERROR, "Failed to read resource")
        }
    }

    private fun handleResourcesTemplatesList(id: JsonElement): JsonRpcResponse {
        val templates = resourceProvider.listTemplates().map { t ->
            buildJsonObject {
                put("uriTemplate", JsonPrimitive(t.uriTemplate))
                put("name", JsonPrimitive(t.name))
                put("description", JsonPrimitive(t.description))
                put("mimeType", JsonPrimitive(t.mimeType))
            }
        }
        return JsonRpcResponse.success(
            id = id,
            result = buildJsonObject {
                put("resourceTemplates", JsonArray(templates))
            },
        )
    }

    private fun handlePromptsList(id: JsonElement): JsonRpcResponse {
        val prompts = promptProvider.list().map { p ->
            buildJsonObject {
                put("name", JsonPrimitive(p.name))
                put("description", JsonPrimitive(p.description))
                put("arguments", JsonArray(p.arguments.map { a ->
                    buildJsonObject {
                        put("name", JsonPrimitive(a.name))
                        put("description", JsonPrimitive(a.description))
                        put("required", JsonPrimitive(a.required))
                    }
                }))
            }
        }
        return JsonRpcResponse.success(
            id = id,
            result = buildJsonObject {
                put("prompts", JsonArray(prompts))
            },
        )
    }

    private suspend fun handlePromptsGet(id: JsonElement, params: JsonObject): JsonRpcResponse {
        val name = params["name"]?.let { (it as? JsonPrimitive)?.content } ?: ""
        val arguments = params["arguments"] as? JsonObject
        val args = arguments?.entries?.associate { (k, v) -> k to (v as? JsonPrimitive)?.content.orEmpty() } ?: emptyMap()

        if (name.isBlank()) {
            return JsonRpcResponse.error(id, JsonRpcErrorCode.INVALID_PARAMS, "Missing prompt name")
        }

        val prompt = promptProvider.get(name)
        if (prompt == null) {
            return JsonRpcResponse.error(id, JsonRpcErrorCode.RESOURCE_NOT_FOUND, "Prompt not found: $name")
        }

        return try {
            val result = prompt.get(args)
            JsonRpcResponse.success(
                id = id,
                result = buildJsonObject {
                    put("description", JsonPrimitive(result.description))
                    put("messages", JsonArray(result.messages.map { m ->
                        buildJsonObject {
                            put("role", JsonPrimitive(m.role))
                            put("content", buildJsonObject {
                                put("type", JsonPrimitive(m.content.type))
                                put("text", JsonPrimitive(m.content.text))
                            })
                        }
                    }))
                },
            )
        } catch (e: Exception) {
            logger.e(LogCategory.MCP, "获取 Prompt 失败: $name - ${e.message}", e)
            JsonRpcResponse.error(id, JsonRpcErrorCode.INTERNAL_ERROR, "Failed to get prompt")
        }
    }

    private fun handleCompletion(id: JsonElement, params: JsonObject): JsonRpcResponse {
        // 简易 completion 实现
        return JsonRpcResponse.success(id, buildJsonObject {
            put("completion", buildJsonObject {
                put("values", JsonArray(emptyList()))
                put("total", JsonPrimitive(0))
            })
        })
    }
}