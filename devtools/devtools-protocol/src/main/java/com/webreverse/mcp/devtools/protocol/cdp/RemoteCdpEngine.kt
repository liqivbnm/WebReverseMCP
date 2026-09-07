package com.webreverse.mcp.devtools.protocol.cdp

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.put
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket

/**
 * 可插拔真 Chrome / CDP 后端（方向6 / ）。
 *
 * 让本应用的 MCP 调试能力不再只绑定进程内 WebView——支持把外部真实浏览器
 * （桌面 Chrome、Chromium、Edge、AnyProxy/自研 CDP 网关、独立 headless 实例等）
 * 作为可插拔后端接入：发现 host:port 上暴露的 DevTools HTTP 端点（/json/version、
 * /json/list），选中一个 target，用 [TcpWebSocket] 连到其 webSocketDebuggerUrl 的
 * WebSocket，包一层 [CdpSession] 即可复用上层全部 CDP 命令/事件链路。
 *
 * 与本地 WebView 后端的关系：
 * - 本地后端：`CdpTransport`/`CdpHub`（unix socket + 进程内复用枢纽），绑定本 WebView。
 * - 远端后端：本引擎（TCP + 真 Chrome），绑定外部实例，二者通过
 *   [RemoteCdpEngine.active] 作为互斥可插拔切换后端；MCP 工具据此决定走哪条链路。
 *
 * 复用点：TcpWebSocket（帧/握手/超时）、CdpSession（JSON-RPC/状态机/事件流）均已
 * 抽象为独立于"本地 unix socket"的传输，因此外部 Chrome 接入零额外依赖。
 */
object RemoteCdpEngine {

    private val json = Json { ignoreUnknownKeys = true }

    /** 引擎独立协程作用域（TcpWebSocket + CdpSession 的接收循环用） */
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /** 最近一次发现/附加失败原因（供 attach_remote 提示） */
    @Volatile
    var lastError: String? = null

    /** 一条可插拔远端 CDP 后端连接 */
    class RemoteBackend(
        val host: String,
        val port: Int,
        val target: DevToolsPageInfo,
        val session: CdpSession,
        /** 启用状态：Runtime.enable 成功后由 [attach] 置 true */
        val ready: Boolean,
        /** 后端描述：version/browser 名，discover 时一并拿到 */
        val browser: String = "",
    ) {
        val isAlive: Boolean get() = session.isConnected
        fun describe(): Map<String, String> = linkedMapOf(
            "host" to host,
            "port" to port.toString(),
            "targetId" to target.id,
            "title" to target.title,
            "url" to target.url,
            "browser" to browser,
            "ready" to ready.toString(),
            "alive" to isAlive.toString(),
            "state" to session.state.value.name,
        )
    }

    /** 当前可插拔远端后端；null = 未附加（此时工具走本地 WebView 后端） */
    @Volatile
    private var _active: RemoteBackend? = null
    val active: RemoteBackend? get() = _active
    val isAttached: Boolean get() = _active?.isAlive == true

    /**
     * tcpGet /json/version——探测远端浏览器并拿取版本/标签信息。
     * @return 按行解析的键值，如 {"Browser":"Chrome/126.0.0.0","Protocol-Version":"1.3"}
     */
    suspend fun probe(host: String, port: Int): Map<String, String> = withContext(Dispatchers.IO) {
        val body = tcpGet(host, port, "/json/version") ?: return@withContext emptyMap()
        body.lineSequence().mapNotNull { line ->
            val idx = line.indexOf(':')
            if (idx <= 0) null else line.substring(0, idx).trim() to line.substring(idx + 1).trim()
        }.toMap()
    }

    /**
     * 发现远端浏览器可调试 target（/json/list，与本地 WebView 同格式）。
     * @param filter 可选 URL/标题子串过滤（不区分大小写）；null = 全部
     */
    suspend fun discover(host: String, port: Int, filter: String? = null): List<DevToolsPageInfo> =
        withContext(Dispatchers.IO) {
            val body = tcpGet(host, port, "/json/list")
                ?: run { lastError = "远端 CDP HTTP 不可达($host:$port)" ; return@withContext emptyList() }
            val targets = runCatching {
                json.decodeFromString(ListSerializer(DevToolsPageInfo.serializer()), body)
            }.getOrElse {
                lastError = "远端 /json/list 解析失败: ${it.message}"
                return@withContext emptyList()
            }
            val f = filter?.trim()?.lowercase()
            if (f.isNullOrBlank()) targets
            else targets.filter {
                it.url.lowercase().contains(f) || it.title.lowercase().contains(f) ||
                    (it.type + ":" + it.id).lowercase().contains(f)
            }
        }

    /**
     * 附加到远端 target（可插拔后端接入的核心）。
     * 断开上一个 active，经 TCP 升级 WebSocket，启用 Runtime 域，返回 [RemoteBackend]。
     */
    suspend fun attach(
        host: String,
        port: Int,
        target: DevToolsPageInfo,
        browser: String = "",
    ): RemoteBackend? {
        detach()
        val path = wsPathOf(target)
        val ws = withContext(Dispatchers.IO) {
            TcpWebSocket.connect("$host:$port", path)
        } ?: run {
            if (lastError == null) lastError = "远端 WebSocket 连接失败($host:$port$path)"
            return null
        }
        val session = CdpSession(ws, scope)
        session.start()
        if (!session.isConnected) {
            session.close()
            lastError = "远端会话未建立($host:$port$path)"
            return null
        }
        val enable = session.callDetailed("Runtime.enable", JsonObject(emptyMap()), null, 2)
        if (enable.isFailure) {
            lastError = "远端 Runtime.enable 失败: ${enable.exceptionOrNull()?.message}"
            session.close()
            return null
        }
        // 收集目标自身的描述信息以作后端标识
        val titleElement = runCatching {
            val r = session.call(
                "Runtime.evaluate",
                kotlinx.serialization.json.buildJsonObject { put("expression", "document.title") },
            )
            (r?.get("result") as? JsonObject)?.get("value")?.toString()?.trim('"').orEmpty()
        }.getOrNull().orEmpty()
        runCatching { session.markReady() }
        val backend = RemoteBackend(host, port, target, session, ready = true, browser = browser)
        _active = backend
        lastError = null
        return backend
    }

    /** 根据 target 的 webSocketDebuggerUrl 提取 WS path（如 /devtools/page/ABC）。 */
    fun wsPathOf(target: DevToolsPageInfo): String {
        val url = target.webSocketDebuggerUrl
        if (url.isNotBlank()) {
            runCatching {
                val uri = java.net.URI.create(url)
                val path = uri.rawPath
                if (path.isNotBlank()) return path
            }
        }
        return "/devtools/page/${target.id}"
    }

    /** 分离并释放当前远端后端连接。幂等。 */
    fun detach() {
        val current = _active ?: return
        _active = null
        runCatching { current.session.close() }
    }

    /** 检查活跃后端是否仍可调用（可插拔切换的探活快捷方式） */
    fun healthy(): Boolean = isAttached && _active != null && _active!!.session.state.value != CdpSession.State.CLOSED

    // ---------------- HTTP over TCP （远端发现，无 OkHttp 依赖） ----------------

    /** 秒级超时 */
    private const val IO_TIMEOUT_MS = 6_000

    private fun tcpGet(host: String, port: Int, path: String): String? {
        var socket: Socket? = null
        return try {
            socket = Socket()
            socket.tcpNoDelay = true
            socket.connect(InetSocketAddress(host, port), 5_000)
            socket.soTimeout = IO_TIMEOUT_MS
            val output = socket.getOutputStream()
            // Chrome DevTools 要求 Host 携带端口（防 DNS rebinding 与多实例路由）
            val request = "GET $path HTTP/1.1\r\nHost: $host:$port\r\nConnection: close\r\n\r\n"
            output.write(request.toByteArray(Charsets.US_ASCII))
            output.flush()
            readHttpResponse(socket.getInputStream())
        } catch (e: Exception) {
            lastError = "连接远端($host:$port$path): ${e.javaClass.simpleName}: ${e.message}"
            null
        } finally {
            runCatching { socket?.close() }
        }
    }

    /** 解析 HTTP 响应，返回 body（支持 Content-Length / chunked）。 */
    private fun readHttpResponse(input: InputStream): String? {
        val headerBuilder = StringBuilder()
        while (true) {
            val line = RawWebSocket.readLine(input) ?: return null
            headerBuilder.append(line).append('\n')
            if (line.isEmpty()) break
        }
        val headers = headerBuilder.toString()
        if (!headers.substringBefore('\n').contains("200")) return null
        val chunked = headers.contains("transfer-encoding: chunked", ignoreCase = true)
        val contentLength = Regex("content-length:\\s*(\\d+)", RegexOption.IGNORE_CASE)
            .find(headers)?.groupValues?.get(1)?.toIntOrNull()
        return if (chunked) readChunked(input)
        else readFully(input, contentLength ?: 0)?.toString(Charsets.UTF_8)
    }

    private fun readChunked(input: InputStream): String? {
        val out = ByteArrayOutputStream()
        while (true) {
            val sizeLine = RawWebSocket.readLine(input) ?: break
            val size = sizeLine.substringBefore(';').trim().toIntOrNull(16) ?: break
            if (size == 0) break
            val chunk = readFully(input, size) ?: break
            out.write(chunk)
            RawWebSocket.readLine(input) // 尾部 CRLF
        }
        return out.toString("UTF-8")
    }

    private fun readFully(input: InputStream, length: Int): ByteArray? {
        if (length <= 0) return ByteArray(0)
        val buf = ByteArray(length)
        var read = 0
        while (read < length) {
            val r = try {
                input.read(buf, read, length - read)
            } catch (e: IOException) {
                -1
            }
            if (r < 0) return if (read > 0) buf.copyOf(read) else null
            read += r
        }
        return buf
    }
}