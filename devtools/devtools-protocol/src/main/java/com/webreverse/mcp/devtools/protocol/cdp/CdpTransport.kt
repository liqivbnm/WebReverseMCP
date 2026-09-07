package com.webreverse.mcp.devtools.protocol.cdp

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.builtins.ListSerializer
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.URI

/**
 * CDP 传输层：发现 WebView DevTools socket、HTTP 发现页面、升级 WebSocket。
 *
 * 流程（与桌面 Chrome DevTools 的 adb forward 方式同构，只是直接连本地 socket）：
 * 1. WebView.setWebContentsDebuggingEnabled(true) 后存在 abstract socket
 *    `webview_devtools_remote_<pid>`（pid = 宿主 app 进程）。
 * 2. 在该 socket 上发送 HTTP `GET /json/list` 获取页面列表。
 * 3. 用页面 webSocketDebuggerUrl 的 path 发起 RFC6455 升级，得到 CDP 会话通道。
 */
object CdpTransport {

    private val json = Json { ignoreUnknownKeys = true }

    /** 最近一次发现/连接失败原因（供 attach 提示，避免一律"socket 不可用"） */
    @Volatile
    var lastError: String? = null

    /** 已验证可用的 socket（缓存，避免每次 attach 都全量探测） */
    @Volatile
    private var cachedSocket: String? = null

    /** app 进程对应的 DevTools socket 名 */
    fun defaultSocketName(): String = "webview_devtools_remote_${android.os.Process.myPid()}"

    /**
     * 候选 socket 名列表。
     * 不同 WebView 版本/厂商命名不一致：新版带 pid 后缀，部分老版/定制内核无后缀，
     * 因此除固定候选外还会枚举 /proc/net/unix 中所有 devtools_remote 条目（自身 UID 的可见）。
     */
    fun candidateSocketNames(): List<String> {
        val out = LinkedHashSet<String>()
        out.add(defaultSocketName())
        out.add("webview_devtools_remote")
        runCatching {
            java.io.File("/proc/net/unix").forEachLine { line ->
                val name = line.trim().substringAfterLast(' ')
                if (name.startsWith("@")) {
                    val n = name.substring(1)
                    if (n.contains("devtools_remote")) out.add(n)
                }
            }
        }
        return out.toList()
    }

    /**
     * 逐个探测候选 socket；全部失败记录原因并返回 null。
     *
     * 增加重试等待——WebContents 调试开关开启后，DevTools socket
     * 的建立有短暂延迟（Chromium 异步启动 DevTools server），一次探测可能
     * 恰好落在 socket 出现之前。重试 3 轮（每轮间隔 250ms）显著提高命中率。
     */
    fun discoverSocket(): String? {
        cachedSocket?.let { name ->
            if (httpGet(name, "/json/version") != null) return name
            cachedSocket = null
        }
        val tried = mutableListOf<String>()
        val errors = mutableListOf<String>()
        val attempts = 3
        for (attempt in 0 until attempts) {
            for (name in candidateSocketNames()) {
                if (attempt == 0) tried.add(name)
                val probe = probeSocket(name)
                if (probe == null) {
                    cachedSocket = name
                    lastError = null
                    return name
                }
                if (attempt == 0) errors.add("$name($probe)")
            }
            if (attempt < attempts - 1) {
                try {
                    Thread.sleep(250L)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    break
                }
            }
        }
        lastError = "未找到可用 DevTools socket（已试 ${tried.size} 个候选：${errors.joinToString("、")}）。" +
            "提示：确认 App 内页面已加载；本应用 WebView 调试已默认开启（setWebContentsDebuggingEnabled）；" +
            "部分 ROM 限制自连 abstract socket 时 CDP 不可用，注入式监控不受影响"
        return null
    }

    /** 探测单个 socket，失败返回原因描述 */
    private fun probeSocket(socketName: String): String? {
        return try {
            android.net.LocalSocket().use { socket ->
                socket.connect(
                    android.net.LocalSocketAddress(
                        socketName,
                        android.net.LocalSocketAddress.Namespace.ABSTRACT,
                    ),
                )
                val output = socket.outputStream
                val request = "GET /json/version HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                output.write(request.toByteArray(Charsets.US_ASCII))
                output.flush()
                val body = readHttpResponse(socket.inputStream)
                    ?: return@use "/json/version 无 HTTP 响应"
                if (body.isBlank()) "/json/version 返回空" else null
            }
        } catch (e: Exception) {
            when (e) {
                is java.io.IOException, is java.net.ConnectException ->
                    "connect 失败: ${e.javaClass.simpleName}"
                else -> "${e.javaClass.simpleName}: ${e.message}"
            }
        }
    }

    /**
     * 探测 socket 是否可用（连上即断开，用于 attach 前的快速判断）。
     * 默认参数时走完整候选发现（含重试等待），避免只探测默认 socket 名
     * 而漏判（部分 WebView 版本 socket 无 pid 后缀）。
     */
    fun isAvailable(socketName: String = defaultSocketName()): Boolean {
        if (httpGet(socketName, "/json/version") != null) return true
        return if (socketName == defaultSocketName()) discoverSocket() != null else false
    }

    /** 获取 /json/list 页面列表；连接失败返回 null */
    suspend fun listPages(socketName: String? = null): List<DevToolsPageInfo>? =
        withContext(Dispatchers.IO) {
            val name = socketName ?: discoverSocket() ?: return@withContext null
            val body = httpGet(name, "/json/list")
            if (body == null) {
                lastError = "socket($name) /json/list 无响应（页面可能尚未完成加载）"
                return@withContext null
            }
            runCatching {
                json.decodeFromString(ListSerializer(DevToolsPageInfo.serializer()), body)
            }.getOrNull().also {
                if (it == null) lastError = "页面列表解析失败（WebView 版本协议异常）"
                else if (it.isEmpty()) lastError = "DevTools 已连接但无 page 目标（等待页面完全加载后重试）"
            }
        }

    /** 建立 CDP WebSocket 连接 */
    fun connectWebSocket(socketName: String? = null, wsPath: String): LocalWebSocket? {
        val name = socketName ?: cachedSocket ?: discoverSocket()
        if (name == null) {
            if (lastError == null) lastError = "无 DevTools socket"
            return null
        }
        return LocalWebSocket.connect(name, wsPath)
    }

    /** 从 webSocketDebuggerUrl 提取 path（如 /devtools/page/ABC） */
    fun wsPathOf(page: DevToolsPageInfo): String {
        val url = page.webSocketDebuggerUrl
        if (url.isNotBlank()) {
            runCatching {
                val uri = URI.create(url)
                val path = uri.rawPath
                if (path.isNotBlank()) return path
            }
        }
        return "/devtools/page/${page.id}"
    }

    // ---------------- HTTP over LocalSocket ----------------

    private fun httpGet(socketName: String, path: String): String? {
        return try {
            android.net.LocalSocket().use { socket ->
                socket.connect(
                    android.net.LocalSocketAddress(
                        socketName,
                        android.net.LocalSocketAddress.Namespace.ABSTRACT,
                    ),
                )
                val input = socket.inputStream
                val output = socket.outputStream
                // DevTools HTTP 服务要求 Host 为 localhost/IP（防 DNS rebinding）
                val request = "GET $path HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                output.write(request.toByteArray(Charsets.US_ASCII))
                output.flush()
                readHttpResponse(input)
            }
        } catch (e: Exception) {
            null
        }
    }

    private fun readHttpResponse(input: java.io.InputStream): String? {
        // 读响应头
        val headerBuilder = StringBuilder()
        while (true) {
            val line = RawWebSocket.readLine(input) ?: return null
            headerBuilder.append(line).append('\n')
            if (line.isEmpty()) break
        }
        val headers = headerBuilder.toString()
        val firstLine = headers.substringBefore('\n')
        if (!firstLine.contains("200")) return null
        val chunked = headers.contains("transfer-encoding: chunked", ignoreCase = true)
        val contentLength = Regex("content-length:\\s*(\\d+)", RegexOption.IGNORE_CASE)
            .find(headers)?.groupValues?.get(1)?.toIntOrNull()
        return if (chunked) {
            readChunked(input)
        } else {
            readFully(input, contentLength ?: 0)?.toString(Charsets.UTF_8)
        }
    }

    private fun readChunked(input: java.io.InputStream): String? {
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

    private fun readFully(input: java.io.InputStream, length: Int): ByteArray? {
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
