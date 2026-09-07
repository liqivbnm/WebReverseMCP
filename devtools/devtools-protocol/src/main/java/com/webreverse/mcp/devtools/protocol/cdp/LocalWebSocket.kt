package com.webreverse.mcp.devtools.protocol.cdp

import android.net.LocalSocket
import android.net.LocalSocketAddress
import java.io.InputStream
import java.io.OutputStream

/**
 * 基于 LocalSocket 的 WebSocket 客户端（帧协议实现见 [RawWebSocket]）。
 *
 * Android 上 WebView DevTools 服务只暴露为 abstract unix socket，OkHttp 等
 * 常规 WS 库无法直接连接（LocalSocket 不是 java.net.Socket），因此用本类直连。
 */
class LocalWebSocket private constructor(
    private val socket: LocalSocket,
    input: InputStream,
    output: OutputStream,
) : RawWebSocket(input, output) {

    override fun closeTransport() {
        runCatching { socket.close() }
    }

    companion object {
        /**
         * 连接+握手总超时。DevTools socket 偶发半死状态（accept 后不响应升级请求），
         * LocalSocket 无原生超时机制，阻塞读会永久挂起——届时上层（CDP 枢纽后端
         * 连接/attach）会跟着无限转圈。用看门狗线程兜底：超时即强关 socket，
         * 令阻塞读抛错返回 null。
         */
        private const val CONNECT_TIMEOUT_MS = 8_000L

        /** 连接 abstract socket 并完成 WebSocket 升级（带看门狗超时） */
        fun connect(socketName: String, path: String): LocalWebSocket? {
            val socket = LocalSocket()
            val done = java.util.concurrent.atomic.AtomicBoolean(false)
            val watchdog = Thread {
                runCatching { Thread.sleep(CONNECT_TIMEOUT_MS) }
                if (!done.get()) {
                    CdpTransport.lastError =
                        "WebSocket 连接超时($socketName$path): DevTools socket " +
                            "${CONNECT_TIMEOUT_MS / 1000}s 内未完成握手（可能被占用或半死）"
                    runCatching { socket.close() }
                }
            }
            watchdog.isDaemon = true
            watchdog.start()
            return try {
                socket.connect(LocalSocketAddress(socketName, LocalSocketAddress.Namespace.ABSTRACT))
                val ws = LocalWebSocket(socket, socket.inputStream, socket.outputStream)
                ws.handshake(path)
                done.set(true)
                ws
            } catch (e: Exception) {
                done.set(true)
                runCatching { socket.close() }
                // 看门狗已记录更具体的超时原因时保留之
                val lastErr = CdpTransport.lastError
                if (lastErr == null || !lastErr.startsWith("WebSocket 连接超时")) {
                    CdpTransport.lastError =
                        "WebSocket 连接失败($socketName$path): ${e.javaClass.simpleName}: ${e.message}"
                }
                null
            }
        }
    }
}
