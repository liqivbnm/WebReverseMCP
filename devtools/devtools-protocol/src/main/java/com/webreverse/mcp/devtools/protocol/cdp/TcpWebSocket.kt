package com.webreverse.mcp.devtools.protocol.cdp

import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket

/**
 * 基于 TCP 的 WebSocket 客户端（帧协议实现见 [RawWebSocket]）。
 *
 * 用途：进程内 MCP 调试工具（CdpDebuggerSession / CdpNetworkMonitor 等）连接
 * CDP 复用枢纽（ws://127.0.0.1:&lt;port&gt;/devtools/page/{id}，见 CdpProxyServer），
 * 与进程内其他 MCP 会话共享同一条后端 CDP 会话——调试与网络监控同时接入
 * 同一页面而不互踢，断点/暂停/网络事件在会话间广播（CDP 多路复用的基础设施）。
 *
 * @param target 形如 "127.0.0.1:9222"
 */
class TcpWebSocket private constructor(
    private val socket: Socket,
    input: InputStream,
    output: OutputStream,
) : RawWebSocket(input, output) {

    override fun closeTransport() {
        runCatching { socket.close() }
    }

    companion object {
        /** 连接 TCP 目标并完成 WebSocket 升级 */
        fun connect(target: String, path: String): TcpWebSocket? {
            return try {
                val host = target.substringBefore(':').ifBlank { "127.0.0.1" }
                val port = target.substringAfter(':', "").toIntOrNull()
                    ?: return null.also { CdpTransport.lastError = "非法 TCP 目标: $target" }
                val socket = Socket()
                socket.tcpNoDelay = true
                socket.connect(InetSocketAddress(host, port), 5000)
                // （P1-1 修复）：读超时兜底。原 soTimeout=0 时半开连接
                // （页面被系统冻结/ROM 杀 socket）下阻塞读永久挂起，isConnected
                // 恒 true，每条命令都要等满 20s 超时。现由 CdpSession 接收循环
                // 捕获 SocketTimeoutException 做探活判断：空闲超时先探活，
                // 连续 2 次探活无响应才判死并触发 watcher 重连。
                socket.soTimeout = 60_000
                val ws = TcpWebSocket(socket, socket.getInputStream(), socket.getOutputStream())
                ws.handshake(path)
                ws
            } catch (e: Exception) {
                CdpTransport.lastError = "TCP WebSocket 连接失败($target$path): ${e.javaClass.simpleName}: ${e.message}"
                null
            }
        }
    }
}
