package com.webreverse.mcp.devtools.protocol.cdp

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean

/**
 * 最小 RFC6455 WebSocket 客户端基类（帧协议实现，传输层无关）。
 *
 * Android 上 WebView DevTools 服务只暴露为 abstract unix socket，OkHttp 等
 * 常规 WS 库无法直接连接（LocalSocket 不是 java.net.Socket），因此自实现
 * 协议所需的最小子集：文本帧收发、客户端掩码、分片重组、ping/pong、close。
 *
 * 两个传输层子类：
 * - [LocalWebSocket]：LocalSocket（unix abstract socket，直连 WebView DevTools）
 * - [TcpWebSocket]：java.net.Socket（TCP，连本进程 DevTools 代理的 CDP 复用枢纽）
 */
abstract class RawWebSocket protected constructor(
    private val input: InputStream,
    private val output: OutputStream,
) {
    private val closed = AtomicBoolean(false)
    private val writeLock = Any()
    private val random = SecureRandom()

    /** 最近一次 readTextMessage 返回 null 的原因（CLOSE 帧详情 / EOF / 解析异常），供上层日志 */
    @Volatile
    var lastEndReason: String? = null
        protected set

    fun isClosed(): Boolean = closed.get()

    /** 关闭底层传输（socket.close） */
    protected abstract fun closeTransport()

    // ---------------- 握手 ----------------

    /** 完成 HTTP Upgrade 握手（由子类工厂在构造后调用；同模块可见） */
    internal fun handshake(path: String) {
        val key = java.util.Base64.getEncoder()
            .encodeToString(ByteArray(16).also { random.nextBytes(it) })
        val request = buildString {
            append("GET ").append(path).append(" HTTP/1.1\r\n")
            append("Host: localhost\r\n")
            append("Upgrade: websocket\r\n")
            append("Connection: Upgrade\r\n")
            append("Sec-WebSocket-Key: ").append(key).append("\r\n")
            append("Sec-WebSocket-Version: 13\r\n")
            append("\r\n")
        }
        output.write(request.toByteArray(Charsets.US_ASCII))
        output.flush()
        val statusLine = readLine(input) ?: throw IOException("WebSocket 握手无响应")
        if (!statusLine.contains("101")) throw IOException("WebSocket 握手被拒绝: $statusLine")
        // 读完剩余响应头
        while (true) {
            val line = readLine(input) ?: throw IOException("握手响应被截断")
            if (line.isEmpty()) break
        }
    }

    // ---------------- 发送（客户端帧必须掩码） ----------------

    fun sendText(text: String): Boolean {
        if (closed.get()) return false
        val payload = text.toByteArray(Charsets.UTF_8)
        return sendFrame(OPCODE_TEXT, payload)
    }

    private fun sendFrame(opcode: Int, payload: ByteArray): Boolean {
        if (closed.get()) return false
        val maskKey = ByteArray(4).also { random.nextBytes(it) }
        val header = ByteArrayOutputStream()
        header.write(0x80 or opcode) // FIN + opcode
        // RFC6455 §5.3：客户端→服务端的帧必须掩码，第二字节最高位（MASK 位）必须置 1。
        // 【关键修复】此前三个长度分支都漏了 mask 位——服务端把 4 字节掩码键当成了
        // payload 开头，判定协议违规(1002)后立即关闭连接。这是"DevTools 握手成功后
        // 毫秒级断开（WebSocket disconnected）"的根本原因。
        when {
            payload.size < 126 -> header.write(0x80 or payload.size)
            payload.size < 65536 -> {
                header.write(0x80 or 126)
                header.write((payload.size ushr 8) and 0xff)
                header.write(payload.size and 0xff)
            }
            else -> {
                header.write(0x80 or 127)
                val len = payload.size.toLong()
                for (shift in 56 downTo 0 step 8) {
                    header.write(((len ushr shift) and 0xff).toInt())
                }
            }
        }
        val masked = ByteArray(payload.size)
        for (i in payload.indices) {
            masked[i] = (payload[i].toInt() xor maskKey[i and 3].toInt()).toByte()
        }
        synchronized(writeLock) {
            return try {
                output.write(header.toByteArray())
                output.write(maskKey)
                output.write(masked)
                output.flush()
                true
            } catch (e: Exception) {
                false
            }
        }
    }

    // ---------------- 接收 ----------------

    /**
     * 阻塞读取一条完整文本消息（自动重组分片、响应 ping）。
     * 连接关闭或出错时返回 null，原因记录在 [lastEndReason]。
     */
    fun readTextMessage(): String? {
        val buffer = ByteArrayOutputStream()
        while (true) {
            val frame = readFrame() ?: run {
                lastEndReason = "读帧失败($frameError)"
                return null
            }
            when (frame.opcode) {
                OPCODE_TEXT, OPCODE_BINARY, OPCODE_CONTINUATION -> {
                    buffer.write(frame.payload)
                    if (frame.fin) return buffer.toString("UTF-8")
                }
                OPCODE_PING -> sendFrame(OPCODE_PONG, frame.payload)
                OPCODE_PONG -> Unit
                OPCODE_CLOSE -> {
                    // 解析 Chromium 关闭原因（如 1001 target detached / 1002 协议错误）
                    val info = if (frame.payload.size >= 2) {
                        val code = ((frame.payload[0].toInt() and 0xff) shl 8) or
                            (frame.payload[1].toInt() and 0xff)
                        val reason = String(frame.payload, 2, frame.payload.size - 2, Charsets.UTF_8)
                        "code=$code reason=$reason"
                    } else {
                        "无载荷"
                    }
                    lastEndReason = "对端发送 CLOSE 帧($info)"
                    sendFrame(OPCODE_CLOSE, ByteArray(0))
                    return null
                }
            }
        }
    }

    /** 最近一次 readFrame 失败的细节 */
    private var frameError: String? = null

    private fun readFrame(): Frame? {
        frameError = null
        val hdr = readExact(2) ?: run { frameError = "帧头 EOF"; return null }
        val fin = (hdr[0].toInt() and 0x80) != 0
        val opcode = hdr[0].toInt() and 0x0f
        val masked = (hdr[1].toInt() and 0x80) != 0
        var length = (hdr[1].toInt() and 0x7f).toLong()
        if (length == 126L) {
            val ext = readExact(2) ?: run { frameError = "16位长度 EOF"; return null }
            length = ((ext[0].toLong() and 0xff) shl 8) or (ext[1].toLong() and 0xff)
        } else if (length == 127L) {
            val ext = readExact(8) ?: run { frameError = "64位长度 EOF"; return null }
            length = 0
            for (b in ext) length = (length shl 8) or (b.toLong() and 0xff)
        }
        if (length < 0 || length > MAX_FRAME_BYTES) {
            frameError = "帧长越界($length)"
            return null
        }
        val maskKey = if (masked) readExact(4) ?: run { frameError = "掩码键 EOF"; return null } else null
        val payload = if (length > 0) {
            readExact(length.toInt()) ?: run { frameError = "载荷 EOF"; return null }
        } else {
            ByteArray(0)
        }
        if (maskKey != null) {
            for (i in payload.indices) {
                payload[i] = (payload[i].toInt() xor maskKey[i and 3].toInt()).toByte()
            }
        }
        return Frame(fin, opcode, payload)
    }

    private fun readExact(n: Int): ByteArray? {
        if (n <= 0) return ByteArray(0)
        val buf = ByteArray(n)
        var read = 0
        while (read < n) {
            val r = try {
                input.read(buf, read, n - read)
            } catch (e: Exception) {
                -1
            }
            if (r < 0) return null
            read += r
        }
        return buf
    }

    fun close() {
        if (closed.getAndSet(true)) return
        try {
            sendFrame(OPCODE_CLOSE, ByteArray(0))
        } catch (_: Exception) {
        }
        try {
            closeTransport()
        } catch (_: Exception) {
        }
    }

    private data class Frame(val fin: Boolean, val opcode: Int, val payload: ByteArray)

    companion object {
        private const val OPCODE_CONTINUATION = 0x0
        private const val OPCODE_TEXT = 0x1
        private const val OPCODE_BINARY = 0x2
        private const val OPCODE_CLOSE = 0x8
        private const val OPCODE_PING = 0x9
        private const val OPCODE_PONG = 0xA

        /** 单帧上限 64MB，防御异常数据 */
        private const val MAX_FRAME_BYTES = 64L * 1024 * 1024

        fun readLine(input: InputStream): String? {
            val sb = StringBuilder()
            while (true) {
                val b = try {
                    input.read()
                } catch (e: Exception) {
                    -1
                }
                if (b < 0) return if (sb.isEmpty()) null else sb.toString()
                if (b == '\n'.code) return sb.toString().trimEnd('\r')
                sb.append(b.toChar())
            }
        }
    }
}
