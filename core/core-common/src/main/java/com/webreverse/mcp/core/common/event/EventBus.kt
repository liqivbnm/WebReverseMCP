package com.webreverse.mcp.core.common.event

import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.filterIsInstance
import kotlinx.coroutines.flow.map
import java.util.concurrent.atomic.AtomicLong

/**
 * 统一事件总线：所有模块通过它解耦通信。
 *
 * 报七优化（捕获事件不得静默丢失）：
 *  - 普通订阅走 [events]（DROP_OLDEST，适合低延迟、允许丢帧的实时视图）；
 *  - 持久化/建档类消费者（Room 桥、SSE 推送、Evidence 落库）应改走 [journal]——
 *    它是一个带 replay 缓冲的可回放流，容量远大于普通订阅，慢消费者也能回放近期事件而不丢失；
 *  - [subscribeWithSeq] 为实时视图提供单调递增序号，便于检测 DROP_OLDEST 发生的丢帧。
 */
class EventBus(
    private val extraBufferCapacity: Int = 256,
    private val journalReplay: Int = 2048,
) {
    private val _events = MutableSharedFlow<Event>(
        extraBufferCapacity = extraBufferCapacity,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )
    val events: SharedFlow<Event> = _events.asSharedFlow()

    /** 持久化回放通道：replay 缓冲足够覆盖慢消费者处理窗口，避免捕获事件静默丢失（报七） */
    private val _journal = MutableSharedFlow<Event>(
        replay = journalReplay,
        extraBufferCapacity = 0,
        onBufferOverflow = BufferOverflow.SUSPEND,
    )
    val journal: SharedFlow<Event> = _journal.asSharedFlow()

    /** 单调递增事件序号（用于丢帧检测） */
    private val sequence = AtomicLong(0L)

    suspend fun emit(event: Event) {
        _events.emit(event)
        _journal.emit(event)
    }

    fun tryEmit(event: Event): Boolean {
        val okFast = _events.tryEmit(event)
        _journal.tryEmit(event)
        return okFast
    }

    inline fun <reified T : Event> subscribe(): Flow<T> = events.filterIsInstance<T>()

    /** 带单调序号的实时订阅：seq 出现跳变即说明 DROP_OLDEST 丢过帧（报七） */
    fun subscribeWithSeq(): Flow<SeqEvent> = events.map { SeqEvent(sequence.incrementAndGet(), it) }

    /** 当前已分发的最大序号 */
    fun lastSequence(): Long = sequence.get()
}

/** 携带全局序号的投递事件 */
data class SeqEvent(val seq: Long, val event: Event)

/** 事件基类 */
sealed interface Event {
    val timestamp: Long
}

/** 浏览器事件 */
sealed class BrowserEvent(override val timestamp: Long = System.currentTimeMillis()) : Event {
    data class PageStarted(val tabId: String, val url: String, override val timestamp: Long = System.currentTimeMillis()) : BrowserEvent(timestamp)
    data class PageFinished(val tabId: String, val url: String, override val timestamp: Long = System.currentTimeMillis()) : BrowserEvent(timestamp)
    data class PageError(val tabId: String, val url: String, val error: String, override val timestamp: Long = System.currentTimeMillis()) : BrowserEvent(timestamp)
    data class ProgressChanged(val tabId: String, val progress: Int, override val timestamp: Long = System.currentTimeMillis()) : BrowserEvent(timestamp)
    data class TitleChanged(val tabId: String, val title: String, override val timestamp: Long = System.currentTimeMillis()) : BrowserEvent(timestamp)
    data class UrlChanged(val tabId: String, val url: String, override val timestamp: Long = System.currentTimeMillis()) : BrowserEvent(timestamp)
    data class TabCreated(val tabId: String, val url: String, override val timestamp: Long = System.currentTimeMillis()) : BrowserEvent(timestamp)
    data class TabClosed(val tabId: String, override val timestamp: Long = System.currentTimeMillis()) : BrowserEvent(timestamp)
    data class TabActivated(val tabId: String, override val timestamp: Long = System.currentTimeMillis()) : BrowserEvent(timestamp)
    data class DomReady(val tabId: String, val url: String, override val timestamp: Long = System.currentTimeMillis()) : BrowserEvent(timestamp)
}

/** 网络事件 */
sealed class NetworkEvent(override val timestamp: Long = System.currentTimeMillis()) : Event {
    data class RequestStarted(val entryId: String, val tabId: String, val url: String, val method: String, override val timestamp: Long = System.currentTimeMillis()) : NetworkEvent(timestamp)
    data class ResponseReceived(val entryId: String, val tabId: String, val url: String, val status: Int, override val timestamp: Long = System.currentTimeMillis()) : NetworkEvent(timestamp)
    data class RequestCompleted(val entryId: String, val tabId: String, val url: String, val status: Int, val durationMs: Long, override val timestamp: Long = System.currentTimeMillis()) : NetworkEvent(timestamp)
    data class RequestFailed(val entryId: String, val tabId: String, val url: String, val error: String, override val timestamp: Long = System.currentTimeMillis()) : NetworkEvent(timestamp)
    // opcode 1=文本 / 2=二进制（二进制 payload 为 base64: 前缀），供实时事件区分二进制帧
    data class WebSocketFrame(val tabId: String, val url: String, val direction: String, val payload: String, val opcode: Int = 1, override val timestamp: Long = System.currentTimeMillis()) : NetworkEvent(timestamp)
    // SSE/EventSource 推送消息事件（event.wait network.sse 即时捕获）
    data class SseMessage(val tabId: String, val url: String, val eventName: String, val data: String, override val timestamp: Long = System.currentTimeMillis()) : NetworkEvent(timestamp)
}

/** 控制台事件 */
sealed class ConsoleEvent(override val timestamp: Long = System.currentTimeMillis()) : Event {
    data class Message(val tabId: String, val level: String, val text: String, override val timestamp: Long = System.currentTimeMillis()) : ConsoleEvent(timestamp)
    data class Exception(val tabId: String, val message: String, val stack: String, override val timestamp: Long = System.currentTimeMillis()) : ConsoleEvent(timestamp)
}

/** 调试器事件 */
sealed class DebuggerEvent(override val timestamp: Long = System.currentTimeMillis()) : Event {
    data class Paused(val tabId: String, val reason: String, val callFrames: String, override val timestamp: Long = System.currentTimeMillis()) : DebuggerEvent(timestamp)
    data class Resumed(val tabId: String, override val timestamp: Long = System.currentTimeMillis()) : DebuggerEvent(timestamp)
    data class BreakpointHit(val tabId: String, val breakpointId: String, val url: String, val line: Int, override val timestamp: Long = System.currentTimeMillis()) : DebuggerEvent(timestamp)
    data class ScriptParsed(val tabId: String, val scriptId: String, val url: String, override val timestamp: Long = System.currentTimeMillis()) : DebuggerEvent(timestamp)
}

/** Hook 事件 */
sealed class HookEvent(override val timestamp: Long = System.currentTimeMillis()) : Event {
    data class Triggered(val hookId: String, val ruleName: String, val target: String, val payload: String, override val timestamp: Long = System.currentTimeMillis()) : HookEvent(timestamp)
    data class Installed(val hookId: String, val type: String, override val timestamp: Long = System.currentTimeMillis()) : HookEvent(timestamp)
    data class Removed(val hookId: String, override val timestamp: Long = System.currentTimeMillis()) : HookEvent(timestamp)
}

/** MCP 事件 */
sealed class McpEvent(override val timestamp: Long = System.currentTimeMillis()) : Event {
    data class ServerStarted(val host: String, val port: Int, override val timestamp: Long = System.currentTimeMillis()) : McpEvent(timestamp)
    data class ServerStopped(override val timestamp: Long = System.currentTimeMillis()) : McpEvent(timestamp)
    data class ClientConnected(val clientId: String, val clientName: String, override val timestamp: Long = System.currentTimeMillis()) : McpEvent(timestamp)
    data class ClientDisconnected(val clientId: String, override val timestamp: Long = System.currentTimeMillis()) : McpEvent(timestamp)
    data class ToolInvoked(val toolName: String, val sessionId: String, val isError: Boolean, override val timestamp: Long = System.currentTimeMillis()) : McpEvent(timestamp)
    data class AuthFailed(val remoteAddress: String, val reason: String, override val timestamp: Long = System.currentTimeMillis()) : McpEvent(timestamp)
}

/** 安全事件 */
sealed class SecurityEvent(override val timestamp: Long = System.currentTimeMillis()) : Event {
    data class PermissionDenied(val scope: String, val reason: String, override val timestamp: Long = System.currentTimeMillis()) : SecurityEvent(timestamp)
    data class SensitiveDataRedacted(val context: String, override val timestamp: Long = System.currentTimeMillis()) : SecurityEvent(timestamp)
    data class PermissionGranted(val scope: String, val tabId: String?, override val timestamp: Long = System.currentTimeMillis()) : SecurityEvent(timestamp)
}

/** 日志事件 */
data class LogEvent(
    val tag: String,
    val level: LogLevel,
    val message: String,
    val throwable: Throwable? = null,
    override val timestamp: Long = System.currentTimeMillis(),
) : Event

enum class LogLevel { VERBOSE, DEBUG, INFO, WARN, ERROR, ASSERT }
