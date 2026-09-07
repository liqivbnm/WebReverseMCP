package com.webreverse.mcp.core.logging

import com.webreverse.mcp.core.common.event.EventBus
import com.webreverse.mcp.core.common.event.LogEvent
import com.webreverse.mcp.core.common.event.LogLevel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.concurrent.ConcurrentLinkedDeque
import timber.log.Timber

/** 日志分类 */
enum class LogCategory(val tag: String) {
    APP("AppLog"),
    BROWSER("BrowserLog"),
    MCP("McpLog"),
    NETWORK("NetworkLog"),
    CONSOLE("ConsoleLog"),
    DEBUGGER("DebuggerLog"),
    HOOK("HookLog"),
    SECURITY("SecurityLog"),
    AGENT("AgentLog"),
    JS("JsLog"),
}

/** 统一日志条目 */
data class LogEntry(
    val id: Long,
    val category: LogCategory,
    val level: LogLevel,
    val message: String,
    val throwable: Throwable? = null,
    val timestamp: Long = System.currentTimeMillis(),
    val tag: String = "",
)

/** 统一日志系统：分类 + 内存环形缓冲 + 事件总线 */
class AppLogger(
    private val eventBus: EventBus? = null,
    private val maxEntries: Int = 2000,
) {
    private val buffer = ConcurrentLinkedDeque<LogEntry>()
    private val _entries = MutableStateFlow<List<LogEntry>>(emptyList())
    val entries: StateFlow<List<LogEntry>> = _entries.asStateFlow()

    private val counter = java.util.concurrent.atomic.AtomicLong(0)

    init {
        Timber.plant(object : Timber.DebugTree() {
            override fun log(priority: Int, tag: String?, message: String, t: Throwable?) {
                val level = when (priority) {
                    android.util.Log.VERBOSE -> LogLevel.VERBOSE
                    android.util.Log.DEBUG -> LogLevel.DEBUG
                    android.util.Log.INFO -> LogLevel.INFO
                    android.util.Log.WARN -> LogLevel.WARN
                    android.util.Log.ERROR -> LogLevel.ERROR
                    else -> LogLevel.ASSERT
                }
                record(LogCategory.APP, level, message, t, tag.orEmpty())
            }
        })
    }

    private fun record(category: LogCategory, level: LogLevel, message: String, t: Throwable?, tag: String) {
        val entry = LogEntry(counter.incrementAndGet(), category, level, message, t, System.currentTimeMillis(), tag)
        buffer.addLast(entry)
        while (buffer.size > maxEntries) buffer.pollFirst()
        _entries.value = buffer.toList()
        eventBus?.tryEmit(LogEvent(category.tag, level, message, t))
    }

    fun v(category: LogCategory, message: String, tag: String = "") = record(category, LogLevel.VERBOSE, message, null, tag)
    fun d(category: LogCategory, message: String, tag: String = "") = record(category, LogLevel.DEBUG, message, null, tag)
    fun i(category: LogCategory, message: String, tag: String = "") = record(category, LogLevel.INFO, message, null, tag)
    fun w(category: LogCategory, message: String, tag: String = "") = record(category, LogLevel.WARN, message, null, tag)
    fun e(category: LogCategory, message: String, t: Throwable? = null, tag: String = "") = record(category, LogLevel.ERROR, message, t, tag)

    fun search(query: String, category: LogCategory? = null, level: LogLevel? = null): List<LogEntry> =
        _entries.value.filter { entry ->
            (category == null || entry.category == category) &&
                (level == null || entry.level == level) &&
                (query.isBlank() || entry.message.contains(query, ignoreCase = true) || entry.tag.contains(query, ignoreCase = true))
        }

    fun export(): String = _entries.value.joinToString("\n") { entry ->
        "[${entry.timestamp}] [${entry.category.tag}] [${entry.level}] ${entry.message}"
    }

    fun clear() {
        buffer.clear()
        _entries.value = emptyList()
    }
}
