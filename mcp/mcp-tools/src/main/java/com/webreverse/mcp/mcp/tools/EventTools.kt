package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.common.event.BrowserEvent
import com.webreverse.mcp.core.common.event.ConsoleEvent
import com.webreverse.mcp.core.common.event.DebuggerEvent
import com.webreverse.mcp.core.common.event.Event
import com.webreverse.mcp.core.common.event.EventBus
import com.webreverse.mcp.core.common.event.HookEvent
import com.webreverse.mcp.core.common.event.NetworkEvent
import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** Event Tools：事件订阅 / 等待（AI 长链路任务核心） */
object EventTools {

    /** 事件名称 -> 匹配器 */
    private fun matcherFor(eventName: String): ((Event) -> Boolean)? = when (eventName.lowercase()) {
        "network.request", "network.requeststarted" -> { e -> e is NetworkEvent.RequestStarted }
        "network.response", "network.responsereceived" -> { e -> e is NetworkEvent.ResponseReceived }
        "network.completed", "network.requestcompleted" -> { e -> e is NetworkEvent.RequestCompleted }
        "network.failed", "network.requestfailed" -> { e -> e is NetworkEvent.RequestFailed }
        "network.websocket", "network.websocketframe" -> { e -> e is NetworkEvent.WebSocketFrame }
        "network.sse", "network.eventsource" -> { e -> e is NetworkEvent.SseMessage }
        "console.message", "console.log" -> { e -> e is ConsoleEvent.Message }
        "console.error", "console.exception" -> { e -> e is ConsoleEvent.Exception }
        "debugger.paused" -> { e -> e is DebuggerEvent.Paused }
        "debugger.resumed" -> { e -> e is DebuggerEvent.Resumed }
        "debugger.breakpoint" -> { e -> e is DebuggerEvent.BreakpointHit }
        "debugger.script" -> { e -> e is DebuggerEvent.ScriptParsed }
        "hook.triggered" -> { e -> e is HookEvent.Triggered }
        "hook.installed" -> { e -> e is HookEvent.Installed }
        "page.loaded", "page.finished" -> { e -> e is BrowserEvent.PageFinished }
        "page.started" -> { e -> e is BrowserEvent.PageStarted }
        "page.urlchanged" -> { e -> e is BrowserEvent.UrlChanged }
        "page.titlechanged" -> { e -> e is BrowserEvent.TitleChanged }
        "page.error" -> { e -> e is BrowserEvent.PageError }
        "tab.created" -> { e -> e is BrowserEvent.TabCreated }
        "tab.closed" -> { e -> e is BrowserEvent.TabClosed }
        "tab.activated" -> { e -> e is BrowserEvent.TabActivated }
        "dom.ready" -> { e -> e is BrowserEvent.DomReady }
        else -> null
    }

    private fun describe(event: Event): String = when (event) {
        is NetworkEvent.RequestStarted -> "network.request ${event.method} ${event.url}"
        is NetworkEvent.ResponseReceived -> "network.response ${event.url} ${event.status}"
        is NetworkEvent.RequestCompleted -> "network.completed ${event.url} ${event.status} ${event.durationMs}ms"
        is NetworkEvent.RequestFailed -> "network.failed ${event.url} ${event.error}"
        is NetworkEvent.WebSocketFrame -> "network.websocket ${event.url} ${event.direction}"
        is NetworkEvent.SseMessage -> "network.sse ${event.url} ${event.eventName}"
        is ConsoleEvent.Message -> "console.message ${event.level} ${event.text}"
        is ConsoleEvent.Exception -> "console.error ${event.message}" +
            (event.stack.takeIf { it.isNotBlank() }?.let { "\n$it" } ?: "")
        is DebuggerEvent.Paused -> "debugger.paused ${event.reason}"
        is DebuggerEvent.Resumed -> "debugger.resumed"
        is DebuggerEvent.BreakpointHit -> "debugger.breakpoint ${event.url}:${event.line}"
        is DebuggerEvent.ScriptParsed -> "debugger.script ${event.url}"
        is HookEvent.Triggered -> "hook.triggered ${event.ruleName} ${event.target}"
        is HookEvent.Installed -> "hook.installed ${event.type}"
        is HookEvent.Removed -> "hook.removed ${event.hookId}"
        is BrowserEvent.PageStarted -> "page.started ${event.url}"
        is BrowserEvent.PageFinished -> "page.loaded ${event.url}"
        is BrowserEvent.PageError -> "page.error ${event.url} ${event.error}"
        is BrowserEvent.ProgressChanged -> "page.progress ${event.progress}"
        is BrowserEvent.TitleChanged -> "page.titlechanged ${event.title}"
        is BrowserEvent.UrlChanged -> "page.urlchanged ${event.url}"
        is BrowserEvent.TabCreated -> "tab.created ${event.url}"
        is BrowserEvent.TabClosed -> "tab.closed ${event.tabId}"
        is BrowserEvent.TabActivated -> "tab.activated ${event.tabId}"
        is BrowserEvent.DomReady -> "dom.ready ${event.url}"
        else -> event.javaClass.simpleName
    }

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)
        return listOf(
            f.tool(
                "event.subscribe", "订阅事件流", ToolCategory.EVENT,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "event" to Schemas.strSchema("事件类型，如 network.request / debugger.paused / console.error"),
                    "timeoutMs" to Schemas.intSchema("订阅超时"),
                ),
            ) { args ->
                val event = ToolArgs.str(args, "event")
                val timeoutMs = ToolArgs.long(args, "timeoutMs", 30_000L)
                if (event.isBlank()) return@tool McpToolResult.error("INVALID_ARGUMENTS", "event 不能为空")
                val matcher = matcherFor(event)
                    ?: return@tool McpToolResult.error("INVALID_ARGUMENTS", "未知事件类型: $event")
                val result = withTimeoutOrNull(timeoutMs) {
                    deps.eventBus.events.first { matcher(it) }
                }
                if (result == null) {
                    McpToolResult.error("TIMEOUT", "等待事件超时: $event")
                } else {
                    McpToolResult.json(
                        buildJsonObject {
                            put("event", JsonPrimitive(event))
                            put("detail", JsonPrimitive(describe(result)))
                        },
                    )
                }
            },
            f.tool(
                "event.wait", "等待特定事件发生（阻塞直到事件或超时）", ToolCategory.EVENT,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "event" to Schemas.strSchema("事件类型"),
                    "timeoutMs" to Schemas.intSchema("超时毫秒"),
                    "filter" to Schemas.strSchema("过滤条件（URL 片段等）"),
                ),
            ) { args ->
                val event = ToolArgs.str(args, "event")
                val timeoutMs = ToolArgs.long(args, "timeoutMs", 30_000L)
                val filter = ToolArgs.optStr(args, "filter")
                if (event.isBlank()) return@tool McpToolResult.error("INVALID_ARGUMENTS", "event 不能为空")
                val matcher = matcherFor(event)
                    ?: return@tool McpToolResult.error("INVALID_ARGUMENTS", "未知事件类型: $event")
                val result = withTimeoutOrNull(timeoutMs) {
                    deps.eventBus.events.first { e ->
                        matcher(e) && (filter == null || describe(e).contains(filter, ignoreCase = true))
                    }
                }
                if (result == null) {
                    McpToolResult.error("TIMEOUT", "等待事件超时: $event")
                } else {
                    McpToolResult.json(
                        buildJsonObject {
                            put("event", JsonPrimitive(event))
                            put("detail", JsonPrimitive(describe(result)))
                        },
                    )
                }
            },
            f.tool(
                "event.unsubscribe", "取消事件订阅", ToolCategory.EVENT,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("subscriptionId" to Schemas.strSchema("订阅 ID")),
            ) { args ->
                val subscriptionId = ToolArgs.str(args, "subscriptionId")
                McpToolResult.text("已取消订阅: $subscriptionId")
            },
            f.tool(
                "event.list", "列出可用事件类型", ToolCategory.EVENT,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                McpToolResult.json(
                    buildJsonObject {
                        put(
                            "events",
                            JsonArray(
                                listOf(
                                    "network.request", "network.response", "network.completed", "network.failed",
                                    "network.websocket", "network.sse", "console.message", "console.error", "debugger.paused",
                                    "debugger.resumed", "debugger.breakpoint", "debugger.script", "hook.triggered",
                                    "hook.installed", "page.loaded", "page.started", "page.urlchanged",
                                    "page.titlechanged", "page.error", "tab.created", "tab.closed",
                                    "tab.activated", "dom.ready",
                                ).map { JsonPrimitive(it) },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "event.wait_network", "等待新的网络请求出现", ToolCategory.EVENT,
                PermissionScope.READ_NETWORK, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "urlPattern" to Schemas.strSchema("URL 匹配"),
                    "timeoutMs" to Schemas.intSchema("超时毫秒"),
                ),
            ) { args ->
                val pattern = ToolArgs.str(args, "urlPattern")
                val timeoutMs = ToolArgs.long(args, "timeoutMs", 30_000L)
                val session = deps.activeSession()
                val before = deps.networkInspector.getEntries(session.engine).size
                val result = withTimeoutOrNull(timeoutMs) {
                    deps.eventBus.events.first { e ->
                        e is NetworkEvent.RequestStarted &&
                            (pattern.isBlank() || describe(e).contains(pattern, ignoreCase = true))
                    }
                }
                val entries = deps.networkInspector.getEntries(session.engine)
                val newEntries = entries.drop(before)
                McpToolResult.json(
                    buildJsonObject {
                        put("event", JsonPrimitive(if (result != null) "network.request" else "timeout"))
                        put(
                            "newRequests",
                            JsonArray(
                                newEntries.take(50).map { e ->
                                    buildJsonObject {
                                        put("url", JsonPrimitive(e.url))
                                        put("method", JsonPrimitive(e.method.wire))
                                        put("status", JsonPrimitive(e.status))
                                    }
                                },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "event.wait_console", "等待控制台输出", ToolCategory.EVENT,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "level" to Schemas.strSchema("log/warn/error/info"),
                    "timeoutMs" to Schemas.intSchema("超时毫秒"),
                ),
            ) { args ->
                val level = ToolArgs.str(args, "level")
                val timeoutMs = ToolArgs.long(args, "timeoutMs", 30_000L)
                val result = withTimeoutOrNull(timeoutMs) {
                    deps.eventBus.events.first { e ->
                        e is ConsoleEvent.Message &&
                            (level.isBlank() || e.level.equals(level, ignoreCase = true))
                    } as ConsoleEvent.Message
                }
                if (result == null) {
                    McpToolResult.error("TIMEOUT", "等待控制台输出超时")
                } else {
                    McpToolResult.json(
                        buildJsonObject {
                            put("event", JsonPrimitive("console.message"))
                            put("level", JsonPrimitive(result.level))
                            put("text", JsonPrimitive(result.text))
                        },
                    )
                }
            },
        )
    }
}
