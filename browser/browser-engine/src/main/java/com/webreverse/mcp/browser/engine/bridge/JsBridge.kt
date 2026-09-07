package com.webreverse.mcp.browser.engine.bridge

import android.webkit.JavascriptInterface
import com.webreverse.mcp.core.common.event.EventBus
import com.webreverse.mcp.core.common.event.LogEvent
import com.webreverse.mcp.core.common.event.LogLevel
import org.json.JSONObject

/**
 * 暴露给网页的受控 Bridge：window.__MCP__
 * 网页 JS 只能通过这里与 App 通信，无法直接访问 Android API / MCP / 文件系统。
 */
class JsBridge(
    private val eventBus: EventBus,
    private val onAnalysisRequest: (String) -> Unit = {},
    private val onNetEvent: (String) -> Unit = {},
) {

    @JavascriptInterface
    fun log(message: String) {
        eventBus.tryEmit(LogEvent("JsBridge", LogLevel.INFO, message))
    }

    /**
     * 页面内 fetch/XHR hook 上报的网络事件（JSON 字符串）。
     * 由 NetworkBridge 合并进网络条目，补全 shouldInterceptRequest 看不到的
     * 响应状态/耗时/响应体——CDP 不可用时的注入式补全通道。
     */
    @JavascriptInterface
    fun netEvent(json: String) {
        if (json.isBlank()) return
        onNetEvent(json)
    }

    @JavascriptInterface
    fun warn(message: String) {
        eventBus.tryEmit(LogEvent("JsBridge", LogLevel.WARN, message))
    }

    @JavascriptInterface
    fun error(message: String) {
        eventBus.tryEmit(LogEvent("JsBridge", LogLevel.ERROR, message))
    }

    @JavascriptInterface
    fun notify(title: String, body: String) {
        eventBus.tryEmit(LogEvent("JsBridge", LogLevel.INFO, "[$title] $body"))
    }

    @JavascriptInterface
    fun requestAnalysis(payload: String) {
        onAnalysisRequest(payload)
    }

    @JavascriptInterface
    fun getBridgeInfo(): String {
        return JSONObject()
            .put("name", "WebReverseMCP")
            .put("version", "1.0.0")
            .put("capabilities", listOf("log", "notify", "requestAnalysis"))
            .toString()
    }
}
