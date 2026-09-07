package com.webreverse.mcp.browser.engine

import android.graphics.Bitmap
import com.webreverse.mcp.core.common.model.BrowserTab
import com.webreverse.mcp.core.common.model.NetworkEntry
import kotlinx.coroutines.flow.StateFlow

/**
 * 浏览器引擎抽象。
 * MCP Tool -> UseCase -> BrowserService -> BrowserEngine(WebView/Chromium/Remote)
 * 未来可通过 RemoteBrowserAdapter 替换底层实现。
 */
interface BrowserEngine {
    val tabId: String

    suspend fun loadUrl(url: String)
    suspend fun reload()
    suspend fun stop()
    suspend fun goBack(): Boolean
    suspend fun goForward(): Boolean
    suspend fun evaluateJavascript(script: String): String?
    suspend fun evaluateJavascriptAsync(script: String): String?
    suspend fun screenshot(): Bitmap?
    suspend fun currentUrl(): String?
    suspend fun currentTitle(): String?
    suspend fun canGoBack(): Boolean
    suspend fun canGoForward(): Boolean
    suspend fun getPageSource(): String?
    suspend fun getCookies(): List<Map<String, String>>
    suspend fun setCookie(name: String, value: String, domain: String, path: String)
    suspend fun getLocalStorage(): Map<String, String>
    suspend fun getSessionStorage(): Map<String, String>
    suspend fun setLocalStorage(key: String, value: String)
    suspend fun clearLocalStorage()
    suspend fun clearSessionStorage()
    suspend fun clearCache()
    suspend fun clearCookies()
    suspend fun getNetworkEntries(): List<NetworkEntry>
    suspend fun clearNetworkEntries()
    suspend fun destroy()

    /** 页面加载状态 */
    val state: StateFlow<BrowserEngineState>
}

/** 浏览器后端适配器（支持 LocalWebView / RemoteChrome / Chromium） */
interface BrowserBackend {
    val name: String
    suspend fun createSession(tabId: String): BrowserEngine
    suspend fun destroySession(tabId: String)
    suspend fun listSessions(): List<String>
}

/** 引擎状态 */
data class BrowserEngineState(
    val url: String = "",
    val title: String = "",
    val isLoading: Boolean = false,
    val progress: Int = 0,
    val canGoBack: Boolean = false,
    val canGoForward: Boolean = false,
    val isReady: Boolean = false,
    val error: String? = null,
)
