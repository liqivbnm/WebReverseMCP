package com.webreverse.mcp.browser.engine

import android.content.Context
import com.webreverse.mcp.browser.engine.bridge.NetworkBridge
import com.webreverse.mcp.core.common.event.EventBus
import com.webreverse.mcp.core.common.model.BrowserTab
import com.webreverse.mcp.core.common.util.Ids
import com.webreverse.mcp.core.database.repository.UserScriptRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.concurrent.ConcurrentHashMap

/**
 * 浏览器服务：管理多 Tab 会话、提供统一入口。
 * MCP Tool 通过 UseCase 调用本服务，而不是直接操作 WebView。
 */
class BrowserService(
    private val context: Context,
    private val eventBus: EventBus,
    private val networkBridge: NetworkBridge,
    private val userScriptRepository: UserScriptRepository,
) {
    private val backend = LocalWebViewBackend(context, eventBus, networkBridge, userScriptRepository)
    private val sessions = ConcurrentHashMap<String, BrowserSession>()
    private val _tabs = MutableStateFlow<List<BrowserTab>>(emptyList())
    val tabs: StateFlow<List<BrowserTab>> = _tabs.asStateFlow()

    private val _activeTabId = MutableStateFlow<String?>(null)
    val activeTabId: StateFlow<String?> = _activeTabId.asStateFlow()

    private val _desktopUa = MutableStateFlow(WebViewBrowserEngine.desktopUaMode)

    /** 当前 UA 模式：false = 手机 UA（原生 WebView UA），true = 桌面 UA（桌面 Chrome） */
    val desktopUa: StateFlow<Boolean> = _desktopUa.asStateFlow()

    /**
     * 切换手机/电脑 UA 模式，应用到所有标签页并重载已打开的页面：
     * - 手机模式：原生 WebView UA（仅移除 wv 标记的最小清洗）
     * - 桌面模式：由原生 UA 派生的桌面 Chrome UA（内核版本号与真实引擎一致）
     * 切换后新导航自动使用新 UA；重载使已打开页面立即生效。
     */
    suspend fun setDesktopUa(enabled: Boolean) {
        if (_desktopUa.value == enabled && WebViewBrowserEngine.desktopUaMode == enabled) return
        _desktopUa.value = enabled
        backend.getController().setDesktopUa(enabled)
        // 重载已加载过的页面使新 UA 立即生效；空标签（未导航）跳过
        sessions.values.forEach { session ->
            if (session.engine.state.value.url.isNotBlank()) {
                session.engine.reload()
            }
        }
    }

    /** 切换 UA 模式（手机↔电脑取反），返回切换后的模式（true = 桌面 UA） */
    suspend fun toggleDesktopUa(): Boolean {
        setDesktopUa(!_desktopUa.value)
        return _desktopUa.value
    }

    suspend fun createTab(url: String = ""): BrowserSession {
        val tabId = Ids.uuid()
        val engine = backend.createSession(tabId)
        val session = BrowserSession(tabId, engine, eventBus)
        sessions[tabId] = session
        val tab = BrowserTab(id = tabId, url = url, sessionId = tabId)
        _tabs.value = _tabs.value + tab
        _activeTabId.value = tabId
        if (url.isNotBlank()) {
            engine.loadUrl(url)
        }
        return session
    }

    fun getSession(tabId: String?): BrowserSession? {
        val id = tabId ?: _activeTabId.value ?: return null
        return sessions[id]
    }

    suspend fun getOrCreateActiveSession(): BrowserSession {
        getSession(null)?.let { return it }
        return createTab()
    }

    suspend fun closeTab(tabId: String) {
        sessions.remove(tabId)?.let { session ->
            backend.destroySession(tabId)
        }
        _tabs.value = _tabs.value.filterNot { it.id == tabId }
        if (_activeTabId.value == tabId) {
            _activeTabId.value = _tabs.value.lastOrNull()?.id
        }
    }

    fun activateTab(tabId: String) {
        if (sessions.containsKey(tabId)) {
            _activeTabId.value = tabId
        }
    }

    suspend fun closeAll() {
        sessions.keys.toList().forEach { closeTab(it) }
    }

    fun listSessions(): List<BrowserSession> = sessions.values.toList()

    /** 获取指定 tab 的 WebView（供 Compose UI 显示） */
    fun getWebView(tabId: String?): android.webkit.WebView? {
        val id = tabId ?: _activeTabId.value ?: return null
        return backend.getController().getWebView(id)
    }

    /** 获取指定 tab 的引擎 */
    fun getEngine(tabId: String?): BrowserEngine? {
        val id = tabId ?: _activeTabId.value ?: return null
        return backend.getController().getEngine(id)
    }

    /** 应用上下文（供 MCP 工具使用，如系统下载服务） */
    fun appContext(): Context = context.applicationContext
}

/** 每个 Tab 的独立会话：包含引擎、网络、调试、Hook 上下文 */
class BrowserSession(
    val tabId: String,
    val engine: BrowserEngine,
    val eventBus: EventBus,
) {
    val networkEntries = MutableStateFlow<List<com.webreverse.mcp.core.common.model.NetworkEntry>>(emptyList())
    val consoleMessages = MutableStateFlow<List<String>>(emptyList())

    fun recordConsole(level: String, message: String) {
        consoleMessages.value = consoleMessages.value + "[$level] $message"
    }

    fun clearConsole() {
        consoleMessages.value = emptyList()
    }
}
