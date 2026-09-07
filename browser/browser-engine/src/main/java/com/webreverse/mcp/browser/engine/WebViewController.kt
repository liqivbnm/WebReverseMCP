package com.webreverse.mcp.browser.engine

import android.content.Context
import android.webkit.WebView
import com.webreverse.mcp.browser.engine.bridge.JsBridge
import com.webreverse.mcp.browser.engine.bridge.NetworkBridge
import com.webreverse.mcp.core.common.event.EventBus
import com.webreverse.mcp.core.common.util.Ids
import com.webreverse.mcp.core.database.repository.UserScriptRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap

/**
 * WebView 控制器：负责创建 / 管理 / 销毁每个 Tab 的 WebView 与引擎。
 * Compose UI 不直接操作 WebView，统一通过本控制器。
 */
class WebViewController(
    private val context: Context,
    private val eventBus: EventBus,
    private val networkBridge: NetworkBridge,
    private val userScriptRepository: UserScriptRepository,
) {
    private val engines = ConcurrentHashMap<String, WebViewBrowserEngine>()
    private val webViews = ConcurrentHashMap<String, WebView>()

    init {
        // 允许 WebView 渲染整个文档（而非仅可视区域），browser.pdf 全页导出依赖此设置。
        // 必须在进程内第一个 WebView 实例化之前调用，本类统一管理所有 WebView 的创建，
        // 放在 init 块可保证时序。
        // 基线模式（BASELINE_MODE）下关闭：此调用切换 Chromium 渲染管线为整文档模式，
        // 属于渲染路径干扰项，基线验证阶段使用标准渲染路径。
        if (!WebViewBrowserEngine.BASELINE_MODE) {
            try {
                WebView.enableSlowWholeDocumentDraw()
            } catch (_: Throwable) {
                // 部分 ROM 上重复调用或时机过晚会抛异常，忽略即可（仅影响全页 PDF 的完整性）
            }
        }
        // 恢复 行为：WebContents 调试无条件开启（CDP 附加 / debugger.attach 依赖）。
        // 放在 init 块保证早于 createEngine 的 WebView(context) 构造——Android 要求
        // setWebContentsDebuggingEnabled 先于任何 WebView 实例化，否则 DevTools abstract
        // socket（webview_devtools_remote_<pid>）不会建立。
        WebView.setWebContentsDebuggingEnabled(true)
    }

    /**
     * 创建引擎。WebView 必须在主线程构造——若在无 Looper 的后台线程（如 Ktor/Netty 线程）
     * 构造，Chromium 内部 Handler 初始化会因 Looper 为 null 抛 NPE。
     * 请通过 [createEngineOnMain] 调用。
     */
    private fun createEngine(tabId: String = Ids.uuid()): WebViewBrowserEngine {
        // 关键修复：显式设置 MATCH_PARENT LayoutParams。
        // Compose AndroidView + 手工 new WebView 的组合下，WebView 缺省无 LayoutParams，
        // 初始测量可能得到未定/零尺寸，CSS viewport 与 media query 按错误宽度计算，
        // 布局初始化异常——表现为"图片正常显示（固有尺寸）、文字缺失（依赖布局计算）"。
        // 与 m.bilibili.com + Compose WebView 的已知案例症状一致，MATCH_PARENT 修复有效。
        val webView = WebView(context.applicationContext).apply {
            layoutParams = android.widget.FrameLayout.LayoutParams(
                android.view.ViewGroup.LayoutParams.MATCH_PARENT,
                android.view.ViewGroup.LayoutParams.MATCH_PARENT,
            )
        }
        val jsBridge = JsBridge(
            eventBus,
            onNetEvent = { json -> networkBridge.onJsNetEvent(tabId, json) },
        )
        val engine = WebViewBrowserEngine(webView, tabId, eventBus, networkBridge, jsBridge, userScriptRepository)
        engines[tabId] = engine
        webViews[tabId] = webView
        return engine
    }

    /** 在主线程创建引擎（WebView 构造的线程要求），可从任意线程安全调用 */
    suspend fun createEngineOnMain(tabId: String = Ids.uuid()): WebViewBrowserEngine =
        withContext(Dispatchers.Main) { createEngine(tabId) }

    fun getEngine(tabId: String): WebViewBrowserEngine? = engines[tabId]

    fun getWebView(tabId: String): WebView? = webViews[tabId]

    /**
     * 切换全局 UA 模式（手机/电脑）并立即应用到所有已创建的 WebView。
     * 引擎创建时（setupWebView）会读取当前模式，故新建标签自动继承；
     * 页面重载由上层（BrowserService）负责触发。
     */
    fun setDesktopUa(enabled: Boolean) {
        WebViewBrowserEngine.desktopUaMode = enabled
        engines.values.forEach { it.refreshUserAgent() }
    }

    suspend fun destroyEngine(tabId: String) {
        engines.remove(tabId)?.let { engine ->
            engine.destroy() // 内部已切换到主线程执行
        }
        webViews.remove(tabId)
    }

    suspend fun destroyAll() {
        engines.keys.toList().forEach { destroyEngine(it) }
    }

    fun listEngines(): List<WebViewBrowserEngine> = engines.values.toList()
}

/** 本地 WebView 后端适配器 */
class LocalWebViewBackend(
    private val context: Context,
    private val eventBus: EventBus,
    private val networkBridge: NetworkBridge,
    private val userScriptRepository: UserScriptRepository,
) : BrowserBackend {
    private val controller = WebViewController(context, eventBus, networkBridge, userScriptRepository)

    override val name: String = "LocalWebView"

    override suspend fun createSession(tabId: String): BrowserEngine {
        val existing = controller.getEngine(tabId)
        if (existing != null) return existing
        // MCP 工具从 Ktor/Netty 线程调用，必须切到主线程构造 WebView
        return controller.createEngineOnMain(tabId)
    }

    override suspend fun destroySession(tabId: String) {
        controller.destroyEngine(tabId)
    }

    override suspend fun listSessions(): List<String> = controller.listEngines().map { it.tabId }

    fun getController(): WebViewController = controller
}
