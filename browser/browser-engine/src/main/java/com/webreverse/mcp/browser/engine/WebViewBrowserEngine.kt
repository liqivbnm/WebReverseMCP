package com.webreverse.mcp.browser.engine

import android.annotation.SuppressLint
import android.graphics.Bitmap
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.webkit.CookieManager
import android.webkit.JavascriptInterface
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import com.webreverse.mcp.browser.engine.bridge.JsBridge
import com.webreverse.mcp.browser.engine.bridge.NetworkBridge
import com.webreverse.mcp.browser.engine.util.JsScripts
import com.webreverse.mcp.core.common.event.BrowserEvent
import com.webreverse.mcp.core.common.event.ConsoleEvent
import com.webreverse.mcp.core.common.event.EventBus
import com.webreverse.mcp.core.common.event.NetworkEvent
import com.webreverse.mcp.core.common.model.NetworkEntry
import com.webreverse.mcp.core.common.util.Ids
import com.webreverse.mcp.core.database.entity.UserScriptEntity
import com.webreverse.mcp.core.database.repository.UserScriptRepository
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import java.io.ByteArrayInputStream
import java.util.concurrent.ConcurrentHashMap
import kotlin.coroutines.resume

/**
 * 基于 Android WebView 的浏览器引擎实现。
 * 每个 Tab 拥有独立的 WebView 与独立会话上下文。
 */
@SuppressLint("SetJavaScriptEnabled")
class WebViewBrowserEngine(
    private val webView: WebView,
    override val tabId: String,
    private val eventBus: EventBus,
    private val networkBridge: NetworkBridge,
    private val jsBridge: JsBridge,
    /* * 用户脚本仓库（页面加载时按 runAt 自动注入已启用的用户脚本） */
    private val userScriptRepository: UserScriptRepository,
) : BrowserEngine {

    private val mainHandler = Handler(Looper.getMainLooper())
    /** 用户脚本注入协程作用域（Room 查询为挂起函数，需在协程中调用） */
    private val scriptScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private val _state = MutableStateFlow(BrowserEngineState())
    override val state: StateFlow<BrowserEngineState> = _state.asStateFlow()

    private val pendingEvaluations = ConcurrentHashMap<Long, CompletableDeferred<String?>>()
    private val evalCounter = java.util.concurrent.atomic.AtomicLong(0)

    /* * P2-9：读写分离调度器——并发工具调用下读读并行、写独占且写优先 */
    private val accessScheduler = com.webreverse.mcp.browser.engine.util.AccessScheduler()

    init {
        mainHandler.post { setupWebView() }
    }

    private fun setupWebView() {
        val settings = webView.settings
        settings.javaScriptEnabled = true
        settings.domStorageEnabled = true
        settings.databaseEnabled = true
        settings.allowFileAccess = true
        settings.allowContentAccess = true
        settings.mediaPlaybackRequiresUserGesture = false
        settings.javaScriptCanOpenWindowsAutomatically = true
        settings.setSupportMultipleWindows(true)
        // 恢复 行为：Mixed Content 始终放行（网页逆向常需 http 资源内嵌于 https 页面）
        settings.mixedContentMode = WebSettings.MIXED_CONTENT_ALWAYS_ALLOW
        settings.cacheMode = WebSettings.LOAD_DEFAULT
        settings.useWideViewPort = true
        settings.loadWithOverviewMode = true
        settings.builtInZoomControls = true
        settings.displayZoomControls = false
        settings.textZoom = 100
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            // 恢复 行为：关闭 SafeBrowsing（逆向分析需访问任意站点）
            settings.safeBrowsingEnabled = false
        }
        // UA 策略：
        // - 手机模式（默认）：原生 WebView UA，仅做"移除 wv 标记"的最小清洗。
        //   任何 UA 伪装都有风险——站点按 UA 做特性/资源分发，伪装 UA 与真实引擎能力
        //   不匹配时会拿到错误资源（此前 Chrome/127 硬编码导致 bilibili 文字缺失的教训）。
        // - 桌面模式：由原生 UA 派生桌面 Chrome UA（保留真实内核版本号，能力匹配），
        //   供底栏"手机/电脑 UA"切换使用。
        // 首次创建引擎时记录原生 UA 基准，之后切换模式均以基准为源，避免读到已改写的 UA。
        if (nativeUaBase == null) {
            nativeUaBase = settings.userAgentString
        }
        applyUserAgent(settings)
        // 显式启用 Cookie（含三方 Cookie，WebView 默认关闭三方 Cookie，影响登录态）
        runCatching {
            val cm = android.webkit.CookieManager.getInstance()
            cm.setAcceptCookie(true)
            cm.setAcceptThirdPartyCookies(webView, true)
        }
        // 默认文本编码 UTF-8，防止中文乱码
        settings.defaultTextEncodingName = "utf-8"
        // （CDP 修复）：WebContents 调试开关已前移到 WebViewController.init
        // （任何 WebView 创建之前）。此处不再调用——Android 要求该开关必须先于
        // WebView 实例化，否则 DevTools socket 不建立；在此调用为时已晚且无效。

        // 暴露受控 Bridge：window.__MCP__
        webView.addJavascriptInterface(jsBridge, "__MCP__")

        // document_start 单次合并注入（报告 §30）：
        // 在页面自身任何脚本（含内联 <script>、`const old = window.fetch` 引用保存、
        // webpack 初始化）运行之前，一次性完成「网络/框架 Hook → 动态代码捕获
        // （eval/Function/Blob/Worker）→ stealth 反调试对抗层」三层安装。
        // - 单次注入消除两次注入之间的时序窗口（第一条执行完到第二条注入前，
        //   页面早期脚本可能已运行）；
        // - WebViewCompat 在 WebView 105+ 用原生 document-start 注入，
        //   旧版本自动降级为 onPageStarted 注入（仍早于页面脚本可见时机）；
        // - WebViewFeature.DOCUMENT_START_SCRIPT 能力检查（报告 §29）：
        //   特性不支持时降级 onPageStarted evaluate 注入，不再静默 runCatching 吞错。
        // - 基线模式（BASELINE_MODE）下关闭，保持零注入验证路径。
        if (!BASELINE_MODE) {
            val docStartSupported = androidx.webkit.WebViewFeature.isFeatureSupported(
                androidx.webkit.WebViewFeature.DOCUMENT_START_SCRIPT,
            )
            if (docStartSupported) {
                runCatching {
                    androidx.webkit.WebViewCompat.addDocumentStartJavaScript(
                        webView,
                        JsScripts.documentStartScript(),
                        setOf("*"),
                    )
                }
            } else {
                // 降级路径：无 document-start 特性（WebView < 105 或 androidx 不可用）
                // ——在每次 onPageStarted 时补注入（幂等守卫保证不重复安装）
                fallbackInjectDocumentStart = true
            }
        }

        webView.webViewClient = object : WebViewClient() {
            override fun onPageStarted(view: WebView?, url: String?, favicon: Bitmap?) {
                val u = url ?: return
                _state.value = _state.value.copy(url = u, isLoading = true, progress = 5, error = null)
                eventBus.tryEmit(BrowserEvent.PageStarted(tabId, u))
                // 环境兼容脚本注入（补 window.chrome 等）——基线模式关闭，零注入验证渲染
                if (!BASELINE_MODE) {
                    val envScript = JsScripts.browserEnvCompatScript()
                    view?.post { view.evaluateJavascript(envScript, null) }
                    // document-start 特性降级：合并脚本补注入（幂等）
                    if (fallbackInjectDocumentStart) {
                        view?.post { view.evaluateJavascript(JsScripts.documentStartScript(), null) }
                    }
                }
                // 用户脚本自动注入：PAGE_START / BEFORE_REQUEST 早期执行，DOM_READY 等待 DOMContentLoaded
                injectUserScripts(atStart = true, url = u)
            }

            override fun onPageFinished(view: WebView?, url: String?) {
                val u = url ?: return
                _state.value = _state.value.copy(
                    url = u,
                    title = view?.title ?: _state.value.title,
                    isLoading = false,
                    progress = 100,
                    isReady = true,
                    canGoBack = view?.canGoBack() ?: false,
                    canGoForward = view?.canGoForward() ?: false,
                )
                eventBus.tryEmit(BrowserEvent.PageFinished(tabId, u))
                // 运行时观测脚本注入（fetch/XHR Hook、缩放解锁）——基线模式关闭，零注入
                if (!BASELINE_MODE) {
                    injectRuntimeObservers()
                }
                // 用户脚本自动注入：AFTER_LOAD / AFTER_REQUEST / MANUAL 页面加载完成后执行
                injectUserScripts(atStart = false, url = u)
            }

            override fun onReceivedError(view: WebView?, request: WebResourceRequest?, error: android.webkit.WebResourceError?) {
                val message = error?.description?.toString() ?: "Unknown error"
                if (request?.isForMainFrame == true) {
                    _state.value = _state.value.copy(error = message)
                    eventBus.tryEmit(BrowserEvent.PageError(tabId, request.url.toString(), message))
                }
            }

            /**
             * 地址跟随关键回调：URL 变化但不触发完整页面加载的场景都会走这里——
             * SPA 的 history.pushState/replaceState、锚点跳转、iframe 内导航等。
             * onPageStarted 只覆盖完整导航，缺失此回调会导致地址栏在这些场景下不跟随。
             */
            override fun doUpdateVisitedHistory(view: WebView?, url: String?, isReload: Boolean) {
                val u = url ?: return
                if (_state.value.url != u) {
                    _state.value = _state.value.copy(
                        url = u,
                        canGoBack = view?.canGoBack() ?: _state.value.canGoBack,
                        canGoForward = view?.canGoForward() ?: _state.value.canGoForward,
                    )
                }
            }

            /**
             * 拦截自定义 scheme 跳转（baiduboxapp:// / bilibili:// / intent:// / weixin:// 等）。
             * 站点尝试唤起 App 时，若设备未装对应 App，startActivity 会失败甚至导致页面卡死。
             * 这里统一吞掉此类导航（返回 true = WebView 不处理），只记录事件供调试查看。
             */
            override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
                val url = request?.url?.toString() ?: return false
                return handleCustomScheme(url)
            }

            @Suppress("DEPRECATION", "OverridingDeprecatedMember")
            override fun shouldOverrideUrlLoading(view: WebView?, url: String?): Boolean {
                val u = url ?: return false
                return handleCustomScheme(u)
            }

            override fun shouldInterceptRequest(
                view: WebView?,
                request: WebResourceRequest?,
            ): WebResourceResponse? {
                val req = request ?: return null
                return networkBridge.intercept(tabId, req)
            }

            override fun shouldInterceptRequest(view: WebView?, url: String?): WebResourceResponse? {
                if (url == null) return null
                return networkBridge.interceptLegacy(tabId, url)
            }
        }

        webView.webChromeClient = object : WebChromeClient() {
            override fun onProgressChanged(view: WebView?, newProgress: Int) {
                _state.value = _state.value.copy(progress = newProgress)
                eventBus.tryEmit(BrowserEvent.ProgressChanged(tabId, newProgress))
            }

            override fun onReceivedTitle(view: WebView?, title: String?) {
                val t = title ?: return
                _state.value = _state.value.copy(title = t)
                eventBus.tryEmit(BrowserEvent.TitleChanged(tabId, t))
            }

            override fun onConsoleMessage(consoleMessage: android.webkit.ConsoleMessage?): Boolean {
                val msg = consoleMessage ?: return false
                eventBus.tryEmit(
                    ConsoleEvent.Message(
                        tabId,
                        msg.messageLevel().name.lowercase(),
                        "${msg.message()} (${msg.sourceId()}:${msg.lineNumber()})",
                    )
                )
                return true
            }

            /**
             * window.open 新窗口处理：站点（如 bilibili）的登录/播放器会调用 window.open，
             * 若不处理会静默失败甚至导致主页面卡死。这里让新窗口的 URL 在当前 Tab 打开。
             * 加固：仅重定向 http/https（about:blank 等空目标直接忽略，防止劫持主页面），
             * 并延迟销毁临时 WebView 释放原生资源。
             */
            override fun onCreateWindow(
                view: WebView?,
                isDialog: Boolean,
                isUserGesture: Boolean,
                resultMsg: android.os.Message?,
            ): Boolean {
                val parentView = view ?: return false
                val tempWebView = android.webkit.WebView(parentView.context)
                tempWebView.webViewClient = object : WebViewClient() {
                    override fun shouldOverrideUrlLoading(v: WebView?, request: WebResourceRequest?): Boolean {
                        val url = request?.url?.toString()
                        handleNewWindowUrl(url)
                        return true
                    }

                    @Suppress("DEPRECATION", "OverridingDeprecatedMember")
                    override fun shouldOverrideUrlLoading(v: WebView?, url: String?): Boolean {
                        handleNewWindowUrl(url)
                        return true
                    }
                }
                val transport = resultMsg?.obj as? android.webkit.WebView.WebViewTransport
                transport?.webView = tempWebView
                resultMsg?.sendToTarget()
                // 临时 WebView 只用于捕获新窗口 URL，延迟销毁防止泄漏
                mainHandler.postDelayed({ runCatching { tempWebView.destroy() } }, 10_000)
                return true
            }
        }
    }

    /**
     * 按当前全局 UA 模式设置 WebView UA（须在主线程调用）。
     * - 手机模式：原生 UA 基准 + "移除 wv 标记"最小清洗（基线模式下一字不改）
     * - 桌面模式：由原生 UA 基准派生的桌面 Chrome UA
     */
    private fun applyUserAgent(settings: android.webkit.WebSettings) {
        runCatching {
            val base = nativeUaBase ?: settings.userAgentString ?: return
            settings.userAgentString = if (desktopUaMode) {
                deriveDesktopUa(base)
            } else if (!BASELINE_MODE) {
                base
                    .replace("; wv)", ")")
                    .replace("Version/4.0 ", "")
                    .trim()
            } else {
                base
            }
        }
    }

    /** 全局 UA 模式切换后重新应用本引擎 WebView 的 UA（由 WebViewController 对所有引擎调用） */
    fun refreshUserAgent() {
        mainHandler.post { applyUserAgent(webView.settings) }
    }

    /**
     * 自定义 scheme 处理：非 http/https/data/about/javascript/blob/file 的 scheme 一律拦截。
     * 返回 true 表示已处理（WebView 不再导航），同时发出网络事件供调试面板查看。
     */
    private fun handleCustomScheme(url: String): Boolean {
        val scheme = Uri.parse(url).scheme?.lowercase() ?: return false
        val allowed = setOf("http", "https", "data", "about", "javascript", "blob", "file")
        if (scheme in allowed) return false
        // 拦截 baiduboxapp:// / bilibili:// / intent:// / weixin:// / alipays:// 等唤起跳转
        networkBridge.recordBlockedScheme(tabId, url)
        return true
    }

    /**
     * 新窗口（window.open / target=_blank）URL 处理：
     * - 自定义 scheme → 拦截（同 handleCustomScheme）
     * - http/https → 在当前标签页打开
     * - 其他（about:blank、空 URL 等）→ 直接忽略，防止广告/跟踪脚本用空 window.open 劫持主页面
     */
    private fun handleNewWindowUrl(url: String?) {
        if (url.isNullOrBlank()) return
        val scheme = Uri.parse(url).scheme?.lowercase()
        if (scheme != "http" && scheme != "https") {
            handleCustomScheme(url)
            return
        }
        mainHandler.post { webView.loadUrl(url) }
    }

    /** 注入运行时观测脚本（fetch/XHR/console 观测、Hook 基础框架）+ 缩放解锁。基线模式下直接跳过 */
    private fun injectRuntimeObservers() {
        if (BASELINE_MODE) return
        val script = JsScripts.runtimeObserverScript()
        val zoomUnlock = JsScripts.zoomUnlockScript()
        webView.post {
            webView.evaluateJavascript(script, null)
            webView.evaluateJavascript(zoomUnlock, null)
        }
    }

    /**
     * 用户脚本自动注入。
     * 在页面加载生命周期按 runAt 时机注入已启用的用户脚本：
     * - atStart=true（onPageStarted）：PAGE_START / BEFORE_REQUEST 直接执行；DOM_READY 包装为等待 DOMContentLoaded
     * - atStart=false（onPageFinished）：AFTER_LOAD / AFTER_REQUEST / MANUAL 直接执行
     * matchPatterns 为空时全站生效，否则按通配模式匹配当前 URL。
     * 注入失败不影响页面加载（静默忽略）。
     */
    private fun injectUserScripts(atStart: Boolean, url: String?) {
        if (BASELINE_MODE) return
        scriptScope.launch {
            try {
                val all = userScriptRepository.getAll().filter { it.enabled }
                if (all.isEmpty()) return@launch
                val matched = all.filter { matchesUrl(it.matchPatterns, url) }
                if (matched.isEmpty()) return@launch
                if (atStart) {
                    val direct = matched.filter { it.runAt == "PAGE_START" || it.runAt == "BEFORE_REQUEST" }
                    val domReady = matched.filter { it.runAt == "DOM_READY" }
                    webView.post {
                        if (direct.isNotEmpty()) {
                            webView.evaluateJavascript(direct.joinToString("\n;\n") { it.code }, null)
                        }
                        if (domReady.isNotEmpty()) {
                            webView.evaluateJavascript(domReady.joinToString("\n") { wrapDomReady(it.code) }, null)
                        }
                    }
                } else {
                    val late = matched.filter { it.runAt == "AFTER_LOAD" || it.runAt == "AFTER_REQUEST" || it.runAt == "MANUAL" }
                    if (late.isNotEmpty()) {
                        webView.post { webView.evaluateJavascript(late.joinToString("\n;\n") { it.code }, null) }
                    }
                }
            } catch (e: Exception) {
                // 注入失败不影响页面加载
            }
        }
    }

    /** 将脚本包装为等待 DOMContentLoaded 后执行（幂等：若已就绪则立即执行） */
    private fun wrapDomReady(code: String): String =
        "(function(){function __run(){try{" + code + "}catch(e){}}if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',__run)}else{__run()}})();"

    /** 判断脚本是否匹配当前 URL：matchPatterns 为空 = 全站生效 */
    private fun matchesUrl(patternJson: String, url: String?): Boolean {
        if (url.isNullOrBlank()) return false
        val patterns = parsePatterns(patternJson)
        if (patterns.isEmpty()) return true
        return patterns.any { globMatch(it, url) }
    }

    /** 解析 matchPatterns 存储格式（JSON 数组或逗号分隔字符串） */
    private fun parsePatterns(json: String): List<String> = try {
        val el = Json.parseToJsonElement(json)
        if (el is JsonArray) el.mapNotNull { (it as? JsonPrimitive)?.content } else emptyList()
    } catch (e: Exception) {
        json.split(',').map { it.trim() }.filter { it.isNotBlank() }
    }

    /** 通配匹配：* 匹配任意字符序列，? 匹配单个字符 */
    private fun globMatch(pattern: String, url: String): Boolean {
        val regex = buildString {
            append('^')
            pattern.forEach { c ->
                when (c) {
                    '*' -> append(".*")
                    '?' -> append('.')
                    else -> {
                        if (c in "\\.[]{}()+-^$|") append('\\')
                        append(c)
                    }
                }
            }
            append('$')
        }
        return runCatching { Regex(regex).matches(url) }.getOrDefault(false)
    }

    override suspend fun loadUrl(url: String) {
        withContext(Dispatchers.Main) {
            webView.loadUrl(url)
        }
    }

    override suspend fun reload() {
        withContext(Dispatchers.Main) { webView.reload() }
    }

    override suspend fun stop() {
        withContext(Dispatchers.Main) { webView.stopLoading() }
    }

    override suspend fun goBack(): Boolean = withContext(Dispatchers.Main) {
        if (webView.canGoBack()) {
            webView.goBack()
            true
        } else false
    }

    override suspend fun goForward(): Boolean = withContext(Dispatchers.Main) {
        if (webView.canGoForward()) {
            webView.goForward()
            true
        } else false
    }

    override suspend fun evaluateJavascript(script: String): String? {
        // P2-9：按脚本形态走读/写路径（读并行、写互斥且写优先），
        // 避免 Agent 并发调用时读到半安装状态
        val access = accessScheduler.classify(script)
        val exec: suspend () -> String? = { doEvaluate(script) }
        return when (access) {
            com.webreverse.mcp.browser.engine.util.AccessScheduler.Access.READ -> accessScheduler.read(exec)
            com.webreverse.mcp.browser.engine.util.AccessScheduler.Access.WRITE -> accessScheduler.write(exec)
        }
    }

    private suspend fun doEvaluate(script: String): String? {
        val deferred = CompletableDeferred<String?>()
        val id = evalCounter.incrementAndGet()
        pendingEvaluations[id] = deferred
        withContext(Dispatchers.Main) {
            webView.evaluateJavascript(script) { result ->
                pendingEvaluations.remove(id)?.complete(result)
            }
        }
        return withTimeoutOrNull(15_000) { deferred.await() }
    }

    /**
     * 异步执行 JavaScript：等待 Promise 结算后返回结果（ 修复）。
     *
     * 根因：Android WebView 的 evaluateJavascript 回调不会等待 Promise——
     * 脚本返回 Promise 时回调只拿到 Promise 对象的 JSON 序列化 `{}`。
     * 原实现直接委托同步路径，导致所有返回 Promise 的脚本
     * （storage.get_indexeddb/cache_storage/service_workers、performance.get_fps、
     * browser.upload 等）一律得到空结果。
     *
     * 修法：「落盘 + 轮询」两段式——包装脚本把（可能是 Promise 的）求值结果
     * 结算后写入页面全局槽位 window.__mcpAsyncResults[id]，Kotlin 侧轮询取回。
     * 结算值在页面内序列化为字符串（字符串原样、对象 JSON.stringify、
     * 循环引用回退 String()），返回时去除外层引号，调用方拿到的语义与
     * 同步 evaluateJavascript 的 JSON 文本一致。
     *
     * @return 结算值文本；Promise rejected 或超时（30s）返回 null
     */
    override suspend fun evaluateJavascriptAsync(script: String): String? {
        val wrapped = """
            (function(){
              var seq = (window.__mcpAsyncSeq = (window.__mcpAsyncSeq || 0) + 1);
              var id = 'r' + seq;
              window.__mcpAsyncResults = window.__mcpAsyncResults || {};
              window.__mcpAsyncResults[id] = {done: false};
              Promise.resolve().then(function(){
                return (async function(){
                  $script
                })();
              }).then(function(v){
                var s;
                try { s = (typeof v === 'string') ? v : JSON.stringify(v); } catch(e) { s = String(v); }
                if (s === undefined || s === null) s = String(v);
                window.__mcpAsyncResults[id] = {done: true, ok: true, value: String(s).substring(0, 1000000)};
              }).catch(function(e){
                var msg = (e && e.message) ? (e.message + '') : String(e);
                window.__mcpAsyncResults[id] = {done: true, ok: false, error: msg.substring(0, 10000)};
              });
              return id;
            })()
        """.trimIndent()
        val idRaw = evaluateJavascript(wrapped) ?: return null
        val slotId = idRaw.trim().removeSurrounding("\"")
        if (slotId.isBlank()) return null

        val deadline = System.currentTimeMillis() + ASYNC_EVAL_TIMEOUT_MS
        while (true) {
            val poll = """
                (function(){
                  var r = window.__mcpAsyncResults && window.__mcpAsyncResults[${JsScripts.quote(slotId)}];
                  if (!r || !r.done) return null;
                  var out = JSON.stringify(r);
                  try { delete window.__mcpAsyncResults[${JsScripts.quote(slotId)}]; } catch(e){}
                  return out;
                })()
            """.trimIndent()
            val raw = evaluateJavascript(poll) ?: return null
            val settled = parseAsyncSettled(raw)
            if (settled != null) {
                return settled.second
            }
            if (System.currentTimeMillis() > deadline) {
                evaluateJavascript(
                    "(function(){try{delete (window.__mcpAsyncResults||{})[${JsScripts.quote(slotId)}]}catch(e){}})()"
                )
                return null
            }
            kotlinx.coroutines.delay(150)
        }
    }

    /**
     * 解析轮询取回的结算 JSON。WebView 回调给的是「JSON 编码的字符串」：
     * 脚本 return "{...}" 时回调收到外层再包一层引号的转义文本，
     * 因此先 parse 外层得到内层 JSON 文本，再 parse 内层。
     * @return (ok, value)；value 为 null 表示 rejected（调用方按执行失败处理）
     */
    private fun parseAsyncSettled(raw: String?): Pair<Boolean, String?>? {
        if (raw.isNullOrBlank() || raw == "null") return null
        return try {
            val outer = Json.parseToJsonElement(raw)
            val innerText = when (outer) {
                is JsonPrimitive -> outer.content
                is kotlinx.serialization.json.JsonObject -> outer.toString()
                else -> return null
            }
            val obj = Json.parseToJsonElement(innerText).let { it as? kotlinx.serialization.json.JsonObject }
                ?: return null
            if (obj["done"]?.let { it as? JsonPrimitive }?.content != "true") {
                return null
            }
            val ok = obj["ok"]?.let { it as? JsonPrimitive }?.content == "true"
            val value = obj["value"]?.let { it as? JsonPrimitive }?.content
            ok to value
        } catch (e: Exception) {
            null
        }
    }

    override suspend fun screenshot(): Bitmap? = withContext(Dispatchers.Main) {
        webView.draw(android.graphics.Canvas())
        val width = webView.width
        val height = webView.height
        if (width <= 0 || height <= 0) return@withContext null
        val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
        val canvas = android.graphics.Canvas(bitmap)
        webView.draw(canvas)
        bitmap
    }

    override suspend fun currentUrl(): String? = _state.value.url.ifBlank { null }

    override suspend fun currentTitle(): String? = _state.value.title.ifBlank { null }

    override suspend fun canGoBack(): Boolean = _state.value.canGoBack

    override suspend fun canGoForward(): Boolean = _state.value.canGoForward

    override suspend fun getPageSource(): String? =
        evaluateJavascript("document.documentElement.outerHTML")

    override suspend fun getCookies(): List<Map<String, String>> {
        val cookieManager = CookieManager.getInstance()
        val cookieString = cookieManager.getCookie(_state.value.url) ?: return emptyList()
        return cookieString.split(";").mapNotNull { pair ->
            val idx = pair.indexOf('=')
            if (idx > 0) {
                mapOf(
                    "name" to pair.substring(0, idx).trim(),
                    "value" to pair.substring(idx + 1).trim(),
                )
            } else null
        }
    }

    override suspend fun setCookie(name: String, value: String, domain: String, path: String) {
        val cookieManager = CookieManager.getInstance()
        cookieManager.setCookie(
            "https://$domain$path",
            "$name=$value; Path=$path; Domain=$domain",
        )
    }

    override suspend fun getLocalStorage(): Map<String, String> {
        val json = evaluateJavascript(
            "(()=>{const o={};for(let i=0;i<localStorage.length;i++){const k=localStorage.key(i);o[k]=localStorage.getItem(k)}return JSON.stringify(o)})()"
        ) ?: return emptyMap()
        return parseJsonMap(json)
    }

    override suspend fun getSessionStorage(): Map<String, String> {
        val json = evaluateJavascript(
            "(()=>{const o={};for(let i=0;i<sessionStorage.length;i++){const k=sessionStorage.key(i);o[k]=sessionStorage.getItem(k)}return JSON.stringify(o)})()"
        ) ?: return emptyMap()
        return parseJsonMap(json)
    }

    override suspend fun setLocalStorage(key: String, value: String) {
        evaluateJavascript("localStorage.setItem(${JsScripts.quote(key)}, ${JsScripts.quote(value)})")
    }

    override suspend fun clearLocalStorage() {
        evaluateJavascript("localStorage.clear()")
    }

    override suspend fun clearSessionStorage() {
        evaluateJavascript("sessionStorage.clear()")
    }

    override suspend fun clearCache() {
        withContext(Dispatchers.Main) {
            webView.clearCache(true)
        }
    }

    override suspend fun clearCookies() {
        CookieManager.getInstance().removeAllCookies(null)
        CookieManager.getInstance().flush()
    }

    override suspend fun getNetworkEntries(): List<NetworkEntry> = networkBridge.getEntries(tabId)

    override suspend fun clearNetworkEntries() = networkBridge.clear(tabId)

    override suspend fun destroy() {
        withContext(Dispatchers.Main) {
            webView.stopLoading()
            webView.removeJavascriptInterface("__MCP__")
            // WebView.destroy() 要求视图已从视图树移除，否则 Chromium 报错甚至崩溃。
            // 关闭激活中的标签时 WebView 仍挂在显示容器上，先摘下再销毁。
            (webView.parent as? android.view.ViewGroup)?.removeView(webView)
            webView.destroy()
        }
    }

    private fun parseJsonMap(json: String): Map<String, String> {
        return try {
            val element = kotlinx.serialization.json.Json.parseToJsonElement(json)
            if (element is kotlinx.serialization.json.JsonObject) {
                element.mapValues { (_, v) -> v.toString().trim('"') }
            } else emptyMap()
        } catch (e: Exception) {
            emptyMap()
        }
    }

    /**
     * document-start 特性降级标记：WebView 不支持 DOCUMENT_START_SCRIPT 时，
     * onPageStarted 中补注入合并脚本（幂等守卫防重复）。
     */
    @Volatile
    private var fallbackInjectDocumentStart = false

    companion object {
        /* * 异步求值（Promise 等待）的总超时上限：超时按失败返回 null */
        private const val ASYNC_EVAL_TIMEOUT_MS = 30_000L

        /**
         * 基线模式开关（全局）。
         *
         * true  = 基线验证：原生 UA + 零 JS 注入（无 fetch/XHR Hook、无 viewport 修改、
         *         无 window.chrome 补齐）+ 标准渲染路径（不启用整文档绘制）。
         * false = 完整功能：恢复 UA 清洗、运行时 Hook、缩放解锁等全部 MCP 能力。
         *
         * 排查结论（2026-08-21，bilibili"图片正常、文字缺失"问题已解决）：
         * 根因确认为 WebView 缺省 LayoutParams——Compose AndroidView + 手工 new WebView
         * 组合下无显式尺寸约束，初始测量异常导致 CSS 布局计算错误。
         * 修复：WebViewController.createEngine() 显式设置 MATCH_PARENT。
         * 基线验证通过（bilibili 正常显示），故关闭基线模式恢复全部功能。
         * LayoutParams 修复为永久性修复，与功能开关无关。
         */
        const val BASELINE_MODE: Boolean = false

        /**
         * 全局 UA 模式：false = 手机 UA（原生 WebView UA），true = 桌面 UA（桌面 Chrome）。
         * 浏览器底栏"手机/电脑 UA"切换按钮驱动；新标签创建与已有标签切换共用此模式。
         */
        @Volatile
        var desktopUaMode: Boolean = false

        /** 原生 WebView UA 基准：首个引擎创建时记录；UA 模式来回切换时以此为准（settings 读回的是已改写值） */
        @Volatile
        private var nativeUaBase: String? = null

        /**
         * 由原生 WebView UA 派生桌面 Chrome UA：仅替换平台标识，保留真实 Chromium 内核
         * 版本号——UA 声明与引擎能力保持一致，避免站点按版本分发错误资源。
         * 例：
         *   Mozilla/5.0 (Linux; Android 14; ...) ... Chrome/127.0.6533.120 Mobile Safari/537.36
         *   → Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/127.0.6533.120 Safari/537.36
         */
        fun deriveDesktopUa(nativeUa: String): String {
            var ua = nativeUa
                .replace("; wv)", ")")
                .replace("Version/4.0 ", "")
                .trim()
            ua = ua.replaceFirst(
                Regex("""^Mozilla/5\.0\s*\([^)]*\)"""),
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            )
            ua = ua.replace(" Mobile Safari/", " Safari/")
            return ua
        }
    }
}
