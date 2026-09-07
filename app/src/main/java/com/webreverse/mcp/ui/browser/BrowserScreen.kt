package com.webreverse.mcp.ui.browser

import android.webkit.WebView
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.ime
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.union
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.DesktopWindows
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Smartphone
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.StarBorder
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import com.webreverse.mcp.core.common.model.BrowserTab
import com.webreverse.mcp.di.AppContainer
import kotlinx.coroutines.launch

/** 浏览器默认起始页（新标签页 / 首页按钮 / 空地址导航的统一入口） */
private const val START_PAGE_URL = "https://go.mintab.cn/"

/**
 * 浏览器模式：地址栏 + 多标签 + WebView 显示 + 导航控制。
 * 双指缩放已全局解锁（引擎层注入 viewport 修正脚本），无缩放按钮。
 * 地址栏跟随：完整导航 + SPA 页内导航（doUpdateVisitedHistory）均实时同步；
 * 用户编辑时暂停同步，防止正在输入的内容被覆盖。
 * 底栏最后一键：手机/电脑 UA 切换（全局模式，切换后自动重载已打开页面）。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BrowserScreen(container: AppContainer) {
    val scope = rememberCoroutineScope()
    val tabs by container.browserService.tabs.collectAsState()
    val activeTabId by container.browserService.activeTabId.collectAsState()
    val desktopUa by container.browserService.desktopUa.collectAsState()

    var urlInput by remember { mutableStateOf("") }
    var isUrlEditing by remember { mutableStateOf(false) }
    var isBookmarked by remember { mutableStateOf(false) }
    val snackbarHostState = remember { SnackbarHostState() }

    val activeSession = remember(activeTabId) {
        if (activeTabId != null) container.browserService.getSession(activeTabId) else null
    }
    val engineState by (activeSession?.engine?.state?.collectAsState() ?: remember { androidx.compose.runtime.mutableStateOf(com.webreverse.mcp.browser.engine.BrowserEngineState()) })

    // 地址跟随：页面 URL 变化时同步到地址栏（用户正在编辑时暂停，避免覆盖输入）
    LaunchedEffect(engineState.url) {
        if (!isUrlEditing && engineState.url.isNotBlank() && urlInput != engineState.url) {
            urlInput = engineState.url
        }
    }

    // 首次进入浏览器模式：无标签页时自动打开起始页
    LaunchedEffect(Unit) {
        if (container.browserService.tabs.value.isEmpty()) {
            container.browserService.createTab(START_PAGE_URL)
        }
    }

    // 当前页是否已收藏（URL 变化时刷新）
    LaunchedEffect(engineState.url) {
        isBookmarked = if (engineState.url.isBlank()) false else {
            try { container.bookmarkManager.isBookmarked(engineState.url) } catch (e: Exception) { false }
        }
    }

    fun toggleBookmark() {
        val url = engineState.url
        if (url.isBlank()) return
        scope.launch {
            try {
                if (isBookmarked) {
                    container.bookmarkManager.remove(url)
                    isBookmarked = false
                    snackbarHostState.showSnackbar("已取消收藏")
                } else {
                    val title = engineState.title.ifBlank { url }
                    container.bookmarkManager.add(title, url)
                    isBookmarked = true
                    snackbarHostState.showSnackbar("已收藏: $title")
                }
            } catch (e: Exception) {
                snackbarHostState.showSnackbar("操作失败: ${e.message}")
            }
        }
    }

    Scaffold(
        // 底部沉浸修复：
        // - 只取 systemBars 的「顶部 + 水平」inset——底部系统栏 inset 不在此消费
        //   （手机端由根布局 AppBottomBar 负责；平板端由底部工具栏自己负责，
        //   此前底部 inset 在此 padding 会把工具栏顶起，露出白色窗口背景 = 白色长条）
        // - ime 保留：地址栏输入时键盘不遮挡
        contentWindowInsets = WindowInsets.systemBars
            .only(WindowInsetsSides.Horizontal + WindowInsetsSides.Top)
            .union(WindowInsets.ime),
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { innerPadding ->
        Column(modifier = Modifier.fillMaxSize().padding(innerPadding)) {
            // 标签栏（新标签页默认加载起始页）
            TabStrip(
                tabs = tabs,
                activeTabId = activeTabId,
                onSelect = { id -> scope.launch { container.browserService.activateTab(id) } },
                onClose = { id -> scope.launch { container.browserService.closeTab(id) } },
                onNewTab = { scope.launch { container.browserService.createTab(START_PAGE_URL) } },
            )

            // 地址栏（含收藏星标；编辑时暂停 URL 自动跟随）
            AddressBar(
                urlInput = urlInput,
                onUrlChange = { urlInput = it },
                onNavigate = { input ->
                    isUrlEditing = false
                    val url = normalizeUrl(input)
                    scope.launch { container.browserService.getOrCreateActiveSession().engine.loadUrl(url) }
                },
                isLoading = engineState.isLoading,
                isBookmarked = isBookmarked,
                onToggleBookmark = { toggleBookmark() },
                onEditingChanged = { editing -> isUrlEditing = editing },
            )

            // WebView 显示
            // 关键修复：AndroidView 的 factory 只在首次组合时执行一次，直接把 WebView 传给
            // factory 的话，切标签时 factory 参数变化不会重新调用——视图永远停留在第一个
            // 标签的 WebView，表现为"标签页切换没效果"。
            // 正确做法：factory 创建一个持久容器（FrameLayout），update 回调里按
            // activeTabId 动态换入对应 WebView（先摘下旧的，再挂新的）。
            Box(modifier = Modifier.weight(1f)) {
                val context = LocalContext.current
                val webViewHost = remember {
                    android.widget.FrameLayout(context).apply {
                        layoutParams = android.view.ViewGroup.LayoutParams(
                            android.view.ViewGroup.LayoutParams.MATCH_PARENT,
                            android.view.ViewGroup.LayoutParams.MATCH_PARENT,
                        )
                    }
                }
                val currentWebView = remember(activeTabId) {
                    container.browserService.getWebView(activeTabId)
                }
                AndroidView(
                    factory = { webViewHost },
                    modifier = Modifier.fillMaxSize(),
                    update = {
                        val active = container.browserService.getWebView(activeTabId)
                        if (active != null) {
                            if (active.parent !== webViewHost) {
                                // WebView 只能有一个父容器：先从原父容器摘下
                                (active.parent as? android.view.ViewGroup)?.removeView(active)
                                while (webViewHost.childCount > 0) webViewHost.removeViewAt(0)
                                webViewHost.addView(
                                    active,
                                    android.view.ViewGroup.LayoutParams.MATCH_PARENT,
                                    android.view.ViewGroup.LayoutParams.MATCH_PARENT,
                                )
                            }
                        } else if (webViewHost.childCount > 0) {
                            while (webViewHost.childCount > 0) webViewHost.removeViewAt(0)
                        }
                    },
                )
                if (currentWebView == null) {
                    EmptyBrowserPlaceholder()
                }

                // 调试暂停提示条：断点命中（AI 经 MCP 设置、外部调试客户端或页面
                // debugger 语句）页面暂停时显示，一键放行——手机上没有放行入口时
                // 页面会一直卡死在暂停态
                val debuggerPaused = rememberDebuggerPaused()
                if (debuggerPaused) {
                    DebuggerPausedBanner(
                        onResume = {
                            scope.launch {
                                val resumed = com.webreverse.mcp.devtools.protocol.cdp.CdpHub.resumePausedSessions()
                                if (resumed == 0) {
                                    snackbarHostState.showSnackbar("没有需要放行的暂停会话")
                                }
                            }
                        },
                        modifier = Modifier
                            .align(Alignment.BottomCenter)
                            .padding(bottom = 16.dp),
                    )
                }

                // 加载进度
                if (engineState.isLoading) {
                    CircularProgressIndicator(
                        modifier = Modifier
                            .align(Alignment.TopCenter)
                            .padding(top = 2.dp)
                            .size(24.dp),
                        strokeWidth = 2.dp,
                    )
                }
            }

            // 导航栏
            NavigationBar(
                canGoBack = engineState.canGoBack,
                canGoForward = engineState.canGoForward,
                isLoading = engineState.isLoading,
                onBack = { scope.launch { activeSession?.engine?.goBack() } },
                onForward = { scope.launch { activeSession?.engine?.goForward() } },
                onReload = { scope.launch { activeSession?.engine?.reload() } },
                onStop = { scope.launch { activeSession?.engine?.stop() } },
                onHome = { scope.launch { activeSession?.engine?.loadUrl(START_PAGE_URL) } },
                isDesktopUa = desktopUa,
                onToggleUa = {
                    scope.launch {
                        val desktop = container.browserService.toggleDesktopUa()
                        snackbarHostState.showSnackbar(if (desktop) "已切换为电脑 UA" else "已切换为手机 UA")
                    }
                },
            )
        }
    }
}

/** 轮询 CDP 枢纽暂停态（800ms；断点命中 → true，放行/恢复 → false） */
@Composable
private fun rememberDebuggerPaused(): Boolean {
    var paused by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        while (true) {
            paused = com.webreverse.mcp.devtools.protocol.cdp.CdpHub.anyPaused()
            kotlinx.coroutines.delay(800)
        }
    }
    return paused
}

/** 调试暂停提示条：断点命中页面停止执行时悬浮显示，提供放行按钮 */
@Composable
private fun DebuggerPausedBanner(
    onResume: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Surface(
        color = MaterialTheme.colorScheme.errorContainer,
        contentColor = MaterialTheme.colorScheme.onErrorContainer,
        shape = MaterialTheme.shapes.large,
        shadowElevation = 8.dp,
        modifier = modifier,
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier
                .padding(start = 16.dp, end = 8.dp, top = 6.dp, bottom = 6.dp),
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "调试器已暂停",
                    style = MaterialTheme.typography.titleSmall,
                )
                Text(
                    text = "断点命中，页面已停止执行",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            Spacer(modifier = Modifier.width(8.dp))
            Button(onClick = onResume) {
                Icon(
                    Icons.Filled.PlayArrow,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp),
                )
                Spacer(modifier = Modifier.width(4.dp))
                Text("放行")
            }
        }
    }
}

@Composable
private fun TabStrip(
    tabs: List<BrowserTab>,
    activeTabId: String?,
    onSelect: (String) -> Unit,
    onClose: (String) -> Unit,
    onNewTab: () -> Unit,
) {
    LazyRow(
        modifier = Modifier
            .fillMaxWidth()
            .height(48.dp),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(horizontal = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        items(tabs, key = { it.id }) { tab ->
            FilterChip(
                selected = tab.id == activeTabId,
                onClick = { onSelect(tab.id) },
                label = {
                    Text(
                        text = tab.title.ifBlank { tab.url.ifBlank { "新标签页" } }.take(12),
                        maxLines = 1,
                    )
                },
                trailingIcon = {
                    IconButton(onClick = { onClose(tab.id) }, modifier = Modifier.size(20.dp)) {
                        Icon(Icons.Filled.Close, contentDescription = "关闭", modifier = Modifier.size(14.dp))
                    }
                },
            )
        }
        item {
            AssistChip(
                onClick = onNewTab,
                label = { Icon(Icons.Filled.Add, contentDescription = "新建标签页", modifier = Modifier.size(18.dp)) },
            )
        }
    }
}

@Composable
private fun AddressBar(
    urlInput: String,
    onUrlChange: (String) -> Unit,
    onNavigate: (String) -> Unit,
    isLoading: Boolean,
    isBookmarked: Boolean = false,
    onToggleBookmark: () -> Unit = {},
    onEditingChanged: (Boolean) -> Unit = {},
) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceContainer,
        tonalElevation = 2.dp,
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Icon(
                Icons.Filled.Search,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedTextField(
                value = urlInput,
                onValueChange = onUrlChange,
                modifier = Modifier
                    .weight(1f)
                    .onFocusChanged { focusState ->
                        // 获得焦点 = 进入编辑态（暂停 URL 自动跟随）；失焦 = 恢复跟随
                        onEditingChanged(focusState.isFocused)
                    },
                placeholder = { Text("输入 URL 或搜索") },
                singleLine = true,
                keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                    keyboardType = androidx.compose.ui.text.input.KeyboardType.Uri,
                    imeAction = androidx.compose.ui.text.input.ImeAction.Go,
                ),
                keyboardActions = androidx.compose.foundation.text.KeyboardActions(
                    onGo = { onNavigate(urlInput) },
                ),
            )
            // 收藏星标：实心=已收藏，空心=未收藏
            IconButton(onClick = onToggleBookmark) {
                Icon(
                    if (isBookmarked) Icons.Filled.Star else Icons.Filled.StarBorder,
                    contentDescription = if (isBookmarked) "取消收藏" else "收藏此页",
                    tint = if (isBookmarked) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun NavigationBar(
    canGoBack: Boolean,
    canGoForward: Boolean,
    isLoading: Boolean,
    onBack: () -> Unit,
    onForward: () -> Unit,
    onReload: () -> Unit,
    onStop: () -> Unit,
    onHome: () -> Unit,
    isDesktopUa: Boolean,
    onToggleUa: () -> Unit,
) {
    // 底部沉浸：平板/横屏（宽屏）模式下没有 AppBottomBar，
    // 本工具栏就是屏幕最底部元素——Surface 铺满到底部边缘，
    // 内容 Row 用 navigationBarsPadding 抬升，栏背景（surfaceContainer 灰）
    // 延伸绘制到系统手势区后面，与状态栏沉浸（TopAppBar 画到状态栏后）同构。
    // 手机（COMPACT）模式由根布局 AppBottomBar 负责底部 inset，此处不再重复消费。
    val immersiveBottom = com.webreverse.mcp.ui.navigation.windowSizeClass() !=
        com.webreverse.mcp.ui.navigation.WindowSizeClass.COMPACT
    Surface(
        color = MaterialTheme.colorScheme.surfaceContainer,
        tonalElevation = 2.dp,
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .then(
                    if (immersiveBottom) Modifier.navigationBarsPadding() else Modifier,
                )
                .padding(vertical = 4.dp),
            horizontalArrangement = Arrangement.SpaceEvenly,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconButton(onClick = onBack, enabled = canGoBack) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "后退")
            }
            IconButton(onClick = onForward, enabled = canGoForward) {
                Icon(Icons.AutoMirrored.Filled.ArrowForward, contentDescription = "前进")
            }
            IconButton(onClick = if (isLoading) onStop else onReload) {
                Icon(
                    if (isLoading) Icons.Filled.Stop else Icons.Filled.Refresh,
                    contentDescription = if (isLoading) "停止" else "刷新",
                )
            }
            IconButton(onClick = onHome) {
                Icon(Icons.Filled.Home, contentDescription = "首页")
            }
            // 手机/电脑 UA 切换：图标显示当前模式（手机/电脑），点击全局切换并重载页面
            IconButton(onClick = onToggleUa) {
                Icon(
                    if (isDesktopUa) Icons.Filled.DesktopWindows else Icons.Filled.Smartphone,
                    contentDescription = if (isDesktopUa) "当前为电脑UA，点击切换为手机UA" else "当前为手机UA，点击切换为电脑UA",
                    tint = if (isDesktopUa) {
                        MaterialTheme.colorScheme.primary
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    },
                )
            }
        }
    }
}

@Composable
private fun EmptyBrowserPlaceholder() {
    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = "打开新标签页开始浏览",
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

/** URL 规范化：识别 https/http/www/domain/localhost/IP，否则走搜索 */
private fun normalizeUrl(input: String): String {
    val trimmed = input.trim()
    if (trimmed.isBlank()) return START_PAGE_URL
    if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) return trimmed
    if (trimmed.startsWith("about:") || trimmed.startsWith("data:") || trimmed.startsWith("file:")) return trimmed
    if (trimmed.startsWith("localhost") || trimmed.startsWith("127.") || trimmed.startsWith("192.168.") || trimmed.startsWith("10.")) {
        return "http://$trimmed"
    }
    val looksLikeDomain = Regex("""^[\w-]+(\.[\w-]+)+(:\\d+)?(/.*)?$""").matches(trimmed)
    if (looksLikeDomain) return "https://$trimmed"
    return "https://www.google.com/search?q=${android.net.Uri.encode(trimmed)}"
}
