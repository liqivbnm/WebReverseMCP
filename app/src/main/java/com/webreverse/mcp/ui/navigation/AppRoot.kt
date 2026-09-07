package com.webreverse.mcp.ui.navigation

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.systemBars
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.unit.dp
import com.webreverse.mcp.di.AppContainer
import com.webreverse.mcp.ui.bookmarks.BookmarksScreen
import com.webreverse.mcp.ui.browser.BrowserScreen
import com.webreverse.mcp.ui.breakpoints.BreakpointsScreen
import com.webreverse.mcp.ui.history.HistoryScreen
import com.webreverse.mcp.ui.home.HomeScreen
import com.webreverse.mcp.ui.hooks.HooksScreen
import com.webreverse.mcp.ui.logs.LogsScreen
import com.webreverse.mcp.ui.mcp.McpServerScreen
import com.webreverse.mcp.ui.permissions.PermissionsScreen
import com.webreverse.mcp.ui.scripts.ScriptsScreen
import com.webreverse.mcp.ui.settings.SettingsScreen
import com.webreverse.mcp.ui.terminal.TerminalScreen
import com.webreverse.mcp.ui.theme.ThemeMode
import com.webreverse.mcp.ui.workspace.WorkspaceScreen

/** 窗口尺寸档位（对齐 Material3 WindowSizeClass 断点） */
enum class WindowSizeClass {
    /** 手机竖屏（<600dp）：底部 NavigationBar */
    COMPACT,

    /** 平板竖屏/小横屏（600-840dp）：NavigationRail 仅图标，节省横向空间 */
    MEDIUM,

    /** 平板横屏/大屏（>=840dp）：NavigationRail 图标+文字标签 */
    EXPANDED,
}

/**
 * 应用根布局：响应式导航 + 主/子页面路由。
 * - 手机（窄屏）：底部 NavigationBar
 * - 中屏（600-840dp）：左侧 NavigationRail（仅图标）
 * - 大屏（>=840dp）：左侧 NavigationRail（图标+标签），内容区加水平留白
 * - 子页面：顶部 TopAppBar 带返回箭头
 *
 * 沉浸式修复：根 Scaffold 的 contentWindowInsets 置零。
 * 之前根 Scaffold（默认 systemBars）会给内容区叠加一次状态栏高度，
 * 而各页面自己的 Scaffold/TopAppBar 又会再叠加一次——首页/子页面顶部
 * 出现双倍状态栏留白。现在由各页面自行处理顶部 inset，TopAppBar 背景
 * 延伸到状态栏后面，实现真正的沉浸式（edge-to-edge 已在 MainActivity 启用）。
 */
@Composable
fun WebReverseAppRoot(
    container: AppContainer,
    themeMode: ThemeMode,
    onThemeModeChange: (ThemeMode) -> Unit,
    dynamicColor: Boolean,
    onDynamicColorChange: (Boolean) -> Unit,
) {
    var currentDestination by rememberSaveable { mutableStateOf(Destination.Home.route) }
    var currentSubRoute by rememberSaveable { mutableStateOf<String?>(null) }

    val windowSize = windowSizeClass()
    val useRail = windowSize != WindowSizeClass.COMPACT

    /** 导航：主页面路由切换主导航，子页面路由进入子页面 */
    val navigateTo: (String) -> Unit = { route ->
        if (Routes.mainRoutes.contains(route)) {
            currentDestination = route
            currentSubRoute = null
        } else {
            currentSubRoute = route
        }
    }

    /** 从子页面返回 */
    val goBack: () -> Unit = { currentSubRoute = null }

    val showBottomBar = !useRail && currentSubRoute == null
    val showRail = useRail && currentSubRoute == null
    val isSubPage = currentSubRoute != null

    // 子页面时拦截系统返回键，返回主页而非退出 App
    BackHandler(enabled = isSubPage) {
        currentSubRoute = null
    }

    Scaffold(
        // 关键：置零。状态栏/导航栏 inset 由各页面与 bottomBar/Rail 各自处理，
        // 避免嵌套 Scaffold 双重叠加状态栏高度
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        bottomBar = {
            if (showBottomBar) {
                AppBottomBar(
                    current = currentDestination,
                    onSelect = { currentDestination = it },
                )
            }
        },
    ) { padding ->
        Row(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            // 左侧 NavigationRail（仅宽屏主页面显示）
            if (showRail) {
                AppRail(
                    current = currentDestination,
                    onSelect = { currentDestination = it },
                    showLabels = windowSize == WindowSizeClass.EXPANDED,
                )
            }

            // 右侧内容区域：大屏加水平留白，避免内容顶满屏幕边缘
            Box(
                modifier = Modifier
                    .weight(1f)
                    .then(
                        if (useRail) Modifier.padding(horizontal = 16.dp) else Modifier,
                    ),
            ) {
                // 委托属性无法 smart cast，先捕获到局部变量再判空
                val subRoute = currentSubRoute
                if (isSubPage && subRoute != null) {
                    // 子页面自带 TopAppBar 和返回按钮，直接渲染
                    SubScreen(
                        container = container,
                        route = subRoute,
                        onBack = goBack,
                    )
                } else {
                    AppContent(
                        container = container,
                        destination = currentDestination,
                        themeMode = themeMode,
                        onThemeModeChange = onThemeModeChange,
                        dynamicColor = dynamicColor,
                        onDynamicColorChange = onDynamicColorChange,
                        onNavigate = navigateTo,
                    )
                }
            }
        }
    }
}

@Composable
private fun AppBottomBar(
    current: String,
    onSelect: (String) -> Unit,
) {
    NavigationBar {
        Destination.all.forEach { dest ->
            NavigationBarItem(
                selected = current == dest.route,
                onClick = { onSelect(dest.route) },
                icon = {
                    Icon(
                        imageVector = dest.icon,
                        contentDescription = dest.label,
                    )
                },
                label = { Text(dest.label) },
            )
        }
    }
}

/** 宽屏侧边导航：MEDIUM 只显示图标，EXPANDED 显示图标+标签 */
@Composable
private fun AppRail(
    current: String,
    onSelect: (String) -> Unit,
    showLabels: Boolean,
) {
    NavigationRail {
        Destination.all.forEach { dest ->
            NavigationRailItem(
                selected = current == dest.route,
                onClick = { onSelect(dest.route) },
                icon = {
                    Icon(
                        imageVector = dest.icon,
                        contentDescription = dest.label,
                    )
                },
                label = if (showLabels) {
                    { Text(dest.label) }
                } else {
                    null
                },
                alwaysShowLabel = showLabels,
            )
        }
    }
}

@Composable
private fun AppContent(
    container: AppContainer,
    destination: String,
    themeMode: ThemeMode,
    onThemeModeChange: (ThemeMode) -> Unit,
    dynamicColor: Boolean,
    onDynamicColorChange: (Boolean) -> Unit,
    onNavigate: (String) -> Unit,
) {
    when (destination) {
        Destination.Home.route -> HomeScreen(container, onNavigate)
        Destination.Browser.route -> BrowserScreen(container)
        Destination.Mcp.route -> McpServerScreen(container)
        Destination.Workspace.route -> WorkspaceScreen(container)
        Destination.Settings.route -> SettingsScreen(
            container = container,
            themeMode = themeMode,
            onThemeModeChange = onThemeModeChange,
            dynamicColor = dynamicColor,
            onDynamicColorChange = onDynamicColorChange,
        )
    }
}

/** 子页面路由分发 */
@Composable
private fun SubScreen(
    container: AppContainer,
    route: String,
    onBack: () -> Unit,
) {
    when (route) {
        Routes.HISTORY -> HistoryScreen(container, onBack)
        Routes.BOOKMARKS -> BookmarksScreen(container, onBack)
        Routes.SCRIPTS -> ScriptsScreen(container, onBack)
        Routes.HOOKS -> HooksScreen(container, onBack)
        Routes.BREAKPOINTS -> BreakpointsScreen(container, onBack)
        Routes.PERMISSIONS -> PermissionsScreen(container, onBack)
        Routes.LOGS -> LogsScreen(container, onBack)
        Routes.TERMINAL -> TerminalScreen(container)
        else -> {
            // 未知路由：显示提示而非立即返回（补状态栏 padding，避免内容顶进状态栏）
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .statusBarsPadding()
                    .padding(32.dp),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text("页面不存在", style = MaterialTheme.typography.titleLarge)
                Text(
                    "路由：$route",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 8.dp),
                )
                Button(
                    onClick = onBack,
                    modifier = Modifier.padding(top = 16.dp),
                ) {
                    Text("返回")
                }
            }
        }
    }
}

/** 窗口尺寸档位（对齐 Material3 WindowSizeClass 断点：600/840dp） */
@Composable
fun windowSizeClass(): WindowSizeClass {
    val widthDp = LocalConfiguration.current.screenWidthDp
    return when {
        widthDp >= 840 -> WindowSizeClass.EXPANDED
        widthDp >= 600 -> WindowSizeClass.MEDIUM
        else -> WindowSizeClass.COMPACT
    }
}

/**
 * 页面级 Scaffold 的 contentWindowInsets（ 各页面统一接入）。
 *
 * 手机端（COMPACT）：底部系统栏高度已由根布局 AppBottomBar 的 NavigationBar
 * 消费——其 Surface 背景会延伸绘制到手势区后面。若页面 Scaffold 再计一次
 * 底部 inset，内容会被抬高一条 systemBars.bottom 的空白带（页面 surface 底色
 * 浅色主题下近白），表现为「底部导航栏上方的白色长条」。故只取 顶部+水平。
 *
 * 平板端（MEDIUM/EXPANDED）：无根底部栏，页面保留完整 systemBars——
 * Scaffold 的 surface 填满到手势区后面，内容不被系统栏遮挡。
 */
@Composable
fun pageScaffoldInsets(): WindowInsets =
    if (windowSizeClass() == WindowSizeClass.COMPACT) {
        WindowInsets.systemBars.only(WindowInsetsSides.Horizontal + WindowInsetsSides.Top)
    } else {
        WindowInsets.systemBars
    }
