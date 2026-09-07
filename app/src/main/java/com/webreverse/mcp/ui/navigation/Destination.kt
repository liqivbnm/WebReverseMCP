package com.webreverse.mcp.ui.navigation

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Workspaces
import androidx.compose.ui.graphics.vector.ImageVector

/** 主导航目标（底部导航栏 / NavigationRail） */
sealed class Destination(
    val route: String,
    val label: String,
    val icon: ImageVector,
) {
    data object Home : Destination("home", "首页", Icons.Filled.Home)
    data object Browser : Destination("browser", "浏览器", Icons.Filled.Language)
    data object Mcp : Destination("mcp", "MCP", Icons.Filled.Dns)
    data object Workspace : Destination("workspace", "工作区", Icons.Filled.Workspaces)
    data object Settings : Destination("settings", "设置", Icons.Filled.Settings)

    companion object {
        /**
         * 注意：必须使用 getter 而非直接初始化的 val。
         * 若写成 `val all = listOf(Home, ...)`，首次访问 Destination.Home 时会触发
         * companion object 初始化，此时 Home 实例尚未赋值完成（JVM 递归初始化保护
         * 直接返回），导致列表第一个元素为 null，进而引发 NPE 崩溃。
         */
        val all: List<Destination>
            get() = listOf(Home, Browser, Mcp, Workspace, Settings)
    }
}

/** 子页面路由（从主页面进入的二级页面） */
object Routes {
    // 主页面
    const val HOME = "home"
    const val BROWSER = "browser"
    const val MCP = "mcp"
    const val WORKSPACE = "workspace"
    const val SETTINGS = "settings"

    /** 全部主页面路由（底部导航栏 / NavigationRail 可直达） */
    val mainRoutes = setOf(HOME, BROWSER, MCP, WORKSPACE, SETTINGS)

    // 子页面
    const val HISTORY = "history"
    const val BOOKMARKS = "bookmarks"
    const val SCRIPTS = "scripts"
    const val HOOKS = "hooks"
    const val BREAKPOINTS = "breakpoints"
    const val PERMISSIONS = "permissions"
    const val LOGS = "logs"
    const val TERMINAL = "terminal"

    /** 全部子页面路由 */
    val subRoutes = setOf(HISTORY, BOOKMARKS, SCRIPTS, HOOKS, BREAKPOINTS, PERMISSIONS, LOGS, TERMINAL)
}
