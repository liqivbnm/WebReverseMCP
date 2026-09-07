package com.webreverse.mcp.ui.home

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Hub
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material.icons.filled.TrackChanges
import androidx.compose.material.icons.filled.TripOrigin
import androidx.compose.material.icons.filled.Workspaces
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.webreverse.mcp.di.AppContainer
import com.webreverse.mcp.ui.components.StatCard
import com.webreverse.mcp.ui.navigation.Routes

/**
 * 首页：现代 Material 3 Dashboard。
 * 显示统计信息、快速入口（含全部子页面）、最近目标、最近分析、功能概览。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(
    container: AppContainer,
    onNavigate: (String) -> Unit = {},
) {
    // 展示当前模式可见工具数（聚合模式约 32 个枢纽）
    val toolCount = container.toolRegistry.visibleCount()
    val tabs by container.browserService.tabs.collectAsState()
    val mcpState by container.mcpServerManager.serverState.collectAsState()

    Scaffold(
        // 底部沉浸：手机端底部 inset 由根 AppBottomBar 消费，避免内容上方空白带
        contentWindowInsets = com.webreverse.mcp.ui.navigation.pageScaffoldInsets(),
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("WebReverse MCP", style = MaterialTheme.typography.titleLarge)
                        Text(
                            "AI 驱动的网页调试与逆向分析工作台",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                },
            )
        },
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            // ---- 统计卡片（按窗口档位自适应列数） ----
            item {
                val windowSize = com.webreverse.mcp.ui.navigation.windowSizeClass()
                if (windowSize == com.webreverse.mcp.ui.navigation.WindowSizeClass.COMPACT) {
                    // 手机：两行两列（第二行单卡半宽，原布局）
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        StatCard(
                            title = "MCP Tools",
                            value = toolCount.toString(),
                            icon = Icons.Filled.Hub,
                            modifier = Modifier.weight(1f),
                        )
                        StatCard(
                            title = "标签页",
                            value = tabs.size.toString(),
                            icon = Icons.Filled.Language,
                            modifier = Modifier.weight(1f),
                        )
                    }
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 12.dp),
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        StatCard(
                            title = "MCP Server",
                            value = if (mcpState.name == "RUNNING") "运行中" else "已停止",
                            icon = Icons.Filled.Dns,
                            modifier = Modifier.weight(1f),
                            onClick = { onNavigate(Routes.MCP) },
                        )
                    }
                } else {
                    // 平板/横屏：三卡一行等宽，避免单卡被拉得过宽
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        StatCard(
                            title = "MCP Tools",
                            value = toolCount.toString(),
                            icon = Icons.Filled.Hub,
                            modifier = Modifier.weight(1f),
                        )
                        StatCard(
                            title = "标签页",
                            value = tabs.size.toString(),
                            icon = Icons.Filled.Language,
                            modifier = Modifier.weight(1f),
                        )
                        StatCard(
                            title = "MCP Server",
                            value = if (mcpState.name == "RUNNING") "运行中" else "已停止",
                            icon = Icons.Filled.Dns,
                            modifier = Modifier.weight(1f),
                            onClick = { onNavigate(Routes.MCP) },
                        )
                    }
                }
            }

            // ---- 核心入口 ----
            item {
                Text(
                    text = "核心入口",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(8.dp)) {
                        NavigateEntry("打开浏览器", "多标签浏览 · 地址栏 · 前进/后退/刷新", Icons.Filled.Language, Routes.BROWSER, onNavigate)
                        NavigateEntry("MCP Server", "启动 AI 连接 · 局域网地址 · 一键复制", Icons.Filled.Dns, Routes.MCP, onNavigate)
                        NavigateEntry("AI 工作区", "管理分析项目 · 目标 · 笔记 · 发现", Icons.Filled.Workspaces, Routes.WORKSPACE, onNavigate)
                        NavigateEntry("内置终端", "交互式 Shell · Host Tools 管理 · 安装 git/python", Icons.Filled.Terminal, Routes.TERMINAL, onNavigate)
                    }
                }
            }

            // ---- 调试与分析工具 ----
            item {
                Text(
                    text = "调试与分析工具",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(8.dp)) {
                        NavigateEntry("Hook 规则", "Fetch / XHR / WebSocket / Storage / Function Hook", Icons.Filled.TrackChanges, Routes.HOOKS, onNavigate)
                        NavigateEntry("断点管理", "Line / Function / DOM / XHR / 异常断点", Icons.Filled.TripOrigin, Routes.BREAKPOINTS, onNavigate)
                        NavigateEntry("用户脚本", "Tampermonkey 风格脚本管理", Icons.Filled.Code, Routes.SCRIPTS, onNavigate)
                        NavigateEntry("统一日志", "App / Browser / MCP / Network / Hook 日志", Icons.Filled.Terminal, Routes.LOGS, onNavigate)
                    }
                }
            }

            // ---- 浏览器数据 ----
            item {
                Text(
                    text = "浏览器数据",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(8.dp)) {
                        NavigateEntry("历史记录", "访问历史 · 搜索 · 清空", Icons.Filled.History, Routes.HISTORY, onNavigate)
                        NavigateEntry("收藏夹", "书签管理 · 文件夹分组", Icons.Filled.Workspaces, Routes.BOOKMARKS, onNavigate)
                        NavigateEntry("权限管理", "Agent 权限边界 · 敏感数据保护", Icons.Filled.Security, Routes.PERMISSIONS, onNavigate)
                    }
                }
            }

            // ---- 功能概览 ----
            item {
                Text(
                    text = "功能概览",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(8.dp)) {
                        FeatureRow("浏览器模式", "多标签、Tab Groups、阅读模式、下载")
                        FeatureRow("DOM 分析", "DOM Tree、属性、样式、事件监听、XPath")
                        FeatureRow("JavaScript 分析", "AST、混淆检测、API 发现、格式化")
                        FeatureRow("网络分析", "请求采集、HAR 导出、Hook、Mock")
                        FeatureRow("调试器", "断点、Watch、调用栈、作用域")
                        FeatureRow("Hook 引擎", "Function / Fetch / XHR / WebSocket / Storage Hook")
                        FeatureRow("MCP Server", "固定 Streamable HTTP，连接 AI Agent")
                        FeatureRow("安全模型", "权限作用域、敏感数据脱敏、Token 认证")
                    }
                }
            }
        }
    }
}

/** 可导航的入口条目 */
@Composable
private fun NavigateEntry(
    title: String,
    subtitle: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    route: String,
    onNavigate: (String) -> Unit,
) {
    ListItem(
        headlineContent = { Text(title) },
        supportingContent = { Text(subtitle) },
        leadingContent = {
            Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
        },
        trailingContent = {
            Icon(
                Icons.AutoMirrored.Filled.KeyboardArrowRight,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        },
        modifier = Modifier.clickable { onNavigate(route) },
    )
}

@Composable
private fun FeatureRow(title: String, subtitle: String) {
    ListItem(
        headlineContent = { Text(title, style = MaterialTheme.typography.bodyLarge) },
        supportingContent = { Text(subtitle, style = MaterialTheme.typography.bodySmall) },
        leadingContent = {
            Icon(
                Icons.Filled.TrackChanges,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.secondary,
            )
        },
    )
}
