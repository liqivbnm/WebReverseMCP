package com.webreverse.mcp.ui.mcp

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
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
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.webreverse.mcp.core.common.model.McpClient
import com.webreverse.mcp.core.common.model.McpServerConfig
import com.webreverse.mcp.di.AppContainer
import com.webreverse.mcp.mcp.server.McpServerState
import kotlinx.coroutines.launch

/**
 * MCP Server 管理页面。
 * 展示：状态、Host/Port、MCP 端点地址（本地 + 局域网）、端口占用检测、
 * 固定 HTTP MCP 端点、连接统计、已连接 Agent。
 * 控制：Start/Stop/Restart、一键复制 MCP 地址。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun McpServerScreen(container: AppContainer) {
    val scope = rememberCoroutineScope()
    val snackbarHostState = remember { SnackbarHostState() }
    val clipboard = LocalClipboardManager.current

    val serverState by container.mcpServerManager.serverState.collectAsState()
    val config by container.mcpServerManager.config.collectAsState()
    val clients by container.mcpServerManager.clients.collectAsState()
    val stats by container.mcpServerManager.stats.collectAsState()

    // 局域网地址（记忆化，避免每次 recomposition 都重新计算）
    val lanAddresses = remember { container.mcpServerManager.getLanAddresses() }

    // 当前认证 Token（DataStore 异步读取；开启强制认证后客户端需携带）
    var authToken by remember { mutableStateOf("") }
    LaunchedEffect(Unit) {
        runCatching { container.tokenManager.getOrCreateToken() }
            .onSuccess { authToken = it }
    }

    // 端口占用检测：涉及阻塞 socket 操作，放到 IO 线程异步执行，避免主线程卡顿
    var portInUse by remember { mutableStateOf(false) }
    LaunchedEffect(config.port, serverState) {
        portInUse = serverState != McpServerState.RUNNING &&
            container.mcpServerManager.checkPort(config.port)
    }
    val localEndpoint = remember(config) { container.mcpServerManager.mcpEndpoint() }
    val lanEndpoints = remember(config.port, lanAddresses) {
        lanAddresses.map { "http://$it:${config.port}/mcp" }
    }

    val running = serverState == McpServerState.RUNNING

    Scaffold(
        // 底部沉浸：手机端底部 inset 由根 AppBottomBar 消费，避免内容上方空白带
        contentWindowInsets = com.webreverse.mcp.ui.navigation.pageScaffoldInsets(),
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("MCP Server")
                        Text(
                            "AI Agent 连接与工具分发",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            // ---- 状态卡片 ----
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = when (serverState) {
                            McpServerState.RUNNING -> MaterialTheme.colorScheme.primaryContainer
                            McpServerState.ERROR -> MaterialTheme.colorScheme.errorContainer
                            else -> MaterialTheme.colorScheme.surfaceContainer
                        },
                    ),
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Icon(
                                Icons.Filled.Dns,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary,
                            )
                            Text(
                                text = "Status: ${serverState.name}",
                                style = MaterialTheme.typography.titleLarge,
                                modifier = Modifier.padding(start = 12.dp),
                            )
                        }
                        Text(
                            text = "Host: ${config.host}  ·  Port: ${config.port}",
                            style = MaterialTheme.typography.bodyMedium,
                            modifier = Modifier.padding(top = 8.dp),
                        )

                        // 端口占用检测
                        if (!running && portInUse) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(top = 8.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Icon(
                                    Icons.Filled.Stop,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.error,
                                    modifier = Modifier.size(16.dp),
                                )
                                Text(
                                    text = "端口 ${config.port} 已被占用",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.error,
                                    modifier = Modifier.padding(start = 4.dp),
                                )
                            }
                        }

                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(top = 12.dp),
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            Button(
                                onClick = {
                                    scope.launch {
                                        if (running) {
                                            // 阻塞的 Netty 关闭已在 Manager 内部切换到 IO 线程，主线程不再卡顿
                                            container.mcpServerManager.stop()
                                        } else {
                                            val ok = container.mcpServerManager.start()
                                            if (!ok) {
                                                snackbarHostState.showSnackbar("启动失败：端口 ${config.port} 可能被占用")
                                            }
                                        }
                                    }
                                },
                                enabled = serverState != McpServerState.STARTING &&
                                    serverState != McpServerState.STOPPING,
                            ) {
                                Icon(
                                    if (running) Icons.Filled.Stop else Icons.Filled.PlayArrow,
                                    contentDescription = null,
                                    modifier = Modifier.padding(end = 4.dp),
                                )
                                Text(if (running) "停止" else "启动")
                            }
                            OutlinedButton(
                                onClick = { scope.launch { container.mcpServerManager.restart() } },
                                enabled = running,
                            ) {
                                Icon(
                                    Icons.Filled.Refresh,
                                    contentDescription = null,
                                    modifier = Modifier.padding(end = 4.dp),
                                )
                                Text("重启")
                            }
                        }
                    }
                }
            }

            // ---- MCP 端点地址 ----
            item {
                Text(
                    text = "MCP 端点地址",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }
            // 本地地址
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(
                            text = "本地地址",
                            style = MaterialTheme.typography.titleSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(top = 8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(
                                text = localEndpoint,
                                style = MaterialTheme.typography.bodyMedium,
                                fontFamily = FontFamily.Monospace,
                                modifier = Modifier.weight(1f),
                            )
                            IconButton(onClick = {
                                clipboard.setText(AnnotatedString(localEndpoint))
                                scope.launch { snackbarHostState.showSnackbar("MCP 地址已复制") }
                            }) {
                                Icon(Icons.Filled.ContentCopy, contentDescription = "复制")
                            }
                        }
                    }
                }
            }
            // 局域网地址
            if (lanEndpoints.isNotEmpty()) {
                item {
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Icon(
                                    Icons.Filled.Wifi,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.primary,
                                    modifier = Modifier.size(20.dp),
                                )
                                Text(
                                    text = "局域网地址",
                                    style = MaterialTheme.typography.titleSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.padding(start = 8.dp),
                                )
                            }
                            lanEndpoints.forEach { endpoint ->
                                HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    verticalAlignment = Alignment.CenterVertically,
                                ) {
                                    Text(
                                        text = endpoint,
                                        style = MaterialTheme.typography.bodyMedium,
                                        fontFamily = FontFamily.Monospace,
                                        modifier = Modifier.weight(1f),
                                    )
                                    IconButton(onClick = {
                                        clipboard.setText(AnnotatedString(endpoint))
                                        scope.launch { snackbarHostState.showSnackbar("MCP 地址已复制") }
                                    }) {
                                        Icon(Icons.Filled.ContentCopy, contentDescription = "复制")
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // ---- 统计 ----
            item {
                Text(
                    text = "统计",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    StatChip("连接数", stats.connectionCount.toString(), Modifier.weight(1f))
                    StatChip("客户端", stats.clientCount.toString(), Modifier.weight(1f))
                    StatChip("会话", stats.sessionCount.toString(), Modifier.weight(1f))
                }
            }
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    StatChip("Tool 调用", stats.toolCallCount.toString(), Modifier.weight(1f))
                    StatChip("注册 Tools", container.toolRegistry.count().toString(), Modifier.weight(1f))
                    StatChip("运行时长", formatUptime(stats.uptimeMs), Modifier.weight(1f))
                }
            }

            // ---- 配置 ----
            item {
                Text(
                    text = "配置",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(8.dp)) {
                        PortEditor(
                            currentPort = config.port,
                            running = running,
                            manager = container.mcpServerManager,
                            config = config,
                            scope = scope,
                            snackbarHostState = snackbarHostState,
                        )
                        HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                        ConfigSwitch(
                            title = "仅局域网",
                            subtitle = "禁止公网访问",
                            checked = config.lanOnly,
                            onCheckedChange = { updateConfig(scope, container, config.copy(lanOnly = it)) },
                        )
                        ConfigSwitch(
                            title = "强制 Token 认证",
                            subtitle = "开启后客户端必须携带 Token 才能连接（更安全）",
                            checked = config.requireAuth ?: false,
                            onCheckedChange = { updateConfig(scope, container, config.copy(requireAuth = it)) },
                        )
                        // Token 展示与复制（开启强制认证后客户端配置用）
                        if (authToken.isNotBlank()) {
                            ListItem(
                                headlineContent = { Text("连接 Token") },
                                supportingContent = {
                                    Text(
                                        text = authToken,
                                        fontFamily = FontFamily.Monospace,
                                        style = MaterialTheme.typography.bodySmall,
                                    )
                                },
                                trailingContent = {
                                    IconButton(onClick = {
                                        clipboard.setText(AnnotatedString(authToken))
                                        scope.launch { snackbarHostState.showSnackbar("Token 已复制") }
                                    }) {
                                        Icon(Icons.Filled.ContentCopy, contentDescription = "复制 Token")
                                    }
                                },
                            )
                        }
                    }
                }
            }

            // ---- 已连接 Agent ----
            item {
                Text(
                    text = "已连接 Agent (${clients.size})",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }
            if (clients.isEmpty()) {
                item {
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Text(
                            text = "暂无连接，启动 Server 后等待 AI Agent 接入",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(16.dp),
                        )
                    }
                }
            } else {
                items(clients, key = { it.id }) { client ->
                    ClientCard(client)
                }
            }
        }
    }
}

private fun updateConfig(scope: kotlinx.coroutines.CoroutineScope, container: AppContainer, config: McpServerConfig) {
    scope.launch { container.mcpServerManager.updateConfig(config) }
}

/**
 * 端口自定义编辑：数字输入 + 保存。
 * - 校验范围 1024-65535
 * - 未运行时保存前检测端口占用（运行中时服务自身占用端口会误报，跳过预检测，
 *   updateConfig 内部重启时先释放再绑定，失败会进入 ERROR 状态）
 */
@Composable
private fun PortEditor(
    currentPort: Int,
    running: Boolean,
    manager: com.webreverse.mcp.mcp.server.McpServerManager,
    config: McpServerConfig,
    scope: kotlinx.coroutines.CoroutineScope,
    snackbarHostState: SnackbarHostState,
) {
    var portInput by remember(currentPort) { mutableStateOf(currentPort.toString()) }
    val newPort = portInput.toIntOrNull()
    val portValid = newPort != null && newPort in 1024..65535
    val portDirty = portValid && newPort != currentPort

    Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
        Text(
            text = "端口",
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            OutlinedTextField(
                value = portInput,
                onValueChange = { input ->
                    if (input.length <= 5 && input.all { it.isDigit() }) portInput = input
                },
                modifier = Modifier.weight(1f),
                singleLine = true,
                label = { Text("1024 - 65535") },
                isError = portInput.isNotBlank() && !portValid,
                keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                    keyboardType = androidx.compose.ui.text.input.KeyboardType.Number,
                ),
                supportingText = {
                    when {
                        portInput.isNotBlank() && !portValid -> Text("端口需在 1024 - 65535 之间")
                        portDirty && running -> Text("未保存，保存后自动重启生效")
                        portDirty -> Text("未保存")
                        else -> Text("")
                    }
                },
            )
            Button(
                enabled = portDirty,
                onClick = {
                    val port = newPort ?: return@Button
                    scope.launch {
                        if (!running && manager.checkPort(port)) {
                            snackbarHostState.showSnackbar("端口 $port 已被占用")
                        } else {
                            manager.updateConfig(config.copy(port = port))
                            snackbarHostState.showSnackbar(
                                if (running) "端口已更新为 $port，服务重启中" else "端口已保存为 $port",
                            )
                        }
                    }
                },
            ) {
                Text("保存")
            }
        }
    }
}

@Composable
private fun StatChip(title: String, value: String, modifier: Modifier = Modifier) {
    Card(
        modifier = modifier,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
        ) {
            Text(text = value, style = MaterialTheme.typography.titleMedium)
            Text(
                text = title,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun ConfigSwitch(
    title: String,
    subtitle: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    ListItem(
        headlineContent = { Text(title) },
        supportingContent = { Text(subtitle) },
        trailingContent = {
            Switch(checked = checked, onCheckedChange = onCheckedChange)
        },
    )
}

@Composable
private fun ClientCard(client: McpClient) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = client.name,
                    style = MaterialTheme.typography.titleSmall,
                    modifier = Modifier.weight(1f),
                )
                AssistChip(
                    onClick = {},
                    label = { Text(client.transport) },
                )
            }
            Text(
                text = "地址: ${client.remoteAddress}  ·  协议: ${client.protocolVersion}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 4.dp),
            )
        }
    }
}

private fun formatUptime(ms: Long): String {
    if (ms <= 0) return "0s"
    val totalSec = ms / 1000
    val h = totalSec / 3600
    val m = (totalSec % 3600) / 60
    val s = totalSec % 60
    return if (h > 0) "${h}h ${m}m" else if (m > 0) "${m}m ${s}s" else "${s}s"
}
