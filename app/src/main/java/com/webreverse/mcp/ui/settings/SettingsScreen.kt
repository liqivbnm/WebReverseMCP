package com.webreverse.mcp.ui.settings

import com.webreverse.mcp.BuildConfig

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.PowerManager
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BatteryStd
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.DarkMode
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.LightMode
import androidx.compose.material.icons.filled.Palette
import androidx.compose.material.icons.filled.PhoneAndroid
import androidx.compose.material.icons.filled.RocketLaunch
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.webreverse.mcp.MainActivity
import com.webreverse.mcp.core.common.util.Redactor
import com.webreverse.mcp.core.common.util.WorkDir
import com.webreverse.mcp.di.AppContainer
import com.webreverse.mcp.keepalive.KeepAliveService
import com.webreverse.mcp.ui.theme.ThemeMode
import kotlinx.coroutines.launch

/**
 * 设置页面：外观、保活（常驻通知/悬浮球）、存储（工作目录）、权限、安全与隐私、调试、关于。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    container: AppContainer,
    themeMode: ThemeMode,
    onThemeModeChange: (ThemeMode) -> Unit,
    dynamicColor: Boolean,
    onDynamicColorChange: (Boolean) -> Unit,
) {
    val context = LocalContext.current

    // ---- 保活 / 权限 / 工作目录状态 ----
    var keepAlive by remember { mutableStateOf(KeepAliveService.isKeepAliveEnabled(context)) }
    var ballEnabled by remember { mutableStateOf(KeepAliveService.isBallEnabled(context)) }
    var overlayGranted by remember { mutableStateOf(Settings.canDrawOverlays(context)) }
    var batteryIgnored by remember { mutableStateOf(isIgnoringBatteryOptimizations(context)) }
    var allFilesGranted by remember { mutableStateOf(hasAllFilesAccess(context)) }
    var workDir by remember { mutableStateOf(WorkDir.get()) }
    var workDirWritable by remember { mutableStateOf(WorkDir.isWritable()) }
    var dirInput by remember(workDir) { mutableStateOf(workDir) }
    var dirMessage by remember { mutableStateOf<String?>(null) }
    var redactionEnabled by remember { mutableStateOf(Redactor.enabled) }
    // MCP 工具暴露模式（聚合枢纽 / 全量），用户手动开关
    var hubCompact by remember { mutableStateOf(com.webreverse.mcp.settings.ToolModePrefs.isCompact(context)) }
    val scope = rememberCoroutineScope()

    fun refreshStates() {
        keepAlive = KeepAliveService.isKeepAliveEnabled(context)
        ballEnabled = KeepAliveService.isBallEnabled(context)
        overlayGranted = Settings.canDrawOverlays(context)
        batteryIgnored = isIgnoringBatteryOptimizations(context)
        allFilesGranted = hasAllFilesAccess(context)
        workDir = WorkDir.get()
        workDirWritable = WorkDir.isWritable()
        redactionEnabled = Redactor.enabled
        KeepAliveService.refresh(context)
    }

    // 从系统设置页返回时刷新权限状态并刷新悬浮球
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) refreshStates()
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    val overlayLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { refreshStates() }

    Scaffold(
        // 底部沉浸：手机端底部 inset 由根 AppBottomBar 消费，避免内容上方空白带
        contentWindowInsets = com.webreverse.mcp.ui.navigation.pageScaffoldInsets(),
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("设置")
                        Text(
                            "主题、保活、存储与权限",
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
            // ---- 外观 ----
            item {
                Text(
                    text = "外观",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        ListItem(
                            headlineContent = { Text("主题模式") },
                            supportingContent = { Text("系统 / 浅色 / 深色") },
                            leadingContent = {
                                Icon(Icons.Filled.Palette, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                            },
                        )
                        SingleChoiceSegmentedButtonRow(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(top = 8.dp),
                        ) {
                            ThemeMode.entries.forEachIndexed { index, mode ->
                                SegmentedButton(
                                    selected = themeMode == mode,
                                    onClick = { onThemeModeChange(mode) },
                                    shape = SegmentedButtonDefaults.itemShape(index = index, count = ThemeMode.entries.size),
                                    icon = {
                                        Icon(
                                            imageVector = when (mode) {
                                                ThemeMode.SYSTEM -> Icons.Filled.PhoneAndroid
                                                ThemeMode.LIGHT -> Icons.Filled.LightMode
                                                ThemeMode.DARK -> Icons.Filled.DarkMode
                                            },
                                            contentDescription = null,
                                        )
                                    },
                                ) {
                                    Text(mode.label)
                                }
                            }
                        }
                        HorizontalDivider(modifier = Modifier.padding(vertical = 12.dp))
                        ListItem(
                            headlineContent = { Text("Dynamic Color") },
                            supportingContent = { Text("使用系统动态取色（Android 12+）") },
                            leadingContent = {
                                Icon(Icons.Filled.Palette, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                            },
                            trailingContent = {
                                Switch(checked = dynamicColor, onCheckedChange = onDynamicColorChange)
                            },
                        )
                    }
                }
            }

            // ---- 保活 ----
            item {
                Text(
                    text = "保活",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(8.dp)) {
                        ListItem(
                            headlineContent = { Text("保活服务") },
                            supportingContent = { Text("常驻通知保活，降低进程被系统回收的概率；开机自动拉起") },
                            leadingContent = {
                                Icon(Icons.Filled.Bolt, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                            },
                            trailingContent = {
                                Switch(
                                    checked = keepAlive,
                                    onCheckedChange = { enabled ->
                                        KeepAliveService.setKeepAliveEnabled(context, enabled)
                                        keepAlive = enabled
                                    },
                                )
                            },
                        )
                        HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                        ListItem(
                            headlineContent = { Text("悬浮球") },
                            supportingContent = { Text("应用图标 + 运行中角标，可拖动，单击回到应用") },
                            leadingContent = {
                                Icon(Icons.Filled.RocketLaunch, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                            },
                            trailingContent = {
                                Switch(
                                    checked = ballEnabled,
                                    onCheckedChange = { enabled ->
                                        KeepAliveService.setBallEnabled(context, enabled)
                                        ballEnabled = enabled
                                        if (enabled && !Settings.canDrawOverlays(context)) {
                                            overlayLauncher.launch(
                                                Intent(
                                                    Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                                                    Uri.parse("package:${context.packageName}"),
                                                ),
                                            )
                                        }
                                    },
                                )
                            },
                        )
                        if (!overlayGranted) {
                            Text(
                                "未授予悬浮窗权限，悬浮球暂不可见",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.error,
                                modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                            )
                        }
                    }
                }
            }

            // ---- 存储（工作目录） ----
            item {
                Text(
                    text = "存储",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        ListItem(
                            headlineContent = { Text("工作目录") },
                            supportingContent = { Text("所有导出文件（PDF / 下载等）统一存放于此目录") },
                            leadingContent = {
                                Icon(Icons.Filled.Folder, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                            },
                        )
                        OutlinedTextField(
                            value = dirInput,
                            onValueChange = { dirInput = it },
                            label = { Text("目录路径") },
                            singleLine = true,
                            isError = !workDirWritable,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(top = 8.dp),
                        )
                        Text(
                            if (workDirWritable) "当前目录可写" else "当前目录不可写：请先授予「所有文件管理权限」",
                            style = MaterialTheme.typography.bodySmall,
                            color = if (workDirWritable) {
                                MaterialTheme.colorScheme.onSurfaceVariant
                            } else {
                                MaterialTheme.colorScheme.error
                            },
                            modifier = Modifier.padding(top = 4.dp),
                        )
                        Row(
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            modifier = Modifier.padding(top = 12.dp),
                        ) {
                            Button(
                                onClick = {
                                    val ok = WorkDir.set(context, dirInput)
                                    dirMessage = if (ok) {
                                        "工作目录已更新为 ${WorkDir.get()}"
                                    } else {
                                        "设置失败：目录不存在或不可写（检查所有文件权限）"
                                    }
                                    if (ok) {
                                        workDir = WorkDir.get()
                                        workDirWritable = WorkDir.isWritable()
                                        dirInput = workDir
                                    }
                                },
                            ) {
                                Text("保存")
                            }
                            OutlinedButton(
                                onClick = {
                                    val ok = WorkDir.reset(context)
                                    dirMessage = if (ok) {
                                        "已恢复默认目录 ${WorkDir.DEFAULT_PATH}"
                                    } else {
                                        "恢复失败：默认目录不可写，请检查所有文件权限"
                                    }
                                    workDir = WorkDir.get()
                                    workDirWritable = WorkDir.isWritable()
                                    dirInput = workDir
                                },
                            ) {
                                Text("恢复默认")
                            }
                        }
                        dirMessage?.let {
                            Text(
                                it,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.padding(top = 8.dp),
                            )
                        }
                    }
                }
            }

            // ---- MCP ----
            item {
                Text(
                    text = "MCP",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(8.dp)) {
                        ListItem(
                            headlineContent = { Text("工具聚合模式") },
                            supportingContent = {
                                Column {
                                    Text(
                                        if (hubCompact) {
                                            "开启：AI 客户端的工具列表只显示 ${container.toolRegistry.visibleCount()} 个枢纽工具" +
                                                "（如 debugger、network、js），通过 action 参数选择具体动作。上下文占用小、工具选择更准，推荐"
                                        } else {
                                            "关闭：AI 客户端看到全部 ${container.toolRegistry.visibleCount()} 个原始工具" +
                                                "（如 debugger.set_breakpoint），功能与聚合模式完全等价，适合习惯全名直调的客户端"
                                        },
                                    )
                                    Text(
                                        "两种模式下全部 ${container.toolRegistry.count()} 个原始工具均可按全名直调；" +
                                            "MCP 统一使用 HTTP，切换后新一轮 tools/list 请求即可生效",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        modifier = Modifier.padding(top = 4.dp),
                                    )
                                }
                            },
                            leadingContent = {
                                Icon(
                                    Icons.Filled.Bolt,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.primary,
                                )
                            },
                            trailingContent = {
                                Switch(
                                    checked = hubCompact,
                                    onCheckedChange = { enabled ->
                                        hubCompact = enabled
                                        com.webreverse.mcp.settings.ToolModePrefs.setCompact(context, enabled)
                                        container.toolRegistry.hubMode = enabled
                                    },
                                )
                            },
                        )
                    }
                }
            }

            // ---- 权限 ----
            item {
                Text(
                    text = "权限",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(8.dp)) {
                        ListItem(
                            headlineContent = { Text("所有文件管理权限") },
                            supportingContent = {
                                Text(
                                    if (allFilesGranted) "已授予：可读写工作目录" else "未授予：工作目录不可写，文件将保存到应用私有目录",
                                )
                            },
                            leadingContent = {
                                Icon(Icons.Filled.Folder, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                            },
                            trailingContent = {
                                if (!allFilesGranted) {
                                    OutlinedButton(onClick = {
                                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                                            overlayLauncher.launch(
                                                Intent(
                                                    Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                                                    Uri.parse("package:${context.packageName}"),
                                                ),
                                            )
                                        } else {
                                            (context as? MainActivity)?.requestKeepAlivePermissions()
                                        }
                                    }) {
                                        Text("去授权")
                                    }
                                }
                            },
                        )
                        HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                        ListItem(
                            headlineContent = { Text("电池优化白名单") },
                            supportingContent = {
                                Text(
                                    if (batteryIgnored) "已加入白名单：后台不被冻结" else "未加入：后台可能被系统休眠",
                                )
                            },
                            leadingContent = {
                                Icon(Icons.Filled.BatteryStd, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                            },
                            trailingContent = {
                                if (!batteryIgnored) {
                                    OutlinedButton(onClick = {
                                        try {
                                            overlayLauncher.launch(
                                                Intent(
                                                    Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                                                    Uri.parse("package:${context.packageName}"),
                                                ),
                                            )
                                        } catch (e: Exception) {
                                            (context as? MainActivity)?.requestKeepAlivePermissions()
                                        }
                                    }) {
                                        Text("去授权")
                                    }
                                }
                            },
                        )
                        HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                        ListItem(
                            headlineContent = { Text("悬浮窗权限") },
                            supportingContent = {
                                Text(if (overlayGranted) "已授予：悬浮球可显示" else "未授予：悬浮球不可见")
                            },
                            leadingContent = {
                                Icon(Icons.Filled.RocketLaunch, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                            },
                            trailingContent = {
                                if (!overlayGranted) {
                                    OutlinedButton(onClick = {
                                        overlayLauncher.launch(
                                            Intent(
                                                Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                                                Uri.parse("package:${context.packageName}"),
                                            ),
                                        )
                                    }) {
                                        Text("去授权")
                                    }
                                }
                            },
                        )
                        Button(
                            onClick = { (context as? MainActivity)?.requestKeepAlivePermissions() },
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(16.dp),
                        ) {
                            Text("一键申请保活权限")
                        }
                    }
                }
            }

            // ---- 安全 ----
            item {
                Text(
                    text = "安全与隐私",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(8.dp)) {
                        ListItem(
                            headlineContent = { Text("权限模型") },
                            supportingContent = { Text("READ_PAGE / EXECUTE_JS / READ_NETWORK / INSTALL_HOOK 等细粒度权限，默认全部开启，可在权限管理页面按作用域关闭") },
                            leadingContent = {
                                Icon(Icons.Filled.Security, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                            },
                        )
                        HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                        ListItem(
                            headlineContent = { Text("敏感数据脱敏") },
                            supportingContent = {
                                Text(
                                    if (redactionEnabled) {
                                        "已开启：Cookie / Token / Authorization / API Key 输出为 [REDACTED]"
                                    } else {
                                        "默认关闭：输出原始数据，不做脱敏（可在权限管理页面开启）"
                                    },
                                )
                            },
                            leadingContent = {
                                Icon(Icons.Filled.Security, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                            },
                            trailingContent = {
                                Switch(
                                    checked = redactionEnabled,
                                    onCheckedChange = { enabled ->
                                        Redactor.setEnabled(context, enabled)
                                        redactionEnabled = enabled
                                    },
                                )
                            },
                        )
                        ListItem(
                            headlineContent = { Text("MCP 认证") },
                            supportingContent = { Text("API Token + 配对码 + 仅局域网，默认开启") },
                            leadingContent = {
                                Icon(Icons.Filled.Security, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                            },
                        )
                    }
                }
            }

            // ---- 调试 ----
            item {
                Text(
                    text = "调试",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(8.dp)) {
                        ListItem(
                            headlineContent = { Text("WebView 调试（CDP）") },
                            supportingContent = {
                                Text("已开启 setWebContentsDebuggingEnabled，debugger.attach / network.attach_cdp 可用")
                            },
                            leadingContent = {
                                Icon(Icons.Filled.BugReport, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                            },
                        )
                        ListItem(
                            headlineContent = { Text("日志系统") },
                            supportingContent = { Text("App / Browser / MCP / Network / Console / Debugger / Hook / Security / Agent") },
                            leadingContent = {
                                Icon(Icons.Filled.Info, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                            },
                        )
                    }
                }
            }

            // ---- 关于 ----
            item {
                Text(
                    text = "关于",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text("WebReverse MCP", style = MaterialTheme.typography.titleLarge)
                        Text(
                            "v${BuildConfig.VERSION_NAME} · AI 驱动的网页调试与逆向分析工作台",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(top = 4.dp),
                        )
                        Text(
                            "基于 Kotlin / Jetpack Compose / Material 3 / Ktor / WebView 构建。\n" +
                                "让 Claude、GPT、Gemini、Cursor 等 AI Agent 通过 MCP 连接浏览器，\n" +
                                "执行 DOM 分析、JavaScript 分析、网络分析、调试与 Hook。",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(top = 8.dp),
                        )
                    }
                }
            }
        }
    }
}

private val ThemeMode.label: String
    get() = when (this) {
        ThemeMode.SYSTEM -> "系统"
        ThemeMode.LIGHT -> "浅色"
        ThemeMode.DARK -> "深色"
    }

private fun isIgnoringBatteryOptimizations(context: Context): Boolean =
    (context.getSystemService(Context.POWER_SERVICE) as PowerManager)
        .isIgnoringBatteryOptimizations(context.packageName)

private fun hasAllFilesAccess(context: Context): Boolean =
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        Environment.isExternalStorageManager()
    } else {
        ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.WRITE_EXTERNAL_STORAGE,
        ) == PackageManager.PERMISSION_GRANTED
    }
