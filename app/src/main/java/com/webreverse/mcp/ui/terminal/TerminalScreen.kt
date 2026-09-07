package com.webreverse.mcp.ui.terminal

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.ime
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.union
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Archive
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.CloudDownload
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Extension
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.HourglassEmpty
import androidx.compose.material.icons.filled.Input
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Send
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.webreverse.mcp.di.AppContainer
import com.webreverse.mcp.mcp.tools.terminal.HostToolsManager
import com.webreverse.mcp.mcp.tools.terminal.HostToolsState
import com.webreverse.mcp.mcp.tools.terminal.TerminalSession
import kotlinx.coroutines.launch

/**
 * 终端页面。
 *
 * 内置真实终端（交互式 shell），并集成 Host Tools / NDK 管理：
 * - 终端 Tab：常驻 shell 会话，命令写入 stdin、输出流式返回，支持 cd 等状态保持
 * - Host Tools Tab：从 Termux 源安装 git/python/perl 及额外工具包
 * - NDK Tab：下载安装 Android NDK（aarch64 定制版），pip 编译 C 扩展用
 * - 文件管理 Tab
 *
 * AI 通过 MCP 工具（terminal.exec / terminal.run_python / terminal.install / terminal.ndk）
 * 也能在设备上安装和使用工具、测试 Python 代码、修复 bug、编译 Python C 扩展。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TerminalScreen(container: AppContainer) {
    var selectedTab by remember { mutableIntStateOf(0) }

    Scaffold(
        // edge-to-edge 下 adjustResize 不再生效，显式合并 IME inset，
        // 保证终端输入行/命令输入框不被软键盘遮挡
        // 底部沉浸：手机端底部 inset 由根 AppBottomBar 消费；键盘避让保留
        contentWindowInsets = com.webreverse.mcp.ui.navigation.pageScaffoldInsets().union(WindowInsets.ime),
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("终端")
                        Text(
                            "内置 Shell · Tools · NDK · 文件管理",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            TabRow(selectedTabIndex = selectedTab) {
                Tab(
                    selected = selectedTab == 0,
                    onClick = { selectedTab = 0 },
                    text = {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                Icons.Filled.Terminal,
                                contentDescription = null,
                                modifier = Modifier.size(16.dp),
                            )
                            Spacer(Modifier.width(4.dp))
                            Text("终端")
                        }
                    },
                )
                Tab(
                    selected = selectedTab == 1,
                    onClick = { selectedTab = 1 },
                    text = {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                Icons.Filled.Extension,
                                contentDescription = null,
                                modifier = Modifier.size(16.dp),
                            )
                            Spacer(Modifier.width(4.dp))
                            Text("Tools")
                        }
                    },
                )
                Tab(
                    selected = selectedTab == 2,
                    onClick = { selectedTab = 2 },
                    text = {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                Icons.Filled.Build,
                                contentDescription = null,
                                modifier = Modifier.size(16.dp),
                            )
                            Spacer(Modifier.width(4.dp))
                            Text("NDK")
                        }
                    },
                )
                Tab(
                    selected = selectedTab == 3,
                    onClick = { selectedTab = 3 },
                    text = {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                Icons.Filled.Folder,
                                contentDescription = null,
                                modifier = Modifier.size(16.dp),
                            )
                            Spacer(Modifier.width(4.dp))
                            Text("文件管理")
                        }
                    },
                )
            }
            when (selectedTab) {
                0 -> TerminalView(container)
                1 -> HostToolsView(container)
                2 -> NdkView(container)
                3 -> FileManagerView()
            }
        }
    }
}

// ==================== 终端 Tab ====================

@Composable
private fun TerminalView(container: AppContainer) {
    // 会话键：手动终止后可自增键值重建会话（修复"结束后无法重新开启"的问题）
    var sessionKey by remember { mutableIntStateOf(0) }
    val session = remember(sessionKey) { container.terminalEngine.createSession() }
    val outputLines by session.outputLines.collectAsState()
    val running by session.running.collectAsState()
    val stdinOpen by session.stdinOpen.collectAsState()
    val cwd by session.cwd.collectAsState()
    val lastLineComplete by session.lastLineComplete.collectAsState()
    // 标记模式状态：shellReady=命令已结束等待下一条；awaitingMore=需续行
    val shellReady by session.shellReady.collectAsState()
    val awaitingMore by session.awaitingMore.collectAsState()

    // ===== 终端式控制台状态（借鉴 NdkCompiler RunScreen）=====
    // lockedText: 程序输出 + 已回显的输入（只读部分），从 outputLines 构建
    val lockedText = remember(outputLines) {
        buildString {
            outputLines.forEachIndexed { index, line ->
                if (index > 0) append("\n")
                append(line.text)
            }
        }
    }

    // inputBuffer: 用户正在输入但尚未发送的内容
    var inputBuffer by remember { mutableStateOf("") }

    // sentLine: 已发送但尚未被 lockedText 回显确认的行（防止闪烁）
    var sentLine by remember { mutableStateOf<String?>(null) }

    // consoleValue: BasicTextField 的值（TextFieldValue，支持光标管理）
    var consoleValue by remember { mutableStateOf(TextFieldValue("")) }

    val consoleScrollState = rememberScrollState()
    val consoleFocusRequester = remember { FocusRequester() }

    // 会话销毁时终止进程
    DisposableEffect(session) {
        onDispose { session.kill() }
    }

    // 提示符前缀（只读）。
    // 标记模式：命令完成由注入的 echo 标记驱动（见 TerminalEngine）。
    // - shellReady=true：命令执行完毕，就绪等待下一条 → 显示 ~ $ / /path $；
    // - awaitingMore=true：命令未闭合（引号/括号/管道）等待续行 → 显示 > ；
    // - 两者皆 false：命令执行中（网络请求/长任务/交互程序）→ 不显示提示符。
    // 兼容模式（非标记）回退 lastLineComplete。
    val promptVisible = stdinOpen &&
        (if (session.markerMode) (shellReady || awaitingMore) else lastLineComplete)

    // 提示符文本：续行（PS2）显示 "> "，就绪显示 ~ $ / /path $
    val prompt = when {
        !promptVisible -> ""
        awaitingMore -> "> "
        else -> {
            val display = if (cwd == com.webreverse.mcp.mcp.tools.terminal.TerminalPaths.homeDir.absolutePath) "~" else cwd
            "$display \$ "
        }
    }

    // 提示符前是否需要换行：lockedText 非空 且 最后一行完整（程序输出以 \n 结束）
    // 解决 "hello~ $" 问题：程序输出 hello\n 后，提示符应另起一行
    val promptPrefix = if (lockedText.isNotEmpty() && promptVisible) "\n" else ""

    // 程序输出更新时，重建 consoleValue 并将光标定位到文本末尾
    // （依赖 shellReady/awaitingMore：标记模式下命令结束/需续行时提示符即时刷新）
    LaunchedEffect(lockedText, stdinOpen, prompt, promptVisible, awaitingMore) {
        // 如果有已发送的行，且 lockedText 已更新（包含回显），则清空 inputBuffer
        if (sentLine != null) {
            inputBuffer = ""
            sentLine = null
        }
        val newText = lockedText + promptPrefix + prompt + inputBuffer
        // 光标定位到文本末尾 —— 每次程序输出新内容（如 printf 提示），光标自动跳到末尾
        consoleValue = TextFieldValue(
            text = newText,
            selection = TextRange(newText.length),
        )
    }

    // 自动滚动到底部
    LaunchedEffect(consoleValue.text) {
        if (consoleScrollState.maxValue > 0) {
            consoleScrollState.animateScrollTo(consoleScrollState.maxValue)
        }
    }

    // stdin 开放时自动聚焦控制台（弹出键盘）；关闭时清空未发送输入
    LaunchedEffect(stdinOpen) {
        if (stdinOpen) {
            kotlinx.coroutines.delay(200)
            // 防御性保护：BasicTextField 始终渲染，FocusRequester 始终挂载；
            // 极端情况下 requestFocus 仍可能抛异常，捕获避免崩溃
            runCatching { consoleFocusRequester.requestFocus() }
        } else {
            inputBuffer = ""
            sentLine = null
        }
    }

    // 会话结束时清空输入缓冲
    LaunchedEffect(running) {
        if (!running) {
            inputBuffer = ""
            sentLine = null
        }
    }

    /**
     * 处理控制台文本变化（用户输入）。
     *
     * - 仅允许在 lockedText + 提示符之后编辑（锁定程序输出与提示符部分）
     * - 检测回车（\n）时，提取一行发送到 stdin
     * - 发送后保留显示，直到 TerminalSession 回显更新 lockedText
     */
    fun onConsoleChange(newValue: TextFieldValue) {
        if (!stdinOpen) return

        val lockedRegion = lockedText + promptPrefix + prompt
        val lockEnd = lockedRegion.length

        // 阻止修改锁定区域（程序输出 + 提示符部分）
        if (newValue.text.length < lockEnd ||
            newValue.text.substring(0, lockEnd) != lockedRegion
        ) {
            // 用户试图修改锁定区域，回退到合法状态（光标保持在末尾）
            val reverted = lockedRegion + inputBuffer
            consoleValue = TextFieldValue(
                text = reverted,
                selection = TextRange(reverted.length),
            )
            return
        }

        // 提取用户在锁定区域之后输入的文本
        val typed = if (newValue.text.length > lockEnd)
            newValue.text.substring(lockEnd) else ""

        // 检测回车键（\n）
        val nlIdx = typed.indexOf('\n')
        if (nlIdx >= 0) {
            val line = typed.substring(0, nlIdx)
            // 发送到 stdin（TerminalSession 会回显带提示符的行，更新 lockedText）
            session.sendInput(line)
            // 保留已输入内容显示，等 lockedText 更新后再清除（防止闪烁）
            sentLine = line
            inputBuffer = line
            val newText = lockedRegion + line
            consoleValue = TextFieldValue(
                text = newText,
                selection = TextRange(newText.length),
            )
        } else {
            inputBuffer = typed
            // 保留用户的光标位置
            consoleValue = newValue
        }
    }

    Column(modifier = Modifier.fillMaxSize()) {
        // 终端式控制台（单个 BasicTextField：程序输出 + 用户输入在同一区域）
        Box(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .background(Color(0xFF0D1117)),
        ) {
            // BasicTextField 始终渲染：保证 FocusRequester 始终挂载到节点，
            // 避免空状态时 requestFocus 崩溃（FocusRequester is not initialized）
            BasicTextField(
                value = consoleValue,
                onValueChange = ::onConsoleChange,
                modifier = Modifier
                    .fillMaxSize()
                    .padding(12.dp)
                    .verticalScroll(consoleScrollState)
                    .focusRequester(consoleFocusRequester),
                readOnly = !stdinOpen,
                textStyle = TextStyle(
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp,
                    color = Color(0xFFE6EDF3),
                    lineHeight = 16.sp,
                ),
                cursorBrush = SolidColor(Color(0xFFE6EDF3)),
                keyboardOptions = KeyboardOptions(
                    capitalization = KeyboardCapitalization.None,
                    autoCorrect = false,
                ),
            )
            // 空状态占位提示（覆盖层，不拦截点击，不影响 FocusRequester 挂载）
            if (outputLines.isEmpty() && inputBuffer.isEmpty()) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(12.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        "在提示符后输入命令并按回车执行\n" +
                            "如: python3 -c 'print(1+1)'\n" +
                            "如: cd /sdcard && ls -la\n\n" +
                            "提示: 若 python3/git 不可用，请到「Host Tools」Tab 安装",
                        color = Color(0xFF888888),
                        fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp,
                        lineHeight = 16.sp,
                        textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                    )
                }
            }
        }

        // 工具栏
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 8.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                modifier = Modifier
                    .size(8.dp)
                    .background(
                        if (running) Color(0xFF43A047) else Color(0xFFE53935),
                        androidx.compose.foundation.shape.CircleShape,
                    ),
            )
            Spacer(Modifier.width(6.dp))
            Text(
                when {
                    !running -> "会话已结束"
                    stdinOpen -> "运行中 · 等待输入"
                    else -> "运行中"
                },
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.weight(1f))

            // 结束输入（EOF）
            if (running && stdinOpen) {
                IconButton(onClick = { session.closeStdin() }) {
                    Icon(Icons.Filled.Input, contentDescription = "结束输入(EOF)")
                }
            }
            // 清空
            IconButton(onClick = { session.clear() }) {
                Icon(Icons.Filled.DeleteSweep, contentDescription = "清空")
            }
            // 终止 / 重启
            if (running) {
                IconButton(onClick = { session.kill() }) {
                    Icon(Icons.Filled.Stop, contentDescription = "终止")
                }
            } else {
                IconButton(
                    onClick = {
                        inputBuffer = ""
                        sentLine = null
                        sessionKey++
                    },
                ) {
                    Icon(Icons.Filled.Refresh, contentDescription = "重启会话")
                }
            }
        }

        // 状态条
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                "HOME: ${com.webreverse.mcp.mcp.tools.terminal.TerminalPaths.homeDir.absolutePath}",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

// ==================== Host Tools Tab ====================

@Composable
private fun HostToolsView(container: AppContainer) {
    val scope = rememberCoroutineScope()
    val hostToolsState by container.hostToolsManager.state.collectAsState()
    val lastRepoBase by container.hostToolsManager.lastRepoBase.collectAsState()

    var showUninstallDialog by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        // 状态卡片
        HostToolsStatusCard(hostToolsState)

        // 工具信息
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.2f),
            ),
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Text("默认安装的工具", style = MaterialTheme.typography.titleSmall)
                InfoRow("来源", container.hostToolsManager.repoBaseLabel(lastRepoBase))
                InfoRow("git", "版本控制 (.deb)")
                InfoRow("perl", "git submodule 依赖 (.deb)")
                InfoRow("python", "Python 解释器 (.deb)")
                InfoRow("python-pip", "pip 包管理器 (.deb)")
            }
        }

        // 额外工具包管理（仅在已安装时显示）
        val installedState = hostToolsState
        if (installedState is HostToolsState.Installed) {
            AdditionalPackagesSection(container, installedState)
        }

        // 操作按钮
        when (hostToolsState) {
            is HostToolsState.NotInstalled, is HostToolsState.Failed -> {
                Button(
                    onClick = {
                        scope.launch {
                            container.hostToolsDownloader.downloadAndExtract()
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Icon(Icons.Filled.Download, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text("下载并安装 Host Tools")
                }
            }
            is HostToolsState.Downloading,
            is HostToolsState.Extracting,
            is HostToolsState.Configuring -> {
                Button(
                    onClick = {},
                    enabled = false,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Icon(Icons.Filled.HourglassEmpty, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text("处理中，请稍候...")
                }
            }
            is HostToolsState.Installed -> {
                OutlinedButton(
                    onClick = { showUninstallDialog = true },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Icon(Icons.Filled.Delete, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text("卸载 Host Tools")
                }
            }
        }

        // 使用说明
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.2f),
            ),
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Text("使用说明", style = MaterialTheme.typography.titleSmall)
                Text("1. 安装后终端内可直接使用 git / python3 / pip", style = MaterialTheme.typography.bodySmall)
                Text("2. AI 可用 terminal.exec / terminal.run_python 测试代码、修复 bug", style = MaterialTheme.typography.bodySmall)
                Text("3. 用 terminal.pip_install 安装 Python 库", style = MaterialTheme.typography.bodySmall)
                Text("4. 如需其他工具（make/cmake/nodejs 等），用「额外工具包」按需安装", style = MaterialTheme.typography.bodySmall)
                Text("5. 工具安装在应用私有目录，卸载 App 后自动清除", style = MaterialTheme.typography.bodySmall)
            }
        }
    }

    if (showUninstallDialog) {
        androidx.compose.material3.AlertDialog(
            onDismissRequest = { showUninstallDialog = false },
            title = { Text("卸载 Host Tools") },
            text = { Text("确定要卸载 Host Tools 吗？git/python/perl 及已安装的额外工具包都会被清除。") },
            confirmButton = {
                TextButton(
                    onClick = {
                        scope.launch {
                            container.hostToolsManager.uninstall()
                            showUninstallDialog = false
                        }
                    },
                ) {
                    Text("卸载", color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = { showUninstallDialog = false }) { Text("取消") }
            },
        )
    }
}

@Composable
private fun HostToolsStatusCard(state: HostToolsState) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = when (state) {
                is HostToolsState.Installed -> MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.3f)
                is HostToolsState.Failed -> MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.3f)
                else -> MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f)
            },
        ),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                val (icon, color) = when (state) {
                    is HostToolsState.Installed -> Icons.Filled.CheckCircle to MaterialTheme.colorScheme.primary
                    is HostToolsState.Downloading -> Icons.Filled.Download to MaterialTheme.colorScheme.tertiary
                    is HostToolsState.Extracting -> Icons.Filled.Archive to MaterialTheme.colorScheme.tertiary
                    is HostToolsState.Configuring -> Icons.Filled.Build to MaterialTheme.colorScheme.tertiary
                    is HostToolsState.Failed -> Icons.Filled.Error to MaterialTheme.colorScheme.error
                    HostToolsState.NotInstalled -> Icons.Filled.CloudDownload to MaterialTheme.colorScheme.onSurfaceVariant
                }
                Icon(icon, contentDescription = null, tint = color, modifier = Modifier.size(28.dp))
                Spacer(Modifier.width(12.dp))
                Text(
                    text = when (state) {
                        is HostToolsState.Installed -> "Host Tools 已安装"
                        is HostToolsState.Downloading -> "下载中..."
                        is HostToolsState.Extracting -> "解压中..."
                        is HostToolsState.Configuring -> "配置中..."
                        is HostToolsState.Failed -> "安装失败"
                        HostToolsState.NotInstalled -> "Host Tools 未安装"
                    },
                    style = MaterialTheme.typography.titleMedium,
                )
            }

            when (val s = state) {
                is HostToolsState.Installed -> {
                    Text(
                        "安装路径: ${s.prefixDir.absolutePath}",
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                    )
                    s.gitPath?.let {
                        Text(
                            "git: ${it.absolutePath}",
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                    s.pythonPath?.let {
                        Text(
                            "python: ${it.absolutePath}",
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                    s.perlPath?.let {
                        Text(
                            "perl: ${it.absolutePath}",
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                    Text(
                        "架构: ${s.arch}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                is HostToolsState.Downloading -> {
                    Text(s.message, style = MaterialTheme.typography.bodySmall, maxLines = 2, overflow = TextOverflow.Ellipsis)
                    LinearProgressIndicator(
                        progress = { s.progress / 100f },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Text("${s.progress}%", style = MaterialTheme.typography.bodySmall)
                }
                is HostToolsState.Extracting -> {
                    Text(s.message, style = MaterialTheme.typography.bodySmall, maxLines = 2, overflow = TextOverflow.Ellipsis)
                    LinearProgressIndicator(
                        progress = { s.progress / 100f },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Text("${s.progress}%", style = MaterialTheme.typography.bodySmall)
                }
                is HostToolsState.Configuring -> {
                    Text(s.message, style = MaterialTheme.typography.bodySmall, maxLines = 2, overflow = TextOverflow.Ellipsis)
                    LinearProgressIndicator(
                        progress = { s.progress / 100f },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Text("${s.progress}%", style = MaterialTheme.typography.bodySmall)
                }
                is HostToolsState.Failed -> {
                    Text(
                        "错误: ${s.message}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
                HostToolsState.NotInstalled -> {
                    Text(
                        "需要安装 Host Tools 以启用 git / python3 / pip 等工具。",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun AdditionalPackagesSection(
    container: AppContainer,
    installedState: HostToolsState.Installed,
) {
    val scope = rememberCoroutineScope()
    val hostToolsState by container.hostToolsManager.state.collectAsState()
    var customPackageName by remember { mutableStateOf("") }

    val isProcessing = hostToolsState.let {
        it is HostToolsState.Downloading || it is HostToolsState.Extracting || it is HostToolsState.Configuring
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.2f),
        ),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    Icons.Filled.Extension,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(20.dp),
                )
                Spacer(Modifier.width(8.dp))
                Text("额外工具包", style = MaterialTheme.typography.titleSmall)
            }

            Text(
                "构建/分析不同项目时可能需要额外工具。点击下方按钮快速安装，或在输入框中输入 Termux 包名手动安装。",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            Text("常用工具", style = MaterialTheme.typography.labelMedium)
            FlowRow(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                for (pkg in HostToolsManager.RECOMMENDED_PACKAGES) {
                    val isAlreadyInstalled = pkg in installedState.additionalPackages
                    AssistChip(
                        onClick = {
                            if (!isProcessing) {
                                scope.launch {
                                    container.hostToolsDownloader.installAdditionalPackages(listOf(pkg))
                                }
                            }
                        },
                        label = { Text(pkg, style = MaterialTheme.typography.labelSmall) },
                        leadingIcon = {
                            Icon(
                                if (isAlreadyInstalled) Icons.Filled.Check else Icons.Filled.Add,
                                contentDescription = null,
                                modifier = Modifier.size(16.dp),
                            )
                        },
                        enabled = !isProcessing && !isAlreadyInstalled,
                    )
                }
            }

            HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
            Text("自定义包名", style = MaterialTheme.typography.labelMedium)
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedTextField(
                    value = customPackageName,
                    onValueChange = { customPackageName = it.trim() },
                    label = { Text("Termux 包名") },
                    placeholder = { Text("如: cmake, nodejs...") },
                    modifier = Modifier.weight(1f),
                    singleLine = true,
                    enabled = !isProcessing,
                )
                Button(
                    onClick = {
                        if (customPackageName.isNotBlank()) {
                            scope.launch {
                                container.hostToolsDownloader.installAdditionalPackages(listOf(customPackageName))
                            }
                            customPackageName = ""
                        }
                    },
                    enabled = !isProcessing && customPackageName.isNotBlank(),
                ) {
                    Icon(Icons.Filled.Download, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("安装")
                }
            }

            if (installedState.additionalPackages.isNotEmpty()) {
                HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                Text("已安装的额外包", style = MaterialTheme.typography.labelMedium)
                installedState.additionalPackages.forEach { pkg ->
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Icon(
                            Icons.Filled.CheckCircle,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(16.dp),
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(pkg, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                    }
                }
            }
        }
    }
}

@Composable
private fun InfoRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(
            label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            value,
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

// ==================== NDK Tab（终端内置 NDK，pip 编译 C 扩展用） ====================

@Composable
private fun NdkView(container: AppContainer) {
    val scope = rememberCoroutineScope()
    val ndkState by container.ndkManager.state.collectAsState()
    val installLogs by container.ndkDownloader.installLogs.collectAsState()

    var showUninstallDialog by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        // 状态卡片
        NdkStatusCard(ndkState)

        // 版本信息（精简卡片，仅保留版本与架构，下载链接不再展示）
        val version = container.ndkManager.availableVersions.firstOrNull()
        if (version != null) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.2f),
                ),
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Text("NDK 信息", style = MaterialTheme.typography.titleSmall)
                    InfoRow("版本", version.displayName)
                    InfoRow("架构", "aarch64 (Android 设备本地运行)")
                }
            }
        }

        // 操作按钮
        when (ndkState) {
            is com.webreverse.mcp.mcp.tools.terminal.NdkState.NotInstalled,
            is com.webreverse.mcp.mcp.tools.terminal.NdkState.Failed -> {
                Button(
                    onClick = {
                        scope.launch {
                            container.ndkDownloader.downloadAndExtract(
                                container.ndkManager.availableVersions.first(),
                            )
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Icon(Icons.Filled.Download, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text(if (ndkState is com.webreverse.mcp.mcp.tools.terminal.NdkState.Failed) "重试下载并安装 NDK" else "下载并安装 NDK")
                }
            }
            is com.webreverse.mcp.mcp.tools.terminal.NdkState.Downloading,
            is com.webreverse.mcp.mcp.tools.terminal.NdkState.Extracting,
            is com.webreverse.mcp.mcp.tools.terminal.NdkState.Configuring -> {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = {},
                        enabled = false,
                        modifier = Modifier.weight(1f),
                    ) {
                        Icon(Icons.Filled.HourglassEmpty, contentDescription = null)
                        Spacer(Modifier.width(8.dp))
                        Text("处理中，请稍候...")
                    }
                    OutlinedButton(
                        onClick = { container.ndkDownloader.cancel() },
                    ) {
                        Text("取消")
                    }
                }
            }
            is com.webreverse.mcp.mcp.tools.terminal.NdkState.Installed -> {
                OutlinedButton(
                    onClick = { showUninstallDialog = true },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Icon(Icons.Filled.Delete, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text("卸载 NDK")
                }
            }
        }

        // 使用说明
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.2f),
            ),
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Text("使用说明", style = MaterialTheme.typography.titleSmall)
                Text("1. 先在「Host Tools」Tab 安装 python / python-pip", style = MaterialTheme.typography.bodySmall)
                Text("2. 安装 NDK 后，终端自动注入 clang 编译工具链（CC/CXX/AR 等）", style = MaterialTheme.typography.bodySmall)
                Text("3. 终端内直接 pip install pycryptodome 等带 C 扩展的库，会自动用 NDK 编译", style = MaterialTheme.typography.bodySmall)
                Text("4. 验证: python3 -c \"from Crypto.Cipher import AES; print('ok')\"", style = MaterialTheme.typography.bodySmall)
                Text("5. 编译目标: aarch64-linux-android24（对齐 Termux python）", style = MaterialTheme.typography.bodySmall)
                Text("6. NDK 安装在应用私有目录，卸载 App 后自动清除", style = MaterialTheme.typography.bodySmall)
            }
        }

        // 安装日志（最近 50 条）
        if (installLogs.isNotEmpty()) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = Color(0xFF0D1117),
                ),
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text(
                        "安装日志（最近 ${minOf(installLogs.size, 50)} 条）",
                        style = MaterialTheme.typography.labelMedium,
                        color = Color(0xFFE6EDF3),
                    )
                    Spacer(Modifier.height(8.dp))
                    installLogs.takeLast(50).forEach { log ->
                        Text(
                            log,
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 10.sp,
                            lineHeight = 13.sp,
                            color = Color(0xFF8B949E),
                        )
                    }
                }
            }
        }
    }

    if (showUninstallDialog) {
        androidx.compose.material3.AlertDialog(
            onDismissRequest = { showUninstallDialog = false },
            title = { Text("卸载 NDK") },
            text = { Text("确定要卸载 NDK 吗？所有版本与 pip 编译工具链都会被清除。") },
            confirmButton = {
                TextButton(
                    onClick = {
                        scope.launch {
                            container.ndkManager.uninstall()
                            showUninstallDialog = false
                        }
                    },
                ) {
                    Text("卸载", color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = { showUninstallDialog = false }) { Text("取消") }
            },
        )
    }
}

@Composable
private fun NdkStatusCard(state: com.webreverse.mcp.mcp.tools.terminal.NdkState) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = when (state) {
                is com.webreverse.mcp.mcp.tools.terminal.NdkState.Installed ->
                    MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.3f)
                is com.webreverse.mcp.mcp.tools.terminal.NdkState.Failed ->
                    MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.3f)
                else -> MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f)
            },
        ),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                val (icon, color) = when (state) {
                    is com.webreverse.mcp.mcp.tools.terminal.NdkState.Installed ->
                        Icons.Filled.CheckCircle to MaterialTheme.colorScheme.primary
                    is com.webreverse.mcp.mcp.tools.terminal.NdkState.Downloading ->
                        Icons.Filled.Download to MaterialTheme.colorScheme.tertiary
                    is com.webreverse.mcp.mcp.tools.terminal.NdkState.Extracting ->
                        Icons.Filled.Archive to MaterialTheme.colorScheme.tertiary
                    is com.webreverse.mcp.mcp.tools.terminal.NdkState.Configuring ->
                        Icons.Filled.Build to MaterialTheme.colorScheme.tertiary
                    is com.webreverse.mcp.mcp.tools.terminal.NdkState.Failed ->
                        Icons.Filled.Error to MaterialTheme.colorScheme.error
                    com.webreverse.mcp.mcp.tools.terminal.NdkState.NotInstalled ->
                        Icons.Filled.CloudDownload to MaterialTheme.colorScheme.onSurfaceVariant
                }
                Icon(icon, contentDescription = null, tint = color, modifier = Modifier.size(28.dp))
                Spacer(Modifier.width(12.dp))
                Text(
                    text = when (state) {
                        is com.webreverse.mcp.mcp.tools.terminal.NdkState.Installed -> "NDK 已安装"
                        is com.webreverse.mcp.mcp.tools.terminal.NdkState.Downloading -> "下载中..."
                        is com.webreverse.mcp.mcp.tools.terminal.NdkState.Extracting -> "解压中..."
                        is com.webreverse.mcp.mcp.tools.terminal.NdkState.Configuring -> "配置中..."
                        is com.webreverse.mcp.mcp.tools.terminal.NdkState.Failed -> "安装失败"
                        com.webreverse.mcp.mcp.tools.terminal.NdkState.NotInstalled -> "NDK 未安装"
                    },
                    style = MaterialTheme.typography.titleMedium,
                )
            }

            when (val s = state) {
                is com.webreverse.mcp.mcp.tools.terminal.NdkState.Installed -> {
                    Text(
                        "版本: ${s.version}",
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                    )
                    Text(
                        "安装路径: ${s.ndkPath}",
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        "编译器: ${s.binDir}",
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        "架构: ${s.arch} · 终端已注入 CC/CXX/AR 编译环境",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                is com.webreverse.mcp.mcp.tools.terminal.NdkState.Downloading -> {
                    Text(
                        "下载中 (${com.webreverse.mcp.mcp.tools.terminal.TerminalPaths.formatSize(s.receivedBytes)}" +
                            (if (s.totalBytes > 0) " / ${com.webreverse.mcp.mcp.tools.terminal.TerminalPaths.formatSize(s.totalBytes)}" else "") + ")",
                        style = MaterialTheme.typography.bodySmall,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                    )
                    LinearProgressIndicator(
                        progress = { s.progress / 100f },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Text("${s.progress}%", style = MaterialTheme.typography.bodySmall)
                }
                is com.webreverse.mcp.mcp.tools.terminal.NdkState.Extracting -> {
                    Text(s.message.ifEmpty { "解压中..." }, style = MaterialTheme.typography.bodySmall, maxLines = 2, overflow = TextOverflow.Ellipsis)
                    LinearProgressIndicator(
                        progress = { s.progress / 100f },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Text("${s.progress}%", style = MaterialTheme.typography.bodySmall)
                }
                is com.webreverse.mcp.mcp.tools.terminal.NdkState.Configuring -> {
                    Text(s.message.ifEmpty { "配置中..." }, style = MaterialTheme.typography.bodySmall, maxLines = 2, overflow = TextOverflow.Ellipsis)
                    LinearProgressIndicator(
                        progress = { s.progress / 100f },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Text("${s.progress}%", style = MaterialTheme.typography.bodySmall)
                }
                is com.webreverse.mcp.mcp.tools.terminal.NdkState.Failed -> {
                    Text(
                        "错误: ${s.message}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
                com.webreverse.mcp.mcp.tools.terminal.NdkState.NotInstalled -> {
                    Text(
                        "安装 NDK 后，终端 pip 可本地编译带 C 扩展的 Python 库（pycryptodome / cryptography 等）。",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}
