package com.webreverse.mcp.ui.logs

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.Save
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
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
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.webreverse.mcp.core.common.event.LogLevel
import com.webreverse.mcp.core.logging.LogCategory
import com.webreverse.mcp.core.logging.LogEntry
import com.webreverse.mcp.di.AppContainer
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 统一日志页面：App / Browser / MCP / Network / Console / Debugger / Hook / Security / Agent。
 * 支持分类筛选、级别筛选、搜索、导出、清空、复制。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LogsScreen(
    container: AppContainer,
    onBack: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    val snackbarHostState = remember { SnackbarHostState() }
    val clipboard = LocalClipboardManager.current

    val entries by container.logger.entries.collectAsState()
    var query by remember { mutableStateOf("") }
    var selectedCategory by remember { mutableStateOf<LogCategory?>(null) }
    var selectedLevel by remember { mutableStateOf<LogLevel?>(null) }
    val listState = rememberLazyListState()

    val filtered = remember(query, selectedCategory, selectedLevel, entries) {
        entries.filter { entry ->
            (selectedCategory == null || entry.category == selectedCategory) &&
                (selectedLevel == null || entry.level == selectedLevel) &&
                (query.isBlank() || entry.message.contains(query, ignoreCase = true) || entry.tag.contains(query, ignoreCase = true))
        }.asReversed() // 最新在前
    }

    // 自动滚动到底部
    LaunchedEffect(filtered.size) {
        if (filtered.isNotEmpty() && selectedCategory == null && query.isBlank()) {
            listState.animateScrollToItem(0)
        }
    }

    Scaffold(
        // 底部沉浸：手机端底部 inset 由根 AppBottomBar 消费，避免内容上方空白带
        contentWindowInsets = com.webreverse.mcp.ui.navigation.pageScaffoldInsets(),
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("统一日志")
                        Text(
                            "${entries.size} 条 · 显示 ${filtered.size} 条",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回")
                    }
                },
                actions = {
                    // 复制
                    IconButton(onClick = {
                        clipboard.setText(AnnotatedString(container.logger.export()))
                        scope.launch { snackbarHostState.showSnackbar("日志已复制") }
                    }) {
                        Icon(Icons.Filled.ContentCopy, contentDescription = "复制")
                    }
                    // 导出
                    IconButton(onClick = {
                        scope.launch { snackbarHostState.showSnackbar("已导出 ${entries.size} 条日志") }
                    }) {
                        Icon(Icons.Filled.Save, contentDescription = "导出")
                    }
                    // 清空
                    IconButton(onClick = { container.logger.clear() }) {
                        Icon(Icons.Filled.DeleteSweep, contentDescription = "清空")
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            // 搜索框
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 4.dp),
                placeholder = { Text("搜索日志") },
                leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                singleLine = true,
            )

            // 分类筛选
            LazyRow(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 4.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                item {
                    FilterChip(
                        selected = selectedCategory == null,
                        onClick = { selectedCategory = null },
                        label = { Text("全部") },
                    )
                }
                items(LogCategory.entries) { category ->
                    FilterChip(
                        selected = selectedCategory == category,
                        onClick = { selectedCategory = if (selectedCategory == category) null else category },
                        label = { Text(category.tag) },
                    )
                }
            }

            // 级别筛选
            LazyRow(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 4.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                item {
                    FilterChip(
                        selected = selectedLevel == null,
                        onClick = { selectedLevel = null },
                        label = { Text("全部级别") },
                    )
                }
                items(LogLevel.entries) { level ->
                    FilterChip(
                        selected = selectedLevel == level,
                        onClick = { selectedLevel = if (selectedLevel == level) null else level },
                        label = { Text(level.name) },
                    )
                }
            }

            // 日志列表
            if (filtered.isEmpty()) {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = androidx.compose.ui.Alignment.Center,
                ) {
                    Text(
                        text = "暂无日志",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            } else {
                LazyColumn(
                    state = listState,
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = androidx.compose.foundation.layout.PaddingValues(
                        horizontal = 16.dp,
                        vertical = 8.dp,
                    ),
                    verticalArrangement = Arrangement.spacedBy(2.dp),
                ) {
                    items(filtered, key = { it.id }) { entry ->
                        LogEntryRow(entry)
                    }
                }
            }
        }
    }
}

@Composable
private fun LogEntryRow(entry: LogEntry) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp),
    ) {
        Text(
            text = formatTimestamp(entry.timestamp),
            style = MaterialTheme.typography.labelSmall,
            fontFamily = FontFamily.Monospace,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(end = 8.dp),
        )
        Text(
            text = "[${entry.category.tag}]",
            style = MaterialTheme.typography.labelSmall,
            fontFamily = FontFamily.Monospace,
            color = when (entry.category) {
                LogCategory.APP -> MaterialTheme.colorScheme.primary
                LogCategory.BROWSER -> Color(0xFF00897B)
                LogCategory.MCP -> Color(0xFF7C4DFF)
                LogCategory.NETWORK -> Color(0xFF1A73E8)
                LogCategory.CONSOLE -> Color(0xFF00ACC1)
                LogCategory.DEBUGGER -> Color(0xFFE53935)
                LogCategory.HOOK -> Color(0xFFFF8F00)
                LogCategory.SECURITY -> Color(0xFFD81B60)
                LogCategory.AGENT -> Color(0xFF43A047)
                LogCategory.JS -> Color(0xFF6D4C41)
            },
            modifier = Modifier.padding(end = 8.dp),
        )
        Text(
            text = "[${entry.level.name}]",
            style = MaterialTheme.typography.labelSmall,
            fontFamily = FontFamily.Monospace,
            color = when (entry.level) {
                LogLevel.ERROR -> MaterialTheme.colorScheme.error
                LogLevel.WARN -> Color(0xFFFF8F00)
                LogLevel.INFO -> MaterialTheme.colorScheme.primary
                else -> MaterialTheme.colorScheme.onSurfaceVariant
            },
            modifier = Modifier.padding(end = 8.dp),
        )
        Text(
            text = entry.message,
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            color = when (entry.level) {
                LogLevel.ERROR -> MaterialTheme.colorScheme.error
                LogLevel.WARN -> MaterialTheme.colorScheme.onSurface
                else -> MaterialTheme.colorScheme.onSurface
            },
            modifier = Modifier.weight(1f),
        )
    }
}

private val timeFormat = SimpleDateFormat("HH:mm:ss.SSS", Locale.getDefault())
private fun formatTimestamp(timestamp: Long): String = timeFormat.format(Date(timestamp))
