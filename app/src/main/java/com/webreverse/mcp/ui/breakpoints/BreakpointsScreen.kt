package com.webreverse.mcp.ui.breakpoints

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.webreverse.mcp.core.common.model.Breakpoint
import com.webreverse.mcp.core.common.model.BreakpointType
import com.webreverse.mcp.di.AppContainer
import kotlinx.coroutines.launch

/**
 * 断点管理页面：管理所有类型的断点（Line / Function / DOM / Event / XHR / Exception 等）。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BreakpointsScreen(
    container: AppContainer,
    onBack: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    val breakpoints by container.debuggerManager.breakpoints.collectAsState()
    val watches by container.debuggerManager.watchExpressions.collectAsState()
    var showAddDialog by remember { mutableStateOf(false) }
    var selectedType by remember { mutableStateOf<BreakpointType?>(null) }

    val filtered = remember(selectedType, breakpoints) {
        if (selectedType == null) breakpoints else breakpoints.filter { it.type == selectedType }
    }

    val types = BreakpointType.entries

    Scaffold(
        // 底部沉浸：手机端底部 inset 由根 AppBottomBar 消费，避免内容上方空白带
        contentWindowInsets = com.webreverse.mcp.ui.navigation.pageScaffoldInsets(),
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("断点管理")
                        Text(
                            "${breakpoints.size} 个断点 · ${watches.size} 个 Watch",
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
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = { showAddDialog = true }) {
                Icon(Icons.Filled.Add, contentDescription = "新建断点")
            }
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            // 类型筛选
            androidx.compose.foundation.layout.Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 8.dp),
            ) {
                androidx.compose.foundation.lazy.LazyRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    item {
                        FilterChip(
                            selected = selectedType == null,
                            onClick = { selectedType = null },
                            label = { Text("全部") },
                        )
                    }
                    items(types) { type ->
                        FilterChip(
                            selected = selectedType == type,
                            onClick = { selectedType = type },
                            label = { Text(type.display) },
                        )
                    }
                }
            }

            if (filtered.isEmpty() && watches.isEmpty()) {
                androidx.compose.foundation.layout.Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = androidx.compose.ui.Alignment.Center,
                ) {
                    Column(horizontalAlignment = androidx.compose.ui.Alignment.CenterHorizontally) {
                        Icon(
                            Icons.Filled.BugReport,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(bottom = 8.dp),
                        )
                        Text(
                            "暂无断点",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            } else {
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    if (filtered.isNotEmpty()) {
                        item {
                            Text(
                                "断点 (${filtered.size})",
                                style = MaterialTheme.typography.titleSmall,
                                color = MaterialTheme.colorScheme.primary,
                            )
                        }
                        items(filtered, key = { it.id }) { bp ->
                            BreakpointCard(
                                breakpoint = bp,
                                onToggle = { enabled ->
                                    // 通过设置 enabled 状态
                                },
                                onDelete = {
                                    scope.launch {
                                        val engine = container.browserService.getEngine(null)
                                        if (engine != null) {
                                            container.debuggerManager.removeBreakpoint(engine, bp.id)
                                        }
                                    }
                                },
                            )
                        }
                    }

                    if (watches.isNotEmpty()) {
                        item {
                            Text(
                                "Watch 表达式 (${watches.size})",
                                style = MaterialTheme.typography.titleSmall,
                                color = MaterialTheme.colorScheme.secondary,
                                modifier = Modifier.padding(top = 8.dp),
                            )
                        }
                        items(watches, key = { it.id }) { watch ->
                            WatchCard(
                                expression = watch.expression,
                                onDelete = {
                                    scope.launch { container.debuggerManager.removeWatch(watch.id) }
                                },
                            )
                        }
                    }
                }
            }
        }
    }

    if (showAddDialog) {
        AddBreakpointDialog(
            onDismiss = { showAddDialog = false },
            onAdd = { type, url, line, condition, target, logExpr ->
                scope.launch {
                    val engine = container.browserService.getEngine(null)
                    if (engine != null) {
                        if (type == BreakpointType.FUNCTION && target != null) {
                            container.debuggerManager.setFunctionBreakpoint(engine, target, condition)
                        } else if (type == BreakpointType.LOGPOINT && logExpr != null) {
                            container.debuggerManager.setLogpoint(engine, url, line, logExpr)
                        } else {
                            container.debuggerManager.setBreakpoint(
                                engine = engine,
                                type = type,
                                url = url,
                                lineNumber = line,
                                condition = condition,
                                logExpression = logExpr,
                                target = target,
                            )
                        }
                        showAddDialog = false
                    }
                }
            },
        )
    }
}

@Composable
private fun BreakpointCard(
    breakpoint: Breakpoint,
    onToggle: (Boolean) -> Unit,
    onDelete: () -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer,
        ),
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
            ) {
                Icon(
                    Icons.Filled.BugReport,
                    contentDescription = null,
                    tint = if (breakpoint.enabled) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(end = 8.dp),
                )
                Text(
                    text = breakpoint.type.display,
                    style = MaterialTheme.typography.titleSmall,
                    modifier = Modifier.weight(1f),
                )
                Switch(checked = breakpoint.enabled, onCheckedChange = onToggle)
            }
            if (breakpoint.url.isNotBlank()) {
                Text(
                    text = breakpoint.url,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    modifier = Modifier.padding(top = 4.dp),
                )
            }
            if (breakpoint.lineNumber > 0) {
                Text(
                    text = "行 ${breakpoint.lineNumber}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.secondary,
                )
            }
            if (breakpoint.target != null) {
                Text(
                    text = "目标: ${breakpoint.target}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.secondary,
                )
            }
            if (breakpoint.condition != null) {
                Text(
                    text = "条件: ${breakpoint.condition}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.tertiary,
                )
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
            ) {
                AssistChip(
                    onClick = {},
                    label = { Text("命中: ${breakpoint.hitCount}") },
                )
                IconButton(onClick = onDelete) {
                    Icon(Icons.Filled.Delete, contentDescription = "删除")
                }
            }
        }
    }
}

@Composable
private fun WatchCard(
    expression: String,
    onDelete: () -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.secondaryContainer,
        ),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
        ) {
            Icon(
                Icons.Filled.Visibility,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSecondaryContainer,
                modifier = Modifier.padding(end = 8.dp),
            )
            Text(
                text = expression,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSecondaryContainer,
                modifier = Modifier.weight(1f),
            )
            IconButton(onClick = onDelete) {
                Icon(Icons.Filled.Delete, contentDescription = "删除")
            }
        }
    }
}

@Composable
private fun AddBreakpointDialog(
    onDismiss: () -> Unit,
    onAdd: (type: BreakpointType, url: String, line: Int, condition: String?, target: String?, logExpr: String?) -> Unit,
) {
    var typeIndex by remember { mutableStateOf(0) }
    var url by remember { mutableStateOf("") }
    var line by remember { mutableStateOf("") }
    var condition by remember { mutableStateOf("") }
    var target by remember { mutableStateOf("") }
    var logExpr by remember { mutableStateOf("") }

    val types = BreakpointType.entries.toList()

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("新建断点") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("断点类型", style = MaterialTheme.typography.bodySmall)
                androidx.compose.foundation.layout.Box(modifier = Modifier.fillMaxWidth()) {
                    androidx.compose.foundation.lazy.LazyRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        items(types) { t ->
                            FilterChip(
                                selected = types[typeIndex] == t,
                                onClick = { typeIndex = types.indexOf(t) },
                                label = { Text(t.display) },
                            )
                        }
                    }
                }
                when (types[typeIndex]) {
                    BreakpointType.FUNCTION -> {
                        OutlinedTextField(
                            value = target,
                            onValueChange = { target = it },
                            label = { Text("函数名") },
                            singleLine = true,
                            placeholder = { Text("例如: window.login") },
                        )
                    }
                    BreakpointType.LOGPOINT -> {
                        OutlinedTextField(
                            value = logExpr,
                            onValueChange = { logExpr = it },
                            label = { Text("日志表达式") },
                            singleLine = true,
                            placeholder = { Text("例如: 'User: ' + user.name") },
                        )
                    }
                    else -> {
                        OutlinedTextField(
                            value = url,
                            onValueChange = { url = it },
                            label = { Text("URL") },
                            singleLine = true,
                        )
                        OutlinedTextField(
                            value = line,
                            onValueChange = { line = it.filter { c -> c.isDigit() } },
                            label = { Text("行号") },
                            singleLine = true,
                        )
                    }
                }
                OutlinedTextField(
                    value = condition,
                    onValueChange = { condition = it },
                    label = { Text("条件（可选）") },
                    singleLine = true,
                    placeholder = { Text("例如: x > 10") },
                )
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    onAdd(
                        types[typeIndex],
                        url.trim(),
                        line.toIntOrNull() ?: 0,
                        condition.ifBlank { null },
                        target.ifBlank { null },
                        logExpr.ifBlank { null },
                    )
                },
            ) { Text("创建") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("取消") }
        },
    )
}
