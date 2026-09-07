package com.webreverse.mcp.ui.hooks

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
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.TrackChanges
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
import com.webreverse.mcp.core.common.model.HookAction
import com.webreverse.mcp.core.common.model.HookMatch
import com.webreverse.mcp.core.common.model.HookRule
import com.webreverse.mcp.core.common.model.HookType
import com.webreverse.mcp.di.AppContainer
import kotlinx.coroutines.launch

/**
 * Hook 规则管理页面：管理所有 Hook 规则（Function / Fetch / XHR / WebSocket / Storage 等）。
 * 支持创建、启用/禁用、删除、导入导出。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HooksScreen(
    container: AppContainer,
    onBack: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    val rules by container.hookEngine.rules.collectAsState()
    val events by container.hookEngine.events.collectAsState()
    var showAddDialog by remember { mutableStateOf(false) }
    var selectedType by remember { mutableStateOf<HookType?>(null) }

    val filteredRules = remember(selectedType, rules) {
        if (selectedType == null) rules else rules.filter { it.type == selectedType }
    }

    val types = HookType.entries.take(8) // 显示主要类型

    Scaffold(
        // 底部沉浸：手机端底部 inset 由根 AppBottomBar 消费，避免内容上方空白带
        contentWindowInsets = com.webreverse.mcp.ui.navigation.pageScaffoldInsets(),
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("Hook 规则")
                        Text(
                            "${rules.size} 条规则 · ${events.size} 次触发",
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
                    IconButton(onClick = {
                        scope.launch {
                            container.hookEngine.reset()
                        }
                    }) {
                        Icon(Icons.Filled.Delete, contentDescription = "重置")
                    }
                },
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = { showAddDialog = true }) {
                Icon(Icons.Filled.Add, contentDescription = "新建规则")
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

            if (filteredRules.isEmpty()) {
                androidx.compose.foundation.layout.Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = androidx.compose.ui.Alignment.Center,
                ) {
                    Column(horizontalAlignment = androidx.compose.ui.Alignment.CenterHorizontally) {
                        Icon(
                            Icons.Filled.TrackChanges,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(bottom = 8.dp),
                        )
                        Text(
                            "暂无 Hook 规则",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Text(
                            "点击 + 创建第一条 Hook 规则",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(top = 4.dp),
                        )
                    }
                }
            } else {
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    items(filteredRules, key = { it.id }) { rule ->
                        HookRuleCard(
                            rule = rule,
                            onToggle = { enabled ->
                                scope.launch { container.hookEngine.setEnabled(rule.id, enabled) }
                            },
                            onDelete = {
                                scope.launch { container.hookEngine.deleteRule(rule.id) }
                            },
                        )
                    }
                }
            }
        }
    }

    if (showAddDialog) {
        AddHookRuleDialog(
            onDismiss = { showAddDialog = false },
            onAdd = { name, type, urlPattern, action, description ->
                scope.launch {
                    container.hookEngine.createRule(
                        name = name,
                        type = type,
                        match = HookMatch(urlPattern = urlPattern.ifBlank { null }),
                        action = action,
                        description = description,
                    )
                    showAddDialog = false
                }
            },
        )
    }
}

@Composable
private fun HookRuleCard(
    rule: HookRule,
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
                    Icons.Filled.TrackChanges,
                    contentDescription = null,
                    tint = if (rule.enabled) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(end = 8.dp),
                )
                Text(
                    text = rule.name,
                    style = MaterialTheme.typography.titleSmall,
                    modifier = Modifier.weight(1f),
                )
                Switch(checked = rule.enabled, onCheckedChange = onToggle)
            }
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                AssistChip(
                    onClick = {},
                    label = { Text(rule.type.display) },
                )
                AssistChip(
                    onClick = {},
                    label = { Text(rule.action.display) },
                )
            }
            if (rule.match.urlPattern != null) {
                Text(
                    text = "URL: ${rule.match.urlPattern}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 4.dp),
                )
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
            ) {
                Text(
                    "命中: ${rule.hitCount}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.secondary,
                )
                IconButton(onClick = onDelete) {
                    Icon(Icons.Filled.Delete, contentDescription = "删除")
                }
            }
        }
    }
}

@Composable
private fun AddHookRuleDialog(
    onDismiss: () -> Unit,
    onAdd: (name: String, type: HookType, urlPattern: String, action: HookAction, description: String) -> Unit,
) {
    var name by remember { mutableStateOf("") }
    var urlPattern by remember { mutableStateOf("") }
    var description by remember { mutableStateOf("") }
    var typeIndex by remember { mutableStateOf(0) }
    var actionIndex by remember { mutableStateOf(0) }

    val types = HookType.entries.take(8).toList()
    val actions = listOf(
        HookAction.LOG, HookAction.BLOCK, HookAction.MOCK,
        HookAction.REDIRECT, HookAction.MODIFY_HEADER, HookAction.DELAY,
    )

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("新建 Hook 规则") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("规则名称") },
                    singleLine = true,
                )
                Text("Hook 类型", style = MaterialTheme.typography.bodySmall)
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
                OutlinedTextField(
                    value = urlPattern,
                    onValueChange = { urlPattern = it },
                    label = { Text("URL 匹配模式") },
                    singleLine = true,
                    placeholder = { Text("例如: api.example.com") },
                )
                Text("动作", style = MaterialTheme.typography.bodySmall)
                androidx.compose.foundation.layout.Box(modifier = Modifier.fillMaxWidth()) {
                    androidx.compose.foundation.lazy.LazyRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        items(actions) { a ->
                            FilterChip(
                                selected = actions[actionIndex] == a,
                                onClick = { actionIndex = actions.indexOf(a) },
                                label = { Text(a.display) },
                            )
                        }
                    }
                }
                OutlinedTextField(
                    value = description,
                    onValueChange = { description = it },
                    label = { Text("描述（可选）") },
                    singleLine = true,
                )
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    onAdd(
                        name.trim(),
                        types[typeIndex],
                        urlPattern.trim(),
                        actions[actionIndex],
                        description.trim(),
                    )
                },
                enabled = name.isNotBlank(),
            ) { Text("创建") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("取消") }
        },
    )
}
