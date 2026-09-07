package com.webreverse.mcp.ui.scripts

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
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
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
import com.webreverse.mcp.core.database.entity.UserScriptEntity
import com.webreverse.mcp.di.AppContainer
import com.webreverse.mcp.ui.theme.CodeTextStyle
import kotlinx.coroutines.launch

/**
 * 用户脚本管理页面：管理 User Scripts（类似 Tampermonkey / DevTools Snippets）。
 * 支持创建、编辑、启用/禁用、运行时机选择。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScriptsScreen(
    container: AppContainer,
    onBack: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    val scripts by container.userScriptRepository.observeAll().collectAsState(initial = emptyList())
    var showAddDialog by remember { mutableStateOf(false) }
    var editingScript by remember { mutableStateOf<UserScriptEntity?>(null) }

    Scaffold(
        // 底部沉浸：手机端底部 inset 由根 AppBottomBar 消费，避免内容上方空白带
        contentWindowInsets = com.webreverse.mcp.ui.navigation.pageScaffoldInsets(),
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("用户脚本")
                        Text(
                            "${scripts.size} 个脚本",
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
                Icon(Icons.Filled.Add, contentDescription = "新建脚本")
            }
        },
    ) { padding ->
        if (scripts.isEmpty()) {
            androidx.compose.foundation.layout.Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding),
                contentAlignment = androidx.compose.ui.Alignment.Center,
            ) {
                Column(horizontalAlignment = androidx.compose.ui.Alignment.CenterHorizontally) {
                    Icon(
                        Icons.Filled.Code,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(bottom = 8.dp),
                    )
                    Text(
                        "暂无用户脚本",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(
                        "点击 + 创建你的第一个脚本",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = 4.dp),
                    )
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding),
                contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                items(scripts, key = { it.id }) { script ->
                    ScriptCard(
                        script = script,
                        onEdit = { editingScript = script },
                        onDelete = {
                            scope.launch {
                                container.userScriptRepository.delete(script)
                            }
                        },
                        onToggle = { enabled ->
                            scope.launch {
                                container.userScriptRepository.setEnabled(script.id, enabled)
                            }
                        },
                    )
                }
            }
        }
    }

    if (showAddDialog || editingScript != null) {
        val isEdit = editingScript != null
        val current = editingScript
        ScriptEditorDialog(
            initial = current,
            onDismiss = {
                showAddDialog = false
                editingScript = null
            },
            onSave = { name, description, code, runAt ->
                scope.launch {
                    val entity = if (isEdit && current != null) {
                        current.copy(
                            name = name,
                            description = description,
                            code = code,
                            runAt = runAt,
                            updatedAt = System.currentTimeMillis(),
                        )
                    } else {
                        UserScriptEntity(
                            id = java.util.UUID.randomUUID().toString(),
                            name = name,
                            description = description,
                            code = code,
                            runAt = runAt,
                        )
                    }
                    container.userScriptRepository.upsert(entity)
                    showAddDialog = false
                    editingScript = null
                }
            },
        )
    }
}

@Composable
private fun ScriptCard(
    script: UserScriptEntity,
    onEdit: () -> Unit,
    onDelete: () -> Unit,
    onToggle: (Boolean) -> Unit,
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
                    Icons.Filled.Code,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.padding(end = 8.dp),
                )
                Text(
                    text = script.name,
                    style = MaterialTheme.typography.titleSmall,
                    modifier = Modifier.weight(1f),
                )
                Switch(checked = script.enabled, onCheckedChange = onToggle)
            }
            if (script.description.isNotBlank()) {
                Text(
                    text = script.description,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 4.dp),
                )
            }
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
            ) {
                AssistChip(
                    onClick = {},
                    label = { Text("运行: ${script.runAt}") },
                )
                androidx.compose.foundation.layout.Spacer(modifier = Modifier.weight(1f))
                IconButton(onClick = onEdit) {
                    Icon(
                        Icons.Filled.Edit,
                        contentDescription = "编辑",
                    )
                }
                IconButton(onClick = onDelete) {
                    Icon(Icons.Filled.Delete, contentDescription = "删除")
                }
            }
        }
    }
}

@Composable
private fun ScriptEditorDialog(
    initial: UserScriptEntity?,
    onDismiss: () -> Unit,
    onSave: (name: String, description: String, code: String, runAt: String) -> Unit,
) {
    var name by remember { mutableStateOf(initial?.name ?: "") }
    var description by remember { mutableStateOf(initial?.description ?: "") }
    var code by remember { mutableStateOf(initial?.code ?: "// 在此编写 JavaScript 代码\nconsole.log('Hello from UserScript');") }
    val runAtOptions = listOf("MANUAL", "PAGE_START", "DOM_READY", "AFTER_LOAD", "BEFORE_REQUEST", "AFTER_REQUEST")
    var selectedRunAt by remember { mutableStateOf(initial?.runAt ?: "MANUAL") }
    var selectedIndex by remember { mutableStateOf(runAtOptions.indexOf(initial?.runAt ?: "MANUAL").coerceAtLeast(0)) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (initial != null) "编辑脚本" else "新建脚本") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("脚本名称") },
                    singleLine = true,
                )
                OutlinedTextField(
                    value = description,
                    onValueChange = { description = it },
                    label = { Text("描述（可选）") },
                    singleLine = true,
                )
                Text("运行时机", style = MaterialTheme.typography.bodySmall)
                SingleChoiceSegmentedButtonRow(
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    runAtOptions.forEachIndexed { index, option ->
                        SegmentedButton(
                            selected = selectedIndex == index,
                            onClick = {
                                selectedIndex = index
                                selectedRunAt = option
                            },
                            shape = SegmentedButtonDefaults.itemShape(index = index, count = runAtOptions.size),
                        ) {
                            Text(option, style = MaterialTheme.typography.labelSmall)
                        }
                    }
                }
                OutlinedTextField(
                    value = code,
                    onValueChange = { code = it },
                    label = { Text("JavaScript 代码") },
                    modifier = Modifier.fillMaxWidth(),
                    minLines = 8,
                    maxLines = 12,
                    textStyle = CodeTextStyle,
                )
            }
        },
        confirmButton = {
            Button(
                onClick = { onSave(name.trim(), description.trim(), code, selectedRunAt) },
                enabled = name.isNotBlank() && code.isNotBlank(),
            ) { Text("保存") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("取消") }
        },
    )
}
