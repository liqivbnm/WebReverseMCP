package com.webreverse.mcp.ui.workspace

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
import androidx.compose.material.icons.filled.Analytics
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Note
import androidx.compose.material.icons.filled.TrackChanges
import androidx.compose.material.icons.filled.Workspaces
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.webreverse.mcp.core.database.entity.AnalysisResultEntity
import com.webreverse.mcp.core.database.entity.FindingEntity
import com.webreverse.mcp.core.database.entity.NoteEntity
import com.webreverse.mcp.core.database.entity.TargetEntity
import com.webreverse.mcp.core.database.entity.WorkspaceEntity
import com.webreverse.mcp.di.AppContainer
import kotlinx.coroutines.launch

/**
 * Workspace 页面：AI 逆向工程工作区。
 * 管理 Workspace / Targets / Notes / Findings / Analysis Results。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WorkspaceScreen(container: AppContainer) {
    val scope = rememberCoroutineScope()
    val workspaces by container.workspaceManager.observeWorkspaces().collectAsState(initial = emptyList())

    var selectedId by remember { mutableStateOf<String?>(null) }
    var showCreateDialog by remember { mutableStateOf(false) }

    val selected = workspaces.firstOrNull { it.id == selectedId }

    Scaffold(
        // 底部沉浸：手机端底部 inset 由根 AppBottomBar 消费，避免内容上方空白带
        contentWindowInsets = com.webreverse.mcp.ui.navigation.pageScaffoldInsets(),
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(if (selected != null) selected.name else "Workspace")
                        Text(
                            if (selected != null) "目标 / 笔记 / 发现 / 分析" else "AI 逆向工程工作区",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                },
                navigationIcon = {
                    if (selected != null) {
                        IconButton(onClick = { selectedId = null }) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回")
                        }
                    }
                },
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = { showCreateDialog = true },
            ) {
                Icon(Icons.Filled.Add, contentDescription = "新建")
            }
        },
    ) { padding ->
        if (selected == null) {
            WorkspaceList(
                workspaces = workspaces,
                onOpen = { selectedId = it.id },
                onDelete = { ws -> scope.launch { container.workspaceManager.deleteWorkspace(ws.id) } },
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding),
            )
        } else {
            WorkspaceDetail(
                container = container,
                workspace = selected,
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding),
            )
        }
    }

    if (showCreateDialog) {
        CreateWorkspaceDialog(
            onDismiss = { showCreateDialog = false },
            onCreate = { name, desc, url ->
                scope.launch {
                    container.workspaceManager.createWorkspace(name, desc, url)
                    showCreateDialog = false
                }
            },
        )
    }
}

// ==================== Workspace 列表 ====================

@Composable
private fun WorkspaceList(
    workspaces: List<WorkspaceEntity>,
    onOpen: (WorkspaceEntity) -> Unit,
    onDelete: (WorkspaceEntity) -> Unit,
    modifier: Modifier = Modifier,
) {
    LazyColumn(
        modifier = modifier,
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (workspaces.isEmpty()) {
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(32.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                    ) {
                        Icon(
                            Icons.Filled.Workspaces,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.padding(bottom = 8.dp),
                        )
                        Text(
                            "暂无工作区，点击 + 创建",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        } else {
            items(workspaces, key = { it.id }) { ws ->
                Card(
                    onClick = { onOpen(ws) },
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surfaceContainer,
                    ),
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(start = 16.dp, end = 4.dp, top = 4.dp, bottom = 4.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(ws.name, style = MaterialTheme.typography.titleMedium)
                            if (ws.description.isNotBlank()) {
                                Text(
                                    ws.description,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                            if (ws.targetUrl.isNotBlank()) {
                                Text(
                                    ws.targetUrl,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.primary,
                                )
                            }
                        }
                        IconButton(onClick = { onDelete(ws) }) {
                            Icon(Icons.Filled.Delete, contentDescription = "删除")
                        }
                    }
                }
            }
        }
    }
}

// ==================== Workspace 详情 ====================

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun WorkspaceDetail(
    container: AppContainer,
    workspace: WorkspaceEntity,
    modifier: Modifier = Modifier,
) {
    val scope = rememberCoroutineScope()
    val targets by container.workspaceManager.observeTargets().collectAsState(initial = emptyList())
    val notes by container.workspaceManager.observeNotes(workspace.id).collectAsState(initial = emptyList())
    val findings by container.workspaceManager.observeFindings(workspace.id).collectAsState(initial = emptyList())
    val analysis by container.workspaceManager.observeAnalysis(workspace.id).collectAsState(initial = emptyList())

    var showAddTarget by remember { mutableStateOf(false) }
    var showAddNote by remember { mutableStateOf(false) }

    LazyColumn(
        modifier = modifier,
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        // 目标
        item {
            SectionHeader("目标 (${targets.size})", onAdd = { showAddTarget = true })
        }
        if (targets.isEmpty()) {
            item { EmptyCard("暂无目标，点击 + 添加") }
        } else {
            items(targets, key = { it.id }) { target ->
                TargetRow(
                    target = target,
                    onDelete = { scope.launch { container.workspaceManager.deleteTarget(target) } },
                )
            }
        }

        // 笔记
        item {
            SectionHeader("笔记 (${notes.size})", onAdd = { showAddNote = true })
        }
        if (notes.isEmpty()) {
            item { EmptyCard("暂无笔记") }
        } else {
            items(notes, key = { it.id }) { note ->
                NoteRow(
                    note = note,
                    onDelete = { scope.launch { container.workspaceManager.deleteNote(note) } },
                )
            }
        }

        // 发现
        item {
            SectionHeader("发现 (${findings.size})", onAdd = null)
        }
        if (findings.isEmpty()) {
            item { EmptyCard("暂无发现，运行分析后自动生成") }
        } else {
            items(findings, key = { it.id }) { finding ->
                FindingRow(finding)
            }
        }

        // 分析结果
        item {
            SectionHeader("分析结果 (${analysis.size})", onAdd = null)
        }
        if (analysis.isEmpty()) {
            item { EmptyCard("暂无分析结果") }
        } else {
            items(analysis, key = { it.id }) { result ->
                AnalysisRow(result)
            }
        }
    }

    if (showAddTarget) {
        AddTargetDialog(
            onDismiss = { showAddTarget = false },
            onAdd = { name, url, framework ->
                scope.launch {
                    container.workspaceManager.addTarget(name, url, framework)
                    showAddTarget = false
                }
            },
        )
    }
    if (showAddNote) {
        AddNoteDialog(
            workspaceId = workspace.id,
            onDismiss = { showAddNote = false },
            onAdd = { title, content ->
                scope.launch {
                    container.workspaceManager.addNote(workspace.id, title, content)
                    showAddNote = false
                }
            },
        )
    }
}

@Composable
private fun SectionHeader(title: String, onAdd: (() -> Unit)?) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = title,
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.weight(1f),
        )
        if (onAdd != null) {
            TextButton(onClick = onAdd) {
                Icon(Icons.Filled.Add, contentDescription = null, modifier = Modifier.padding(end = 4.dp))
                Text("添加")
            }
        }
    }
}

@Composable
private fun EmptyCard(message: String) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Text(
            text = message,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(16.dp),
        )
    }
}

@Composable
private fun TargetRow(target: TargetEntity, onDelete: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        ListItem(
            headlineContent = { Text(target.name) },
            supportingContent = {
                Column {
                    Text(target.url)
                    target.framework?.let { Text("框架: $it", style = MaterialTheme.typography.bodySmall) }
                }
            },
            leadingContent = {
                Icon(Icons.Filled.Link, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
            },
            trailingContent = {
                IconButton(onClick = onDelete) {
                    Icon(Icons.Filled.Delete, contentDescription = "删除")
                }
            },
        )
    }
}

@Composable
private fun NoteRow(note: NoteEntity, onDelete: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        ListItem(
            headlineContent = { Text(note.title) },
            supportingContent = { Text(note.content, maxLines = 2) },
            leadingContent = {
                Icon(Icons.Filled.Note, contentDescription = null, tint = MaterialTheme.colorScheme.secondary)
            },
            trailingContent = {
                IconButton(onClick = onDelete) {
                    Icon(Icons.Filled.Delete, contentDescription = "删除")
                }
            },
        )
    }
}

@Composable
private fun FindingRow(finding: FindingEntity) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    Icons.Filled.TrackChanges,
                    contentDescription = null,
                    tint = when (finding.severity) {
                        "HIGH" -> MaterialTheme.colorScheme.error
                        "MEDIUM" -> MaterialTheme.colorScheme.tertiary
                        else -> MaterialTheme.colorScheme.primary
                    },
                )
                Text(
                    text = finding.title,
                    style = MaterialTheme.typography.titleSmall,
                    modifier = Modifier.padding(start = 8.dp),
                )
            }
            Text(
                text = "${finding.type} · ${finding.severity} · ${finding.confidence}",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 4.dp),
            )
            if (finding.description.isNotBlank()) {
                Text(
                    text = finding.description,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(top = 4.dp),
                )
            }
        }
    }
}

@Composable
private fun AnalysisRow(result: AnalysisResultEntity) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    Icons.Filled.Analytics,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                )
                Text(
                    text = result.title,
                    style = MaterialTheme.typography.titleSmall,
                    modifier = Modifier.padding(start = 8.dp),
                )
            }
            Text(
                text = result.type,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 4.dp),
            )
            if (result.summary.isNotBlank()) {
                Text(
                    text = result.summary,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(top = 4.dp),
                )
            }
        }
    }
}

// ==================== 对话框 ====================

@Composable
private fun CreateWorkspaceDialog(
    onDismiss: () -> Unit,
    onCreate: (name: String, desc: String, url: String) -> Unit,
) {
    var name by remember { mutableStateOf("") }
    var desc by remember { mutableStateOf("") }
    var url by remember { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("新建工作区") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("名称") },
                    singleLine = true,
                )
                OutlinedTextField(
                    value = desc,
                    onValueChange = { desc = it },
                    label = { Text("描述") },
                    singleLine = true,
                )
                OutlinedTextField(
                    value = url,
                    onValueChange = { url = it },
                    label = { Text("目标 URL") },
                    singleLine = true,
                )
            }
        },
        confirmButton = {
            Button(
                onClick = { onCreate(name.trim(), desc.trim(), url.trim()) },
                enabled = name.isNotBlank(),
            ) {
                Text("创建")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("取消") }
        },
    )
}

@Composable
private fun AddTargetDialog(
    onDismiss: () -> Unit,
    onAdd: (name: String, url: String, framework: String?) -> Unit,
) {
    var name by remember { mutableStateOf("") }
    var url by remember { mutableStateOf("") }
    var framework by remember { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("添加目标") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("名称") },
                    singleLine = true,
                )
                OutlinedTextField(
                    value = url,
                    onValueChange = { url = it },
                    label = { Text("URL") },
                    singleLine = true,
                )
                OutlinedTextField(
                    value = framework,
                    onValueChange = { framework = it },
                    label = { Text("框架（可选）") },
                    singleLine = true,
                )
            }
        },
        confirmButton = {
            Button(
                onClick = { onAdd(name.trim(), url.trim(), framework.trim().ifBlank { null }) },
                enabled = name.isNotBlank() && url.isNotBlank(),
            ) {
                Text("添加")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("取消") }
        },
    )
}

@Composable
private fun AddNoteDialog(
    workspaceId: String?,
    onDismiss: () -> Unit,
    onAdd: (title: String, content: String) -> Unit,
) {
    var title by remember { mutableStateOf("") }
    var content by remember { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("新建笔记") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = title,
                    onValueChange = { title = it },
                    label = { Text("标题") },
                    singleLine = true,
                )
                OutlinedTextField(
                    value = content,
                    onValueChange = { content = it },
                    label = { Text("内容") },
                    minLines = 3,
                )
            }
        },
        confirmButton = {
            Button(
                onClick = { onAdd(title.trim(), content.trim()) },
                enabled = title.isNotBlank(),
            ) {
                Text("保存")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("取消") }
        },
    )
}
