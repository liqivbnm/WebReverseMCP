package com.webreverse.mcp.ui.terminal

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.CreateNewFolder
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.webreverse.mcp.mcp.tools.terminal.TerminalPaths
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 文件管理。
 *
 * 用于手动管理 AI 创建的文件/文件夹（HOME、scripts、logs、tmp 等），
 * 避免 AI 忘记清理时用户无法操作。支持：
 * - 浏览目录（文件夹优先，按名称排序）
 * - 进入子目录 / 返回上级 / 快捷切换根目录
 * - 删除文件或文件夹（递归，带确认）
 * - 重命名、新建文件夹
 * - 查看文本文件内容、查看文件信息
 *
 * 四个根目录全部位于设置里的存储（工作）目录之下，
 * 与 file.* 工具、terminal.* 落盘位置完全一致。
 */
@Composable
fun FileManagerView() {
    // 可管理的根目录（统一存储目录之下；WorkDir 不可写时自动回退应用私有目录）
    val roots = remember {
        listOf(
            RootEntry("HOME", TerminalPaths.homeDir),
            RootEntry("scripts", TerminalPaths.scriptsDir),
            RootEntry("logs", TerminalPaths.logDir),
            RootEntry("tmp", TerminalPaths.tmpDir),
        )
    }
    val defaultRoot = remember { TerminalPaths.homeDir }

    var currentDir by remember { mutableStateOf(defaultRoot) }
    var refreshTick by remember { mutableIntStateOf(0) }
    val scope = rememberCoroutineScope()

    // 当前目录内容（文件夹优先，按名称排序）
    val entries = remember(currentDir, refreshTick) {
        (currentDir.listFiles() ?: emptyArray())
            .sortedWith(compareBy({ !it.isDirectory }, { it.name.lowercase(Locale.ROOT) }))
    }

    // 对话框状态
    var deleteTarget by remember { mutableStateOf<File?>(null) }
    var renameTarget by remember { mutableStateOf<File?>(null) }
    var renameText by remember { mutableStateOf("") }
    var newFolderOpen by remember { mutableStateOf(false) }
    var newFolderText by remember { mutableStateOf("") }
    var contentTarget by remember { mutableStateOf<File?>(null) }
    var infoTarget by remember { mutableStateOf<File?>(null) }

    Column(modifier = Modifier.fillMaxSize()) {
        // 根目录快捷切换
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 8.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                "根目录:",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            roots.forEach { root ->
                TextButton(onClick = { currentDir = root.dir }) {
                    Text(
                        root.label,
                        style = MaterialTheme.typography.labelSmall,
                        color = if (currentDir == root.dir) {
                            MaterialTheme.colorScheme.primary
                        } else {
                            MaterialTheme.colorScheme.onSurfaceVariant
                        },
                    )
                }
            }
        }
        HorizontalDivider()

        // 路径栏：返回上级 + 当前路径 + 刷新 + 新建文件夹
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 4.dp, vertical = 2.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            if (currentDir.parentFile != null && currentDir !in roots.map { it.dir }) {
                IconButton(onClick = { currentDir = currentDir.parentFile ?: defaultRoot }) {
                    Icon(Icons.Filled.ArrowBack, contentDescription = "返回上级")
                }
            } else {
                Spacer(Modifier.width(48.dp))
            }
            Text(
                currentDir.absolutePath,
                style = MaterialTheme.typography.bodySmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f),
            )
            IconButton(onClick = { refreshTick++ }) {
                Icon(Icons.Filled.Refresh, contentDescription = "刷新")
            }
            IconButton(onClick = {
                newFolderText = ""
                newFolderOpen = true
            }) {
                Icon(Icons.Filled.CreateNewFolder, contentDescription = "新建文件夹")
            }
        }
        HorizontalDivider()

        // 文件列表
        if (entries.isEmpty()) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Spacer(Modifier.size(40.dp))
                Text(
                    "此目录为空",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        } else {
            LazyColumn(modifier = Modifier.fillMaxSize()) {
                items(entries, key = { it.absolutePath }) { file ->
                    ListItem(
                        modifier = Modifier.clickable {
                            if (file.isDirectory) {
                                currentDir = file
                            } else {
                                contentTarget = file
                            }
                        },
                        leadingContent = {
                            Icon(
                                if (file.isDirectory) Icons.Filled.Folder else Icons.Filled.Description,
                                contentDescription = null,
                                tint = if (file.isDirectory) {
                                    MaterialTheme.colorScheme.primary
                                } else {
                                    MaterialTheme.colorScheme.onSurfaceVariant
                                },
                            )
                        },
                        headlineContent = {
                            Text(
                                file.name,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        },
                        supportingContent = {
                            Text(
                                if (file.isDirectory) {
                                    "文件夹 · ${formatModified(file)}"
                                } else {
                                    "${TerminalPaths.formatSize(file.length())} · ${formatModified(file)}"
                                },
                                style = MaterialTheme.typography.labelSmall,
                            )
                        },
                        trailingContent = {
                            Row {
                                IconButton(onClick = { infoTarget = file }) {
                                    Icon(
                                        Icons.Filled.Info,
                                        contentDescription = "信息",
                                        modifier = Modifier.size(18.dp),
                                    )
                                }
                                IconButton(onClick = {
                                    renameText = file.name
                                    renameTarget = file
                                }) {
                                    Icon(
                                        Icons.Filled.Edit,
                                        contentDescription = "重命名",
                                        modifier = Modifier.size(18.dp),
                                    )
                                }
                                IconButton(onClick = { deleteTarget = file }) {
                                    Icon(
                                        Icons.Filled.Delete,
                                        contentDescription = "删除",
                                        modifier = Modifier.size(18.dp),
                                        tint = MaterialTheme.colorScheme.error,
                                    )
                                }
                            }
                        },
                    )
                }
            }
        }
    }

    // ===== 删除确认 =====
    deleteTarget?.let { target ->
        AlertDialog(
            onDismissRequest = { deleteTarget = null },
            title = { Text("删除确认") },
            text = {
                Text(
                    if (target.isDirectory) {
                        "确定要删除文件夹「${target.name}」及其全部内容吗？此操作不可恢复。"
                    } else {
                        "确定要删除文件「${target.name}」吗？此操作不可恢复。"
                    },
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    scope.launch(Dispatchers.IO) {
                        if (target.isDirectory) {
                            target.deleteRecursively()
                        } else {
                            target.delete()
                        }
                    }
                    deleteTarget = null
                    refreshTick++
                }) {
                    Text("删除", color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = { deleteTarget = null }) {
                    Text("取消")
                }
            },
        )
    }

    // ===== 重命名 =====
    renameTarget?.let { target ->
        AlertDialog(
            onDismissRequest = { renameTarget = null },
            title = { Text("重命名") },
            text = {
                OutlinedTextField(
                    value = renameText,
                    onValueChange = { renameText = it },
                    singleLine = true,
                    label = { Text("新名称") },
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    val newName = renameText.trim()
                    if (newName.isNotEmpty() && newName != target.name) {
                        scope.launch(Dispatchers.IO) {
                            runCatching {
                                target.renameTo(File(target.parentFile, newName))
                            }
                        }
                        refreshTick++
                    }
                    renameTarget = null
                }) {
                    Text("确定")
                }
            },
            dismissButton = {
                TextButton(onClick = { renameTarget = null }) {
                    Text("取消")
                }
            },
        )
    }

    // ===== 新建文件夹 =====
    if (newFolderOpen) {
        AlertDialog(
            onDismissRequest = { newFolderOpen = false },
            title = { Text("新建文件夹") },
            text = {
                OutlinedTextField(
                    value = newFolderText,
                    onValueChange = { newFolderText = it },
                    singleLine = true,
                    label = { Text("文件夹名称") },
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    val name = newFolderText.trim()
                    if (name.isNotEmpty()) {
                        scope.launch(Dispatchers.IO) {
                            runCatching {
                                File(currentDir, name).mkdirs()
                            }
                        }
                        refreshTick++
                    }
                    newFolderOpen = false
                }) {
                    Text("创建")
                }
            },
            dismissButton = {
                TextButton(onClick = { newFolderOpen = false }) {
                    Text("取消")
                }
            },
        )
    }

    // ===== 文件内容查看 =====
    contentTarget?.let { target ->
        var content by remember(target) { mutableStateOf<String?>(null) }
        var isText by remember(target) { mutableStateOf(false) }
        var loadError by remember(target) { mutableStateOf<String?>(null) }

        // 异步读取文本内容（限制 64KB）
        androidx.compose.runtime.LaunchedEffect(target) {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    val bytes = target.readBytes()
                    if (bytes.size > 64 * 1024) {
                        loadError = "文件过大（${TerminalPaths.formatSize(bytes.size.toLong())}），仅支持预览 64KB 以内"
                        null
                    } else {
                        val text = String(bytes, Charsets.UTF_8)
                        // 简单二进制检测：包含 NUL 或大量不可打印字符视为二进制
                        val printable = text.count { it.isLetterOrDigit() || it.isWhitespace() || it in ".,;:!?()[]{}\"'`~@#$%^&*+-_=/\\|<>" }
                        val ratio = if (text.isNotEmpty()) printable.toDouble() / text.length else 1.0
                        if (ratio < 0.7) {
                            loadError = "二进制文件，无法预览文本内容"
                            null
                        } else {
                            isText = true
                            text
                        }
                    }
                }.getOrElse { e ->
                    loadError = "读取失败: ${e.message}"
                    null
                }
            }
            content = result
        }

        AlertDialog(
            onDismissRequest = { contentTarget = null },
            title = { Text(target.name, maxLines = 1, overflow = TextOverflow.Ellipsis) },
            text = {
                Column {
                    Text(
                        "大小: ${TerminalPaths.formatSize(target.length())} · ${formatModified(target)}",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.size(8.dp))
                    when {
                        loadError != null -> Text(
                            loadError!!,
                            color = MaterialTheme.colorScheme.error,
                        )
                        content != null -> Text(
                            content!!,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 12.sp,
                            maxLines = 40,
                        )
                        else -> Text("加载中...")
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { contentTarget = null }) {
                    Text("关闭")
                }
            },
        )
    }

    // ===== 文件信息 =====
    infoTarget?.let { target ->
        AlertDialog(
            onDismissRequest = { infoTarget = null },
            title = { Text("文件信息") },
            text = {
                Column {
                    InfoRow("名称", target.name)
                    InfoRow("类型", if (target.isDirectory) "文件夹" else "文件")
                    InfoRow("大小", if (target.isDirectory) "-" else TerminalPaths.formatSize(target.length()))
                    InfoRow("修改时间", formatModified(target))
                    InfoRow("路径", target.absolutePath)
                }
            },
            confirmButton = {
                TextButton(onClick = { infoTarget = null }) {
                    Text("关闭")
                }
            },
        )
    }
}

/** 根目录快捷入口 */
private data class RootEntry(val label: String, val dir: File)

/** 信息对话框行 */
@Composable
private fun InfoRow(label: String, value: String) {
    Row(modifier = Modifier.padding(vertical = 2.dp)) {
        Text(
            "$label: ",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            value,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.weight(1f),
        )
    }
}

/** 格式化修改时间 */
private fun formatModified(file: File): String {
    val sdf = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault())
    return sdf.format(Date(file.lastModified()))
}
