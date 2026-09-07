package com.webreverse.mcp.ui.permissions

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.AdminPanelSettings
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.util.Redactor
import com.webreverse.mcp.di.AppContainer
import kotlinx.coroutines.launch

/**
 * 权限管理页面。
 * - 权限作用域默认全部开启，用户可按作用域手动关闭（关闭后对应工具调用被拒绝）
 * - 敏感数据脱敏默认关闭（输出原始数据），用户可手动开启
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PermissionsScreen(
    container: AppContainer,
    onBack: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val permissionManager =
        container.permissionManager as? com.webreverse.mcp.core.security.PermissionManagerImpl
    val denied by (permissionManager?.deniedScopes?.collectAsState()
        ?: remember { mutableStateOf(emptySet<PermissionScope>()) })
    var redactionEnabled by remember { mutableStateOf(Redactor.enabled) }

    Scaffold(
        // 底部沉浸：手机端底部 inset 由根 AppBottomBar 消费，避免内容上方空白带
        contentWindowInsets = com.webreverse.mcp.ui.navigation.pageScaffoldInsets(),
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("权限管理")
                        Text(
                            "权限默认全部开启，可按需关闭",
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
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            // ---- 敏感数据脱敏 ----
            item {
                Text(
                    text = "敏感数据",
                    style = MaterialTheme.typography.titleMedium,
                )
            }
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(vertical = 8.dp)) {
                        ListItem(
                            headlineContent = { Text("敏感数据脱敏") },
                            supportingContent = {
                                Text(
                                    if (redactionEnabled) {
                                        "已开启：敏感字段输出为 [REDACTED]"
                                    } else {
                                        "已关闭（默认）：工具输出原始数据，不做脱敏"
                                    },
                                )
                            },
                            leadingContent = {
                                Icon(
                                    Icons.Filled.Security,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.primary,
                                )
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
                        Text(
                            text = "开启后，Cookie、Token、Authorization、API Key、密码等敏感字段" +
                                "在所有工具输出中自动脱敏为 [REDACTED]；关闭时输出原始数据。",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                        )
                    }
                }
            }

            // ---- 权限作用域 ----
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
                ) {
                    Text(
                        text = "权限作用域 (${PermissionScope.entries.size})",
                        style = MaterialTheme.typography.titleMedium,
                        modifier = Modifier
                            .padding(top = 8.dp)
                            .weight(1f),
                    )
                    OutlinedButton(
                        onClick = {
                            scope.launch { permissionManager?.allowAll() }
                        },
                    ) {
                        Text("全部开启")
                    }
                }
            }
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(vertical = 4.dp)) {
                        Text(
                            text = "以下权限默认全部开启；关闭某个作用域后，使用该权限的 MCP 工具调用会被拒绝。",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                        )
                        PermissionScope.entries.forEachIndexed { index, permScope ->
                            val allowed = permScope !in denied
                            val highRisk = permissionManager?.isHighRisk(permScope) ?: false
                            PermissionScopeRow(
                                scope = permScope,
                                isHighRisk = highRisk,
                                allowed = allowed,
                                onToggle = { newValue ->
                                    scope.launch {
                                        permissionManager?.setAllowed(permScope, newValue)
                                    }
                                },
                            )
                            if (index != PermissionScope.entries.lastIndex) {
                                HorizontalDivider(modifier = Modifier.padding(horizontal = 8.dp))
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun PermissionScopeRow(
    scope: PermissionScope,
    isHighRisk: Boolean,
    allowed: Boolean,
    onToggle: (Boolean) -> Unit,
) {
    ListItem(
        headlineContent = {
            Text(
                scope.display,
                style = MaterialTheme.typography.bodyLarge,
                color = if (allowed) {
                    MaterialTheme.colorScheme.onSurface
                } else {
                    MaterialTheme.colorScheme.onSurfaceVariant
                },
            )
        },
        supportingContent = {
            Text(if (isHighRisk) "${scope.name} · 高风险" else scope.name)
        },
        leadingContent = {
            Icon(
                if (allowed) Icons.Filled.LockOpen else Icons.Filled.Lock,
                contentDescription = null,
                tint = if (allowed) {
                    if (isHighRisk) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary
                } else {
                    MaterialTheme.colorScheme.onSurfaceVariant
                },
            )
        },
        trailingContent = {
            Switch(checked = allowed, onCheckedChange = onToggle)
        },
    )
}
