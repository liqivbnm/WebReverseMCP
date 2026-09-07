package com.webreverse.mcp.core.security

import android.content.Context
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.preferencesDataStore
import com.webreverse.mcp.core.common.permission.GrantScope
import com.webreverse.mcp.core.common.permission.PermissionDecision
import com.webreverse.mcp.core.common.permission.PermissionManager
import com.webreverse.mcp.core.common.permission.PermissionRequest
import com.webreverse.mcp.core.common.permission.PermissionResult
import com.webreverse.mcp.core.common.permission.PermissionScope
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

private val Context.permissionDataStore by preferencesDataStore(name = "permissions")

/**
 * 权限管理器实现。
 * 默认策略：所有权限作用域默认全部开启（工具调用直接放行）；
 * 用户可在权限管理页面按作用域手动关闭，关闭后使用该权限的 MCP 工具会被拒绝。
 * 敏感数据脱敏默认关闭，由用户手动开启（见 [com.webreverse.mcp.core.common.util.Redactor]）。
 */
class PermissionManagerImpl(private val context: Context) : PermissionManager {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val _pendingRequests = MutableStateFlow<List<PermissionRequest>>(emptyList())
    val pendingRequests: StateFlow<List<PermissionRequest>> = _pendingRequests.asStateFlow()

    /** 用户显式关闭的权限作用域（空集合 = 全部允许） */
    private val _deniedScopes = MutableStateFlow<Set<PermissionScope>>(emptySet())
    val deniedScopes: StateFlow<Set<PermissionScope>> = _deniedScopes.asStateFlow()

    private val highRiskScopes = setOf(
        PermissionScope.READ_COOKIES,
        PermissionScope.READ_HEADERS,
        PermissionScope.MODIFY_NETWORK,
        PermissionScope.EXECUTE_JS,
        PermissionScope.INSTALL_HOOK,
        PermissionScope.MODIFY_STORAGE,
        PermissionScope.MODIFY_PAGE,
    )

    init {
        // 启动时加载用户关闭的作用域（后台异步，不阻塞初始化）
        scope.launch {
            val denied = context.permissionDataStore.data.first().asMap().keys
                .filter { it.name.startsWith(DENIED_PREFIX) }
                .mapNotNull { key ->
                    runCatching {
                        PermissionScope.valueOf(key.name.removePrefix(DENIED_PREFIX))
                    }.getOrNull()
                }
                .toSet()
            _deniedScopes.value = denied
        }
    }

    override fun isHighRisk(scope: PermissionScope): Boolean = scope in highRiskScopes

    /** 某作用域当前是否允许（默认全部允许） */
    fun isAllowed(scope: PermissionScope): Boolean = scope !in _deniedScopes.value

    /** 开启/关闭某个权限作用域（持久化，立即生效） */
    suspend fun setAllowed(scope: PermissionScope, allowed: Boolean) {
        context.permissionDataStore.edit { prefs ->
            val key = booleanPreferencesKey("$DENIED_PREFIX${scope.name}")
            if (allowed) prefs.remove(key) else prefs[key] = true
        }
        _deniedScopes.value = if (allowed) {
            _deniedScopes.value - scope
        } else {
            _deniedScopes.value + scope
        }
    }

    /** 一键恢复全部权限默认开启 */
    suspend fun allowAll() {
        val deniedNames = _deniedScopes.value.map { "$DENIED_PREFIX${it.name}" }
        context.permissionDataStore.edit { prefs ->
            deniedNames.forEach { prefs.remove(booleanPreferencesKey(it)) }
        }
        _deniedScopes.value = emptySet()
    }

    override suspend fun check(request: PermissionRequest): PermissionResult {
        // 用户显式关闭的作用域：直接拒绝
        if (request.scope in _deniedScopes.value) {
            return PermissionResult(
                false,
                PermissionDecision.DENIED,
                request.scope,
                message = "权限「${request.scope.display}」已被用户关闭，请在权限管理页面重新开启",
            )
        }
        // 默认全部允许
        return PermissionResult(true, PermissionDecision.GRANTED, request.scope, GrantScope.FOREVER)
    }

    override suspend fun decide(request: PermissionRequest, decision: PermissionDecision, grantScope: GrantScope) {
        // 默认策略下不再产生待授权请求；保留接口实现以兼容调用方
        _pendingRequests.value = _pendingRequests.value.filterNot { it == request }
    }

    override suspend fun revoke(scope: PermissionScope, tabId: String?) {
        // 新模型按「作用域开关」管理（setAllowed），此处保留空实现以兼容接口
    }

    override suspend fun granted(): List<PermissionRequest> = emptyList()

    private companion object {
        const val DENIED_PREFIX = "denied:"
    }
}
