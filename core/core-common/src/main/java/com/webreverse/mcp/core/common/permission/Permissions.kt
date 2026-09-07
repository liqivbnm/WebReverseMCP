package com.webreverse.mcp.core.common.permission

import kotlinx.serialization.Serializable

/** 权限作用域 */
@Serializable
enum class PermissionScope(val display: String) {
    READ_PAGE("读取页面"),
    EXECUTE_JS("执行 JavaScript"),
    READ_DOM("读取 DOM"),
    READ_NETWORK("读取网络"),
    MODIFY_NETWORK("修改网络"),
    READ_STORAGE("读取存储"),
    MODIFY_STORAGE("修改存储"),
    DEBUG_SCRIPT("调试脚本"),
    INSTALL_HOOK("安装 Hook"),
    MODIFY_PAGE("修改页面"),
    READ_COOKIES("读取 Cookie"),
    READ_HEADERS("读取请求头"),
    SCREENSHOT("截图"),
    DOWNLOAD("下载"),
    UPLOAD("上传"),
    READ_WORKSPACE("读取工作区"),
    WRITE_WORKSPACE("写入工作区"),
    READ_FILE("读取文件"),
    WRITE_FILE("写入文件"),
    CONTROL_MCP("控制 MCP Server"),
}

/** 风险等级 */
@Serializable
enum class RiskLevel(val display: String, val score: Int) {
    LOW("低", 1),
    MEDIUM("中", 2),
    HIGH("高", 3),
    CRITICAL("极高", 4),
}

/** 授权决定 */
@Serializable
enum class PermissionDecision {
    GRANTED,
    DENIED,
    PENDING_USER,
}

/** 授权范围 */
@Serializable
enum class GrantScope {
    ONCE,
    CURRENT_SITE,
    CURRENT_TAB,
    FOREVER,
}

/** 权限请求 */
@Serializable
data class PermissionRequest(
    val scope: PermissionScope,
    val tabId: String? = null,
    val url: String? = null,
    val reason: String = "",
    val agentName: String = "AI Agent",
)

/** 权限结果 */
@Serializable
data class PermissionResult(
    val granted: Boolean,
    val decision: PermissionDecision,
    val scope: PermissionScope,
    val grantScope: GrantScope = GrantScope.ONCE,
    val redacted: Boolean = false,
    val message: String = "",
)

/** 权限管理器接口 */
interface PermissionManager {
    /** 检查权限，未授权则返回 PENDING_USER */
    suspend fun check(request: PermissionRequest): PermissionResult
    /** 用户做出决定 */
    suspend fun decide(request: PermissionRequest, decision: PermissionDecision, grantScope: GrantScope)
    /** 撤销某范围权限 */
    suspend fun revoke(scope: PermissionScope, tabId: String? = null)
    /** 列出已授权权限 */
    suspend fun granted(): List<PermissionRequest>
    /** 是否高风险操作 */
    fun isHighRisk(scope: PermissionScope): Boolean
}
