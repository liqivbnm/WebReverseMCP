package com.webreverse.mcp.core.common.model

import kotlinx.serialization.Serializable

/** MCP 客户端 */
@Serializable
data class McpClient(
    val id: String,
    val name: String,
    val transport: String,
    val remoteAddress: String,
    val connectedAt: Long = System.currentTimeMillis(),
    val lastActiveAt: Long = System.currentTimeMillis(),
    val protocolVersion: String = "2025-03-26",
    val capabilities: List<String> = emptyList(),
)

/** MCP 会话 */
@Serializable
data class McpSession(
    val id: String,
    val clientId: String,
    val clientName: String,
    val startedAt: Long = System.currentTimeMillis(),
    val endedAt: Long? = null,
    val toolCallCount: Int = 0,
    val status: McpSessionStatus = McpSessionStatus.ACTIVE,
)

@Serializable
enum class McpSessionStatus { ACTIVE, CLOSED, ERROR }

/** Tool 调用记录 */
@Serializable
data class ToolCallRecord(
    val id: String,
    val sessionId: String,
    val toolName: String,
    val arguments: String = "",
    val result: String = "",
    val isError: Boolean = false,
    val errorCode: String? = null,
    val durationMs: Long = 0,
    val timestamp: Long = System.currentTimeMillis(),
)

/** MCP Server 配置 */
@Serializable
data class McpServerConfig(
    /**
     * 服务器绑定地址。
     * 修复：原默认 "127.0.0.1" 只监听回环接口，局域网 AI 客户端连接
     * LAN IP（如 192.168.1.7:8787）时 TCP 直接被拒（Failed to connect）。
     * 现默认绑定 0.0.0.0 监听全部接口（回环 + WiFi + 热点），局域网可直连。
     * 客户端连接时仍用本机具体 IP（127.0.0.1 或局域网 IP），0.0.0.0 仅为绑定通配地址。
     */
    val host: String = "0.0.0.0",
    val port: Int = 8787,
    val enabled: Boolean = false,
    val lanOnly: Boolean = true,
    val ipAllowlist: List<String> = emptyList(),
    val maxConnections: Int = 16,
    /**
     * 是否强制 Token 认证（P0-1 安全）。
     * - true：HTTP MCP 入口必须携带合法 Token，否则 401，防止局域网暴露。
     * - false：仅当请求携带 Token 时校验（兼容不支持的客户端）。
     * 修复：原默认 null（自动）在绑定 0.0.0.0 时会强制认证，而 App 内无 Token
     * 展示入口、多数 AI 客户端不支持自定义请求头，导致局域网客户端全部 401 无法使用。
     * 现默认 false 保证开箱即连，用户可在 MCP Server 页面显式开启强制认证。
     */
    val requireAuth: Boolean? = false,
    /** 每客户端每分钟最大请求数（P0-1 速率限制，0 表示不限制） */
    val rateLimitPerMinute: Int = 0,
) {
    companion object {
        /** 默认端口 */
        const val DEFAULT_PORT: Int = 8787
    }
}
