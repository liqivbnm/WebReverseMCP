package com.webreverse.mcp.devtools.protocol.cdp

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * CDP 复用枢纽注册表：进程内 MCP 工具与 CDP 代理服务的汇合点。
 *
 * 背景：Chromium DevTools 服务对同一 target 的并发 WS 客户端兼容性因版本而异
 * （部分实现后连踢前连），MCP 调试会话与网络监视器各自直连同一页面会互相干扰。
 * CdpProxyServer 内置 CDP 复用枢纽（[CdpHubSession]）：同一 target 只保持一条
 * 后端 CDP 连接，MCP 工具（CdpDebuggerSession / CdpNetworkMonitor，经
 * [TcpWebSocket] 走 127.0.0.1 回环）都作为枢纽客户端接入，JSON-RPC id 由
 * 枢纽重写路由——调试器与网络监视器并存互不踢线。
 *
 * 模块依赖方向：mcp-server（代理服务）→ devtools-protocol（本对象）。
 * 代理服务启动后回填 [endpoint]，debugger/network 侧读它决定连接方式，
 * 避免反向依赖。
 */
object CdpHub {

    /** 枢纽端点（形如 "127.0.0.1:9222"），代理服务启动后设置；null = 未启动 */
    @Volatile
    var endpoint: String? = null
        private set

    /**
     * 确保枢纽已启动并返回端点。由宿主注入（AppContainer 注册
     * CdpProxyServer.ensureStarted），使 MCP 工具在代理未启动时也能拉起它。
     */
    @Volatile
    var ensureStarted: (suspend () -> String?)? = null

    /** 代理服务启动后注册端点（由 CdpProxyServer.ensureStarted 调用） */
    fun onStarted(value: String) {
        endpoint = value
    }

    /** 代理服务停止时清空端点（由 CdpProxyServer.stop 调用） */
    fun onProxyStopped() {
        endpoint = null
        statusProvider = null
        resumeProvider = null
    }

    /**
     * 状态提供者：由 CdpProxyServer 注册，mcp.status 读取
     * （各枢纽的客户端连接数、暂停态，跨模块且不引入反向依赖）。
     */
    @Volatile
    var statusProvider: (() -> List<Map<String, Any>>)? = null

    /** 当前枢纽状态快照（代理未启动时为空表） */
    fun linkageStatus(): List<Map<String, Any>> = statusProvider?.invoke() ?: emptyList()

    /**
     * 放行提供者：由 CdpProxyServer 注册（resumePaused），App UI 暂停
     * 提示条与 MCP debugger.resume 兜底经它恢复暂停页面。
     */
    @Volatile
    var resumeProvider: (() -> Int)? = null

    /** 是否有 CDP 会话处于暂停态（App UI 轮询显示暂停提示条） */
    fun anyPaused(): Boolean = linkageStatus().any { it["paused"] == true }

    /**
     * 恢复所有暂停中的 CDP 会话（放行）。
     * @return 实际恢复的会话数（0 = 无暂停或代理未启动）
     */
    fun resumePausedSessions(): Int = resumeProvider?.invoke() ?: 0

    /**
     * 经枢纽连接指定 target：多个 MCP 会话共享同一条后端 CDP 连接。
     * 枢纽不可用/连接失败返回 null，调用方回退直连（LocalSocket）。
     *
     * 路径追加 ?client=mcp 标记：代理侧据此把本连接归类为 MCP 客户端
     * （断开时仅撤销自身断点；非 MCP 客户端断开则额外触发暂停自动恢复等语义）。
     *
     * @param wsPath 形如 "/devtools/page/{targetId}"
     */
    suspend fun connectViaHub(wsPath: String): TcpWebSocket? {
        val ep = endpoint ?: ensureStarted?.invoke()?.also { endpoint = it } ?: endpoint
        if (ep.isNullOrBlank()) return null
        val path = if (wsPath.contains('?')) wsPath else "$wsPath?client=mcp"
        return withContext(Dispatchers.IO) { TcpWebSocket.connect(ep, path) }
    }
}
