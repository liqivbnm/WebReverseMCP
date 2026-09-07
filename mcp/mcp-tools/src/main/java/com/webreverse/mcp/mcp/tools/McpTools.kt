package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** MCP Tools：MCP Server 自身管理 */
object McpTools {

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)
        return listOf(
            f.tool(
                "mcp.status", "获取 MCP Server 状态（含 CDP 枢纽会话、后端、断点数）", ToolCategory.MCP,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val linkage = com.webreverse.mcp.devtools.protocol.cdp.CdpHub.linkageStatus()
                val anyPaused = linkage.any { it["paused"] == true }
                McpToolResult.json(
                    buildJsonObject {
                        put("server", JsonPrimitive("WebReverse MCP Server"))
                        put("protocol", JsonPrimitive("2025-03-26"))
                        // 同时给出可见数（当前模式）与注册总数
                        put("toolCount", JsonPrimitive(deps.toolRegistry.visibleCount()))
                        put("registeredTools", JsonPrimitive(deps.toolRegistry.count()))
                        put("hubMode", JsonPrimitive(deps.toolRegistry.hubMode))
                        put("transport", JsonPrimitive("Streamable HTTP"))
                        put("debuggerBackend", JsonPrimitive(deps.debuggerManager.backend))
                        put("debuggerState", JsonPrimitive(deps.debuggerManager.state.value.name))
                        put(
                            "cdpHubs",
                            JsonArray(
                                linkage.map { l ->
                                    buildJsonObject {
                                        put("target", JsonPrimitive(l["target"]?.toString() ?: ""))
                                        put("connected", JsonPrimitive(l["connected"] == true))
                                        put("mcpClients", JsonPrimitive((l["mcpClients"] as? Int) ?: 0))
                                        put("paused", JsonPrimitive(l["paused"] == true))
                                    }
                                },
                            ),
                        )
                        put(
                            "hint",
                            JsonPrimitive(
                                buildString {
                                    if (linkage.isEmpty()) {
                                        append("无活跃 CDP 会话（debugger.attach 后建立）")
                                    } else {
                                        append("CDP 复用枢纽工作中（多会话共享后端连接）")
                                        if (anyPaused) append("；当前页面处于暂停态（debugger.resume 或界面放行按钮恢复）")
                                    }
                                    val cdpNet = com.webreverse.mcp.devtools.network.CdpNetworkMonitor
                                    if (cdpNet.isIntercepting) {
                                        append("；注意：请求拦截开启中（${cdpNet.pausedRequests.value.size} 个请求暂停待决策，network.paused_requests 处理或 network.intercept enabled=false 关闭）")
                                    }
                                },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "mcp.tools", "列出所有可用 MCP 工具", ToolCategory.MCP,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val tools = deps.toolRegistry.listMetadata()
                McpToolResult.json(
                    buildJsonObject {
                        put("count", JsonPrimitive(tools.size))
                        put(
                            "tools",
                            JsonArray(
                                tools.map { t ->
                                    buildJsonObject {
                                        put("name", JsonPrimitive(t.name))
                                        put("description", JsonPrimitive(t.description))
                                        put("category", JsonPrimitive(t.category.name))
                                        put("permission", JsonPrimitive(t.permission.name))
                                        put("riskLevel", JsonPrimitive(t.riskLevel.name))
                                        put("timeoutMs", JsonPrimitive(t.timeoutMs))
                                        put("supportsImage", JsonPrimitive(t.supportsImage))
                                        put("supportsStreaming", JsonPrimitive(t.supportsStreaming))
                                    }
                                },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "mcp.tool_schema", "获取工具 JSON Schema", ToolCategory.MCP,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("name" to Schemas.strSchema("工具名")),
            ) { args ->
                val name = ToolArgs.str(args, "name")
                val tool = deps.toolRegistry.get(name)
                    ?: return@tool McpToolResult.error("TOOL_NOT_FOUND", "未找到工具: $name")
                McpToolResult.json(
                    buildJsonObject {
                        // 对客户端统一返回 MCP 规范的下划线名（与 tools/list 一致）
                        put("name", JsonPrimitive(com.webreverse.mcp.core.mcp.ToolRegistry.normalizeName(tool.metadata.name)))
                        put("description", JsonPrimitive(tool.metadata.description))
                        put("inputSchema", tool.metadata.inputSchema)
                        put("category", JsonPrimitive(tool.metadata.category.name))
                        put("permission", JsonPrimitive(tool.metadata.permission.name))
                        put("riskLevel", JsonPrimitive(tool.metadata.riskLevel.name))
                    },
                )
            },
        )
    }
}
