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

/** System Tools：系统信息、日志、健康检查 */
object SystemTools {

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)
        return listOf(
            f.tool(
                "system.info", "获取系统信息", ToolCategory.SYSTEM,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                McpToolResult.json(
                    buildJsonObject {
                        put("app", JsonPrimitive("WebReverse MCP"))
                        put("version", JsonPrimitive("1.0.0"))
                        put("platform", JsonPrimitive("Android"))
                        put("minSdk", JsonPrimitive(26))
                        put("protocol", JsonPrimitive("MCP 2025-03-26"))
                        put("toolCount", JsonPrimitive(deps.toolRegistry.count()))
                    },
                )
            },
            f.tool(
                "system.logs", "读取系统日志", ToolCategory.SYSTEM,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "category" to Schemas.strSchema("日志分类"),
                    "limit" to Schemas.intSchema("数量上限"),
                ),
            ) { args ->
                val category = ToolArgs.str(args, "category")
                val limit = ToolArgs.int(args, "limit", 100)
                val logs = deps.logger.entries.value
                val filtered = if (category.isBlank()) logs else logs.filter { it.category.tag.contains(category, ignoreCase = true) || it.message.contains(category, ignoreCase = true) }
                McpToolResult.json(
                    buildJsonObject {
                        put(
                            "logs",
                            JsonArray(
                                filtered.takeLast(limit).map { JsonPrimitive("[${it.timestamp}] [${it.category.tag}] [${it.level}] ${it.message}") },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "system.clear_logs", "清空日志", ToolCategory.SYSTEM,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                deps.logger.clear()
                McpToolResult.text("日志已清空")
            },
        )
    }
}
