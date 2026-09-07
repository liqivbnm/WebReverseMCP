package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.database.entity.UserScriptEntity
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.util.UUID

/**
 * User Script Tools：用户脚本管理。
 *
 * 让 AI 能直接创建/编辑/启停/删除 App 的「用户脚本」。
 * 创建后脚本会出现在 App 的「脚本」页面，可按运行时机（runAt）注入网页执行，
 * 与手动在脚本页面创建完全等价。
 */
object UserScriptTools {

    private val VALID_RUN_AT = setOf(
        "MANUAL", "PAGE_START", "DOM_READY", "AFTER_LOAD", "BEFORE_REQUEST", "AFTER_REQUEST",
    )

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)
        val repo = deps.userScriptRepository
        return listOf(
            // ---------- 创建 ----------
            f.tool(
                "user_script.create", "创建用户脚本（创建后出现在 App 脚本页面，可按运行时机注入网页执行）", ToolCategory.JAVASCRIPT,
                PermissionScope.EXECUTE_JS, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "name" to Schemas.strSchema("脚本名称（必填）"),
                    "code" to Schemas.strSchema("脚本 JS 代码（必填）"),
                    "description" to Schemas.strSchema("描述"),
                    "runAt" to Schemas.strSchema("运行时机：MANUAL/PAGE_START/DOM_READY/AFTER_LOAD/BEFORE_REQUEST/AFTER_REQUEST，默认 MANUAL"),
                    "matchPatterns" to Schemas.arraySchema("匹配的 URL 模式数组，如 [\"*://*.example.com/*\"]"),
                ),
            ) { args ->
                val name = ToolArgs.str(args, "name")
                val code = ToolArgs.str(args, "code")
                if (name.isBlank()) return@tool McpToolResult.error("INVALID_ARGUMENTS", "name 不能为空")
                if (code.isBlank()) return@tool McpToolResult.error("INVALID_ARGUMENTS", "code 不能为空")
                val runAt = ToolArgs.str(args, "runAt", "MANUAL")
                if (runAt !in VALID_RUN_AT) {
                    return@tool McpToolResult.error("INVALID_ARGUMENTS", "runAt 无效: $runAt，可选: ${VALID_RUN_AT.joinToString()}")
                }
                val now = System.currentTimeMillis()
                val entity = UserScriptEntity(
                    id = UUID.randomUUID().toString(),
                    name = name,
                    description = ToolArgs.str(args, "description"),
                    code = code,
                    runAt = runAt,
                    matchPatterns = parseMatchPatterns(args["matchPatterns"]),
                    enabled = true,
                    createdAt = now,
                    updatedAt = now,
                )
                repo.upsert(entity)
                McpToolResult.json(
                    buildJsonObject {
                        put("id", JsonPrimitive(entity.id))
                        put("name", JsonPrimitive(entity.name))
                        put("runAt", JsonPrimitive(entity.runAt))
                        put("enabled", JsonPrimitive(entity.enabled))
                        put("message", JsonPrimitive("用户脚本已创建，可在 App 脚本页面查看"))
                    },
                )
            },

            // ---------- 列表 ----------
            f.tool(
                "user_script.list", "列出所有用户脚本（概要，不含代码）", ToolCategory.JAVASCRIPT,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val scripts = repo.getAll()
                McpToolResult.json(
                    buildJsonObject {
                        put(
                            "scripts",
                            JsonArray(
                                scripts.map { s ->
                                    buildJsonObject {
                                        put("id", JsonPrimitive(s.id))
                                        put("name", JsonPrimitive(s.name))
                                        put("description", JsonPrimitive(s.description))
                                        put("runAt", JsonPrimitive(s.runAt))
                                        put("enabled", JsonPrimitive(s.enabled))
                                        put("createdAt", JsonPrimitive(s.createdAt))
                                        put("updatedAt", JsonPrimitive(s.updatedAt))
                                    }
                                },
                            ),
                        )
                        put("count", JsonPrimitive(scripts.size))
                    },
                )
            },

            // ---------- 详情 ----------
            f.tool(
                "user_script.get", "获取用户脚本详情（含代码）", ToolCategory.JAVASCRIPT,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("id" to Schemas.strSchema("脚本 ID")),
            ) { args ->
                val id = ToolArgs.str(args, "id")
                if (id.isBlank()) return@tool McpToolResult.error("INVALID_ARGUMENTS", "id 不能为空")
                val s = repo.getById(id)
                    ?: return@tool McpToolResult.error("SCRIPT_NOT_FOUND", "未找到用户脚本: $id")
                McpToolResult.json(
                    buildJsonObject {
                        put("id", JsonPrimitive(s.id))
                        put("name", JsonPrimitive(s.name))
                        put("description", JsonPrimitive(s.description))
                        put("code", JsonPrimitive(s.code))
                        put("runAt", JsonPrimitive(s.runAt))
                        put("matchPatterns", JsonPrimitive(s.matchPatterns))
                        put("enabled", JsonPrimitive(s.enabled))
                        put("createdAt", JsonPrimitive(s.createdAt))
                        put("updatedAt", JsonPrimitive(s.updatedAt))
                    },
                )
            },

            // ---------- 更新 ----------
            f.tool(
                "user_script.update", "更新用户脚本（仅更新传入的字段，其余保持不变）", ToolCategory.JAVASCRIPT,
                PermissionScope.EXECUTE_JS, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "id" to Schemas.strSchema("脚本 ID（必填）"),
                    "name" to Schemas.strSchema("新名称"),
                    "description" to Schemas.strSchema("新描述"),
                    "code" to Schemas.strSchema("新 JS 代码"),
                    "runAt" to Schemas.strSchema("新运行时机"),
                    "matchPatterns" to Schemas.arraySchema("新匹配 URL 模式数组"),
                ),
            ) { args ->
                val id = ToolArgs.str(args, "id")
                if (id.isBlank()) return@tool McpToolResult.error("INVALID_ARGUMENTS", "id 不能为空")
                val existing = repo.getById(id)
                    ?: return@tool McpToolResult.error("SCRIPT_NOT_FOUND", "未找到用户脚本: $id")
                val runAt = ToolArgs.str(args, "runAt")
                if (runAt.isNotBlank() && runAt !in VALID_RUN_AT) {
                    return@tool McpToolResult.error("INVALID_ARGUMENTS", "runAt 无效: $runAt，可选: ${VALID_RUN_AT.joinToString()}")
                }
                val updated = existing.copy(
                    name = ToolArgs.str(args, "name").ifBlank { existing.name },
                    description = ToolArgs.str(args, "description").ifBlank { existing.description },
                    code = ToolArgs.str(args, "code").ifBlank { existing.code },
                    runAt = runAt.ifBlank { existing.runAt },
                    matchPatterns = if (args["matchPatterns"] != null) parseMatchPatterns(args["matchPatterns"]) else existing.matchPatterns,
                    updatedAt = System.currentTimeMillis(),
                )
                repo.upsert(updated)
                McpToolResult.json(
                    buildJsonObject {
                        put("id", JsonPrimitive(updated.id))
                        put("name", JsonPrimitive(updated.name))
                        put("runAt", JsonPrimitive(updated.runAt))
                        put("message", JsonPrimitive("用户脚本已更新"))
                    },
                )
            },

            // ---------- 删除 ----------
            f.tool(
                "user_script.delete", "删除用户脚本", ToolCategory.JAVASCRIPT,
                PermissionScope.EXECUTE_JS, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema("id" to Schemas.strSchema("脚本 ID")),
            ) { args ->
                val id = ToolArgs.str(args, "id")
                if (id.isBlank()) return@tool McpToolResult.error("INVALID_ARGUMENTS", "id 不能为空")
                val s = repo.getById(id)
                    ?: return@tool McpToolResult.error("SCRIPT_NOT_FOUND", "未找到用户脚本: $id")
                repo.delete(s)
                McpToolResult.text("已删除用户脚本: ${s.name} ($id)")
            },

            // ---------- 启停 ----------
            f.tool(
                "user_script.set_enabled", "启用/停用用户脚本", ToolCategory.JAVASCRIPT,
                PermissionScope.EXECUTE_JS, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "id" to Schemas.strSchema("脚本 ID"),
                    "enabled" to Schemas.boolSchema("是否启用"),
                ),
            ) { args ->
                val id = ToolArgs.str(args, "id")
                if (id.isBlank()) return@tool McpToolResult.error("INVALID_ARGUMENTS", "id 不能为空")
                if (repo.getById(id) == null) return@tool McpToolResult.error("SCRIPT_NOT_FOUND", "未找到用户脚本: $id")
                val enabled = ToolArgs.bool(args, "enabled")
                repo.setEnabled(id, enabled)
                McpToolResult.json(
                    buildJsonObject {
                        put("id", JsonPrimitive(id))
                        put("enabled", JsonPrimitive(enabled))
                        put("message", JsonPrimitive(if (enabled) "用户脚本已启用" else "用户脚本已停用"))
                    },
                )
            },
        )
    }

    /**
     * 解析 matchPatterns 参数为 JSON 字符串（存储格式）。
     * 支持：JSON 数组（元素为 URL 通配模式）或逗号分隔字符串。
     */
    private fun parseMatchPatterns(raw: JsonElement?): String {
        val patterns = when (raw) {
            is JsonArray -> raw.mapNotNull { (it as? JsonPrimitive)?.content }
            is JsonPrimitive -> raw.content
                .split(',')
                .map { it.trim() }
                .filter { it.isNotBlank() }
            else -> emptyList()
        }
        return JsonArray(patterns.map { JsonPrimitive(it) }).toString()
    }
}
