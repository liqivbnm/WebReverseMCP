package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.common.model.AnalysisResult
import com.webreverse.mcp.core.common.model.Confidence
import com.webreverse.mcp.core.common.model.Finding
import com.webreverse.mcp.core.common.model.FindingType
import com.webreverse.mcp.core.common.model.Severity
import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.common.util.Ids
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import kotlinx.coroutines.flow.first
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** Workspace Tools：项目工作区管理 */
object WorkspaceTools {

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)
        return listOf(
            f.tool(
                "workspace.list", "列出所有工作区", ToolCategory.WORKSPACE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val workspaces = deps.workspaceManager.getWorkspaces()
                McpToolResult.json(
                    buildJsonObject {
                        put(
                            "workspaces",
                            JsonArray(
                                workspaces.map { w ->
                                    buildJsonObject {
                                        put("id", JsonPrimitive(w.id))
                                        put("name", JsonPrimitive(w.name))
                                        put("description", JsonPrimitive(w.description))
                                        put("targetUrl", JsonPrimitive(w.targetUrl))
                                        put("createdAt", JsonPrimitive(w.createdAt))
                                    }
                                },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "workspace.create", "创建工作区", ToolCategory.WORKSPACE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "name" to Schemas.strSchema("工作区名称"),
                    "description" to Schemas.strSchema("描述"),
                    "targetUrl" to Schemas.strSchema("目标 URL"),
                ),
            ) { args ->
                val name = ToolArgs.str(args, "name")
                val description = ToolArgs.str(args, "description")
                val targetUrl = ToolArgs.str(args, "targetUrl")
                if (name.isBlank()) return@tool McpToolResult.error("INVALID_ARGUMENTS", "name 不能为空")
                val workspace = deps.workspaceManager.createWorkspace(name, description, targetUrl)
                McpToolResult.json(
                    buildJsonObject {
                        put("id", JsonPrimitive(workspace.id))
                        put("name", JsonPrimitive(workspace.name))
                    },
                )
            },
            f.tool(
                "workspace.get", "获取工作区详情", ToolCategory.WORKSPACE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("workspaceId" to Schemas.strSchema("工作区 ID")),
            ) { args ->
                val workspaceId = ToolArgs.str(args, "workspaceId")
                val workspace = deps.workspaceManager.getWorkspace(workspaceId)
                    ?: return@tool McpToolResult.error("WORKSPACE_NOT_FOUND", "未找到工作区: $workspaceId")
                McpToolResult.json(
                    buildJsonObject {
                        put("id", JsonPrimitive(workspace.id))
                        put("name", JsonPrimitive(workspace.name))
                        put("description", JsonPrimitive(workspace.description))
                        put("targetUrl", JsonPrimitive(workspace.targetUrl))
                    },
                )
            },
            f.tool(
                "workspace.delete", "删除工作区", ToolCategory.WORKSPACE,
                PermissionScope.READ_PAGE, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema("workspaceId" to Schemas.strSchema("工作区 ID")),
            ) { args ->
                val workspaceId = ToolArgs.str(args, "workspaceId")
                deps.workspaceManager.deleteWorkspace(workspaceId)
                McpToolResult.text("已删除工作区: $workspaceId")
            },
            f.tool(
                "workspace.add_finding", "添加分析发现", ToolCategory.WORKSPACE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "workspaceId" to Schemas.strSchema("工作区 ID"),
                    "type" to Schemas.strSchema("类型：API/FUNCTION/OBFUSCATION/SECURITY 等"),
                    "title" to Schemas.strSchema("标题"),
                    "description" to Schemas.strSchema("描述"),
                    "severity" to Schemas.strSchema("严重程度：INFO/LOW/MEDIUM/HIGH/CRITICAL"),
                    "evidence" to Schemas.strSchema("证据"),
                    "source" to Schemas.strSchema("来源文件"),
                    "line" to Schemas.intSchema("行号"),
                    "confidence" to Schemas.strSchema("置信度：LOW/MEDIUM/HIGH/CONFIRMED"),
                ),
            ) { args ->
                val workspaceId = ToolArgs.str(args, "workspaceId")
                val title = ToolArgs.str(args, "title")
                val description = ToolArgs.str(args, "description")
                val severity = runCatching { Severity.valueOf(ToolArgs.str(args, "severity", "INFO").uppercase()) }
                    .getOrDefault(Severity.INFO)
                val evidence = ToolArgs.str(args, "evidence")
                val source = ToolArgs.str(args, "source")
                val line = ToolArgs.int(args, "line")
                val confidence = runCatching { Confidence.valueOf(ToolArgs.str(args, "confidence", "MEDIUM").uppercase()) }
                    .getOrDefault(Confidence.MEDIUM)
                val type = runCatching { FindingType.valueOf(ToolArgs.str(args, "type", "INTERESTING").uppercase()) }
                    .getOrDefault(FindingType.INTERESTING)
                val finding = Finding(
                    id = Ids.uuid(),
                    workspaceId = workspaceId,
                    type = type,
                    title = title,
                    description = description,
                    evidence = evidence,
                    source = source,
                    line = line,
                    confidence = confidence,
                    severity = severity,
                )
                val entity = deps.workspaceManager.addFinding(finding)
                McpToolResult.json(
                    buildJsonObject {
                        put("id", JsonPrimitive(entity.id))
                        put("title", JsonPrimitive(entity.title))
                    },
                )
            },
            f.tool(
                "workspace.list_findings", "列出工作区发现", ToolCategory.WORKSPACE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("workspaceId" to Schemas.strSchema("工作区 ID")),
            ) { args ->
                val workspaceId = ToolArgs.str(args, "workspaceId")
                val findings = deps.workspaceManager.observeFindings(workspaceId).first()
                McpToolResult.json(
                    buildJsonObject {
                        put(
                            "findings",
                            JsonArray(
                                findings.map { fn ->
                                    buildJsonObject {
                                        put("id", JsonPrimitive(fn.id))
                                        put("title", JsonPrimitive(fn.title))
                                        put("description", JsonPrimitive(fn.description))
                                        put("severity", JsonPrimitive(fn.severity))
                                        put("confidence", JsonPrimitive(fn.confidence))
                                        put("type", JsonPrimitive(fn.type))
                                    }
                                },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "workspace.add_note", "添加笔记", ToolCategory.WORKSPACE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "workspaceId" to Schemas.strSchema("工作区 ID"),
                    "title" to Schemas.strSchema("笔记标题"),
                    "content" to Schemas.strSchema("笔记内容"),
                ),
            ) { args ->
                val workspaceId = ToolArgs.str(args, "workspaceId")
                val title = ToolArgs.str(args, "title", "Note")
                val content = ToolArgs.str(args, "content")
                val note = deps.workspaceManager.addNote(workspaceId, title, content)
                McpToolResult.json(
                    buildJsonObject {
                        put("id", JsonPrimitive(note.id))
                        put("title", JsonPrimitive(note.title))
                    },
                )
            },
            f.tool(
                "workspace.list_notes", "列出工作区笔记", ToolCategory.WORKSPACE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("workspaceId" to Schemas.strSchema("工作区 ID")),
            ) { args ->
                val workspaceId = ToolArgs.str(args, "workspaceId")
                val notes = deps.workspaceManager.observeNotes(workspaceId).first()
                McpToolResult.json(
                    buildJsonObject {
                        put(
                            "notes",
                            JsonArray(
                                notes.map { n ->
                                    buildJsonObject {
                                        put("id", JsonPrimitive(n.id))
                                        put("title", JsonPrimitive(n.title))
                                        put("content", JsonPrimitive(n.content.take(500)))
                                        put("createdAt", JsonPrimitive(n.createdAt))
                                    }
                                },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "workspace.save_analysis", "保存分析结果", ToolCategory.WORKSPACE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "workspaceId" to Schemas.strSchema("工作区 ID"),
                    "type" to Schemas.strSchema("分析类型"),
                    "title" to Schemas.strSchema("标题"),
                    "summary" to Schemas.strSchema("摘要"),
                    "content" to Schemas.strSchema("分析内容"),
                    "confidence" to Schemas.doubleSchema("置信度 0-1"),
                ),
            ) { args ->
                val workspaceId = ToolArgs.str(args, "workspaceId")
                val type = ToolArgs.str(args, "type", "analysis")
                val title = ToolArgs.str(args, "title", "Analysis")
                val summary = ToolArgs.str(args, "summary")
                val content = ToolArgs.str(args, "content")
                val confidence = ToolArgs.double(args, "confidence")
                val result = AnalysisResult(
                    id = Ids.uuid(),
                    workspaceId = workspaceId,
                    type = type,
                    title = title,
                    summary = summary,
                    content = content,
                    confidence = confidence,
                )
                val entity = deps.workspaceManager.saveAnalysis(result)
                McpToolResult.json(
                    buildJsonObject {
                        put("id", JsonPrimitive(entity.id))
                        put("type", JsonPrimitive(entity.type))
                    },
                )
            },
            f.tool(
                "workspace.list_analysis", "列出工作区分析结果", ToolCategory.WORKSPACE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("workspaceId" to Schemas.strSchema("工作区 ID")),
            ) { args ->
                val workspaceId = ToolArgs.str(args, "workspaceId")
                val results = deps.workspaceManager.observeAnalysis(workspaceId).first()
                McpToolResult.json(
                    buildJsonObject {
                        put(
                            "results",
                            JsonArray(
                                results.map { r ->
                                    buildJsonObject {
                                        put("id", JsonPrimitive(r.id))
                                        put("type", JsonPrimitive(r.type))
                                        put("title", JsonPrimitive(r.title))
                                        put("createdAt", JsonPrimitive(r.createdAt))
                                    }
                                },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "workspace.add_target", "添加分析目标", ToolCategory.WORKSPACE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "name" to Schemas.strSchema("目标名称"),
                    "url" to Schemas.strSchema("目标 URL"),
                    "framework" to Schemas.strSchema("框架"),
                ),
            ) { args ->
                val name = ToolArgs.str(args, "name")
                val url = ToolArgs.str(args, "url")
                val framework = ToolArgs.optStr(args, "framework")
                val target = deps.workspaceManager.addTarget(name, url, framework)
                McpToolResult.json(
                    buildJsonObject {
                        put("id", JsonPrimitive(target.id))
                        put("name", JsonPrimitive(target.name))
                        put("url", JsonPrimitive(target.url))
                    },
                )
            },
            f.tool(
                "workspace.list_targets", "列出分析目标", ToolCategory.WORKSPACE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val targets = deps.workspaceManager.getTargets()
                McpToolResult.json(
                    buildJsonObject {
                        put(
                            "targets",
                            JsonArray(
                                targets.map { t ->
                                    buildJsonObject {
                                        put("id", JsonPrimitive(t.id))
                                        put("name", JsonPrimitive(t.name))
                                        put("url", JsonPrimitive(t.url))
                                        put("framework", JsonPrimitive(t.framework ?: ""))
                                    }
                                },
                            ),
                        )
                    },
                )
            },
        )
    }
}
