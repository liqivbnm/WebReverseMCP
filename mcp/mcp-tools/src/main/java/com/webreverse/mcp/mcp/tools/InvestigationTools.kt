package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.common.model.FindingType
import com.webreverse.mcp.core.common.model.Confidence
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.put
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * 逆向调查引擎（P0-3/P0-4 重写）。
 *
 * 相比 的两处关键修正：
 *
 * 1. **调查主键从 sessionId 解耦为 investigationId**（P0-3）
 *    用 `ConcurrentHashMap<sessionId, ReverseInvestigation>`，导致「一个 MCP Session
 *    只能存在一个调查」，后启动的会覆盖前者。现改为以 investigationId 为主键：
 *    ```
 *    investigations: Map<investigationId, ReverseInvestigation>
 *    sessionToInvestigations: Map<sessionId, List<investigationId>>
 *    ```
 *    一个 Agent 可在同一会话并发跟踪多个调查（/api/login、/api/search、token ...），
 *    恢复 `Agent ─ 会话 ─ 多个调查` 的正确层级。
 *
 * 2. **阶段状态机升级为 8 态，人工阶段不再自动 SKIPPED**（P0-4）
 *    中 `stage.pipeline == null` 直接置为 SKIPPED，导致「Hook 根本没做、
 *    Breakpoint 没做，但 investigation 显示 all_done」的假完成状态。
 *    现改为：人工阶段推进到 `WAITING_INPUT`（携带 requiredAction），
 *    由 Agent 完成外部动作后调用 `investigation.action_done` 显式标记 DONE，
 *    系统随后自动推进后续流水线阶段（事件驱动的半自动编排）。
 *
 * 阶段状态机：
 * ```
 * PENDING → READY → RUNNING → DONE
 *               ↘ (人工阶段) WAITING_INPUT --action_done--> DONE
 * RUNNING --异常--> FAILED ；任意时刻可 CANCELLED
 * ```
 */
object InvestigationTools {

    // ================================================================
    // 状态模型
    // ================================================================

    enum class Goal(val display: String) {
        REVERSE_API("还原接口完整请求链（定位签名/参数来源）"),
        SIGNATURE_ANALYSIS("定位签名算法并验证输入输出"),
        TOKEN_TRACE("追踪令牌的生成/消费位置"),
        GENERAL_RECON("页面全景侦察与能力盘点"),
    }

    /** 8 态阶段状态机 */
    enum class StageStatus {
        PENDING,      // 尚未到它
        READY,        // 可以开始（前驱已完成）
        RUNNING,      // 流水线执行中
        WAITING_INPUT,  // 需要 Agent 完成外部动作（hook/断点/手动复现）
        WAITING_EVENT,  // 等待运行时事件（如 Hook 命中触发的自动证据回填）
        DONE,         // 已完成
        FAILED,       // 执行异常
        CANCELLED,    // 已取消
    }

    /** 调查中的一个阶段 */
    data class InvestigationStage(
        val name: String,
        val description: String,
        /** 对应可自动驱动的内置流水线名；null 表示需外部动作配合 */
        val pipeline: String?,
        /** 人工阶段的下一步指引 */
        val toolHint: String? = null,
        /** 人工阶段需要执行的动作说明（requiredAction） */
        val requiredAction: String = "",
        var status: StageStatus = StageStatus.PENDING,
        var detail: String = "",
        var confidence: Double = 0.0,
    )

    /** 一次逆向调查（主键 = investigationId） */
    class ReverseInvestigation(
        val id: String,
        val mcpSessionId: String,
        val goal: Goal,
        val target: String,
        val workspaceId: String? = null,
        val targetId: String? = null,
        val createdAt: Long = System.currentTimeMillis(),
    ) {
        val stages = mutableListOf<InvestigationStage>()
        var status: StageStatus = StageStatus.PENDING
        var summary: String = ""
        var bestCandidate: String = ""
        var bestConfidence: Double = 0.0
        var updatedAt: Long = createdAt

        val doneCount: Int get() = stages.count { it.status == StageStatus.DONE }
        val totalCount: Int get() = stages.size
        val currentStage: InvestigationStage? get() = stages.firstOrNull { it.status in ACTIVE }
        val blockedCount: Int get() = stages.count { it.status in listOf(StageStatus.FAILED, StageStatus.WAITING_INPUT, StageStatus.WAITING_EVENT) }

        fun stageByName(name: String): InvestigationStage? = stages.firstOrNull { it.name == name }

        /** 下一个可推进阶段（READY 优先，其次 PENDING） */
        val nextStage: InvestigationStage? get() =
            stages.firstOrNull { it.status == StageStatus.READY } ?: stages.firstOrNull { it.status == StageStatus.PENDING }

        fun refreshStatus() {
            val failed = stages.any { it.status == StageStatus.FAILED }
            val hasActive = stages.any { it.status in ACTIVE }
            status = when {
                failed -> StageStatus.FAILED
                hasActive -> StageStatus.RUNNING
                else -> StageStatus.DONE
            }
            updatedAt = System.currentTimeMillis()
        }

        companion object {
            val ACTIVE = setOf(
                StageStatus.PENDING, StageStatus.READY, StageStatus.RUNNING,
                StageStatus.WAITING_INPUT, StageStatus.WAITING_EVENT,
            )
        }
    }

    // ================================================================
    // 存储：以 investigationId 为主键；会话→调查列表做索引
    // ================================================================

    private val investigations = ConcurrentHashMap<String, ReverseInvestigation>()
    private val sessionToInvestigations = ConcurrentHashMap<String, MutableList<String>>()
    private val MAX_INVESTIGATIONS = 128

    fun byId(id: String): ReverseInvestigation? = investigations[id]

    /** 按会话取调查（按创建时间升序，最近的在后） */
    fun forSession(sessionId: String): List<ReverseInvestigation> =
        sessionToInvestigations[sessionId]?.mapNotNull { investigations[it] }?.sortedBy { it.createdAt }
            ?: emptyList()

    fun all(): List<ReverseInvestigation> = investigations.values.sortedByDescending { it.createdAt }

    /** 解析调查：优先 investigationId，其次该会话最近一次调查 */
    private suspend fun resolveInvestigation(
        deps: ToolDependencies,
        args: JsonObject,
    ): ReverseInvestigation? {
        val invId = args["investigationId"]?.let { (it as? JsonPrimitive)?.content }
        if (!invId.isNullOrBlank()) return byId(invId)
        val sessionId = deps.context()?.sessionId ?: "default"
        return forSession(sessionId).lastOrNull()
    }

    // ================================================================
    // MCP 工具
    // ================================================================

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)
        return listOf(
            f.tool(
                "investigation.start", "启动一次逆向调查（investigationId 为主键，同一会话可并行多个调查）：给定 goal+target，自动生成阶段计划并自动推进到首个人工阶段", ToolCategory.REVERSE,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "goal" to Schemas.strSchema("调查目标：reverse_api / signature_analysis / token_trace / general_recon"),
                    "target" to Schemas.strSchema("目标（接口 URL 关键词 / 函数名 / 存储键名），reverse_api 必填"),
                    "workspaceId" to Schemas.strSchema("关联的工作区 ID（可选）"),
                    "autoRun" to Schemas.boolSchema("是否自动执行前序流水线阶段直到首个人工阶段（默认 true）"),
                ),
                timeoutMs = 120_000,
            ) { args ->
                val goal = runCatching {
                    Goal.valueOf(ToolArgs.str(args, "goal").uppercase().let { if (it == "REVERSE_API") "REVERSE_API" else it })
                }.getOrNull() ?: return@tool McpToolResult.error("INVALID_GOAL", "目标需为 reverse_api / signature_analysis / token_trace / general_recon")
                val target = ToolArgs.str(args, "target")
                if (goal == Goal.REVERSE_API && target.isBlank()) {
                    return@tool McpToolResult.error("INVALID_ARGS", "reverse_api 需要 target（接口 URL 关键词）")
                }
                val autoRun = ToolArgs.bool(args, "autoRun", true)
                val workspaceId = ToolArgs.optStr(args, "workspaceId")?.ifBlank { null }
                val sessionId = deps.context()?.sessionId ?: "default"
                if (investigations.size >= MAX_INVESTIGATIONS) {
                    investigations.values.sortedBy { it.createdAt }.take(10).forEach { evict(it) }
                }
                val inv = ReverseInvestigation(
                    id = "inv-" + UUID.randomUUID().toString().take(8),
                    mcpSessionId = sessionId,
                    goal = goal,
                    target = target,
                    workspaceId = workspaceId,
                    targetId = "$target@${deps.context()?.tabId ?: "tab"}/$sessionId",
                )
                inv.stages += buildStages(goal, target).map { it.copy(status = StageStatus.READY) }
                investigations[inv.id] = inv
                sessionToInvestigations.computeIfAbsent(sessionId) { mutableListOf() }.add(inv.id)
                if (autoRun) autoAdvance(deps, inv)
                McpToolResult.json(planJson(inv))
            },
            f.tool(
                "investigation.plan", "查看一次逆向调查的阶段计划（不执行）", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "investigationId" to Schemas.strSchema("调查 ID（缺省用当前会话最近一次）"),
                ),
            ) { args ->
                val inv = resolveInvestigation(deps, args)
                    ?: return@tool McpToolResult.error("NO_INVESTIGATION", "尚无调查任务，先 investigation.start 或传 investigationId")
                McpToolResult.json(planJson(inv))
            },
            f.tool(
                "investigation.status", "查看调查进度：当前阶段/置信度/候选函数/人工待办（requiredAction）/下一步建议", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "investigationId" to Schemas.strSchema("调查 ID（缺省用当前会话最近一次）"),
                ),
            ) { args ->
                val inv = resolveInvestigation(deps, args)
                    ?: return@tool McpToolResult.error("NO_INVESTIGATION", "尚无调查任务，先 investigation.start")
                McpToolResult.json(statusJson(inv))
            },
            f.tool(
                "investigation.next", "推进调查到下一阶段（人工强制推进）：执行对应流水线；遇到人工阶段则置为 WAITING_INPUT 并返回待办", ToolCategory.REVERSE,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "investigationId" to Schemas.strSchema("调查 ID（缺省用当前会话最近一次）"),
                    "stage" to Schemas.strSchema("指定要执行的阶段名（缺省自动取下个 READY/PENDING）"),
                ),
                timeoutMs = 180_000,
            ) { args ->
                val inv = resolveInvestigation(deps, args)
                    ?: return@tool McpToolResult.error("NO_INVESTIGATION", "尚无调查任务，先 investigation.start")
                val stageName = ToolArgs.optStr(args, "stage")
                val stage = stageName?.let { inv.stageByName(it) }
                    ?: inv.nextStage
                    ?: return@tool McpToolResult.json(buildJsonObject {
                        put("finished", true)
                        put("status", inv.status.name)
                        put("summary", inv.summary)
                    })
                val (executed, advanced) = executeStage(deps, inv, stage)
                if (advanced) {
                    autoAdvance(deps, inv) // 连续推进后续流水线阶段，停在下一个人工阶段
                }
                McpToolResult.json(
                    buildJsonObject {
                        put("investigationId", inv.id)
                        put("stage", executed.name)
                        put("status", executed.status.name)
                        put("detail", executed.detail)
                        put("confidence", JsonPrimitive(executed.confidence))
                        if (executed.status == StageStatus.WAITING_INPUT) {
                            put("requiredAction", executed.requiredAction.ifBlank { executed.toolHint ?: "" })
                            put("completeHint", JsonPrimitive("完成动作后用 investigation.action_done stage=${executed.name} 标记完成，系统会自动继续"))
                        }
                        inv.nextStage?.let {
                            put("nextStage", buildJsonObject {
                                put("name", it.name)
                                put("description", it.description)
                                put("status", it.status.name)
                            })
                        } ?: put("nextStage", JsonPrimitive("all_done"))
                    },
                )
            },
            f.tool(
                "investigation.action_done", "标记一个 WAITING_INPUT/WAITING_EVENT 人工阶段已完成（如已安装 Hook/已设断点），系统随后自动推进后续阶段", ToolCategory.REVERSE,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "investigationId" to Schemas.strSchema("调查 ID（缺省用当前会话最近一次）"),
                    "stage" to Schemas.strSchema("已完成的人工阶段名（必填）"),
                    "note" to Schemas.strSchema("完成说明（可选）"),
                    "autoContinue" to Schemas.boolSchema("完成后是否自动推进后续阶段（默认 true）"),
                ),
                timeoutMs = 180_000,
            ) { args ->
                val inv = resolveInvestigation(deps, args)
                    ?: return@tool McpToolResult.error("NO_INVESTIGATION", "尚无调查任务")
                val stageName = ToolArgs.str(args, "stage")
                val note = ToolArgs.optStr(args, "note")
                val autoContinue = ToolArgs.bool(args, "autoContinue", true)
                val stage = inv.stageByName(stageName)
                    ?: return@tool McpToolResult.error("NO_STAGE", "阶段 $stageName 不存在")
                if (stage.status != StageStatus.WAITING_INPUT && stage.status != StageStatus.WAITING_EVENT) {
                    return@tool McpToolResult.error("BAD_STATE", "阶段 $stageName 当前状态 ${stage.status.name}，非人工待办状态")
                }
                stage.status = StageStatus.DONE
                stage.detail = note?.takeIf { it.isNotBlank() } ?: (stage.toolHint ?: "人工动作已完成")
                inv.refreshStatus()
                if (autoContinue) autoAdvance(deps, inv)
                McpToolResult.json(buildJsonObject {
                    put("investigationId", inv.id)
                    put("stage", stage.name)
                    put("status", stage.status.name)
                    inv.nextStage?.let {
                        put("nextStage", buildJsonObject {
                            put("name", it.name)
                            put("status", it.status.name)
                            put("description", it.description)
                        })
                    } ?: put("nextStage", JsonPrimitive("all_done"))
                })
            },
            f.tool(
                "investigation.list", "列出所有调查任务（investigationId/目标/状态/置信度/会话归属）", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "sessionId" to Schemas.strSchema("按会话过滤（可选）"),
                ),
            ) { args ->
                val sessionFilter = ToolArgs.optStr(args, "sessionId")?.ifBlank { null }
                val list = all().filter { sessionFilter == null || it.mcpSessionId == sessionFilter }
                McpToolResult.json(buildJsonObject {
                    put(
                        "investigations",
                        JsonArray(list.map { inv ->
                            buildJsonObject {
                                put("investigationId", inv.id)
                                put("sessionId", inv.mcpSessionId)
                                put("goal", inv.goal.name)
                                put("target", inv.target)
                                put("status", inv.status.name)
                                put("progress", "${inv.doneCount}/${inv.totalCount}")
                                put("createdAt", inv.createdAt)
                                put("bestConfidence", JsonPrimitive(inv.bestConfidence))
                                put("blocked", inv.blockedCount)
                            }
                        }),
                    )
                })
            },
            f.tool(
                "investigation.reproduce", "为已完成签名定位的调查提取复现要素（候选签名函数/置信度/请求要素），供生成 Python/curl 复现代码", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "investigationId" to Schemas.strSchema("调查 ID（缺省用当前会话最近一次）"),
                ),
            ) { args ->
                val inv = resolveInvestigation(deps, args)
                    ?: return@tool McpToolResult.error("NO_INVESTIGATION", "尚无调查任务")
                val endpoint = inv.target
                val confidence = inv.bestConfidence
                McpToolResult.json(buildJsonObject {
                    put("investigationId", inv.id)
                    put("endpoint", endpoint)
                    put("signatureCandidate", inv.bestCandidate)
                    put("confidence", JsonPrimitive(confidence))
                    put(
                        "reproducePlan",
                        JsonArray(
                            buildList {
                                add(reproduceStep("capture_request", "用网络面板记录一次 $endpoint 的完整请求（标头+Body+Query）"))
                                add(reproduceStep("identify_signature", "确认候选签名函数 ${inv.bestCandidate.ifBlank { "<待发现>" }} 的入参与输出"))
                                add(reproduceStep("replay", "以同样参数+时间戳重算签名，比对 header 中签名值是否一致"))
                            },
                        ),
                    )
                    put("hint", JsonPrimitive("用该要素手写 requests/fetch 复现代码，并用 evidence.correlate 复核签名"))
                })
            },
            f.tool(
                "investigation.history", "查看已持久化的历史调查（来自 Room，App 重启后仍在）：可配合 investigation.resume 恢复", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "sessionId" to Schemas.strSchema("按会话过滤（可选）"),
                    "limit" to Schemas.intSchema("返回条数上限（默认 50）"),
                ),
                timeoutMs = 30_000,
            ) { args ->
                val sessionFilter = ToolArgs.optStr(args, "sessionId")?.ifBlank { null }
                val limit = ToolArgs.int(args, "limit", 50)
                val repo = deps.investigationRepository
                val persisted = if (sessionFilter != null) {
                    repo.listBySession(sessionFilter)
                } else {
                    repo.getAll()
                }
                McpToolResult.json(buildJsonObject {
                    put(
                        "investigations",
                        JsonArray(persisted.take(limit).map { inv ->
                            buildJsonObject {
                                put("investigationId", inv.id)
                                put("sessionId", inv.mcpSessionId)
                                put("goal", inv.goal)
                                put("target", inv.target)
                                put("status", inv.status)
                                put("confidence", JsonPrimitive(inv.confidence))
                                put("summary", inv.summary)
                                put("createdAt", inv.createdAt)
                                put("updatedAt", inv.updatedAt)
                            }
                        }),
                    )
                    put("count", persisted.take(limit).size)
                    put("hint", JsonPrimitive("investigation.resume investigationId=<id> 可将其恢复到当前运行内存继续推进"))
                })
            },
            f.tool(
                "investigation.resume", "把一条已持久化的调查恢复到当前运行内存（含阶段计划与人工待办），实现重启恢复 / 跨会话接续", ToolCategory.REVERSE,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "investigationId" to Schemas.strSchema("要恢复的调查 ID"),
                    "sessionId" to Schemas.strSchema("恢复到哪个会话（缺省用当前请求会话）"),
                ),
                timeoutMs = 30_000,
            ) { args ->
                val invId = ToolArgs.str(args, "investigationId")
                if (invId.isBlank()) return@tool McpToolResult.error("INVALID_ARGS", "需提供 investigationId")
                val sessionId: String = ToolArgs.optStr(args, "sessionId")?.ifBlank { null }
                    ?: (deps.context()?.sessionId ?: "default")
                val repo = deps.investigationRepository
                val entity = repo.getById(invId)
                    ?: return@tool McpToolResult.error("NOT_FOUND", "数据库中没有调查 $invId，先 investigation.history 查看")
                val goal = runCatching { Goal.valueOf(entity.goal) }.getOrNull()
                    ?: return@tool McpToolResult.error("CORRUPT", "未知 goal: ${entity.goal}")
                val stageEntities = repo.stagesOf(invId)()
                val inv = ReverseInvestigation(
                    id = entity.id,
                    mcpSessionId = sessionId,
                    goal = goal,
                    target = entity.target,
                    workspaceId = entity.workspaceId,
                    targetId = entity.targetId,
                    createdAt = entity.createdAt,
                )
                inv.summary = entity.summary
                inv.bestCandidate = entity.bestCandidate
                inv.bestConfidence = entity.confidence
                inv.stages += stageEntities.map { se ->
                    InvestigationStage(
                        name = se.name,
                        description = se.description,
                        pipeline = null,
                        toolHint = se.requiredAction,
                        requiredAction = se.requiredAction,
                        status = runCatching { StageStatus.valueOf(se.status) }.getOrDefault(StageStatus.PENDING),
                        detail = se.detail,
                        confidence = se.confidence,
                    )
                }
                inv.refreshStatus()
                investigations[inv.id] = inv
                sessionToInvestigations.computeIfAbsent(sessionId) { mutableListOf() }.apply { if (!contains(inv.id)) add(inv.id) }
                McpToolResult.json(buildJsonObject {
                    put("resumed", true)
                    put("investigationId", inv.id)
                    put("sessionId", sessionId)
                    put("status", inv.status.name)
                    inv.nextStage?.let { put("nextStage", it.name) }
                    put("persistedStages", stageEntities.size)
                })
            },
        )
    }

    private fun reproduceStep(name: String, detail: String): JsonObject = buildJsonObject {
        put("step", name)
        put("detail", detail)
    }

    // ================================================================
    // 执行器
    // ================================================================

    /**
     * 从当前可推进阶段开始，连续执行所有「流水线阶段」，直到命中人工阶段（置 WAITING_INPUT）
     * 或全部完成/失败。人工阶段不自动跳过（P0-4），等待 Agent 用 action_done 完成。
     */
    private suspend fun autoAdvance(deps: ToolDependencies, inv: ReverseInvestigation) {
        while (true) {
            val nxt = inv.nextStage ?: break
            // 人工阶段：不跳过，置 WAITING_INPUT 后停下
            if (nxt.pipeline == null) {
                nxt.status = StageStatus.WAITING_INPUT
                nxt.detail = "待外部动作：${nxt.requiredAction.ifBlank { nxt.toolHint ?: "手动/工具配合" }}"
                inv.refreshStatus()
                break
            }
            val (_, advanced) = executeStage(deps, inv, nxt)
            if (!advanced) break
        }
        inv.refreshStatus()
    }

    private suspend fun executeStage(
        deps: ToolDependencies,
        inv: ReverseInvestigation,
        stage: InvestigationStage,
    ): Pair<InvestigationStage, Boolean> {
        // 人工阶段：转为 WAITING_INPUT（不 SKIP）
        if (stage.pipeline == null) {
            stage.status = StageStatus.WAITING_INPUT
            stage.detail = "待外部动作：${stage.requiredAction.ifBlank { stage.toolHint ?: "手动/工具配合" }}"
            inv.refreshStatus()
            return stage to false
        }
        if (stage.status == StageStatus.DONE) return stage to false
        stage.status = StageStatus.RUNNING
        inv.refreshStatus()
        return try {
            val pipelineArgs = buildJsonObject {
                put("saveFindings", JsonPrimitive(true))
                when (stage.pipeline) {
                    "api_trace" -> put("urlPattern", JsonPrimitive(inv.target))
                    "token_trace" -> if (inv.goal == Goal.TOKEN_TRACE) put("key", JsonPrimitive(inv.target))
                }
            }
            val result = EvidenceTools.runPipeline(deps, stage.pipeline, pipelineArgs)
            stage.status = StageStatus.DONE
            stage.detail = summarizePipelineResult(stage.pipeline, result)
            stage.confidence = extractConfidence(result)
            // crypto_link 阶段：把最高置信度候选写回调查级最佳
            if (stage.name == "crypto_link") {
                val fn = resolveFunctionName(result)
                if (fn.isNotBlank()) inv.bestCandidate = fn
                if (stage.confidence > 0.0) inv.bestConfidence = stage.confidence
            }
            if (stage.confidence > inv.bestConfidence) inv.bestConfidence = stage.confidence
            inv.refreshStatus()
            if (stage.confidence >= 0.8) {
                runCatching {
                    deps.workspaceManager.addFinding(
                        com.webreverse.mcp.core.common.model.Finding(
                            id = UUID.randomUUID().toString(),
                            workspaceId = inv.workspaceId ?: deps.workspaceManager.getWorkspaces().firstOrNull()?.id,
                            type = FindingType.CRYPTO,
                            title = "调查确认: $inv.bestCandidate SIGNS ${inv.target.take(60)}",
                            description = "置信度 ${"%.2f".format(stage.confidence)}，依据: $stage.detail",
                            evidence = stage.detail,
                            source = inv.target,
                            confidence = if (stage.confidence >= 0.85) Confidence.HIGH else Confidence.MEDIUM,
                        ),
                    )
                }
            }
            stage to true
        } catch (e: Exception) {
            stage.status = StageStatus.FAILED
            stage.detail = e.message ?: "阶段执行失败"
            inv.refreshStatus()
            stage to false
        }
    }

    private fun resolveFunctionName(result: JsonObject): String = runCatching {
        val links = result["links"] as? JsonArray ?: JsonArray(emptyList())
        val first = links.firstOrNull() as? JsonObject ?: return@runCatching ""
        val cands = first["candidates"] as? JsonArray ?: JsonArray(emptyList())
        (cands.firstOrNull() as? JsonObject)?.get("function")?.let { (it as? JsonPrimitive)?.content } ?: ""
    }.getOrNull().orEmpty()

    private fun extractConfidence(result: JsonObject): Double = runCatching {
        val links = result["links"] as? JsonArray ?: JsonArray(emptyList())
        links.mapNotNull { it as? JsonObject }
            .mapNotNull { it["confidence"]?.let { el -> (el as? JsonPrimitive)?.doubleOrNull } }
            .maxOrNull() ?: 0.0
    }.getOrNull() ?: 0.0

    private fun summarizePipelineResult(pipeline: String, result: JsonObject): String = when (pipeline) {
        "recon" -> {
            val steps = (result["steps"] as? JsonArray) ?: JsonArray(emptyList())
            steps.mapNotNull { it as? JsonObject }
                .joinToString("；") { (it["name"] as? JsonPrimitive)?.content ?: "" }
        }
        "crypto_link" -> {
            val links = (result["links"] as? JsonArray) ?: JsonArray(emptyList())
            "签名候选 ${links.size} 组，最高置信度 ${"%.2f".format(extractConfidence(result))}"
        }
        "snapshot" -> "运行时现场已捕获并建图"
        else -> "完成"
    }

    private fun evict(inv: ReverseInvestigation) {
        investigations.remove(inv.id)
        sessionToInvestigations[inv.mcpSessionId]?.remove(inv.id)
    }

    // ================================================================
    // 阶段计划定义
    // ================================================================

    private fun buildStages(goal: Goal, target: String): List<InvestigationStage> = when (goal) {
        Goal.REVERSE_API -> listOf(
            InvestigationStage("recon", "页面全景侦察（框架/API/脚本/混淆/存储）", "recon"),
            InvestigationStage("api_trace", "定位 $target 的调用链（initiator→函数→脚本）", "api_trace"),
            InvestigationStage("hook", "对调用方函数安装 Hook 观察实时参数", pipeline = null,
                requiredAction = "安装调用方函数 Hook 并触发一次请求，观察是否引入签名/时间戳；推荐 hook.add type=crypto",
                toolHint = "hook.add type=crypto target=<调用方候选函数>；触发后 evidence/事件回填"),
            InvestigationStage("crypto_link", "加密命中与请求多证据关联，输出候选签名函数+置信度", "crypto_link"),
            InvestigationStage("breakpoint", "对高置信度候选设断点验证签名生成现场", pipeline = null,
                requiredAction = "对候选签名函数设断点并触发；命中后抓取入参与密钥",
                toolHint = "debugger.set_breakpoint type=function target=<候选函数>；命中后 pipeline.run name=snapshot"),
            InvestigationStage("reproduce", "汇总请求要素，生成可复现的提交结构", pipeline = null,
                requiredAction = "用 investigation.reproduce 提取要素并手写 requests/fetch 复现代码",
                toolHint = "investigation.reproduce 提取复现要素"),
        )
        Goal.SIGNATURE_ANALYSIS -> listOf(
            InvestigationStage("api_trace", "定位 $target 的调用链", "api_trace"),
            InvestigationStage("crypto_link", "多证据关联定位签名函数", "crypto_link"),
            InvestigationStage("hook", "拦截 crypto/sign 类函数抓取输入输出", pipeline = null,
                requiredAction = "安装 crypto/sign Hook 并触发，观察返回值是否进请求头/体",
                toolHint = "hook.add type=crypto target=<候选函数>"),
            InvestigationStage("snapshot", "断点命中抓取密钥与会参", pipeline = null,
                requiredAction = "对候选函数设断点命中后抓取密钥与会参",
                toolHint = "debugger.set_breakpoint 命中后 pipeline.run name=snapshot"),
            InvestigationStage("verify", "重放验证签名输入输出一致", pipeline = null,
                requiredAction = "用相同入参重算签名，比对 header 中的签名值",
                toolHint = "investigation.reproduce 提取要素并重放验证"),
        )
        Goal.TOKEN_TRACE -> listOf(
            InvestigationStage("token_trace", "扫描令牌类存储键并找引用脚本", "token_trace"),
            InvestigationStage("hook", "监控令牌写入时刻与来源函数", pipeline = null,
                requiredAction = "安装 storage Hook 观察令牌写入者与来源函数",
                toolHint = "hook.add type=storage target=<key>"),
            InvestigationStage("crypto_link", "关联令牌是否参与签名生成", "crypto_link"),
            InvestigationStage("snapshot", "抓取令牌生成的运行时现场", pipeline = null,
                requiredAction = "命中后抓取令牌生成的运行时现场",
                toolHint = "命中后 pipeline.run name=snapshot"),
        )
        Goal.GENERAL_RECON -> listOf(
            InvestigationStage("recon", "页面全景侦察", "recon"),
            InvestigationStage("crypto_link", "扫描并关联加密行为", "crypto_link"),
            InvestigationStage("followup", "针对关键端点细化", pipeline = null,
                requiredAction = "对重点接口 investigation.start goal=reverse_api target=<endpoint>",
                toolHint = "investigation.start goal=reverse_api target=<endpoint>"),
        )
    }

    // ================================================================
    // JSON 序列化
    // ================================================================

    private fun planJson(inv: ReverseInvestigation): JsonObject = buildJsonObject {
        put("investigationId", inv.id)
        put("sessionId", inv.mcpSessionId)
        put("goal", inv.goal.name)
        put("target", inv.target)
        put("status", inv.status.name)
        put("progress", "${inv.doneCount}/${inv.totalCount}")
        put("confidence", inv.bestConfidence)
        put("createdAt", inv.createdAt)
        put("plan", JsonArray(inv.stages.map { stageJson(it) }))
        inv.currentStage?.let { put("currentStage", JsonPrimitive(it.name)) }
        inv.nextStage?.let { put("nextStage", JsonPrimitive(it.name)) }
        put("hint", JsonPrimitive("investigation.next 推进；人工阶段 investigation.action_done stage=<name>；investigation.status 查看进度"))
    }

    private fun stageJson(s: InvestigationStage): JsonObject = buildJsonObject {
        put("name", s.name)
        put("description", s.description)
        put("status", s.status.name)
        put("pipeline", s.pipeline?.let { JsonPrimitive(it) } ?: JsonPrimitive("manual"))
        if (s.toolHint != null) put("toolHint", s.toolHint)
        if (s.requiredAction.isNotBlank() && s.status == StageStatus.WAITING_INPUT) put("requiredAction", s.requiredAction)
        if (s.detail.isNotBlank()) put("detail", s.detail)
        if (s.confidence > 0.0) put("confidence", JsonPrimitive(s.confidence))
    }

    private fun statusJson(inv: ReverseInvestigation): JsonObject = buildJsonObject {
        put("investigationId", inv.id)
        put("sessionId", inv.mcpSessionId)
        put("goal", inv.goal.name)
        put("target", inv.target)
        put("workspaceId", inv.workspaceId ?: "")
        put("status", inv.status.name)
        put("progress", "${inv.doneCount}/${inv.totalCount}")
        put("currentStage", inv.currentStage?.let {
            buildJsonObject {
                put("name", it.name)
                put("status", it.status.name)
                put("description", it.description)
            }
        } ?: JsonPrimitive("none"))
        put("bestCandidate", inv.bestCandidate)
        put("bestConfidence", JsonPrimitive(inv.bestConfidence))
        put("stages", JsonArray(inv.stages.map { stageJson(it) }))
        inv.currentStage?.let { cur ->
            when (cur.status) {
                StageStatus.WAITING_INPUT, StageStatus.WAITING_EVENT -> put("requiredAction",
                    cur.requiredAction.ifBlank { cur.toolHint ?: "" })
                else -> Unit
            }
        }
        put("nextAction", inv.nextStage?.let {
            buildJsonObject {
                put("name", it.name)
                put("hint", it.toolHint ?: ("运行流水线 ${it.pipeline}"))
            }
        } ?: JsonPrimitive("all_done"))
        put("summary", inv.summary)
    }
}