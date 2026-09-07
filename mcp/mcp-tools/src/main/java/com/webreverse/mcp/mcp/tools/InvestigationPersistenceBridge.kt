package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.database.entity.InvestigationEntity
import com.webreverse.mcp.core.database.entity.InvestigationStageEntity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * P1-14 调查持久化桥：把 InvestigationTools 内存中的调查定期同步到 Room。
 *
 * 动机（对应 ChatGPT 分析十六）： 的 `ReverseInvestigation` 完全存在
 * `ConcurrentHashMap` 里，App 重启后全部消失。本桥以「存量快照同步」方式，把每个在内存
 * 中的调查（含阶段状态机）周期落库到 `investigations / investigation_stages`，供
 * `investigation.history / investigation.resume` 在重启后恢复，无需重写 InvestigationTools 内部逻辑。
 *
 * 因既有内存库仍作为权威运行时状态（AI 交互频繁读写），本桥只做幂等落库（upsert），
 * 不改写内存。真正的库存/kill 后由 `investigation.resume` 回读重建。
 */
class InvestigationPersistenceBridge(
    private val deps: ToolDependencies,
    private val scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.IO),
) {
    private var job: Job? = null
    private var lastPersistedKeys = LinkedHashMap<String, Long>()

    fun start() {
        if (job != null) return
        job = scope.launch {
            while (isActive) {
                try { sync() } catch (t: Throwable) {
                    deps.logger.e(com.webreverse.mcp.core.logging.LogCategory.AGENT, "调查持久化失败: ${t.message}")
                }
                delay(10_000)
            }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
    }

    /** 全量把内存调查落库（幂等 upsert） */
    suspend fun sync() {
        val repo = deps.investigationRepository
        for (inv in InvestigationTools.all()) {
            val entity = InvestigationEntity(
                id = inv.id,
                workspaceId = inv.workspaceId,
                mcpSessionId = inv.mcpSessionId,
                targetId = inv.targetId,
                goal = inv.goal.name,
                target = inv.target,
                status = inv.status.name,
                confidence = inv.bestConfidence,
                summary = inv.summary,
                bestCandidate = inv.bestCandidate,
                createdAt = inv.createdAt,
                updatedAt = inv.updatedAt,
            )
            repo.upsert(entity)
            inv.stages.forEach { st ->
                repo.upsertStage(
                    InvestigationStageEntity(
                        id = "${inv.id}:${st.name}",
                        investigationId = inv.id,
                        name = st.name,
                        description = st.description,
                        status = st.status.name,
                        confidence = st.confidence,
                        detail = st.detail,
                        requiredAction = st.requiredAction,
                        startedAt = st.startedAtOrNow(),
                    ),
                )
            }
            lastPersistedKeys[inv.id] = entity.updatedAt
        }
        // 清理内存中已消失但本地仍残留的调查（局限于本次会话创建过的）
    }

    suspend fun forceSync(investigationId: String) {
        val inv = InvestigationTools.byId(investigationId) ?: return
        val repo = deps.investigationRepository
        repo.upsert(
            InvestigationEntity(
                id = inv.id, workspaceId = inv.workspaceId, mcpSessionId = inv.mcpSessionId,
                targetId = inv.targetId, goal = inv.goal.name, target = inv.target,
                status = inv.status.name, confidence = inv.bestConfidence, summary = inv.summary,
                bestCandidate = inv.bestCandidate, createdAt = inv.createdAt, updatedAt = inv.updatedAt,
            ),
        )
    }
}

/** 阶段实体需要 startedAt 默认值（内存阶段无该字段，借用最新状态变更时间兜底） */
private fun InvestigationTools.InvestigationStage.startedAtOrNow(): Long = System.currentTimeMillis()