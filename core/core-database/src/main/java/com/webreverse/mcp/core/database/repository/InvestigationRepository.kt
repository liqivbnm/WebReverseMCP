package com.webreverse.mcp.core.database.repository

import com.webreverse.mcp.core.database.dao.InvestigationDao
import com.webreverse.mcp.core.database.entity.InvestigationActionEntity
import com.webreverse.mcp.core.database.entity.InvestigationEntity
import com.webreverse.mcp.core.database.entity.InvestigationStageEntity
import kotlinx.coroutines.flow.Flow

/** 逆向调查仓库（P1-14：Investigation 进入数据库，支持 resume/历史审计） */
class InvestigationRepository(private val dao: InvestigationDao) {

    fun observeAll(): Flow<List<InvestigationEntity>> = dao.observeAll()

    suspend fun getAll(): List<InvestigationEntity> = dao.getAll()

    suspend fun getById(id: String): InvestigationEntity? = dao.byId(id)
    suspend fun listBySession(sessionId: String): List<InvestigationEntity> = dao.bySession(sessionId)
    suspend fun upsert(investigation: InvestigationEntity) = dao.upsert(investigation)
    suspend fun update(investigation: InvestigationEntity) = dao.update(investigation)
    suspend fun delete(investigation: InvestigationEntity) = dao.delete(investigation)

    fun stagesOf(investigationId: String): suspend () -> List<InvestigationStageEntity> = { dao.stages(investigationId) }
    suspend fun upsertStage(stage: InvestigationStageEntity) = dao.upsertStage(stage)
    suspend fun updateStage(stage: InvestigationStageEntity) = dao.updateStage(stage)

    fun actionsOf(investigationId: String): suspend () -> List<InvestigationActionEntity> = { dao.actions(investigationId) }
    suspend fun upsertAction(action: InvestigationActionEntity) = dao.upsertAction(action)
}