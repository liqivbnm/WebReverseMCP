package com.webreverse.mcp.core.database.repository

import com.webreverse.mcp.core.database.dao.AnalysisResultDao
import com.webreverse.mcp.core.database.dao.FindingDao
import com.webreverse.mcp.core.database.dao.McpSessionDao
import com.webreverse.mcp.core.database.dao.McpToolConfigDao
import com.webreverse.mcp.core.database.dao.NoteDao
import com.webreverse.mcp.core.database.dao.TargetDao
import com.webreverse.mcp.core.database.dao.WorkspaceDao
import com.webreverse.mcp.core.database.entity.AnalysisResultEntity
import com.webreverse.mcp.core.database.entity.FindingEntity
import com.webreverse.mcp.core.database.entity.McpSessionEntity
import com.webreverse.mcp.core.database.entity.McpToolConfigEntity
import com.webreverse.mcp.core.database.entity.NoteEntity
import com.webreverse.mcp.core.database.entity.TargetEntity
import com.webreverse.mcp.core.database.entity.WorkspaceEntity
import kotlinx.coroutines.flow.Flow

/** 工作区仓库 */
class WorkspaceRepository(
    private val workspaceDao: WorkspaceDao,
    private val targetDao: TargetDao,
    private val noteDao: NoteDao,
    private val findingDao: FindingDao? = null,
    private val analysisResultDao: AnalysisResultDao? = null,
) {
    fun observeAll(): Flow<List<WorkspaceEntity>> = workspaceDao.observeAll()
    suspend fun getAll(): List<WorkspaceEntity> = workspaceDao.getAll()
    suspend fun getById(id: String): WorkspaceEntity? = workspaceDao.getById(id)
    suspend fun upsert(workspace: WorkspaceEntity) = workspaceDao.upsert(workspace)
    suspend fun deleteById(id: String) = workspaceDao.deleteById(id)

    fun observeTargets(): Flow<List<TargetEntity>> = targetDao.observeAll()
    suspend fun getTargets(): List<TargetEntity> = targetDao.getAll()
    suspend fun upsertTarget(target: TargetEntity) = targetDao.upsert(target)
    suspend fun deleteTarget(target: TargetEntity) = targetDao.delete(target)

    fun observeNotes(workspaceId: String?): Flow<List<NoteEntity>> = noteDao.observeByWorkspace(workspaceId)
    suspend fun upsertNote(note: NoteEntity) = noteDao.upsert(note)
    suspend fun deleteNote(note: NoteEntity) = noteDao.delete(note)

    // ---- Findings ----
    fun observeFindings(workspaceId: String?): Flow<List<FindingEntity>> =
        findingDao?.observeByWorkspace(workspaceId) ?: kotlinx.coroutines.flow.flowOf(emptyList())
    suspend fun upsertFinding(finding: FindingEntity) = findingDao?.upsert(finding)
    suspend fun clearFindings(workspaceId: String?) = findingDao?.clearByWorkspace(workspaceId)

    // ---- Analysis Results ----
    fun observeAnalysisByWorkspace(workspaceId: String?): Flow<List<AnalysisResultEntity>> =
        analysisResultDao?.observeByWorkspace(workspaceId) ?: kotlinx.coroutines.flow.flowOf(emptyList())
    suspend fun upsertAnalysis(result: AnalysisResultEntity) = analysisResultDao?.upsert(result)
}

/** MCP 仓库 */
class McpRepository(
    private val sessionDao: McpSessionDao,
    private val toolConfigDao: McpToolConfigDao,
    private val analysisResultDao: AnalysisResultDao,
    private val findingDao: FindingDao,
) {
    fun observeSessions(limit: Int = 100): Flow<List<McpSessionEntity>> = sessionDao.observeRecent(limit)
    suspend fun upsertSession(session: McpSessionEntity) = sessionDao.upsert(session)
    suspend fun bumpToolCall(id: String) = sessionDao.bumpToolCall(id)
    suspend fun closeSession(id: String) = sessionDao.close(id, System.currentTimeMillis())

    fun observeToolConfigs(): Flow<List<McpToolConfigEntity>> = toolConfigDao.observeAll()
    suspend fun upsertToolConfig(config: McpToolConfigEntity) = toolConfigDao.upsert(config)
    suspend fun setToolEnabled(name: String, enabled: Boolean) = toolConfigDao.setEnabled(name, enabled)

    fun observeAnalysis(limit: Int = 200): Flow<List<AnalysisResultEntity>> = analysisResultDao.observeRecent(limit)
    fun observeAnalysisByWorkspace(workspaceId: String?): Flow<List<AnalysisResultEntity>> =
        analysisResultDao.observeByWorkspace(workspaceId)
    suspend fun upsertAnalysis(result: AnalysisResultEntity) = analysisResultDao.upsert(result)

    fun observeFindings(workspaceId: String?): Flow<List<FindingEntity>> =
        findingDao.observeByWorkspace(workspaceId)
    fun observeRecentFindings(limit: Int = 200): Flow<List<FindingEntity>> = findingDao.observeRecent(limit)
    suspend fun upsertFinding(finding: FindingEntity) = findingDao.upsert(finding)
    suspend fun clearFindings(workspaceId: String?) = findingDao.clearByWorkspace(workspaceId)
}
