package com.webreverse.mcp.workspace.core

import com.webreverse.mcp.core.common.model.AnalysisResult
import com.webreverse.mcp.core.common.model.Finding
import com.webreverse.mcp.core.common.util.Ids
import com.webreverse.mcp.core.database.entity.AnalysisResultEntity
import com.webreverse.mcp.core.database.entity.FindingEntity
import com.webreverse.mcp.core.database.entity.NoteEntity
import com.webreverse.mcp.core.database.entity.TargetEntity
import com.webreverse.mcp.core.database.entity.WorkspaceEntity
import com.webreverse.mcp.core.database.repository.WorkspaceRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/**
 * 工作区管理器：逆向项目的“案件档案室”。
 *
 * 职责：把散落的分析产物（findings / notes / analysis / targets）
 * 归档到 workspace 维度，供 MCP 工具与 UI 双向读写。
 * 领域模型（Finding/AnalysisResult，core-common）与 DB 实体解耦，
 * JSON 字段（data/findings）经 kotlinx.serialization 序列化。
 */
class WorkspaceManager(
    private val repository: WorkspaceRepository,
) {
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    // ---------------- Workspace ----------------

    suspend fun getWorkspaces(): List<WorkspaceEntity> = repository.getAll()

    fun observeWorkspaces(): Flow<List<WorkspaceEntity>> = repository.observeAll()

    suspend fun createWorkspace(name: String, description: String, targetUrl: String): WorkspaceEntity {
        val now = System.currentTimeMillis()
        val entity = WorkspaceEntity(
            id = Ids.uuid(),
            name = name,
            description = description,
            targetUrl = targetUrl,
            createdAt = now,
            updatedAt = now,
        )
        repository.upsert(entity)
        return entity
    }

    suspend fun getWorkspace(id: String): WorkspaceEntity? = repository.getById(id)

    suspend fun deleteWorkspace(id: String) = repository.deleteById(id)

    // ---------------- Finding ----------------

    suspend fun addFinding(finding: Finding): FindingEntity {
        val entity = finding.toEntity()
        repository.upsertFinding(entity)
        return entity
    }

    fun observeFindings(workspaceId: String?): Flow<List<FindingEntity>> =
        repository.observeFindings(workspaceId)

    // ---------------- Note ----------------

    suspend fun addNote(workspaceId: String, title: String, content: String): NoteEntity {
        val now = System.currentTimeMillis()
        val entity = NoteEntity(
            id = Ids.uuid(),
            workspaceId = workspaceId.ifBlank { null },
            title = title,
            content = content,
            createdAt = now,
            updatedAt = now,
        )
        repository.upsertNote(entity)
        return entity
    }

    fun observeNotes(workspaceId: String?): Flow<List<NoteEntity>> =
        repository.observeNotes(workspaceId)

    // ---------------- Analysis ----------------

    suspend fun saveAnalysis(result: AnalysisResult): AnalysisResultEntity {
        val entity = result.toEntity(json)
        repository.upsertAnalysis(entity)
        return entity
    }

    fun observeAnalysis(workspaceId: String?): Flow<List<AnalysisResultEntity>> =
        repository.observeAnalysisByWorkspace(workspaceId)

    // ---------------- Target ----------------

    suspend fun addTarget(name: String, url: String, framework: String?): TargetEntity {
        val entity = TargetEntity(
            id = Ids.uuid(),
            name = name,
            url = url,
            framework = framework,
        )
        repository.upsertTarget(entity)
        return entity
    }

    fun observeTargets(): Flow<List<TargetEntity>> = repository.observeTargets()

    suspend fun getTargets(): List<TargetEntity> = repository.getTargets()

    suspend fun deleteTarget(target: TargetEntity) = repository.deleteTarget(target)

    suspend fun deleteNote(note: NoteEntity) = repository.deleteNote(note)
}

// ---------------- 映射 ----------------

private fun Finding.toEntity(): FindingEntity = FindingEntity(
    id = id,
    workspaceId = workspaceId,
    type = type.name,
    title = title,
    description = description,
    evidence = evidence,
    source = source,
    line = line,
    confidence = confidence.name,
    severity = severity.name,
    relatedTool = relatedTool,
    relatedRequest = relatedRequest,
    relatedFunction = relatedFunction,
    createdAt = createdAt,
)

private fun AnalysisResult.toEntity(json: Json): AnalysisResultEntity = AnalysisResultEntity(
    id = id,
    workspaceId = workspaceId,
    type = type,
    title = title,
    summary = summary,
    content = content,
    confidence = confidence,
    findingsJson = runCatching { json.encodeToString(findings) }.getOrDefault("[]"),
    relatedUrlsJson = runCatching { json.encodeToString(relatedUrls) }.getOrDefault("[]"),
    createdAt = createdAt,
    dataJson = runCatching { json.encodeToString(data) }.getOrDefault("{}"),
)
