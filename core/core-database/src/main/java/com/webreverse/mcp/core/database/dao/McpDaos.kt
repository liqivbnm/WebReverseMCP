package com.webreverse.mcp.core.database.dao

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.webreverse.mcp.core.database.entity.McpToolConfigEntity
import com.webreverse.mcp.core.database.entity.McpSessionEntity
import com.webreverse.mcp.core.database.entity.AnalysisResultEntity
import com.webreverse.mcp.core.database.entity.FindingEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface McpToolConfigDao {
    @Query("SELECT * FROM mcp_tool_configs")
    fun observeAll(): Flow<List<McpToolConfigEntity>>

    @Query("SELECT * FROM mcp_tool_configs WHERE name = :name")
    suspend fun getByName(name: String): McpToolConfigEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(config: McpToolConfigEntity)

    @Query("UPDATE mcp_tool_configs SET enabled = :enabled WHERE name = :name")
    suspend fun setEnabled(name: String, enabled: Boolean)
}

@Dao
interface McpSessionDao {
    @Query("SELECT * FROM mcp_sessions ORDER BY startedAt DESC LIMIT :limit")
    fun observeRecent(limit: Int = 100): Flow<List<McpSessionEntity>>

    @Query("SELECT * FROM mcp_sessions WHERE id = :id")
    suspend fun getById(id: String): McpSessionEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(session: McpSessionEntity)

    @Query("UPDATE mcp_sessions SET toolCallCount = toolCallCount + 1, status = :status WHERE id = :id")
    suspend fun bumpToolCall(id: String, status: String = "ACTIVE")

    @Query("UPDATE mcp_sessions SET endedAt = :time, status = 'CLOSED' WHERE id = :id")
    suspend fun close(id: String, time: Long)

    @Query("DELETE FROM mcp_sessions")
    suspend fun clearAll()
}

@Dao
interface AnalysisResultDao {
    @Query("SELECT * FROM analysis_results ORDER BY createdAt DESC LIMIT :limit")
    fun observeRecent(limit: Int = 200): Flow<List<AnalysisResultEntity>>

    @Query("SELECT * FROM analysis_results WHERE workspaceId = :workspaceId ORDER BY createdAt DESC")
    fun observeByWorkspace(workspaceId: String?): Flow<List<AnalysisResultEntity>>

    @Query("SELECT * FROM analysis_results WHERE id = :id")
    suspend fun getById(id: String): AnalysisResultEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(result: AnalysisResultEntity)

    @Delete
    suspend fun delete(result: AnalysisResultEntity)
}

@Dao
interface FindingDao {
    @Query("SELECT * FROM findings WHERE workspaceId = :workspaceId ORDER BY createdAt DESC")
    fun observeByWorkspace(workspaceId: String?): Flow<List<FindingEntity>>

    @Query("SELECT * FROM findings ORDER BY createdAt DESC LIMIT :limit")
    fun observeRecent(limit: Int = 200): Flow<List<FindingEntity>>

    @Query("SELECT * FROM findings WHERE id = :id")
    suspend fun getById(id: String): FindingEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(finding: FindingEntity)

    @Delete
    suspend fun delete(finding: FindingEntity)

    @Query("DELETE FROM findings WHERE workspaceId = :workspaceId")
    suspend fun clearByWorkspace(workspaceId: String?)
}
