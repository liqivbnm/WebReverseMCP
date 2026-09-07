package com.webreverse.mcp.core.database.dao

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Transaction
import androidx.room.Update
import com.webreverse.mcp.core.database.entity.InvestigationActionEntity
import com.webreverse.mcp.core.database.entity.InvestigationEntity
import com.webreverse.mcp.core.database.entity.InvestigationStageEntity
import kotlinx.coroutines.flow.Flow

/** 逆向调查持久化 DAO（P1-14 恢复/审计） */
@Dao
interface InvestigationDao {

    @Query("SELECT * FROM investigations ORDER BY createdAt DESC")
    fun observeAll(): Flow<List<InvestigationEntity>>

    @Query("SELECT * FROM investigations ORDER BY createdAt DESC")
    suspend fun getAll(): List<InvestigationEntity>

    @Query("SELECT * FROM investigations WHERE mcpSessionId = :sessionId ORDER BY createdAt DESC")
    suspend fun bySession(sessionId: String): List<InvestigationEntity>

    @Query("SELECT * FROM investigations WHERE id = :id LIMIT 1")
    suspend fun byId(id: String): InvestigationEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(investigation: InvestigationEntity)

    @Update
    suspend fun update(investigation: InvestigationEntity)

    @Delete
    suspend fun delete(investigation: InvestigationEntity)

    // ---- 阶段 ----

    @Query("SELECT * FROM investigation_stages WHERE investigationId = :investigationId ORDER BY startedAt ASC")
    suspend fun stages(investigationId: String): List<InvestigationStageEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertStage(stage: InvestigationStageEntity)

    @Update
    suspend fun updateStage(stage: InvestigationStageEntity)

    // ---- 动作 ----

    @Query("SELECT * FROM investigation_actions WHERE investigationId = :investigationId ORDER BY createdAt ASC")
    suspend fun actions(investigationId: String): List<InvestigationActionEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertAction(action: InvestigationActionEntity)

    @Query("DELETE FROM investigation_actions WHERE investigationId = :investigationId")
    suspend fun clearActions(investigationId: String)
}