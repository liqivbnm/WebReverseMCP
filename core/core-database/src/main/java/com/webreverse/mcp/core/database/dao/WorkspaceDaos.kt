package com.webreverse.mcp.core.database.dao

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import com.webreverse.mcp.core.database.entity.WorkspaceEntity
import com.webreverse.mcp.core.database.entity.TargetEntity
import com.webreverse.mcp.core.database.entity.NoteEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface WorkspaceDao {
    @Query("SELECT * FROM workspaces ORDER BY updatedAt DESC")
    fun observeAll(): Flow<List<WorkspaceEntity>>

    @Query("SELECT * FROM workspaces ORDER BY updatedAt DESC")
    suspend fun getAll(): List<WorkspaceEntity>

    @Query("SELECT * FROM workspaces WHERE id = :id")
    suspend fun getById(id: String): WorkspaceEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(workspace: WorkspaceEntity)

    @Delete
    suspend fun delete(workspace: WorkspaceEntity)

    @Query("DELETE FROM workspaces WHERE id = :id")
    suspend fun deleteById(id: String)
}

@Dao
interface TargetDao {
    @Query("SELECT * FROM targets ORDER BY createdAt DESC")
    fun observeAll(): Flow<List<TargetEntity>>

    @Query("SELECT * FROM targets ORDER BY createdAt DESC")
    suspend fun getAll(): List<TargetEntity>

    @Query("SELECT * FROM targets WHERE id = :id")
    suspend fun getById(id: String): TargetEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(target: TargetEntity)

    @Delete
    suspend fun delete(target: TargetEntity)
}

@Dao
interface NoteDao {
    @Query("SELECT * FROM notes WHERE workspaceId = :workspaceId ORDER BY updatedAt DESC")
    fun observeByWorkspace(workspaceId: String?): Flow<List<NoteEntity>>

    @Query("SELECT * FROM notes WHERE id = :id")
    suspend fun getById(id: String): NoteEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(note: NoteEntity)

    @Delete
    suspend fun delete(note: NoteEntity)
}
