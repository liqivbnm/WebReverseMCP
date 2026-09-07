package com.webreverse.mcp.core.database.dao

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import com.webreverse.mcp.core.database.entity.NetworkEntryEntity
import com.webreverse.mcp.core.database.entity.HookRuleEntity
import com.webreverse.mcp.core.database.entity.BreakpointEntity
import com.webreverse.mcp.core.database.entity.UserScriptEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface NetworkEntryDao {
    @Query("SELECT * FROM network_entries WHERE tabId = :tabId ORDER BY startedAt DESC LIMIT :limit")
    fun observeByTab(tabId: String, limit: Int = 500): Flow<List<NetworkEntryEntity>>

    @Query("SELECT * FROM network_entries WHERE tabId = :tabId ORDER BY startedAt DESC LIMIT :limit")
    suspend fun getByTab(tabId: String, limit: Int = 500): List<NetworkEntryEntity>

    @Query("SELECT * FROM network_entries WHERE id = :id")
    suspend fun getById(id: String): NetworkEntryEntity?

    @Query("SELECT * FROM network_entries WHERE url LIKE '%' || :query || '%' ORDER BY startedAt DESC LIMIT :limit")
    suspend fun search(query: String, limit: Int = 200): List<NetworkEntryEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(entry: NetworkEntryEntity)

    @Query("DELETE FROM network_entries WHERE tabId = :tabId")
    suspend fun clearByTab(tabId: String)

    @Query("DELETE FROM network_entries")
    suspend fun clearAll()
}

@Dao
interface HookRuleDao {
    @Query("SELECT * FROM hook_rules ORDER BY createdAt DESC")
    fun observeAll(): Flow<List<HookRuleEntity>>

    @Query("SELECT * FROM hook_rules ORDER BY createdAt DESC")
    suspend fun getAll(): List<HookRuleEntity>

    @Query("SELECT * FROM hook_rules WHERE id = :id")
    suspend fun getById(id: String): HookRuleEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(rule: HookRuleEntity)

    @Delete
    suspend fun delete(rule: HookRuleEntity)

    @Query("DELETE FROM hook_rules WHERE id = :id")
    suspend fun deleteById(id: String)

    @Query("UPDATE hook_rules SET enabled = :enabled WHERE id = :id")
    suspend fun setEnabled(id: String, enabled: Boolean)

    @Query("UPDATE hook_rules SET hitCount = hitCount + 1, lastTriggeredAt = :time WHERE id = :id")
    suspend fun bumpHit(id: String, time: Long)
}

@Dao
interface BreakpointDao {
    @Query("SELECT * FROM breakpoints WHERE tabId = :tabId ORDER BY createdAt DESC")
    fun observeByTab(tabId: String): Flow<List<BreakpointEntity>>

    @Query("SELECT * FROM breakpoints WHERE tabId = :tabId")
    suspend fun getByTab(tabId: String): List<BreakpointEntity>

    @Query("SELECT * FROM breakpoints WHERE id = :id")
    suspend fun getById(id: String): BreakpointEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(breakpoint: BreakpointEntity)

    @Delete
    suspend fun delete(breakpoint: BreakpointEntity)

    @Query("DELETE FROM breakpoints WHERE id = :id")
    suspend fun deleteById(id: String)

    @Query("UPDATE breakpoints SET enabled = :enabled WHERE id = :id")
    suspend fun setEnabled(id: String, enabled: Boolean)

    @Query("UPDATE breakpoints SET hitCount = hitCount + 1 WHERE id = :id")
    suspend fun bumpHit(id: String)

    @Query("DELETE FROM breakpoints WHERE tabId = :tabId")
    suspend fun clearByTab(tabId: String)
}

@Dao
interface UserScriptDao {
    @Query("SELECT * FROM user_scripts ORDER BY createdAt DESC")
    fun observeAll(): Flow<List<UserScriptEntity>>

    @Query("SELECT * FROM user_scripts ORDER BY createdAt DESC")
    suspend fun getAll(): List<UserScriptEntity>

    @Query("SELECT * FROM user_scripts WHERE id = :id")
    suspend fun getById(id: String): UserScriptEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(script: UserScriptEntity)

    @Delete
    suspend fun delete(script: UserScriptEntity)

    @Query("UPDATE user_scripts SET enabled = :enabled WHERE id = :id")
    suspend fun setEnabled(id: String, enabled: Boolean)
}
