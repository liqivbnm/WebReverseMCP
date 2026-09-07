package com.webreverse.mcp.core.database.repository

import com.webreverse.mcp.core.database.dao.BreakpointDao
import com.webreverse.mcp.core.database.dao.HookRuleDao
import com.webreverse.mcp.core.database.dao.UserScriptDao
import com.webreverse.mcp.core.database.entity.BreakpointEntity
import com.webreverse.mcp.core.database.entity.HookRuleEntity
import com.webreverse.mcp.core.database.entity.UserScriptEntity
import kotlinx.coroutines.flow.Flow

/** Hook 规则仓库 */
class HookRuleRepository(private val dao: HookRuleDao) {
    fun observeAll(): Flow<List<HookRuleEntity>> = dao.observeAll()
    suspend fun getAll(): List<HookRuleEntity> = dao.getAll()
    suspend fun getById(id: String): HookRuleEntity? = dao.getById(id)
    suspend fun upsert(rule: HookRuleEntity) = dao.upsert(rule)
    suspend fun deleteById(id: String) = dao.deleteById(id)
    suspend fun setEnabled(id: String, enabled: Boolean) = dao.setEnabled(id, enabled)
    suspend fun bumpHit(id: String) = dao.bumpHit(id, System.currentTimeMillis())
}

/** 断点仓库 */
class BreakpointRepository(private val dao: BreakpointDao) {
    fun observeByTab(tabId: String): Flow<List<BreakpointEntity>> = dao.observeByTab(tabId)
    suspend fun getByTab(tabId: String): List<BreakpointEntity> = dao.getByTab(tabId)
    suspend fun getById(id: String): BreakpointEntity? = dao.getById(id)
    suspend fun upsert(breakpoint: BreakpointEntity) = dao.upsert(breakpoint)
    suspend fun deleteById(id: String) = dao.deleteById(id)
    suspend fun setEnabled(id: String, enabled: Boolean) = dao.setEnabled(id, enabled)
    suspend fun bumpHit(id: String) = dao.bumpHit(id)
    suspend fun clearByTab(tabId: String) = dao.clearByTab(tabId)
}

/** 用户脚本仓库 */
class UserScriptRepository(private val dao: UserScriptDao) {
    fun observeAll(): Flow<List<UserScriptEntity>> = dao.observeAll()
    suspend fun getAll(): List<UserScriptEntity> = dao.getAll()
    suspend fun getById(id: String): UserScriptEntity? = dao.getById(id)
    suspend fun upsert(script: UserScriptEntity) = dao.upsert(script)
    suspend fun delete(script: UserScriptEntity) = dao.delete(script)
    suspend fun setEnabled(id: String, enabled: Boolean) = dao.setEnabled(id, enabled)
}
