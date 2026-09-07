package com.webreverse.mcp.core.database.repository

import com.webreverse.mcp.core.database.dao.NetworkEntryDao
import com.webreverse.mcp.core.database.entity.NetworkEntryEntity
import kotlinx.coroutines.flow.Flow

/** 网络条目仓库 */
class NetworkRepository(private val dao: NetworkEntryDao) {
    fun observeByTab(tabId: String, limit: Int = 500): Flow<List<NetworkEntryEntity>> =
        dao.observeByTab(tabId, limit)

    suspend fun getByTab(tabId: String, limit: Int = 500): List<NetworkEntryEntity> =
        dao.getByTab(tabId, limit)

    suspend fun getById(id: String): NetworkEntryEntity? = dao.getById(id)

    suspend fun search(query: String, limit: Int = 200): List<NetworkEntryEntity> =
        dao.search(query, limit)

    suspend fun upsert(entry: NetworkEntryEntity) = dao.upsert(entry)

    suspend fun clearByTab(tabId: String) = dao.clearByTab(tabId)
    suspend fun clearAll() = dao.clearAll()
}
