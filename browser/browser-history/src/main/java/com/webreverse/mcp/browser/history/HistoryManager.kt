package com.webreverse.mcp.browser.history

import com.webreverse.mcp.core.database.entity.HistoryEntity
import com.webreverse.mcp.core.database.repository.HistoryRepository
import kotlinx.coroutines.flow.Flow

/** 历史记录管理器 */
class HistoryManager(private val repository: HistoryRepository) {
    fun observeRecent(limit: Int = 200): Flow<List<HistoryEntity>> = repository.observeRecent(limit)
    fun search(query: String): Flow<List<HistoryEntity>> = repository.search(query)
    suspend fun getRecent(limit: Int = 200): List<HistoryEntity> = repository.getRecent(limit)

    suspend fun recordVisit(url: String, title: String) {
        if (url.isBlank() || url.startsWith("about:") || url.startsWith("data:")) return
        repository.recordVisit(url, title.ifBlank { url })
    }

    suspend fun delete(entry: HistoryEntity) = repository.delete(entry)
    suspend fun clearAll() = repository.clearAll()
}
