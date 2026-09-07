package com.webreverse.mcp.core.database.repository

import com.webreverse.mcp.core.database.dao.BookmarkDao
import com.webreverse.mcp.core.database.dao.HistoryDao
import com.webreverse.mcp.core.database.entity.BookmarkEntity
import com.webreverse.mcp.core.database.entity.HistoryEntity
import kotlinx.coroutines.flow.Flow

/** 历史记录仓库 */
class HistoryRepository(private val dao: HistoryDao) {
    fun observeRecent(limit: Int = 200): Flow<List<HistoryEntity>> = dao.observeRecent(limit)
    fun search(query: String): Flow<List<HistoryEntity>> = dao.search(query)
    suspend fun getRecent(limit: Int = 200): List<HistoryEntity> = dao.getRecent(limit)

    suspend fun recordVisit(url: String, title: String) {
        val safeTitle = title.ifBlank { url }
        val existing = dao.findByUrl(url)
        if (existing != null) {
            dao.bumpVisit(url, System.currentTimeMillis(), safeTitle)
        } else {
            dao.insert(HistoryEntity(url = url, title = safeTitle))
        }
    }

    suspend fun delete(entry: HistoryEntity) = dao.delete(entry)
    suspend fun clearAll() = dao.clearAll()
}

/** 收藏夹仓库 */
class BookmarkRepository(private val dao: BookmarkDao) {
    fun observeAll(): Flow<List<BookmarkEntity>> = dao.observeAll()
    fun observeByFolder(folder: String): Flow<List<BookmarkEntity>> = dao.observeByFolder(folder)
    suspend fun getAll(): List<BookmarkEntity> = dao.getAll()
    suspend fun isBookmarked(url: String): Boolean = dao.findByUrl(url) != null

    suspend fun add(title: String, url: String, folder: String = "默认"): Boolean {
        if (dao.findByUrl(url) != null) return false
        dao.insert(BookmarkEntity(title = title, url = url, folder = folder))
        return true
    }

    suspend fun remove(url: String) {
        dao.findByUrl(url)?.let { dao.delete(it) }
    }

    suspend fun deleteById(id: Long) = dao.deleteById(id)
    suspend fun clearAll() = dao.clearAll()
}
