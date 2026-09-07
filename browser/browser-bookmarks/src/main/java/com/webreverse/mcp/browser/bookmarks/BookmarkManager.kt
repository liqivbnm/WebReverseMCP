package com.webreverse.mcp.browser.bookmarks

import com.webreverse.mcp.core.database.entity.BookmarkEntity
import com.webreverse.mcp.core.database.repository.BookmarkRepository
import kotlinx.coroutines.flow.Flow

/** 收藏夹管理器 */
class BookmarkManager(private val repository: BookmarkRepository) {
    fun observeAll(): Flow<List<BookmarkEntity>> = repository.observeAll()
    fun observeByFolder(folder: String): Flow<List<BookmarkEntity>> = repository.observeByFolder(folder)
    suspend fun getAll(): List<BookmarkEntity> = repository.getAll()
    suspend fun isBookmarked(url: String): Boolean = repository.isBookmarked(url)
    suspend fun add(title: String, url: String, folder: String = "默认"): Boolean =
        repository.add(title, url, folder)
    suspend fun remove(url: String) = repository.remove(url)
    suspend fun deleteById(id: Long) = repository.deleteById(id)
    suspend fun clearAll() = repository.clearAll()
}
