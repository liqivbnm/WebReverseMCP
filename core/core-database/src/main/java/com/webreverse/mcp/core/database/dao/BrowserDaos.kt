package com.webreverse.mcp.core.database.dao

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import com.webreverse.mcp.core.database.entity.BrowserTabEntity
import com.webreverse.mcp.core.database.entity.HistoryEntity
import com.webreverse.mcp.core.database.entity.BookmarkEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface BrowserTabDao {
    @Query("SELECT * FROM browser_tabs ORDER BY lastAccessedAt DESC")
    fun observeAll(): Flow<List<BrowserTabEntity>>

    @Query("SELECT * FROM browser_tabs WHERE id = :id")
    suspend fun getById(id: String): BrowserTabEntity?

    @Query("SELECT * FROM browser_tabs ORDER BY lastAccessedAt DESC")
    suspend fun getAll(): List<BrowserTabEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(tab: BrowserTabEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertAll(tabs: List<BrowserTabEntity>)

    @Update
    suspend fun update(tab: BrowserTabEntity)

    @Delete
    suspend fun delete(tab: BrowserTabEntity)

    @Query("DELETE FROM browser_tabs WHERE id = :id")
    suspend fun deleteById(id: String)

    @Query("DELETE FROM browser_tabs")
    suspend fun clearAll()
}

@Dao
interface HistoryDao {
    @Query("SELECT * FROM history ORDER BY visitTime DESC LIMIT :limit")
    fun observeRecent(limit: Int = 200): Flow<List<HistoryEntity>>

    @Query("SELECT * FROM history WHERE url LIKE '%' || :query || '%' OR title LIKE '%' || :query || '%' ORDER BY visitTime DESC")
    fun search(query: String): Flow<List<HistoryEntity>>

    @Query("SELECT * FROM history ORDER BY visitTime DESC LIMIT :limit")
    suspend fun getRecent(limit: Int = 200): List<HistoryEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(entry: HistoryEntity)

    @Query("SELECT * FROM history WHERE url = :url LIMIT 1")
    suspend fun findByUrl(url: String): HistoryEntity?

    @Query("UPDATE history SET visitCount = visitCount + 1, visitTime = :time, title = :title WHERE url = :url")
    suspend fun bumpVisit(url: String, time: Long, title: String)

    @Delete
    suspend fun delete(entry: HistoryEntity)

    @Query("DELETE FROM history")
    suspend fun clearAll()

    @Query("DELETE FROM history WHERE id = :id")
    suspend fun deleteById(id: Long)
}

@Dao
interface BookmarkDao {
    @Query("SELECT * FROM bookmarks ORDER BY createdAt DESC")
    fun observeAll(): Flow<List<BookmarkEntity>>

    @Query("SELECT * FROM bookmarks WHERE folder = :folder ORDER BY createdAt DESC")
    fun observeByFolder(folder: String): Flow<List<BookmarkEntity>>

    @Query("SELECT * FROM bookmarks ORDER BY createdAt DESC")
    suspend fun getAll(): List<BookmarkEntity>

    @Query("SELECT * FROM bookmarks WHERE url = :url LIMIT 1")
    suspend fun findByUrl(url: String): BookmarkEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(bookmark: BookmarkEntity)

    @Delete
    suspend fun delete(bookmark: BookmarkEntity)

    @Query("DELETE FROM bookmarks WHERE id = :id")
    suspend fun deleteById(id: Long)

    @Query("DELETE FROM bookmarks")
    suspend fun clearAll()
}
