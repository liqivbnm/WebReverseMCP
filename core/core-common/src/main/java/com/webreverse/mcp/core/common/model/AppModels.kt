package com.webreverse.mcp.core.common.model

import kotlinx.serialization.Serializable

/** 浏览器标签页领域模型 */
@Serializable
data class BrowserTab(
    val id: String,
    val title: String = "",
    val url: String = "",
    val originalUrl: String = "",
    val faviconUrl: String? = null,
    val groupId: String? = null,
    val isIncognito: Boolean = false,
    val isPinned: Boolean = false,
    val isMuted: Boolean = false,
    val isLoading: Boolean = false,
    val progress: Int = 0,
    val canGoBack: Boolean = false,
    val canGoForward: Boolean = false,
    val createdAt: Long = System.currentTimeMillis(),
    val lastAccessedAt: Long = System.currentTimeMillis(),
    val thumbnailPath: String? = null,
    val sessionId: String = id,
)

/** 标签组 */
@Serializable
data class TabGroup(
    val id: String,
    val name: String,
    val color: Long = 0xFF6200EE,
    val collapsed: Boolean = false,
    val tabIds: List<String> = emptyList(),
)

/** 历史记录条目 */
@Serializable
data class HistoryEntry(
    val id: Long = 0,
    val url: String,
    val title: String,
    val visitTime: Long = System.currentTimeMillis(),
    val visitCount: Int = 1,
    val faviconUrl: String? = null,
)

/** 收藏夹条目 */
@Serializable
data class Bookmark(
    val id: Long = 0,
    val title: String,
    val url: String,
    val folder: String = "默认",
    val createdAt: Long = System.currentTimeMillis(),
    val faviconUrl: String? = null,
)

/** 分析目标（Target） */
@Serializable
data class Target(
    val id: String,
    val name: String,
    val url: String,
    val framework: String? = null,
    val notes: String = "",
    val createdAt: Long = System.currentTimeMillis(),
    val lastAnalyzedAt: Long? = null,
)

/** 最近关闭的标签 */
@Serializable
data class RecentlyClosedTab(
    val id: String,
    val title: String,
    val url: String,
    val closedAt: Long = System.currentTimeMillis(),
)
