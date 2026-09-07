package com.webreverse.mcp.core.database.entity

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(tableName = "browser_tabs", indices = [Index("url"), Index("groupId")])
data class BrowserTabEntity(
    @PrimaryKey val id: String,
    val title: String = "",
    val url: String = "",
    val originalUrl: String = "",
    val faviconUrl: String? = null,
    val groupId: String? = null,
    val isIncognito: Boolean = false,
    val isPinned: Boolean = false,
    val isMuted: Boolean = false,
    val createdAt: Long = System.currentTimeMillis(),
    val lastAccessedAt: Long = System.currentTimeMillis(),
)

@Entity(tableName = "history", indices = [Index("url"), Index("visitTime")])
data class HistoryEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val url: String,
    val title: String,
    val visitTime: Long = System.currentTimeMillis(),
    val visitCount: Int = 1,
    val faviconUrl: String? = null,
)

@Entity(tableName = "bookmarks", indices = [Index("url", unique = true)])
data class BookmarkEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val title: String,
    val url: String,
    val folder: String = "默认",
    val createdAt: Long = System.currentTimeMillis(),
    val faviconUrl: String? = null,
)

@Entity(tableName = "workspaces")
data class WorkspaceEntity(
    @PrimaryKey val id: String,
    val name: String,
    val description: String = "",
    val targetUrl: String = "",
    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis(),
)

@Entity(tableName = "targets", indices = [Index("url")])
data class TargetEntity(
    @PrimaryKey val id: String,
    val name: String,
    val url: String,
    val framework: String? = null,
    val notes: String = "",
    val createdAt: Long = System.currentTimeMillis(),
    val lastAnalyzedAt: Long? = null,
)

@Entity(tableName = "network_entries", indices = [Index("tabId"), Index("url"), Index("requestId")])
data class NetworkEntryEntity(
    @PrimaryKey val id: String,
    val tabId: String,
    val requestId: String,
    val url: String,
    val method: String = "GET",
    val status: Int = 0,
    val statusText: String = "",
    val protocol: String = "",
    val mimeType: String = "",
    val resourceType: String = "Other",
    val requestHeaders: String = "{}",
    val responseHeaders: String = "{}",
    val queryParams: String = "{}",
    val requestBody: String? = null,
    val responseBody: String? = null,
    val requestBodySize: Long = 0,
    val responseBodySize: Long = 0,
    val timingJson: String = "{}",
    val initiator: String = "",
    val initiatorStack: String = "",
    val remoteAddress: String = "",
    val isRedirect: Boolean = false,
    val redirectUrl: String? = null,
    val fromCache: Boolean = false,
    val fromServiceWorker: Boolean = false,
    val isBlocked: Boolean = false,
    val blockedReason: String? = null,
    val isMocked: Boolean = false,
    val startedAt: Long = System.currentTimeMillis(),
    val endedAt: Long = 0,
    val cookiesJson: String = "[]",
)

@Entity(tableName = "hook_rules")
data class HookRuleEntity(
    @PrimaryKey val id: String,
    val name: String,
    val type: String = "FETCH",
    val matchJson: String = "{}",
    val action: String = "LOG",
    val enabled: Boolean = true,
    val payload: String = "",
    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis(),
    val hitCount: Long = 0,
    val lastTriggeredAt: Long? = null,
    val description: String = "",
)

@Entity(tableName = "breakpoints", indices = [Index("tabId")])
data class BreakpointEntity(
    @PrimaryKey val id: String,
    val tabId: String,
    val type: String = "LINE",
    val url: String = "",
    val scriptId: String? = null,
    val lineNumber: Int = 0,
    val columnNumber: Int = 0,
    val condition: String? = null,
    val logExpression: String? = null,
    val enabled: Boolean = true,
    val hitCount: Int = 0,
    val createdAt: Long = System.currentTimeMillis(),
    val target: String? = null,
)

@Entity(tableName = "user_scripts")
data class UserScriptEntity(
    @PrimaryKey val id: String,
    val name: String,
    val description: String = "",
    val code: String,
    val runAt: String = "MANUAL",
    val matchPatterns: String = "[]",
    val enabled: Boolean = true,
    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis(),
)

@Entity(tableName = "mcp_tool_configs")
data class McpToolConfigEntity(
    @PrimaryKey val name: String,
    val enabled: Boolean = true,
    val configJson: String = "{}",
    val updatedAt: Long = System.currentTimeMillis(),
)

@Entity(tableName = "mcp_sessions")
data class McpSessionEntity(
    @PrimaryKey val id: String,
    val clientId: String,
    val clientName: String,
    val startedAt: Long = System.currentTimeMillis(),
    val endedAt: Long? = null,
    val toolCallCount: Int = 0,
    val status: String = "ACTIVE",
)

@Entity(tableName = "analysis_results")
data class AnalysisResultEntity(
    @PrimaryKey val id: String,
    val workspaceId: String? = null,
    val type: String,
    val title: String,
    val summary: String = "",
    val content: String = "",
    val confidence: Double = 0.0,
    val findingsJson: String = "[]",
    val relatedUrlsJson: String = "[]",
    val createdAt: Long = System.currentTimeMillis(),
    val dataJson: String = "{}",
)

@Entity(tableName = "findings", indices = [Index("workspaceId")])
data class FindingEntity(
    @PrimaryKey val id: String,
    val workspaceId: String? = null,
    val type: String,
    val title: String,
    val description: String = "",
    val evidence: String = "",
    val source: String = "",
    val line: Int = 0,
    val confidence: String = "MEDIUM",
    val severity: String = "INFO",
    val relatedTool: String? = null,
    val relatedRequest: String? = null,
    val relatedFunction: String? = null,
    val createdAt: Long = System.currentTimeMillis(),
    val dataJson: String = "{}",
)

@Entity(tableName = "notes")
data class NoteEntity(
    @PrimaryKey val id: String,
    val workspaceId: String? = null,
    val title: String,
    val content: String = "",
    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis(),
)
