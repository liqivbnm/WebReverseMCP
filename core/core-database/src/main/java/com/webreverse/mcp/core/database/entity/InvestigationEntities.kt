package com.webreverse.mcp.core.database.entity

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/** 一次逆向调查（P0-7 / P1-14 持久化：App 重启后调查任务可恢复） */
@Entity(tableName = "investigations", indices = [Index("mcpSessionId"), Index("workspaceId")])
data class InvestigationEntity(
    @PrimaryKey val id: String,
    val workspaceId: String? = null,
    val mcpSessionId: String,
    val targetId: String? = null,
    val goal: String,
    val target: String,
    val status: String,
    val confidence: Double = 0.0,
    val summary: String = "",
    val bestCandidate: String = "",
    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis(),
)

/** 调查中的阶段 */
@Entity(tableName = "investigation_stages", indices = [Index("investigationId")])
data class InvestigationStageEntity(
    @PrimaryKey val id: String,
    val investigationId: String,
    val name: String,
    val description: String = "",
    val status: String,
    val confidence: Double = 0.0,
    val detail: String = "",
    val requiredAction: String = "",
    val startedAt: Long = System.currentTimeMillis(),
    val completedAt: Long? = null,
)

/** Agent 为推进调查所执行的工具动作（investigation_actions） */
@Entity(tableName = "investigation_actions", indices = [Index("investigationId"), Index("stageId")])
data class InvestigationActionEntity(
    @PrimaryKey val id: String,
    val investigationId: String,
    val stageId: String? = null,
    val tool: String,
    val arguments: String = "{}",
    val result: String = "",
    val status: String = "PENDING",
    val createdAt: Long = System.currentTimeMillis(),
)