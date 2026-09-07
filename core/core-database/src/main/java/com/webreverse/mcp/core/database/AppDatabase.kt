package com.webreverse.mcp.core.database

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import com.webreverse.mcp.core.database.dao.AnalysisResultDao
import com.webreverse.mcp.core.database.dao.BookmarkDao
import com.webreverse.mcp.core.database.dao.BreakpointDao
import com.webreverse.mcp.core.database.dao.BrowserTabDao
import com.webreverse.mcp.core.database.dao.FindingDao
import com.webreverse.mcp.core.database.dao.HistoryDao
import com.webreverse.mcp.core.database.dao.HookRuleDao
import com.webreverse.mcp.core.database.dao.InvestigationDao
import com.webreverse.mcp.core.database.dao.McpSessionDao
import com.webreverse.mcp.core.database.dao.McpToolConfigDao
import com.webreverse.mcp.core.database.dao.NetworkEntryDao
import com.webreverse.mcp.core.database.dao.NoteDao
import com.webreverse.mcp.core.database.dao.TargetDao
import com.webreverse.mcp.core.database.dao.UserScriptDao
import com.webreverse.mcp.core.database.dao.WorkspaceDao
import com.webreverse.mcp.core.database.entity.AnalysisResultEntity
import com.webreverse.mcp.core.database.entity.BookmarkEntity
import com.webreverse.mcp.core.database.entity.BreakpointEntity
import com.webreverse.mcp.core.database.entity.BrowserTabEntity
import com.webreverse.mcp.core.database.entity.FindingEntity
import com.webreverse.mcp.core.database.entity.HistoryEntity
import com.webreverse.mcp.core.database.entity.HookRuleEntity
import com.webreverse.mcp.core.database.entity.InvestigationActionEntity
import com.webreverse.mcp.core.database.entity.InvestigationEntity
import com.webreverse.mcp.core.database.entity.InvestigationStageEntity
import com.webreverse.mcp.core.database.entity.McpSessionEntity
import com.webreverse.mcp.core.database.entity.McpToolConfigEntity
import com.webreverse.mcp.core.database.entity.NetworkEntryEntity
import com.webreverse.mcp.core.database.entity.NoteEntity
import com.webreverse.mcp.core.database.entity.TargetEntity
import com.webreverse.mcp.core.database.entity.UserScriptEntity
import com.webreverse.mcp.core.database.entity.WorkspaceEntity

@Database(
    entities = [
        BrowserTabEntity::class,
        HistoryEntity::class,
        BookmarkEntity::class,
        WorkspaceEntity::class,
        TargetEntity::class,
        NetworkEntryEntity::class,
        HookRuleEntity::class,
        BreakpointEntity::class,
        UserScriptEntity::class,
        McpToolConfigEntity::class,
        McpSessionEntity::class,
        AnalysisResultEntity::class,
        FindingEntity::class,
        NoteEntity::class,
        InvestigationEntity::class,
        InvestigationStageEntity::class,
        InvestigationActionEntity::class,
    ],
    version = 2,
    exportSchema = true,
)
@TypeConverters(Converters::class)
abstract class AppDatabase : RoomDatabase() {
    abstract fun browserTabDao(): BrowserTabDao
    abstract fun historyDao(): HistoryDao
    abstract fun bookmarkDao(): BookmarkDao
    abstract fun workspaceDao(): WorkspaceDao
    abstract fun targetDao(): TargetDao
    abstract fun networkEntryDao(): NetworkEntryDao
    abstract fun hookRuleDao(): HookRuleDao
    abstract fun breakpointDao(): BreakpointDao
    abstract fun userScriptDao(): UserScriptDao
    abstract fun mcpToolConfigDao(): McpToolConfigDao
    abstract fun mcpSessionDao(): McpSessionDao
    abstract fun analysisResultDao(): AnalysisResultDao
    abstract fun findingDao(): FindingDao
    abstract fun noteDao(): NoteDao
    abstract fun investigationDao(): InvestigationDao

    companion object {
        @Volatile
        private var instance: AppDatabase? = null

        fun get(context: Context): AppDatabase = instance ?: synchronized(this) {
            instance ?: Room.databaseBuilder(
                context.applicationContext,
                AppDatabase::class.java,
                "webreverse_mcp.db",
            )
                // P0-7 规范：废弃 fallbackToDestructiveMigration，改用显式增量迁移，
                // 避免后续 schema 变更把 Workspace/Finding/Notes/Network/Investigation 等镀层清空。
                .addMigrations(MIGRATION_1_2)
                .build()
                .also { instance = it }
        }

        /**
         * 1 → 2：新增逆向调查三张表（investigations / investigation_stages / investigation_actions）。
         * 纯新增表，不动已有表结构，老数据完整保留。
         */
        private val MIGRATION_1_2 = androidx.room.migration.Migration(1, 2) { db ->
            db.execSQL(
                """CREATE TABLE IF NOT EXISTS `investigations` (
                    `id` TEXT NOT NULL,
                    `workspaceId` TEXT,
                    `mcpSessionId` TEXT NOT NULL,
                    `targetId` TEXT,
                    `goal` TEXT NOT NULL,
                    `target` TEXT NOT NULL,
                    `status` TEXT NOT NULL,
                    `confidence` REAL NOT NULL,
                    `summary` TEXT NOT NULL,
                    `bestCandidate` TEXT NOT NULL,
                    `createdAt` INTEGER NOT NULL,
                    `updatedAt` INTEGER NOT NULL,
                    PRIMARY KEY(`id`)
                )""",
            )
            db.execSQL("CREATE INDEX IF NOT EXISTS `index_investigations_mcpSessionId` ON `investigations` (`mcpSessionId`)")
            db.execSQL("CREATE INDEX IF NOT EXISTS `index_investigations_workspaceId` ON `investigations` (`workspaceId`)")

            db.execSQL(
                """CREATE TABLE IF NOT EXISTS `investigation_stages` (
                    `id` TEXT NOT NULL,
                    `investigationId` TEXT NOT NULL,
                    `name` TEXT NOT NULL,
                    `description` TEXT NOT NULL,
                    `status` TEXT NOT NULL,
                    `confidence` REAL NOT NULL,
                    `detail` TEXT NOT NULL,
                    `requiredAction` TEXT NOT NULL,
                    `startedAt` INTEGER NOT NULL,
                    `completedAt` INTEGER,
                    PRIMARY KEY(`id`)
                )""",
            )
            db.execSQL("CREATE INDEX IF NOT EXISTS `index_investigation_stages_investigationId` ON `investigation_stages` (`investigationId`)")

            db.execSQL(
                """CREATE TABLE IF NOT EXISTS `investigation_actions` (
                    `id` TEXT NOT NULL,
                    `investigationId` TEXT NOT NULL,
                    `stageId` TEXT,
                    `tool` TEXT NOT NULL,
                    `arguments` TEXT NOT NULL,
                    `result` TEXT NOT NULL,
                    `status` TEXT NOT NULL,
                    `createdAt` INTEGER NOT NULL,
                    PRIMARY KEY(`id`)
                )""",
            )
            db.execSQL("CREATE INDEX IF NOT EXISTS `index_investigation_actions_investigationId` ON `investigation_actions` (`investigationId`)")
            db.execSQL("CREATE INDEX IF NOT EXISTS `index_investigation_actions_stageId` ON `investigation_actions` (`stageId`)")
        }
    }
}
