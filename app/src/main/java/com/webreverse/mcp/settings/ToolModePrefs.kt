package com.webreverse.mcp.settings

import android.content.Context

/**
 * MCP 工具暴露模式偏好。
 *
 * 由用户在设置页手动开关（不提供 MCP 工具切换，避免 AI 自行变更暴露面）：
 * - true（默认）：聚合模式，tools/list 只返回约 34 个命名空间枢纽工具
 * - false：全量模式，返回全部 400+ 原始工具
 * 两种模式下原工具均可按全名直调。
 */
object ToolModePrefs {
    private const val PREFS = "mcp_prefs"
    private const val KEY_COMPACT = "tool_hub_compact"

    fun isCompact(context: Context): Boolean =
        context.applicationContext
            .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getBoolean(KEY_COMPACT, true)

    fun setCompact(context: Context, compact: Boolean) {
        context.applicationContext
            .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(KEY_COMPACT, compact)
            .apply()
    }
}
