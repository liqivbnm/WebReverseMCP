package com.webreverse.mcp.core.common.util

import android.content.Context
import android.os.Environment
import java.io.File

/**
 * 统一工作目录管理：所有产出文件（PDF / 下载 / 导出等）默认存放于此目录。
 *
 * - 默认目录：/storage/emulated/0/Download/WebReverseMCP
 * - 可在设置页自定义并持久化（SharedPreferences）
 * - 目录不可写时（未授予"所有文件权限"）自动回退到应用外部私有目录，
 *   保证工具调用不会因权限问题直接失败
 */
object WorkDir {

    const val DEFAULT_PATH = "/storage/emulated/0/Download/WebReverseMCP"

    private const val PREFS_NAME = "webreverse_prefs"
    private const val KEY_WORK_DIR = "work_directory"

    @Volatile
    private var current: String = DEFAULT_PATH

    /** 初始化：读取持久化的工作目录（应用启动时调用一次） */
    fun init(context: Context) {
        val prefs = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        current = prefs.getString(KEY_WORK_DIR, null)?.takeIf { it.isNotBlank() } ?: DEFAULT_PATH
    }

    /** 当前工作目录路径 */
    fun get(): String = current

    /** 设置工作目录：目录必须能成功创建且可写，成功后持久化 */
    fun set(context: Context, path: String): Boolean {
        val trimmed = path.trim().trimEnd('/')
        if (trimmed.isEmpty()) return false
        return try {
            val dir = File(trimmed)
            dir.mkdirs()
            if (dir.isDirectory && dir.canWrite()) {
                current = trimmed
                context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                    .edit()
                    .putString(KEY_WORK_DIR, trimmed)
                    .apply()
                true
            } else {
                false
            }
        } catch (e: Exception) {
            false
        }
    }

    /** 恢复默认工作目录 */
    fun reset(context: Context): Boolean = set(context, DEFAULT_PATH)

    /** 主工作目录是否可写（用于 UI 状态提示与下载策略选择） */
    fun isWritable(): Boolean = try {
        val dir = File(current)
        dir.mkdirs()
        dir.canWrite()
    } catch (e: Exception) {
        false
    }

    /**
     * 解析工作目录下的文件路径（文件名做净化，禁止路径穿越）。
     * 主目录不可写时回退到应用外部私有下载目录，保证调用方总能拿到可写位置。
     */
    fun resolve(context: Context, filename: String): File {
        val safeName = sanitize(filename)
        return try {
            val dir = File(current)
            dir.mkdirs()
            if (dir.canWrite()) File(dir, safeName) else fallbackDir(context).let { File(it, safeName) }
        } catch (e: Exception) {
            File(fallbackDir(context), safeName)
        }
    }

    /** 工作目录本身（不可写时回退应用私有目录） */
    fun directory(context: Context): File = try {
        val dir = File(current)
        dir.mkdirs()
        if (dir.canWrite()) dir else fallbackDir(context)
    } catch (e: Exception) {
        fallbackDir(context)
    }

    /** 净化文件名：剥掉路径分隔符，防止越出工作目录；空名回退为时间戳名 */
    private fun sanitize(filename: String): String {
        val safe = filename.replace("/", "_").replace("\\", "_").replace("\u0000", "").trim()
        return safe.ifBlank { "file-${System.currentTimeMillis()}" }
    }

    private fun fallbackDir(context: Context): File {
        val dir = context.applicationContext.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS)
            ?: context.applicationContext.filesDir
        dir.mkdirs()
        return dir
    }
}
