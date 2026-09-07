package com.webreverse.mcp.mcp.tools.terminal

import android.content.Context
import java.io.File

/**
 * 终端相关路径管理。
 *
 * 关键约束（Android 运行时验证）：交互式 shell 的**工作目录 cwd** 若落在共享存储
 * （/storage/emulated/0，FUSE）上，会破坏交互式终端的完成标记/换行回车行为
 * （回车后不显示提示符、需两次回车才换行）。因此交互式终端必须启动在应用私有目录。
 *
 * 为此，终端路径分两套：
 * - homeDir（私有 filesDir/home）—— 交互式终端的工作目录与 `~`，保证换行回车正常；
 * - workspaceDir（设置里的工作区目录，如 /storage/emulated/0/Download/WebReverseMCP）——
 *   一次性 `terminal.exec / run_python / run_node` 的默认工作目录，AI 保存的
 *   Python/JS 等文件默认落在工作区，用户在存储目录/文件管理器即可见
 *   （一次性执行不经过回显标记机制，共享存储 cwd 无问题）。
 *
 * shell 运行环境与内部设施同样保持在应用私有目录：
 * - shellHomeDir — `$HOME`（私有，配合私有 cwd 保证交互式完成标记稳定）
 * - tmp/ — TMPDIR（私有）+ python/node 包装脚本（共享存储 noexec）
 * - host_tools/prefix/ — Host Tools 安装前缀（共享存储 noexec）
 * - scripts/ logs/ — AI 生成的脚本 / 日志（私有）
 */
object TerminalPaths {

    @Volatile
    private var appContext: Context? = null

    fun init(context: Context) {
        appContext = context.applicationContext
        ensureDirectories()
    }

    private fun ctx(): Context =
        appContext ?: throw IllegalStateException("TerminalPaths 未初始化，请先调用 init(context)")

    /** Host Tools 安装根目录 */
    val hostToolsRootDir: File
        get() = File(ctx().filesDir, "host_tools")

    /** Host Tools prefix 目录（镜像 Termux 的 /data/data/com.termux/files/usr/） */
    val hostToolsPrefixDir: File
        get() = File(hostToolsRootDir, "prefix")

    /** Host Tools 下载临时文件目录 */
    val hostToolsDownloadDir: File
        get() = File(ctx().cacheDir, "host_tools_download")

    // ==================== NDK（终端内置 NDK，pip 编译 C 扩展用）====================

    /** NDK 安装根目录（应用私有目录，参考 NdkCompiler 的 PathUtils.ndkRootDir） */
    val ndkRootDir: File
        get() = File(ctx().filesDir, "ndk")

    /** NDK 下载临时文件目录 */
    val ndkDownloadDir: File
        get() = File(ctx().cacheDir, "ndk_download")

    /** NDK pip 编译工具链 wrapper 目录（稳定路径，内容随 NDK 安装/卸载重建） */
    val ndkPipBinDir: File
        get() = File(ndkRootDir, "pip-bin")

    /**
     * 交互式 terminal 的工作目录（`~`）：固定在应用私有目录。
     *
     * Android 运行时验证：cwd 落在共享存储会破坏交互式完成标记/换行回车
     * （1.37.0 回归就是 homeDir 指向 WorkDir 所致）。故交互式必须私有目录。
     */
    val homeDir: File
        get() = File(ctx().filesDir, "home")

    /**
     * 一次性 `terminal.exec / run_python / run_node` 的默认工作目录 =
     * 设置里的工作（存储）目录。AI 通过终端 MCP 保存的 Python/JS 等文件
     * 默认落在这里；不可写时随 [com.webreverse.mcp.core.common.util.WorkDir] 自动回退。
     */
    val workspaceDir: File
        get() = com.webreverse.mcp.core.common.util.WorkDir.directory(ctx())

    /** 一次性执行进程的 `$HOME`（固定应用私有目录，稳定运行环境） */
    val shellHomeDir: File
        get() = File(ctx().filesDir, "home")

    /** 临时目录（TMPDIR；应用私有，脚本由解释器执行、无需 exec 权限） */
    val tmpDir: File
        get() = File(ctx().cacheDir, "tmp")

    /** 脚本目录（AI 生成的脚本默认存放处） */
    val scriptsDir: File
        get() = File(ctx().filesDir, "scripts")

    /** 日志目录 */
    val logDir: File
        get() = File(ctx().filesDir, "logs")

    fun ensureDirectories() {
        listOf(
            hostToolsRootDir, hostToolsPrefixDir, hostToolsDownloadDir,
            ndkRootDir, ndkDownloadDir, ndkPipBinDir,
            homeDir, tmpDir, scriptsDir, logDir,
        ).forEach {
            if (!it.exists() && !it.mkdirs()) {
                android.util.Log.w("TerminalPaths", "Failed to create directory: ${it.absolutePath}")
            }
        }
    }

    /** 计算文件或目录的可读大小描述 */
    fun formatSize(bytes: Long): String {
        val units = arrayOf("B", "KB", "MB", "GB")
        var size = bytes.toDouble()
        var unitIndex = 0
        while (size >= 1024 && unitIndex < units.lastIndex) {
            size /= 1024
            unitIndex++
        }
        return String.format("%.1f %s", size, units[unitIndex])
    }

    /** 递归删除目录 */
    fun deleteRecursively(file: File): Boolean = file.deleteRecursively()
}
