package com.webreverse.mcp.mcp.tools.terminal

import java.io.File

/**
 * Host Tools（Git / Python / Perl 等）安装状态。
 */
sealed class HostToolsState {
    /** 未安装 */
    data object NotInstalled : HostToolsState()

    /** 下载中（进度 0-100） */
    data class Downloading(val progress: Int, val message: String) : HostToolsState()

    /** 解压中（进度 0-100） */
    data class Extracting(val progress: Int, val message: String) : HostToolsState()

    /** 配置中（修复 shebang、设置权限等） */
    data class Configuring(val progress: Int, val message: String) : HostToolsState()

    /** 已安装 */
    data class Installed(
        val prefixDir: File,
        val gitPath: File?,
        val pythonPath: File?,
        val perlPath: File? = null,
        val arch: String,
        /** 额外安装的工具包列表（如 make, gawk, cmake 等） */
        val additionalPackages: List<String> = emptyList(),
    ) : HostToolsState()

    /** 安装失败 */
    data class Failed(val message: String) : HostToolsState()
}
