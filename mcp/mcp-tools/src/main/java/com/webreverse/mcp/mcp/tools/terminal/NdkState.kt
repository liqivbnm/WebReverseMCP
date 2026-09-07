package com.webreverse.mcp.mcp.tools.terminal

/**
 * NDK 安装状态（参考 NdkCompiler 的 NdkState / HostToolsState 风格）。
 */
sealed class NdkState {

    /** 未安装 */
    data object NotInstalled : NdkState()

    /** 正在下载（progress 0-100，receivedBytes/totalBytes 用于 UI 显示字节数） */
    data class Downloading(
        val progress: Int,
        val receivedBytes: Long = 0,
        val totalBytes: Long = -1,
    ) : NdkState()

    /** 正在解压（progress 0-100） */
    data class Extracting(val progress: Int, val message: String = "") : NdkState()

    /** 正在配置（符号链接修复 / 权限设置 / pip 工具链生成） */
    data class Configuring(val progress: Int, val message: String = "") : NdkState()

    /** 已安装就绪 */
    data class Installed(
        val ndkPath: String,
        val version: String,
        val binDir: String,
        val arch: String,
    ) : NdkState()

    /** 安装失败 */
    data class Failed(val message: String) : NdkState()
}
