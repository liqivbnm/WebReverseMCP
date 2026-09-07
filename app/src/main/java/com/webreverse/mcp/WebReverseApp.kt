package com.webreverse.mcp

import android.app.Application
import com.webreverse.mcp.core.common.util.Redactor
import com.webreverse.mcp.core.common.util.WorkDir
import com.webreverse.mcp.core.logging.LogCategory
import com.webreverse.mcp.di.AppContainer
import com.webreverse.mcp.mcp.tools.terminal.TerminalPaths
import timber.log.Timber

/**
 * 应用入口：持有全局 DI 容器。
 */
class WebReverseApp : Application() {

    lateinit var container: AppContainer
        private set

    override fun onCreate() {
        super.onCreate()
        if (BuildConfig.DEBUG) {
            Timber.plant(Timber.DebugTree())
        }
        // 工作目录初始化（越早越好，所有文件产出统一走此目录）
        WorkDir.init(this)
        // 修复：终端路径必须在任何 TerminalEngine/UI 访问目录之前初始化，
        // 否则首次访问 TerminalPaths 会抛"IllegalStateException: 未初始化"导致启动崩溃
        // 必须在 WorkDir.init 之后——终端 HOME 现在直接取 WorkDir（设置里的存储目录），
        // 先初始化 WorkDir 才能保证终端目录读到用户自定义路径而非默认值
        TerminalPaths.init(this)
        // 敏感数据脱敏开关初始化（默认关闭，用户可手动开启）
        Redactor.init(this)
        container = AppContainer(this)
        container.logger.i(LogCategory.APP, "WebReverseMCP 启动完成")
    }
}
