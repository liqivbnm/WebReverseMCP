package com.webreverse.mcp.di

import android.content.Context
import com.webreverse.mcp.browser.bookmarks.BookmarkManager
import com.webreverse.mcp.browser.engine.BrowserService
import com.webreverse.mcp.browser.engine.bridge.NetworkBridge
import com.webreverse.mcp.browser.history.HistoryManager
import com.webreverse.mcp.browser.tabs.TabManager
import com.webreverse.mcp.core.common.event.EventBus
import com.webreverse.mcp.core.database.AppDatabase
import com.webreverse.mcp.core.database.repository.BookmarkRepository
import com.webreverse.mcp.core.database.repository.BreakpointRepository
import com.webreverse.mcp.core.database.repository.HistoryRepository
import com.webreverse.mcp.core.database.repository.HookRuleRepository
import com.webreverse.mcp.core.database.repository.InvestigationRepository
import com.webreverse.mcp.core.database.repository.McpRepository
import com.webreverse.mcp.core.database.repository.NetworkRepository
import com.webreverse.mcp.core.database.repository.UserScriptRepository
import com.webreverse.mcp.core.database.repository.WorkspaceRepository
import com.webreverse.mcp.core.logging.AppLogger
import com.webreverse.mcp.core.mcp.ToolRegistry
import com.webreverse.mcp.core.security.PermissionManagerImpl
import com.webreverse.mcp.core.security.TokenManager
import com.webreverse.mcp.devtools.console.ConsoleManager
import com.webreverse.mcp.devtools.debugger.DebuggerManager
import com.webreverse.mcp.devtools.dom.DomInspector
import com.webreverse.mcp.devtools.network.NetworkInspector
import com.webreverse.mcp.devtools.performance.PerformanceAnalyzer
import com.webreverse.mcp.devtools.storage.StorageInspector
import com.webreverse.mcp.hook.engine.HookEngine
import com.webreverse.mcp.javascript.analysis.ApiDiscoveryEngine
import com.webreverse.mcp.javascript.analysis.DiffEngine
import com.webreverse.mcp.javascript.analysis.FrameworkDetector
import com.webreverse.mcp.javascript.analysis.AntiDebugDetector
import com.webreverse.mcp.javascript.analysis.BrowserEnvironmentSynthesizer
import com.webreverse.mcp.javascript.analysis.ObfuscationAnalyzer
import com.webreverse.mcp.javascript.analysis.PauseLoopDetector
import com.webreverse.mcp.javascript.analysis.ScriptInterceptor
import com.webreverse.mcp.javascript.analysis.SourceMapParser
import com.webreverse.mcp.javascript.parser.JsParser
import com.webreverse.mcp.javascript.runtime.JsRuntimeHook
import com.webreverse.mcp.mcp.server.McpServerManager
import com.webreverse.mcp.mcp.tools.ToolDependencies
import com.webreverse.mcp.mcp.tools.ToolModule
import com.webreverse.mcp.mcp.tools.terminal.HostToolsDownloader
import com.webreverse.mcp.mcp.tools.terminal.HostToolsManager
import com.webreverse.mcp.mcp.tools.terminal.NdkDownloader
import com.webreverse.mcp.mcp.tools.terminal.NdkManager
import com.webreverse.mcp.mcp.tools.terminal.TerminalEngine
import com.webreverse.mcp.mcp.tools.terminal.TerminalPaths
import com.webreverse.mcp.workspace.core.WorkspaceManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * 手动 DI 容器：组装所有领域服务与 MCP 工具。
 * 遵循 Clean Architecture：App 层只依赖抽象，具体实现在此组装。
 */
class AppContainer(private val context: Context) {

    val appScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    // ---- 基础设施 ----
    val eventBus = EventBus()
    val logger = AppLogger(eventBus)
    val database = AppDatabase.get(context)
    val tokenManager = TokenManager(context)
    val permissionManager = PermissionManagerImpl(context)

    // ---- 仓库 ----
    val historyRepository = HistoryRepository(database.historyDao())
    val bookmarkRepository = BookmarkRepository(database.bookmarkDao())
    val networkRepository = NetworkRepository(database.networkEntryDao())
    val hookRuleRepository = HookRuleRepository(database.hookRuleDao())
    val breakpointRepository = BreakpointRepository(database.breakpointDao())
    val userScriptRepository = UserScriptRepository(database.userScriptDao())
    val investigationRepository = InvestigationRepository(database.investigationDao())
    val workspaceRepository = WorkspaceRepository(
                database.workspaceDao(),
                database.targetDao(),
                database.noteDao(),
                database.findingDao(),
                database.analysisResultDao(),
            )
    val mcpRepository = McpRepository(
        database.mcpSessionDao(),
        database.mcpToolConfigDao(),
        database.analysisResultDao(),
        database.findingDao(),
    )

    // ---- 浏览器 ----
    val networkBridge = NetworkBridge(eventBus)
    val browserService = BrowserService(context, eventBus, networkBridge, userScriptRepository)
    val tabManager = TabManager(browserService, eventBus)
    val historyManager = HistoryManager(historyRepository)
    val bookmarkManager = BookmarkManager(bookmarkRepository)

    // ---- DevTools ----
    val domInspector = DomInspector()
    val consoleManager = ConsoleManager()
    val debuggerManager = DebuggerManager(eventBus)
    val networkInspector = NetworkInspector()
    val storageInspector = StorageInspector()
    val performanceAnalyzer = PerformanceAnalyzer()

    // ---- JavaScript 分析 ----
    val jsParser = JsParser()
    val obfuscationAnalyzer = ObfuscationAnalyzer(jsParser)
    val apiDiscoveryEngine = ApiDiscoveryEngine(jsParser)
    val frameworkDetector = FrameworkDetector()
    val sourceMapParser = SourceMapParser()
    val diffEngine = DiffEngine()
    val jsRuntimeHook = JsRuntimeHook()

    // ---- 反调试/脚本拦截/暂停循环检测/浏览器环境合成（参考 ChatGPT 报告 §7/§9/§10/§43）----
    val antiDebugDetector = AntiDebugDetector()
    val scriptInterceptor = ScriptInterceptor()
    val pauseLoopDetector = PauseLoopDetector()
    val browserEnvSynthesizer = BrowserEnvironmentSynthesizer()

    // ---- Hook ----
    val hookEngine = HookEngine(hookRuleRepository, eventBus, jsRuntimeHook)

    // ---- Workspace ----
    val workspaceManager = WorkspaceManager(workspaceRepository)

    // ---- 内置终端 + Host Tools----
    val hostToolsManager = HostToolsManager(context)
    val hostToolsDownloader = HostToolsDownloader(context, hostToolsManager)
    // ---- 终端内置 NDK（参考 NdkCompiler 的 NDK 逻辑）----
    // NDK 安装后自动注入 CC/CXX/AR 等，pip install pycryptodome 等带 C 扩展的库可直接编译
    val ndkManager = NdkManager()
    val ndkDownloader = NdkDownloader(context, ndkManager)
    val terminalEngine = TerminalEngine(context, hostToolsManager, ndkManager)

    // ---- 证据库 + 逆向图谱（EventBus 被动沉淀，图谱供 MCP 工具/流水线查询）----
    val evidenceStore = com.webreverse.mcp.workspace.core.EvidenceStore(eventBus)

    // ---- MCP ----
    val toolRegistry = ToolRegistry()
    val toolDependencies = ToolDependencies(
        eventBus = eventBus,
        logger = logger,
        browserService = browserService,
        tabManager = tabManager,
        historyManager = historyManager,
        bookmarkManager = bookmarkManager,
        domInspector = domInspector,
        consoleManager = consoleManager,
        debuggerManager = debuggerManager,
        networkInspector = networkInspector,
        storageInspector = storageInspector,
        performanceAnalyzer = performanceAnalyzer,
        hookEngine = hookEngine,
        jsRuntimeHook = jsRuntimeHook,
        jsParser = jsParser,
        obfuscationAnalyzer = obfuscationAnalyzer,
        apiDiscoveryEngine = apiDiscoveryEngine,
        frameworkDetector = frameworkDetector,
        sourceMapParser = sourceMapParser,
        diffEngine = diffEngine,
        antiDebugDetector = antiDebugDetector,
        scriptInterceptor = scriptInterceptor,
        pauseLoopDetector = pauseLoopDetector,
        browserEnvSynthesizer = browserEnvSynthesizer,
        workspaceManager = workspaceManager,
        evidenceStore = evidenceStore,
        permissionManager = permissionManager,
        networkRepository = networkRepository,
        breakpointRepository = breakpointRepository,
        hookRuleRepository = hookRuleRepository,
        investigationRepository = investigationRepository,
        userScriptRepository = userScriptRepository,
        workspaceRepository = workspaceRepository,
        toolRegistry = toolRegistry,
        terminalEngine = terminalEngine,
        hostToolsManager = hostToolsManager,
        hostToolsDownloader = hostToolsDownloader,
        ndkManager = ndkManager,
        ndkDownloader = ndkDownloader,
    )

    // ---- MCP Server ----
    val mcpServerManager = McpServerManager(
        context = context,
        deps = toolDependencies,
        tokenManager = tokenManager,
        eventBus = eventBus,
        logger = logger,
    )

    // ---- CDP 多路复用代理（纯内部基础设施：MCP 调试/网络工具共享后端 CDP 会话，互不踢线）----
    val cdpProxy = com.webreverse.mcp.mcp.server.CdpProxyServer(context, logger)

    init {
        // 初始化终端路径（HOME/scripts/logs/tmp 全部在统一存储目录之下）
        TerminalPaths.init(context)

        // 启动证据库被动采集：网络/Hook/断点/控制台事件自动沉淀为证据与图谱节点
        evidenceStore.start()

        // 注册所有 MCP Tools
        ToolModule.registerAll(toolDependencies, toolRegistry)
        logger.i(com.webreverse.mcp.core.logging.LogCategory.APP, "已注册 ${toolRegistry.count()} 个 MCP Tools")

        // 应用工具暴露模式（设置页手动开关，默认聚合枢纽模式）
        toolRegistry.hubMode = com.webreverse.mcp.settings.ToolModePrefs.isCompact(context)
        logger.i(
            com.webreverse.mcp.core.logging.LogCategory.APP,
            "工具暴露模式：${if (toolRegistry.hubMode) "聚合枢纽（${toolRegistry.visibleCount()} 个）" else "全量（${toolRegistry.visibleCount()} 个）"}",
        )

        // CDP 复用枢纽注册：MCP 调试工具（debugger.attach / network.attach）在
        // 代理未启动时也能拉起它，多会话共享同一条 CDP 连接
        com.webreverse.mcp.devtools.protocol.cdp.CdpHub.ensureStarted = {
            runCatching { cdpProxy.ensureStarted() }.getOrNull()
                ?.takeIf { it > 0 }
                ?.let { "127.0.0.1:$it" }
        }

        // 初始化 Hook 规则
        appScope.launch {
            hookEngine.loadFromDatabase()
        }

        // 检测已安装的 Host Tools（终端工具状态）
        appScope.launch {
            runCatching { hostToolsManager.detectInstalled() }
                .onFailure { logger.w(com.webreverse.mcp.core.logging.LogCategory.APP, "检测 Host Tools 失败: ${it.message}") }
        }

        // 检测已安装的 NDK（恢复 NDK 状态 + 重建 pip 编译工具链）
        appScope.launch {
            runCatching { ndkManager.detectInstalled() }
                .onFailure { logger.w(com.webreverse.mcp.core.logging.LogCategory.APP, "检测 NDK 失败: ${it.message}") }
        }

        // 浏览器历史记录：页面加载完成后自动写入（此前从未接线，导致历史记录页面始终为空）
        appScope.launch {
            eventBus.subscribe<com.webreverse.mcp.core.common.event.BrowserEvent.PageFinished>().collect { event ->
                try {
                    val title = browserService.getEngine(event.tabId)?.state?.value?.title.orEmpty()
                    historyManager.recordVisit(event.url, title)
                } catch (e: Exception) {
                    logger.w(com.webreverse.mcp.core.logging.LogCategory.APP, "记录历史失败: ${e.message}")
                }
            }
        }
    }
}
