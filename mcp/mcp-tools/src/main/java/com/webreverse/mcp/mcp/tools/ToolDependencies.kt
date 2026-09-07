package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.browser.bookmarks.BookmarkManager
import com.webreverse.mcp.browser.engine.BrowserService
import com.webreverse.mcp.browser.engine.BrowserSession
import com.webreverse.mcp.browser.history.HistoryManager
import com.webreverse.mcp.browser.tabs.TabManager
import com.webreverse.mcp.core.common.event.EventBus
import com.webreverse.mcp.core.common.util.AppError
import com.webreverse.mcp.core.common.permission.PermissionManager
import com.webreverse.mcp.core.common.permission.PermissionRequest
import com.webreverse.mcp.core.common.util.AppResult
import com.webreverse.mcp.core.database.repository.BookmarkRepository
import com.webreverse.mcp.core.database.repository.BreakpointRepository
import com.webreverse.mcp.core.database.repository.HistoryRepository
import com.webreverse.mcp.core.database.repository.HookRuleRepository
import com.webreverse.mcp.core.database.repository.InvestigationRepository
import com.webreverse.mcp.core.database.repository.NetworkRepository
import com.webreverse.mcp.core.database.repository.UserScriptRepository
import com.webreverse.mcp.core.database.repository.WorkspaceRepository
import com.webreverse.mcp.core.logging.AppLogger
import com.webreverse.mcp.core.logging.LogCategory
import com.webreverse.mcp.core.mcp.ToolRegistry
import com.webreverse.mcp.devtools.console.ConsoleManager
import com.webreverse.mcp.devtools.debugger.DebuggerManager
import com.webreverse.mcp.devtools.dom.DomInspector
import com.webreverse.mcp.devtools.network.NetworkInspector
import com.webreverse.mcp.devtools.performance.PerformanceAnalyzer
import com.webreverse.mcp.devtools.storage.StorageInspector
import com.webreverse.mcp.hook.engine.HookEngine
import com.webreverse.mcp.javascript.analysis.ApiDiscoveryEngine
import com.webreverse.mcp.javascript.analysis.AntiDebugDetector
import com.webreverse.mcp.javascript.analysis.BrowserEnvironmentSynthesizer
import com.webreverse.mcp.javascript.analysis.DiffEngine
import com.webreverse.mcp.javascript.analysis.FrameworkDetector
import com.webreverse.mcp.javascript.analysis.ObfuscationAnalyzer
import com.webreverse.mcp.javascript.analysis.PauseLoopDetector
import com.webreverse.mcp.javascript.analysis.ScriptInterceptor
import com.webreverse.mcp.javascript.analysis.SourceMapParser
import com.webreverse.mcp.javascript.parser.JsParser
import com.webreverse.mcp.javascript.runtime.JsRuntimeHook
import com.webreverse.mcp.mcp.tools.terminal.HostToolsDownloader
import com.webreverse.mcp.mcp.tools.terminal.HostToolsManager
import com.webreverse.mcp.mcp.tools.terminal.NdkDownloader
import com.webreverse.mcp.mcp.tools.terminal.NdkManager
import com.webreverse.mcp.mcp.tools.terminal.TerminalEngine
import com.webreverse.mcp.workspace.core.EvidenceStore
import com.webreverse.mcp.workspace.core.WorkspaceManager
import java.util.concurrent.ConcurrentHashMap

/**
 * 工具依赖容器：所有 MCP Tool 通过它访问各领域服务。
 * 保证 MCP Tool -> UseCase -> BrowserService 的解耦架构。
 */
class ToolDependencies(
    val eventBus: EventBus,
    val logger: AppLogger,
    val browserService: BrowserService,
    val tabManager: TabManager,
    val historyManager: HistoryManager,
    val bookmarkManager: BookmarkManager,
    val domInspector: DomInspector,
    val consoleManager: ConsoleManager,
    val debuggerManager: DebuggerManager,
    val networkInspector: NetworkInspector,
    val storageInspector: StorageInspector,
    val performanceAnalyzer: PerformanceAnalyzer,
    val hookEngine: HookEngine,
    val jsRuntimeHook: JsRuntimeHook,
    val jsParser: JsParser,
    val obfuscationAnalyzer: ObfuscationAnalyzer,
    val apiDiscoveryEngine: ApiDiscoveryEngine,
    val frameworkDetector: FrameworkDetector,
    val sourceMapParser: SourceMapParser,
    val diffEngine: DiffEngine,
    /* * 反调试类别检测器 */
    val antiDebugDetector: AntiDebugDetector,
    /* * 执行前脚本拦截改写器 */
    val scriptInterceptor: ScriptInterceptor,
    /* * 暂停循环检测 + 四级恢复状态机 */
    val pauseLoopDetector: PauseLoopDetector,
    /* * Node 浏览器环境合成器 */
    val browserEnvSynthesizer: BrowserEnvironmentSynthesizer,
    val workspaceManager: WorkspaceManager,
    /* * 证据库 + 逆向图谱（ 核心：被动沉淀 + 主动写入 + 图谱查询） */
    val evidenceStore: EvidenceStore,
    val permissionManager: PermissionManager,
    val networkRepository: NetworkRepository,
    val breakpointRepository: BreakpointRepository,
    val hookRuleRepository: HookRuleRepository,
    val investigationRepository: InvestigationRepository,
    val userScriptRepository: UserScriptRepository,
    val workspaceRepository: WorkspaceRepository,
    val toolRegistry: com.webreverse.mcp.core.mcp.ToolRegistry,
    /** 内置终端引擎（命令执行 + 交互式 shell） */
    val terminalEngine: TerminalEngine,
    /** Host Tools 管理器（git/python/perl 安装状态） */
    val hostToolsManager: HostToolsManager,
    /** Host Tools 下载安装器（Termux 源） */
    val hostToolsDownloader: HostToolsDownloader,
    /* * NDK 管理器（终端内置 NDK，pip 编译 C 扩展用；可选） */
    val ndkManager: NdkManager? = null,
    /* * NDK 下载安装器（；可选） */
    val ndkDownloader: NdkDownloader? = null,
) {
    /**
     * Session → 固定 Tab 绑定（P0 上下文隔离）：
     * Agent 可把某 Session 固定到指定 Tab，此后该 Session 内所有工具的 activeSession()
     * 都会解析到固定 Tab 的会话，避免多 Agent/多 Tab 切换时串到别的现场。
     */
    private val sessionTabBindings = ConcurrentHashMap<String, String>()

    /** 绑定 Session 到指定 Tab */
    fun pinTabForSession(sessionId: String, tabId: String) {
        sessionTabBindings[sessionId] = tabId
    }

    /** 解除 Session 的 Tab 固定 */
    fun unpinTabForSession(sessionId: String): String? = sessionTabBindings.remove(sessionId)

    /** 当前 Session 固定的 Tab（若无返回 null） */
    fun pinnedTabForSession(sessionId: String?): String? =
        sessionId?.let { sessionTabBindings[it] }

    /** 读取当前工具调用的 ToolContext（由 ToolFactory 写入协程上下文） */
    suspend fun context(): com.webreverse.mcp.core.mcp.ToolContext? =
        com.webreverse.mcp.core.mcp.ToolContextScope.current()

    /**
     * 获取活动会话（上下文感知）：
     * 优先按当前 ToolContext 的 tabId / 固定 Tab 绑定解析到专属会话，
     * 否则才退回全局活动会话。这是「Agent ─ Session ─ Tab」隔离的地基。
     */
    suspend fun activeSession(): BrowserSession {
        val ctx = context()
        val tabId = ctx?.tabId?.takeIf { it.isNotBlank() } ?: pinnedTabForSession(ctx?.sessionId)
        return if (tabId.isNullOrBlank()) {
            browserService.getOrCreateActiveSession()
        } else {
            browserService.getSession(tabId) ?: browserService.getOrCreateActiveSession()
        }
    }

    /** 获取指定 tab 的会话 */
    suspend fun sessionFor(tabId: String?): BrowserSession =
        browserService.getSession(tabId) ?: activeSession()

    /** 依据上下文解析会话：显式指定 tab 优先，其次上下文，其次固定绑定 */
    suspend fun sessionForContext(tabId: String? = null): BrowserSession {
        val ctx = context()
        val explicit = tabId?.takeIf { it.isNotBlank() }
        val resolved = explicit ?: ctx?.tabId?.takeIf { it.isNotBlank() } ?: pinnedTabForSession(ctx?.sessionId)
        return if (resolved.isNullOrBlank()) browserService.getOrCreateActiveSession()
        else browserService.getSession(resolved) ?: browserService.getOrCreateActiveSession()
    }

    fun log(category: LogCategory, message: String) {
        logger.i(category, message)
    }
}

/** 参数解析工具 */
object ToolArgs {
    fun str(args: kotlinx.serialization.json.JsonObject, key: String, default: String = ""): String {
        val v = args[key] ?: return default
        return (v as? kotlinx.serialization.json.JsonPrimitive)?.content ?: default
    }

    fun optStr(args: kotlinx.serialization.json.JsonObject, key: String): String? {
        val v = args[key] ?: return null
        if (v is kotlinx.serialization.json.JsonNull) return null
        return (v as? kotlinx.serialization.json.JsonPrimitive)?.content
    }

    fun int(args: kotlinx.serialization.json.JsonObject, key: String, default: Int = 0): Int {
        val v = args[key] ?: return default
        return (v as? kotlinx.serialization.json.JsonPrimitive)?.content?.toIntOrNull() ?: default
    }

    /** 可选 int：缺省或 null 返回 null（区别于 int 的 default 语义） */
    fun optInt(args: kotlinx.serialization.json.JsonObject, key: String): Int? {
        val v = args[key] ?: return null
        if (v is kotlinx.serialization.json.JsonNull) return null
        return (v as? kotlinx.serialization.json.JsonPrimitive)?.content?.toIntOrNull()
    }

    fun long(args: kotlinx.serialization.json.JsonObject, key: String, default: Long = 0L): Long {
        val v = args[key] ?: return default
        return (v as? kotlinx.serialization.json.JsonPrimitive)?.content?.toLongOrNull() ?: default
    }

    fun bool(args: kotlinx.serialization.json.JsonObject, key: String, default: Boolean = false): Boolean {
        val v = args[key] ?: return default
        return (v as? kotlinx.serialization.json.JsonPrimitive)?.content?.toBooleanStrictOrNull() ?: default
    }

    fun double(args: kotlinx.serialization.json.JsonObject, key: String, default: Double = 0.0): Double {
        val v = args[key] ?: return default
        return (v as? kotlinx.serialization.json.JsonPrimitive)?.content?.toDoubleOrNull() ?: default
    }
}

/** 工具工厂：减少样板代码 */
class ToolFactory(private val deps: ToolDependencies) {

    fun tool(
        name: String,
        description: String,
        category: com.webreverse.mcp.core.mcp.ToolCategory,
        permission: com.webreverse.mcp.core.common.permission.PermissionScope,
        riskLevel: com.webreverse.mcp.core.common.permission.RiskLevel = com.webreverse.mcp.core.common.permission.RiskLevel.LOW,
        timeoutMs: Long = 30_000,
        supportsImage: Boolean = false,
        supportsStreaming: Boolean = false,
        inputSchema: kotlinx.serialization.json.JsonObject = kotlinx.serialization.json.JsonObject(emptyMap()),
        capabilities: String = "",
        cost: Int = 1,
        reliability: Int = 70,
        block: suspend (kotlinx.serialization.json.JsonObject) -> com.webreverse.mcp.core.mcp.McpToolResult,
    ): com.webreverse.mcp.core.mcp.McpTool = object : com.webreverse.mcp.core.mcp.McpTool {
        override val metadata = com.webreverse.mcp.core.mcp.ToolMetadata(
            name = name,
            description = description,
            category = category,
            permission = permission,
            riskLevel = riskLevel,
            timeoutMs = timeoutMs,
            supportsImage = supportsImage,
            supportsStreaming = supportsStreaming,
            inputSchema = inputSchema,
            capabilities = capabilities,
            cost = cost,
            reliability = reliability,
        )

        override suspend fun execute(arguments: kotlinx.serialization.json.JsonObject): com.webreverse.mcp.core.mcp.McpToolResult {
            // 无上下文入口：以占位上下文走上下文执行（session 固定不参与）
            return execute(com.webreverse.mcp.core.mcp.ToolContextScope.unknown(), arguments)
        }

        override suspend fun execute(
            context: com.webreverse.mcp.core.mcp.ToolContext,
            arguments: kotlinx.serialization.json.JsonObject,
        ): com.webreverse.mcp.core.mcp.McpToolResult {
            // 权限边界：默认开启；用户在权限管理中关闭的作用域会拒绝执行。
            // 上下文（tab/url/agent）一并传入，为 CURRENT_TAB / CURRENT_SITE 隔离预留。
            val permissionResult = deps.permissionManager.check(
                PermissionRequest(
                    scope = permission,
                    tabId = context.tabId,
                    url = context.url,
                    agentName = context.agentName,
                    reason = "执行工具 $name",
                ),
            )
            if (!permissionResult.granted) {
                return com.webreverse.mcp.core.mcp.McpToolResult.error(
                    "PERMISSION_DENIED",
                    permissionResult.message,
                )
            }
            // 把 context 写入协程作用域：工具内部 deps.activeSession()/deps.sessionForContext() 按此解析
            return try {
                com.webreverse.mcp.core.mcp.ToolContextScope.run(context) { block(arguments) }
            } catch (e: Exception) {
                com.webreverse.mcp.core.mcp.McpToolResult.error(
                    "TOOL_EXECUTION_ERROR",
                    e.message ?: "执行失败",
                    mapOf("type" to e.javaClass.simpleName),
                )
            }
        }
    }
}

/* * JSON Schema 构建工具（支持 required / enum / items，补齐 JSON Schema 完整性） */
object Schemas {
    fun objectSchema(
        vararg props: Pair<String, kotlinx.serialization.json.JsonObject>,
        required: List<String> = emptyList(),
    ): kotlinx.serialization.json.JsonObject =
        kotlinx.serialization.json.buildJsonObject {
            put("type", kotlinx.serialization.json.JsonPrimitive("object"))
            put(
                "properties",
                kotlinx.serialization.json.buildJsonObject {
                    props.forEach { (k, v) -> put(k, v) }
                },
            )
            // required：缺省不输出（全部可选）；标注后客户端可在发请求前校验，减少一轮无效调用
            if (required.isNotEmpty()) {
                put(
                    "required",
                    kotlinx.serialization.json.JsonArray(required.map { kotlinx.serialization.json.JsonPrimitive(it) }),
                )
            }
        }

    /** 字符串枚举：type=string + enum 值列表（如断点类型、排序方式等离散参数） */
    fun enumSchema(description: String = "", vararg values: String): kotlinx.serialization.json.JsonObject =
        kotlinx.serialization.json.buildJsonObject {
            put("type", kotlinx.serialization.json.JsonPrimitive("string"))
            if (description.isNotBlank()) put("description", kotlinx.serialization.json.JsonPrimitive(description))
            put(
                "enum",
                kotlinx.serialization.json.JsonArray(values.map { kotlinx.serialization.json.JsonPrimitive(it) }),
            )
        }

    fun strSchema(description: String = ""): kotlinx.serialization.json.JsonObject =
        kotlinx.serialization.json.buildJsonObject {
            put("type", kotlinx.serialization.json.JsonPrimitive("string"))
            if (description.isNotBlank()) put("description", kotlinx.serialization.json.JsonPrimitive(description))
        }

    fun intSchema(description: String = "", min: Int? = null, max: Int? = null): kotlinx.serialization.json.JsonObject =
        kotlinx.serialization.json.buildJsonObject {
            put("type", kotlinx.serialization.json.JsonPrimitive("integer"))
            if (description.isNotBlank()) put("description", kotlinx.serialization.json.JsonPrimitive(description))
            if (min != null) put("minimum", kotlinx.serialization.json.JsonPrimitive(min))
            if (max != null) put("maximum", kotlinx.serialization.json.JsonPrimitive(max))
        }

    fun longSchema(description: String = ""): kotlinx.serialization.json.JsonObject =
        kotlinx.serialization.json.buildJsonObject {
            put("type", kotlinx.serialization.json.JsonPrimitive("integer"))
            put("format", kotlinx.serialization.json.JsonPrimitive("int64"))
            if (description.isNotBlank()) put("description", kotlinx.serialization.json.JsonPrimitive(description))
        }

    fun boolSchema(description: String = ""): kotlinx.serialization.json.JsonObject =
        kotlinx.serialization.json.buildJsonObject {
            put("type", kotlinx.serialization.json.JsonPrimitive("boolean"))
            if (description.isNotBlank()) put("description", kotlinx.serialization.json.JsonPrimitive(description))
        }

    fun doubleSchema(description: String = ""): kotlinx.serialization.json.JsonObject =
        kotlinx.serialization.json.buildJsonObject {
            put("type", kotlinx.serialization.json.JsonPrimitive("number"))
            if (description.isNotBlank()) put("description", kotlinx.serialization.json.JsonPrimitive(description))
        }

    fun arraySchema(
        description: String = "",
        items: kotlinx.serialization.json.JsonObject? = null,
    ): kotlinx.serialization.json.JsonObject =
        kotlinx.serialization.json.buildJsonObject {
            put("type", kotlinx.serialization.json.JsonPrimitive("array"))
            if (description.isNotBlank()) put("description", kotlinx.serialization.json.JsonPrimitive(description))
            // items：JSON Schema 中数组应声明元素类型；缺省输出（兼容历史调用）
            if (items != null) put("items", items)
        }
}
