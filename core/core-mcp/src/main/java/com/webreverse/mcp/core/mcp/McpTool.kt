package com.webreverse.mcp.core.mcp

import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.ThreadContextElement
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

/** 工具分类 */
@Serializable
enum class ToolCategory(val display: String) {
    BROWSER("Browser"),
    TAB("Tab"),
    DOM("DOM"),
    JAVASCRIPT("JavaScript"),
    DEBUGGER("Debugger"),
    NETWORK("Network"),
    HOOK("Hook"),
    STORAGE("Storage"),
    PAGE("Page Analysis"),
    REVERSE("Reverse Engineering"),
    PERFORMANCE("Performance"),
    EVENT("Event"),
    FRAME("Frame"),
    WORKER("Worker"),
    WORKSPACE("Workspace"),
    FILE("File System"),
    MCP("MCP"),
    SYSTEM("System"),
}

/** 工具元数据 */
@Serializable
data class ToolMetadata(
    val name: String,
    val description: String,
    val category: ToolCategory,
    val version: String = "1.0.0",
    val permission: PermissionScope,
    val riskLevel: RiskLevel = RiskLevel.LOW,
    val timeoutMs: Long = 30_000,
    val supportsStreaming: Boolean = false,
    val supportsImage: Boolean = false,
    val supportsCancellation: Boolean = false,
    val inputSchema: JsonObject = JsonObject(emptyMap()),
    val outputSchema: JsonObject = JsonObject(emptyMap()),
    /* * ：命名空间聚合枢纽工具（tools/list 按 hubMode 决定是否返回） */
    val isHub: Boolean = false,
    /**
     * 能力标签簇。LLM/编排层据此做能力路由：
     * - capabilities：工具能力关键词（如 "wasm","memory-provenance","jsvmp","micro-ir"）。
     *   多个以逗号分隔；空表「无静态能力标注」。
     * - cost：相对调用成本 1（极轻）~10（重型，如反汇编/LLM 周边）。用于规划器
     *   在低资源/强实时场景优先选 cost 更低的工具。
     * - reliability：静态可靠性估计 0-100（历史观测或实现成熟度主观评级）。
     *   100 = 平台保证确定性输出；越低越依赖启发式/动态环境，越需验证闭环兜底。
     * 三者默认值保证不破坏既有调用方（旧工具保留中性评级）。
     */
    val capabilities: String = "",
    val cost: Int = 1,
    val reliability: Int = 70,
)

/** 工具能力分类的固定词表（供 capabilities 字段取值参考） */
object ToolCapability {
    const val STATIC_ANALYSIS = "static-analysis"
    const val DYNAMIC_TRACING = "dynamic-tracing"
    const val HOOKING = "hooking"
    const val NETWORK = "network"
    const val DATA_FLOW = "data-flow"
    const val TAINT = "taint"
    const val WASM = "wasm"
    const val WASM_MEMORY_PROVENANCE = "wasm-memory-provenance"
    const val JSVMP = "jsvmp"
    const val JSVMP_MICRO_IR = "jsvmp-micro-ir"
    const val JSVMP_SIGNATURE = "jsvmp-signature"
    const val DECRYPT = "decrypt"
    const val VALIDATION = "validation"
    const val EVIDENCE = "evidence"
    const val PLANNING = "planning"
    const val UNAMBIGUOUS = "unambiguous"
    const val HEURISTIC = "heuristic"
}

/** MCP 工具接口 */
interface McpTool {
    val metadata: ToolMetadata

    suspend fun execute(arguments: JsonObject): McpToolResult

    /**
     * 上下文感知执行入口：把 [ToolContext]（session/tab/frame/cdp 执行上下文/代理/工作区/截止时间）
     * 显式传入执行链，工具据此隔离 Session/Tab/Frame，取代全局 "activeSession" 依赖。
     *
     * 默认实现委托给 [execute]（无上下文版本），保持既有的非上下文调用方兼容；
     * [com.webreverse.mcp.mcp.tools.ToolFactory] 生成的工具会重写本方法以真正建立上下文作用域。
     */
    suspend fun execute(context: ToolContext, arguments: JsonObject): McpToolResult = execute(arguments)
}

/** 工具执行结果 */
@Serializable
data class McpToolResult(
    val content: List<McpContent> = emptyList(),
    val structuredContent: JsonObject? = null,
    val isError: Boolean = false,
    val errorCode: String? = null,
    val errorMessage: String? = null,
    val details: Map<String, String> = emptyMap(),
    val progress: Int? = null,
    val total: Int? = null,
) {
    companion object {
        fun text(text: String): McpToolResult = McpToolResult(
            content = listOf(McpContent(type = "text", text = text))
        )

        fun json(json: JsonObject): McpToolResult = McpToolResult(
            content = listOf(McpContent(type = "text", text = json.toString())),
            structuredContent = json,
        )

        fun image(base64: String, mimeType: String = "image/png"): McpToolResult = McpToolResult(
            content = listOf(McpContent(type = "image", mimeType = mimeType, data = base64))
        )

        fun error(code: String, message: String, details: Map<String, String> = emptyMap()): McpToolResult =
            McpToolResult(
                content = listOf(McpContent(type = "text", text = "Error [$code]: $message")),
                isError = true,
                errorCode = code,
                errorMessage = message,
                details = details,
            )

        fun success(text: String): McpToolResult = text(text)
    }
}

/** MCP 内容块 */
@Serializable
data class McpContent(
    val type: String = "text",
    val text: String? = null,
    val mimeType: String? = null,
    val data: String? = null,
    val uri: String? = null,
    val resource: JsonObject? = null,
)

/**
 * 工具执行上下文：贯穿整个 Tool 执行链的「逆向现场定位」。
 *
 * 用于取代各 Tool 直接依赖全局 activeSession 的模型，实现：
 * ```
 * Agent ── Session ── Tab ── Frame ── ExecutionContext
 * ```
 * 隔离。请求进入时由 [com.webreverse.mcp.mcp.tools.ToolFactory] 写入协程上下文，
 * 工具内部通过 [ToolContextScope.current] 读取，据此解析会话/标签页/工作区归属。
 */
data class ToolContext(
    val sessionId: String,
    val clientId: String,
    val tabId: String? = null,
    val frameId: String? = null,
    val executionContextId: String? = null,
    val agentName: String = "AI Agent",
    /** 当前逆向工作区（Investigaton 目标落点） */
    val workspaceId: String? = null,
    /** 上下文对应的目标 URL（权限 CURRENT_SITE 隔离用） */
    val url: String? = null,
    /** 截止时间戳（ms）：超过即视为取消/超时 */
    val deadline: Long = 0L,
)

/** 协程上下文键 */
val ToolContextKey = ToolContextElement.Key

/** 协程上下文载体（ThreadContextElement）：跨 withContext 保持当前 ToolContext */
class ToolContextElement(val context: ToolContext) : ThreadContextElement<ToolContext> {
    override val key: CoroutineContext.Key<ToolContextElement> = Key

    override fun updateThreadContext(context: CoroutineContext): ToolContext = this.context

    override fun restoreThreadContext(context: CoroutineContext, oldState: ToolContext) {
        // 不依赖线程本地还原：读取统一走 coroutineContext[ToolContextElement]
    }

    companion object Key : CoroutineContext.Key<ToolContextElement>
}

/**
 * ToolContext 作用域：把上下文绑定到一段执行块（与线程切换无关）。
 *
 * 用法（由 ToolFactory 在每次工具调用时自动完成）：
 * ```
 * ToolContextScope.run(ctx) { block(args) }
 * ```
 * 工具内部读取：
 * ```
 * ToolContextScope.current()   // suspend 版本
 * ```
 */
object ToolContextScope {
    /** 在 [ctx] 作用域内执行 [block]；block 任意挂起点后仍能读到该上下文 */
    suspend fun <T> run(ctx: ToolContext, block: suspend (ToolContext) -> T): T =
        withContext(ToolContextElement(ctx)) { block(ctx) }

    /** 读取当前工具调用的 [ToolContext]；无作用域时返回 null（如非 MCP 触发的调用） */
    suspend fun current(): ToolContext? =
        kotlin.coroutines.coroutineContext[ToolContextElement.Key]?.context

    /** 缺省上下文工厂（无显式上下文时的兜底） */
    fun unknown(sessionId: String = "unknown", clientId: String = "unknown"): ToolContext =
        ToolContext(sessionId = sessionId, clientId = clientId)
}
