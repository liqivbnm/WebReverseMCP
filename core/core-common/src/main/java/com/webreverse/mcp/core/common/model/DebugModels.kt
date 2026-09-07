package com.webreverse.mcp.core.common.model

import kotlinx.serialization.Serializable

/** 断点类型 */
@Serializable
enum class BreakpointType(val display: String) {
    LINE("Line"), FUNCTION("Function"), DOM("DOM"), EVENT("Event"),
    XHR("XHR/Fetch"), EXCEPTION("Exception"), PROMISE("Promise"),
    MUTATION("Mutation"), LOGPOINT("Logpoint")
}

/** 断点 */
@Serializable
data class Breakpoint(
    val id: String,
    val tabId: String,
    val type: BreakpointType = BreakpointType.LINE,
    val url: String = "",
    val scriptId: String? = null,
    val lineNumber: Int = 0,
    val columnNumber: Int = 0,
    val condition: String? = null,
    val logExpression: String? = null,
    val enabled: Boolean = true,
    val hitCount: Int = 0,
    val createdAt: Long = System.currentTimeMillis(),
    val target: String? = null,
)

/** 调用帧 */
@Serializable
data class CallFrame(
    val callFrameId: String,
    val functionName: String,
    val url: String,
    val lineNumber: Int,
    val columnNumber: Int,
    val scopeChain: List<Scope> = emptyList(),
    val thisObject: String = "",
)

/** 作用域 */
@Serializable
data class Scope(
    val type: ScopeType,
    val name: String,
    val variables: Map<String, String> = emptyMap(),
)

@Serializable
enum class ScopeType { LOCAL, CLOSURE, GLOBAL, CATCH, BLOCK, SCRIPT, WITH, MODULE }

/** 调试器状态 */
@Serializable
enum class DebuggerState { DETACHED, ATTACHED, PAUSED, RESUMED, CRASHED }

/** 观察表达式 */
@Serializable
data class WatchExpression(
    val id: String,
    val expression: String,
    val value: String = "",
    val enabled: Boolean = true,
)
