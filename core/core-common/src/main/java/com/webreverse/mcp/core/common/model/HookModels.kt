package com.webreverse.mcp.core.common.model

import kotlinx.serialization.Serializable

/** Hook 类型 */
@Serializable
enum class HookType(val display: String) {
    FUNCTION("Function"), METHOD("Method"), PROPERTY("Property"),
    EVENT("Event"), FETCH("Fetch"), XHR("XHR"), WEBSOCKET("WebSocket"),
    STORAGE("Storage"), COOKIE("Cookie"), HISTORY("History"),
    DOM("DOM"), CONSOLE("Console"), TIMER("Timer"), CRYPTO("Crypto"),
    CANVAS("Canvas"), CLIPBOARD("Clipboard"), LOCATION("Location"), CUSTOM("Custom"),
    // 新增
    WORKER("Worker"), SUBTLE_CRYPTO("SubtleCrypto"), FINGERPRINT("Fingerprint"), NOTIFICATION("Notification")
}

/** Hook 匹配条件 */
@Serializable
data class HookMatch(
    val urlPattern: String? = null,
    val hostPattern: String? = null,
    val pathPattern: String? = null,
    val methodPattern: String? = null,
    val headerPattern: String? = null,
    val bodyPattern: String? = null,
    val responsePattern: String? = null,
    val regexPattern: String? = null,
    val target: String? = null,
)

/** Hook 动作 */
@Serializable
enum class HookAction(val display: String) {
    LOG("Log"), MODIFY_REQUEST("Modify Request"), MODIFY_HEADER("Modify Header"),
    MODIFY_QUERY("Modify Query"), MODIFY_BODY("Modify Body"), MODIFY_RESPONSE("Modify Response"),
    BLOCK("Block"), REDIRECT("Redirect"), DELAY("Delay"), MOCK("Mock Response"),
    ADD_HEADER("Add Header"), REMOVE_HEADER("Remove Header"), REPLACE("Replace String"),
    BREAKPOINT("Breakpoint"), TRACE("Trace")
}

/** Hook 规则 */
@Serializable
data class HookRule(
    val id: String,
    val name: String,
    val type: HookType = HookType.FETCH,
    val match: HookMatch = HookMatch(),
    val action: HookAction = HookAction.LOG,
    val enabled: Boolean = true,
    val payload: String = "",
    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis(),
    val hitCount: Long = 0,
    val lastTriggeredAt: Long? = null,
    val description: String = "",
)

/** Hook 触发记录 */
@Serializable
data class HookEvent(
    val id: String,
    val ruleId: String,
    val ruleName: String,
    val type: HookType,
    val target: String,
    val arguments: String = "",
    val result: String = "",
    val stackTrace: String = "",
    val timestamp: Long = System.currentTimeMillis(),
    val tabId: String = "",
    val redacted: Boolean = false,
)
