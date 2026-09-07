package com.webreverse.mcp.core.mcp

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** JSON-RPC 2.0 请求 */
@Serializable
data class JsonRpcRequest(
    val jsonrpc: String = "2.0",
    val id: JsonElement = JsonNull,
    val method: String,
    val params: JsonObject = JsonObject(emptyMap()),
)

/** JSON-RPC 2.0 响应 */
@Serializable
data class JsonRpcResponse(
    val jsonrpc: String = "2.0",
    val id: JsonElement = JsonNull,
    val result: JsonElement? = null,
    val error: JsonRpcError? = null,
) {
    companion object {
        fun success(id: JsonElement, result: JsonElement): JsonRpcResponse =
            JsonRpcResponse(id = id, result = result)

        fun error(id: JsonElement, code: Int, message: String, data: JsonElement? = null): JsonRpcResponse =
            JsonRpcResponse(id = id, error = JsonRpcError(code, message, data))
    }
}

/** JSON-RPC 2.0 错误 */
@Serializable
data class JsonRpcError(
    val code: Int,
    val message: String,
    val data: JsonElement? = null,
)

/** JSON-RPC 错误码（-32000~-32099 为 MCP 保留的服务器错误区间） */
object JsonRpcErrorCode {
    const val PARSE_ERROR = -32700
    const val INVALID_REQUEST = -32600
    const val METHOD_NOT_FOUND = -32601
    const val INVALID_PARAMS = -32602
    const val INTERNAL_ERROR = -32603
    // MCP 2025-03-26 服务器错误码
    const val REQUEST_FAILED = -32001
    const val RESOURCE_NOT_FOUND = -32002
    const val INVALID_REQUEST_MCP = -32003
    const val RESOURCE_EXHAUSTED = -32004
    const val INVALID_PARAMS_MCP = -32005
    const val INTERNAL_ERROR_MCP = -32006
    // 业务扩展码（保留区间内自定义）
    const val TOOL_NOT_FOUND = REQUEST_FAILED
    const val TOOL_EXECUTION_ERROR = INTERNAL_ERROR_MCP
    const val PERMISSION_DENIED = -32003
    const val AUTH_FAILED = -32004
    const val TIMEOUT = -32005
    const val CANCELLED = -32006
}

/** MCP 协议方法名 */
object McpMethod {
    const val INITIALIZE = "initialize"
    const val NOTIFICATIONS_INITIALIZED = "notifications/initialized"
    const val PING = "ping"
    const val TOOLS_LIST = "tools/list"
    const val TOOLS_CALL = "tools/call"
    const val RESOURCES_LIST = "resources/list"
    const val RESOURCES_READ = "resources/read"
    const val RESOURCES_TEMPLATES_LIST = "resources/templates/list"
    const val PROMPTS_LIST = "prompts/list"
    const val PROMPTS_GET = "prompts/get"
    const val COMPLETION_COMPLETE = "completion/complete"
    const val LOGGING_SET_LEVEL = "logging/setLevel"
    const val NOTIFICATION_CANCELLED = "notifications/cancelled"
    const val NOTIFICATION_PROGRESS = "notifications/progress"
    const val NOTIFICATION_TOOLS_LIST_CHANGED = "notifications/tools/list_changed"
    const val NOTIFICATION_RESOURCES_LIST_CHANGED = "notifications/resources/list_changed"
    const val NOTIFICATION_MESSAGE = "notifications/message"
}

/** 便捷构造 */
fun jsonObjectOf(vararg pairs: Pair<String, JsonElement>): JsonObject = JsonObject(pairs.toMap())

fun string(value: String): JsonPrimitive = JsonPrimitive(value)
fun number(value: Number): JsonPrimitive = JsonPrimitive(value)
fun boolean(value: Boolean): JsonPrimitive = JsonPrimitive(value)
