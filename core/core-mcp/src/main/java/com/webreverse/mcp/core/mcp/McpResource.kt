package com.webreverse.mcp.core.mcp

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

/** MCP 资源 */
interface McpResource {
    val uri: String
    val name: String
    val description: String
    val mimeType: String

    suspend fun read(arguments: Map<String, String> = emptyMap()): McpResourceContent
}

/** 资源内容 */
@Serializable
data class McpResourceContent(
    val uri: String,
    val mimeType: String,
    val text: String? = null,
    val blob: String? = null,
    val structured: JsonObject? = null,
)

/** 资源模板 */
data class ResourceTemplate(
    val uriTemplate: String,
    val name: String,
    val description: String = "",
    val mimeType: String = "text/plain",
)
