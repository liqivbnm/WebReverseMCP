package com.webreverse.mcp.core.mcp

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

/** MCP Prompt */
interface McpPrompt {
    val name: String
    val description: String
    val arguments: List<PromptArgument>

    suspend fun get(arguments: Map<String, String> = emptyMap()): PromptResult
}

/** Prompt 参数 */
@Serializable
data class PromptArgument(
    val name: String,
    val description: String = "",
    val required: Boolean = false,
)

/** Prompt 结果 */
@Serializable
data class PromptResult(
    val description: String = "",
    val messages: List<PromptMessage> = emptyList(),
)

@Serializable
data class PromptMessage(
    val role: String = "user",
    val content: PromptContent = PromptContent(),
)

@Serializable
data class PromptContent(
    val type: String = "text",
    val text: String = "",
)
