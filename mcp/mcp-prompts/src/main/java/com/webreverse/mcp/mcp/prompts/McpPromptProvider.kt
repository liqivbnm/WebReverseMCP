package com.webreverse.mcp.mcp.prompts

import com.webreverse.mcp.core.mcp.McpPrompt

/**
 * MCP Prompt 注册表：管理所有内置 Prompt。
 * 支持 prompts/list、prompts/get。
 */
class McpPromptProvider {
    private val prompts = LinkedHashMap<String, McpPrompt>()

    @Synchronized
    fun register(prompt: McpPrompt): McpPromptProvider {
        prompts[prompt.name] = prompt
        return this
    }

    @Synchronized
    fun registerAll(prompts: List<McpPrompt>): McpPromptProvider {
        prompts.forEach { register(it) }
        return this
    }

    @Synchronized
    fun get(name: String): McpPrompt? = prompts[name]

    @Synchronized
    fun list(): List<McpPrompt> = prompts.values.toList()

    @Synchronized
    fun count(): Int = prompts.size
}
