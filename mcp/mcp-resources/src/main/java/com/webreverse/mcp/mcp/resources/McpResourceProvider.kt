package com.webreverse.mcp.mcp.resources

import com.webreverse.mcp.core.mcp.McpResource
import com.webreverse.mcp.core.mcp.ResourceTemplate

/**
 * MCP 资源注册表：管理所有 browser:// 资源与资源模板。
 * 支持 resources/list、resources/read、resources/templates/list。
 */
class McpResourceProvider {
    private val resources = LinkedHashMap<String, McpResource>()
    private val templates = LinkedHashMap<String, ResourceTemplate>()

    @Synchronized
    fun register(resource: McpResource): McpResourceProvider {
        resources[resource.uri] = resource
        return this
    }

    @Synchronized
    fun registerAll(resources: List<McpResource>): McpResourceProvider {
        resources.forEach { register(it) }
        return this
    }

    @Synchronized
    fun registerTemplate(template: ResourceTemplate): McpResourceProvider {
        templates[template.uriTemplate] = template
        return this
    }

    @Synchronized
    fun get(uri: String): McpResource? = resources[uri]

    @Synchronized
    fun list(): List<McpResource> = resources.values.toList()

    @Synchronized
    fun listTemplates(): List<ResourceTemplate> = templates.values.toList()

    @Synchronized
    fun count(): Int = resources.size
}
