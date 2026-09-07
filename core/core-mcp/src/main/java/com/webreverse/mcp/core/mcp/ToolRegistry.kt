package com.webreverse.mcp.core.mcp

/** MCP 工具注册表 */
class ToolRegistry {
    private val tools = LinkedHashMap<String, McpTool>()

    companion object {
        /**
         * MCP 命名规范合规：工具名必须匹配 ^[a-zA-Z0-9_-]{1,64}$（MCP 规范），
         * 历史命名空间分隔符 `.`（含遗留 `/`）不合法。此处统一把分隔符映射为 `_`：
         * `dom.get_tree` → `dom_get_tree`、`function.name` → `function_name`。
         *
         * 集中在注册表边界做规范化（register/get/unregister/listMetadata），所有工具
         * 一次生效；客户端传旧点号名（如缓存的 `js.evaluate`）经同一规则归一后仍可
         * 直调，天然向后兼容。
         *
         * 兜底防线：映射后再清洗一次——任何仍不属于 [a-zA-Z0-9_-] 的字符
         * （空格、中文等未来动态注册名可能出现的字符）一律替换为 `_`，并截断到 64
         * 字符，保证 tools/list 出口的每个名字都满足 OpenAI/MCP 的
         * `^[a-zA-Z0-9_-]{1,64}$` 校验，杜绝 `Invalid tools[N].function.name` 报错。
         */
        private val ILLEGAL_NAME_CHARS = Regex("[^a-zA-Z0-9_-]")

        fun normalizeName(name: String): String {
            val cleaned = name.trim()
                .replace('.', '_')
                .replace('/', '_')
                .replace(ILLEGAL_NAME_CHARS, "_")
            return if (cleaned.length > 64) cleaned.substring(0, 64) else cleaned
        }
    }

    /**
     * 枢纽模式开关：
     * - true（默认）：tools/list 只返回命名空间聚合工具（约 32 个），保护客户端上下文
     * - false：兼容模式，返回全部原始工具（400+）
     * 两种模式下 get() 均可按名直调任意工具（原工具全部保留注册）
     */
    @Volatile
    var hubMode: Boolean = true

    @Synchronized
    fun register(tool: McpTool): ToolRegistry {
        tools[normalizeName(tool.metadata.name)] = tool
        return this
    }

    @Synchronized
    fun registerAll(tools: List<McpTool>): ToolRegistry {
        tools.forEach { register(it) }
        return this
    }

    @Synchronized
    fun unregister(name: String): Boolean = tools.remove(normalizeName(name)) != null

    @Synchronized
    fun get(name: String): McpTool? = tools[normalizeName(name)]

    @Synchronized
    fun list(): List<McpTool> = tools.values.toList()

    /** 当前模式下对外可见的工具元数据（hubMode 决定返回枢纽或原始工具）；名称统一为 MCP 规范的下划线形式 */
    @Synchronized
    fun listMetadata(): List<ToolMetadata> =
        tools.values.map { it.metadata.copy(name = normalizeName(it.metadata.name)) }
            .filter { it.isHub == hubMode }

    /** 当前模式可见工具数（UI 展示用；count() 始终为注册总数） */
    @Synchronized
    fun visibleCount(): Int = listMetadata().size

    @Synchronized
    fun count(): Int = tools.size

    @Synchronized
    fun clear() = tools.clear()

    @Synchronized
    fun byCategory(category: ToolCategory): List<McpTool> =
        tools.values.filter { it.metadata.category == category }
}
