package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import com.webreverse.mcp.core.mcp.ToolContext
import com.webreverse.mcp.core.mcp.ToolContextScope
import com.webreverse.mcp.core.mcp.ToolMetadata
import com.webreverse.mcp.core.mcp.ToolRegistry
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.put

/**
 * 命名空间聚合工具生成器。
 *
 * 背景：本项目 410+ 个细粒度工具在 tools/list 中一次性涌入客户端，
 * 造成上下文膨胀与选择困难（多数客户端超过 128 个工具即明显劣化）。
 *
 * 方案：按命名空间（名字第一个 `.` 之前的部分）把原工具聚合为 1 个枢纽工具：
 * - 枢纽工具名 = 命名空间本身（如 `debugger`、`network`）
 * - `action` 参数（enum）选择具体动作，值 = 原工具名去掉命名空间前缀
 * - 其余参数原样透传给原工具——原实现零改动，功能零损失
 * - 原工具仍全部注册，get("debugger_set_breakpoint")（及旧点号名 "debugger.set_breakpoint"）
 *   依旧可直调（兼容模式，ToolRegistry.normalizeName 统一归一）
 * - 枢纽返回值附 `nextActions`（同命名空间可继续调用的动作），
 *   引导 AI 完成链式工作流：调用 A → 读结果 nextActions → 调 B → C
 *
 * 对客户端暴露的名称（tools/list / tools/call）统一为 MCP 规范的
 * 下划线形式（`ns_action`，如 `dom_get_tree`）；子枢纽名同样去点号
 * （`debugger_bp` / `debugger_script` / `debugger_runtime`）。
 *
 * 生成完全自动化：新增工具只需保持 `ns.action` 命名，重新注册即自动纳入枢纽。
 */
object HubTools {

    /** 单个 action 描述行截断长度（控制枢纽 description 总体积） */
    private const val DESC_LINE_MAX = 80

    /** 只读权限 scope（用于推导枢纽 permission：含任一写操作则整体按写算） */
    private val READ_ONLY_SCOPES = setOf(
        PermissionScope.READ_PAGE,
        PermissionScope.READ_DOM,
        PermissionScope.READ_NETWORK,
        PermissionScope.READ_STORAGE,
        PermissionScope.READ_COOKIES,
        PermissionScope.READ_HEADERS,
        PermissionScope.SCREENSHOT,
        PermissionScope.READ_WORKSPACE,
        PermissionScope.READ_FILE,
    )

    /** nextActions 提示最多列出的同命名空间动作数 */
    private const val NEXT_ACTIONS_MAX = 8

    /**
     * 大命名空间手动拆分：action 过多（>30）时 AI 选型准确率下降，
     * 按职责拆为子枢纽。key = 原命名空间，value = (子枢纽名, 该枢纽承载的 action 集)，
     * 未列出的 action 归入命名空间同名主枢纽。
     */
    private val SUB_HUBS: Map<String, List<Pair<String, Set<String>>>> = mapOf(
        "debugger" to listOf(
            "debugger_bp" to setOf(
                "set_breakpoint", "set_conditional_breakpoint", "set_dom_breakpoint",
                "set_event_breakpoint", "set_listener_breakpoint", "set_logpoint",
                "set_promise_breakpoint", "set_script_breakpoint", "set_source_breakpoint",
                "set_xhr_breakpoint", "remove_breakpoint", "list_breakpoints",
                "wait_breakpoint", "get_breakable_locations",
            ),
            "debugger_script" to setOf(
                "get_script_source", "list_scripts", "list_source_maps",
                "search_script", "resolve_position",
            ),
            "debugger_runtime" to setOf(
                "runtime_evaluate", "evaluate_on_call_frame", "evaluate_watch",
                "call_on_object", "call_stack", "get_object_properties", "query_objects",
                "locals", "scopes", "set_variable", "restart_frame",
                "watch", "unwatch", "snapshot", "state",
            ),
            // 其余（attach/detach/pause/resume/step/exceptions/cpu_profile/
            // detect_vmp/trace_vmp/get_vmp_trace/diff_vmp_trace/*_hits）归 debugger 主枢纽
        ),
    )

    /** 子枢纽职责标题（写进 description 开头，帮助 AI 理解分工） */
    private val HUB_TITLES: Map<String, String> = mapOf(
        "debugger" to "调试器核心控制与追踪（连接/暂停/单步/CPU 采样/VMP 追踪）",
        "debugger_bp" to "断点管理（行/条件/DOM/事件/监听器/XHR 断点与 logpoint）",
        "debugger_script" to "脚本与源码（脚本列表/源码/源码映射/内容搜索/位置解析）",
        "debugger_runtime" to "运行时求值与对象检查（求值/调用栈/作用域/对象属性/观察点）",
    )

    /** 工具归属的枢纽名：先查手动拆分规则，未命中则归命名空间主枢纽 */
    private fun hubNameFor(toolName: String): String {
        val ns = toolName.substringBefore('.')
        val action = toolName.substringAfter('.', "")
        SUB_HUBS[ns]?.forEach { (hub, actions) ->
            if (action in actions) return hub
        }
        return ns
    }

    /**
     * 扫描注册表中全部非枢纽工具，按枢纽归属（SUB_HUBS 拆分规则 + 命名空间）
     * 聚合生成枢纽并注册。应在所有原始工具注册完成后调用一次。
     */
    fun buildAndRegister(registry: ToolRegistry) {
        val originals = registry.list().filter { !it.metadata.isHub }
        val groups = originals.groupBy { hubNameFor(it.metadata.name) }
        val hubs = groups.map { (hubName, members) -> buildHub(hubName, members, registry) }
        registry.registerAll(hubs)
    }

    private fun buildHub(hubName: String, members: List<McpTool>, registry: ToolRegistry): McpTool {
        // 命名空间从成员名推导（子枢纽成员的原名前缀仍是原命名空间）
        val ns = members.first().metadata.name.substringBefore('.')
        val sorted = members.sortedBy { it.metadata.name }
        val actionNames = sorted.map { it.metadata.name.removePrefix("$ns.") }

        // ---- 1) description：职责标题 + 全部 action 及各自入参（AI 选型依据） ----
        val title = HUB_TITLES[hubName]
        val desc = buildString {
            if (title != null) append(title).append('\n')
            append("$hubName 聚合工具（${sorted.size} 个 action）。")
            append("用法：action 选动作，其余参数为该动作入参（各 action 参数见下）。可用 action：\n")
            sorted.forEach { t ->
                val action = t.metadata.name.removePrefix("$ns.")
                val props = (t.metadata.inputSchema["properties"] as? JsonObject)?.keys?.toList().orEmpty()
                val firstLine = t.metadata.description.lineSequence()
                    .firstOrNull { it.isNotBlank() }?.trim().orEmpty()
                val brief = if (firstLine.length > DESC_LINE_MAX) firstLine.take(DESC_LINE_MAX) + "…" else firstLine
                append("- $action: $brief")
                if (props.isNotEmpty()) append("（参数: ${props.joinToString(", ")}）")
                append('\n')
            }
        }.trimEnd()

        // ---- 2) inputSchema：action enum + 全成员参数并集（同名冲突取首个，仅提示性） ----
        val mergedProps = LinkedHashMap<String, JsonObject>()
        sorted.forEach { t ->
            val props = t.metadata.inputSchema["properties"] as? JsonObject ?: return@forEach
            props.forEach { (k, v) ->
                val vo = v as? JsonObject ?: return@forEach
                mergedProps.putIfAbsent(k, vo)
            }
        }
        val schema = buildJsonObject {
            put("type", "object")
            put(
                "properties",
                buildJsonObject {
                    put(
                        "action",
                        buildJsonObject {
                            put("type", "string")
                            put("description", "要执行的动作（全部可选值见工具描述）")
                            put("enum", JsonArray(actionNames.map { JsonPrimitive(it) }))
                        },
                    )
                    mergedProps.forEach { (k, v) -> put(k, v) }
                },
            )
            put("required", JsonArray(listOf(JsonPrimitive("action"))))
        }

        // ---- 3) 元数据聚合：权限取首个写操作、风险取最高、超时取最大 ----
        val firstWrite = sorted.firstOrNull { it.metadata.permission !in READ_ONLY_SCOPES } ?: sorted.first()
        val risk = sorted.maxByOrNull { it.metadata.riskLevel.ordinal }?.metadata?.riskLevel ?: RiskLevel.LOW
        val timeout = sorted.maxOfOrNull { it.metadata.timeoutMs } ?: 60_000L
        val category = sorted.groupingBy { it.metadata.category }.eachCount()
            .maxByOrNull { it.value }?.key ?: ToolCategory.MCP

        return object : McpTool {
            override val metadata = ToolMetadata(
                name = hubName,
                description = desc,
                category = category,
                permission = firstWrite.metadata.permission,
                riskLevel = risk,
                timeoutMs = timeout,
                inputSchema = schema,
                isHub = true,
            )

            override suspend fun execute(arguments: JsonObject): McpToolResult =
                execute(ToolContextScope.unknown(), arguments)

            override suspend fun execute(context: ToolContext, arguments: JsonObject): McpToolResult {
                val action = (arguments["action"] as? JsonPrimitive)?.contentOrNull?.trim()
                if (action.isNullOrBlank()) {
                    return McpToolResult.error(
                        "MISSING_ACTION",
                        "缺少 action 参数。可选 action：${actionNames.joinToString(", ")}",
                    )
                }
                // 原工具名还原（如 set_breakpoint -> debugger.set_breakpoint），转发执行；
                // 权限检查由原工具自身完成（携带真实 ToolContext）
                val member = registry.get("$ns.$action")
                    ?: return McpToolResult.error(
                        "ACTION_NOT_FOUND",
                        "未知 action \"$action\"。可选 action：${actionNames.joinToString(", ")}",
                    )
                val result = member.execute(context, arguments)
                return withNextActions(result, actionNames - action)
            }
        }
    }

    /**
     * 链式引导：在结构化返回值中追加 nextActions（同命名空间其他动作），
     * AI 读到即可知下一步可继续调什么。仅在有 structuredContent 时注入，
     * 并同步重镜像 text，保持 content 与 structuredContent 一致。
     */
    private fun withNextActions(result: McpToolResult, others: List<String>): McpToolResult {
        if (others.isEmpty() || result.structuredContent == null) return result
        val sc = result.structuredContent ?: return result
        val suggestions = others.take(NEXT_ACTIONS_MAX)
        val enriched = buildJsonObject {
            sc.forEach { (k, v) -> put(k, v) }
            put("nextActions", JsonArray(suggestions.map { JsonPrimitive(it) }))
        }
        val newContent = result.content.mapIndexed { idx, c ->
            if (idx == 0 && c.text != null) c.copy(text = enriched.toString()) else c
        }
        return result.copy(content = newContent, structuredContent = enriched)
    }
}
