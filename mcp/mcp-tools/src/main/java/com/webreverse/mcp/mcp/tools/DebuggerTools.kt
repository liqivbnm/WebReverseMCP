package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.common.model.BreakpointType
import com.webreverse.mcp.core.common.model.DebuggerState
import com.webreverse.mcp.browser.engine.BrowserSession
import com.webreverse.mcp.core.common.event.DebuggerEvent
import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import com.webreverse.mcp.devtools.protocol.cdp.CdpScript
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.coroutines.flow.first

/** Debugger Tools：断点、步进、调用栈、作用域、Watch（CDP 优先 + 注入式降级） */
object DebuggerTools {

    /** 未附加时自动 attach（幂等，CDP 优先） */
    private suspend fun ensureAttached(deps: ToolDependencies) {
        if (deps.debuggerManager.backend == "none") {
            deps.debuggerManager.attach(debugSession(deps).engine)
        }
    }

    /**
     * 调试目标会话：优先已建立 CDP 会话的 Tab（最近 attach 优先）。
     * 不随"活跃 Tab"漂移——多 Tab 场景下切换活跃 Tab 后，调试工具仍应
     * 作用于 attach 的目标页，否则断点列表为空、设置也打不到目标页面。
     */
    private suspend fun debugSession(deps: ToolDependencies): BrowserSession {
        for (tabId in deps.debuggerManager.connectedTabIds()) {
            deps.browserService.getSession(tabId)?.let { return it }
        }
        return deps.activeSession()
    }

    /** CDP 复用枢纽状态（AI 据此判断会话共享/暂停情况） */
    private fun linkageInfo(): JsonObject = buildJsonObject {
        val status = com.webreverse.mcp.devtools.protocol.cdp.CdpHub.linkageStatus()
        val mcpClients = status.sumOf { (it["mcpClients"] as? Int) ?: 0 }
        put("hubTargets", status.size)
        put("mcpClients", mcpClients)
        put(
            "hint",
            if (mcpClients > 0) {
                "CDP 复用枢纽工作中：调试与网络会话共享后端连接，互不踢线"
            } else {
                "尚无 MCP 会话接入 CDP 枢纽；debugger.attach / network.attach 后此处应有计数"
            },
        )
    }

    /**
     * 同 URL 脚本按最新解析者去重（inline 空 URL 不合并，按 scriptId 区分）。
     * _scripts 尾部为最新 scriptParsed，因此后出现的覆盖先出现的。
     */
    private fun dedupeLatest(list: List<CdpScript>): List<CdpScript> {
        val seen = LinkedHashMap<String, CdpScript>()
        for (s in list) {
            val key = if (s.url.isBlank()) "inline:${s.scriptId}" else s.url
            seen[key] = s
        }
        return seen.values.toList()
    }

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)
        return listOf(
            f.tool(
                "debugger.attach", "附加调试器（优先建立 CDP 会话，获得真实 V8 断点/单步/调用栈能力）", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
            ) { _ ->
                val session = debugSession(deps)
                val result = deps.debuggerManager.attach(session.engine)
                result.fold(
                    onSuccess = {
                        McpToolResult.json(
                            buildJsonObject {
                                put("backend", JsonPrimitive(deps.debuggerManager.backend))
                                put("state", JsonPrimitive(deps.debuggerManager.state.value.name))
                                put("debugTabId", JsonPrimitive(session.tabId))
                                if (deps.debuggerManager.backend == "cdp") put("linkage", linkageInfo())
                                put(
                                    "hint",
                                    JsonPrimitive(
                                        if (deps.debuggerManager.backend == "cdp") {
                                            "CDP 已连接：断点/单步/调用栈/作用域为 V8 原生语义；注入的 debugger; 语句同样会真实暂停"
                                        } else {
                                            val reason = com.webreverse.mcp.devtools.protocol.cdp.CdpTransport.lastError
                                            "CDP 不可用，已降级注入式后端：仅支持函数断点/异常断点，步进与暂停态变量不可用" +
                                                (reason?.let { "。原因：$it" } ?: "")
                                        },
                                    ),
                                )
                            },
                        )
                    },
                    onFailure = { McpToolResult.error("DEBUGGER_UNAVAILABLE", it.message) },
                )
            },
            f.tool(
                "debugger.detach", "分离调试器（断开 CDP 会话）", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
            ) { _ ->
                deps.debuggerManager.detach()
                McpToolResult.text("调试器已分离")
            },
            f.tool(
                "debugger.health", "CDP 调试会话健康巡检：后端/状态/枢纽/附加目标（返回可操作性建议，成员项均为当前会话可诊断信息）", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.LOW,
            ) { _ ->
                val session = debugSession(deps)
                val backend = deps.debuggerManager.backend
                val state = deps.debuggerManager.state.value
                val tabs = deps.debuggerManager.connectedTabIds().toList()
                McpToolResult.json(
                    buildJsonObject {
                        put("backend", JsonPrimitive(if (backend == "cdp") "cdp" else "injection"))
                        put("state", JsonPrimitive(state.name))
                        put("activeTab", JsonPrimitive(session.tabId))
                        put("connectedTabs", JsonArray(tabs.map { JsonPrimitive(it) }))
                        put("linkage", linkageInfo())
                        put(
                            "hint",
                            JsonPrimitive(
                                when {
                                    backend == "cdp" && state.name == "attached" ->
                                        "CDP 会话健康。若需强制重建连接（长时间无响应/断线自愈未触发），执行 debugger.reconnect 重连；trace 工具若超时可配合降低采样率"
                                    backend == "cdp" ->
                                        "CDP 已附加但状态为 ${state.name}，可 debugger.pause/debugger.resume 或 debugger.reconnect 恢复"
                                    backend == "none" ->
                                        "当前为注入式降级（无 CDP），功能受限；可 debugger.attach 尝试建立 CDP 会话"
                                    else -> "泄漏注入式后端，已附加（debugger.attach）时优先用 CDP"
                                },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "debugger.reconnect", "强制重连调试器（detach+attach，幂等）：CDP 会话漂移/连续超时后一键重建，重试失败自动回退注入后端", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
            ) { _ ->
                val session = debugSession(deps)
                runCatching { deps.debuggerManager.detach() }
                val result = deps.debuggerManager.attach(session.engine)
                result.fold(
                    onSuccess = {
                        McpToolResult.json(
                            buildJsonObject {
                                put("backend", JsonPrimitive(deps.debuggerManager.backend))
                                put("state", JsonPrimitive(deps.debuggerManager.state.value.name))
                                put("debugTabId", JsonPrimitive(session.tabId))
                                put("hint", JsonPrimitive("已强制重连${if (deps.debuggerManager.backend == "cdp") "（CDP 会话已重建）" else "（回退注入式后端）"}"))
                            },
                        )
                    },
                    onFailure = { McpToolResult.error("RECONNECT_FAILED", "重连失败：${it.message}") },
                )
            },
            f.tool(
                "debugger.pause", "暂停 JavaScript 执行", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
            ) { _ ->
                val session = debugSession(deps)
                ensureAttached(deps)
                val result = deps.debuggerManager.pause(session.engine)
                result.fold(
                    onSuccess = { McpToolResult.text("已暂停") },
                    onFailure = { McpToolResult.error("DEBUGGER_UNAVAILABLE", it.message) },
                )
            },
            f.tool(
                "debugger.resume", "恢复 JavaScript 执行", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
            ) { _ ->
                val session = debugSession(deps)
                val result = deps.debuggerManager.resume(session.engine)
                result.fold(
                    onSuccess = { McpToolResult.text("已恢复") },
                    onFailure = { McpToolResult.error("DEBUGGER_UNAVAILABLE", it.message) },
                )
            },
            f.tool(
                "debugger.step_into", "单步进入", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
            ) { _ ->
                val session = debugSession(deps)
                val result = deps.debuggerManager.stepInto(session.engine)
                result.fold(
                    onSuccess = { McpToolResult.text("已单步进入") },
                    onFailure = { McpToolResult.error("DEBUGGER_UNAVAILABLE", it.message) },
                )
            },
            f.tool(
                "debugger.step_over", "单步跳过", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
            ) { _ ->
                val session = debugSession(deps)
                val result = deps.debuggerManager.stepOver(session.engine)
                result.fold(
                    onSuccess = { McpToolResult.text("已单步跳过") },
                    onFailure = { McpToolResult.error("DEBUGGER_UNAVAILABLE", it.message) },
                )
            },
            f.tool(
                "debugger.step_out", "单步跳出", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
            ) { _ ->
                val session = debugSession(deps)
                val result = deps.debuggerManager.stepOut(session.engine)
                result.fold(
                    onSuccess = { McpToolResult.text("已单步跳出") },
                    onFailure = { McpToolResult.error("DEBUGGER_UNAVAILABLE", it.message) },
                )
            },
            f.tool(
                "debugger.restart_frame", "重启当前帧", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
            ) { _ ->
                val session = debugSession(deps)
                val result = deps.debuggerManager.restartFrame(session.engine)
                result.fold(
                    onSuccess = { McpToolResult.text("已重启帧") },
                    onFailure = { McpToolResult.error("DEBUGGER_UNAVAILABLE", it.message) },
                )
            },
            f.tool(
                "debugger.set_breakpoint", "设置断点", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "type" to Schemas.strSchema("line/function/exception/xhr/dom/event"),
                    "url" to Schemas.strSchema("源码 URL"),
                    "line" to Schemas.intSchema("行号"),
                    "target" to Schemas.strSchema("目标（函数名/URL 片段）"),
                ),
            ) { args ->
                val type = ToolArgs.str(args, "type", "line")
                val url = ToolArgs.str(args, "url")
                var line = ToolArgs.int(args, "line")
                val target = ToolArgs.str(args, "target")
                val session = debugSession(deps)
                ensureAttached(deps)
                val bpType = when (type.lowercase()) {
                    "function" -> BreakpointType.FUNCTION
                    "exception" -> BreakpointType.EXCEPTION
                    "xhr" -> BreakpointType.XHR
                    "dom" -> BreakpointType.DOM
                    "event" -> BreakpointType.EVENT
                    "logpoint" -> BreakpointType.LOGPOINT
                    else -> BreakpointType.LINE
                }
                // LINE 断点失败时自动校准行号：V8 要求断在语句起点，
                // 猜测的行号（尤其 minified）常落在表达式中间导致未命中。
                // 用 getPossibleBreakpoints 找最近可断位置重试一次。
                var corrected = false
                var result = if (bpType == BreakpointType.FUNCTION && target.isNotBlank()) {
                    deps.debuggerManager.setFunctionBreakpoint(session.engine, target)
                } else {
                    deps.debuggerManager.setBreakpoint(session.engine, bpType, url, line, target = target)
                }
                if (result.isFailure && bpType == BreakpointType.LINE && url.isNotBlank() && line > 0) {
                    // get_breakable_locations 返回结构升级为 {scriptId,total,locations,hint}
                    val correctedLine = deps.debuggerManager
                        .getBreakableLocations(session.engine, url, line, null, 1)
                        .getOrNull()
                        ?.get("locations")
                        ?.jsonArray
                        ?.firstOrNull()
                        ?.let { loc -> (loc as? JsonObject)?.get("lineNumber")?.jsonPrimitive?.intOrNull }
                    if (correctedLine != null && correctedLine > 0 && correctedLine != line) {
                        line = correctedLine
                        corrected = true
                        result = deps.debuggerManager.setBreakpoint(session.engine, bpType, url, line, target = target)
                    }
                }
                result.fold(
                    onSuccess = { bp ->
                        McpToolResult.json(
                            buildJsonObject {
                                put("id", JsonPrimitive(bp.id))
                                put("type", JsonPrimitive(bp.type.name))
                                put("url", JsonPrimitive(bp.url))
                                put("line", JsonPrimitive(bp.lineNumber))
                                put("target", JsonPrimitive(bp.target ?: ""))
                                if (corrected) put(
                                    "note",
                                    JsonPrimitive("原行号不可断，已自动校准到最近的语句起点（$line）"),
                                )
                                put(
                                    "hint",
                                    JsonPrimitive("event.wait eventType=debugger.breakpoint 阻塞等待命中；命中后 debugger.snapshot 一次取全现场"),
                                )
                            },
                        )
                    },
                    onFailure = { McpToolResult.error("DEBUGGER_UNAVAILABLE", it.message) },
                )
            },
            f.tool(
                "debugger.remove_breakpoint", "移除断点", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema("breakpointId" to Schemas.strSchema("断点 ID")),
            ) { args ->
                val id = ToolArgs.str(args, "breakpointId")
                val session = debugSession(deps)
                val result = deps.debuggerManager.removeBreakpoint(session.engine, id)
                result.fold(
                    onSuccess = { McpToolResult.text("已移除断点: $id") },
                    onFailure = { McpToolResult.error("DEBUGGER_UNAVAILABLE", it.message) },
                )
            },
            f.tool(
                "debugger.list_breakpoints", "列出所有断点（含外部调试客户端设置的断点，source 字段区分 mcp/devtools）", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.LOW,
            ) { _ ->
                val session = debugSession(deps)
                val breakpoints = deps.debuggerManager.listAllBreakpoints(session.engine)
                McpToolResult.json(
                    buildJsonObject {
                        put(
                            "breakpoints",
                            JsonArray(breakpoints),
                        )
                        if (deps.debuggerManager.backend == "cdp") put("linkage", linkageInfo())
                        put(
                            "hint",
                            JsonPrimitive("source=mcp 的用 remove_breakpoint(id) 移除；source=devtools 的 id 即 CDP breakpointId"),
                        )
                    },
                )
            },
            f.tool(
                "debugger.set_conditional_breakpoint", "设置条件断点", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "url" to Schemas.strSchema("源码 URL"),
                    "line" to Schemas.intSchema("行号"),
                    "condition" to Schemas.strSchema("条件表达式"),
                ),
            ) { args ->
                val url = ToolArgs.str(args, "url")
                val line = ToolArgs.int(args, "line")
                val condition = ToolArgs.str(args, "condition")
                val session = debugSession(deps)
                val result = deps.debuggerManager.setBreakpoint(session.engine, BreakpointType.LINE, url, line, condition = condition)
                result.fold(
                    onSuccess = { bp -> McpToolResult.text("已设置条件断点: ${bp.id}") },
                    onFailure = { McpToolResult.error("DEBUGGER_UNAVAILABLE", it.message) },
                )
            },
            f.tool(
                "debugger.set_logpoint", "设置日志断点（Logpoint）", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "url" to Schemas.strSchema("源码 URL"),
                    "line" to Schemas.intSchema("行号"),
                    "expression" to Schemas.strSchema("日志表达式"),
                ),
            ) { args ->
                val url = ToolArgs.str(args, "url")
                val line = ToolArgs.int(args, "line")
                val expression = ToolArgs.str(args, "expression")
                val session = debugSession(deps)
                val result = deps.debuggerManager.setLogpoint(session.engine, url, line, expression)
                result.fold(
                    onSuccess = { bp -> McpToolResult.text("已设置 Logpoint: ${bp.id}") },
                    onFailure = { McpToolResult.error("DEBUGGER_UNAVAILABLE", it.message) },
                )
            },
            f.tool(
                "debugger.watch", "添加 Watch 表达式", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema("expression" to Schemas.strSchema("Watch 表达式")),
            ) { args ->
                val expression = ToolArgs.str(args, "expression")
                val session = debugSession(deps)
                val result = deps.debuggerManager.addWatch(session.engine, expression)
                result.fold(
                    onSuccess = { w -> McpToolResult.text("已添加 Watch: ${w.id}") },
                    onFailure = { McpToolResult.error("DEBUGGER_UNAVAILABLE", it.message) },
                )
            },
            f.tool(
                "debugger.unwatch", "移除 Watch 表达式", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema("watchId" to Schemas.strSchema("Watch ID")),
            ) { args ->
                val id = ToolArgs.str(args, "watchId")
                val result = deps.debuggerManager.removeWatch(id)
                result.fold(
                    onSuccess = { McpToolResult.text("已移除 Watch: $id") },
                    onFailure = { McpToolResult.error("DEBUGGER_UNAVAILABLE", it.message) },
                )
            },
            f.tool(
                "debugger.evaluate_watch", "求值 Watch 表达式", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema("expression" to Schemas.strSchema("表达式")),
            ) { args ->
                val expression = ToolArgs.str(args, "expression")
                val session = debugSession(deps)
                val result = deps.debuggerManager.evaluateWatch(session.engine, expression)
                result.fold(
                    onSuccess = { McpToolResult.text(it) },
                    onFailure = { McpToolResult.error("DEBUGGER_UNAVAILABLE", it.message) },
                )
            },
            f.tool(
                "debugger.call_stack", "获取当前调用栈（ 含异步调用栈 asyncCauses：await/Promise.then 等异步来源帧）", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
            ) { _ ->
                val session = debugSession(deps)
                val result = deps.debuggerManager.getCallStack(session.engine)
                val asyncResult = deps.debuggerManager.getAsyncCallStack(session.engine)
                val syncFrames = result.getOrNull()
                if (syncFrames == null) {
                    return@tool result.fold(
                        onSuccess = { McpToolResult.text("") },
                        onFailure = { McpToolResult.error("DEBUGGER_UNAVAILABLE", it.message) },
                    )
                }
                McpToolResult.json(
                    buildJsonObject {
                        put(
                            "callFrames",
                            JsonArray(
                                syncFrames.map { fr ->
                                    buildJsonObject {
                                        put("functionName", JsonPrimitive(fr.functionName))
                                        put("url", JsonPrimitive(fr.url))
                                        put("lineNumber", JsonPrimitive(fr.lineNumber))
                                        put("columnNumber", JsonPrimitive(fr.columnNumber))
                                    }
                                },
                            ),
                        )
                        // 异步调用栈（DevTools async stack traces 同款）。
                        // 修复：结构固定化——无论有无异步栈都返回 asyncCauses 字段，
                        // 空数组=后端确认无异步来源（区别于旧版本字段缺失无法判断）。
                        val asyncCauses = asyncResult.getOrNull() ?: JsonArray(emptyList())
                        put("asyncCauses", asyncCauses)
                        if (asyncCauses.isNotEmpty()) {
                            put(
                                "hint",
                                "以上为同步帧；asyncCauses 为异步来源链（await / Promise.then 等），越靠前越接近当前帧",
                            )
                        }
                    },
                )
            },
            f.tool(
                "debugger.scopes", "获取作用域", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
            ) { _ ->
                val session = debugSession(deps)
                val result = deps.debuggerManager.getScopes(session.engine)
                result.fold(
                    onSuccess = { scopes ->
                        McpToolResult.json(
                            buildJsonObject {
                                put(
                                    "scopes",
                                    JsonArray(
                                        scopes.map { s ->
                                            buildJsonObject {
                                                put("type", JsonPrimitive(s.type.name))
                                                put("name", JsonPrimitive(s.name))
                                            }
                                        },
                                    ),
                                )
                            },
                        )
                    },
                    onFailure = { McpToolResult.error("DEBUGGER_UNAVAILABLE", it.message) },
                )
            },
            f.tool(
                "debugger.locals", "获取局部变量", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
            ) { _ ->
                val session = debugSession(deps)
                val result = deps.debuggerManager.getLocals(session.engine)
                result.fold(
                    onSuccess = { locals ->
                        McpToolResult.json(buildJsonObject { locals.forEach { (k, v) -> put(k, JsonPrimitive(v)) } })
                    },
                    onFailure = { McpToolResult.error("DEBUGGER_UNAVAILABLE", it.message) },
                )
            },
            f.tool(
                "debugger.exceptions", "设置异常断点（ 支持粒度：mode=all 所有异常 / uncaught 仅未捕获 / none 关闭）", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "mode" to Schemas.strSchema("all=所有异常(含已捕获) / uncaught=仅未捕获 / none=关闭（默认 all）"),
                    "enabled" to Schemas.boolSchema("向后兼容开关：true→all，false→none（可选，优先用 mode）"),
                ),
            ) { args ->
                val mode = ToolArgs.str(args, "mode")
                    .ifBlank { if (ToolArgs.bool(args, "enabled", true)) "all" else "none" }
                val session = debugSession(deps)
                if (deps.debuggerManager.backend != "cdp") {
                    ensureAttached(deps)
                }
                val result = deps.debuggerManager.setExceptionBreakpoints(session.engine, mode)
                result.fold(
                    onSuccess = {
                        McpToolResult.text(
                            when (mode.lowercase()) {
                                "uncaught" -> "已启用异常断点：仅未捕获异常/V8 unhandled rejection（DevTools 同款 uncaught 粒度）"
                                "none" -> "已禁用异常断点"
                                "caught", "all" -> "已启用异常断点：所有异常（含已捕获）"
                                else -> "已设置异常断点: $mode"
                            },
                        )
                    },
                    onFailure = { McpToolResult.error("DEBUGGER_UNAVAILABLE", it.message) },
                )
            },
            f.tool(
                "debugger.list_scripts", "列出页面已解析脚本（CDP scriptParsed 流；含 scriptId/url/sourceMapUrl）", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "urlFilter" to Schemas.strSchema("按 URL 子串过滤（可选）"),
                ),
            ) { args ->
                if (deps.debuggerManager.backend != "cdp") {
                    ensureAttached(deps)
                }
                if (deps.debuggerManager.backend != "cdp") {
                    return@tool McpToolResult.error("CDP_NOT_ATTACHED", "需要 CDP 会话，debugger.attach 失败（DevTools socket 不可用）")
                }
                val urlFilter = ToolArgs.str(args, "urlFilter")
                val session = debugSession(deps)
                val raw = deps.debuggerManager.listScripts(session.engine)
                    .filter { urlFilter.isBlank() || it.url.contains(urlFilter) }
                // （报告 P1）：同 URL 脚本重新解析后会保留新旧两个 scriptId，
                // 旧 ID 在 V8 中已失效。按 URL 去重只留最新解析者，避免 AI 拿旧 ID 报错。
                val scripts = dedupeLatest(raw)
                McpToolResult.json(
                    buildJsonObject {
                        put("count", JsonPrimitive(scripts.size))
                        put("totalParsed", JsonPrimitive(raw.size))
                        if (raw.size > scripts.size) {
                            put("deduped", JsonPrimitive(raw.size - scripts.size))
                            put("hint", JsonPrimitive("检测到重复解析的同 URL 脚本，已按最新 scriptId 去重"))
                        }
                        put(
                            "scripts",
                            JsonArray(
                                scripts.take(300).map { s ->
                                    buildJsonObject {
                                        put("scriptId", JsonPrimitive(s.scriptId))
                                        put("url", JsonPrimitive(s.url))
                                        put("length", JsonPrimitive(s.length))
                                        put("startLine", JsonPrimitive(s.startLine))
                                        put("endLine", JsonPrimitive(s.endLine))
                                        put("sourceMapUrl", JsonPrimitive(s.sourceMapUrl ?: ""))
                                    }
                                },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "debugger.get_script_source", "获取脚本源码（配合 list_scripts 的 scriptId；可用于定位真实断点行号）", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "scriptId" to Schemas.strSchema("脚本 ID（来自 debugger.list_scripts）"),
                    "maxChars" to Schemas.intSchema("最大返回字符数（默认 100000，上限 400000；minified 建议配合 js.format 格式化后分段阅读）"),
                ),
            ) { args ->
                val scriptId = ToolArgs.str(args, "scriptId")
                // （P1-5 修复）：maxChars 加上限约束（原实现无 coerce，
                // AI 传 10_000_000 也照做，响应体直接撑爆上下文/内存）
                // 上限 2M -> 400K（AI 上下文保护；更长源码用 js.format 分段）
                val maxChars = ToolArgs.int(args, "maxChars", 100_000).coerceIn(1000, 400_000)
                if (scriptId.isBlank()) return@tool McpToolResult.error("INVALID_ARGS", "scriptId 不能为空")
                val session = debugSession(deps)
                val result = deps.debuggerManager.getScriptSource(session.engine, scriptId, maxChars)
                result.fold(
                    onSuccess = { src ->
                        McpToolResult.json(
                            buildJsonObject {
                                put("scriptId", JsonPrimitive(scriptId))
                                put("length", JsonPrimitive(src.length))
                                put("source", JsonPrimitive(src))
                            },
                        )
                    },
                    onFailure = { McpToolResult.error("SCRIPT_NOT_FOUND", it.message) },
                )
            },
            f.tool(
                "debugger.evaluate_on_call_frame", "暂停态在指定调用帧上求值（可读取断点处局部变量/闭包变量）", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "expression" to Schemas.strSchema("JS 表达式（如变量名 token）"),
                    "frame" to Schemas.intSchema("调用帧序号（默认 0，即栈顶）"),
                ),
            ) { args ->
                val expression = ToolArgs.str(args, "expression")
                val frame = ToolArgs.int(args, "frame", 0)
                if (expression.isBlank()) return@tool McpToolResult.error("INVALID_ARGS", "expression 不能为空")
                val session = debugSession(deps)
                val result = deps.debuggerManager.evaluateOnCallFrame(session.engine, expression, frame)
                result.fold(
                    onSuccess = { McpToolResult.text(it) },
                    onFailure = { McpToolResult.error("EVALUATE_FAILED", it.message) },
                )
            },
            f.tool(
                "debugger.set_source_breakpoint",
                "原始源码断点：src/api/sign.ts:87 -> 自动下载 sourcemap 反查 bundle 位置 -> V8 setBreakpointByUrl（DevTools Sources 面板语义）",
                ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "sourceFile" to Schemas.strSchema("原始源文件路径（如 src/api/sign.ts，可用 debugger.list_source_maps 查看）"),
                    "line" to Schemas.intSchema("源文件行号（1-based）"),
                    "condition" to Schemas.strSchema("条件表达式（在断点位置由 V8 执行，可引用局部变量）"),
                ),
            ) { args ->
                val sourceFile = ToolArgs.str(args, "sourceFile")
                val line = ToolArgs.int(args, "line", 0)
                val condition = ToolArgs.str(args, "condition")
                if (sourceFile.isBlank() || line <= 0) {
                    return@tool McpToolResult.error("INVALID_ARGS", "sourceFile 与 line(>=1) 必填")
                }
                if (deps.debuggerManager.backend != "cdp") {
                    ensureAttached(deps)
                }
                val session = debugSession(deps)
                val result = deps.debuggerManager.setSourceBreakpoint(session.engine, sourceFile, line, condition.ifBlank { null })
                result.fold(
                    onSuccess = { bp ->
                        McpToolResult.json(
                            buildJsonObject {
                                put("breakpointId", JsonPrimitive(bp.id))
                                put("sourceFile", JsonPrimitive("$sourceFile:$line"))
                                put("bundleUrl", JsonPrimitive(bp.url))
                                put("bundleLine", JsonPrimitive(bp.lineNumber))
                                put("cdpBreakpointId", JsonPrimitive(bp.scriptId ?: ""))
                                put("hint", JsonPrimitive("断点已映射到 bundle 并由 V8 生效；触发对应代码后用 debugger.call_stack 查看"))
                            },
                        )
                    },
                    onFailure = { McpToolResult.error(it.code, it.message) },
                )
            },
            f.tool(
                "debugger.resolve_position", "bundle 位置 -> 原始源码位置（sourcemap 反查；用于把断点调用栈映射回源码）", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "url" to Schemas.strSchema("脚本 URL（来自 list_scripts / call_stack）"),
                    "line" to Schemas.intSchema("bundle 行号（1-based）"),
                    "column" to Schemas.intSchema("列号（可选，默认 1）"),
                ),
            ) { args ->
                val url = ToolArgs.str(args, "url")
                val line = ToolArgs.int(args, "line", 0)
                val column = ToolArgs.int(args, "column", 1)
                if (url.isBlank() || line <= 0) return@tool McpToolResult.error("INVALID_ARGS", "url 与 line 必填")
                val session = debugSession(deps)
                val result = deps.debuggerManager.resolveOriginalPosition(session.engine, url, line, column)
                result.fold(
                    onSuccess = { loc ->
                        McpToolResult.json(
                            buildJsonObject {
                                put("source", JsonPrimitive(loc.source))
                                put("line", JsonPrimitive(loc.line))
                                put("column", JsonPrimitive(loc.column))
                                loc.name?.let { put("name", JsonPrimitive(it)) }
                            },
                        )
                    },
                    onFailure = { McpToolResult.error(it.code, it.message) },
                )
            },
            f.tool(
                "debugger.list_source_maps", "列出带 sourcemap 的脚本及原始源文件清单（下载解析后返回，供选择断点目标）", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.LOW,
            ) { _ ->
                if (deps.debuggerManager.backend != "cdp") {
                    ensureAttached(deps)
                }
                if (deps.debuggerManager.backend != "cdp") {
                    return@tool McpToolResult.error("CDP_NOT_ATTACHED", "需要 CDP 会话")
                }
                val session = debugSession(deps)
                val entries = deps.debuggerManager.listSourceMappedScripts(session.engine)
                McpToolResult.json(
                    buildJsonObject {
                        put("count", JsonPrimitive(entries.size))
                        put(
                            "scripts",
                            JsonArray(
                                entries.take(50).map { e ->
                                    buildJsonObject {
                                        put("scriptUrl", JsonPrimitive(e.scriptUrl))
                                        put("sourceMapUrl", JsonPrimitive(e.sourceMapUrl))
                                        put("parsed", JsonPrimitive(e.info?.parsed == true))
                                        e.error?.let { put("error", JsonPrimitive(it)) }
                                        put(
                                            "sources",
                                            JsonArray(e.sources.take(200).map { JsonPrimitive(it) }),
                                        )
                                    }
                                },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "debugger.runtime_evaluate", "CDP Runtime.evaluate：支持 await/Promise，返回异常详情与 objectId（DevTools Console 语义）", ToolCategory.DEBUGGER,
                PermissionScope.EXECUTE_JS, RiskLevel.MEDIUM,
                timeoutMs = 60_000, // 覆盖 evaluateDetailed 的超时重试（2×20s）与 objectId 二次求值
                inputSchema = Schemas.objectSchema(
                    "expression" to Schemas.strSchema("JS 表达式（如 await fetch('/api/user').then(r=>r.json())）"),
                    "awaitPromise" to Schemas.boolSchema("是否等待 Promise（默认 true）"),
                    required = listOf("expression"),
                ),
            ) { args ->
                val expression = ToolArgs.str(args, "expression")
                val awaitPromise = ToolArgs.bool(args, "awaitPromise", true)
                if (expression.isBlank()) return@tool McpToolResult.error("INVALID_ARGS", "expression 必填")
                if (deps.debuggerManager.backend != "cdp") {
                    ensureAttached(deps)
                }
                if (deps.debuggerManager.backend != "cdp") {
                    return@tool McpToolResult.error("CDP_NOT_ATTACHED", "需要 CDP 会话")
                }
                val session = debugSession(deps)
                val result = deps.debuggerManager.runtimeEvaluate(session.engine, expression, awaitPromise)
                result.fold(
                    onSuccess = { McpToolResult.json(it) },
                    onFailure = { McpToolResult.error(it.code, it.message) },
                )
            },
            f.tool(
                "debugger.get_object_properties", "按 objectId 展开远程对象属性（配合 runtime_evaluate 返回的 objectId 深入检查对象）", ToolCategory.DEBUGGER,
                PermissionScope.EXECUTE_JS, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "objectId" to Schemas.strSchema("对象 ID（来自 runtime_evaluate / get_object_properties 的嵌套值）"),
                ),
            ) { args ->
                val objectId = ToolArgs.str(args, "objectId")
                if (objectId.isBlank()) return@tool McpToolResult.error("INVALID_ARGS", "objectId 必填")
                if (deps.debuggerManager.backend != "cdp") {
                    return@tool McpToolResult.error("CDP_NOT_ATTACHED", "需要 CDP 会话")
                }
                val session = debugSession(deps)
                val result = deps.debuggerManager.getObjectProperties(session.engine, objectId)
                result.fold(
                    onSuccess = { props ->
                        McpToolResult.json(
                            buildJsonObject {
                                put("count", JsonPrimitive(props.size))
                                put("properties", props)
                            },
                        )
                    },
                    onFailure = { McpToolResult.error(it.code, it.message) },
                )
            },
            f.tool(
                "debugger.detect_vmp",
                "静态探测 JSVMP 解释器 Dispatch 循环（while+大 switch+0x 密度特征），返回候选行号与疑似 opcode/pc 变量名",
                ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "scriptId" to Schemas.strSchema("脚本 ID（来自 debugger.list_scripts；留空则扫描最大脚本）"),
                ),
                timeoutMs = 60_000,
            ) { args ->
                if (deps.debuggerManager.backend != "cdp") {
                    ensureAttached(deps)
                }
                if (deps.debuggerManager.backend != "cdp") {
                    return@tool McpToolResult.error("CDP_NOT_ATTACHED", "需要 CDP 会话")
                }
                val scriptId = ToolArgs.str(args, "scriptId")
                val session = debugSession(deps)
                val scripts = deps.debuggerManager.listScripts(session.engine)
                    .filter { it.url.isNotBlank() && it.length > 1000 }
                val target = if (scriptId.isNotBlank()) {
                    scripts.firstOrNull { it.scriptId == scriptId }
                } else {
                    scripts.maxByOrNull { it.length }
                } ?: return@tool McpToolResult.error("SCRIPT_NOT_FOUND", "未找到可分析脚本")
                // 拉取源码上限与 VmpDetector 内部 SCAN_BUDGET(600KB) 对齐，
                // 1.7MB 大脚本不再全量跨 CDP 传输（此前是 2MB），显著降低大脚本检测延迟。
                val source = deps.debuggerManager.getScriptSource(session.engine, target.scriptId, 700_000).getOrNull()
                    ?: return@tool McpToolResult.error("SOURCE_UNAVAILABLE", "源码获取失败")
                val detector = com.webreverse.mcp.javascript.analysis.VmpDetector()
                // 检测本身为同步 CPU 扫描（预算内），用 withContext 挪到 IO 线程避免耗尽工具主线程；
                // 配合工具层 timeoutMs=60s 兜底。
                val candidates = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                    detector.detect(source)
                }
                McpToolResult.json(
                    buildJsonObject {
                        put("scriptUrl", JsonPrimitive(target.url))
                        put("scriptId", JsonPrimitive(target.scriptId))
                        put("candidateCount", JsonPrimitive(candidates.size))
                        put(
                            "candidates",
                            JsonArray(
                                candidates.map { c ->
                                    buildJsonObject {
                                        put("line", JsonPrimitive(c.line))
                                        put("column", JsonPrimitive(c.column))
                                        put("switchLine", JsonPrimitive(c.switchLine))
                                        put("switchColumn", JsonPrimitive(c.switchColumn))
                                        put("score", JsonPrimitive(c.score))
                                        put("caseCount", JsonPrimitive(c.caseCount))
                                        put("reasons", JsonPrimitive(c.reasons.joinToString("; ")))
                                        put("suggestedOps", JsonPrimitive(c.suggestedOps.joinToString(",")))
                                        if (c.handlers.isNotEmpty()) {
                                            put(
                                                "handlers",
                                                JsonArray(
                                                    c.handlers.take(20).map { h ->
                                                        buildJsonObject {
                                                            put("op", JsonPrimitive(h.key))
                                                            put("at", JsonPrimitive("${h.line}:${h.column}"))
                                                            put("code", JsonPrimitive(h.snippet.take(200)))
                                                        }
                                                    },
                                                ),
                                            )
                                        }
                                        put(
                                            "hint",
                                            JsonPrimitive(
                                                "下一步：debugger.trace_vmp url=<scriptUrl> line=${c.line} column=${c.column} expression=<opcode变量或其[pc]取值表达式>（minified 必须带 column）",
                                            ),
                                        )
                                    }
                                },
                            ),
                        )
                        if (candidates.isEmpty()) put("hint", JsonPrimitive("未发现典型 JSVMP 特征（可能是普通混淆或无保护）"))
                    },
                )
            },
            f.tool(
                "debugger.trace_vmp",
                "在 Dispatch 循环行设采样断点（条件恒 false 零暂停），每次执行记录表达式值到内存缓冲；运行目标操作后用 debugger.get_vmp_trace 取回",
                ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "url" to Schemas.strSchema("脚本 URL"),
                    "line" to Schemas.intSchema("dispatch 循环行号（detect_vmp 的候选行）"),
                    "column" to Schemas.intSchema("dispatch 循环列号（detect_vmp 候选列；minified 单行脚本必填，否则断点打不进循环）"),
                    "expression" to Schemas.strSchema("采样表达式（如 opcode 变量名，或 code[pc] 取下条指令；可用 {op:x,pc:y} 对象采样多个值）"),
                    "sampleRate" to Schemas.intSchema("采样率：每 N 次执行记录 1 次（默认 1 全采；高频 dispatch 建议 10~100 降开销）"),
                ),
            ) { args ->
                val url = ToolArgs.str(args, "url")
                val line = ToolArgs.int(args, "line", 0)
                val column = ToolArgs.optInt(args, "column")
                val sampleRate = ToolArgs.int(args, "sampleRate", 1)
                val expression = ToolArgs.str(args, "expression")
                if (url.isBlank() || line <= 0 || expression.isBlank()) {
                    return@tool McpToolResult.error("INVALID_ARGS", "url / line / expression 必填")
                }
                if (deps.debuggerManager.backend != "cdp") {
                    ensureAttached(deps)
                }
                val session = debugSession(deps)
                val result = deps.debuggerManager.setTraceBreakpoint(session.engine, url, line, expression, column, sampleRate)
                result.fold(
                    onSuccess = { bp ->
                        McpToolResult.json(
                            buildJsonObject {
                                put("breakpointId", JsonPrimitive(bp.id))
                                put("url", JsonPrimitive(url))
                                put("line", JsonPrimitive(line))
                                put("column", JsonPrimitive(column ?: 0))
                                put("sampleRate", JsonPrimitive(sampleRate))
                                put("expression", JsonPrimitive(expression))
                                put(
                                    "hint",
                                    JsonPrimitive(
                                        "已开始采样（环形缓冲 5 万条上限）。触发目标操作（点击/请求），随后调用 debugger.get_vmp_trace 获取折叠分析；对照组实验先 baseline=true 快照，操作后 diff_vmp_trace",
                                    ),
                                )
                            },
                        )
                    },
                    onFailure = { McpToolResult.error(it.code, it.message) },
                )
            },
            f.tool(
                "debugger.get_vmp_trace",
                "取回 VMP 采样并输出折叠摘要（opcode 频次 + 循环块识别 + RLE 序列），数万条样本压缩为数百 token",
                ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "maxSamples" to Schemas.intSchema("最多取回样本数（默认 5000）"),
                    "clear" to Schemas.boolSchema("取回后是否清空缓冲（默认 true）"),
                    "baseline" to Schemas.boolSchema("是否同时把当前采样保存为对照组快照（供 diff_vmp_trace 差分；默认 false，置 true 时不清空）"),
                ),
            ) { args ->
                val maxSamples = ToolArgs.int(args, "maxSamples", 5000)
                val baseline = ToolArgs.bool(args, "baseline", false)
                val clear = if (baseline) false else ToolArgs.bool(args, "clear", true)
                val session = debugSession(deps)
                if (baseline) {
                    deps.debuggerManager.snapshotVmpBaseline(session.engine)
                }
                val result = deps.debuggerManager.collectVmpTrace(session.engine, maxSamples)
                if (clear) deps.debuggerManager.clearVmpTrace(session.engine)
                result.fold(
                    onSuccess = { report ->
                        McpToolResult.json(
                            buildJsonObject {
                                put("totalSamples", JsonPrimitive(report.totalSamples))
                                put("uniqueOpcodes", JsonPrimitive(report.uniqueOpcodes))
                                put(
                                    "topOpcodes",
                                    JsonArray(
                                        report.topOpcodes.take(20).map { s ->
                                            buildJsonObject {
                                                put("opcode", JsonPrimitive(s.opcode.take(120)))
                                                put("count", JsonPrimitive(s.count))
                                            }
                                        },
                                    ),
                                )
                                put(
                                    "loops",
                                    JsonArray(
                                        report.loops.map { l ->
                                            buildJsonObject {
                                                put("sequence", JsonPrimitive(l.sequence))
                                                put("repeats", JsonPrimitive(l.repeats))
                                            }
                                        },
                                    ),
                                )
                                put("sequenceSummary", JsonPrimitive(report.sequenceSummary))
                                if (baseline) {
                                    put(
                                        "baselineSaved",
                                        JsonPrimitive("对照组已保存；触发对照操作（如登录/签名请求）后调用 debugger.diff_vmp_trace"),
                                    )
                                }
                            },
                        )
                    },
                    onFailure = { McpToolResult.error(it.code, it.message) },
                )
            },
            f.tool(
                "debugger.diff_vmp_trace",
                "对照组差分：把当前采样与 baseline 快照做 LCS 对齐，新增/缺失的 opcode 块即疑似签名生成路径（实战最快定位法）",
                ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.LOW,
            ) { _ ->
                val session = debugSession(deps)
                val result = deps.debuggerManager.diffVmpTrace(session.engine)
                result.fold(
                    onSuccess = { d ->
                        McpToolResult.json(
                            buildJsonObject {
                                put("baselineLen", JsonPrimitive(d.baselineLen))
                                put("testLen", JsonPrimitive(d.testLen))
                                put("commonRatio", JsonPrimitive("%.3f".format(d.commonRatio)))
                                put(
                                    "addedBlocks",
                                    JsonArray(d.addedBlocks.take(40).map { JsonPrimitive(it.take(160)) }),
                                )
                                put(
                                    "removedBlocks",
                                    JsonArray(d.removedBlocks.take(20).map { JsonPrimitive(it.take(160)) }),
                                )
                                put(
                                    "hint",
                                    JsonPrimitive(
                                        "addedBlocks 是对照组没有、本次新增的 opcode 块——疑似目标操作（登录/签名）专属执行路径；配合 detect_vmp 的 handlers 映射定位语义",
                                    ),
                                )
                            },
                        )
                    },
                    onFailure = { McpToolResult.error(it.code, it.message) },
                )
            },
            f.tool(
                "debugger.state", "获取调试器状态", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.LOW,
            ) { _ ->
                McpToolResult.json(
                    buildJsonObject {
                        put("state", JsonPrimitive(deps.debuggerManager.state.value.name))
                        put("backend", JsonPrimitive(deps.debuggerManager.backend))
                        put("breakpointCount", JsonPrimitive(deps.debuggerManager.breakpoints.value.size))
                        put("watchCount", JsonPrimitive(deps.debuggerManager.watchExpressions.value.size))
                    },
                )
            },

            // ==================== 断点增强 ====================

            f.tool(
                "debugger.set_dom_breakpoint",
                "DOM 断点（DevTools Elements 断点语义）：subtree-modified / attribute-modified / node-removed；基于 MutationObserver，无需 CDP；命中记录变更详情+堆栈，pause=true 时在变更处暂停",
                ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "selector" to Schemas.strSchema("CSS 选择器（如 #app 或 div.login-form）"),
                    "kind" to Schemas.strSchema("断点类型：subtree/attribute/removed/all（默认 all）"),
                    "pause" to Schemas.boolSchema("命中时是否 debugger 暂停（CDP attach 后为真实暂停；默认 false 仅记录）"),
                ),
            ) { args ->
                val selector = ToolArgs.str(args, "selector")
                if (selector.isBlank()) return@tool McpToolResult.error("INVALID_ARGS", "selector 必填")
                val kind = ToolArgs.str(args, "kind", "all")
                val pause = ToolArgs.bool(args, "pause", false)
                val session = debugSession(deps)
                val script = com.webreverse.mcp.browser.engine.util.JsScripts
                    .domBreakpointScript(selector, kind, pause)
                val raw = session.engine.evaluateJavascript(script) ?: "null"
                val ok = raw.contains("\"ok\":true")
                if (!ok) {
                    return@tool McpToolResult.error(
                        "SELECTOR_NOT_FOUND",
                        "选择器未匹配到元素（页面可能未就绪，先 browser.wait 或 dom.query 确认）",
                    )
                }
                McpToolResult.json(
                    buildJsonObject {
                        put("installed", JsonPrimitive(true))
                        put("selector", JsonPrimitive(selector))
                        put("kind", JsonPrimitive(kind))
                        put("pause", JsonPrimitive(pause))
                        put("hint", JsonPrimitive("触发 DOM 变化后调用 debugger.get_dom_hits 取回命中记录"))
                    },
                )
            },

            f.tool(
                "debugger.get_dom_hits",
                "取回 DOM 断点命中记录（变更类型/目标/属性/旧值/堆栈）",
                ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "limit" to Schemas.intSchema("最多返回条数（默认 100）"),
                    "clear" to Schemas.boolSchema("取回后清空（默认 false）"),
                ),
            ) { args ->
                val session = debugSession(deps)
                val raw = deps.debuggerManager.collectBreakpointHits(
                    session.engine, "dom", ToolArgs.int(args, "limit", 100),
                ) ?: return@tool McpToolResult.error("EVALUATE_FAILED", "取回失败")
                if (ToolArgs.bool(args, "clear", false)) {
                    deps.debuggerManager.clearBreakpointHits(session.engine, "dom")
                }
                McpToolResult.text(raw)
            },

            f.tool(
                "debugger.set_event_breakpoint",
                "事件监听断点（DevTools Event Listener Breakpoints）：指定事件类型（click/keydown/submit/...；control=控件类全集，all=常见交互全集）在监听器执行前暂停/记录",
                ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "eventType" to Schemas.strSchema("事件类型：click/keydown/submit/mousemove... 或 control/all"),
                    "pause" to Schemas.boolSchema("命中时是否 debugger 暂停（默认 false 仅记录）"),
                    "captureStack" to Schemas.boolSchema("记录调用堆栈（默认 true）"),
                ),
            ) { args ->
                val eventType = ToolArgs.str(args, "eventType")
                if (eventType.isBlank()) return@tool McpToolResult.error("INVALID_ARGS", "eventType 必填")
                val pause = ToolArgs.bool(args, "pause", false)
                val captureStack = ToolArgs.bool(args, "captureStack", true)
                val session = debugSession(deps)
                val script = com.webreverse.mcp.browser.engine.util.JsScripts
                    .eventBreakpointScript(eventType, pause, captureStack)
                session.engine.evaluateJavascript(script)
                McpToolResult.json(
                    buildJsonObject {
                        put("installed", JsonPrimitive(true))
                        put("eventType", JsonPrimitive(eventType))
                        put("pause", JsonPrimitive(pause))
                        put("hint", JsonPrimitive("触发事件后调用 debugger.get_event_hits 取回命中记录"))
                    },
                )
            },

            f.tool(
                "debugger.get_event_hits",
                "取回事件断点命中记录（事件/目标/键值/堆栈）",
                ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "limit" to Schemas.intSchema("最多返回条数（默认 100）"),
                    "clear" to Schemas.boolSchema("取回后清空（默认 false）"),
                ),
            ) { args ->
                val session = debugSession(deps)
                val raw = deps.debuggerManager.collectBreakpointHits(
                    session.engine, "event", ToolArgs.int(args, "limit", 100),
                ) ?: return@tool McpToolResult.error("EVALUATE_FAILED", "取回失败")
                if (ToolArgs.bool(args, "clear", false)) {
                    deps.debuggerManager.clearBreakpointHits(session.engine, "event")
                }
                McpToolResult.text(raw)
            },

            f.tool(
                "debugger.set_promise_breakpoint",
                "Promise 断点：捕获 unhandledrejection（含 reason 与堆栈），pause=true 时暂停",
                ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "pause" to Schemas.boolSchema("命中时是否 debugger 暂停（默认 false 仅记录）"),
                ),
            ) { args ->
                val session = debugSession(deps)
                val script = com.webreverse.mcp.browser.engine.util.JsScripts
                    .promiseBreakpointScript(ToolArgs.bool(args, "pause", false))
                session.engine.evaluateJavascript(script)
                McpToolResult.json(
                    buildJsonObject {
                        put("installed", JsonPrimitive(true))
                        put("hint", JsonPrimitive("Promise 拒绝发生后调用 debugger.get_promise_hits 取回"))
                    },
                )
            },

            f.tool(
                "debugger.get_promise_hits",
                "取回 Promise 断点命中记录（reason/堆栈）",
                ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.LOW,
            ) { _ ->
                val session = debugSession(deps)
                val raw = deps.debuggerManager.collectBreakpointHits(session.engine, "promise", 100)
                    ?: return@tool McpToolResult.error("EVALUATE_FAILED", "取回失败")
                McpToolResult.text(raw)
            },

            // ================= CDP 增强 =================

            f.tool(
                "debugger.snapshot",
                "暂停现场一键快照：断点命中后一次返回 调用栈+每帧局部变量+this+命中断点+原因（免多次调 call_stack/scopes/locals）",
                ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.LOW,
            ) { _ ->
                val session = debugSession(deps)
                ensureAttached(deps)
                deps.debuggerManager.snapshotPausedState(session.engine).fold(
                    onSuccess = { McpToolResult.json(it) },
                    onFailure = { McpToolResult.error(it.code, it.message) },
                )
            },
            f.tool(
                "debugger.wait_breakpoint",
                "等待断点命中并直接返回暂停现场快照（= event.wait debugger.paused + snapshot 一步到位）：设好断点、触发操作后调用，命中即返回调用栈+局部变量；已暂停态立即返回",
                ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "timeoutMs" to Schemas.intSchema("等待毫秒（默认 30000）"),
                ),
            ) { args ->
                val timeoutMs = ToolArgs.long(args, "timeoutMs", 30_000L)
                ensureAttached(deps)
                val session = debugSession(deps)
                if (deps.debuggerManager.state.value != DebuggerState.PAUSED) {
                    val hit = kotlinx.coroutines.withTimeoutOrNull(timeoutMs) {
                        deps.eventBus.events.first { it is DebuggerEvent.Paused }
                    }
                    if (hit == null) {
                        return@tool McpToolResult.error(
                            "TIMEOUT",
                            "等待断点命中超时：确认断点位置可达（get_breakable_locations 校准行号）、触发对应操作，或改用 XHR/事件断点",
                        )
                    }
                }
                deps.debuggerManager.snapshotPausedState(session.engine).fold(
                    onSuccess = { McpToolResult.json(it) },
                    onFailure = { McpToolResult.error(it.code, it.message) },
                )
            },
            f.tool(
                "debugger.search_script",
                "在脚本内容中搜索（CDP Debugger.searchInContent，不拉全量源码，返回行号+命中行）：定位加密函数/关键字出现位置。" +
                    "scriptIdOrUrl 支持 scriptId/完整 URL/URL 子串（如 main.，多个命中取最大脚本）；可省略或传 \"*\"——此时全局搜索所有已解析脚本，" +
                    "命中项附带 scriptId/url（ 新增，解决按关键字全库定位只能盲猜脚本名的问题）。" +
                    "命中的 lineNumber/column 是原始源码坐标，可直接传给 js.format 的 aroundLine/aroundColumn 获取该处格式化后的可读代码",
                ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "scriptIdOrUrl" to Schemas.strSchema("脚本 scriptId、完整 URL 或 URL 子串（如 main.）；省略或传 * 则全局搜索全部脚本"),
                    "query" to Schemas.strSchema("搜索文本（正则语法，必填）"),
                    "caseSensitive" to Schemas.boolSchema("区分大小写（默认 false）"),
                    "limit" to Schemas.intSchema("最多返回条数（默认 50）"),
                ),
            ) { args ->
                val scriptIdOrUrl = ToolArgs.str(args, "scriptIdOrUrl")
                val query = ToolArgs.str(args, "query")
                if (query.isBlank()) {
                    return@tool McpToolResult.error("INVALID_ARGS", "query 必填；scriptIdOrUrl 可省略（省略时全局搜索全部脚本）")
                }
                ensureAttached(deps)
                val session = debugSession(deps)
                deps.debuggerManager.searchScriptContent(
                    session.engine, scriptIdOrUrl, query,
                    ToolArgs.bool(args, "caseSensitive", false),
                    ToolArgs.int(args, "limit", 50),
                ).fold(
                    onSuccess = { matches ->
                        McpToolResult.json(
                            buildJsonObject {
                                put("matches", matches)
                                put("count", JsonPrimitive(matches.size))
                                if (scriptIdOrUrl.isBlank() || scriptIdOrUrl == "*") {
                                    put("mode", JsonPrimitive("global"))
                                    if (matches.isEmpty()) {
                                        put("hint", JsonPrimitive("全局搜索全部脚本无命中。可换正则/关键词重试，或 scriptIdOrUrl 指定脚本，或用 debugger.list_scripts 先看脚本清单"))
                                    }
                                }
                            },
                        )
                    },
                    onFailure = { McpToolResult.error(it.code, it.message) },
                )
            },
            f.tool(
                "debugger.get_breakable_locations",
                "查询可断点位置（CDP getPossibleBreakpoints）：V8 行号自动对齐到语句起点，打断点前先查可精确命中（minified 必用）",
                ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "url" to Schemas.strSchema("脚本 URL"),
                    "line" to Schemas.intSchema("行号（1-based）"),
                    "column" to Schemas.intSchema("列号（可选，1-based）"),
                    "limit" to Schemas.intSchema("最多返回条数（默认 20）"),
                ),
            ) { args ->
                val url = ToolArgs.str(args, "url")
                val line = ToolArgs.int(args, "line", 0)
                if (url.isBlank() || line <= 0) {
                    return@tool McpToolResult.error("INVALID_ARGS", "url 与 line(>=1) 必填")
                }
                ensureAttached(deps)
                val session = debugSession(deps)
                deps.debuggerManager.getBreakableLocations(
                    session.engine, url, line,
                    ToolArgs.int(args, "column", 0).takeIf { it > 0 },
                    ToolArgs.int(args, "limit", 20),
                ).fold(
                    onSuccess = { McpToolResult.json(it) },
                    onFailure = { McpToolResult.error(it.code, it.message) },
                )
            },
            f.tool(
                "debugger.set_variable",
                "暂停态修改局部变量（CDP setVariableValue）：改完单步即可观察加密逻辑走向",
                ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "name" to Schemas.strSchema("变量名"),
                    "value" to Schemas.strSchema("新值（JS 表达式，如 'abc' / 123 / {a:1}）"),
                    "frameIndex" to Schemas.intSchema("调用帧序号（默认 0，顶部帧）"),
                    "scopeNumber" to Schemas.intSchema("作用域序号（默认 0，从 scopes 结果取）"),
                ),
            ) { args ->
                val name = ToolArgs.str(args, "name")
                val value = ToolArgs.str(args, "value")
                if (name.isBlank() || value.isBlank()) {
                    return@tool McpToolResult.error("INVALID_ARGS", "name 与 value 必填")
                }
                val session = debugSession(deps)
                deps.debuggerManager.setVariableValue(
                    session.engine,
                    ToolArgs.int(args, "frameIndex", 0),
                    ToolArgs.int(args, "scopeNumber", 0),
                    name, value,
                ).fold(
                    onSuccess = { McpToolResult.json(buildJsonObject { put("ok", JsonPrimitive(true)); put("variable", JsonPrimitive(name)); put("value", JsonPrimitive(value)) }) },
                    onFailure = { McpToolResult.error(it.code, it.message) },
                )
            },
            f.tool(
                "debugger.query_objects",
                "构造器实例查询（CDP Runtime.queryObjects）：找出某类（加密器/签名器）现存全部实例，逐一 dump 找密钥与配置",
                ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "constructor" to Schemas.strSchema("构造器表达式，如 window.JSEncrypt / Object.getPrototypeOf(obj)"),
                    "limit" to Schemas.intSchema("最多返回实例数（默认 20）"),
                ),
            ) { args ->
                val ctor = ToolArgs.str(args, "constructor")
                if (ctor.isBlank()) return@tool McpToolResult.error("INVALID_ARGS", "constructor 必填")
                ensureAttached(deps)
                val session = debugSession(deps)
                deps.debuggerManager.queryObjects(session.engine, ctor, ToolArgs.int(args, "limit", 20))
                    .fold(
                        onSuccess = { McpToolResult.json(it) },
                        onFailure = { McpToolResult.error(it.code, it.message) },
                    )
            },
            f.tool(
                "debugger.call_on_object",
                "在远程对象上调用方法（CDP Runtime.callFunctionOn）：配合 get_object_properties 的 objectId，读加密器内部状态/调用实例方法",
                ToolCategory.DEBUGGER,
                PermissionScope.EXECUTE_JS, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "objectId" to Schemas.strSchema("对象 objectId（get_object_properties / runtime_evaluate 获取）"),
                    "functionDeclaration" to Schemas.strSchema("函数声明，如 function(){ return this.key; }"),
                    "arguments" to Schemas.strSchema("参数（JSON 数组字符串，每项为 JS 表达式；省略=无参）"),
                ),
            ) { args ->
                val objectId = ToolArgs.str(args, "objectId")
                val fn = ToolArgs.str(args, "functionDeclaration")
                if (objectId.isBlank() || fn.isBlank()) {
                    return@tool McpToolResult.error("INVALID_ARGS", "objectId 与 functionDeclaration 必填")
                }
                val argsJson = ToolArgs.str(args, "arguments").takeIf { it.isNotBlank() }
                val argv: List<String> = if (argsJson == null) {
                    emptyList()
                } else {
                    runCatching {
                        kotlinx.serialization.json.Json.parseToJsonElement(argsJson).jsonArray
                            .mapNotNull { el -> el.jsonPrimitive.contentOrNull }
                    }.getOrDefault(emptyList())
                }
                ensureAttached(deps)
                val session = debugSession(deps)
                deps.debuggerManager.callFunctionOn(session.engine, objectId, fn, argv).fold(
                    onSuccess = { McpToolResult.json(it) },
                    onFailure = { McpToolResult.error(it.code, it.message) },
                )
            },
            f.tool(
                "debugger.set_xhr_breakpoint",
                "CDP 原生 XHR/fetch 断点（DOMDebugger.setXHRBreakpoint）：请求发起前真实暂停（与 DevTools XHR breakpoints 同源），栈底即签名函数",
                ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "urlPattern" to Schemas.strSchema("URL 子串匹配，空串=全部请求"),
                    "enabled" to Schemas.boolSchema("true 设置 / false 移除（默认 true）"),
                ),
            ) { args ->
                val pattern = ToolArgs.str(args, "urlPattern")
                val enabled = ToolArgs.bool(args, "enabled", true)
                val session = debugSession(deps)
                deps.debuggerManager.setXhrBreakpoint(session.engine, pattern, enabled).fold(
                    onSuccess = {
                        McpToolResult.json(
                            buildJsonObject {
                                put("ok", JsonPrimitive(true))
                                put("urlPattern", JsonPrimitive(pattern))
                                put("enabled", JsonPrimitive(enabled))
                                if (enabled) put(
                                    "hint",
                                    JsonPrimitive("触发请求后将暂停：先 debugger.snapshot 看现场，再 debugger.call_stack 找签名函数"),
                                )
                            },
                        )
                    },
                    onFailure = { McpToolResult.error(it.code, it.message) },
                )
            },
            f.tool(
                "debugger.set_listener_breakpoint",
                "CDP 原生事件监听断点（DOMDebugger.setEventListenerBreakpoint）：监听器执行前真实暂停，比注入式断点更准（含第三方框架委托）",
                ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "eventName" to Schemas.strSchema("事件名：click / keydown / submit / mouseover ..."),
                    "enabled" to Schemas.boolSchema("true 设置 / false 移除（默认 true）"),
                ),
            ) { args ->
                val eventName = ToolArgs.str(args, "eventName")
                if (eventName.isBlank()) return@tool McpToolResult.error("INVALID_ARGS", "eventName 必填")
                val enabled = ToolArgs.bool(args, "enabled", true)
                val session = debugSession(deps)
                deps.debuggerManager.setEventListenerBreakpoint(session.engine, eventName, enabled).fold(
                    onSuccess = {
                        McpToolResult.json(
                            buildJsonObject {
                                put("ok", JsonPrimitive(true))
                                put("eventName", JsonPrimitive(eventName))
                                put("enabled", JsonPrimitive(enabled))
                            },
                        )
                    },
                    onFailure = { McpToolResult.error(it.code, it.message) },
                )
            },
            f.tool(
                "debugger.set_script_breakpoint",
                "脚本执行前断点（beforeScriptExecution）：任何新脚本执行前暂停，拦截加密初始化/JSVMP 加载时机（enabled=false 移除）",
                ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "enabled" to Schemas.boolSchema("true 设置 / false 移除（默认 true）"),
                ),
            ) { args ->
                val enabled = ToolArgs.bool(args, "enabled", true)
                val session = debugSession(deps)
                deps.debuggerManager.setInstrumentationBreakpoint(session.engine, enabled).fold(
                    onSuccess = {
                        McpToolResult.json(
                            buildJsonObject {
                                put("ok", JsonPrimitive(true))
                                put("enabled", JsonPrimitive(enabled))
                                if (enabled) put("hint", JsonPrimitive("刷新页面（browser.reload）或等待动态加载即会在每个新脚本前暂停"))
                            },
                        )
                    },
                    onFailure = { McpToolResult.error(it.code, it.message) },
                )
            },
            f.tool(
                "debugger.cpu_profile",
                "CPU 性能分析（CDP Profiler）：start=true 开始采样，操作页面跑加密流程后 start=false 停止，返回 selfTime 热点函数（加密/签名计算通常霸榜，url:line 直接可断点）",
                ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "start" to Schemas.boolSchema("true=开始录制 / false=停止并返回热点（必填）"),
                    "topN" to Schemas.intSchema("热点函数数量（默认 25）"),
                ),
            ) { args ->
                val start = ToolArgs.bool(args, "start", false)
                ensureAttached(deps)
                val session = debugSession(deps)
                deps.debuggerManager.cpuProfile(session.engine, start, ToolArgs.int(args, "topN", 25)).fold(
                    onSuccess = { McpToolResult.json(it) },
                    onFailure = { McpToolResult.error(it.code, it.message) },
                )
            },

            // ---------------- Target 域工具（Worker/ServiceWorker/iframe 统一管理） ----------------

            f.tool(
                "target.list", "列出全部 CDP Target（Page/iframe/Worker/ServiceWorker； Target domain 自动发现，JSVMP Worker 加密源码在此可见）", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.LOW,
            ) { _ ->
                ensureAttached(deps)
                val session = debugSession(deps)
                val targets = deps.debuggerManager.listTargets(session.engine)
                if (targets.isEmpty()) {
                    // 区分"未附加 CDP"与"WebView 不支持 Target 域"两种受限根因
                    val reason = if (deps.debuggerManager.backend != "cdp") {
                        "未附加 CDP 会话（当前后端=${deps.debuggerManager.backend}），请先 debugger.attach 建立 CDP 会话"
                    } else {
                        "当前 WebView 未暴露 Target 域（旧版 Android WebView 限制，Worker/ServiceWorker 发现不可用），或当前无可枚举 target"
                    }
                    return@tool McpToolResult.error("TARGET_DOMAIN_UNAVAILABLE", "Target domain 不可用或无 target：$reason")
                }
                McpToolResult.json(
                    buildJsonObject {
                        put("count", targets.size)
                        put("targets", JsonArray(targets.map { t ->
                            buildJsonObject {
                                put("targetId", t.targetId)
                                put("type", t.type)
                                put("title", t.title)
                                put("url", t.url)
                                put("attached", t.attached)
                                t.sessionId?.let { put("sessionId", it) }
                                put("canDebug", t.canDebug)
                            }
                        }))
                        put("hint", "worker/service_worker 的加密逻辑用 target.evaluate 执行/ target.enable_debugger 后 target.list_scripts 查看")
                    },
                )
            },
            f.tool(
                "target.attach", "attach 指定 Target（建立 flatten 子会话；Worker/SW 断点调试前置步骤）", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "targetId" to Schemas.strSchema("target.list 返回的 targetId"),
                ),
            ) { args ->
                ensureAttached(deps)
                val session = debugSession(deps)
                deps.debuggerManager.attachToTarget(session.engine, ToolArgs.str(args, "targetId")).fold(
                    onSuccess = { sid ->
                        McpToolResult.json(
                            buildJsonObject {
                                put("attached", true)
                                put("sessionId", sid)
                                put("hint", "子会话已建立；后续 target.evaluate / target.enable_debugger 作用于该 target")
                            },
                        )
                    },
                    onFailure = { McpToolResult.error(it.code, it.message) },
                )
            },
            f.tool(
                "target.evaluate", "在指定 Target 上下文执行表达式（Worker/SW 内变量读取、函数调用；主上下文 page 之外的执行通道）", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "targetId" to Schemas.strSchema("target.list 返回的 targetId"),
                    "expression" to Schemas.strSchema("JS 表达式"),
                ),
            ) { args ->
                ensureAttached(deps)
                val session = debugSession(deps)
                deps.debuggerManager.evaluateOnTarget(
                    session.engine,
                    ToolArgs.str(args, "targetId"),
                    ToolArgs.str(args, "expression"),
                ).fold(
                    onSuccess = { McpToolResult.json(it) },
                    onFailure = { McpToolResult.error(it.code, it.message) },
                )
            },
            f.tool(
                "target.enable_debugger", "对指定 Target 启用 Debugger domain（之后 target.list_scripts 可见其脚本、断点可下到 Worker 内部）", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "targetId" to Schemas.strSchema("target.list 返回的 targetId"),
                ),
            ) { args ->
                ensureAttached(deps)
                val session = debugSession(deps)
                deps.debuggerManager.enableDebuggerOnTarget(session.engine, ToolArgs.str(args, "targetId")).fold(
                    onSuccess = {
                        McpToolResult.json(
                            buildJsonObject {
                                put("enabled", true)
                                put("hint", "已启用 Debugger domain；target.list_scripts 查看脚本，debugger.set_breakpoint 断 worker 内代码")
                            },
                        )
                    },
                    onFailure = { McpToolResult.error(it.code, it.message) },
                )
            },
            f.tool(
                "target.list_scripts", "列出指定 Target（Worker/SW）内已解析脚本（需先 target.enable_debugger）", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "targetId" to Schemas.strSchema("target.list 返回的 targetId"),
                ),
            ) { args ->
                ensureAttached(deps)
                val session = debugSession(deps)
                val scripts = deps.debuggerManager.listTargetScripts(session.engine, ToolArgs.str(args, "targetId"))
                if (scripts.isEmpty()) {
                    return@tool McpToolResult.error("NO_TARGET_SCRIPTS", "该 target 无已解析脚本（先 target.enable_debugger，或 target 不支持）")
                }
                McpToolResult.json(
                    buildJsonObject {
                        put("count", scripts.size)
                        put("scripts", JsonArray(scripts.map { s ->
                            buildJsonObject {
                                put("scriptId", s.scriptId)
                                put("url", s.url)
                                put("length", s.length)
                                s.sourceMapUrl?.let { put("sourceMapUrl", it) }
                            }
                        }))
                    },
                )
            },

            // ---------------- 执行前脚本改写工具（Fetch Response 闭环） ----------------

            f.tool(
                "script_rewrite.enable", "启用执行前脚本改写（CDP Fetch Response 阶段拦截：脚本响应到达时改写后再交给 V8 执行；debugger 反调试在 parse 期即被中和）", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.HIGH,
            ) { _ ->
                ensureAttached(deps)
                val session = debugSession(deps)
                deps.debuggerManager.enableScriptRewrite(session.engine).fold(
                    onSuccess = {
                        McpToolResult.json(
                            buildJsonObject {
                                put("enabled", true)
                                put("hint", "先用 script_rewrite.add_rule 配置规则（空规则集=透传不改写）；随后 reload 页面让脚本重新过 Fetch")
                            },
                        )
                    },
                    onFailure = { McpToolResult.error(it.code, it.message) },
                )
            },
            f.tool(
                "script_rewrite.disable", "禁用执行前脚本改写（恢复原始响应直通）", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.LOW,
            ) { _ ->
                val session = debugSession(deps)
                deps.debuggerManager.disableScriptRewrite(session.engine).fold(
                    onSuccess = { McpToolResult.json(buildJsonObject { put("enabled", false) }) },
                    onFailure = { McpToolResult.error(it.code, it.message) },
                )
            },
            f.tool(
                "script_rewrite.add_rule", "添加改写规则（urlPattern 匹配的脚本响应执行前改写：neutralizeDebugger 中和 debugger 语句；prepend/append 注入探针代码）", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.HIGH,
                inputSchema = Schemas.objectSchema(
                    "urlPattern" to Schemas.strSchema("URL 子串匹配（空=全部脚本）"),
                    "neutralizeDebugger" to Schemas.boolSchema("中和 debugger/Function('debugger') 反调试（默认 true）"),
                    "prepend" to Schemas.strSchema("改写后源码前拼接的代码（可选）"),
                    "append" to Schemas.strSchema("改写后源码末尾拼接的代码（可选）"),
                ),
            ) { args ->
                ensureAttached(deps)
                val session = debugSession(deps)
                deps.debuggerManager.addScriptRewriteRule(
                    session.engine,
                    ToolArgs.str(args, "urlPattern"),
                    ToolArgs.bool(args, "neutralizeDebugger", true),
                    ToolArgs.optStr(args, "prepend"),
                    ToolArgs.optStr(args, "append"),
                ).fold(
                    onSuccess = { McpToolResult.json(it) },
                    onFailure = { McpToolResult.error(it.code, it.message) },
                )
            },
            f.tool(
                "script_rewrite.remove_rule", "移除改写规则（按 add_rule 返回的 ruleId）", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "ruleId" to Schemas.strSchema("add_rule 返回的 ruleId"),
                ),
            ) { args ->
                val session = debugSession(deps)
                deps.debuggerManager.removeScriptRewriteRule(session.engine, ToolArgs.str(args, "ruleId")).fold(
                    onSuccess = { removed ->
                        McpToolResult.json(
                            buildJsonObject {
                                put("removed", removed)
                                if (!removed) put("hint", "ruleId 不存在（script_rewrite.rules 查看现有规则）")
                            },
                        )
                    },
                    onFailure = { McpToolResult.error(it.code, it.message) },
                )
            },
            f.tool(
                "script_rewrite.rules", "列出当前改写规则与启用状态", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.LOW,
            ) { _ ->
                val session = debugSession(deps)
                val rules = deps.debuggerManager.listScriptRewriteRules(session.engine)
                McpToolResult.json(
                    buildJsonObject {
                        put("count", rules.size)
                        put("rules", JsonArray(rules.map { r ->
                            buildJsonObject {
                                put("id", r.id)
                                put("urlPattern", r.urlPattern)
                                put("neutralizeDebugger", r.neutralizeDebugger)
                                put("enabled", r.enabled)
                                if (r.prepend != null) put("prepend", (r.prepend ?: "").take(200))
                                if (r.append != null) put("append", (r.append ?: "").take(200))
                            }
                        }))
                    },
                )
            },
            f.tool(
                "script_rewrite.records", "查看改写记录（最近在前：URL/原哈希/改后哈希/中和数/SRI 风险——改写是否真实发生的证据链）", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "limit" to Schemas.intSchema("返回条数（默认 50）"),
                ),
            ) { args ->
                val session = debugSession(deps)
                val records = deps.debuggerManager.listScriptRewriteRecords(session.engine, ToolArgs.int(args, "limit", 50))
                McpToolResult.json(
                    buildJsonObject {
                        put("count", records.size)
                        put("records", JsonArray(records.map { r ->
                            buildJsonObject {
                                put("url", r.url)
                                put("requestId", r.requestId)
                                put("originalHash", r.originalHash.take(16))
                                put("transformedHash", r.transformedHash.take(16))
                                put("neutralized", r.neutralized)
                                put("timestamp", r.timestamp)
                                r.sriWarning?.let { put("sriWarning", it) }
                            }
                        }))
                        if (records.isEmpty()) put("hint", "尚无改写记录（规则添加后 reload 页面；enable 状态下无规则=透传）")
                    },
                )
            },
            f.tool(
                "debugger.blackbox", "把匹配 URL 正则的脚本标记为黑盒（DevTools Sources 右键 Blackbox Script）：单步/断点导航自动跳过这些库脚本", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "patterns" to Schemas.strSchema("逗号分隔的 URL 正则（如 jquery.min.js,vendor）；留空=清空黑盒"),
                ),
            ) { args ->
                val patterns = ToolArgs.str(args, "patterns").split(',', '，').map { it.trim() }.filter { it.isNotBlank() }
                val session = debugSession(deps)
                deps.debuggerManager.setBlackbox(session.engine, patterns).fold(
                    onSuccess = {
                        McpToolResult.json(
                            buildJsonObject {
                                put("patterns", JsonArray(patterns.map { JsonPrimitive(it) }))
                                put("hint", if (patterns.isEmpty()) "已清空黑盒配置" else "单步时将自动跳过匹配脚本；移除黑盒=重设空 patterns")
                            },
                        )
                    },
                    onFailure = { McpToolResult.error(it.code, it.message) },
                )
            },
            f.tool(
                "debugger.pretty_print", "源码 Pretty-print（词法级格式化）+ 缓存格式化行→原始坐标映射（DevTools 源码格式化同款）；随后用 set_pretty_breakpoint 在格式化行下断", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "scriptId" to Schemas.strSchema("脚本 ID"),
                    "rename" to Schemas.boolSchema("是否把混淆标识符(_0x...)重命名为 v1/v2（默认 false）"),
                    "maxChars" to Schemas.intSchema("返回格式化文本最大字符数（默认 120000）"),
                ),
            ) { args ->
                val scriptId = ToolArgs.str(args, "scriptId")
                if (scriptId.isBlank()) return@tool McpToolResult.error("INVALID_ARGS", "scriptId 不能为空")
                val session = debugSession(deps)
                deps.debuggerManager.prettyPrint(
                    session.engine, scriptId,
                    ToolArgs.bool(args, "rename", false),
                    ToolArgs.int(args, "maxChars", 120_000),
                ).fold(
                    onSuccess = { McpToolResult.json(it) },
                    onFailure = { McpToolResult.error(it.code, it.message) },
                )
            },
            f.tool(
                "debugger.set_pretty_breakpoint", "在 pretty_print 格式化后的指定行下断点（自动映射回原始坐标，DevTools 在格式化源码中断点同款）", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "scriptId" to Schemas.strSchema("脚本 ID（须先对该 scriptId 执行 pretty_print）"),
                    "formattedLine" to Schemas.intSchema("格式化输出的行号（1-based）"),
                    "condition" to Schemas.strSchema("条件表达式（可选）"),
                ),
            ) { args ->
                val scriptId = ToolArgs.str(args, "scriptId")
                val line = ToolArgs.int(args, "formattedLine", 0)
                if (scriptId.isBlank() || line <= 0) return@tool McpToolResult.error("INVALID_ARGS", "scriptId 与有效 formattedLine 必填")
                val session = debugSession(deps)
                val condition = ToolArgs.str(args, "condition").ifBlank { null }
                deps.debuggerManager.setPrettyBreakpoint(session.engine, scriptId, line, condition).fold(
                    onSuccess = { McpToolResult.json(it) },
                    onFailure = { McpToolResult.error(it.code, it.message) },
                )
            },
            f.tool(
                "memory.heap_usage", "实时堆内存用量：JS 堆(used/total)+DOM 节点/事件监听器（DevTools Memory 面板顶栏数字同源）", ToolCategory.DEBUGGER,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = debugSession(deps)
                deps.debuggerManager.heapUsage(session.engine).fold(
                    onSuccess = { McpToolResult.json(it) },
                    onFailure = { McpToolResult.error(it.code, it.message) },
                )
            },
            f.tool(
                "memory.heap_snapshot", "导出完整 Heap Snapshot(.heapsnapshot) 到工作目录：对象图/引用链，等效 DevTools 导出的堆快照文件，可离线解析", ToolCategory.DEBUGGER,
                PermissionScope.READ_PAGE, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "path" to Schemas.strSchema("目标文件名（可选，默认 heapsnapshot-<时间戳>.heapsnapshot，存工作目录）"),
                    "timeoutSeconds" to Schemas.intSchema("快照采集超时秒数（默认 120，堆很大时可放宽）"),
                ),
                timeoutMs = 150_000,
            ) { args ->
                val name = ToolArgs.str(args, "path").ifBlank { "heapsnapshot-${System.currentTimeMillis()}.heapsnapshot" }
                val timeoutMs = ToolArgs.int(args, "timeoutSeconds", 120).toLong().coerceAtLeast(10L) * 1000L
                val file = com.webreverse.mcp.core.common.util.WorkDir.resolve(deps.browserService.appContext(), name)
                val session = debugSession(deps)
                deps.debuggerManager.takeHeapSnapshot(session.engine, file.absolutePath, timeoutMs).fold(
                    onSuccess = { McpToolResult.json(it) },
                    onFailure = { McpToolResult.error(it.code, it.message) },
                )
            },
            f.tool(
                "memory.globals", "枚举 window 顶层可枚举全局：名称+类型+取值样本（定位攻击面/隐藏全局/加密库挂载点）", ToolCategory.DEBUGGER,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "maxItems" to Schemas.intSchema("最多返回的全局数（默认 300）"),
                    "globalsPrefix" to Schemas.strSchema("仅列出该前缀的全局（如 Crypto/CJ，便于聚焦）"),
                ),
            ) { args ->
                val maxItems = ToolArgs.int(args, "maxItems", 300).coerceIn(1, 2000)
                val prefix = ToolArgs.str(args, "globalsPrefix")
                val pfxLit = prefix.replace("\\", "\\\\").replace("\"", "\\\"")
                val script = """
                  (function(){
                    var n = 0, out = [];
                    for (var k in window) {
                      if (n++ >= $maxItems) break;
                      if ($pfxLit !== '' && k.toLowerCase().indexOf('$pfxLit'.toLowerCase()) === -1) continue;
                      var v = window[k], t = typeof v, s = '';
                      if (t !== 'function') {
                        try { var j = JSON.stringify(v); s = (j == null ? '' : (j.length > 80 ? j.substring(0,80)+'...' : j)); }
                        catch(e){ s = '[unserializable]'; }
                      }
                      out.push({k:k, t:t, s:s});
                    }
                    return JSON.stringify(out);
                  })()
                """.trimIndent()
                val result = sessionForGlobals(deps)?.let { runCatching { it.evaluateJavascript(script) }.getOrNull() }
                val parsed: List<Pair<String, String>> = try {
                    kotlinx.serialization.json.Json.parseToJsonElement(result ?: "[]").jsonArray
                        .mapNotNull { it.jsonObject }
                        .map { o -> (o["k"]?.jsonPrimitive?.content ?: "?") to (o["t"]?.jsonPrimitive?.content ?: "?") }
                } catch (e: Exception) { emptyList() }
                McpToolResult.json(
                    buildJsonObject {
                        put("count", JsonPrimitive(parsed.size))
                        if (prefix.isNotBlank()) put("prefixFilter", JsonPrimitive(prefix))
                        put("globals", JsonArray(parsed.mapIndexed { idx, (k, t) ->
                            buildJsonObject { put("index", JsonPrimitive(idx)); put("name", JsonPrimitive(k)); put("type", JsonPrimitive(t)) }
                        }))
                    },
                )
            },
            f.tool(
                "memory.string_search", "在最新 Heap Snapshot(.heapsnapshot) 中全文定位字符串：命中串+引用它的节点（名称/类型/自占字节），定位内存中动态解密产物", ToolCategory.DEBUGGER,
                PermissionScope.READ_PAGE, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "query" to Schemas.strSchema("要搜索的子串（不区分大小写；可传引号片段或键名前缀）"),
                    "path" to Schemas.strSchema("快照文件路径（可选，默认取工作目录最新的 .heapsnapshot）"),
                    "limit" to Schemas.intSchema("最多返回的引用节点数（默认 50）"),
                    "timeoutSeconds" to Schemas.intSchema("未找到快照时先采集一份的取证超时（默认 60），传 0 表示不自动采集"),
                ),
                timeoutMs = 180_000,
            ) { args ->
                val query = ToolArgs.str(args, "query")
                if (query.isBlank()) return@tool McpToolResult.error("BAD_ARGS", "query 不能为空")
                val limit = ToolArgs.int(args, "limit", 50).coerceIn(1, 500)
                val pathArg = ToolArgs.str(args, "path")
                val snapTimeout = ToolArgs.int(args, "timeoutSeconds", 60)
                var file = if (pathArg.isNotBlank()) {
                    java.io.File(pathArg).takeIf { it.isFile }
                } else {
                    com.webreverse.mcp.core.common.util.WorkDir.directory(deps.browserService.appContext()).listFiles()
                        ?.filter { it.isFile && it.name.endsWith(".heapsnapshot") }
                        ?.maxByOrNull { it.lastModified() }
                }
                if (file == null && snapTimeout > 0) {
                    val name = "heapsnapshot-${System.currentTimeMillis()}.heapsnapshot"
                    val target = com.webreverse.mcp.core.common.util.WorkDir.resolve(deps.browserService.appContext(), name)
                    val session = debugSession(deps)
                    deps.debuggerManager.takeHeapSnapshot(session.engine, target.absolutePath, snapTimeout.toLong() * 1000L).getOrNull()
                    file = target.takeIf { it.isFile }
                }
                val snap = file ?: return@tool McpToolResult.error("SNAPSHOT_UNAVAILABLE", "未找到堆快照且未采集成功；请先 memory.heap_snapshot 或传 path")
                if (snap.length() > 350L * 1024 * 1024) return@tool McpToolResult.error("SNAPSHOT_TOO_LARGE", "快照过大(${snap.length()/1024/1024}MB)，超出取证上限 350MB")
                val q = query.lowercase()
                val hits = searchHeapSnapshotStrings(snap, q, limit)
                McpToolResult.json(
                    buildJsonObject {
                        put("snapshot", JsonPrimitive(snap.name))
                        put("sizeMB", JsonPrimitive(snap.length() / 1024 / 1024))
                        put("query", JsonPrimitive(query))
                        put("matchedStrings", JsonArray(hits.matchedStrings.take(40).map { JsonPrimitive(it) }))
                        put("stringHits", JsonPrimitive(hits.stringHitCount))
                        put("nodeMatches", JsonArray(hits.nodes.take(limit).map { n ->
                            buildJsonObject {
                                put("nodeIndex", JsonPrimitive(n.nodeIndex))
                                put("name", JsonPrimitive(n.name.take(120)))
                                put("type", JsonPrimitive(n.type))
                                put("selfSize", JsonPrimitive(n.selfSize))
                            }
                        }))
                        put("hint", JsonPrimitive("用 debugger.runtime_evaluate 对命中节点做 Runtime.getProperties 深化取值，可定位解密后的明文"))
                    },
                )
            },
        )
    }

    private suspend fun sessionForGlobals(deps: ToolDependencies): com.webreverse.mcp.browser.engine.BrowserEngine? =
        runCatching { debugSession(deps).engine }.getOrNull()

    /** 取证结果数据类 */
    private data class NodeTextMatch(val nodeIndex: Int, val name: String, val type: String, val selfSize: Long)
    private data class SnapshotSearchResult(
        val matchedStrings: List<String>,
        val stringHitCount: Int,
        val nodes: List<NodeTextMatch>,
    )

    /**
     * 轻量解析 .heapsnapshot（Android 同构 JSON@{snapshot,nodes,edges,strings}）：
     * 1) 在 strings 数组里找包含 query 的子串；2) 扫 nodes（前缀预算内），凡 name 索引
     * 命中的节点即"引用该字符串"，取节点类型名与 selfSize 归还——足以在内存中精确定位
     * 动态解密产物。文件大小受上层 350MB 上限约束，用 org.json 整读换取实现可靠性。
     */
    private fun searchHeapSnapshotStrings(file: java.io.File, query: String, limit: Int): SnapshotSearchResult {
        val matched = LinkedHashSet<String>()
        val hitStringIndices = HashSet<Int>()
        val root = org.json.JSONObject(file.readText(Charsets.UTF_8))
        val strings = root.optJSONArray("strings") ?: org.json.JSONArray()
        val nodes = root.optJSONArray("nodes")
        val nodeFields = runCatching {
            root.optJSONObject("snapshot").optJSONObject("meta").optJSONArray("node_fields")
        }.getOrNull()
        var nameFieldOffset = 0
        var selfFieldOffset = 1
        var stride = 6
        if (nodeFields != null && nodeFields.length() > 0) {
            val arr = (0 until nodeFields.length()).map { nodeFields.optString(it) }
            nameFieldOffset = arr.indexOf("name").coerceAtLeast(0)
            selfFieldOffset = arr.indexOf("self_size").coerceAtLeast(nameFieldOffset + 1)
            stride = nodeFields.length()
        }
        // 第一步：定位命中字符串的索引
        for (i in 0 until strings.length()) {
            val s = strings.optString(i)
            if (s.isNotEmpty() && s.length <= 512 && s.contains(query, ignoreCase = true)) {
                matched.add(s)
                hitStringIndices.add(i)
            }
        }
        // 第二步：扫节点（预算内），收集引用命中串的节点
        val nodeMatches = ArrayList<NodeTextMatch>()
        if (nodes != null && hitStringIndices.isNotEmpty()) {
            val totalNodes = nodes.length() / stride.coerceAtLeast(1)
            val scanCount = minOf(totalNodes, 2_000_000)
            for (n in 0 until scanCount) {
                val base = n * stride
                val nameIdx = nodes.optInt(base + nameFieldOffset, -1)
                if (nameIdx >= 0 && hitStringIndices.contains(nameIdx)) {
                    val selfSize = nodes.optLong(base + selfFieldOffset, 0L)
                    val typeIndex = nodes.optInt(base, 0)
                    nodeMatches.add(
                        NodeTextMatch(
                            nodeIndex = n,
                            name = strings.optString(nameIdx).take(160),
                            type = heapNodeTypeName(typeIndex),
                            selfSize = selfSize,
                        ),
                    )
                    if (nodeMatches.size >= limit) break
                }
            }
        }
        return SnapshotSearchResult(matched.toList(), matched.size, nodeMatches)
    }

    private fun heapNodeTypeName(t: Int): String = when (t) {
        0 -> "object"; 1 -> "closure"; 2 -> "array"; 3 -> "number"; 4 -> "string"
        5 -> "regexp"; 6 -> "hidden"; 7 -> "map"; 8 -> "bigint"; 9 -> "cons_string"
        10 -> "sliced_string"; 11 -> "symbol"; 12 -> "weak_cell"; 13 -> "native"
        14 -> "synthetic"; 15 -> "code"; else -> "type$t"
    }
}
