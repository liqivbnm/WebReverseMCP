package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.common.model.HookAction
import com.webreverse.mcp.core.common.model.HookMatch
import com.webreverse.mcp.core.common.model.HookType
import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** Hook Tools：规则化 Hook 与 Runtime Hook 管理 */
object HookTools {

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)
        return listOf(
            f.tool(
                "hook.list", "列出所有 Hook 规则", ToolCategory.HOOK,
                PermissionScope.INSTALL_HOOK, RiskLevel.LOW,
            ) { _ ->
                val rules = deps.hookEngine.rules.value
                McpToolResult.json(
                    buildJsonObject {
                        put(
                            "rules",
                            JsonArray(
                                rules.map { r ->
                                    buildJsonObject {
                                        put("id", JsonPrimitive(r.id))
                                        put("name", JsonPrimitive(r.name))
                                        put("type", JsonPrimitive(r.type.name))
                                        put("action", JsonPrimitive(r.action.name))
                                        put("enabled", JsonPrimitive(r.enabled))
                                        put("hitCount", JsonPrimitive(r.hitCount))
                                        put("match", JsonPrimitive(r.match.toString()))
                                    }
                                },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "hook.create", "创建 Hook 规则", ToolCategory.HOOK,
                PermissionScope.INSTALL_HOOK, RiskLevel.HIGH,
                inputSchema = Schemas.objectSchema(
                    "name" to Schemas.strSchema("规则名称"),
                    "type" to Schemas.strSchema("hook 类型"),
                    "action" to Schemas.strSchema("动作"),
                    "urlPattern" to Schemas.strSchema("URL 匹配"),
                    "hostPattern" to Schemas.strSchema("Host 匹配"),
                    "pathPattern" to Schemas.strSchema("Path 匹配"),
                    "methodPattern" to Schemas.strSchema("Method 匹配"),
                    "target" to Schemas.strSchema("目标（函数名等）"),
                    "payload" to Schemas.strSchema("载荷（Mock 响应等）"),
                ),
            ) { args ->
                val name = ToolArgs.str(args, "name", "Hook Rule")
                val type = runCatching { HookType.valueOf(ToolArgs.str(args, "type", "FETCH").uppercase()) }
                    .getOrDefault(HookType.FETCH)
                val action = runCatching { HookAction.valueOf(ToolArgs.str(args, "action", "LOG").uppercase()) }
                    .getOrDefault(HookAction.LOG)
                val match = HookMatch(
                    urlPattern = ToolArgs.optStr(args, "urlPattern"),
                    hostPattern = ToolArgs.optStr(args, "hostPattern"),
                    pathPattern = ToolArgs.optStr(args, "pathPattern"),
                    methodPattern = ToolArgs.optStr(args, "methodPattern"),
                    target = ToolArgs.optStr(args, "target"),
                )
                val payload = ToolArgs.str(args, "payload")
                val rule = deps.hookEngine.createRule(name, type, match, action, payload)
                McpToolResult.json(
                    buildJsonObject {
                        put("id", JsonPrimitive(rule.id))
                        put("name", JsonPrimitive(rule.name))
                        put("type", JsonPrimitive(rule.type.name))
                        put("action", JsonPrimitive(rule.action.name))
                    },
                )
            },
            f.tool(
                "hook.enable", "启用 Hook 规则", ToolCategory.HOOK,
                PermissionScope.INSTALL_HOOK, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema("ruleId" to Schemas.strSchema("规则 ID")),
            ) { args ->
                val ruleId = ToolArgs.str(args, "ruleId")
                deps.hookEngine.setEnabled(ruleId, true)
                McpToolResult.text("已启用规则: $ruleId")
            },
            f.tool(
                "hook.disable", "禁用 Hook 规则", ToolCategory.HOOK,
                PermissionScope.INSTALL_HOOK, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema("ruleId" to Schemas.strSchema("规则 ID")),
            ) { args ->
                val ruleId = ToolArgs.str(args, "ruleId")
                deps.hookEngine.setEnabled(ruleId, false)
                McpToolResult.text("已禁用规则: $ruleId")
            },
            f.tool(
                "hook.remove", "删除 Hook 规则", ToolCategory.HOOK,
                PermissionScope.INSTALL_HOOK, RiskLevel.HIGH,
                inputSchema = Schemas.objectSchema("ruleId" to Schemas.strSchema("规则 ID")),
            ) { args ->
                val ruleId = ToolArgs.str(args, "ruleId")
                deps.hookEngine.deleteRule(ruleId)
                McpToolResult.text("已删除规则: $ruleId")
            },
            f.tool(
                "hook.reset", "重置所有 Hook", ToolCategory.HOOK,
                PermissionScope.INSTALL_HOOK, RiskLevel.HIGH,
            ) { _ ->
                val session = deps.activeSession()
                deps.jsRuntimeHook.resetHooks(session.engine)
                deps.hookEngine.reset()
                McpToolResult.text("所有 Hook 已重置")
            },
            f.tool(
                "hook.function", "Hook 页面函数", ToolCategory.HOOK,
                PermissionScope.INSTALL_HOOK, RiskLevel.HIGH,
                inputSchema = Schemas.objectSchema(
                    "target" to Schemas.strSchema("函数名（如 window.fetch）"),
                    "callback" to Schemas.strSchema("回调 JS（可选）"),
                ),
            ) { args ->
                val target = ToolArgs.str(args, "target")
                val callback = ToolArgs.str(args, "callback", "window.__MCP__.log('hook: ' + JSON.stringify(info))")
                val session = deps.activeSession()
                val hookId = deps.jsRuntimeHook.installHook(session.engine, "function", target, callback)
                    ?: return@tool McpToolResult.error("HOOK_FAILED", "Hook 安装失败: $target")
                McpToolResult.text("已 Hook 函数: $target (id=$hookId)")
            },
            f.tool(
                "hook.method", "Hook 对象方法", ToolCategory.HOOK,
                PermissionScope.INSTALL_HOOK, RiskLevel.HIGH,
                inputSchema = Schemas.objectSchema(
                    "target" to Schemas.strSchema("对象表达式"),
                    "method" to Schemas.strSchema("方法名"),
                    "callback" to Schemas.strSchema("回调 JS（可选）"),
                ),
            ) { args ->
                val target = ToolArgs.str(args, "target")
                val method = ToolArgs.str(args, "method")
                val callback = ToolArgs.str(args, "callback", "window.__MCP__.log('hook: ' + JSON.stringify(info))")
                val session = deps.activeSession()
                val hookId = deps.jsRuntimeHook.installHook(session.engine, "method", "$target.$method", callback)
                    ?: return@tool McpToolResult.error("HOOK_FAILED", "Hook 安装失败: $target.$method（对象或方法不存在）")
                McpToolResult.text("已 Hook 方法: $target.$method (id=$hookId)")
            },
            f.tool(
                "hook.property", "Hook 对象属性", ToolCategory.HOOK,
                PermissionScope.INSTALL_HOOK, RiskLevel.HIGH,
                inputSchema = Schemas.objectSchema(
                    "target" to Schemas.strSchema("对象表达式"),
                    "property" to Schemas.strSchema("属性名"),
                    "callback" to Schemas.strSchema("回调 JS（可选）"),
                ),
            ) { args ->
                val target = ToolArgs.str(args, "target")
                val property = ToolArgs.str(args, "property")
                val callback = ToolArgs.str(args, "callback", "window.__MCP__.log('hook: ' + JSON.stringify(info))")
                val session = deps.activeSession()
                val hookId = deps.jsRuntimeHook.installHook(session.engine, "property", "$target.$property", callback)
                    ?: return@tool McpToolResult.error("HOOK_FAILED", "Hook 安装失败: $target.$property（对象或属性不存在）")
                McpToolResult.text("已 Hook 属性: $target.$property (id=$hookId)")
            },
            f.tool(
                "hook.fetch", "Hook window.fetch", ToolCategory.HOOK,
                PermissionScope.INSTALL_HOOK, RiskLevel.HIGH,
                inputSchema = Schemas.objectSchema("callback" to Schemas.strSchema("回调 JS（可选）")),
            ) { args ->
                val callback = ToolArgs.str(args, "callback", "window.__MCP__.log('fetch: ' + JSON.stringify(info))")
                val session = deps.activeSession()
                val hookId = deps.jsRuntimeHook.installHook(session.engine, "fetch", "", callback)
                    ?: return@tool McpToolResult.error("HOOK_FAILED", "Fetch Hook 安装失败")
                McpToolResult.text("已 Hook fetch (id=$hookId)")
            },
            f.tool(
                "hook.xhr", "Hook XMLHttpRequest", ToolCategory.HOOK,
                PermissionScope.INSTALL_HOOK, RiskLevel.HIGH,
                inputSchema = Schemas.objectSchema("callback" to Schemas.strSchema("回调 JS（可选）")),
            ) { args ->
                val callback = ToolArgs.str(args, "callback", "window.__MCP__.log('xhr: ' + JSON.stringify(info))")
                val session = deps.activeSession()
                val hookId = deps.jsRuntimeHook.installHook(session.engine, "xhr", "", callback)
                    ?: return@tool McpToolResult.error("HOOK_FAILED", "XHR Hook 安装失败")
                McpToolResult.text("已 Hook XHR (id=$hookId)")
            },
            f.tool(
                "hook.websocket", "Hook WebSocket", ToolCategory.HOOK,
                PermissionScope.INSTALL_HOOK, RiskLevel.HIGH,
                inputSchema = Schemas.objectSchema("callback" to Schemas.strSchema("回调 JS（可选）")),
            ) { args ->
                val callback = ToolArgs.str(args, "callback", "window.__MCP__.log('ws: ' + JSON.stringify(info))")
                val session = deps.activeSession()
                val hookId = deps.jsRuntimeHook.installHook(session.engine, "websocket", "", callback)
                    ?: return@tool McpToolResult.error("HOOK_FAILED", "WebSocket Hook 安装失败")
                McpToolResult.text("已 Hook WebSocket (id=$hookId)")
            },
            f.tool(
                "hook.storage", "Hook Storage API", ToolCategory.HOOK,
                PermissionScope.INSTALL_HOOK, RiskLevel.HIGH,
                inputSchema = Schemas.objectSchema("callback" to Schemas.strSchema("回调 JS（可选）")),
            ) { args ->
                val callback = ToolArgs.str(args, "callback", "window.__MCP__.log('storage: ' + JSON.stringify(info))")
                val session = deps.activeSession()
                val hookId = deps.jsRuntimeHook.installHook(session.engine, "storage", "", callback)
                    ?: return@tool McpToolResult.error("HOOK_FAILED", "Storage Hook 安装失败")
                McpToolResult.text("已 Hook Storage (id=$hookId)")
            },
            f.tool(
                "hook.event", "Hook DOM 事件", ToolCategory.HOOK,
                PermissionScope.INSTALL_HOOK, RiskLevel.HIGH,
                inputSchema = Schemas.objectSchema(
                    "selector" to Schemas.strSchema("CSS 选择器"),
                    "eventType" to Schemas.strSchema("事件类型"),
                    "callback" to Schemas.strSchema("回调 JS（可选）"),
                ),
            ) { args ->
                val selector = ToolArgs.str(args, "selector")
                val eventType = ToolArgs.str(args, "eventType", "click")
                val callback = ToolArgs.str(args, "callback", "window.__MCP__.log('event: ' + JSON.stringify(info))")
                val session = deps.activeSession()
                val hookId = deps.jsRuntimeHook.installEventHook(session.engine, selector, eventType, callback)
                    ?: return@tool McpToolResult.error("HOOK_FAILED", "事件 Hook 安装失败: $selector")
                McpToolResult.text("已 Hook 事件: $selector $eventType (id=$hookId)")
            },
            f.tool(
                "hook.timer", "Hook 定时器", ToolCategory.HOOK,
                PermissionScope.INSTALL_HOOK, RiskLevel.HIGH,
                inputSchema = Schemas.objectSchema("callback" to Schemas.strSchema("回调 JS（可选）")),
            ) { args ->
                val callback = ToolArgs.str(args, "callback", "window.__MCP__.log('timer: ' + JSON.stringify(info))")
                val session = deps.activeSession()
                val hookId = deps.jsRuntimeHook.installHook(session.engine, "timer", "", callback)
                    ?: return@tool McpToolResult.error("HOOK_FAILED", "Timer Hook 安装失败")
                McpToolResult.text("已 Hook Timer (id=$hookId)")
            },
            f.tool(
                "hook.console", "Hook console API", ToolCategory.HOOK,
                PermissionScope.INSTALL_HOOK, RiskLevel.HIGH,
                inputSchema = Schemas.objectSchema("callback" to Schemas.strSchema("回调 JS（可选）")),
            ) { args ->
                val callback = ToolArgs.str(args, "callback", "window.__MCP__.log('console: ' + JSON.stringify(info))")
                val session = deps.activeSession()
                val hookId = deps.jsRuntimeHook.installHook(session.engine, "console", "", callback)
                    ?: return@tool McpToolResult.error("HOOK_FAILED", "Console Hook 安装失败")
                McpToolResult.text("已 Hook Console (id=$hookId)")
            },
            f.tool(
                "hook.crypto", "Hook Crypto API", ToolCategory.HOOK,
                PermissionScope.INSTALL_HOOK, RiskLevel.HIGH,
                inputSchema = Schemas.objectSchema("callback" to Schemas.strSchema("回调 JS（可选）")),
            ) { args ->
                val callback = ToolArgs.str(args, "callback", "window.__MCP__.log('crypto: ' + JSON.stringify(info))")
                val session = deps.activeSession()
                val hookId = deps.jsRuntimeHook.installHook(session.engine, "crypto", "", callback)
                    ?: return@tool McpToolResult.error("HOOK_FAILED", "Crypto Hook 安装失败")
                McpToolResult.text("已 Hook Crypto (id=$hookId)")
            },
            f.tool(
                "hook.dom", "Hook DOM 变更（MutationObserver）", ToolCategory.HOOK,
                PermissionScope.INSTALL_HOOK, RiskLevel.HIGH,
                inputSchema = Schemas.objectSchema("callback" to Schemas.strSchema("回调 JS（可选）")),
            ) { args ->
                val callback = ToolArgs.str(args, "callback", "window.__MCP__.log('dom: ' + JSON.stringify(info))")
                val session = deps.activeSession()
                val script = """
                    (function(){
                      if (window.__WRMCP_MUTATION__) return 'already';
                      var observer = new MutationObserver(function(mutations){
                        try { $callback } catch(e){}
                      });
                      observer.observe(document.documentElement, {childList:true, subtree:true, attributes:true, characterData:true});
                      window.__WRMCP_MUTATION__ = observer;
                      return 'installed';
                    })()
                """.trimIndent()
                session.engine.evaluateJavascript(script)
                McpToolResult.text("已安装 DOM Mutation Observer")
            },
            f.tool(
                "hook.export", "导出 Hook 规则", ToolCategory.HOOK,
                PermissionScope.INSTALL_HOOK, RiskLevel.LOW,
            ) { _ ->
                McpToolResult.text(deps.hookEngine.export())
            },
            f.tool(
                "hook.import", "导入 Hook 规则", ToolCategory.HOOK,
                PermissionScope.INSTALL_HOOK, RiskLevel.HIGH,
                inputSchema = Schemas.objectSchema("rules" to Schemas.strSchema("Hook 规则 JSON")),
            ) { args ->
                val rules = ToolArgs.str(args, "rules")
                val count = deps.hookEngine.import(rules)
                McpToolResult.text("已导入 $count 条 Hook 规则")
            },
            f.tool(
                "hook.events", "列出 Hook 触发记录", ToolCategory.HOOK,
                PermissionScope.INSTALL_HOOK, RiskLevel.LOW,
            ) { _ ->
                val events = deps.hookEngine.events.value
                McpToolResult.json(
                    buildJsonObject {
                        put(
                            "events",
                            JsonArray(
                                events.take(200).map { e ->
                                    buildJsonObject {
                                        put("ruleName", JsonPrimitive(e.ruleName))
                                        put("type", JsonPrimitive(e.type.name))
                                        put("target", JsonPrimitive(e.target))
                                        put("redacted", JsonPrimitive(e.redacted))
                                        put("timestamp", JsonPrimitive(e.timestamp))
                                    }
                                },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "hook.runtime_list", "列出运行时已安装 Hook", ToolCategory.HOOK,
                PermissionScope.INSTALL_HOOK, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val result = deps.jsRuntimeHook.listHooks(session.engine) ?: "[]"
                McpToolResult.text(result)
            },
            f.tool(
                "hook.runtime_remove", "移除运行时 Hook", ToolCategory.HOOK,
                PermissionScope.INSTALL_HOOK, RiskLevel.HIGH,
                inputSchema = Schemas.objectSchema("hookId" to Schemas.strSchema("Hook ID")),
            ) { args ->
                val hookId = ToolArgs.str(args, "hookId")
                val session = deps.activeSession()
                val ok = deps.jsRuntimeHook.removeHook(session.engine, hookId)
                McpToolResult.text(if (ok) "已移除 Hook: $hookId" else "移除失败")
            },
        )
    }
}
