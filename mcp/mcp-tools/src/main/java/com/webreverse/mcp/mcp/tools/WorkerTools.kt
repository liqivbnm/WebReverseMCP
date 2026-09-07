package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** Worker Tools：Service Worker / Web Worker 分析 */
object WorkerTools {

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)
        return listOf(
            f.tool(
                "worker.list", "列出页面所有 Worker", ToolCategory.WORKER,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val result = session.engine.evaluateJavascript(
                    """
                    (function(){
                      var out = {serviceWorkerSupported: 'serviceWorker' in navigator};
                      out.workerTypes = [];
                      if ('serviceWorker' in navigator) {
                        out.workerTypes.push('service-worker');
                      }
                      if (window.Worker) out.workerTypes.push('dedicated-worker');
                      if (window.SharedWorker) out.workerTypes.push('shared-worker');
                      return JSON.stringify(out);
                    })()
                    """.trimIndent()
                ) ?: "{}"
                McpToolResult.text(result)
            },
            f.tool(
                "worker.inspect", "检查 Service Worker 状态", ToolCategory.WORKER,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("scope" to Schemas.strSchema("SW 作用域")),
            ) { args ->
                val scope = ToolArgs.str(args, "scope", "/")
                val session = deps.activeSession()
                val result = session.engine.evaluateJavascript(
                    """
                    (function(){
                      if (!('serviceWorker' in navigator)) return JSON.stringify({error: 'not supported'});
                      return navigator.serviceWorker.getRegistrations().then(function(regs){
                        var out = [];
                        regs.forEach(function(reg){
                          out.push({
                            scope: reg.scope,
                            active: reg.active ? reg.active.scriptURL : null,
                            installing: reg.installing ? reg.installing.scriptURL : null,
                            waiting: reg.waiting ? reg.waiting.scriptURL : null
                          });
                        });
                        return JSON.stringify(out);
                      }).catch(function(e){ return JSON.stringify({error: e.message}); });
                    })()
                    """.trimIndent()
                ) ?: "{}"
                McpToolResult.text(result)
            },
            f.tool(
                "worker.evaluate", "在 Worker 上下文执行（受限）", ToolCategory.WORKER,
                PermissionScope.EXECUTE_JS, RiskLevel.HIGH,
                inputSchema = Schemas.objectSchema("expression" to Schemas.strSchema("JS 表达式")),
            ) { args ->
                val expression = ToolArgs.str(args, "expression")
                val session = deps.activeSession()
                val result = deps.consoleManager.evaluate(session.engine, expression)
                result.fold(
                    onSuccess = { McpToolResult.text(it) },
                    onFailure = { McpToolResult.error("JS_EXECUTION_FAILED", it.message) },
                )
            },
            f.tool(
                "worker.network", "获取 Worker 相关网络请求", ToolCategory.WORKER,
                PermissionScope.READ_NETWORK, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val entries = deps.networkInspector.getEntries(session.engine)
                    .filter { it.fromServiceWorker }
                McpToolResult.json(
                    buildJsonObject {
                        put(
                            "entries",
                            JsonArray(
                                entries.take(100).map { e ->
                                    buildJsonObject {
                                        put("url", JsonPrimitive(e.url))
                                        put("method", JsonPrimitive(e.method.wire))
                                        put("status", JsonPrimitive(e.status))
                                    }
                                },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "worker.sources", "获取 Worker 脚本源码", ToolCategory.WORKER,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("scope" to Schemas.strSchema("SW 作用域")),
            ) { args ->
                val scope = ToolArgs.str(args, "scope", "/")
                val session = deps.activeSession()
                val result = session.engine.evaluateJavascript(
                    """
                    (function(){
                      if (!('serviceWorker' in navigator)) return JSON.stringify({error: 'not supported'});
                      return navigator.serviceWorker.getRegistrations().then(function(regs){
                        var out = [];
                        regs.forEach(function(reg){
                          if (reg.active) out.push({scope: reg.scope, scriptURL: reg.active.scriptURL});
                        });
                        return JSON.stringify(out);
                      }).catch(function(e){ return JSON.stringify({error: e.message}); });
                    })()
                    """.trimIndent()
                ) ?: "{}"
                McpToolResult.text(result)
            },
        )
    }
}
