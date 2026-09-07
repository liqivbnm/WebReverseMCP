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

/** Frame Tools：iframe / 子框架分析 */
object FrameTools {

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)
        return listOf(
            f.tool(
                "frame.list", "列出页面所有 Frame（含 iframe）", ToolCategory.FRAME,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val result = session.engine.evaluateJavascript(
                    """
                    (function(){
                      var out = [];
                      function walk(win, depth) {
                        out.push({depth: depth, href: win.location.href, name: win.name || '', frames: win.frames.length});
                        for (var i=0; i<win.frames.length; i++) {
                          try { walk(win.frames[i], depth+1); } catch(e) { out.push({depth: depth+1, href: '(cross-origin)', name: '', frames: 0}); }
                        }
                      }
                      walk(window, 0);
                      return JSON.stringify(out);
                    })()
                    """.trimIndent()
                ) ?: "[]"
                McpToolResult.text(result)
            },
            f.tool(
                "frame.select", "选择要操作的 Frame", ToolCategory.FRAME,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "frameId" to Schemas.strSchema("Frame ID（0 为主框架）"),
                    "selector" to Schemas.strSchema("iframe 选择器"),
                ),
            ) { args ->
                val frameId = ToolArgs.str(args, "frameId", "0")
                val selector = ToolArgs.optStr(args, "selector")
                McpToolResult.text("已选择 Frame: $frameId" + (selector?.let { " (selector=$it)" } ?: ""))
            },
            f.tool(
                "frame.evaluate", "在指定 Frame 中执行 JS", ToolCategory.FRAME,
                PermissionScope.EXECUTE_JS, RiskLevel.HIGH,
                inputSchema = Schemas.objectSchema(
                    "frameId" to Schemas.strSchema("Frame ID"),
                    "expression" to Schemas.strSchema("JS 表达式"),
                ),
            ) { args ->
                val frameId = ToolArgs.str(args, "frameId", "0")
                val expression = ToolArgs.str(args, "expression")
                val session = deps.activeSession()
                val script = """
                    (function(){
                      function getFrame(id) {
                        if (id === '0') return window;
                        var parts = id.split('.').map(Number);
                        var w = window;
                        for (var i=0; i<parts.length; i++) { try { w = w.frames[parts[i]]; } catch(e) { return null; } }
                        return w;
                      }
                      var target = getFrame('$frameId');
                      if (!target) return JSON.stringify({error: 'frame not found'});
                      try { return JSON.stringify({result: target.eval(${JsQuote(expression)})}); }
                      catch(e) { return JSON.stringify({error: e.message}); }
                    })()
                """.trimIndent()
                val result = session.engine.evaluateJavascript(script) ?: "{}"
                McpToolResult.text(result)
            },
            f.tool(
                "frame.dom", "获取指定 Frame 的 DOM", ToolCategory.FRAME,
                PermissionScope.READ_DOM, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "frameId" to Schemas.strSchema("Frame ID"),
                    "selector" to Schemas.strSchema("CSS 选择器"),
                ),
            ) { args ->
                val frameId = ToolArgs.str(args, "frameId", "0")
                val selector = ToolArgs.str(args, "selector", "body")
                val session = deps.activeSession()
                val script = """
                    (function(){
                      function getFrame(id) {
                        if (id === '0') return window;
                        var parts = id.split('.').map(Number);
                        var w = window;
                        for (var i=0; i<parts.length; i++) { try { w = w.frames[parts[i]]; } catch(e) { return null; } }
                        return w;
                      }
                      var target = getFrame('$frameId');
                      if (!target) return JSON.stringify({error: 'frame not found'});
                      try {
                        var el = target.document.querySelector(${JsQuote(selector)});
                        return JSON.stringify({html: el ? el.outerHTML.substring(0, 50000) : null});
                      } catch(e) { return JSON.stringify({error: e.message}); }
                    })()
                """.trimIndent()
                val result = session.engine.evaluateJavascript(script) ?: "{}"
                McpToolResult.text(result)
            },
            f.tool(
                "frame.network", "获取指定 Frame 的网络请求", ToolCategory.FRAME,
                PermissionScope.READ_NETWORK, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("frameId" to Schemas.strSchema("Frame ID")),
            ) { args ->
                val frameId = ToolArgs.str(args, "frameId", "0")
                val session = deps.activeSession()
                val entries = deps.networkInspector.getEntries(session.engine)
                McpToolResult.json(
                    buildJsonObject {
                        put("frameId", JsonPrimitive(frameId))
                        put("count", JsonPrimitive(entries.size))
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
                "frame.debug", "在指定 Frame 中设置断点", ToolCategory.FRAME,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "frameId" to Schemas.strSchema("Frame ID"),
                    "url" to Schemas.strSchema("源码 URL"),
                    "line" to Schemas.intSchema("行号"),
                ),
            ) { args ->
                val frameId = ToolArgs.str(args, "frameId", "0")
                val url = ToolArgs.str(args, "url")
                val line = ToolArgs.int(args, "line")
                val session = deps.activeSession()
                val result = deps.debuggerManager.setBreakpoint(
                    session.engine,
                    com.webreverse.mcp.core.common.model.BreakpointType.LINE,
                    url,
                    line,
                )
                result.fold(
                    onSuccess = { bp -> McpToolResult.text("已在 Frame $frameId 设置断点: ${bp.id}") },
                    onFailure = { McpToolResult.error("DEBUGGER_UNAVAILABLE", it.message) },
                )
            },
        )
    }

    private fun JsQuote(s: String): String =
        "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + "\""
}
