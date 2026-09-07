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

/** Performance Tools：性能分析 */
object PerformanceTools {

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)
        return listOf(
            f.tool(
                "performance.navigation_timing", "获取导航时序", ToolCategory.PERFORMANCE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val result = deps.performanceAnalyzer.getNavigationTiming(session.engine)
                result.fold(
                    onSuccess = { t ->
                        McpToolResult.json(
                            buildJsonObject {
                                put("domContentLoaded", JsonPrimitive(t.domContentLoaded))
                                put("loadEvent", JsonPrimitive(t.loadEvent))
                                put("firstPaint", JsonPrimitive(t.firstPaint))
                                put("firstContentfulPaint", JsonPrimitive(t.firstContentfulPaint))
                            },
                        )
                    },
                    onFailure = { McpToolResult.error("PERF_UNAVAILABLE", it.message) },
                )
            },
            f.tool(
                "performance.resource_timing", "获取资源时序", ToolCategory.PERFORMANCE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val result = deps.performanceAnalyzer.getResourceTiming(session.engine)
                result.fold(
                    onSuccess = { r ->
                        McpToolResult.json(
                            buildJsonObject {
                                put("count", JsonPrimitive(r.size))
                                put(
                                    "resources",
                                    JsonArray(
                                        r.take(200).map { res ->
                                            buildJsonObject {
                                                put("name", JsonPrimitive(res.name))
                                                put("duration", JsonPrimitive(res.duration))
                                                put("initiatorType", JsonPrimitive(res.initiatorType))
                                            }
                                        },
                                    ),
                                )
                            },
                        )
                    },
                    onFailure = { McpToolResult.error("PERF_UNAVAILABLE", it.message) },
                )
            },
            f.tool(
                "performance.paint_timing", "获取绘制时序", ToolCategory.PERFORMANCE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val result = session.engine.evaluateJavascript(
                    "(function(){var out={};if(window.performance&&performance.getEntriesByType){performance.getEntriesByType('paint').forEach(function(e){out[e.name]=e.startTime})}return JSON.stringify(out)})()"
                ) ?: "{}"
                McpToolResult.text(result)
            },
            f.tool(
                "performance.long_tasks", "获取长任务列表", ToolCategory.PERFORMANCE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                // 根因：现代 Chrome/WebView（Chrome 111+，本测试环境为 Android 16 /
                // Chrome 150）已用 Long Animation Frames API 记录长帧，页面
                // performance.getEntries() 的 entryType 里只有 'long-animation-frame'、
                // 没有 legacy 'longtask'，旧实现只 observe 'longtask' 故恒返回 []。
                // 现同时注册 LoAF 与 legacy 两个观察器，合并去重；返回 Promise 以便
                // evaluateJavascriptAsync 的落盘通道等到 buffered 回调结算后再取回。
                val result = session.engine.evaluateJavascriptAsync(
                    """
                    return new Promise(function(resolve){
                      var buffered = [];
                      var seen = {};
                      var push = function(e){
                        try {
                          var rec = {duration: Math.round(e.duration), start: Math.round(e.startTime), name: e.name || e.entryType || 'longtask'};
                          var key = rec.start + ':' + rec.duration + ':' + rec.name;
                          if (!seen[key]) { seen[key] = 1; buffered.push(rec); }
                        } catch(err){}
                      };
                      var collect = function(list){
                        var es = (list && list.getEntries) ? list.getEntries() : (list || []);
                        for (var i = 0; i < es.length; i++) push(es[i]);
                      };
                      var obsLoaf = null, obsLegacy = null;
                      var wait = 180; // 给 buffered 回调预留的结算时间
                      if (window.PerformanceObserver) {
                        try {
                          obsLoaf = new PerformanceObserver(function(list){ collect(list); });
                          obsLoaf.observe({type: 'long-animation-frame', buffered: true});
                        } catch(e){}
                        try {
                          obsLegacy = new PerformanceObserver(function(list){ collect(list); });
                          obsLegacy.observe({entryTypes: ['longtask'], buffered: true});
                        } catch(e2){}
                      }
                      // 立即读 buffered timeline 兜底
                      try { collect(performance.getEntriesByType('long-animation-frame')); } catch(e3){}
                      try { collect(performance.getEntriesByType('longtask')); } catch(e4){}
                      setTimeout(function(){
                        if (obsLoaf) { try { obsLoaf.disconnect(); } catch(e){} }
                        if (obsLegacy) { try { obsLegacy.disconnect(); } catch(e2){} }
                        buffered.sort(function(a,b){ return a.start - b.start; });
                        resolve(JSON.stringify(buffered.slice(-200)));
                      }, wait);
                    });
                    """.trimIndent()
                ) ?: "[]"
                McpToolResult.text(result)
            },
            f.tool(
                "performance.memory", "获取 JS 堆内存", ToolCategory.PERFORMANCE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val result = deps.performanceAnalyzer.getMemory(session.engine)
                result.fold(
                    onSuccess = { m ->
                        McpToolResult.json(
                            buildJsonObject {
                                put("usedJSHeapSize", JsonPrimitive(m.usedJSHeapSize))
                                put("totalJSHeapSize", JsonPrimitive(m.totalJSHeapSize))
                                put("jsHeapSizeLimit", JsonPrimitive(m.jsHeapSizeLimit))
                            },
                        )
                    },
                    onFailure = { McpToolResult.error("PERF_UNAVAILABLE", it.message) },
                )
            },
            f.tool(
                "performance.fps", "测量页面 FPS", ToolCategory.PERFORMANCE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                // 原实现用同步 evaluateJavascript 执行返回 Promise 的脚本，引擎同步路径不会等待
                // Promise（ 已知），导致恒返回空 {}。改用 evaluateJavascriptAsync 走
                // 落盘+轮询通道，才拿得到 rAF 采样结算的 fps。
                val result = session.engine.evaluateJavascriptAsync(
                    """
                    return new Promise(function(resolve){
                      var frames = 0;
                      var start = performance.now();
                      var duration = 1000;
                      function tick(){
                        frames++;
                        var now = performance.now();
                        if (now - start < duration) { requestAnimationFrame(tick); }
                        else {
                          var fps = Math.round(frames * 1000 / (now - start));
                          resolve(JSON.stringify({fps: fps, frames: frames, duration: Math.round(now - start)}));
                        }
                      }
                      requestAnimationFrame(tick);
                    });
                    """.trimIndent()
                ) ?: "{}"
                McpToolResult.text(result)
            },
            f.tool(
                "performance.waterfall", "获取网络瀑布图数据", ToolCategory.PERFORMANCE,
                PermissionScope.READ_NETWORK, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val entries = deps.networkInspector.getEntries(session.engine)
                McpToolResult.json(
                    buildJsonObject {
                        put(
                            "waterfall",
                            JsonArray(
                                entries.take(200).map { e ->
                                    buildJsonObject {
                                        put("url", JsonPrimitive(e.url))
                                        put("startedAt", JsonPrimitive(e.startedAt))
                                        put("endedAt", JsonPrimitive(e.endedAt))
                                        put("duration", JsonPrimitive(e.durationMs))
                                        put("status", JsonPrimitive(e.status))
                                    }
                                },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "performance.report", "生成性能分析报告", ToolCategory.PERFORMANCE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val timing = deps.performanceAnalyzer.getNavigationTiming(session.engine).getOrNull()
                val memory = deps.performanceAnalyzer.getMemory(session.engine).getOrNull()
                val entries = deps.networkInspector.getEntries(session.engine)
                val sb = StringBuilder()
                sb.appendLine("# 性能分析报告")
                sb.appendLine()
                sb.appendLine("## 导航时序")
                timing?.let { t ->
                    sb.appendLine("- DOMContentLoaded: ${t.domContentLoaded}ms")
                    sb.appendLine("- LoadEvent: ${t.loadEvent}ms")
                    sb.appendLine("- FirstPaint: ${t.firstPaint}ms")
                    sb.appendLine("- FirstContentfulPaint: ${t.firstContentfulPaint}ms")
                }
                sb.appendLine()
                sb.appendLine("## 内存")
                memory?.let { m ->
                    sb.appendLine("- Used JS Heap: ${m.usedJSHeapSize / 1024 / 1024}MB")
                    sb.appendLine("- Total JS Heap: ${m.totalJSHeapSize / 1024 / 1024}MB")
                }
                sb.appendLine()
                sb.appendLine("## 网络")
                sb.appendLine("- 请求总数: ${entries.size}")
                val totalBytes = entries.sumOf { it.responseBodySize }
                sb.appendLine("- 总传输量: ${totalBytes / 1024}KB")
                val slowest = entries.maxByOrNull { it.endedAt - it.startedAt }
                slowest?.let { s ->
                    sb.appendLine("- 最慢请求: ${s.url} (${s.endedAt - s.startedAt}ms)")
                }
                McpToolResult.text(sb.toString())
            },
        )
    }
}
