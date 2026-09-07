package com.webreverse.mcp.devtools.performance

import com.webreverse.mcp.browser.engine.BrowserEngine
import com.webreverse.mcp.core.common.util.AppError
import com.webreverse.mcp.core.common.util.AppResult
import com.webreverse.mcp.devtools.protocol.MemoryInfo
import com.webreverse.mcp.devtools.protocol.PerformanceTiming
import com.webreverse.mcp.devtools.protocol.ResourceTiming
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject

/** 性能分析器：Navigation Timing / Resource Timing / Memory / FPS */
class PerformanceAnalyzer {

    private val json = Json { ignoreUnknownKeys = true }

    /**
     * 剥离 WebView 对 JS 字符串返回值额外包裹的一层 JSON 引号。
     * WebView.evaluateJavascript 的回调返回值是"JS 返回值再 JSON 序列化一次"的结果：
     * JS 执行 JSON.stringify(obj) 得到字符串 {"a":1}，WebView 回调给 Kotlin 的却是
     * "{\"a\":1}"（整体带引号）。直接解析会报
     * "Expected start of the object '{', but had '\"' instead"。
     * 通过标准 JSON 反序列化取出字符串真实内容（转义自动还原）。
     */
    private fun unquote(raw: String?): String? {
        if (raw == null) return null
        val trimmed = raw.trim()
        if (!trimmed.startsWith("\"")) return trimmed
        return try {
            (Json.parseToJsonElement(trimmed) as? JsonPrimitive)?.content ?: trimmed
        } catch (e: Exception) {
            trimmed
        }
    }

    suspend fun getNavigationTiming(engine: BrowserEngine): AppResult<PerformanceTiming> {
        val script = """
            (function(){
              // 注意：navigation/paint 各条目的 startTime 是浮点毫秒，直接返回 JSON 会被
              // PerformanceTiming(Long 字段) 反序列化时报 "Unexpected symbol '.' in numeric literal"，
              // 故整型字段统一 Math.round 取整，与 getResourceTiming 的做法保持一致。
              var p = performance.getEntriesByType('navigation')[0] || {};
              var nav = performance.timing || {};
              var R = function(x){ return typeof x === 'number' ? Math.round(x) : 0; };
              return JSON.stringify({
                navigationStart: R(nav.navigationStart || 0),
                domContentLoaded: R(p.domContentLoadedEventEnd || nav.domContentLoadedEventEnd - nav.navigationStart || 0),
                loadEvent: R(p.loadEventEnd || nav.loadEventEnd - nav.navigationStart || 0),
                firstPaint: (function(){ var e = performance.getEntriesByType('paint'); return e.length ? Math.round(e[0].startTime) : 0; })(),
                firstContentfulPaint: (function(){ var e = performance.getEntriesByType('paint'); for (var i=0;i<e.length;i++){ if (e[i].name === 'first-contentful-paint') return Math.round(e[i].startTime); } return 0; })(),
                domInteractive: R(p.domInteractive || nav.domInteractive - nav.navigationStart || 0),
                domComplete: R(p.domComplete || nav.domComplete - nav.navigationStart || 0),
                redirectCount: R(p.redirectCount || 0),
                transferSize: R(p.transferSize || 0)
              });
            })()
        """.trimIndent()
        val result = unquote(engine.evaluateJavascript(script))
            ?: return AppResult.failure(AppError.JS_EXECUTION_FAILED)
        return try {
            AppResult.success(json.decodeFromString(PerformanceTiming.serializer(), result))
        } catch (e: Exception) {
            AppResult.failure(AppError("PERF_PARSE_ERROR", e.message.orEmpty()))
        }
    }

    suspend fun getResourceTiming(engine: BrowserEngine): AppResult<List<ResourceTiming>> {
        val script = """
            (function(){
              var out = performance.getEntriesByType('resource').slice(0, 500).map(function(e){
                return {name: e.name, initiatorType: e.initiatorType, duration: Math.round(e.duration), transferSize: e.transferSize || 0, startTime: Math.round(e.startTime)};
              });
              return JSON.stringify(out);
            })()
        """.trimIndent()
        val result = unquote(engine.evaluateJavascript(script))
            ?: return AppResult.failure(AppError.JS_EXECUTION_FAILED)
        return try {
            AppResult.success(json.decodeFromString(kotlinx.serialization.builtins.ListSerializer(ResourceTiming.serializer()), result))
        } catch (e: Exception) {
            AppResult.failure(AppError("PERF_PARSE_ERROR", e.message.orEmpty()))
        }
    }

    suspend fun getMemory(engine: BrowserEngine): AppResult<MemoryInfo> {
        val script = """
            (function(){
              var m = performance.memory || {};
              return JSON.stringify({usedJSHeapSize: m.usedJSHeapSize || 0, totalJSHeapSize: m.totalJSHeapSize || 0, jsHeapSizeLimit: m.jsHeapSizeLimit || 0});
            })()
        """.trimIndent()
        val result = unquote(engine.evaluateJavascript(script))
            ?: return AppResult.failure(AppError.JS_EXECUTION_FAILED)
        return try {
            AppResult.success(json.decodeFromString(MemoryInfo.serializer(), result))
        } catch (e: Exception) {
            AppResult.failure(AppError("PERF_PARSE_ERROR", e.message.orEmpty()))
        }
    }

    suspend fun getLongTasks(engine: BrowserEngine): AppResult<List<Map<String, Any>>> {
        val script = """
            (function(){
              var out = performance.getEntriesByType('longtask').slice(0, 100).map(function(e){
                return {name: e.name, duration: Math.round(e.duration), startTime: Math.round(e.startTime)};
              });
              return JSON.stringify(out);
            })()
        """.trimIndent()
        val result = unquote(engine.evaluateJavascript(script))
            ?: return AppResult.failure(AppError.JS_EXECUTION_FAILED)
        return try {
            val element = Json.parseToJsonElement(result)
            val list = if (element is kotlinx.serialization.json.JsonArray) {
                element.map { obj ->
                    val o = obj.jsonObject
                    mapOf(
                        "name" to (o["name"]?.toString()?.trim('"') ?: ""),
                        "duration" to (o["duration"]?.toString() ?: "0"),
                        "startTime" to (o["startTime"]?.toString() ?: "0"),
                    )
                }
            } else emptyList()
            AppResult.success(list)
        } catch (e: Exception) {
            AppResult.failure(AppError("PERF_PARSE_ERROR", e.message.orEmpty()))
        }
    }

    suspend fun getFps(engine: BrowserEngine): AppResult<Map<String, Any>> {
        val script = """
            (function(){
              return new Promise(function(resolve){
                var frames = 0;
                var start = performance.now();
                function tick(){
                  frames++;
                  if (performance.now() - start < 1000) {
                    requestAnimationFrame(tick);
                  } else {
                    var fps = Math.round(frames * 1000 / (performance.now() - start));
                    resolve(JSON.stringify({fps: fps, frames: frames, duration: Math.round(performance.now() - start)}));
                  }
                }
                requestAnimationFrame(tick);
              });
            })()
        """.trimIndent()
        val result = unquote(engine.evaluateJavascriptAsync(script))
            ?: return AppResult.failure(AppError.JS_EXECUTION_FAILED)
        return try {
            val element = Json.parseToJsonElement(result)
            val map = if (element is kotlinx.serialization.json.JsonObject) element.mapValues { it.value.toString().trim('"') } else emptyMap()
            AppResult.success(map)
        } catch (e: Exception) {
            AppResult.failure(AppError("PERF_PARSE_ERROR", e.message.orEmpty()))
        }
    }

    suspend fun generateReport(engine: BrowserEngine): AppResult<String> {
        val timing = getNavigationTiming(engine).getOrNull()
        val resources = getResourceTiming(engine).getOrNull() ?: emptyList()
        val memory = getMemory(engine).getOrNull()
        val sb = StringBuilder()
        sb.appendLine("# Performance Report")
        sb.appendLine()
        sb.appendLine("## Navigation Timing")
        timing?.let {
            sb.appendLine("- DOM Content Loaded: ${it.domContentLoaded}ms")
            sb.appendLine("- Load Event: ${it.loadEvent}ms")
            sb.appendLine("- First Paint: ${it.firstPaint}ms")
            sb.appendLine("- First Contentful Paint: ${it.firstContentfulPaint}ms")
            sb.appendLine("- Redirect Count: ${it.redirectCount}")
        }
        sb.appendLine()
        sb.appendLine("## Resources (${resources.size})")
        resources.groupBy { it.initiatorType }.forEach { (type, items) ->
            sb.appendLine("- $type: ${items.size} requests, total ${items.sumOf { it.transferSize }} bytes")
        }
        sb.appendLine()
        memory?.let {
            sb.appendLine("## Memory")
            sb.appendLine("- Used JS Heap: ${it.usedJSHeapSize / 1024 / 1024} MB")
            sb.appendLine("- Total JS Heap: ${it.totalJSHeapSize / 1024 / 1024} MB")
        }
        return AppResult.success(sb.toString())
    }
}
