package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import com.webreverse.mcp.javascript.runtime.DynamicTracer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put

/**
 * 动态调试工具链 v1（ 新增）。
 *
 * 与断点（暂停式调试）互补的运行时观测层——不断页面、零干扰采集：
 * - dynamic.trace_function：包装目标函数，记录每次调用的参数/返回值/耗时/堆栈
 *   （签名/加密函数的输入输出分析首选）
 * - dynamic.monitor_object：Proxy 监控对象属性读写（带堆栈，「数据被谁改了」）
 * - dynamic.profile_object：批量剖析对象方法的调用数/总耗时（定位加密热点）
 * - dynamic.collect_trace：取回 trace 时间线（支持过滤）
 * - dynamic.clear_trace：清空
 *
 * trace 结果默认脱敏（Authorization/Cookie/Token/密码）。
 */
object DynamicTools {

    private val tracer = DynamicTracer()
    private val json = Json { ignoreUnknownKeys = true }

    /** WebView 返回值 -> JsonObject（剥一层引号包裹） */
    private fun parseJsObject(raw: String?): JsonObject? {
        if (raw.isNullOrBlank() || raw.trim() == "null") return null
        return try {
            when (val el = json.parseToJsonElement(raw.trim())) {
                is JsonObject -> el
                is JsonPrimitive -> json.parseToJsonElement(el.content) as? JsonObject
                else -> null
            }
        } catch (e: Exception) { null }
    }

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)

        return listOf(
            f.tool(
                "dynamic.trace_function",
                "动态追踪函数（不暂停页面）：包装目标函数记录每次调用的参数/返回值/耗时/可选堆栈；签名/加密函数输入输出分析首选",
                ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "target" to Schemas.strSchema("函数点路径（如 window.sign / JSON.stringify / app.getToken）"),
                    "captureArgs" to Schemas.boolSchema("记录参数（默认 true）"),
                    "captureReturn" to Schemas.boolSchema("记录返回值（默认 true）"),
                    "captureStack" to Schemas.boolSchema("记录调用堆栈（默认 false，开销较大）"),
                ),
            ) { args ->
                val target = ToolArgs.str(args, "target")
                if (target.isBlank()) return@tool McpToolResult.error("INVALID_ARGS", "target 必填")
                val session = deps.activeSession()
                val ok = tracer.traceFunction(
                    session.engine, target,
                    captureArgs = ToolArgs.bool(args, "captureArgs", true),
                    captureReturn = ToolArgs.bool(args, "captureReturn", true),
                    captureStack = ToolArgs.bool(args, "captureStack", false),
                )
                if (!ok) {
                    return@tool McpToolResult.error(
                        "TRACE_FAILED",
                        "目标不是函数或路径不可达（检查点路径；属性应先存在）",
                    )
                }
                McpToolResult.json(
                    buildJsonObject {
                        put("tracing", JsonPrimitive(target))
                        put("hint", JsonPrimitive("触发目标操作后调用 dynamic.collect_trace 取回时间线"))
                    },
                )
            },

            f.tool(
                "dynamic.untrace_function",
                "取消函数追踪（恢复原函数）",
                ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "target" to Schemas.strSchema("函数点路径"),
                ),
            ) { args ->
                val target = ToolArgs.str(args, "target")
                if (target.isBlank()) return@tool McpToolResult.error("INVALID_ARGS", "target 必填")
                val session = deps.activeSession()
                val ok = tracer.untraceFunction(session.engine, target)
                McpToolResult.json(buildJsonObject { put("restored", JsonPrimitive(ok)) })
            },

            f.tool(
                "dynamic.monitor_object",
                "对象属性监控：Proxy 包装目标对象，读写属性即记录值 + 调用堆栈（逆向「数据被谁改了」）",
                ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "target" to Schemas.strSchema("对象点路径（如 window.user / app.config；须为 object）"),
                ),
            ) { args ->
                val target = ToolArgs.str(args, "target")
                if (target.isBlank()) return@tool McpToolResult.error("INVALID_ARGS", "target 必填")
                val session = deps.activeSession()
                val ok = tracer.monitorObject(session.engine, target)
                if (!ok) {
                    return@tool McpToolResult.error(
                        "MONITOR_FAILED",
                        "目标不是对象或路径不可达（Proxy 仅支持 object）",
                    )
                }
                McpToolResult.json(
                    buildJsonObject {
                        put("monitoring", JsonPrimitive(target))
                        put("hint", JsonPrimitive("属性读写将进入 trace；dynamic.collect_trace 取回"))
                    },
                )
            },

            f.tool(
                "dynamic.profile_object",
                "方法耗时剖析：批量包装目标对象的所有方法，统计调用次数/总耗时/平均耗时（定位加密循环等性能热点）",
                ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "target" to Schemas.strSchema("对象点路径（如 window.crypto / 某命名空间对象）"),
                    "maxMethods" to Schemas.intSchema("最多包装方法数（默认 30）"),
                ),
            ) { args ->
                val target = ToolArgs.str(args, "target")
                if (target.isBlank()) return@tool McpToolResult.error("INVALID_ARGS", "target 必填")
                val session = deps.activeSession()
                val count = tracer.profileObject(
                    session.engine, target,
                    ToolArgs.int(args, "maxMethods", 30),
                )
                if (count <= 0) {
                    return@tool McpToolResult.error("PROFILE_FAILED", "目标不是对象或无方法可包装")
                }
                McpToolResult.json(
                    buildJsonObject {
                        put("wrapped", JsonPrimitive(count))
                        put("hint", JsonPrimitive("运行目标操作后调用 dynamic.collect_profile 取回统计"))
                    },
                )
            },

            f.tool(
                "dynamic.collect_profile",
                "取回方法耗时剖析统计（按总耗时降序）",
                ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val raw = tracer.collectProfile(session.engine)
                    ?: return@tool McpToolResult.error("EVALUATE_FAILED", "取回失败")
                McpToolResult.text(raw)
            },

            f.tool(
                "dynamic.collect_trace",
                "取回动态 trace 时间线（函数调用/属性读写事件；支持按 target 过滤）",
                ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "filter" to Schemas.strSchema("按 target 关键字过滤（可选）"),
                    "limit" to Schemas.intSchema("最多返回条数（默认 200）"),
                    "clear" to Schemas.boolSchema("取回后清空（默认 false）"),
                ),
            ) { args ->
                val session = deps.activeSession()
                val filter = ToolArgs.str(args, "filter")
                val limit = ToolArgs.int(args, "limit", 200).coerceIn(1, 2000)
                val raw = tracer.collectTrace(session.engine, filter, limit)
                    ?: return@tool McpToolResult.error("EVALUATE_FAILED", "取回失败（先 dynamic.trace_function 安装追踪）")
                if (ToolArgs.bool(args, "clear", false)) tracer.clearTrace(session.engine)
                McpToolResult.text(raw)
            },

            f.tool(
                "dynamic.clear_trace",
                "清空动态 trace 缓冲",
                ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                tracer.clearTrace(session.engine)
                McpToolResult.json(buildJsonObject { put("cleared", JsonPrimitive(true)) })
            },

            // ---------------- 动态代码捕获（__WRMCP_DYN__，报告 §10） ----------------

            f.tool(
                "dynamic.code_list",
                "列出页面动态代码捕获记录（eval/new Function/Blob/Worker/importScripts/定时器字符串——JSVMP 动态打包站点的真实执行载荷入口；kind 可过滤，默认全部）",
                ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "kind" to Schemas.strSchema("类型过滤：eval/Function/Blob/Worker/importScripts/timer/全部（默认全部）"),
                    "limit" to Schemas.intSchema("返回条数（默认 30，最近在前）"),
                    "includeCode" to Schemas.boolSchema("包含代码预览（默认 false，仅元信息）"),
                ),
            ) { args ->
                val session = deps.activeSession()
                val kind = ToolArgs.str(args, "kind", "").lowercase()
                val limit = ToolArgs.int(args, "limit", 30).coerceIn(1, 200)
                val includeCode = ToolArgs.bool(args, "includeCode", false)
                val filter = if (kind.isBlank() || kind == "all" || kind == "全部") "" else kind.filter { it.isLetter() }
                val script = """
                    (function(){
                      var D = globalThis.__WRMCP_DYN__;
                      if (!D) return JSON.stringify({installed: false});
                      var recs = D.records.slice().reverse();
                      ${if (filter.isNotBlank()) "recs = recs.filter(function(r){ return r.kind === '$filter'; });" else ""}
                      recs = recs.slice(0, $limit);
                      return JSON.stringify({
                        installed: true,
                        stats: D.stats(),
                        records: recs.map(function(r){
                          var o = { i: r.i, kind: r.kind, ts: r.ts, size: r.size, url: r.url, linked: r.linked };
                          if ($includeCode) { o.code = String(r.code).substring(0, 800); o.stack = String(r.stack).substring(0, 400); }
                          return o;
                        })
                      });
                    })()
                """.trimIndent()
                val raw = session.engine.evaluateJavascript(script)
                val obj = parseJsObject(raw)
                    ?: return@tool McpToolResult.error("DYN_NOT_INSTALLED", "页面未安装动态代码捕获（document-start 注入未生效或页面太早）")
                if (obj["installed"]?.let { (it as? JsonPrimitive)?.content == "false" } == true) {
                    return@tool McpToolResult.error(
                        "DYN_NOT_INSTALLED",
                        "页面未安装动态代码捕获（刷新页面后重试；旧 WebView 的 document-start 降级注入可能在部分动态导航后缺失）",
                    )
                }
                McpToolResult.json(obj)
            },
            f.tool(
                "dynamic.code_get",
                "取单条动态代码完整内容（配合 dynamic.code_list 的序号 i；含堆栈定位发起位置）",
                ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "index" to Schemas.intSchema("code_list 记录的 i 序号"),
                    "maxChars" to Schemas.intSchema("代码返回上限（默认 100000）"),
                ),
            ) { args ->
                val session = deps.activeSession()
                val index = ToolArgs.int(args, "index", -1)
                val maxChars = ToolArgs.int(args, "maxChars", 100_000).coerceIn(1000, 500_000)
                if (index <= 0) return@tool McpToolResult.error("INVALID_ARGS", "index 必填（dynamic.code_list 的 i）")
                val script = """
                    (function(){
                      var D = globalThis.__WRMCP_DYN__;
                      if (!D) return JSON.stringify({error: 'NOT_INSTALLED'});
                      var rec = D.records.filter(function(r){ return r.i === $index; }).pop();
                      if (!rec) return JSON.stringify({error: 'NOT_FOUND'});
                      return JSON.stringify({
                        i: rec.i, kind: rec.kind, ts: rec.ts, size: rec.size, url: rec.url,
                        code: String(rec.code).substring(0, $maxChars),
                        truncated: String(rec.code).length > $maxChars,
                        stack: rec.stack, linked: rec.linked
                      });
                    })()
                """.trimIndent()
                val raw = session.engine.evaluateJavascript(script)
                val obj = parseJsObject(raw)
                    ?: return@tool McpToolResult.error("EVALUATE_FAILED", "取回失败（页面可能已刷新）")
                if (obj["error"] != null) {
                    return@tool McpToolResult.error(
                        (obj["error"] as? JsonPrimitive)?.content ?: "ERROR",
                        "取回失败：${(obj["error"] as? JsonPrimitive)?.content ?: ""}",
                    )
                }
                McpToolResult.json(obj)
            },
            f.tool(
                "dynamic.code_add_rule",
                "添加动态代码拦截规则（在 eval/Function/Blob/Worker/timer 执行前同步求值：log 仅记录 / block 丢弃执行 / replace 替换代码——JSVMP 消毒与实验首选）",
                ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.HIGH,
                inputSchema = Schemas.objectSchema(
                    "kind" to Schemas.strSchema("通道：eval/Function/Blob/Worker/timer/all（默认 all）"),
                    "match" to Schemas.strSchema("匹配：子串，或 /regex/flags 形式"),
                    "action" to Schemas.strSchema("动作：log（默认）/ block / replace"),
                    "replacement" to Schemas.strSchema("replace 动作的替换代码"),
                ),
            ) { args ->
                val session = deps.activeSession()
                val kind = ToolArgs.str(args, "kind", "all")
                val match = ToolArgs.str(args, "match")
                if (match.isBlank()) return@tool McpToolResult.error("INVALID_ARGS", "match 必填（子串或 /regex/）")
                val action = ToolArgs.str(args, "action", "log")
                if (action !in setOf("log", "block", "replace")) {
                    return@tool McpToolResult.error("INVALID_ARGS", "action 必须是 log/block/replace")
                }
                val replacement = ToolArgs.optStr(args, "replacement") ?: ""
                if (action == "replace" && replacement.isBlank()) {
                    return@tool McpToolResult.error("INVALID_ARGS", "replace 动作需要 replacement")
                }
                val ruleJson = buildJsonObject {
                    put("kind", kind)
                    put("match", match)
                    put("action", action)
                    put("replacement", replacement)
                }
                val script = """
                    (function(){
                      var D = globalThis.__WRMCP_DYN__;
                      if (!D || !D.addRule) return JSON.stringify({error: 'NOT_INSTALLED'});
                      var n = D.addRule($ruleJson);
                      return JSON.stringify({ok: true, ruleIndex: n, totalRules: D.rules.length});
                    })()
                """.trimIndent()
                val raw = session.engine.evaluateJavascript(script)
                val obj = parseJsObject(raw)
                    ?: return@tool McpToolResult.error("DYN_NOT_INSTALLED", "页面未安装动态代码捕获（刷新页面后重试）")
                if (obj["error"] != null) {
                    return@tool McpToolResult.error("DYN_NOT_INSTALLED", "页面未安装动态代码捕获")
                }
                McpToolResult.json(
                    buildJsonObject {
                        put("ok", JsonPrimitive(true))
                        put("kind", kind)
                        put("match", match)
                        put("action", action)
                        put("totalRules", obj["totalRules"] ?: JsonPrimitive(1))
                        put("hint", JsonPrimitive("规则在代码执行前同步生效；dynamic.code_list 观察命中（(blocked)/(replaced) 标记）"))
                    },
                )
            },
            f.tool(
                "dynamic.code_stats",
                "动态代码捕获统计（总捕获数/当前缓冲/拦截数/替换数/规则数——注入是否生效与拦截强度的体检）",
                ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val raw = session.engine.evaluateJavascript(
                    "(function(){ var D = globalThis.__WRMCP_DYN__; return D ? JSON.stringify(D.stats()) : 'null'; })()",
                )
                val obj = parseJsObject(raw)
                    ?: return@tool McpToolResult.error("DYN_NOT_INSTALLED", "页面未安装动态代码捕获（刷新页面后重试）")
                McpToolResult.json(obj)
            },
        )
    }
}
