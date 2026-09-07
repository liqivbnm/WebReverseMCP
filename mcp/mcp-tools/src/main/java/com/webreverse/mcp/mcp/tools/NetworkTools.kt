package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import com.webreverse.mcp.core.common.util.Redactor
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/** Network Tools：网络监控、过滤、HAR、cURL、Block/Mock */
object NetworkTools {

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)
        return listOf(
            f.tool(
                "network.enable", "启用网络监控", ToolCategory.NETWORK,
                PermissionScope.READ_NETWORK, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                session.engine.clearNetworkEntries()
                McpToolResult.text("网络监控已启用")
            },
            f.tool(
                "network.disable", "禁用网络监控", ToolCategory.NETWORK,
                PermissionScope.READ_NETWORK, RiskLevel.LOW,
            ) { _ ->
                McpToolResult.text("网络监控已禁用")
            },
            f.tool(
                "network.list", "列出所有网络请求", ToolCategory.NETWORK,
                PermissionScope.READ_NETWORK, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "limit" to Schemas.intSchema("返回数量上限"),
                    "includeBodies" to Schemas.boolSchema("是否包含请求/响应体"),
                ),
            ) { args ->
                // （P2-2 修复）：limit 加边界约束。原实现无 coerce——
                // 负数 limit 传给 take() 直接抛 IllegalArgumentException，
                // 工具返回 TOOL_EXECUTION_ERROR。
                val limit = ToolArgs.int(args, "limit", 100).coerceIn(1, 500)
                val includeBodies = ToolArgs.bool(args, "includeBodies", false)
                val session = deps.activeSession()
                val entries = deps.networkInspector.getEntries(session.engine)
                // 注入式环形缓冲按插入顺序存且跨导航不清空，默认 take(limit)
                // 会返回最旧的过期条目（导航前的旧页面请求挤占前 100 位）。改为按
                // startedAt 倒序，让当前页面的新请求优先可见，避免旧页面条目误导。
                val sorted = entries.sortedByDescending { it.startedAt }
                McpToolResult.json(
                    buildJsonObject {
                        put("count", JsonPrimitive(entries.size))
                        // （P2-2 修复）：count 报总数但只返回 limit 条，
                        // 补 truncated 标记让 AI 知道数据不完整（可提高 limit 再取）
                        put("returned", JsonPrimitive(entries.size.coerceAtMost(limit)))
                        put("truncated", JsonPrimitive(entries.size > limit))
                        put(
                            "entries",
                            JsonArray(
                                sorted.take(limit).map { e ->
                                    buildJsonObject {
                                        put("id", JsonPrimitive(e.id))
                                        put("url", JsonPrimitive(Redactor.redactUrl(e.url)))
                                        put("method", JsonPrimitive(e.method.wire))
                                        put("status", JsonPrimitive(e.status))
                                        put("resourceType", JsonPrimitive(e.resourceType.display))
                                        put("mimeType", JsonPrimitive(e.mimeType))
                                        put("duration", JsonPrimitive(e.durationMs))
                                        put("size", JsonPrimitive(e.responseBodySize))
                                        put("initiator", JsonPrimitive(e.initiator))
                                        if (includeBodies) {
                                            // （P1-5 修复）：列表模式的 body 截断
                                            // （原实现全量返回，大响应体可撑爆 AI 上下文）
                                            put("requestBody", JsonPrimitive(Redactor.redactText(e.requestBody ?: "").take(4000)))
                                            put("responseBody", JsonPrimitive(Redactor.redactText(e.responseBody ?: "").take(4000)))
                                        }
                                    }
                                },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "network.get", "获取单个网络请求详情（支持注入式 entryId 与 CDP requestId）", ToolCategory.NETWORK,
                PermissionScope.READ_NETWORK, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "entryId" to Schemas.strSchema("请求 ID（network.list 的 entryId 或 network.cdp_requests 的 requestId）"),
                    "maxBodyChars" to Schemas.intSchema("请求/响应体最大字符数（默认 50000，上限 200000）"),
                ),
            ) { args ->
                val entryId = ToolArgs.str(args, "entryId")
                // （P1-5 修复）：network.get 的 body 原为全量返回（同文件的
                // network.replay 早有 maxBodyChars=50K 截断——同文件内标准不一）。
                // 统一为默认 50K、上限 200K 的截断策略，超限标记 truncated。
                val maxBodyChars = ToolArgs.int(args, "maxBodyChars", 50_000).coerceIn(1000, 200_000)
                val session = deps.activeSession()
                val entry = deps.networkInspector.getEntries(session.engine).firstOrNull { it.id == entryId }
                if (entry == null) {
                    // CDP requestId 回退（修复传 CDP requestId 报 ENTRY_NOT_FOUND）
                    val cdp = com.webreverse.mcp.devtools.network.CdpNetworkMonitor.findByRequestId(entryId)
                        ?: return@tool McpToolResult.error(
                            "ENTRY_NOT_FOUND",
                            "未找到请求: $entryId（注入式 entry 与 CDP requestId 均未命中；CDP 侧请先 network.attach_cdp）",
                        )
                    return@tool McpToolResult.json(
                        buildJsonObject {
                            put("source", JsonPrimitive("cdp"))
                            put("id", JsonPrimitive(cdp.requestId))
                            put("url", JsonPrimitive(Redactor.redactUrl(cdp.url)))
                            put("method", JsonPrimitive(cdp.method))
                            put("status", JsonPrimitive(cdp.status))
                            put("mimeType", JsonPrimitive(cdp.mimeType))
                            put("resourceType", JsonPrimitive(cdp.resourceType))
                            put("fromCache", JsonPrimitive(cdp.fromCache))
                            put("finished", JsonPrimitive(cdp.finished))
                            cdp.remoteAddress?.let { put("remoteAddress", JsonPrimitive(it)) }
                            cdp.errorText?.let { put("error", JsonPrimitive(it)) }
                            put("requestHeaders", JsonPrimitive(Redactor.redactHeaders(cdp.requestHeaders).toString()))
                            put("responseHeaders", JsonPrimitive(Redactor.redactHeaders(cdp.responseHeaders).toString()))
                            cdp.postData?.let { put("requestBody", JsonPrimitive(Redactor.redactText(it).take(maxBodyChars))) }
                            put("initiator", JsonPrimitive(cdp.initiatorType.ifBlank { cdp.initiatorUrl }))
                            if (cdp.initiatorType.isNotBlank()) put("initiatorType", JsonPrimitive(cdp.initiatorType))
                            if (cdp.initiatorUrl.isNotBlank()) put("initiatorUrl", JsonPrimitive(Redactor.redactUrl(cdp.initiatorUrl)))
                            put("initiatorStack", JsonPrimitive(cdp.initiatorStack.take(4000)))
                            put("hint", JsonPrimitive("CDP 条目：响应体用 network.get_response_body requestId=${cdp.requestId} 回取"))
                        },
                    )
                }
                val reqBody = Redactor.redactText(entry.requestBody ?: "")
                val respBody = Redactor.redactText(entry.responseBody ?: "")
                val bodyTruncated = reqBody.length > maxBodyChars || respBody.length > maxBodyChars
                McpToolResult.json(
                    buildJsonObject {
                        put("id", JsonPrimitive(entry.id))
                        put("url", JsonPrimitive(Redactor.redactUrl(entry.url)))
                        put("method", JsonPrimitive(entry.method.wire))
                        put("status", JsonPrimitive(entry.status))
                        put("statusText", JsonPrimitive(entry.statusText))
                        put("protocol", JsonPrimitive(entry.protocol))
                        put("mimeType", JsonPrimitive(entry.mimeType))
                        put("resourceType", JsonPrimitive(entry.resourceType.display))
                        put("remoteAddress", JsonPrimitive(entry.remoteAddress))
                        put("fromCache", JsonPrimitive(entry.fromCache))
                        put("fromServiceWorker", JsonPrimitive(entry.fromServiceWorker))
                        put(
                            "requestHeaders",
                            JsonPrimitive(Redactor.redactHeaders(entry.requestHeaders).toString()),
                        )
                        put(
                            "responseHeaders",
                            JsonPrimitive(Redactor.redactHeaders(entry.responseHeaders).toString()),
                        )
                        put(
                            "queryParams",
                            JsonPrimitive(entry.queryParams.toString()),
                        )
                        put("requestBody", JsonPrimitive(reqBody.take(maxBodyChars)))
                        put("responseBody", JsonPrimitive(respBody.take(maxBodyChars)))
                        put("bodyTruncated", JsonPrimitive(bodyTruncated))
                        put("timing", JsonPrimitive(entry.timing.toString()))
                        put("initiator", JsonPrimitive(entry.initiator))
                        put("initiatorStack", JsonPrimitive(entry.initiatorStack.take(2000)))
                    },
                )
            },
            f.tool(
                "network.search", "搜索网络请求", ToolCategory.NETWORK,
                PermissionScope.READ_NETWORK, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("query" to Schemas.strSchema("搜索关键词")),
            ) { args ->
                val query = ToolArgs.str(args, "query")
                val session = deps.activeSession()
                val entries = deps.networkInspector.search(session.engine, query)
                McpToolResult.json(
                    buildJsonObject {
                        put("count", JsonPrimitive(entries.size))
                        put(
                            "entries",
                            JsonArray(
                                entries.take(100).map { e ->
                                    buildJsonObject {
                                        put("id", JsonPrimitive(e.id))
                                        put("url", JsonPrimitive(Redactor.redactUrl(e.url)))
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
                "network.filter", "按条件过滤网络请求", ToolCategory.NETWORK,
                PermissionScope.READ_NETWORK, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "resourceType" to Schemas.strSchema("资源类型"),
                    "status" to Schemas.intSchema("状态码"),
                    "method" to Schemas.strSchema("HTTP 方法"),
                    "host" to Schemas.strSchema("主机名"),
                ),
            ) { args ->
                val resourceType = ToolArgs.optStr(args, "resourceType")
                val status = ToolArgs.int(args, "status", 0).takeIf { it > 0 }
                val method = ToolArgs.optStr(args, "method")
                val host = ToolArgs.optStr(args, "host")
                val session = deps.activeSession()
                val entries = deps.networkInspector.filter(session.engine, resourceType, status, method, host)
                McpToolResult.json(
                    buildJsonObject {
                        put("count", JsonPrimitive(entries.size))
                        put(
                            "entries",
                            JsonArray(
                                entries.take(100).map { e ->
                                    buildJsonObject {
                                        put("id", JsonPrimitive(e.id))
                                        put("url", JsonPrimitive(Redactor.redactUrl(e.url)))
                                        put("method", JsonPrimitive(e.method.wire))
                                        put("status", JsonPrimitive(e.status))
                                        put("resourceType", JsonPrimitive(e.resourceType.display))
                                    }
                                },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "network.headers", "获取请求/响应头", ToolCategory.NETWORK,
                PermissionScope.READ_HEADERS, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema("entryId" to Schemas.strSchema("请求 ID")),
            ) { args ->
                val entryId = ToolArgs.str(args, "entryId")
                val session = deps.activeSession()
                val entry = deps.networkInspector.getEntries(session.engine).firstOrNull { it.id == entryId }
                    ?: return@tool McpToolResult.error("ENTRY_NOT_FOUND", "未找到请求: $entryId")
                McpToolResult.json(
                    buildJsonObject {
                        put(
                            "requestHeaders",
                            buildJsonObject {
                                Redactor.redactHeaders(entry.requestHeaders).forEach { (k, v) -> put(k, JsonPrimitive(v)) }
                            },
                        )
                        put(
                            "responseHeaders",
                            buildJsonObject {
                                Redactor.redactHeaders(entry.responseHeaders).forEach { (k, v) -> put(k, JsonPrimitive(v)) }
                            },
                        )
                    },
                )
            },
            f.tool(
                "network.cookies", "获取请求相关 Cookie", ToolCategory.NETWORK,
                PermissionScope.READ_COOKIES, RiskLevel.HIGH,
                inputSchema = Schemas.objectSchema("entryId" to Schemas.strSchema("请求 ID")),
            ) { args ->
                val entryId = ToolArgs.str(args, "entryId")
                val session = deps.activeSession()
                val entry = deps.networkInspector.getEntries(session.engine).firstOrNull { it.id == entryId }
                    ?: return@tool McpToolResult.error("ENTRY_NOT_FOUND", "未找到请求: $entryId")
                McpToolResult.json(
                    buildJsonObject {
                        put(
                            "cookies",
                            JsonArray(
                                entry.cookies.map { c ->
                                    buildJsonObject {
                                        put("name", JsonPrimitive(c.name))
                                        put("value", JsonPrimitive(Redactor.redactValue(c.name, c.value)))
                                        put("domain", JsonPrimitive(c.domain))
                                        put("path", JsonPrimitive(c.path))
                                    }
                                },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "network.timing", "获取请求时序（支持注入式 entryId 与 CDP requestId；CDP 仅同源请求才有时序，cdp /缓存/附加过晚字段可能为 0）", ToolCategory.NETWORK,
                PermissionScope.READ_NETWORK, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("entryId" to Schemas.strSchema("请求 ID（network.list 的 entryId 或 network.cdp_requests 的 requestId）")),
            ) { args ->
                val entryId = ToolArgs.str(args, "entryId")
                val session = deps.activeSession()
                // 先查注入式 entry，命中即返回完整时序；未命中则回退 CDP
                val entry = deps.networkInspector.getEntries(session.engine).firstOrNull { it.id == entryId }
                if (entry != null) {
                    return@tool McpToolResult.json(
                        buildJsonObject {
                            put("source", JsonPrimitive("hook"))
                            put("dns", JsonPrimitive(entry.timing.dns))
                            put("connect", JsonPrimitive(entry.timing.connect))
                            put("ssl", JsonPrimitive(entry.timing.ssl))
                            put("ttfb", JsonPrimitive(entry.timing.ttfb))
                            put("download", JsonPrimitive(entry.timing.download))
                            put("total", JsonPrimitive(entry.timing.total))
                        },
                    )
                }
                val cdp = com.webreverse.mcp.devtools.network.CdpNetworkMonitor.findByRequestId(entryId)
                if (cdp != null) {
                    return@tool McpToolResult.json(
                        buildJsonObject {
                            put("source", JsonPrimitive("cdp"))
                            put("requestId", JsonPrimitive(cdp.requestId))
                            put("url", JsonPrimitive(Redactor.redactUrl(cdp.url)))
                            put("dns", JsonPrimitive(cdp.timing.dns))
                            put("connect", JsonPrimitive(cdp.timing.connect))
                            put("ssl", JsonPrimitive(cdp.timing.ssl))
                            put("ttfb", JsonPrimitive(cdp.timing.ttfb))
                            put("download", JsonPrimitive(cdp.timing.download))
                            put("total", JsonPrimitive(cdp.timing.total))
                            if (!cdp.timing.hasData) {
                                put("hint", JsonPrimitive("CDP 未捕获到 ResourceTiming（跨域/命中缓存/CDP 附加晚于请求发出或请求仍进行中）；请 network.attach_cdp 后刷新页面，用同源请求的 requestId 查询"))
                            }
                        },
                    )
                }
                McpToolResult.error(
                    "ENTRY_NOT_FOUND",
                    "未找到请求: $entryId（注入式 entry 与 CDP requestId 均未命中，或请求已过期轮换出；请先重新执行 network.list/cdp_requests 获取当前有效 ID）",
                )
            },
            f.tool(
                "network.initiator", "获取请求发起者（DevTools Initiator 面板同款：request call stack 调用栈 + initiator chain 发起链 文档→脚本→请求；支持注入式 entryId 与 CDP requestId）", ToolCategory.NETWORK,
                PermissionScope.READ_NETWORK, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("entryId" to Schemas.strSchema("请求 ID（network.list 的 entryId 或 network.cdp_requests 的 requestId）")),
            ) { args ->
                val entryId = ToolArgs.str(args, "entryId")
                val session = deps.activeSession()
                val entry = deps.networkInspector.getEntries(session.engine).firstOrNull { it.id == entryId }
                if (entry != null) {
                    return@tool McpToolResult.json(
                        buildJsonObject {
                            put("source", JsonPrimitive("hook"))
                            put("initiator", JsonPrimitive(entry.initiator))
                            put("stack", JsonPrimitive(entry.initiatorStack.take(3000)))
                            put("hint", JsonPrimitive("注入式 hook 条目无完整调用栈；要 DevTools 级 initiator（调用栈+发起链），请 network.attach_cdp 后刷新页面，用 network.cdp_requests 的 requestId 查询"))
                        },
                    )
                }
                // CDP requestId 回退——修复此前传 CDP requestId 报 ENTRY_NOT_FOUND
                val cdp = com.webreverse.mcp.devtools.network.CdpNetworkMonitor.findByRequestId(entryId)
                if (cdp != null) {
                    // 发起链（DevTools "Request initiator chain"：文档→脚本→请求）
                    val chain = com.webreverse.mcp.devtools.network.CdpNetworkMonitor.initiatorChain(cdp.requestId)
                    return@tool McpToolResult.json(
                        buildJsonObject {
                            put("source", JsonPrimitive("cdp"))
                            put("requestId", JsonPrimitive(cdp.requestId))
                            put("url", JsonPrimitive(Redactor.redactUrl(cdp.url)))
                            put("initiator", JsonPrimitive(cdp.initiatorType.ifBlank { cdp.initiatorUrl.ifBlank { "unknown" } }))
                            put("initiatorType", JsonPrimitive(cdp.initiatorType))
                            if (cdp.initiatorUrl.isNotBlank()) put("initiatorUrl", JsonPrimitive(Redactor.redactUrl(cdp.initiatorUrl)))
                            // Request call stack（DevTools Initiator 面板第一区块）
                            put("stack", JsonPrimitive(cdp.initiatorStack.take(8000)))
                            // Request initiator chain（第二区块：根文档在前，目标请求在后）
                            put(
                                "chain",
                                JsonArray(
                                    chain.map { hop ->
                                        buildJsonObject {
                                            put("url", JsonPrimitive(Redactor.redactUrl(hop.url)))
                                            put("requestId", JsonPrimitive(hop.requestId))
                                            put("via", JsonPrimitive(hop.via))
                                            if (hop.isTarget) put("target", JsonPrimitive(true))
                                        }
                                    },
                                ),
                            )
                            if (cdp.initiatorStack.isBlank()) {
                                put("hint", JsonPrimitive("该请求非 JS 直接发起（parser/preload 等类型无调用栈），或 CDP 附加晚于请求发出（刷新页面重抓）"))
                            }
                        },
                    )
                }
                McpToolResult.error("ENTRY_NOT_FOUND", "未找到请求: $entryId（注入式 entry 与 CDP requestId 均未命中；CDP 侧请先 network.attach_cdp 并刷新页面）")
            },
            f.tool(
                "network.replay", "真实重放请求（页面上下文 fetch 重发原 method/headers/body，可选覆盖 url/method/headers/body；返回响应状态/头/体，供改参对比签名）", ToolCategory.NETWORK,
                PermissionScope.MODIFY_NETWORK, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "entryId" to Schemas.strSchema("请求 ID（network.list 的 id）"),
                    "url" to Schemas.strSchema("覆盖目标 URL（可选，默认原 URL）"),
                    "method" to Schemas.strSchema("覆盖 HTTP 方法（可选，默认原方法）"),
                    "body" to Schemas.strSchema("覆盖请求体（可选，默认原请求体；传空串表示无体）"),
                    "headers" to Schemas.strSchema("覆盖请求头 JSON 对象字符串（可选，与原请求头合并，同名覆盖）"),
                    "maxBodyChars" to Schemas.intSchema("响应体返回上限字符数（默认 50000）"),
                ),
                timeoutMs = 60_000,
            ) { args ->
                val entryId = ToolArgs.str(args, "entryId")
                val session = deps.activeSession()
                val entry = deps.networkInspector.getEntries(session.engine).firstOrNull { it.id == entryId }
                    ?: return@tool McpToolResult.error("ENTRY_NOT_FOUND", "未找到请求: $entryId")

                val url = ToolArgs.optStr(args, "url")?.takeIf { it.isNotBlank() } ?: entry.url
                val method = (ToolArgs.optStr(args, "method") ?: entry.method.wire).uppercase()
                val maxBodyChars = ToolArgs.int(args, "maxBodyChars", 50_000).coerceIn(1000, 1_000_000)
                val hasBodyOverride = ToolArgs.optStr(args, "body") != null
                val body = if (hasBodyOverride) (ToolArgs.optStr(args, "body") ?: "") else entry.requestBody
                val overrideHeaders = ToolArgs.optStr(args, "headers")?.let { h ->
                    runCatching {
                        kotlinx.serialization.json.Json.parseToJsonElement(h) as? JsonObject
                    }.getOrNull()
                }

                // 合并请求头：原头 + 覆盖头；剔除 fetch 禁止修改的安全头
                val forbid = setOf(
                    "host", "content-length", "connection", "keep-alive", "transfer-encoding",
                    "upgrade", "proxy-", "te", "trailer",
                )
                val headerPairs = LinkedHashMap<String, String>()
                entry.requestHeaders.forEach { (k, v) ->
                    if (k.lowercase() !in forbid) headerPairs[k] = v
                }
                overrideHeaders?.forEach { (k, v) ->
                    if (k.lowercase() !in forbid) headerPairs[k] = v.jsonPrimitive.contentOrNull ?: v.toString()
                }
                val headerJson = kotlinx.serialization.json.buildJsonObject {
                    headerPairs.forEach { (k, v) -> put(k, v) }
                }

                val bodyArg = if (body != null && method !in setOf("GET", "HEAD")) {
                    ", body: ${com.webreverse.mcp.browser.engine.util.JsScripts.quote(body)}"
                } else ""
                val script = """
                    (async function(){
                      try {
                        var resp = await fetch(${com.webreverse.mcp.browser.engine.util.JsScripts.quote(url)}, {
                          method: ${com.webreverse.mcp.browser.engine.util.JsScripts.quote(method)},
                          headers: $headerJson$bodyArg,
                          redirect: 'follow',
                          credentials: 'include'
                        });
                        var text = '';
                        try { text = await resp.text(); } catch(e2){ text = ''; }
                        var hdrs = {};
                        try { resp.headers.forEach(function(v, k){ hdrs[k] = v; }); } catch(e3){}
                        return JSON.stringify({
                          ok: resp.ok, status: resp.status, statusText: resp.statusText,
                          finalUrl: resp.url, headers: hdrs,
                          body: text.substring(0, $maxBodyChars), bodyTruncated: text.length > $maxBodyChars
                        });
                      } catch(e) {
                        return JSON.stringify({ ok: false, error: String(e && e.message || e) });
                      }
                    })()
                """.trimIndent()
                val raw = session.engine.evaluateJavascript(script)
                    ?: return@tool McpToolResult.error("REPLAY_FAILED", "页面执行重放脚本失败（页面可能已销毁或跳转）")
                val cleaned = raw.trim().removeSurrounding("\"")
                    .replace("\\\"", "\"").replace("\\\\", "\\").replace("\\n", "\n").replace("\\t", "\t")
                val parsed = runCatching { kotlinx.serialization.json.Json.parseToJsonElement(cleaned) }.getOrNull()
                    ?: return@tool McpToolResult.text(cleaned.ifBlank { "重放完成但无法解析结果" })

                McpToolResult.json(
                    buildJsonObject {
                        put("replayed", kotlinx.serialization.json.JsonPrimitive(true))
                        put("method", kotlinx.serialization.json.JsonPrimitive(method))
                        put("url", kotlinx.serialization.json.JsonPrimitive(Redactor.redactUrl(url)))
                        put("result", parsed)
                        put("hint", kotlinx.serialization.json.JsonPrimitive("修改 headers/body 后重放可对比签名/风控差异；响应经 Redactor 脱敏输出"))
                    },
                )
            },
            f.tool(
                "network.export_har", "导出 HAR 文件", ToolCategory.NETWORK,
                PermissionScope.READ_NETWORK, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val har = deps.networkInspector.exportHar(session.engine)
                val json = deps.networkInspector.exportHarJson(har)
                McpToolResult.text(json)
            },
            f.tool(
                "network.import_har", "导入 HAR 文件", ToolCategory.NETWORK,
                PermissionScope.READ_NETWORK, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("har" to Schemas.strSchema("HAR JSON 内容")),
            ) { args ->
                val har = ToolArgs.str(args, "har")
                if (har.isBlank()) return@tool McpToolResult.error("INVALID_ARGUMENTS", "har 不能为空")
                val parsed = deps.networkInspector.importHar(har)
                McpToolResult.text("已导入 HAR，共 ${parsed.log.entries.size} 条记录")
            },
            f.tool(
                "network.copy_curl", "生成 cURL 命令", ToolCategory.NETWORK,
                PermissionScope.READ_NETWORK, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("entryId" to Schemas.strSchema("请求 ID")),
            ) { args ->
                val entryId = ToolArgs.str(args, "entryId")
                val session = deps.activeSession()
                val entry = deps.networkInspector.getEntries(session.engine).firstOrNull { it.id == entryId }
                    ?: return@tool McpToolResult.error("ENTRY_NOT_FOUND", "未找到请求: $entryId")
                McpToolResult.text(deps.networkInspector.toCurl(entry))
            },
            f.tool(
                "network.block", "屏蔽匹配 URL 的请求", ToolCategory.NETWORK,
                PermissionScope.MODIFY_NETWORK, RiskLevel.HIGH,
                inputSchema = Schemas.objectSchema("urlPattern" to Schemas.strSchema("URL 匹配模式")),
            ) { args ->
                val pattern = ToolArgs.str(args, "urlPattern")
                if (pattern.isBlank()) return@tool McpToolResult.error("INVALID_ARGUMENTS", "urlPattern 不能为空")
                deps.hookEngine.createRule(
                    name = "Block: $pattern",
                    type = com.webreverse.mcp.core.common.model.HookType.FETCH,
                    match = com.webreverse.mcp.core.common.model.HookMatch(urlPattern = pattern),
                    action = com.webreverse.mcp.core.common.model.HookAction.BLOCK,
                )
                McpToolResult.text("已屏蔽: $pattern")
            },
            f.tool(
                "network.mock", "Mock 匹配 URL 的响应", ToolCategory.NETWORK,
                PermissionScope.MODIFY_NETWORK, RiskLevel.HIGH,
                inputSchema = Schemas.objectSchema(
                    "urlPattern" to Schemas.strSchema("URL 匹配模式"),
                    "response" to Schemas.strSchema("Mock 响应内容"),
                ),
            ) { args ->
                val pattern = ToolArgs.str(args, "urlPattern")
                val response = ToolArgs.str(args, "response")
                deps.hookEngine.createRule(
                    name = "Mock: $pattern",
                    type = com.webreverse.mcp.core.common.model.HookType.FETCH,
                    match = com.webreverse.mcp.core.common.model.HookMatch(urlPattern = pattern),
                    action = com.webreverse.mcp.core.common.model.HookAction.MOCK,
                    payload = response,
                )
                McpToolResult.text("已 Mock: $pattern")
            },
            f.tool(
                "network.throttle", "设置网络节流", ToolCategory.NETWORK,
                PermissionScope.MODIFY_NETWORK, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "delayMs" to Schemas.intSchema("延迟毫秒"),
                    "enabled" to Schemas.boolSchema("是否启用"),
                ),
            ) { args ->
                val delay = ToolArgs.int(args, "delayMs", 1000)
                val enabled = ToolArgs.bool(args, "enabled", true)
                McpToolResult.text(if (enabled) "已启用节流: ${delay}ms" else "已禁用节流")
            },
            f.tool(
                "network.clear", "清空网络日志", ToolCategory.NETWORK,
                PermissionScope.READ_NETWORK, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                session.engine.clearNetworkEntries()
                McpToolResult.text("网络日志已清空")
            },
            f.tool(
                "network.websocket", "列出 WebSocket 连接", ToolCategory.NETWORK,
                PermissionScope.READ_NETWORK, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val entries = deps.networkInspector.getEntries(session.engine)
                    .filter { it.resourceType == com.webreverse.mcp.core.common.model.ResourceType.WEBSOCKET }
                McpToolResult.json(
                    buildJsonObject {
                        put(
                            "websockets",
                            JsonArray(
                                entries.map { e ->
                                    buildJsonObject {
                                        put("url", JsonPrimitive(Redactor.redactUrl(e.url)))
                                        put("status", JsonPrimitive(e.status))
                                    }
                                },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "network.attach_cdp", "启用 CDP 网络监控（DevTools Network 面板级抓包：覆盖所有资源类型，含跨域，可回取响应体）", ToolCategory.NETWORK,
                PermissionScope.READ_NETWORK, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "clear" to Schemas.boolSchema("是否清空既有记录（默认 true）"),
                ),
            ) { args ->
                if (ToolArgs.bool(args, "clear", true)) {
                    com.webreverse.mcp.devtools.network.CdpNetworkMonitor.clear()
                }
                val session = deps.activeSession()
                val ok = com.webreverse.mcp.devtools.network.CdpNetworkMonitor.attach(session.engine)
                if (ok) {
                    McpToolResult.json(
                        buildJsonObject {
                            put("attached", JsonPrimitive(true))
                            put("hint", JsonPrimitive("之后刷新页面或触发请求，再用 network.cdp_requests 查看，network.get_response_body 取响应体"))
                        },
                    )
                } else {
                    val reason = com.webreverse.mcp.devtools.protocol.cdp.CdpTransport.lastError
                    McpToolResult.error(
                        "CDP_ATTACH_FAILED",
                        "DevTools socket 不可用或 Network.enable 失败" + (reason?.let { "：$it" } ?: ""),
                    )
                }
            },
            f.tool(
                "network.cdp_requests", "列出 CDP 抓取的请求（需先 network.attach_cdp；含资源类型/缓存来源/远端 IP/initiator 调用栈来源标记）", ToolCategory.NETWORK,
                PermissionScope.READ_NETWORK, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "urlFilter" to Schemas.strSchema("URL 子串过滤（可选）"),
                    "limit" to Schemas.intSchema("返回条数（默认 50）"),
                ),
            ) { args ->
                if (!com.webreverse.mcp.devtools.network.CdpNetworkMonitor.isAttached) {
                    return@tool McpToolResult.error("CDP_NOT_ATTACHED", "请先调用 network.attach_cdp")
                }
                val urlFilter = ToolArgs.str(args, "urlFilter")
                val limit = ToolArgs.int(args, "limit", 50)
                val list = com.webreverse.mcp.devtools.network.CdpNetworkMonitor.list(urlFilter, limit)
                McpToolResult.json(
                    buildJsonObject {
                        put("count", JsonPrimitive(list.size))
                        put(
                            "requests",
                            JsonArray(
                                list.map { r ->
                                    buildJsonObject {
                                        put("requestId", JsonPrimitive(r.requestId))
                                        put("url", JsonPrimitive(Redactor.redactUrl(r.url)))
                                        put("method", JsonPrimitive(r.method))
                                        put("type", JsonPrimitive(r.resourceType))
                                        put("status", JsonPrimitive(r.status))
                                        put("mimeType", JsonPrimitive(r.mimeType))
                                        put("size", JsonPrimitive(r.size))
                                        put("fromCache", JsonPrimitive(r.fromCache))
                                        // 协议版本透传（http/1.1 / h2 / h3）+ gRPC 标记
                                        if (r.protocol.isNotBlank()) put("protocol", JsonPrimitive(r.protocol))
                                        if (r.isGrpc) put("grpc", JsonPrimitive(true))
                                        r.remoteAddress?.let { put("remoteAddress", JsonPrimitive(it)) }
                                        r.errorText?.let { put("error", JsonPrimitive(it)) }
                                        r.postData?.let { put("postData", JsonPrimitive(it.take(2000))) }
                                        // initiator 概要（JS 发起=script 且带栈；完整栈用
                                        // network.initiator entryId=<requestId>）
                                        if (r.initiatorType.isNotBlank()) {
                                            put("initiator", JsonPrimitive(r.initiatorType + if (r.initiatorStack.isNotBlank()) " (has stack)" else ""))
                                        } else if (r.initiatorUrl.isNotBlank()) {
                                            put("initiator", JsonPrimitive(Redactor.redactUrl(r.initiatorUrl)))
                                        }
                                        if (r.initiatorStack.isNotBlank()) {
                                            put("initiatorStackPreview", JsonPrimitive(r.initiatorStack.lineSequence().take(3).joinToString("\n")))
                                        }
                                    }
                                },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "network.get_response_body", "回取响应体：优先 CDP（含跨域资源）；CDP 不可用时回退到注入式 hook 捕获的响应体（fetch/XHR 文本类）", ToolCategory.NETWORK,
                PermissionScope.READ_NETWORK, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "requestId" to Schemas.strSchema("请求 ID（来自 network.cdp_requests 或 network.list）"),
                    "maxChars" to Schemas.intSchema("返回 body 最大字符数（默认 50000，上限 200000；超长自动截断打标）"),
                ),
            ) { args ->
                val requestId = ToolArgs.str(args, "requestId")
                if (requestId.isBlank()) return@tool McpToolResult.error("INVALID_ARGS", "requestId 必填")
                // 默认 50K（原 500K 易撑爆 AI 上下文），上限 200K
                val maxChars = ToolArgs.int(args, "maxChars", 50_000).coerceIn(1_000, 200_000)
                // 1) 优先真实 CDP（覆盖所有资源类型，含跨域）
                // 修复：原先 CDP 未附加时直接跳到注入式回退，注入 hook 捕不到
                // 二进制资源就报 BODY_UNAVAILABLE——但其实 DevTools socket 多数可用，
                // 只是没附加。现参照 network.intercept：未附加先自动附加（尽力而为，
                // 失败不阻断，继续走注入式回退）。
                if (!com.webreverse.mcp.devtools.network.CdpNetworkMonitor.isAttached) {
                    runCatching {
                        val session = deps.activeSession()
                        com.webreverse.mcp.devtools.network.CdpNetworkMonitor.attach(session.engine)
                    }
                }
                var cdpAttached = com.webreverse.mcp.devtools.network.CdpNetworkMonitor.isAttached
                if (cdpAttached) {
                    val result = com.webreverse.mcp.devtools.network.CdpNetworkMonitor.getResponseBody(requestId, maxChars)
                    if (result != null && result["body"] != null) {
                        return@tool McpToolResult.json(result)
                    }
                }
                // 2) 注入式回退：fetch/XHR hook 已捕获的响应体（ 起 hook 自动捕获文本类响应）
                val session = deps.activeSession()
                val entry = deps.networkInspector.getEntries(session.engine)
                    .firstOrNull { (it.id == requestId || it.requestId == requestId) && !it.responseBody.isNullOrEmpty() }
                if (entry != null) {
                    val body = entry.responseBody.orEmpty()
                    return@tool McpToolResult.json(
                        buildJsonObject {
                            put("requestId", JsonPrimitive(entry.id))
                            put("url", JsonPrimitive(Redactor.redactUrl(entry.url)))
                            put("status", JsonPrimitive(entry.status))
                            put("mimeType", JsonPrimitive(entry.mimeType))
                            put("source", JsonPrimitive("injected-hook"))
                            put("encoding", JsonPrimitive("utf8"))
                            put("length", JsonPrimitive(body.length))
                            if (body.length > maxChars) put("truncated", true)
                            put("body", JsonPrimitive(body.take(maxChars)))
                        },
                    )
                }
                val hint = if (cdpAttached) {
                    "响应体不可用：CDP 只保留附加之后完成请求的响应体，该请求发生在附加之前或已被丢弃。" +
                        "可刷新页面/重新触发请求后立即重试；或在请求完成后尽早获取"
                } else {
                    "CDP 附加失败且注入式 hook 未捕获到该响应体（" +
                        (com.webreverse.mcp.devtools.protocol.cdp.CdpTransport.lastError ?: "DevTools socket 不可用") +
                        "）。文本类(fetch/XHR)响应会自动捕获；图片/字体等二进制资源需 CDP"
                }
                McpToolResult.error("BODY_UNAVAILABLE", hint)
            },
            // ============ CDP Fetch 域请求拦截 ============
            f.tool(
                "network.intercept",
                "开启/关闭请求拦截（CDP Fetch 域）：匹配的请求在发出前暂停（不访问服务器），可查看完整参数后改写放行/伪造响应/中止。逆向签名接口利器——改 sign 参数重放看服务端校验逻辑；未附加 CDP 时自动附加",
                ToolCategory.NETWORK,
                PermissionScope.MODIFY_NETWORK, RiskLevel.HIGH,
                inputSchema = Schemas.objectSchema(
                    "enabled" to Schemas.boolSchema("true=开启拦截 / false=关闭并放行全部暂停请求（必填）"),
                    "urlPattern" to Schemas.strSchema("URL 通配（空=全部请求），如 */api/sign*"),
                ),
            ) { args ->
                if (ToolArgs.bool(args, "enabled", true)) {
                    if (!com.webreverse.mcp.devtools.network.CdpNetworkMonitor.isAttached) {
                        val session = deps.activeSession()
                        if (!com.webreverse.mcp.devtools.network.CdpNetworkMonitor.attach(session.engine)) {
                            val reason = com.webreverse.mcp.devtools.protocol.cdp.CdpTransport.lastError
                            return@tool McpToolResult.error(
                                "CDP_ATTACH_FAILED",
                                "自动附加 CDP 失败" + (reason?.let { "：$it" } ?: ""),
                            )
                        }
                    }
                    val pattern = ToolArgs.str(args, "urlPattern")
                    val ok = com.webreverse.mcp.devtools.network.CdpNetworkMonitor.enableInterception(pattern)
                    if (ok) {
                        McpToolResult.json(
                            buildJsonObject {
                                put("intercepting", JsonPrimitive(true))
                                put("urlPattern", JsonPrimitive(pattern.ifBlank { "*（全部请求）" }))
                                put(
                                    "hint",
                                    JsonPrimitive(
                                        "触发页面操作后 network.paused_requests 查看被拦截请求（发出前即可见完整 headers/postData），再 resume_request 放行 / mock_response 伪造 / abort_request 中止",
                                    ),
                                )
                            },
                        )
                    } else {
                        McpToolResult.error("INTERCEPT_FAILED", "Fetch.enable 调用失败（CDP 会话可能已断开，重新 attach 后再试）")
                    }
                } else {
                    com.webreverse.mcp.devtools.network.CdpNetworkMonitor.disableInterception()
                    McpToolResult.text("已关闭拦截（暂停中的请求已全部放行）")
                }
            },
            f.tool(
                "network.paused_requests",
                "列出被拦截暂停中的请求（发出前即可见：完整 URL/method/headers/postData——比 network.list 更早一步，签名参数一网打尽）",
                ToolCategory.NETWORK,
                PermissionScope.READ_NETWORK, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "limit" to Schemas.intSchema("返回条数（默认 20，最新在前）"),
                ),
            ) { args ->
                if (!com.webreverse.mcp.devtools.network.CdpNetworkMonitor.isIntercepting) {
                    return@tool McpToolResult.error("NOT_INTERCEPTING", "未开启拦截，请先 network.intercept enabled=true")
                }
                val limit = ToolArgs.int(args, "limit", 20)
                val list = com.webreverse.mcp.devtools.network.CdpNetworkMonitor.pausedRequests.value
                    .takeLast(limit).asReversed()
                McpToolResult.json(
                    buildJsonObject {
                        put("count", JsonPrimitive(list.size))
                        put(
                            "requests",
                            JsonArray(
                                list.map { p ->
                                    buildJsonObject {
                                        put("fetchId", JsonPrimitive(p.fetchId))
                                        put("url", JsonPrimitive(Redactor.redactUrl(p.url)))
                                        put("method", JsonPrimitive(p.method))
                                        put("resourceType", JsonPrimitive(p.resourceType))
                                        put(
                                            "headers",
                                            buildJsonObject {
                                                Redactor.redactHeaders(p.headers).forEach { (k, v) -> put(k, JsonPrimitive(v)) }
                                            },
                                        )
                                        p.postData?.let { put("postData", JsonPrimitive(it.take(4000))) }
                                    }
                                },
                            ),
                        )
                        if (list.isNotEmpty()) {
                            put(
                                "hint",
                                JsonPrimitive(
                                    "fetchId 用于后续操作：resume_request 放行（可改 url/headers/postData）、mock_response 伪造响应、abort_request 中止",
                                ),
                            )
                        }
                    },
                )
            },
            f.tool(
                "network.resume_request",
                "放行被拦截的请求（可先改写 url/method/headers/postData 再放行，例如替换 sign 参数测服务端校验；headers 传完整 JSON 对象整体替换）",
                ToolCategory.NETWORK,
                PermissionScope.MODIFY_NETWORK, RiskLevel.HIGH,
                inputSchema = Schemas.objectSchema(
                    "fetchId" to Schemas.strSchema("暂停请求 ID（来自 network.paused_requests，必填）"),
                    "url" to Schemas.strSchema("改写后的 URL（可选）"),
                    "method" to Schemas.strSchema("改写后的 HTTP 方法（可选）"),
                    "headers" to Schemas.strSchema("改写后的完整请求头 JSON 对象（可选，整体替换）"),
                    "postData" to Schemas.strSchema("改写后的请求体（可选）"),
                ),
            ) { args ->
                val fetchId = ToolArgs.str(args, "fetchId")
                if (fetchId.isBlank()) return@tool McpToolResult.error("INVALID_ARGS", "fetchId 必填")
                val paused = com.webreverse.mcp.devtools.network.CdpNetworkMonitor.pausedRequests.value
                    .firstOrNull { it.fetchId == fetchId }
                    ?: return@tool McpToolResult.error(
                        "REQUEST_NOT_FOUND",
                        "暂停请求不存在（可能已放行或 fetchId 错误），用 network.paused_requests 查看当前暂停列表",
                    )
                val headers = (args["headers"] as? JsonObject)
                    ?.entries?.associate { (k, v) -> k to (v as? JsonPrimitive)?.contentOrNull.orEmpty() }
                val modified = buildList {
                    ToolArgs.optStr(args, "url")?.let { add("url") }
                    ToolArgs.optStr(args, "method")?.let { add("method") }
                    if (headers != null) add("headers")
                    ToolArgs.optStr(args, "postData")?.let { add("postData") }
                }
                val ok = com.webreverse.mcp.devtools.network.CdpNetworkMonitor.resumePaused(
                    fetchId,
                    url = ToolArgs.optStr(args, "url"),
                    method = ToolArgs.optStr(args, "method"),
                    headers = headers,
                    postData = ToolArgs.optStr(args, "postData"),
                )
                if (ok) {
                    McpToolResult.json(
                        buildJsonObject {
                            put("resumed", JsonPrimitive(true))
                            put("url", JsonPrimitive(Redactor.redactUrl(paused.url)))
                            put("modified", JsonArray(modified.map { JsonPrimitive(it) }))
                        },
                    )
                } else {
                    McpToolResult.error("RESUME_FAILED", "Fetch.continueRequest 调用失败（CDP 会话可能已断开）")
                }
            },
            f.tool(
                "network.mock_response",
                "用自定义响应直接回复被拦截的请求（不访问服务器，Mock 语义）：伪造接口返回测前端逻辑、绕过校验、构造异常分支",
                ToolCategory.NETWORK,
                PermissionScope.MODIFY_NETWORK, RiskLevel.HIGH,
                inputSchema = Schemas.objectSchema(
                    "fetchId" to Schemas.strSchema("暂停请求 ID（必填）"),
                    "body" to Schemas.strSchema("响应体内容（必填，通常是 JSON 字符串）"),
                    "status" to Schemas.intSchema("HTTP 状态码（默认 200）"),
                    "mimeType" to Schemas.strSchema("Content-Type（默认 application/json）"),
                ),
            ) { args ->
                val fetchId = ToolArgs.str(args, "fetchId")
                val body = ToolArgs.str(args, "body")
                if (fetchId.isBlank() || body.isBlank()) {
                    return@tool McpToolResult.error("INVALID_ARGS", "fetchId 与 body 必填")
                }
                val paused = com.webreverse.mcp.devtools.network.CdpNetworkMonitor.pausedRequests.value
                    .firstOrNull { it.fetchId == fetchId }
                    ?: return@tool McpToolResult.error(
                        "REQUEST_NOT_FOUND",
                        "暂停请求不存在（可能已放行或 fetchId 错误），用 network.paused_requests 查看当前暂停列表",
                    )
                val ok = com.webreverse.mcp.devtools.network.CdpNetworkMonitor.mockPausedResponse(
                    fetchId,
                    body,
                    status = ToolArgs.int(args, "status", 200),
                    mimeType = ToolArgs.str(args, "mimeType", "application/json"),
                )
                if (ok) {
                    McpToolResult.json(
                        buildJsonObject {
                            put("mocked", JsonPrimitive(true))
                            put("url", JsonPrimitive(Redactor.redactUrl(paused.url)))
                            put("status", JsonPrimitive(ToolArgs.int(args, "status", 200)))
                            put("bodyLength", JsonPrimitive(body.length))
                        },
                    )
                } else {
                    McpToolResult.error("MOCK_FAILED", "Fetch.fulfillRequest 调用失败（CDP 会话可能已断开）")
                }
            },
            f.tool(
                "network.abort_request",
                "中止被拦截的请求（页面收到网络错误）——测前端容错/降级逻辑",
                ToolCategory.NETWORK,
                PermissionScope.MODIFY_NETWORK, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "fetchId" to Schemas.strSchema("暂停请求 ID（必填）"),
                ),
            ) { args ->
                val fetchId = ToolArgs.str(args, "fetchId")
                if (fetchId.isBlank()) return@tool McpToolResult.error("INVALID_ARGS", "fetchId 必填")
                val paused = com.webreverse.mcp.devtools.network.CdpNetworkMonitor.pausedRequests.value
                    .firstOrNull { it.fetchId == fetchId }
                    ?: return@tool McpToolResult.error(
                        "REQUEST_NOT_FOUND",
                        "暂停请求不存在（可能已放行或 fetchId 错误），用 network.paused_requests 查看当前暂停列表",
                    )
                val ok = com.webreverse.mcp.devtools.network.CdpNetworkMonitor.abortPaused(fetchId)
                if (ok) {
                    McpToolResult.json(
                        buildJsonObject {
                            put("aborted", JsonPrimitive(true))
                            put("url", JsonPrimitive(Redactor.redactUrl(paused.url)))
                        },
                    )
                } else {
                    McpToolResult.error("ABORT_FAILED", "Fetch.failRequest 调用失败（CDP 会话可能已断开）")
                }
            },
            // ============ CDP 仿真控制（UA/请求头/缓存） ============
            f.tool(
                "network.set_user_agent",
                "UA 覆盖（CDP Emulation.setUserAgentOverride）：改 navigator.userAgent 与后续请求头，绕过 UA 风控/伪装设备环境（经 CDP 会话生效，共享同一条 CDP 会话的客户端同步可见；reload 后全量生效）",
                ToolCategory.NETWORK,
                PermissionScope.MODIFY_NETWORK, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "userAgent" to Schemas.strSchema("UA 字符串（必填，非空）"),
                    "acceptLanguage" to Schemas.strSchema("Accept-Language（可选）"),
                    "platform" to Schemas.strSchema("navigator.platform（可选，如 Win32/Linux armv8l）"),
                ),
            ) { args ->
                val ua = ToolArgs.str(args, "userAgent")
                if (ua.isBlank()) return@tool McpToolResult.error("INVALID_ARGS", "userAgent 必填（恢复默认请传页面原始 UA，page.info 可查）")
                if (!ensureCdpAttached(deps)) {
                    return@tool McpToolResult.error("CDP_ATTACH_FAILED", cdpAttachError())
                }
                val ok = com.webreverse.mcp.devtools.network.CdpNetworkMonitor.setUserAgentOverride(
                    ua,
                    ToolArgs.str(args, "acceptLanguage"),
                    ToolArgs.str(args, "platform"),
                )
                if (ok) {
                    McpToolResult.json(
                        buildJsonObject {
                            put("overridden", JsonPrimitive(true))
                            put("userAgent", JsonPrimitive(ua))
                            put("hint", JsonPrimitive("browser.reload 后新 UA 全量生效（请求头+navigator.userAgent）"))
                        },
                    )
                } else {
                    McpToolResult.error("UA_OVERRIDE_FAILED", "Emulation.setUserAgentOverride 调用失败（CDP 会话可能已断开）")
                }
            },
            f.tool(
                "network.set_extra_headers",
                "全局附加请求头（CDP Network.setExtraHTTPHeaders）：所有后续请求自动携带；签名接口测试常用（注入 trace/debug 头观察服务端差异）；headers 传空对象清除",
                ToolCategory.NETWORK,
                PermissionScope.MODIFY_NETWORK, RiskLevel.HIGH,
                inputSchema = Schemas.objectSchema(
                    "headers" to Schemas.strSchema("请求头 JSON 对象（如 {\"X-Debug\":\"1\"}；空对象={} 清除）"),
                ),
            ) { args ->
                if (!ensureCdpAttached(deps)) {
                    return@tool McpToolResult.error("CDP_ATTACH_FAILED", cdpAttachError())
                }
                val headers = (args["headers"] as? JsonObject)
                    ?.entries?.associate { (k, v) -> k to (v as? JsonPrimitive)?.contentOrNull.orEmpty() }
                    ?: return@tool McpToolResult.error("INVALID_ARGS", "headers 必须是 JSON 对象")
                val ok = com.webreverse.mcp.devtools.network.CdpNetworkMonitor.setExtraHeaders(headers)
                if (ok) {
                    McpToolResult.json(
                        buildJsonObject {
                            put("applied", JsonPrimitive(true))
                            put("headerCount", JsonPrimitive(headers.size))
                            put("headers", buildJsonObject { headers.forEach { (k, v) -> put(k, JsonPrimitive(v)) } })
                            put("hint", JsonPrimitive("仅对后续新请求生效；清除传 {}"))
                        },
                    )
                } else {
                    McpToolResult.error("SET_HEADERS_FAILED", "Network.setExtraHTTPHeaders 调用失败（CDP 会话可能已断开）")
                }
            },
            f.tool(
                "network.set_cache_disabled",
                "禁用/启用缓存（CDP Network.setCacheDisabled）：true=强制所有请求走网络（防缓存干扰分析，响应才是真服务端数据）",
                ToolCategory.NETWORK,
                PermissionScope.MODIFY_NETWORK, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "disabled" to Schemas.boolSchema("true=禁用缓存 / false=恢复（必填）"),
                ),
            ) { args ->
                if (!ensureCdpAttached(deps)) {
                    return@tool McpToolResult.error("CDP_ATTACH_FAILED", cdpAttachError())
                }
                val disabled = ToolArgs.bool(args, "disabled", true)
                val ok = com.webreverse.mcp.devtools.network.CdpNetworkMonitor.setCacheDisabled(disabled)
                if (ok) {
                    McpToolResult.json(
                        buildJsonObject {
                            put("cacheDisabled", JsonPrimitive(disabled))
                            if (disabled) put("hint", JsonPrimitive("后续请求强制走网络（含 reload），分析签名接口时防缓存干扰"))
                        },
                    )
                } else {
                    McpToolResult.error("SET_CACHE_FAILED", "Network.setCacheDisabled 调用失败（CDP 会话可能已断开）")
                }
            },
            f.tool(
                "network.cdp_ws_frames",
                "列出 CDP 捕获的 WebSocket 帧（需 network.attach_cdp；文本帧原样、二进制帧附 HEX/base64/UTF-8 三视图；实时签名/推送接口的逆向通道）",
                ToolCategory.NETWORK,
                PermissionScope.READ_NETWORK, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "urlFilter" to Schemas.strSchema("WS URL 子串过滤（可选）"),
                    "limit" to Schemas.intSchema("返回条数（默认 50，最新在前）"),
                    "direction" to Schemas.strSchema("方向过滤：send / receive（可选）"),
                ),
            ) { args ->
                if (!com.webreverse.mcp.devtools.network.CdpNetworkMonitor.isAttached) {
                    return@tool McpToolResult.error("CDP_NOT_ATTACHED", "请先调用 network.attach_cdp")
                }
                val urlFilter = ToolArgs.str(args, "urlFilter")
                val direction = ToolArgs.str(args, "direction")
                val limit = ToolArgs.int(args, "limit", 50)
                val frames = com.webreverse.mcp.devtools.network.CdpNetworkMonitor.listWsFrames(urlFilter, limit * 2)
                    .filter { direction.isBlank() || it.direction == direction }
                    .take(limit)
                McpToolResult.json(
                    buildJsonObject {
                        put("count", JsonPrimitive(frames.size))
                        put(
                            "frames",
                            JsonArray(
                                frames.map { fr ->
                                    buildJsonObject {
                                        put("url", JsonPrimitive(Redactor.redactUrl(fr.url)))
                                        put("direction", JsonPrimitive(fr.direction))
                                        put("opcode", JsonPrimitive(fr.opcode))
                                        put("timestamp", JsonPrimitive(fr.timestamp))
                                        put("payload", JsonPrimitive(fr.payload))
                                        // 二进制帧附 HEX/base64/UTF-8 三视图（对齐桌面 DevTools）
                                        if (fr.opcode == 2) {
                                            val view = com.webreverse.mcp.devtools.network.CdpNetworkMonitor.decodeWsBinary(fr.payload)
                                            if (view != null) {
                                                put("isBinary", JsonPrimitive(true))
                                                put("length", JsonPrimitive(view.length))
                                                put("hex", JsonPrimitive(view.hex))
                                                put("base64", JsonPrimitive(view.base64))
                                                put("utf8", JsonPrimitive(view.utf8))
                                            }
                                        }
                                    }
                                },
                            ),
                        )
                        if (frames.isNotEmpty()) {
                            put("hint", JsonPrimitive("二进制帧（opcode=2）附 hex/base64/utf8 三视图，对齐桌面 DevTools；持续观察可 event.wait network.websocket"))
                        }
                    },
                )
            },
            f.tool(
                "network.cdp_sse_messages",
                "列出 CDP 捕获的 SSE/EventSource 推送消息（需 network.attach_cdp；实时推送/流式接口的逆向通道，含 eventName/eventId/data）",
                ToolCategory.NETWORK,
                PermissionScope.READ_NETWORK, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "urlFilter" to Schemas.strSchema("URL 子串过滤（可选）"),
                    "limit" to Schemas.intSchema("返回条数（默认 50，最新在前）"),
                ),
            ) { args ->
                if (!com.webreverse.mcp.devtools.network.CdpNetworkMonitor.isAttached) {
                    return@tool McpToolResult.error("CDP_NOT_ATTACHED", "请先调用 network.attach_cdp")
                }
                val urlFilter = ToolArgs.str(args, "urlFilter")
                val limit = ToolArgs.int(args, "limit", 50)
                val msgs = com.webreverse.mcp.devtools.network.CdpNetworkMonitor.listSseMessages(urlFilter, limit)
                McpToolResult.json(
                    buildJsonObject {
                        put("count", JsonPrimitive(msgs.size))
                        put(
                            "messages",
                            JsonArray(
                                msgs.map { m ->
                                    buildJsonObject {
                                        put("url", JsonPrimitive(Redactor.redactUrl(m.url)))
                                        put("eventName", JsonPrimitive(m.eventName))
                                        put("eventId", JsonPrimitive(m.eventId))
                                        put("timestamp", JsonPrimitive(m.timestamp))
                                        put("data", JsonPrimitive(m.data))
                                    }
                                },
                            ),
                        )
                        if (msgs.isNotEmpty()) {
                            put("hint", JsonPrimitive("SSE 消息为服务端单向推送，data 常为 JSON；持续观察可 event.wait network.sse"))
                        }
                    },
                )
            },
            f.tool(
                "network.cdp_ws_connections",
                "列出 CDP 捕获的 WebSocket 连接详情（需 network.attach_cdp；含握手请求/响应头、状态码、关闭码/原因——分析 WS 鉴权头与连接生命周期）",
                ToolCategory.NETWORK,
                PermissionScope.READ_NETWORK, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "urlFilter" to Schemas.strSchema("WS URL 子串过滤（可选）"),
                    "limit" to Schemas.intSchema("返回条数（默认 50，最新在前）"),
                ),
            ) { args ->
                if (!com.webreverse.mcp.devtools.network.CdpNetworkMonitor.isAttached) {
                    return@tool McpToolResult.error("CDP_NOT_ATTACHED", "请先调用 network.attach_cdp")
                }
                val urlFilter = ToolArgs.str(args, "urlFilter")
                val limit = ToolArgs.int(args, "limit", 50)
                val conns = com.webreverse.mcp.devtools.network.CdpNetworkMonitor.listWsConnections(urlFilter, limit)
                McpToolResult.json(
                    buildJsonObject {
                        put("count", JsonPrimitive(conns.size))
                        put(
                            "connections",
                            JsonArray(
                                conns.map { c ->
                                    buildJsonObject {
                                        put("url", JsonPrimitive(Redactor.redactUrl(c.url)))
                                        put("status", JsonPrimitive(c.status))
                                        put("statusText", JsonPrimitive(c.statusText))
                                        put("closeCode", JsonPrimitive(c.closeCode))
                                        put("closeReason", JsonPrimitive(c.closeReason))
                                        put("createdAt", JsonPrimitive(c.createdAt))
                                        put(
                                            "requestHeaders",
                                            buildJsonObject { c.requestHeaders.forEach { (k, v) -> put(k, JsonPrimitive(v)) } },
                                        )
                                        put(
                                            "responseHeaders",
                                            buildJsonObject { c.responseHeaders.forEach { (k, v) -> put(k, JsonPrimitive(v)) } },
                                        )
                                    }
                                },
                            ),
                        )
                        if (conns.isNotEmpty()) {
                            put("hint", JsonPrimitive("握手头含 Sec-WebSocket-Key/Authorization 等鉴权信息；closeCode 1000=正常关闭，1006=异常断开"))
                        }
                    },
                )
            },
            f.tool(
                "network.cdp_ws_analyze",
                "分析 CDP 捕获的 WebSocket 帧（需 network.attach_cdp；文本帧自动 JSON 解析，二进制帧附 HEX/base64/UTF-8 三视图并按 UTF-8 尝试 JSON，可关键字过滤/仅 JSON——实时签名与推送协议的逆向利器）",
                ToolCategory.NETWORK,
                PermissionScope.READ_NETWORK, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "urlFilter" to Schemas.strSchema("WS URL 子串过滤（可选）"),
                    "keyword" to Schemas.strSchema("帧内容关键字过滤（子串，忽略大小写，可选）"),
                    "jsonOnly" to Schemas.boolSchema("仅返回可解析为 JSON 的帧（默认 false）"),
                    "limit" to Schemas.intSchema("返回条数（默认 50，最新在前）"),
                ),
            ) { args ->
                if (!com.webreverse.mcp.devtools.network.CdpNetworkMonitor.isAttached) {
                    return@tool McpToolResult.error("CDP_NOT_ATTACHED", "请先调用 network.attach_cdp")
                }
                val urlFilter = ToolArgs.str(args, "urlFilter")
                val keyword = ToolArgs.str(args, "keyword")
                val jsonOnly = ToolArgs.bool(args, "jsonOnly", false)
                val limit = ToolArgs.int(args, "limit", 50).coerceIn(1, 200)
                val frames = com.webreverse.mcp.devtools.network.CdpNetworkMonitor.analyzeWsFrames(urlFilter, keyword, jsonOnly, limit)
                McpToolResult.json(
                    buildJsonObject {
                        put("count", JsonPrimitive(frames.size))
                        put(
                            "frames",
                            JsonArray(
                                frames.map { fr ->
                                    buildJsonObject {
                                        put("url", JsonPrimitive(Redactor.redactUrl(fr["url"] as? String ?: "")))
                                        put("direction", JsonPrimitive(fr["direction"] as? String ?: ""))
                                        put("timestamp", JsonPrimitive(fr["timestamp"] as? Long ?: 0L))
                                        put("opcode", JsonPrimitive(fr["opcode"] as? Int ?: 1))
                                        put("isBinary", JsonPrimitive(fr["isBinary"] as? Boolean ?: false))
                                        put("isJson", JsonPrimitive(fr["isJson"] as? Boolean ?: false))
                                        put("payload", JsonPrimitive(fr["payload"] as? String ?: ""))
                                        // 二进制帧三视图（对齐桌面 DevTools）
                                        (fr["length"] as? Int)?.let { put("length", JsonPrimitive(it)) }
                                        (fr["hex"] as? String)?.let { put("hex", JsonPrimitive(it)) }
                                        (fr["base64"] as? String)?.let { put("base64", JsonPrimitive(it)) }
                                        (fr["utf8"] as? String)?.let { put("utf8", JsonPrimitive(it)) }
                                    }
                                },
                            ),
                        )
                        if (frames.isNotEmpty()) {
                            put("hint", JsonPrimitive("isJson=true 表示帧为结构化 JSON，可直接用于协议逆向；二进制帧（isBinary=true）附 hex/base64/utf8 三视图；可配合 keyword 过滤定位签名/鉴权消息"))
                        }
                    },
                )
            },
            f.tool(
                "network.cdp_ws_binary",
                "列出 CDP 捕获的 WebSocket 二进制帧，DevTools 风格 HEX/base64/UTF-8 三视图（需 network.attach_cdp；对齐桌面浏览器 DevTools 的 binary message 查看方式——hex 十六进制、base64 原始编码、utf8 文本解码，供直接阅读二进制协议）",
                ToolCategory.NETWORK,
                PermissionScope.READ_NETWORK, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "urlFilter" to Schemas.strSchema("WS URL 子串过滤（可选）"),
                    "limit" to Schemas.intSchema("返回条数（默认 50，最新在前）"),
                ),
            ) { args ->
                if (!com.webreverse.mcp.devtools.network.CdpNetworkMonitor.isAttached) {
                    return@tool McpToolResult.error("CDP_NOT_ATTACHED", "请先调用 network.attach_cdp")
                }
                val urlFilter = ToolArgs.str(args, "urlFilter")
                val limit = ToolArgs.int(args, "limit", 50).coerceIn(1, 200)
                val frames = com.webreverse.mcp.devtools.network.CdpNetworkMonitor.listBinaryWsFrames(urlFilter, limit)
                McpToolResult.json(
                    buildJsonObject {
                        put("count", JsonPrimitive(frames.size))
                        put(
                            "frames",
                            JsonArray(
                                frames.map { fr ->
                                    buildJsonObject {
                                        put("url", JsonPrimitive(Redactor.redactUrl(fr["url"] as? String ?: "")))
                                        put("direction", JsonPrimitive(fr["direction"] as? String ?: ""))
                                        put("timestamp", JsonPrimitive(fr["timestamp"] as? Long ?: 0L))
                                        put("length", JsonPrimitive(fr["length"] as? Int ?: 0))
                                        put("hex", JsonPrimitive(fr["hex"] as? String ?: ""))
                                        put("base64", JsonPrimitive(fr["base64"] as? String ?: ""))
                                        put("utf8", JsonPrimitive(fr["utf8"] as? String ?: ""))
                                    }
                                },
                            ),
                        )
                        if (frames.isNotEmpty()) {
                            put("hint", JsonPrimitive("二进制帧三视图：hex=十六进制（空格分隔）、base64=原始编码、utf8=文本解码（不可打印字符以 . 显示）；可配合 network.cdp_ws_analyze jsonOnly 定位 JSON 型二进制帧"))
                        }
                    },
                )
            },
        )
    }

    /** 确保网络监控的 CDP 会话已附加（未附加时自动附加到当前页面） */
    private suspend fun ensureCdpAttached(deps: ToolDependencies): Boolean {
        if (com.webreverse.mcp.devtools.network.CdpNetworkMonitor.isAttached) return true
        // 页面主线程瞬时阻塞时首轮 Network.enable 常超时，附加重试 2 次（内部已按幂等重试）
        repeat(3) {
            if (com.webreverse.mcp.devtools.network.CdpNetworkMonitor.attach(deps.activeSession().engine)) return true
            kotlinx.coroutines.delay(150L)
        }
        return false
    }

    private fun cdpAttachError(): String =
        "CDP 附加失败" + (com.webreverse.mcp.devtools.protocol.cdp.CdpTransport.lastError?.let { "：$it" } ?: "（DevTools socket 不可用，稍后重试）")
}
