package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.browser.engine.util.JsScripts
import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import com.webreverse.mcp.workspace.core.EvidenceCorrelator
import com.webreverse.mcp.javascript.analysis.AntiDebugDetector
import com.webreverse.mcp.javascript.analysis.BrowserEnvironmentSynthesizer
import com.webreverse.mcp.javascript.analysis.NetworkUsageKind
import com.webreverse.mcp.javascript.analysis.PauseLoopDetector
import com.webreverse.mcp.javascript.analysis.ScriptInterceptor
import com.webreverse.mcp.mcp.tools.terminal.NodeRunResult
import com.webreverse.mcp.mcp.tools.terminal.TerminalEngine
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/**
 * 逆向能力发现 + 复合工具（P1：把 300+ 工具的暴露面压缩为「能力 + 命名空间 + 高价值复合入口」）。
 *
 * 动机：LLM 层的工具选择成本随工具数线性上涨（Tool Selection Cost）。与其让 Agent 每次面对
 * 300+ 工具，不如让它先问：
 * - reverse.capabilities  → 当前环境具备哪些能力（network/debugger/hook/wasm/jsvmp ...）
 * - reverse.tools("network") → 该能力下暴露哪些高价值入口
 * - network.inspect        → 一个复合工具完成「搜索→详情→initiator→关联」全链路
 *
 * 底层 Tool 仍存在（mcp.tools 可查全量），但 LLM 日常只要抓住这几个入口即可。
 */
object ReverseDiscoveryTools {

    /** 命名空间 → 人类可读能力 + 后端就绪态 */
    fun capabilities(deps: ToolDependencies): Map<String, Map<String, String>> = linkedMapOf(
        "browser" to mapOf("label" to "浏览器控制", "ready" to "true", "hint" to "open/back/forward/screenshot/source"),
        "tab" to mapOf("label" to "标签页管理", "ready" to "true", "hint" to "list/activate/create/pin_session"),
        "dom" to mapOf("label" to "DOM 探查", "ready" to "true", "hint" to "query/click/fill/get_html"),
        "page" to mapOf("label" to "页面控制", "ready" to "true", "hint" to "get_source/inspect/api_list"),
        "network" to mapOf("label" to "网络分析", "ready" to "true", "hint" to "list/get/search/curl/websocket/replay/inspect(复合)"),
        "storage" to mapOf("label" to "存储分析", "ready" to "true", "hint" to "local_storage/cookies/indexeddb"),
        "debugger" to mapOf("label" to "JS 调试", "ready" to (deps.debuggerManager.backend != "none").toString(), "hint" to "attach/breakpoint/pause/resume/runtime_evaluate"),
        "target" to mapOf("label" to "Target 域(Worker/SW/iframe)", "ready" to (deps.debuggerManager.backend == "cdp").toString(), "hint" to "list/attach/evaluate/enable_debugger/list_scripts"),
        "script_rewrite" to mapOf("label" to "执行前脚本改写(Fetch Response 闭环)", "ready" to (deps.debuggerManager.backend == "cdp").toString(), "hint" to "enable/add_rule/remove_rule/rules/records"),
        "dynamic" to mapOf("label" to "运行时动态执行", "ready" to "true", "hint" to "code_list/code_get/add_rule/trace_function/monitor_object"),
        "hook" to mapOf("label" to "运行时 Hook", "ready" to "true", "hint" to "add/list/events"),
        "javascript" to mapOf("label" to "JS 动态执行", "ready" to "true", "hint" to "execute/call_function"),
        "static" to mapOf("label" to "JS 静态分析(AST/CFG/DFG)", "ready" to "true", "hint" to "cfg/call_graph/detect_obfuscation/sourcemap"),
        "wasm" to mapOf("label" to "WASM 分析", "ready" to "true", "hint" to "list_modules/disassemble"),
        "vmp" to mapOf("label" to "JSVMP 反虚拟机", "ready" to "true", "hint" to "detect/ir_translate/debugger.detect_vmp"),
        "evidence" to mapOf("label" to "证据库", "ready" to "true", "hint" to "query/record/correlate/stats"),
        "graph" to mapOf("label" to "逆向图谱", "ready" to "true", "hint" to "query/link/stats"),
        "pipeline" to mapOf("label" to "分析流水线", "ready" to "true", "hint" to "list/run(recon/api_trace/token_trace/crypto_link/snapshot)"),
        "investigation" to mapOf("label" to "逆向调查引擎", "ready" to "true", "hint" to "start/plan/status/next/action_done/list/history/resume/reproduce"),
        "workspace" to mapOf("label" to "工作区", "ready" to "true", "hint" to "list/findings/export"),
        "mcp" to mapOf("label" to "MCP 管理", "ready" to "true", "hint" to "status/tools/tool_schema"),
    )

    /**
     * 命名空间 → 高价值入口清单（而非全量），降低 LLM 选择成本。
     *
     * 幽灵工具名修复：本清单曾包含十余个从未注册的工具名
     * （browser.snapshot / tab.switch / dom.snapshot / page.eval / debugger.evaluate /
     * static.dfg / wasm.imports / vmp.deep_analyze 等）——Agent 按 hint 调用即
     * TOOL_NOT_FOUND。现已逐一对照 registry 实际注册名修正；运行时另有
     * mapNotNull 过滤兜底，即使再出现漂移也不会把幽灵名透出给 LLM。
     */
    private val curatedTools: Map<String, List<String>> = linkedMapOf(
        "browser" to listOf("browser.open", "browser.back", "browser.forward", "browser.screenshot", "browser.source"),
        "tab" to listOf("tab.list", "tab.activate", "tab.create", "tab.pin_session"),
        "dom" to listOf("dom.query", "dom.click", "dom.fill", "dom.get_html"),
        "page" to listOf("page.get_source", "page.inspect", "page.api_list"),
        "network" to listOf("network.inspect", "network.list", "network.get", "network.search", "network.curl", "network.replay", "network.websocket"),
        "storage" to listOf("storage.local_storage", "storage.cookies", "storage.indexeddb"),
        "debugger" to listOf("debugger.attach", "debugger.set_breakpoint", "debugger.pause", "debugger.resume", "debugger.runtime_evaluate", "debugger.list_scripts"),
        "target" to listOf("target.list", "target.attach", "target.evaluate", "target.enable_debugger", "target.list_scripts"),
        "script_rewrite" to listOf("script_rewrite.enable", "script_rewrite.add_rule", "script_rewrite.remove_rule", "script_rewrite.rules", "script_rewrite.records"),
        "dynamic" to listOf("dynamic.code_list", "dynamic.code_get", "dynamic.code_add_rule", "dynamic.code_stats", "dynamic.trace_function", "dynamic.monitor_object"),
        "hook" to listOf("hook.add", "hook.list", "hook.events"),
        "javascript" to listOf("javascript.execute", "js.call_function"),
        "static" to listOf("static.cfg", "static.call_graph", "js.detect_obfuscation", "re.sourcemap"),
        "wasm" to listOf("wasm.list_modules", "wasm.disassemble"),
        "vmp" to listOf("vmp.detect", "vmp.ir_translate", "debugger.detect_vmp"),
        "evidence" to listOf("evidence.query", "evidence.correlate", "evidence.record", "evidence.stats"),
        "graph" to listOf("graph.query", "graph.link", "graph.stats"),
        "pipeline" to listOf("pipeline.list", "pipeline.run"),
        "investigation" to listOf("investigation.start", "investigation.plan", "investigation.status", "investigation.next", "investigation.action_done", "investigation.list", "investigation.history", "investigation.resume", "investigation.reproduce"),
        "workspace" to listOf("workspace.list", "workspace.list_findings", "workspace.save_analysis"),
        "mcp" to listOf("mcp.status", "mcp.tools", "mcp.tool_schema"),
    )

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)
        return listOf(
            f.tool(
                "reverse.capabilities", "查询当前逆向平台具备的能力总览 + 各能力后端就绪态（适合 Agent 开场先探测）", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val sessionId = deps.context()?.sessionId ?: ""
                val engine = runCatching { deps.activeSession().engine }.getOrNull()
                val netEntries = engine?.let { runCatching { deps.networkInspector.getEntries(it).size }.getOrDefault(0) } ?: 0
                val hookInstalled = deps.hookEngine.events.value.size
                val investigationActive = InvestigationTools.forSession(sessionId).size
                McpToolResult.json(buildJsonObject {
                    put("capabilities", buildJsonObject {
                        capabilities(deps).forEach { (ns, info) ->
                            put(ns, info["ready"] ?: "true")
                        }
                    })
                    put("detail", buildJsonObject {
                        capabilities(deps).forEach { (ns, info) ->
                            put(ns, buildJsonObject {
                                put("label", info["label"] ?: ns)
                                put("ready", info["ready"] ?: "false")
                                put("hint", info["hint"] ?: "")
                            })
                        }
                        // 运行时动态状态（区别于静态 Feature Exists，供给 Agent 规划）
                        put("runtime", buildJsonObject {
                            put("network.entries", netEntries)
                            put("hook.hits", hookInstalled)
                            put("investigation.active", investigationActive)
                            put("debugger.attached", deps.debuggerManager.backend != "none")
                        })
                    })
                    put("totalTools", deps.toolRegistry.count())
                    put("hint", JsonPrimitive("reverse.tools(namespace) 查看某能力的高价值入口；mcp.tools 查看全量"))
                })
            },
            f.tool(
                "reverse.tools", "查看某能力命名空间下的高价值工具入口（network/debugger/hook/static/wasm/vmp/evidence/graph/pipeline/investigation...）", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "namespace" to Schemas.strSchema("能力命名空间名（reverse.capabilities 列出）"),
                    "all" to Schemas.boolSchema("true 返回该空间全部工具而非仅高价值入口（默认 false）"),
                ),
            ) { args ->
                val ns = ToolArgs.str(args, "namespace").lowercase()
                val listAll = ToolArgs.bool(args, "all", false)
                val metadata = deps.toolRegistry.listMetadata()
                val curated = curatedTools[ns]
                McpToolResult.json(buildJsonObject {
                    put("namespace", ns)
                    if (listAll) {
                        val all = metadata.filter { it.name.startsWith("$ns.") }
                        put("count", all.size)
                        put("tools", JsonArray(all.map { buildJsonObject {
                            put("name", it.name)
                            put("description", it.description)
                        } }))
                    } else {
                        val curatedMeta = curated?.mapNotNull { name -> metadata.firstOrNull { it.name == name } } ?: emptyList()
                        put("count", curatedMeta.size)
                        put("tools", JsonArray(curatedMeta.map { buildJsonObject {
                            put("name", it.name)
                            put("description", it.description)
                        } }))
                        put("hint", JsonPrimitive("以上为高价值入口；传 all=true 查看该空间全部工具（含底层细粒度）"))
                    }
                })
            },
            f.tool(
                "network.inspect", "复合工具：一次调用完成网络请求深挖（搜索→详情→initiator→调用函数→签名关联），返回完整上下文给 LLM", ToolCategory.NETWORK,
                PermissionScope.READ_NETWORK, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "query" to Schemas.strSchema("URL 关键词（必填）"),
                    "include" to Schemas.arraySchema("包含哪些视图：request/response/initiator/body/headers/callers/correlation（默认全含）"),
                    "limit" to Schemas.intSchema("最多分析几条（默认 5）"),
                    "correlate" to Schemas.boolSchema("对候选请求做加密签名关联（默认 false）"),
                ),
                timeoutMs = 60_000,
            ) { args ->
                val query = ToolArgs.str(args, "query")
                if (query.isBlank()) return@tool McpToolResult.error("INVALID_ARGS", "query 不能为空")
                val limit = ToolArgs.int(args, "limit", 5)
                val include = ToolArgs.optStr(args, "include")?.split(",")?.map { it.trim().lowercase() }?.toSet()
                    ?: setOf("request", "response", "initiator", "body", "headers", "callers")
                val doCorrelate = ToolArgs.bool(args, "correlate", false)
                val session = deps.activeSession()
                val engine = session.engine

                val entries = runCatching { deps.networkInspector.getEntries(engine) }
                    .getOrDefault(emptyList())
                    .filter { it.url.contains(query, true) }
                    .take(limit)
                if (entries.isEmpty()) {
                    return@tool McpToolResult.error("NOT_FOUND", "无匹配 '$query' 的请求（先触发该接口，或 network.list 确认）")
                }

                // 递归搜索 initiator 脚本定位源码调用点
                val callers = mutableListOf<JsonObject>()
                if (include.contains("callers")) {
                    val scriptUrls = entries.mapNotNull { firstFrameUrl(it.initiatorStack) }.distinct().take(3)
                    if (deps.debuggerManager.backend == "cdp") {
                        runCatching {
                            deps.debuggerManager.listScripts(engine)
                                .filter { s -> scriptUrls.any { s.url.contains(it.substringBefore('?'), true) } || s.url.startsWith("http") }
                                .take(6)
                                .forEach { s ->
                                    val hits = deps.debuggerManager.searchScriptContent(engine, s.scriptId, query, limit = 3).getOrNull() ?: return@forEach
                                    if (hits.isNotEmpty()) {
                                        callers.add(buildJsonObject {
                                            put("script", s.url.substringAfterLast('/').take(120))
                                            put("url", s.url)
                                            put("sourceHits", JsonArray(hits.take(3).map { h ->
                                                buildJsonObject {
                                                    val obj = h.jsonObject
                                                    obj["line"]?.let { put("line", it) }
                                                    obj["context"]?.let { put("context", it) }
                                                    obj["content"]?.let { put("content", it) }
                                                }
                                            }))
                                        })
                                    }
                                }
                        }
                    }
                }

                // 签名关联（复用多证据评分器，需要加密 Hook 命中）
                var correlation: JsonObject? = null
                if (doCorrelate) {
                    val hits = deps.hookEngine.events.value
                        .filter { it.result.isNotBlank() }
                        .take(40)
                        .map { hv -> EvidenceCorrelator.CryptoHit(hv.target.ifBlank { hv.ruleName }, hv.stackTrace, hv.timestamp, hv.tabId, "", hv.result, hv.arguments) }
                    val requests = entries.map { n -> EvidenceCorrelator.RequestCandidate(n.url, n.url.substringBefore('?'), n.startedAt, n.tabId, "", n.initiatorStack, n.requestHeaders, n.requestBody.orEmpty()) }
                    val result = EvidenceCorrelator().relate(hits, requests, keepBestPerRequest = true, minScore = 20)
                    result.firstOrNull()?.let { c ->
                        correlation = buildJsonObject {
                            put("function", c.function)
                            put("relation", c.relation)
                            put("confidence", JsonPrimitive(c.confidence))
                            put("signals", JsonArray(c.matchedSignals.map { JsonPrimitive(it) }))
                        }
                    }
                }

                McpToolResult.json(buildJsonObject {
                    put("query", query)
                    put("count", entries.size)
                    put("requests", JsonArray(entries.map { e ->
                        buildJsonObject {
                            put("id", e.id)
                            put("method", e.method.name)
                            put("url", e.url)
                            put("status", e.status)
                            put("memory", "${e.requestBodySize}B → ${e.responseBodySize}B")
                            put("mimeType", e.mimeType)
                            put("resourceType", e.resourceType.display)
                            if (include.contains("headers")) {
                                put("requestHeaders", buildJsonObject { e.requestHeaders.forEach { (k, v) -> put(k, v.take(200)) } })
                            }
                            if (include.contains("body")) {
                                put("requestBody", e.requestBody?.take(600) ?: "")
                                put("responsePreview", e.responseBody?.take(400) ?: "")
                            }
                            if (include.contains("initiator")) {
                                put("initiator", e.initiator.take(200))
                                put("initiatorStack", e.initiatorStack.take(600))
                            }
                            if (include.contains("timing")) {
                                put("startedAt", e.startedAt)
                                put("durationMs", e.durationMs)
                            }
                        }
                    }))
                    if (include.contains("callers")) {
                        put("callers", JsonArray(callers))
                    }
                    if (correlation != null) {
                        put("signatureCorrelation", correlation)
                    }
                    put(
                        "nextSteps",
                        JsonArray(
                            buildList {
                                add("network.curl id=${entries.first().id} 导出 curl 复现")
                                if (correlation != null) add("evidence.correlate function=<签名函数> 深度验证")
                                else add("pipeline.run name=crypto_link 关联该接口签名（需先 hook.add type=crypto）")
                                add("investigation.start goal=signature_analysis target=$query 做端到端调查")
                            }.map { JsonPrimitive(it) },
                        ),
                    )
                })
            },
            // ---- ：反调试/环境合成编排工具（参考 ChatGPT 报告 §7/§9/§10/§43）----
            f.tool(
                "reverse.detect_protection", "检测当前页面脚本的反调试保护（debugger/循环/尺寸检测/Console陷阱等），并给出恢复建议（四级暂停循环状态机）", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "scriptUrl" to Schemas.strSchema("可选：仅检测指定脚本 URL"),
                    "includeSource" to Schemas.boolSchema("是否对命中的脚本做执行前拦截改写预览（transform 中和 debugger），默认 true"),
                ),
                timeoutMs = 60_000,
            ) { args ->
                val scriptUrlFilter = ToolArgs.str(args, "scriptUrl").trim()
                val includeTransform = ToolArgs.bool(args, "includeSource", true)
                val session = runCatching { deps.activeSession() }.getOrElse { null }
                val engine = session?.engine
                val ad = deps.antiDebugDetector
                val pl = deps.pauseLoopDetector
                val si = deps.scriptInterceptor

                // 全页面脚本扫描（细粒度+粗粒度双通道收集，避免漏检）
                val perScript = mutableListOf<JsonObject>()
                if (engine != null && deps.debuggerManager.backend == "cdp") {
                    val scripts = runCatching { deps.debuggerManager.listScripts(engine) }.getOrDefault(emptyList())
                    // 统计：扫描总数/命中反调试/命中 pause 循环
                    scripts
                        .filter { it.url.ifBlank { it.scriptId }.isNotBlank() }
                        .filter { scriptUrlFilter.isBlank() || it.url.contains(scriptUrlFilter, true) }
                        .take(120)
                        .forEach { s ->
                            val srcResult = runCatching { deps.debuggerManager.getScriptSource(engine, s.scriptId, 120_000) }
                                .getOrNull()
                            val src = srcResult?.getOrNull() ?: return@forEach
                            if (src.isBlank()) return@forEach
                            val det = ad.detect(src, url = s.url, scriptId = s.scriptId)
                            if (det.techniques.isNotEmpty()) {
                                val obs = pl.observe(s.url.ifBlank { s.scriptId })
                                perScript.add(buildJsonObject {
                                    put("scriptId", s.scriptId)
                                    put("url", s.url.take(300))
                                    put("risk", JsonPrimitive(det.risk))
                                    put("techniques", JsonArray(det.techniques.map { JsonPrimitive(it) }))
                                    put("pauseLoop", obs.level.label)
                                    put("pauseCount", obs.pauseCount)
                                    if (includeTransform) {
                                        val tr = si.transform(src)
                                        if (tr.debuggerNeutralized > 0) {
                                            put("transform", buildJsonObject {
                                                put("debuggerNeutralized", tr.debuggerNeutralized)
                                                put("transformHash", tr.transformedHash)
                                                put("sri", tr.sriCompatibility.name)
                                            })
                                        }
                                    }
                                })
                            }
                        }
                }

                val pauseReport = pl.report()
                // 聚合：命中反调试的脚本数、最高风险、最高恢复级别
                val hitScripts = perScript.size
                val maxRisk = perScript.maxOfOrNull { it["risk"]?.let { v -> (v as? JsonPrimitive)?.content?.toDoubleOrNull() } ?: 0.0 } ?: 0.0
                McpToolResult.json(buildJsonObject {
                    put("summary", buildJsonObject {
                        put("protectionDetected", hitScripts > 0 || pauseReport.inLoop)
                        put("pausedScripts", perScript.size)
                        put("maxRisk", JsonPrimitive(maxRisk))
                        put("pauseLoopActive", pauseReport.inLoop)
                        put("pauseRecoveryLevel", pauseReport.overallLevel.label)
                        put("totalPauses", pauseReport.totalPauses)
                    })
                    put("scripts", JsonArray(perScript.take(40)))
                    if (pauseReport.inLoop) {
                        put("pauseLoop", buildJsonObject {
                            put("overallLevel", pauseReport.overallLevel.label)
                            put("totalPauses", pauseReport.totalPauses)
                            put("scripts", JsonArray(pauseReport.scripts.map { o -> buildJsonObject {
                                put("url", o.url.take(300))
                                put("pauseCount", o.pauseCount)
                                put("level", o.level.label)
                            } }))
                        })
                    }
                    put("recoveryRecommendation", pauseReport.recommendation)
                    put(
                        "nextSteps",
                        JsonArray(
                            buildList {
                                if (hitScripts > 0) {
                                    add("reverse.intercept_debugger 生成执行前拦截改写配置，从根本上中和 debugger"
                                        + if (pauseReport.inLoop) "（当前已触发暂停循环，拦截改写是唯一根治路径）" else "")
                                } else {
                                    add("未发现明显反调试特征；可 attach 调试器后正常下断点")
                                }
                                add("debugger.attach 附加调试器核对")
                            }.map { JsonPrimitive(it) },
                        ),
                    )
                })
            },
            f.tool(
                "reverse.infer_environment", "静态预扫描 JS 源码，推断其依赖的浏览器全局/路径/网络能力，并生成可直接注入 Node 隔离上下文的 shim（参考报告 §43）", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "source" to Schemas.strSchema("JS 源码（必填；可用 page.eval 拿到，或用工具从脚本注入）"),
                    "includeShim" to Schemas.boolSchema("是否返回生成的 shim 引导脚本（默认 true）"),
                ),
                timeoutMs = 30_000,
            ) { args ->
                val source = ToolArgs.str(args, "source")
                if (source.isBlank()) return@tool McpToolResult.error("INVALID_ARGS", "source 不能为空（可先 page.eval 拿到源码）")
                val includeShim = ToolArgs.bool(args, "includeShim", true)
                val inf = deps.browserEnvSynthesizer.infer(source)
                McpToolResult.json(buildJsonObject {
                    put("requiredGlobals", JsonArray(inf.requiredGlobals.map { JsonPrimitive(it) }))
                    put("requiredPaths", JsonArray(inf.requiredPaths.map { JsonPrimitive(it) }))
                    put("capabilities", buildJsonObject { inf.capabilities.forEach { (k, v) -> put(k, JsonPrimitive(v)) } })
                    put("networkUsage", inf.networkUsage.name)
                    put("networkPolicy", when (inf.networkUsage) {
                        NetworkUsageKind.CAPTURED_ONLY -> "检测到敏感认证信息（cookie/token/sign 等），网络仅回放捕获：请求不直连，只使用 Hook 捕获的响应（防泄漏/防被探测）"
                        NetworkUsageKind.NONE -> "未发现网络依赖，可直接在隔离上下文执行"
                        NetworkUsageKind.TARGET_ONLY -> "存在网络依赖且无敏感认证信息，可在受限目标域内放行（结合 Hook 捕获与目标白名单）"
                        NetworkUsageKind.FULL -> "完全放开网络（不推荐默认启用，需人工确认）"
                    })
                    if (includeShim) {
                        val shim = deps.browserEnvSynthesizer.buildShim(inf.capabilities)
                        val validation = deps.browserEnvSynthesizer.validateShim(shim)
                        put("shimLength", shim.length)
                        put("shimValid", JsonPrimitive(validation.valid))
                        put("shimIssues", JsonArray(validation.issues.map { JsonPrimitive(it) }))
                        put("shim", shim.take(4000))
                        put(
                            "shimNotes",
                            JsonArray(
                                buildList {
                                    add("将 shim 与源码拼接后，在 Node 隔离上下文执行即可")
                                    add("若运行时报缺全局：调用 reverse.backfill_environment 合并缺漏并重新生成 shim（错误驱动闭环）")
                                    add("需要真实浏览器值：调用 reverse.capture_environment 采集后回填")
                                    if (!validation.valid) add("shim 语法校验未通过，请勿直接注入执行，先修复定界符问题")
                                }.map { JsonPrimitive(it) },
                            ),
                        )
                    }
                })
            },
            f.tool(
                "reverse.capture_environment", "在真实浏览器（当前 WebView 页面）采集浏览器环境值（captureableKeys 清单），返回可直接喂给 buildShim 的 captured 映射与带真实值的 Node shim（打通 captureableKeys → 真实浏览器采集管线）", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "keys" to Schemas.arraySchema("可选：要采集的 key 清单（缺省采集全部 captureableKeys）"),
                    "includeShim" to Schemas.boolSchema("是否同时生成带真实捕获值的 shim（默认 true）"),
                ),
                timeoutMs = 30_000,
            ) { args ->
                val engine = runCatching { deps.activeSession().engine }.getOrNull()
                    ?: return@tool McpToolResult.error("NO_ENGINE", "当前无活动浏览器会话，请先 browser.open 打开页面")
                val allKeys = deps.browserEnvSynthesizer.captureableKeys()
                val requested = args["keys"]?.jsonArray?.mapNotNull { (it as? JsonPrimitive)?.content }
                val keys = if (requested.isNullOrEmpty()) allKeys else requested.filter { it in allKeys }
                if (keys.isEmpty()) return@tool McpToolResult.error("INVALID_ARGS", "keys 为空或不在可采集清单内")
                val script = JsScripts.captureEnvScript(keys)
                val raw = engine.evaluateJavascript(script)
                val captured = LinkedHashMap<String, String>()
                if (!raw.isNullOrBlank()) {
                    runCatching {
                        Json.parseToJsonElement(raw).jsonObject.forEach { (k, v) ->
                            if (v !is JsonNull) captured[k] = v.toString()
                        }
                    }
                }
                val includeShim = ToolArgs.bool(args, "includeShim", true)
                McpToolResult.json(buildJsonObject {
                    put("capturedCount", captured.size)
                    put("requestedCount", keys.size)
                    put("captured", buildJsonObject {
                        captured.forEach { (k, v) ->
                            put(k, runCatching { Json.parseToJsonElement(v) }.getOrElse { JsonPrimitive(v) })
                        }
                    })
                    put(
                        "notes",
                        JsonArray(
                            buildList {
                                add("captured 值已是 JSON 表达式形式，可直接作为 buildShim 的 captured 参数")
                                add("未采集到的 key（缺失/不可序列化）不会出现在 captured 中")
                                add("canvas.*/webgl.* 为真实执行采集的几何指纹项（2D 渲染/字体度量/WebGL 枚举表），回填后 Node shim 的 toDataURL/measureText/getParameter 输出与真机一致")
                            }.map { JsonPrimitive(it) },
                        ),
                    )
                    if (includeShim) {
                        val caps = keys.associateWith { true }
                        val shim = deps.browserEnvSynthesizer.buildShim(caps, captured)
                        val validation = deps.browserEnvSynthesizer.validateShim(shim)
                        put("shimLength", shim.length)
                        put("shimValid", JsonPrimitive(validation.valid))
                        put("shimIssues", JsonArray(validation.issues.map { JsonPrimitive(it) }))
                        put("shim", shim.take(4000))
                    }
                })
            },
            f.tool(
                "reverse.backfill_environment", "错误驱动补环境闭环：把 Node 运行时报缺的全局/路径合并进已有 capabilities，重新生成 shim（参考报告 §22 错误驱动回填）", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "capabilities" to Schemas.strSchema("已有 capabilities（JSON 对象字符串，取自 reverse.infer_environment 的 capabilities 字段）"),
                    "missingGlobals" to Schemas.arraySchema("Node 运行时报缺的全局名列表（如 ReferenceError: crypto is not defined → [\"crypto\"]）"),
                    "missingPaths" to Schemas.arraySchema("可选：报缺的嵌套路径列表（如 [\"window.crypto.subtle\"]）"),
                    "includeShim" to Schemas.boolSchema("是否返回合并后的 shim（默认 true）"),
                ),
                timeoutMs = 30_000,
            ) { args ->
                val capsJson = ToolArgs.str(args, "capabilities")
                val existing = LinkedHashMap<String, Boolean>()
                if (capsJson.isNotBlank()) {
                    runCatching {
                        Json.parseToJsonElement(capsJson).jsonObject.forEach { (k, v) ->
                            existing[k] = (v as? JsonPrimitive)?.content?.toBooleanStrictOrNull() ?: true
                        }
                    }
                }
                val missingGlobals = args["missingGlobals"]?.jsonArray?.mapNotNull { (it as? JsonPrimitive)?.content } ?: emptyList()
                val missingPaths = args["missingPaths"]?.jsonArray?.mapNotNull { (it as? JsonPrimitive)?.content } ?: emptyList()
                val missing = (missingGlobals + missingPaths).distinct()
                if (missing.isEmpty()) return@tool McpToolResult.error("INVALID_ARGS", "missingGlobals/missingPaths 至少提供一个")
                val merged = deps.browserEnvSynthesizer.mergeShim(existing, missing)
                val includeShim = ToolArgs.bool(args, "includeShim", true)
                McpToolResult.json(buildJsonObject {
                    put("mergedCapabilities", buildJsonObject { merged.forEach { (k, v) -> put(k, JsonPrimitive(v)) } })
                    put("added", JsonArray(missing.filter { it !in existing }.map { JsonPrimitive(it) }))
                    put("alreadyPresent", JsonArray(missing.filter { it in existing }.map { JsonPrimitive(it) }))
                    put(
                        "notes",
                        JsonArray(
                            buildList {
                                add("把 mergedCapabilities 作为下次 reverse.infer_environment 的输入，或直接使用下方 shim")
                                add("未知全局会走通用兜底分支补成空对象，可再结合 reverse.capture_environment 采集真实值回填")
                            }.map { JsonPrimitive(it) },
                        ),
                    )
                    if (includeShim) {
                        val shim = deps.browserEnvSynthesizer.buildShim(merged)
                        val validation = deps.browserEnvSynthesizer.validateShim(shim)
                        put("shimLength", shim.length)
                        put("shimValid", JsonPrimitive(validation.valid))
                        put("shimIssues", JsonArray(validation.issues.map { JsonPrimitive(it) }))
                        put("shim", shim.take(4000))
                    }
                })
            },
            f.tool(
                "reverse.run_environment", "真实 Node 执行器闭环：把 shim+源码写入临时文件，先跑 node --check 真实语法校验，再执行；自动解析 ReferenceError 报缺全局并回填重建 shim，循环直至通过或达到轮次上限（打通真实 Node 执行 + 错误驱动自动回填）", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "source" to Schemas.strSchema("要执行的 JS 源码（必填）"),
                    "capabilities" to Schemas.strSchema("可选：已有 capabilities（JSON 对象字符串，取自 reverse.infer_environment）"),
                    "captured" to Schemas.strSchema("可选：真实浏览器捕获值（JSON 对象字符串，取自 reverse.capture_environment）"),
                    "maxBackfillRounds" to Schemas.intSchema("可选：自动回填轮次上限（默认 3，0 表示不回填）"),
                    "timeoutMs" to Schemas.intSchema("可选：单次执行超时（毫秒，默认 120000）"),
                ),
                timeoutMs = 300_000,
            ) { args ->
                val source = ToolArgs.str(args, "source")
                if (source.isBlank()) return@tool McpToolResult.error("INVALID_ARGS", "source 不能为空")
                val capabilities = LinkedHashMap<String, Boolean>()
                ToolArgs.str(args, "capabilities").takeIf { it.isNotBlank() }?.let { capsJson ->
                    runCatching {
                        Json.parseToJsonElement(capsJson).jsonObject.forEach { (k, v) ->
                            capabilities[k] = (v as? JsonPrimitive)?.content?.toBooleanStrictOrNull() ?: true
                        }
                    }
                }
                val captured = LinkedHashMap<String, String>()
                ToolArgs.str(args, "captured").takeIf { it.isNotBlank() }?.let { capturedJson ->
                    runCatching {
                        Json.parseToJsonElement(capturedJson).jsonObject.forEach { (k, v) ->
                            captured[k] = v.toString()
                        }
                    }
                }
                val maxRounds = ToolArgs.int(args, "maxBackfillRounds", 3)
                val timeoutMs = ToolArgs.int(args, "timeoutMs", 120_000)

                val rounds = mutableListOf<JsonObject>()
                var currentCaps: Map<String, Boolean> = capabilities
                var lastResult: NodeRunResult? = null
                var round = 0
                while (true) {
                    val shim = deps.browserEnvSynthesizer.buildShim(currentCaps, captured)
                    val composed = composeShimAndSource(shim, source)
                    val result = deps.terminalEngine.runNode(composed, timeoutMs = timeoutMs.toLong())
                    lastResult = result
                    val missing = extractMissingGlobals(result.output)
                    rounds.add(buildJsonObject {
                        put("round", round)
                        put("syntaxValid", result.syntaxValid)
                        put("exitCode", result.exitCode)
                        put("timedOut", result.timedOut)
                        put("missingGlobals", JsonArray(missing.map { JsonPrimitive(it) }))
                        put("output", result.output.take(2000))
                    })
                    if (!result.syntaxValid) break
                    if (missing.isEmpty()) break
                    if (maxRounds <= 0 || round >= maxRounds) break
                    val added = missing.filter { it !in currentCaps }
                    if (added.isEmpty()) break
                    currentCaps = deps.browserEnvSynthesizer.mergeShim(currentCaps, added)
                    round++
                }
                val final = lastResult
                McpToolResult.json(buildJsonObject {
                    put("rounds", JsonArray(rounds))
                    put("roundCount", rounds.size)
                    put("finalSyntaxValid", final?.syntaxValid == true)
                    put("finalExitCode", final?.exitCode ?: -1)
                    put("finalTimedOut", final?.timedOut == true)
                    put("finalOutput", (final?.output ?: "").take(4000))
                    put("finalCapabilities", buildJsonObject { currentCaps.forEach { (k, v) -> put(k, JsonPrimitive(v)) } })
                    put(
                        "notes",
                        JsonArray(
                            buildList {
                                add("已自动解析 ReferenceError 并回填缺失全局（见各 round.missingGlobals 与 finalCapabilities）")
                                add("若仍有缺失：把 finalCapabilities 传给 reverse.backfill_environment 手动补充，或 reverse.capture_environment 采集真实值")
                                if (final?.syntaxValid == false) add("node --check 语法校验未通过，请检查 shim 与源码拼接后的语法")
                            }.map { JsonPrimitive(it) },
                        ),
                    )
                })
            },
            f.tool(
                "reverse.intercept_debugger", "生成针对反调试脚本的执行前拦截改写配置（中和 debugger 语句/构造器/定时器循环），按脚本 URL 起效", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "source" to Schemas.strSchema("待改写的 JS 源码（必填；取命中的脚本源码即可）"),
                    "url" to Schemas.strSchema("脚本来源 URL，用于标记拦截规则"),
                ),
                timeoutMs = 30_000,
            ) { args ->
                val source = ToolArgs.str(args, "source")
                if (source.isBlank()) return@tool McpToolResult.error("INVALID_ARGS", "source 不能为空")
                val url = ToolArgs.str(args, "url")
                val det = deps.antiDebugDetector.detect(source, url = url)
                val tr = deps.scriptInterceptor.transform(source)
                McpToolResult.json(buildJsonObject {
                    put("url", url)
                    put("debuggerNeutralized", tr.debuggerNeutralized)
                    put("antiDebug", JsonArray(det.techniques.map { JsonPrimitive(it) }))
                    put("risk", JsonPrimitive(det.risk))
                    put("originalHash", tr.originalHash)
                    put("transformedHash", tr.transformedHash)
                    put("sri", tr.sriCompatibility.name)
                    if (det.techniques.isNotEmpty() && tr.debuggerNeutralized == 0) {
                        put("warning", "已识别反调试特征，但当前改写未命中可中和的 debugger 结构——这类常为运行时生成（eval/Worker），需在运行时拦截")
                    }
                    put("transformed", tr.transformed.take(4000))
                    put("notes", JsonArray(tr.notes.map { JsonPrimitive(it) }))
                })
            },
        )
    }

    /** 从 initiator 栈解析首个 http(s) 脚本 URL */
    private val stackFrameRegex = Regex("""at\s+(?:([\w$.]+)\s+\()?(https?://[^):\s]+):(\d+):(\d+)?""")

    private fun firstFrameUrl(stack: String): String? {
        val m = stackFrameRegex.find(stack) ?: return null
        return m.groupValues[2].takeIf { it.isNotBlank() }
    }

    // ---- reverse.run_environment 辅助 ----

    /** 把 shim 与源码拼接为可在 Node 中直接执行的完整脚本 */
    private fun composeShimAndSource(shim: String, source: String): String {
        val expose = listOf(
            "window", "document", "navigator", "location", "history", "screen",
            "localStorage", "sessionStorage", "performance", "crypto", "fetch",
            "XMLHttpRequest", "WebSocket", "atob", "btoa", "TextEncoder", "TextDecoder",
            "URL", "URLSearchParams", "Blob", "File", "FormData", "DOMParser",
            "MutationObserver", "IntersectionObserver", "ResizeObserver",
            // 几何指纹一致性：canvas/WebGL 桩类与像素比暴露为全局
            "HTMLCanvasElement", "CanvasRenderingContext2D", "WebGLRenderingContext",
            "WebGL2RenderingContext", "devicePixelRatio",
        ).joinToString(",") { "'$it'" }
        return buildString {
            append(shim).append("\n")
            append("// ---- 暴露 shim 出的浏览器环境为全局（供源码引用；已存在的 Node 原生全局不覆盖）----\n")
            append("var __env = globalThis.__WRMCP_BROWSER_ENV__;\n")
            append("var __win = __env.window;\n")
            append("var __expose = [$expose];\n")
            append("for (var i=0;i<__expose.length;i++){ var g=__expose[i]; if (typeof globalThis[g]==='undefined' && __win[g]!==undefined){ try{ globalThis[g]=__win[g]; }catch(e){} } }\n")
            append("// ---- 源码 ----\n")
            append(source).append("\n")
        }
    }

    /* * 从 Node 输出解析报缺的浏览器对象（ReferenceError / TypeError / undefined 递归读取， 增强） */
    private fun extractMissingGlobals(output: String): List<String> {
        val re = Regex("ReferenceError:\\s*([A-Za-z_$][A-Za-z0-9_$]*)\\s+is not defined")
        val missing = re.findAll(output).map { it.groupValues[1] }.toMutableList()
        // TypeError: foo.bar is not a function -> 顶层对象 foo 需要补齐方法/对象
        val reFn = Regex("TypeError:\\s*([A-Za-z_$][A-Za-z0-9_$]*(?:\\.[A-Za-z_$][A-Za-z0-9_$]*)*)\\s+is not a function")
        missing.addAll(reFn.findAll(output).map { it.groupValues[1].substringBefore('.') })
        // Cannot read properties of undefined (reading 'x') / Cannot read property 'x' of undefined -> 顶层对象缺失
        val reUndef = Regex("Cannot read propert(?:y|ies).*?(?:of (?:undefined|null)|'undefined').*?['\"]([A-Za-z_$][A-Za-z0-9_$]*)['\"]", setOf(RegexOption.IGNORE_CASE))
        missing.addAll(reUndef.findAll(output).map { it.groupValues[1] })
        return missing.filter { it !in BROWSER_ENV_SCRIPT_GLOBALS }.distinct().toList()
    }

    /** 由 shim 内部补齐、无需回填的 JS 基础全局 */
    private val BROWSER_ENV_SCRIPT_GLOBALS = setOf(
        "require", "module", "exports", "process", "global", "Buffer", "console",
        "setTimeout", "setInterval", "clearTimeout", "clearInterval", "queueMicrotask",
        "__dirname", "fetch", "URL", "URLSearchParams", "TextEncoder", "TextDecoder", "crypto",
    )
}