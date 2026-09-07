package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.common.model.Confidence
import com.webreverse.mcp.core.common.model.Finding
import com.webreverse.mcp.core.common.model.FindingType
import com.webreverse.mcp.core.common.model.Severity
import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import com.webreverse.mcp.workspace.core.EvidenceCorrelator
import com.webreverse.mcp.workspace.core.EvidenceSource
import com.webreverse.mcp.workspace.core.GraphEdgeType
import com.webreverse.mcp.workspace.core.GraphNodeType
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import java.util.UUID

/**
 * Evidence Tools：证据库 / 逆向图谱 / 分析流水线。
 *
 * 设计动机（对应整体架构升级方向）：
 * - 不再堆工具数量，而是把 300+ 工具的产出汇聚成一张可查询的逆向知识图谱；
 * - 被动层（EvidenceStore 订阅 EventBus）自动沉淀网络/Hook/断点/控制台证据；
 * - 主动层（本文件的 5 条流水线）编排现有能力完成端到端逆向链路：
 *   recon 全景侦察 / api_trace 接口调用链 / token_trace 令牌溯源 /
 *   crypto_link 加密关联 / snapshot 运行时现场。
 */
object EvidenceTools {

    /** 一条分析流水线的规格定义 */
    data class PipelineSpec(
        val name: String,
        val description: String,
        val params: List<Pair<String, String>>,
        val run: suspend (deps: ToolDependencies, args: JsonObject) -> JsonObject,
    )

    // ================================================================
    // MCP 工具注册
    // ================================================================

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)
        val store = deps.evidenceStore
        return listOf(
            f.tool(
                "evidence.query", "查询证据库：自动沉淀的网络/Hook/断点/控制台/流水线证据，按来源、关键词、时间窗过滤", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "source" to Schemas.strSchema("证据来源过滤：network/hook/debugger/console/browser/websocket/snapshot/manual/pipeline"),
                    "keyword" to Schemas.strSchema("关键词（匹配标题与数据字段）"),
                    "sinceMinutes" to Schemas.intSchema("只看最近 N 分钟"),
                    "limit" to Schemas.intSchema("返回条数上限（默认 50）"),
                ),
            ) { args ->
                val source = ToolArgs.str(args, "source").lowercase().let {
                    runCatching { EvidenceSource.valueOf(it.uppercase()) }.getOrNull()
                }
                val keyword = ToolArgs.optStr(args, "keyword")
                val since = ToolArgs.optInt(args, "sinceMinutes")?.let { it * 60_000L }?.let { System.currentTimeMillis() - it }
                val limit = ToolArgs.int(args, "limit", 50)
                val list = store.queryEvidence(source, keyword, since, limit)
                McpToolResult.json(
                    buildJsonObject {
                        put("count", list.size)
                        put(
                            "evidence",
                            JsonArray(list.map { evidenceJson(it) }),
                        )
                        put(
                            "hint",
                            JsonPrimitive(
                                "证据由 EventBus 自动沉淀，无需手动采集；graph.query 可查这些事实构成的图谱链路",
                            ),
                        )
                    },
                )
            },
            f.tool(
                "evidence.record", "手动记录一条证据（AI 中途结论、人工观察、外部信息入图谱）", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "title" to Schemas.strSchema("证据标题（必填）"),
                    "kind" to Schemas.strSchema("证据类别（如 conclusion/observation）"),
                    "data" to Schemas.strSchema("附加数据 key=value;key=value"),
                ),
            ) { args ->
                val title = ToolArgs.str(args, "title")
                if (title.isBlank()) return@tool McpToolResult.error("INVALID_ARGS", "title 不能为空")
                val kind = ToolArgs.str(args, "kind", "conclusion")
                val data = ToolArgs.str(args, "data").split(";")
                    .mapNotNull { kv -> kv.split("=", limit = 2).takeIf { it.size == 2 }?.let { it[0].trim() to it[1].trim() } }
                    .toMap()
                val ev = store.record(EvidenceSource.MANUAL, "", kind, title, data)
                McpToolResult.json(buildJsonObject {
                    put("id", ev.id)
                    put("recorded", true)
                })
            },
            f.tool(
                "evidence.correlate", "多证据关联评分：对给定加密命中/敏感函数与网络请求做置信度打分（execCtx/调用栈/同Tab/时间/值级命中），输出 SIGNS 关系及 confidence，取代纯时间窗关联", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "function" to Schemas.strSchema("候选函数名（缺省自动取当前 Hook 加密命中）"),
                    "urlPattern" to Schemas.strSchema("请求 URL 关键词过滤（缺省全部）"),
                    "minScore" to Schemas.intSchema("最小命中分（默认 20）"),
                    "linkToGraph" to Schemas.boolSchema("把高置信度关联写入图谱 SIGNS 边（默认 true）"),
                ),
            ) { args ->
                val functionFilter = ToolArgs.optStr(args, "function")
                val urlPattern = ToolArgs.optStr(args, "urlPattern")
                val minScore = ToolArgs.int(args, "minScore", 20)
                val linkToGraph = ToolArgs.bool(args, "linkToGraph", true)
                val correlator = EvidenceCorrelator()

                // 加密命中候选
                val hookEvents = deps.hookEngine.events.value
                val hits = hookEvents
                    .filter { it.result.isNotBlank() }
                    .filter { functionFilter.isNullOrBlank() || it.target.contains(functionFilter, true) || it.ruleName.contains(functionFilter, true) }
                    .take(60)
                    .map { hv ->
                        EvidenceCorrelator.CryptoHit(
                            function = hv.target.ifBlank { hv.ruleName },
                            stackTrace = hv.stackTrace,
                            timestamp = hv.timestamp,
                            tabId = hv.tabId,
                            output = hv.result,
                            input = hv.arguments,
                        )
                    }

                // 请求候选
                val session = deps.activeSession()
                val engine = session.engine
                val requests = runCatching { deps.networkInspector.getEntries(engine) }.getOrDefault(emptyList())
                    .filter { urlPattern.isNullOrBlank() || it.url.contains(urlPattern, true) }
                    .take(400)
                    .map { n ->
                        EvidenceCorrelator.RequestCandidate(
                            url = n.url,
                            endpointKey = n.url.substringBefore('?').substringBefore('#'),
                            timestamp = n.startedAt,
                            tabId = n.tabId,
                            executionContextId = "",
                            stackTrace = n.initiatorStack,
                            headers = n.requestHeaders,
                            body = n.requestBody ?: n.responseBody.orEmpty(),
                        )
                    }

                val correlations = correlator.relate(hits, requests, keepBestPerRequest = true, minScore = minScore)

                // 高置信度写入图谱 SIGNS 边
                var linked = 0
                if (linkToGraph) {
                    correlations.filter { it.confidence >= 0.5 }.forEach { c ->
                        store.addNode(GraphNodeType.CRYPTO, c.function, key = "crypto:${c.function.take(80)}")
                        store.addNode(GraphNodeType.ENDPOINT, c.endpointUrl.take(120), url = c.endpointUrl, key = "ep:${c.endpointKey}")
                        store.addEdge("crypto:${c.function.take(80)}", "ep:${c.endpointKey}", GraphEdgeType.SIGNS)
                        linked++
                    }
                }

                McpToolResult.json(buildJsonObject {
                    put("analyzedHits", hits.size)
                    put("analyzedRequests", requests.size)
                    put("correlationCount", correlations.size)
                    put(
                        "correlations",
                        JsonArray(
                            correlations.take(30).map { c ->
                                buildJsonObject {
                                    put("function", c.function)
                                    put("relation", c.relation)
                                    put("confidence", JsonPrimitive(c.confidence))
                                    put("score", c.score)
                                    put("endpoint", c.endpointUrl.take(160))
                                    put("signals", JsonArray(c.matchedSignals.map { JsonPrimitive(it) }))
                                    put("provenance", JsonArray(c.provenance.map { p ->
                                        buildJsonObject {
                                            put("method", p.method)
                                            put("contribution", p.contribution)
                                            put("confidence", JsonPrimitive(p.confidence))
                                        }
                                    }))
                                }
                            },
                        ),
                    )
                    put("linkedToGraph", linked)
                    put("hint", JsonPrimitive("relation=SIGNS 且 confidence≥0.75 基本可判定签名函数→接口；POSSIBLE_SIGNS 需断点验证；provenance 列出每条判定依据"))
                })
            },
            f.tool(
                "evidence.stats", "证据库与图谱总览：各来源证据量、节点/边分布、时间范围", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                McpToolResult.json(buildJsonObject {
                    store.stats().forEach { (k, v) ->
                        when (v) {
                            is Map<*, *> -> put(
                                k,
                                buildJsonObject { v.forEach { (ik, iv) -> put(ik.toString(), JsonPrimitive(iv.toString())) } },
                            )
                            is Number -> put(k, JsonPrimitive(v))
                            else -> put(k, JsonPrimitive(v.toString()))
                        }
                    }
                })
            },
            f.tool(
                "graph.query", "查询逆向图谱：按节点类型/关键词找节点，或取某节点邻域子图（链路可视化数据）", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "node" to Schemas.strSchema("节点 key（如 ep:https://x.com/api/login），提供时返回其邻域子图"),
                    "type" to Schemas.strSchema("节点类型过滤：script/function/endpoint/token/crypto/storage/cookie/websocket/page"),
                    "keyword" to Schemas.strSchema("关键词（匹配节点标签或 URL）"),
                    "depth" to Schemas.intSchema("邻域展开深度（默认 1，最大 3）"),
                    "limit" to Schemas.intSchema("节点列表上限（默认 30）"),
                ),
            ) { args ->
                val nodeKey = ToolArgs.optStr(args, "node")
                if (!nodeKey.isNullOrBlank()) {
                    val node = store.node(nodeKey) ?: return@tool McpToolResult.error("NOT_FOUND", "节点不存在: $nodeKey（graph.stats 查看已有节点类型分布）")
                    val depth = ToolArgs.int(args, "depth", 1)
                    val (nodes, edges) = store.neighborhood(nodeKey, depth)
                    return@tool McpToolResult.json(buildJsonObject {
                        put("root", nodeJson(node))
                        put("nodes", JsonArray(nodes.map { nodeJson(it) }))
                        put("edges", JsonArray(edges.map { edgeJson(it) }))
                    })
                }
                val type = ToolArgs.str(args, "type").lowercase().let {
                    runCatching { GraphNodeType.valueOf(it.uppercase()) }.getOrNull()
                }
                val keyword = ToolArgs.optStr(args, "keyword")
                val limit = ToolArgs.int(args, "limit", 30)
                val nodes = store.queryNodes(type, keyword, limit)
                McpToolResult.json(buildJsonObject {
                    put("count", nodes.size)
                    put(
                        "nodes",
                        JsonArray(
                            nodes.map { n ->
                                buildJsonObject {
                                    put("key", n.key)
                                    put("type", n.type.name)
                                    put("label", n.label)
                                    put("url", n.url)
                                    put("line", n.line)
                                    put("hits", n.weight)
                                    val nb = store.edgesOf(n.key)
                                    put("edgeCount", nb.size)
                                }
                            },
                        ),
                    )
                    put("hint", JsonPrimitive("传 node=key 返回邻域子图；高 hits 节点是逆向入口"))
                })
            },
            f.tool(
                "graph.link", "手动建立图谱关系（AI 推断出 A 与 B 的联系时记录，跨会话可查）", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "from" to Schemas.strSchema("起点节点 key"),
                    "to" to Schemas.strSchema("终点节点 key"),
                    "type" to Schemas.strSchema("关系类型：calls/requests/generates/consumes/reads/writes/triggers/references/signs/flow"),
                ),
            ) { args ->
                val from = ToolArgs.str(args, "from")
                val to = ToolArgs.str(args, "to")
                val type = ToolArgs.str(args, "type", "references").let {
                    runCatching { GraphEdgeType.valueOf(it.uppercase()) }.getOrNull()
                } ?: GraphEdgeType.REFERENCES
                if (from.isBlank() || to.isBlank()) return@tool McpToolResult.error("INVALID_ARGS", "from/to 不能为空")
                val edge = store.addEdge(from, to, type)
                McpToolResult.json(buildJsonObject {
                    put("linked", edge != null)
                    if (edge != null) put("edge", edgeJson(edge))
                })
            },
            f.tool(
                "graph.stats", "图谱统计：节点/边分布、高权重枢纽（逆向最有价值的入口）、重点关系", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val stats = store.stats()
                McpToolResult.json(buildJsonObject {
                    put("nodes", (stats["nodeCount"] as? Int) ?: 0)
                    put("edges", (stats["edgeCount"] as? Int) ?: 0)
                    put(
                        "nodesByType",
                        buildJsonObject {
                            (stats["nodesByType"] as? Map<*, *>)?.forEach { (k, v) -> put(k.toString(), JsonPrimitive(v.toString())) }
                        },
                    )
                    put(
                        "edgesByType",
                        buildJsonObject {
                            (stats["edgesByType"] as? Map<*, *>)?.forEach { (k, v) -> put(k.toString(), JsonPrimitive(v.toString())) }
                        },
                    )
                    put("topNodes", JsonArray(store.topNodes(15).map { nodeJson(it) }))
                    put(
                        "topEdges",
                        JsonArray(
                            store.topEdges(15).map { e ->
                                buildJsonObject {
                                    put("from", e.from)
                                    put("to", e.to)
                                    put("type", e.type.name)
                                    put("hits", e.weight)
                                }
                            },
                        ),
                    )
                })
            },
            f.tool(
                "pipeline.list", "列出内置分析流水线（端到端逆向链路编排）", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                McpToolResult.json(buildJsonObject {
                    put(
                        "pipelines",
                        JsonArray(
                            pipelines.map { p ->
                                buildJsonObject {
                                    put("name", p.name)
                                    put("description", p.description)
                                    put(
                                        "params",
                                        buildJsonObject {
                                            p.params.forEach { (k, d) -> put(k, d) }
                                        },
                                    )
                                }
                            },
                        ),
                    )
                })
            },
            f.tool(
                "pipeline.run", "运行分析流水线：编排现有能力完成端到端链路（recon/api_trace/token_trace/crypto_link/snapshot），结果自动写入证据库与图谱", ToolCategory.REVERSE,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "name" to Schemas.strSchema("流水线名：recon / api_trace / token_trace / crypto_link / snapshot"),
                    "urlPattern" to Schemas.strSchema("[api_trace] URL 关键词"),
                    "key" to Schemas.strSchema("[token_trace] 存储键名（缺省自动发现令牌类键）"),
                    "saveFindings" to Schemas.boolSchema("结论写入工作区 Finding（默认 true）"),
                ),
                timeoutMs = 120_000,
            ) { args ->
                val name = ToolArgs.str(args, "name").lowercase()
                val spec = pipelines.firstOrNull { it.name == name }
                    ?: return@tool McpToolResult.error(
                        "UNKNOWN_PIPELINE",
                        "未知流水线: $name。可用：${pipelines.joinToString("/") { it.name }}（pipeline.list 查看参数）",
                    )
                val beforeNodes = deps.evidenceStore.stats()["nodeCount"] as? Int ?: 0
                val beforeEdges = deps.evidenceStore.stats()["edgeCount"] as? Int ?: 0
                val result = runCatching { spec.run(deps, args) }
                    .getOrElse {
                        return@tool McpToolResult.error("PIPELINE_FAILED", "${it.message ?: it.javaClass.simpleName}")
                    }
                val afterNodes = deps.evidenceStore.stats()["nodeCount"] as? Int ?: 0
                val afterEdges = deps.evidenceStore.stats()["edgeCount"] as? Int ?: 0
                McpToolResult.json(
                    buildJsonObject {
                        put("pipeline", name)
                        put("result", result)
                        put(
                            "graphDelta",
                            buildJsonObject {
                                put("nodesAdded", (afterNodes - beforeNodes).coerceAtLeast(0))
                                put("edgesAdded", (afterEdges - beforeEdges).coerceAtLeast(0))
                            },
                        )
                        put("hint", JsonPrimitive("graph.query node=<key> 查看链路；evidence.query source=pipeline 查看流水线沉淀的证据"))
                    },
                )
            },
        )
    }

    // ================================================================
    // 内置流水线
    // ================================================================

    private val pipelines: List<PipelineSpec> = listOf(
        PipelineSpec(
            name = "recon",
            description = "页面全景侦察：框架识别 + API 发现 + 脚本清单 + 混淆扫描 + 存储盘点，全部入图谱（逆向第一步）",
            params = listOf("saveFindings" to "结论写入工作区（默认 true）"),
            run = { deps, args -> runRecon(deps, args) },
        ),
        PipelineSpec(
            name = "api_trace",
            description = "接口调用链追踪：网络请求 → initiator 调用栈函数 → 引用脚本 → 混淆标记，生成 端点-函数-脚本 链路",
            params = listOf("urlPattern" to "URL 关键词（必填，如 api/login）", "saveFindings" to "结论写入工作区（默认 true）"),
            run = { deps, args -> runApiTrace(deps, args) },
        ),
        PipelineSpec(
            name = "token_trace",
            description = "令牌溯源：扫描 localStorage/sessionStorage/cookie 中的令牌类键 → 找引用脚本 → 建议监控点（值脱敏只记键名）",
            params = listOf("key" to "存储键名（缺省自动发现）", "saveFindings" to "结论写入工作区（默认 true）"),
            run = { deps, args -> runTokenTrace(deps, args) },
        ),
        PipelineSpec(
            name = "crypto_link",
            description = "加密关联分析（多证据置信度）：Hook 加密命中与网络请求做 execCtx/调用栈/同Tab/值级命中综合打分，输出每个接口的候选签名函数及 confidence（逆向核心链路）",
            params = listOf("minScore" to "最小关联分（默认 20）", "saveFindings" to "结论写入工作区（默认 true）"),
            run = { deps, args -> runCryptoLink(deps, args) },
        ),
        PipelineSpec(
            name = "snapshot",
            description = "运行时现场捕获：断点命中/暂停时抓取调用栈+局部变量入证据库，调用帧链自动建图（需先暂停）",
            params = listOf("saveFindings" to "结论写入工作区（默认 true）"),
            run = { deps, args -> runSnapshot(deps, args) },
        ),
    )

    // ================================================================
    // 供 Investigation 引擎驱动的公共入口（P1：investigation.* 高层编排）
    // ================================================================

    /** 内置流水线名 */
    val availablePipelines: List<String> get() = pipelines.map { it.name }

    /**
     * 按名运行内置流水线（供 Investigation 引擎逐阶段驱动）：
     * [EvidenceTools.all] 内部也可用；跨模块由 [com.webreverse.mcp.mcp.tools.InvestigationTools] 调用。
     */
    suspend fun runPipeline(deps: ToolDependencies, name: String, args: JsonObject): JsonObject {
        val spec = pipelines.firstOrNull { it.name.equals(name, ignoreCase = true) }
            ?: throw IllegalArgumentException("未知流水线: $name，可选: ${pipelines.joinToString("/") { it.name }}")
        return spec.run(deps, args)
    }

    // ================================================================
    // 流水线实现
    // ================================================================

    /** recon：页面全景侦察 */
    private suspend fun runRecon(deps: ToolDependencies, args: JsonObject): JsonObject {
        val store = deps.evidenceStore
        val session = deps.activeSession()
        val engine = session.engine
        val url = engine.currentUrl() ?: ""
        val pageKey = "page:${url.substringBefore('?').substringBefore('#')}"
        store.addNode(GraphNodeType.PAGE, url.take(120), url = url, key = pageKey)
        val ev = store.record(EvidenceSource.PIPELINE, session.tabId, "recon", "全景侦察 ${url.take(120)}")
        val steps = mutableListOf<JsonObject>()
        val saveFindings = ToolArgs.bool(args, "saveFindings", true)

        // 1. 框架/构建工具识别
        val framework = runCatching {
            val html = engine.getPageSource()?.take(400_000) ?: ""
            deps.frameworkDetector.detectFromJs(html)
        }.getOrNull()
        steps += step("framework", framework != null, "框架: ${framework?.frameworks?.joinToString(",").orEmpty().ifBlank { "未识别" }} / 构建: ${framework?.bundlers?.joinToString(",").orEmpty()}")

        // 2. API 发现（网络 + 源码）
        val entries = runCatching { deps.networkInspector.getEntries(engine) }.getOrDefault(emptyList())
        val apiFromNet = runCatching { deps.apiDiscoveryEngine.discoverFromNetwork(entries) }.getOrNull()
        val apiFromHtml = runCatching {
            engine.getPageSource()?.take(400_000)?.let { deps.apiDiscoveryEngine.discoverFromHtml(it, "html") }
        }.getOrNull()
        val endpoints = runCatching { deps.apiDiscoveryEngine.merge(apiFromNet ?: return@runCatching null, apiFromHtml ?: return@runCatching null) }
            .getOrNull()?.endpoints ?: (apiFromNet?.endpoints ?: emptyList()) + (apiFromHtml?.endpoints ?: emptyList())
        val seenKeys = mutableSetOf<String>()
        endpoints.take(60).forEach { ep ->
            val key = "ep:${ep.url.substringBefore('?').substringBefore('#')}"
            if (seenKeys.add(key)) {
                store.addNode(GraphNodeType.ENDPOINT, "${ep.method} ${ep.url.take(120)}", url = ep.url, key = key)
                store.addEdge(pageKey, key, GraphEdgeType.CONTAINS, ev.id)
            }
        }
        steps += step("api_discovery", true, "发现 ${seenKeys.size} 个端点（网络 ${entries.size} 条请求）")

        // 3. CDP 已附加：脚本清单 + top 混淆扫描
        var obfuscatedScripts = 0
        if (deps.debuggerManager.backend == "cdp") {
            val scripts = runCatching { deps.debuggerManager.listScripts(engine) }.getOrDefault(emptyList())
                .filter { it.url.startsWith("http") }
            scripts.take(40).forEach { s ->
                val key = "js:${s.url.substringBefore('?')}"
                store.addNode(GraphNodeType.SCRIPT, s.url.substringAfterLast('/').take(100), url = s.url, key = key)
                store.addEdge(pageKey, key, GraphEdgeType.CONTAINS, ev.id)
            }
            // 体积前 5 的脚本做混淆分析
            scripts.sortedByDescending { it.length }.take(5).forEach { s ->
                runCatching {
                    deps.debuggerManager.getScriptSource(engine, s.scriptId, 200_000).getOrNull()?.let { src ->
                        val report = deps.obfuscationAnalyzer.analyze(src)
                        if (report.isObfuscated) {
                            obfuscatedScripts++
                            if (saveFindings) saveFinding(
                                deps, FindingType.OBFUSCATION, "疑似混淆脚本: ${s.url.substringAfterLast('/')}",
                                "混淆得分 ${report.score}，特征: ${report.detected.take(5).joinToString(",")}",
                                evidence = src.take(200), source = s.url,
                            )
                        }
                    }
                }
            }
            steps += step("scripts", true, "脚本 ${scripts.size} 个（混淆疑点 ${obfuscatedScripts} 个）")
        } else {
            steps += step("scripts", false, "未附加 CDP，跳过脚本清单（debugger.attach 后重跑可得完整脚本图）")
        }

        // 4. 存储盘点（只记键名，值脱敏）
        val storageKeys = mutableListOf<String>()
        runCatching {
            engine.getLocalStorage().keys.forEach { storageKeys += it }
            engine.getSessionStorage().keys.forEach { storageKeys += it }
        }
        runCatching {
            engine.getCookies().forEach { c -> c["name"]?.let { storageKeys += "cookie:$it" } }
        }
        storageKeys.take(50).forEach { k ->
            if (isTokenishKey(k)) {
                store.addNode(GraphNodeType.TOKEN, k, key = "tok:$k")
            } else {
                store.addNode(GraphNodeType.STORAGE, k, key = "sto:$k")
            }
        }
        steps += step("storage", true, "存储键 ${storageKeys.size} 个（令牌类 ${storageKeys.count { isTokenishKey(it) }} 个）")

        // 5. 总结 Finding
        if (saveFindings) {
            saveFinding(
                deps, FindingType.FRAMEWORK, "侦察完成: ${url.take(80)}",
                "框架: ${framework?.frameworks?.joinToString(",").orEmpty().ifBlank { "未识别" }}；端点 ${seenKeys.size} 个；混淆脚本 ${obfuscatedScripts} 个；令牌类存储键 ${storageKeys.count { isTokenishKey(it) }} 个",
                evidence = url, source = url,
            )
        }
        return buildJsonObject {
            put("page", url)
            put("steps", JsonArray(steps))
            put(
                "endpoints",
                JsonArray(seenKeys.take(20).map { JsonPrimitive(it.removePrefix("ep:")) }),
            )
            put(
                "nextSteps",
                JsonArray(
                    listOf(
                        "api_trace 深挖重点接口的调用链（函数+脚本）",
                        "token_trace 溯源令牌生成位置",
                        "crypto_link 关联加密函数与接口签名",
                    ).map { JsonPrimitive(it) },
                ),
            )
        }
    }

    /** api_trace：接口调用链（端点 → initiator 函数 → 引用脚本） */
    private suspend fun runApiTrace(deps: ToolDependencies, args: JsonObject): JsonObject {
        val pattern = ToolArgs.str(args, "urlPattern")
        if (pattern.isBlank()) throw IllegalArgumentException("urlPattern 不能为空")
        val store = deps.evidenceStore
        val session = deps.activeSession()
        val engine = session.engine
        val saveFindings = ToolArgs.bool(args, "saveFindings", true)
        val steps = mutableListOf<JsonObject>()

        // 1. 匹配的网络请求
        val entries = runCatching { deps.networkInspector.search(engine, pattern) }.getOrDefault(emptyList())
            .ifEmpty { runCatching { deps.networkInspector.getEntries(engine) }.getOrDefault(emptyList()).filter { it.url.contains(pattern, true) } }
            .take(20)
        if (entries.isEmpty()) throw IllegalArgumentException("无匹配 '$pattern' 的网络请求（先触发该接口，或检查关键词）")
        val endpointKeys = mutableSetOf<String>()
        entries.forEach { entry ->
            val key = "ep:${entry.url.substringBefore('?').substringBefore('#')}"
            endpointKeys += key
            store.addNode(GraphNodeType.ENDPOINT, "${entry.method} ${entry.url.take(140)}", url = entry.url, key = key)
            store.record(
                EvidenceSource.PIPELINE, session.tabId, "api_entry",
                "${entry.method} ${entry.url.take(140)} → ${entry.status}",
                buildMap {
                    put("method", entry.method.name)
                    put("url", entry.url)
                    put("status", entry.status.toString())
                    entry.requestBody?.let { put("requestBody", it.take(600)) }
                    entry.responseBody?.let { put("responseBody", it.take(600)) }
                    put("initiator", entry.initiator.take(200))
                },
            )
        }
        steps += step("network", true, "匹配 ${entries.size} 条请求 / ${endpointKeys.size} 个端点")

        // 2. initiator 调用栈 → 函数节点 + CALLS 边
        val callerFunctions = mutableSetOf<String>()
        entries.forEach { entry ->
            entry.initiatorStack.lineSequence().take(8).forEach { line ->
                parseStackFrame(line)?.let { (fn, furl, fline) ->
                    val fnKey = "fn:$fn@${furl.substringBefore('?')}:$fline"
                    callerFunctions += fn
                    store.addNode(GraphNodeType.FUNCTION, "$fn:${fline}", url = furl, line = fline, key = fnKey)
                    val epKey = "ep:${entry.url.substringBefore('?').substringBefore('#')}"
                    store.addEdge(fnKey, epKey, GraphEdgeType.CALLS)
                    val scriptKey = "js:${furl.substringBefore('?')}"
                    store.addNode(GraphNodeType.SCRIPT, furl.substringAfterLast('/').take(100), url = furl, key = scriptKey)
                    store.addEdge(scriptKey, fnKey, GraphEdgeType.CONTAINS)
                }
            }
        }
        steps += step("initiators", callerFunctions.isNotEmpty(), "调用方函数 ${callerFunctions.size} 个（来自 initiator 栈）")

        // 3. CDP 脚本内容搜索（引用该端点的脚本）
        var scriptRefs = 0
        if (deps.debuggerManager.backend == "cdp") {
            runCatching {
                deps.debuggerManager.listScripts(engine)
                    .filter { it.url.startsWith("http") }
                    .take(40)
                    .forEach { s ->
                        val hits = deps.debuggerManager.searchScriptContent(engine, s.scriptId, pattern, limit = 3).getOrNull() ?: return@forEach
                        if (hits.size > 0) {
                            scriptRefs++
                            val scriptKey = "js:${s.url.substringBefore('?')}"
                            store.addNode(GraphNodeType.SCRIPT, s.url.substringAfterLast('/').take(100), url = s.url, key = scriptKey)
                            endpointKeys.forEach { store.addEdge(scriptKey, it, GraphEdgeType.REFERENCES) }
                        }
                    }
            }
            steps += step("script_search", true, "引用脚本 $scriptRefs 个")
        } else {
            steps += step("script_search", false, "未附加 CDP，跳过脚本内容搜索（debugger.attach 提升完整度）")
        }

        // 4. Finding
        if (saveFindings) {
            saveFinding(
                deps, FindingType.API, "接口链路: ${pattern.take(60)}",
                "端点 ${endpointKeys.size} 个；调用方函数: ${callerFunctions.take(10).joinToString(", ")}；引用脚本 $scriptRefs 个",
                evidence = entries.firstOrNull()?.url.orEmpty(), source = entries.firstOrNull()?.url.orEmpty(),
                relatedRequest = entries.firstOrNull()?.id,
            )
        }
        return buildJsonObject {
            put("pattern", pattern)
            put("steps", JsonArray(steps))
            put("endpoints", JsonArray(endpointKeys.map { JsonPrimitive(it.removePrefix("ep:")) }))
            put("callerFunctions", JsonArray(callerFunctions.take(20).map { JsonPrimitive(it) }))
            put(
                "nextSteps",
                JsonArray(
                    buildList {
                        if (callerFunctions.isNotEmpty()) add("hook.add_function 拦截 ${callerFunctions.first()} 观察实时参数")
                        if (callerFunctions.isNotEmpty()) add("debugger.set_breakpoint target=${callerFunctions.first()} 断点抓生成现场")
                        add("crypto_link 确认该接口是否经过加密签名")
                    }.map { JsonPrimitive(it) },
                ),
            )
        }
    }

    /** token_trace：令牌溯源 */
    private suspend fun runTokenTrace(deps: ToolDependencies, args: JsonObject): JsonObject {
        val store = deps.evidenceStore
        val session = deps.activeSession()
        val engine = session.engine
        val saveFindings = ToolArgs.bool(args, "saveFindings", true)
        val givenKey = ToolArgs.optStr(args, "key")
        val steps = mutableListOf<JsonObject>()

        // 1. 存储扫描（值脱敏：只记长度与前 6 位）
        data class Hit(val scope: String, val key: String, val valueLen: Int, val preview: String)
        val hits = mutableListOf<Hit>()
        runCatching {
            engine.getLocalStorage().forEach { (k, v) -> hits += Hit("localStorage", k, v.length, v.take(6)) }
            engine.getSessionStorage().forEach { (k, v) -> hits += Hit("sessionStorage", k, v.length, v.take(6)) }
        }
        runCatching {
            engine.getCookies().forEach { c ->
                c["name"]?.let { n -> hits += Hit("cookie", n, (c["value"]?.length ?: 0), c["value"]?.take(6) ?: "") }
            }
        }
        val tokens = hits.filter { givenKey?.let { g -> it.key.contains(g, true) } ?: isTokenishKey(it.key) }.take(30)
        tokens.forEach { t ->
            val key = "tok:${t.key}"
            store.addNode(GraphNodeType.TOKEN, t.key, key = key)
            store.record(
                EvidenceSource.PIPELINE, session.tabId, "token_found",
                "令牌类存储 ${t.scope}.${t.key}（len=${t.valueLen}，预览 ${t.preview}***）",
                mapOf("scope" to t.scope, "key" to t.key, "valueLength" to t.valueLen.toString(), "preview" to "${t.preview}***"),
            )
        }
        steps += step("storage_scan", true, "存储 ${hits.size} 键，令牌类命中 ${tokens.size} 个")

        // 2. 引用脚本搜索（页面源码 + CDP 脚本）
        var refs = 0
        val targetKeys = tokens.map { it.key }.take(5)
        if (targetKeys.isNotEmpty()) {
            runCatching {
                val html = engine.getPageSource()?.take(400_000) ?: ""
                targetKeys.forEach { k ->
                    if (html.contains(k)) {
                        refs++
                        store.addNode(GraphNodeType.SCRIPT, "inline-html", key = "js:inline-html")
                        store.addEdge("js:inline-html", "tok:$k", GraphEdgeType.REFERENCES)
                    }
                }
            }
            if (deps.debuggerManager.backend == "cdp") {
                runCatching {
                    deps.debuggerManager.listScripts(engine)
                        .filter { it.url.startsWith("http") }
                        .take(40)
                        .forEach { s ->
                            val anyHit = targetKeys.any { k ->
                                (deps.debuggerManager.searchScriptContent(engine, s.scriptId, k, limit = 1).getOrNull()?.size ?: 0) > 0
                            }
                            if (anyHit) {
                                refs++
                                val scriptKey = "js:${s.url.substringBefore('?')}"
                                store.addNode(GraphNodeType.SCRIPT, s.url.substringAfterLast('/').take(100), url = s.url, key = scriptKey)
                                targetKeys.forEach { k -> store.addEdge(scriptKey, "tok:$k", GraphEdgeType.REFERENCES) }
                            }
                        }
                }
            }
        }
        steps += step("script_refs", true, "引用脚本 $refs 个")

        // 3. Finding
        if (saveFindings && tokens.isNotEmpty()) {
            saveFinding(
                deps, FindingType.STORAGE, "令牌盘点（${tokens.size} 个）",
                tokens.take(10).joinToString("; ") { "${it.scope}.${it.key}(len=${it.valueLen})" },
                evidence = tokens.joinToString(",") { it.key }, source = engine.currentUrl().orEmpty(),
            )
        }
        return buildJsonObject {
            put("steps", JsonArray(steps))
            put(
                "tokens",
                JsonArray(
                    tokens.map { t ->
                        buildJsonObject {
                            put("scope", t.scope)
                            put("key", t.key)
                            put("valueLength", t.valueLen)
                            put("preview", "${t.preview}***")
                        }
                    },
                ),
            )
            put(
                "nextSteps",
                JsonArray(
                    listOf(
                        "hook.add type=storage target=<key> 监控该令牌的写入时刻",
                        "写入命中后 pipeline.run name=snapshot 抓生成现场",
                        "api_trace 追踪携带该令牌的接口",
                    ).map { JsonPrimitive(it) },
                ),
            )
        }
    }

    /** crypto_link：加密命中 ↔ 请求多证据关联（置信度评分取代纯时间窗） */
    private suspend fun runCryptoLink(deps: ToolDependencies, args: JsonObject): JsonObject {
        val store = deps.evidenceStore
        val session = deps.activeSession()
        val engine = session.engine
        val saveFindings = ToolArgs.bool(args, "saveFindings", true)
        val steps = mutableListOf<JsonObject>()
        val correlator = EvidenceCorrelator()
        val ctxSessionId = deps.context()?.sessionId ?: ""

        // 1. Hook 命中记录（含 stackTrace / 返回值 / 输入，供值级关联）
        val hookEvents = deps.hookEngine.events.value
        val cryptoHits = hookEvents.filter {
            val t = "${it.ruleName} ${it.target}".lowercase()
            listOf("crypto", "encrypt", "sign", "aes", "rsa", "md5", "sha", "hmac", "digest", "subtle").any { k -> k in t }
        }
        steps += step("hook_events", true, "Hook 命中 ${hookEvents.size} 条，其中加密类 ${cryptoHits.size} 条")

        // 2. 网络请求
        val entries = runCatching { deps.networkInspector.getEntries(engine) }.getOrDefault(emptyList())
        steps += step("network", true, "网络请求 ${entries.size} 条")

        // 3. 多证据关联评分：单个加密命中 → 各请求候选打分
        val hits = cryptoHits.take(80).map { hv ->
            EvidenceCorrelator.CryptoHit(
                function = hv.target.ifBlank { hv.ruleName },
                stackTrace = hv.stackTrace,
                timestamp = hv.timestamp,
                tabId = hv.tabId,
                output = hv.result,
                input = hv.arguments,
            )
        }
        val requests = entries.take(400).map { n ->
            EvidenceCorrelator.RequestCandidate(
                url = n.url,
                endpointKey = n.url.substringBefore('?').substringBefore('#'),
                timestamp = n.startedAt,
                tabId = n.tabId,
                stackTrace = n.initiatorStack,
                headers = n.requestHeaders,
                body = n.requestBody ?: (n.queryParams.entries.joinToString("&") { "${it.key}=${it.value}" }),
            )
        }
        val correlations = correlator.relate(hits, requests, keepBestPerRequest = true, minScore = 20)

        // 4. 按分级写边（SIGNS/POSSIBLE_SIGNS 均写入，避免一刀切丢失弱证）
        var strongLinks = 0
        correlations.filter { it.relation != "LOW" }.forEach { c ->
            strongLinks++
            val fnKey = "crypto:${c.function.take(80)}"
            val epKey = "ep:${c.endpointKey}"
            store.addNode(GraphNodeType.CRYPTO, c.function, key = fnKey)
            store.addNode(GraphNodeType.ENDPOINT, c.endpointUrl.take(120), url = c.endpointUrl, key = epKey)
            store.addEdge(fnKey, epKey, GraphEdgeType.SIGNS, sessionId = ctxSessionId)
            store.record(
                EvidenceSource.PIPELINE, session.tabId, "crypto_link",
                "加密关联: ${c.function.take(60)} ${c.relation} ${c.endpointKey.take(100)} (conf=${"%.2f".format(c.confidence)})",
                buildMap {
                    put("function", c.function)
                    put("endpoint", c.endpointKey)
                    put("relation", c.relation)
                    put("confidence", "%.2f".format(c.confidence))
                    put("score", c.score.toString())
                    put("signals", c.matchedSignals.joinToString(","))
                    put("provenance", c.provenance.joinToString(",") { "${it.method}:${it.confidence.toInt()}" })
                },
                sessionId = ctxSessionId,
            )
        }

        // 5. 被动层已累计的 SIGNS 边合并展示
        val signsEdges = store.topEdges(200).filter { it.type == GraphEdgeType.SIGNS }
        steps += step("correlate", true, "多证据关联 ${correlations.size} 对，高置信度写入图谱 $strongLinks 条 + 累计 SIGNS 边 ${signsEdges.size} 条")
        steps += step(
            "confidence",
            correlations.isNotEmpty(),
            "平均置信度 ${"%.2f".format(correlations.map { it.confidence }.average().let { if (correlations.isEmpty()) 0.0 else it })}；判定依据: ${correlations.take(1).flatMap { it.matchedSignals }.distinct().take(5).joinToString(", ")}",
        )

        // 6. 每个端点的候选签名函数（按置信度降序）+ Finding
        val byEndpoint = correlations.groupBy { it.endpointKey }
        if (saveFindings) {
            byEndpoint.entries.take(10).forEach { (endpoint, cs) ->
                val best = cs.maxByOrNull { it.confidence } ?: return@forEach
                saveFinding(
                    deps, FindingType.CRYPTO, "签名候选: ${endpoint.substringAfterLast('/').take(50)}",
                    "候选函数: ${cs.map { it.function }.distinct().take(5).joinToString(", ")}（置信度 ${"%.2f".format(best.confidence)}，依据: ${best.matchedSignals.take(3).joinToString(",")}）",
                    evidence = best.matchedSignals.joinToString(","), source = best.endpointUrl,
                    confidence = when {
                        best.confidence >= 0.8 -> Confidence.HIGH
                        best.confidence >= 0.5 -> Confidence.MEDIUM
                        else -> Confidence.MEDIUM
                    },
                )
            }
        }
        return buildJsonObject {
            put("steps", JsonArray(steps))
            put(
                "links",
                JsonArray(
                    byEndpoint.entries.take(15).map { (endpoint, cs) ->
                        val best = cs.maxByOrNull { it.confidence } ?: return@map buildJsonObject { }
                        buildJsonObject {
                            put("endpoint", endpoint)
                            put(
                                "candidates",
                                JsonArray(
                                    cs.sortedByDescending { it.confidence }.take(5).map { c ->
                                        buildJsonObject {
                                            put("function", c.function)
                                            put("relation", c.relation)
                                            put("confidence", JsonPrimitive(c.confidence))
                                            put("score", c.score)
                                            put("signals", JsonArray(c.matchedSignals.map { JsonPrimitive(it) }))
                                            put("provenance", JsonArray(c.provenance.map { p ->
                                                buildJsonObject {
                                                    put("method", p.method)
                                                    put("contribution", p.contribution)
                                                    put("confidence", JsonPrimitive(p.confidence))
                                                }
                                            }))
                                        }
                                    },
                                ),
                            )
                            put("bestConfidence", JsonPrimitive(best.confidence))
                            put("confidence", JsonPrimitive(best.confidence))
                            put("relation", best.relation)
                        }
                    },
                ),
            )
            put(
                "nextSteps",
                JsonArray(
                    listOf(
                        "对高置信度候选设断点验证签名生成现场（debugger.set_breakpoint type=function）",
                        "命中后 pipeline.run name=snapshot 抓取入参与密钥",
                        "低置信度时用 evidence.correlate function=<fn> urlPattern=<api> 精准复核",
                    ).map { JsonPrimitive(it) },
                ),
            )
        }
    }

    /** snapshot：运行时现场捕获（断点命中/暂停态） */
    private suspend fun runSnapshot(deps: ToolDependencies, args: JsonObject): JsonObject {
        val store = deps.evidenceStore
        val session = deps.activeSession()
        val engine = session.engine
        val saveFindings = ToolArgs.bool(args, "saveFindings", true)
        val steps = mutableListOf<JsonObject>()

        if (deps.debuggerManager.backend == "none") {
            runCatching { deps.debuggerManager.attach(engine) }
        }
        val snap = deps.debuggerManager.snapshotPausedState(engine).getOrNull()
            ?: throw IllegalArgumentException("无暂停现场：先设断点（debugger.set_breakpoint）并触发命中，或 debugger.pause")
        val reason = snap["reason"]?.jsonPrimitive?.content ?: ""
        val frames = runCatching { snap["callFrames"]?.jsonArray ?: JsonArray(emptyList()) }.getOrDefault(JsonArray(emptyList()))
        steps += step("paused_state", true, "暂停原因: $reason，调用帧 ${frames.size} 个")

        // 证据沉淀
        val ev = store.record(
            EvidenceSource.SNAPSHOT, session.tabId, "paused_state",
            "运行时现场（$reason）",
            buildMap {
                put("reason", reason)
                put("frameCount", frames.size.toString())
                frames.take(3).forEachIndexed { i, fr ->
                    runCatching {
                        val o = fr.jsonObject
                        put(
                            "frame$i",
                            "${o["functionName"]?.jsonPrimitive?.content ?: "?"}@${o["url"]?.jsonPrimitive?.content ?: "?"}:${(o["lineNumber"] as? JsonPrimitive)?.intOrNull ?: 0}",
                        )
                    }
                }
            },
        )

        // 调用帧链建图：frame[i] CALLS frame[i+1]
        var prevKey: String? = null
        frames.take(10).forEach { fr ->
            runCatching {
                val o = fr.jsonObject
                val fn = o["functionName"]?.jsonPrimitive?.content?.ifBlank { "(anonymous)" } ?: "(anonymous)"
                val furl = o["url"]?.jsonPrimitive?.content ?: ""
                val fline = (o["lineNumber"] as? JsonPrimitive)?.intOrNull ?: 0
                val fnKey = "fn:$fn@${furl.substringBefore('?')}:$fline"
                store.addNode(GraphNodeType.FUNCTION, "$fn:$fline", url = furl, line = fline, key = fnKey)
                if (furl.isNotBlank()) {
                    val scriptKey = "js:${furl.substringBefore('?')}"
                    store.addNode(GraphNodeType.SCRIPT, furl.substringAfterLast('/').take(100), url = furl, key = scriptKey)
                    store.addEdge(scriptKey, fnKey, GraphEdgeType.CONTAINS, ev.id)
                }
                if (prevKey != null) store.addEdge(prevKey!!, fnKey, GraphEdgeType.CALLS, ev.id)
                prevKey = fnKey
            }
        }
        steps += step("graph", true, "调用链 ${frames.size} 帧已入图谱")

        // 变量摘要（locals 已在 snapshot 内）
        if (saveFindings) {
            saveFinding(
                deps, FindingType.FUNCTION, "运行时现场（$reason）",
                "调用链: ${
                    frames.take(5).mapNotNull {
                        runCatching { it.jsonObject["functionName"]?.jsonPrimitive?.content }.getOrNull()
                    }.joinToString(" → ")
                }",
                evidence = snap.toString().take(500),
                source = runCatching { frames.firstOrNull()?.jsonObject?.get("url")?.jsonPrimitive?.content }.getOrNull() ?: "",
            )
        }
        return buildJsonObject {
            put("reason", reason)
            put("steps", JsonArray(steps))
            put("callFrames", JsonArray(frames.take(10)))
            put(
                "nextSteps",
                JsonArray(
                    listOf(
                        "debugger.get_locals / evaluate_on_call_frame 深挖变量",
                        "debugger.step_over 单步跟踪",
                        "graph.query node=fn:... 查看该函数在图谱中的上下游",
                    ).map { JsonPrimitive(it) },
                ),
            )
        }
    }

    // ================================================================
    // 辅助
    // ================================================================

    private fun step(name: String, ok: Boolean, detail: String): JsonObject = buildJsonObject {
        put("name", name)
        put("ok", ok)
        put("detail", detail)
    }

    private suspend fun saveFinding(
        deps: ToolDependencies,
        type: FindingType,
        title: String,
        description: String,
        evidence: String = "",
        source: String = "",
        relatedRequest: String? = null,
        relatedFunction: String? = null,
        confidence: Confidence = Confidence.MEDIUM,
    ) {
        runCatching {
            val wsId = deps.workspaceManager.getWorkspaces().firstOrNull()?.id
            deps.workspaceManager.addFinding(
                Finding(
                    id = UUID.randomUUID().toString(),
                    workspaceId = wsId,
                    type = type,
                    title = title,
                    description = description,
                    evidence = evidence.take(800),
                    source = source,
                    confidence = confidence,
                    relatedRequest = relatedRequest,
                    relatedFunction = relatedFunction,
                ),
            )
        }
    }

    private fun isTokenishKey(key: String): Boolean {
        val k = key.lowercase()
        return listOf("token", "jwt", "auth", "sign", "secret", "session", "sess", "access", "refresh", "credential").any { it in k }
    }

    /** 解析 V8 调用栈帧："at fn (url:1:2)" / "at url:1:2" */
    private val stackFrameRegex = Regex("""at\s+(?:([\w$.]+)\s+\()?(https?://[^):\s]+):(\d+):(\d+)\)?""")

    private fun parseStackFrame(line: String): Triple<String, String, Int>? {
        val m = stackFrameRegex.find(line) ?: return null
        val fn = m.groupValues[1].ifBlank { "(anonymous)" }
        return Triple(fn, m.groupValues[2], m.groupValues[3].toIntOrNull() ?: 0)
    }

    private fun evidenceJson(e: com.webreverse.mcp.workspace.core.Evidence): JsonObject = buildJsonObject {
        put("id", e.id)
        put("ts", e.timestamp)
        put("source", e.source.name.lowercase())
        put("kind", e.kind)
        put("title", e.title)
        if (e.data.isNotEmpty()) {
            put("data", buildJsonObject { e.data.forEach { (k, v) -> put(k, v) } })
        }
    }

    private fun nodeJson(n: com.webreverse.mcp.workspace.core.GraphNode): JsonObject = buildJsonObject {
        put("key", n.key)
        put("type", n.type.name.lowercase())
        put("label", n.label)
        put("url", n.url)
        put("line", n.line)
        put("hits", n.weight)
    }

    private fun edgeJson(e: com.webreverse.mcp.workspace.core.GraphEdge): JsonObject = buildJsonObject {
        put("from", e.from)
        put("to", e.to)
        put("type", e.type.name.lowercase())
        put("hits", e.weight)
    }
}
