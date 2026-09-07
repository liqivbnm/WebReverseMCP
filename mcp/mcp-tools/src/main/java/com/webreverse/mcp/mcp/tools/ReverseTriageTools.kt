package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import com.webreverse.mcp.javascript.analysis.JsCryptoScanner
import com.webreverse.mcp.javascript.analysis.ReverseAnalysisEngine
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * 页面级逆向分诊入口：把已有专家引擎收敛成一次调用可读的现场画像。
 * 只读、不安装 Hook、不修改页面；适合作为 AI Agent 的逆向第一步。
 */
object ReverseTriageTools {
    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)
        return listOf(
            f.tool(
                "reverse.page_triage",
                "当前页面一键逆向分诊：统一采集 URL/环境/框架/脚本/网络/Trace，并运行 API、Crypto、混淆、反调试与 JS 结构分析，输出高价值线索、置信度和下一步动作。",
                ToolCategory.REVERSE,
                PermissionScope.READ_PAGE,
                RiskLevel.LOW,
                timeoutMs = 45_000,
                capabilities = "reverse,triage,page,network,trace,crypto,obfuscation,anti-debug,api,ranking",
                cost = 6,
                reliability = 94,
                inputSchema = Schemas.objectSchema(
                    "topN" to Schemas.intSchema("每类最多返回多少条高价值线索，默认 10"),
                ),
            ) { args ->
                val topN = ToolArgs.int(args, "topN", 10).coerceIn(3, 30)
                val session = deps.activeSession()
                val engine = session.engine
                val source = engine.getPageSource().orEmpty()
                val network = engine.getNetworkEntries()

                val runtimeRaw = engine.evaluateJavascript(
                    """(function(){return JSON.stringify({url:location.href,title:document.title,ready:document.readyState,userAgent:navigator.userAgent,webdriver:!!navigator.webdriver,webAssembly:typeof WebAssembly!=='undefined',serviceWorker:'serviceWorker' in navigator,webSocket:typeof WebSocket!=='undefined,eventSource:typeof EventSource!=='undefined,scriptCount:document.scripts.length})})()""",
                ).orEmpty()
                val scriptsRaw = engine.evaluateJavascript(
                    """(function(){return JSON.stringify(Array.from(document.scripts).map(function(s){return {src:s.src||"(inline)",type:s.type||"text/javascript",async:!!s.async,defer:!!s.defer,size:(s.textContent||"").length}}).slice(0,200))})()""",
                ).orEmpty()

                val framework = deps.frameworkDetector.detectFromJs(source)
                val runtimeFramework = deps.frameworkDetector.detectFromRuntime(runtimeRaw)
                val api = deps.apiDiscoveryEngine.merge(
                    deps.apiDiscoveryEngine.discoverFromHtml(source),
                    deps.apiDiscoveryEngine.discoverFromJs(source, "page.html"),
                    deps.apiDiscoveryEngine.discoverFromNetwork(network),
                )
                val crypto = JsCryptoScanner().scan(source)
                val obfuscation = deps.obfuscationAnalyzer.analyze(source)
                val antiDebug = deps.antiDebugDetector.detect(source, scriptId = "page")
                val reverse = if (source.length >= 32_768) {
                    ReverseAnalysisEngine().analyze(source, topN)
                } else null

                val traceStats = deps.evidenceStore.traceBuffer.stats()
                val hotEndpoints = network
                    .groupingBy { it.url }
                    .eachCount()
                    .entries
                    .sortedByDescending { it.value }
                    .take(topN)
                val uniqueNetworkHosts = network
                    .mapNotNull { runCatching { java.net.URI(it.url).host }.getOrNull() }
                    .filter { it.isNotBlank() }
                    .distinct()
                    .take(50)

                val signals = mutableListOf<Pair<String, Double>>()
                if (crypto.identifications.isNotEmpty()) signals += "JS crypto 命中 ${crypto.identifications.size} 处" to 0.95
                if (api.endpoints.isNotEmpty()) signals += "发现 ${api.endpoints.size} 个 API 端点候选" to 0.91
                if (antiDebug.techniques.isNotEmpty()) signals += "检测到 ${antiDebug.techniques.size} 类反调试技术" to 0.90
                if (obfuscation.isObfuscated) signals += "页面存在明显混淆特征" to 0.86
                if (framework.frameworks.isNotEmpty()) {
                    val fwConfidence = framework.frameworks.mapNotNull { framework.confidence[it] }.maxOrNull() ?: 0.85
                    signals += "检测到框架：${framework.frameworks.distinct().take(5).joinToString()}" to fwConfidence
                }
                if (network.isNotEmpty()) signals += "已捕获 ${network.size} 条网络记录" to 0.82
                if (traceStats.size > 0) signals += "Trace 已积累 ${traceStats.size} 个事件" to 0.84
                if (source.contains(Regex("(?i)WebAssembly|\\.wasm|WebAssembly\\.instantiate"))) signals += "检测到 JS↔WASM 边界线索" to 0.88

                val nextActions = buildList {
                    when {
                        api.endpoints.isNotEmpty() -> add("优先对高频/敏感端点调用 reverse.signature_candidates，再用 reverse.causality 反查签名链")
                        else -> add("先使用 network.recon / page.api_list 扩充真实请求与端点证据")
                    }
                    if (crypto.identifications.isNotEmpty()) add("继续 crypto 热点：追踪输入/输出值指纹，并与 network sink 做 value_link 关联")
                    if (antiDebug.techniques.isNotEmpty()) add("存在反调试：优先定位检测函数，再按需启用对应 Hook/脚本干预")
                    if (source.contains(Regex("(?i)WebAssembly|\\.wasm|WebAssembly\\.instantiate"))) add("存在 WASM：进入 wasm.dump_module → wasm.recognize_crypto → wasm.disassemble_func / wasm.memory_provenance")
                    if (obfuscation.isObfuscated) add("混淆较重：先 source-map / beautify，再对热点函数执行 AST/SSA 与调用图分析")
                    add("最后用 reverse.introspect / reverse.quality_gate 汇总证据完整度，避免只凭单一时间顺序下结论")
                }.distinct().take(8)

                McpToolResult.json(buildJsonObject {
                    put("ok", true)
                    put("url", runtimeRaw.extractJsonField("url"))
                    put("title", runtimeRaw.extractJsonField("title"))
                    put("sourceChars", source.length)
                    put("networkCount", network.size)
                    put("traceEvents", traceStats.size)
                    put("runtime", JsonPrimitive(runtimeRaw))
                    put("scripts", JsonPrimitive(scriptsRaw))
                    put("frameworks", JsonArray((framework.frameworks + runtimeFramework.frameworks).distinct().take(topN).map(::JsonPrimitive)))
                    put("bundlers", JsonArray(framework.bundlers.take(topN).map(::JsonPrimitive)))
                    put("apiCandidates", JsonArray(api.endpoints.take(topN * 3).map {
                        buildJsonObject {
                            put("method", it.method); put("url", it.url); put("source", it.source); put("caller", it.caller); put("line", it.line); put("confidence", it.confidence)
                        }
                    }))
                    put("crypto", JsonArray(crypto.identifications.take(topN).map {
                        buildJsonObject { put("algorithm", it.algorithm); put("confidence", it.confidence); put("lines", JsonArray(it.lines.take(8).map(::JsonPrimitive))); put("evidence", JsonArray(it.evidence.take(6).map(::JsonPrimitive))) }
                    }))
                    put("antiDebug", JsonArray(antiDebug.techniques.take(topN).map(::JsonPrimitive)))
                    put("obfuscation", buildJsonObject {
                        put("isObfuscated", obfuscation.isObfuscated)
                        put("score", obfuscation.score)
                        put("signals", JsonArray(obfuscation.detected.take(topN).map(::JsonPrimitive)))
                    })
                    put("networkHotspots", JsonArray(hotEndpoints.map { buildJsonObject { put("url", it.key); put("count", it.value) } }))
                    put("networkHosts", JsonArray(uniqueNetworkHosts.map(::JsonPrimitive)))
                    put("signals", JsonArray(signals.sortedByDescending { it.second }.take(topN).map { buildJsonObject { put("label", it.first); put("confidence", it.second) } }))
                    if (reverse != null) {
                        put("jsAnalysis", buildJsonObject {
                            put("functionCount", reverse.functionCount)
                            put("endpointCount", reverse.endpointCount)
                            put("cryptoCount", reverse.cryptoCount)
                            put("taintFlowCount", reverse.taintFlowCount)
                            put("deepReadiness", reverse.deepReadiness)
                            put("hotFunctions", JsonArray(reverse.hotFunctions.take(topN).map { fn -> buildJsonObject { put("name", fn.name); put("line", fn.line); put("score", fn.score); put("reasons", JsonArray(fn.reasons.map(::JsonPrimitive))) } }))
                        })
                    }
                    put("nextActions", JsonArray(nextActions.map(::JsonPrimitive)))
                    put("hint", "这是入口级分诊，不替代专家工具；优先沿高置信 signal → endpoint → crypto/token → causality/value_link → validation 闭环推进。")
                })
            },
        )
    }

    private fun String.extractJsonField(key: String): JsonPrimitive = runCatching {
        val re = Regex("\\\"" + Regex.escape(key) + "\\\"\\s*:\\s*\\\"((?:\\\\.|[^\\\"])*)\\\"")
        JsonPrimitive(re.find(this)?.groupValues?.getOrNull(1) ?: "")
    }.getOrDefault(JsonPrimitive(""))
}
