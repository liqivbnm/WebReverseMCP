package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import com.webreverse.mcp.javascript.analysis.UniversalTargetProfiler
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** Universal, site-agnostic reverse-engineering orchestration entry points. */
object UniversalReverseTools {
    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)
        return listOf(
            f.tool(
                name = "reverse.target_profile",
                description = "通用网页逆向目标画像：从当前页面源码、真实网络记录和运行时快照建立能力向量，不依赖具体站点，识别 API/Auth/Token/Crypto/WASM/JSVMP/反调试/Worker/Storage/GraphQL/WebSocket/SSE/gRPC/动态代码/打包器等路线，并输出证据、盲点、覆盖率与推荐工具。只读，不注入 Hook。",
                category = ToolCategory.REVERSE,
                permission = PermissionScope.READ_PAGE,
                riskLevel = RiskLevel.LOW,
                timeoutMs = 45_000,
                capabilities = "reverse,universal,target-profile,triage,api,auth,crypto,wasm,jsvmp,worker,graphql,websocket,sse,grpc,storage,environment",
                cost = 4,
                reliability = 96,
                inputSchema = Schemas.objectSchema(
                    "includeSource" to Schemas.boolSchema("是否读取当前页面源码；默认 true"),
                    "includeNetwork" to Schemas.boolSchema("是否纳入当前 Tab 网络记录；默认 true"),
                    "includeRuntime" to Schemas.boolSchema("是否采集轻量 runtime 快照；默认 true"),
                ),
            ) { args ->
                val session = deps.activeSession()
                val engine = session.engine
                val includeSource = ToolArgs.bool(args, "includeSource", true)
                val includeNetwork = ToolArgs.bool(args, "includeNetwork", true)
                val includeRuntime = ToolArgs.bool(args, "includeRuntime", true)
                val source = if (includeSource) engine.getPageSource().orEmpty() else ""
                val network = if (includeNetwork) engine.getNetworkEntries() else emptyList()
                val runtime = if (includeRuntime) runCatching {
                    engine.evaluateJavascript("""(function(){try{return JSON.stringify({url:location.href,title:document.title,ready:document.readyState,origin:location.origin,host:location.host,secure:location.protocol==='https:',webdriver:!!navigator.webdriver,serviceWorker:'serviceWorker' in navigator,webAssembly:typeof WebAssembly!=='undefined',webSocket:typeof WebSocket!=='undefined',eventSource:typeof EventSource!=='undefined,storage:!!window.localStorage,sessionStorage:!!window.sessionStorage,indexedDB:!!window.indexedDB,worker:typeof Worker!=='undefined,sharedWorker:typeof SharedWorker!=='undefined,scripts:document.scripts.length,iframes:document.querySelectorAll('iframe').length})}catch(e){return JSON.stringify({error:String(e)})}})()""")
                }.getOrDefault("").orEmpty() else ""
                val profile = UniversalTargetProfiler().profile(source, network, runtime)
                McpToolResult.json(buildJsonObject {
                    put("ok", true)
                    put("url", session.engine.currentUrl().orEmpty())
                    put("coverage", profile.coverage)
                    put("environment", buildJsonObject { profile.environment.forEach { (k, v) -> put(k, v) } })
                    put("primaryTracks", JsonArray(profile.primaryTracks.map { JsonPrimitive(it.name) }))
                    put("blindSpots", JsonArray(profile.blindSpots.map(::JsonPrimitive)))
                    put("recommendedTools", JsonArray(profile.recommendedTools.map(::JsonPrimitive)))
                    put("signals", JsonArray(profile.detected.map { s ->
                        buildJsonObject {
                            put("kind", s.kind.name)
                            put("score", s.score)
                            put("confidence", s.confidence)
                            put("evidence", JsonArray(s.evidence.map(::JsonPrimitive)))
                            put("nextActions", JsonArray(s.nextActions.map(::JsonPrimitive)))
                        }
                    }))
                    put("agentRule", "先补 blindSpots，再沿最高 score 路线深入；任何签名/解密结论至少满足静态证据 + 运行时样本 + reverse.validate 三者中的两项，避免单 regex 误判。")
                })
            },
        )
    }

}
