package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import com.webreverse.mcp.javascript.analysis.AntiDebugDetector
import com.webreverse.mcp.javascript.analysis.DeepReverseAnalyzer
import com.webreverse.mcp.javascript.analysis.JsvmpDeepAnalyzer
import com.webreverse.mcp.javascript.analysis.JsvmpSemanticRecovery
import com.webreverse.mcp.javascript.analysis.JsvmpSemanticValidator
import com.webreverse.mcp.javascript.analysis.ReverseAnalysisEngine
import com.webreverse.mcp.javascript.analysis.StructuredWasmDecompiler
import com.webreverse.mcp.javascript.analysis.UniversalTargetProfiler
import com.webreverse.mcp.javascript.analysis.VmpDecompiler
import com.webreverse.mcp.javascript.analysis.VmpDetector
import com.webreverse.mcp.javascript.analysis.WasmAnalyzer
import com.webreverse.mcp.javascript.analysis.WasmCryptoRecognizer
import com.webreverse.mcp.javascript.analysis.WasmMemoryProvenance
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * 一键自动逆向编排层（Auto-Pilot）。
 *
 * 动机：既有引擎（画像/静态/JSVMP/WASM/反调试/验证）已非常完整，但 AI Agent
 * 需要手工串联 5~10 个工具才能走完一条逆向链路。本层把「检测 → 画像 → 深度分析
 * → 反混淆/反编译 → 验证 → 行动建议」收敛为单次调用，输出结构化报告，让 Agent
 * 逆向更顺手：
 * - reverse.auto_pilot：实时页面一键全链路（画像 + 源码 + VMP/反调试 + 深度 + 建议）
 * - jsvmp.auto_deobfuscate：JSVMP 一键反混淆（检测 → ISA 语义 → 伪代码 → 验证）
 * - wasm.auto_decompile：WASM 一键反编译（画像 → 伪代码 → 加密识别 → 边界/字符串）
 */
object AutoPilotTools {

    private suspend fun ensureAttached(deps: ToolDependencies) {
        if (deps.debuggerManager.backend != "cdp") {
            val session = deps.activeSession()
            deps.debuggerManager.attach(session.engine)
        }
    }

    /** 取待分析脚本源码：优先 scriptId，否则取最大脚本 */
    private suspend fun resolveSource(
        deps: ToolDependencies,
        scriptId: String,
    ): Triple<String, String, String>? { // (source, scriptId, url)
        if (deps.debuggerManager.backend != "cdp") return null
        val session = deps.activeSession()
        val scripts = deps.debuggerManager.listScripts(session.engine)
            .filter { it.url.isNotBlank() && it.length > 1000 }
        val target = if (scriptId.isNotBlank()) {
            scripts.firstOrNull { it.scriptId == scriptId }
        } else {
            scripts.maxByOrNull { it.length }
        } ?: return null
        val source = deps.debuggerManager.getScriptSource(session.engine, target.scriptId, 4_000_000).getOrNull()
            ?: return null
        return Triple(source, target.scriptId, target.url)
    }

    private fun decodeBytes(s: String): ByteArray? {
        val t = s.trim()
        return when {
            t.startsWith("base64:", ignoreCase = true) ->
                runCatching { android.util.Base64.decode(t.substringAfter(':').trim(), android.util.Base64.DEFAULT) }.getOrNull()
            t.matches(Regex("(?i)^[0-9a-f\\s]+$")) && t.replace(" ", "").length % 2 == 0 ->
                runCatching {
                    val hex = t.replace(" ", "")
                    ByteArray(hex.length / 2) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
                }.getOrNull()
            else -> runCatching { android.util.Base64.decode(t, android.util.Base64.DEFAULT) }.getOrNull()
        }
    }

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)

        return listOf(
            // ---------------- reverse.auto_pilot：实时页面一键全链路 ----------------
            f.tool(
                name = "reverse.auto_pilot",
                description = "一键自动逆向（实时页面）：自动完成 目标画像 → 源码分析 → VMP/反调试/加密识别 → 深度分析 → 行动建议 的完整闭环，返回结构化逆向报告。输入 focus 聚焦目标端点/函数（如 sign/encrypt/wdf）。",
                category = ToolCategory.REVERSE,
                permission = PermissionScope.READ_PAGE,
                riskLevel = RiskLevel.LOW,
                timeoutMs = 60_000,
                capabilities = "reverse,auto-pilot,orchestration,target-profile,vmp,anti-debug,crypto,deep-analysis",
                cost = 8,
                reliability = 92,
                inputSchema = Schemas.objectSchema(
                    "focus" to Schemas.strSchema("关注端点/函数关键词（如 sign/encrypt/wdf），用于聚焦热点与发现"),
                    "includeSource" to Schemas.boolSchema("是否读取当前页面源码；默认 true"),
                    "includeNetwork" to Schemas.boolSchema("是否纳入当前 Tab 网络记录；默认 true"),
                    "includeRuntime" to Schemas.boolSchema("是否采集轻量 runtime 快照；默认 true"),
                ),
            ) { args ->
                val session = deps.activeSession()
                val engine = session.engine
                val focus = ToolArgs.str(args, "focus")
                val includeSource = ToolArgs.bool(args, "includeSource", true)
                val includeNetwork = ToolArgs.bool(args, "includeNetwork", true)
                val includeRuntime = ToolArgs.bool(args, "includeRuntime", true)
                val source = if (includeSource) engine.getPageSource().orEmpty() else ""
                val network = if (includeNetwork) engine.getNetworkEntries() else emptyList()
                val runtime = if (includeRuntime) runCatching {
                    engine.evaluateJavascript("""(function(){try{return JSON.stringify({url:location.href,title:document.title,ready:document.readyState,origin:location.origin,host:location.host,secure:location.protocol==='https:',webdriver:!!navigator.webdriver,serviceWorker:'serviceWorker' in navigator,webAssembly:typeof WebAssembly!=='undefined',webSocket:typeof WebSocket!=='undefined',eventSource:typeof EventSource!=='undefined',storage:!!window.localStorage,sessionStorage:!!window.sessionStorage,indexedDB:!!window.indexedDB,worker:typeof Worker!=='undefined',sharedWorker:typeof SharedWorker!=='undefined',scripts:document.scripts.length,iframes:document.querySelectorAll('iframe').length})}catch(e){return JSON.stringify({error:String(e)})}})()""")
                }.getOrDefault("").orEmpty() else ""

                val profile = UniversalTargetProfiler().profile(source, network, runtime)
                val base = if (source.isNotBlank()) runCatching { ReverseAnalysisEngine().analyze(source, 30) }.getOrNull() else null
                val verdict = if (source.isNotBlank()) runCatching { VmpDetector().verify(source) }.getOrNull() else null
                val antiDebug = if (source.isNotBlank()) runCatching { AntiDebugDetector().detect(source) }.getOrNull() else null
                val deep = if (source.isNotBlank()) runCatching { DeepReverseAnalyzer().analyze(source) }.getOrNull() else null

                val hotAll = base?.hotFunctions ?: emptyList()
                val hot = if (focus.isNotBlank()) hotAll.filter { fn ->
                    fn.name.contains(focus, ignoreCase = true) || fn.reasons.any { it.contains(focus, ignoreCase = true) }
                } else hotAll.take(10)
                val focusFindings = base?.findings?.filter { f ->
                    focus.isBlank() || f.name.contains(focus, ignoreCase = true) || f.reasons.any { it.contains(focus, ignoreCase = true) }
                } ?: emptyList()

                McpToolResult.json(buildJsonObject {
                    put("ok", true)
                    put("url", engine.currentUrl().orEmpty())
                    put("focus", focus)
                    put("coverage", profile.coverage)
                    put("environment", buildJsonObject { profile.environment.forEach { (k, v) -> put(k, v) } })
                    put("primaryTracks", JsonArray(profile.primaryTracks.map { JsonPrimitive(it.name) }))
                    put("blindSpots", JsonArray(profile.blindSpots.map(::JsonPrimitive)))
                    put("signals", JsonArray(profile.detected.map { s ->
                        buildJsonObject {
                            put("kind", s.kind.name)
                            put("score", s.score)
                            put("confidence", s.confidence)
                            put("evidence", JsonArray(s.evidence.map(::JsonPrimitive)))
                            put("nextActions", JsonArray(s.nextActions.map(::JsonPrimitive)))
                        }
                    }))
                    put("vmpVerdict", verdict?.let {
                        buildJsonObject {
                            put("family", it.family)
                            put("confidence", it.confidence)
                            put("reliability", it.reliability)
                            put("supporting", JsonArray(it.supporting.map(::JsonPrimitive)))
                            put("contradicting", JsonArray(it.contradicting.map(::JsonPrimitive)))
                        }
                    } ?: buildJsonObject { put("family", "none"); put("confidence", 0) })
                    put("antiDebug", antiDebug?.let {
                        buildJsonObject {
                            put("risk", it.risk)
                            put("techniques", JsonArray(it.techniques.map(::JsonPrimitive)))
                        }
                    } ?: buildJsonObject {})
                    put("hotFunctions", JsonArray(hot.map { fn ->
                        buildJsonObject {
                            put("name", fn.name)
                            put("line", fn.line)
                            put("score", fn.score)
                            put("callers", fn.callers)
                            put("callees", fn.callees)
                            put("reasons", JsonArray(fn.reasons.take(3).map(::JsonPrimitive)))
                        }
                    }))
                    put("focusFindings", JsonArray(focusFindings.take(20).map { f ->
                        buildJsonObject {
                            put("type", f.type.name)
                            put("name", f.name)
                            put("line", f.line)
                            put("confidence", f.confidence)
                            put("reasons", JsonArray(f.reasons.take(3).map(::JsonPrimitive)))
                        }
                    }))
                    put("cryptoCount", base?.cryptoCount ?: 0)
                    put("endpointCount", base?.endpointCount ?: 0)
                    put("deepMetrics", deep?.let {
                        buildJsonObject {
                            put("overallReadiness", it.metrics.overallReadiness)
                            put("cryptoBindingCoverage", it.metrics.cryptoBindingCoverage)
                            put("wasmBoundaryCoverage", it.metrics.wasmBoundaryCoverage)
                            put("networkBindingCoverage", it.metrics.networkBindingCoverage)
                        }
                    } ?: buildJsonObject {})
                    put("recommendedTools", JsonArray(profile.recommendedTools.map(::JsonPrimitive)))
                    put("agentRule", "沿 primaryTracks 最高分路线深入；先补 blindSpots；任何签名/解密结论需静态证据 + 运行时样本 + reverse.validate 三者中至少两项。")
                })
            },

            // ---------------- jsvmp.auto_deobfuscate：JSVMP 一键反混淆 ----------------
            f.tool(
                name = "jsvmp.auto_deobfuscate",
                description = "JSVMP 一键自动反混淆：自动完成 检测 → 深度画像 → 语义恢复(ISA) → 反编译伪代码 → 语义验证 的完整闭环，返回可读伪代码 + opcode 语义表 + 置信度。",
                category = ToolCategory.REVERSE,
                permission = PermissionScope.DEBUG_SCRIPT,
                riskLevel = RiskLevel.MEDIUM,
                timeoutMs = 60_000,
                capabilities = "jsvmp,auto-deobfuscate,isa,decompile,semantic-recovery,validation",
                cost = 8,
                reliability = 88,
                inputSchema = Schemas.objectSchema(
                    "scriptId" to Schemas.strSchema("脚本 ID（来自 debugger.list_scripts；留空则分析最大脚本）"),
                    "source" to Schemas.strSchema("直接传入 JS 源码（与 scriptId 二选一且优先，适合配合 file.read 离线分析）"),
                    "candidateIndex" to Schemas.intSchema("候选序号（detect_vmp 返回多个候选时选择，默认 0=最高分）"),
                ),
            ) { args ->
                val inlineSource = ToolArgs.str(args, "source")
                val scriptId = ToolArgs.str(args, "scriptId")
                val candIdx = ToolArgs.int(args, "candidateIndex", 0)

                val (source, resolvedId, url) = when {
                    inlineSource.isNotBlank() -> Triple(inlineSource, "inline", "inline")
                    else -> {
                        ensureAttached(deps)
                        resolveSource(deps, scriptId)
                            ?: return@tool McpToolResult.error(
                                "SOURCE_UNAVAILABLE",
                                "无 CDP 会话或脚本源码获取失败（可先 debugger.attach，或直接传 source 参数）",
                            )
                    }
                }

                val candidates = VmpDetector().detect(source)
                if (candidates.isEmpty()) {
                    return@tool McpToolResult.error("NO_VMP_FOUND", "未检测到 JSVMP 特征（无 while+switch dispatch 结构）")
                }
                val candidate = candidates.getOrNull(candIdx) ?: candidates.first()
                val analyzer = JsvmpDeepAnalyzer()
                val profile = analyzer.analyze(source, candidate)
                val recovery = JsvmpSemanticRecovery().recover(profile.handlers, profile.variables)
                val decompiled = VmpDecompiler().decompile(source, candidate, maxInstructions = 400)
                val validation = JsvmpSemanticValidator().validate(profile.handlers)

                McpToolResult.json(buildJsonObject {
                    put("ok", true)
                    put("scriptUrl", url)
                    put("scriptId", resolvedId)
                    put("dispatch", buildJsonObject {
                        put("line", candidate.line)
                        put("style", candidate.dispatchStyle)
                        put("score", candidate.score)
                        put("reasons", JsonArray(candidate.reasons.map(::JsonPrimitive)))
                    })
                    put("vmVariables", buildJsonObject {
                        put("pc", JsonArray(profile.variables.pcCandidates.map(::JsonPrimitive)))
                        put("sp", JsonArray(profile.variables.spCandidates.map(::JsonPrimitive)))
                        put("ctx", JsonArray(profile.variables.ctxCandidates.map(::JsonPrimitive)))
                        put("bytecodeArray", JsonArray(profile.variables.bytecodeCandidates.map(::JsonPrimitive)))
                    })
                    put("isaTable", recovery.isaTable)
                    put("mnemonicHistogram", buildJsonObject {
                        recovery.mnemonicHistogram.forEach { (k, v) -> put(k, JsonPrimitive(v)) }
                    })
                    put("handlers", JsonArray(recovery.handlers.take(120).map { h ->
                        buildJsonObject {
                            put("opcode", h.key)
                            put("mnemonic", h.mnemonic)
                            put("signature", h.signature)
                            put("arity", h.arity)
                            put("stackIn", h.stackIn)
                            put("stackOut", h.stackOut)
                            put("readsBytecode", h.readsBytecode)
                            put("branchTarget", h.branchTarget)
                            put("callsHost", h.callsHost)
                            put("confidence", h.confidence)
                        }
                    }))
                    put("decompiled", buildJsonObject {
                        put("ok", decompiled.ok)
                        put("carrierType", decompiled.carrierType)
                        put("totalInstructions", decompiled.totalInstructions)
                        put("decodedInstructions", decompiled.decodedInstructions)
                        put("blocks", decompiled.blocks)
                        put("loopBacks", decompiled.loopBacks)
                        put("runtimeNeeded", decompiled.runtimeNeeded)
                        put("decodeFormula", decompiled.decodeFormula)
                        put("listing", decompiled.listing.take(8000))
                        put("namingHints", decompiled.namingHints.take(2000))
                    })
                    put("validation", buildJsonObject {
                        put("ok", validation.ok)
                        put("handlers", validation.handlers)
                        put("validated", validation.validated)
                        put("confidence", validation.confidence)
                        put("issues", JsonArray(validation.issues.take(20).map { i ->
                            buildJsonObject {
                                put("severity", i.severity)
                                put("message", i.message)
                                put("handler", i.handler)
                            }
                        }))
                        put("recommendations", JsonArray(validation.recommendations.map(::JsonPrimitive)))
                    })
                    put("agentRule", "先读 isaTable 建立 opcode→语义映射，再读 decompiled.listing 还原字节码逻辑；低置信 handler 用 debugger.trace_vmp 采样做动态差分验证。")
                })
            },

            // ---------------- wasm.auto_decompile：WASM 一键反编译 ----------------
            f.tool(
                name = "wasm.auto_decompile",
                description = "WASM 一键自动反编译：自动完成 模块画像 → 导出函数结构化反编译 → 加密算法识别 → 内存/边界溯源 → 字符串提取 的完整闭环，返回关键导出伪代码 + 加密发现 + JS↔WASM 边界。",
                category = ToolCategory.REVERSE,
                permission = PermissionScope.READ_PAGE,
                riskLevel = RiskLevel.LOW,
                timeoutMs = 60_000,
                capabilities = "wasm,auto-decompile,structured-pseudocode,crypto-recognition,memory-provenance,boundary",
                cost = 8,
                reliability = 86,
                inputSchema = Schemas.objectSchema(
                    "wasm" to Schemas.strSchema("WASM 二进制内容（base64 优先；其次 hex）"),
                    "topExports" to Schemas.intSchema("反编译 Top N 个导出函数（默认 5，按 cryptoScore 排序）"),
                ),
            ) { args ->
                val wasmStr = ToolArgs.str(args, "wasm")
                if (wasmStr.isBlank()) return@tool McpToolResult.error("INVALID_ARGS", "wasm 参数必填（base64/hex）")
                val bytes = decodeBytes(wasmStr) ?: return@tool McpToolResult.error("DECODE_FAILED", "wasm 内容解码失败")
                val topN = ToolArgs.int(args, "topExports", 5).coerceIn(1, 20)

                val analyzer = WasmAnalyzer()
                val exports = analyzer.exportProfiles(bytes).sortedByDescending { it.cryptoScore }.take(topN)
                val decompiler = StructuredWasmDecompiler()
                val decompiled = exports.map { exp -> runCatching { decompiler.decompileExport(bytes, exp.name) }.getOrNull() }
                val crypto = WasmCryptoRecognizer().recognize(bytes)
                val memory = WasmMemoryProvenance().analyze(bytes)
                val strings = analyzer.strings(bytes, 4, 100)

                McpToolResult.json(buildJsonObject {
                    put("ok", true)
                    put("exportCount", exports.size)
                    put("exports", JsonArray(exports.map { exp ->
                        buildJsonObject {
                            put("name", exp.name)
                            put("funcIndex", exp.funcIndex)
                            put("params", exp.params)
                            put("results", exp.results)
                            put("instructionCount", exp.instructionCount)
                            put("cryptoScore", exp.cryptoScore)
                            put("internalCalls", exp.internalCalls)
                            put("indirectCalls", exp.indirectCalls)
                            put("realName", exp.realName ?: "")
                        }
                    }))
                    put("decompiled", JsonArray(decompiled.mapNotNull { d ->
                        d?.takeIf { it.ok }?.let {
                            buildJsonObject {
                                put("funcName", it.funcName)
                                put("funcIndex", it.funcIndex)
                                put("signature", it.signature)
                                put("instructionCount", it.instructionCount)
                                put("pseudocode", it.toReadableText().take(6000))
                            }
                        }
                    }))
                    put("crypto", buildJsonObject {
                        put("summary", crypto.summary)
                        put("findings", JsonArray(crypto.findings.take(20).map { f ->
                            buildJsonObject {
                                put("algorithm", f.algorithm)
                                put("confidence", f.confidence)
                                put("kind", f.kind)
                                put("funcIndex", f.funcIndex)
                                put("funcName", f.funcName ?: "")
                                put("evidence", JsonArray(f.evidence.take(3).map(::JsonPrimitive)))
                            }
                        }))
                    })
                    put("memory", buildJsonObject {
                        put("ok", memory.ok)
                        if (memory.ok) {
                            put("funcCount", memory.funcs.size)
                            put("totalWrites", memory.totalWrites)
                            put("totalReads", memory.totalReads)
                            put("topWriters", JsonArray(memory.topWriters.take(8).map { fw ->
                                buildJsonObject {
                                    put("func", fw.funcName)
                                    put("writeCount", fw.writeCount)
                                }
                            }))
                            put("memoryExports", JsonArray(memory.boundary.memoryExports.map(::JsonPrimitive)))
                            put("pointerExports", JsonArray(memory.boundary.pointerExports.take(20).map { bf ->
                                buildJsonObject {
                                    put("export", bf.export)
                                    put("signature", bf.signature)
                                    put("category", bf.category)
                                    put("hint", bf.hint)
                                }
                            }))
                        } else {
                            put("error", memory.error)
                        }
                    })
                    put("strings", JsonArray(strings.strings.take(50).map { s ->
                        buildJsonObject {
                            put("offset", s.offset)
                            put("value", s.value.take(120))
                            put("kind", s.kind)
                        }
                    }))
                    put("agentRule", "先看 crypto.findings 定位算法，再读关键导出 pseudocode 还原主逻辑；pointerExports 揭示 JS 传入内存指针的边界，配合 wasm.provenance 做单地址溯源。")
                })
            },
        )
    }
}
