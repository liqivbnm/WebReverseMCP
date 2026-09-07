package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.common.model.TraceEvent
import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import com.webreverse.mcp.javascript.analysis.JsMemorySsaBuilder
import com.webreverse.mcp.javascript.analysis.JsWasmProvenanceChain
import com.webreverse.mcp.javascript.analysis.JsvmpVmSsa
import com.webreverse.mcp.javascript.analysis.UnifiedCausalGraph
import com.webreverse.mcp.javascript.analysis.ValidationEngine
import com.webreverse.mcp.javascript.analysis.VmpDetector
import com.webreverse.mcp.javascript.analysis.WasmProvenanceEngine
import com.webreverse.mcp.javascript.analysis.WorkerDataFlow
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/* * 深层能力入口：Memory SSA / WASM provenance / Worker dataflow / JSVMP VM-SSA。 */
object DeepReverseTools {
    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)
        return listOf(
            f.tool(
                "reverse.memory_ssa",
                "构建 JS Heap/Memory SSA：field-sensitive 属性位置、wildcard alias、MemoryPhi、def-use 与 escape 分析。",
                ToolCategory.REVERSE, PermissionScope.READ_PAGE, RiskLevel.LOW,
                timeoutMs = 30_000,
                capabilities = "memory-ssa,heap-ssa,alias-analysis,dataflow",
                cost = 5, reliability = 91,
                inputSchema = Schemas.objectSchema("source" to Schemas.strSchema("JS 源码")),
            ) { args ->
                val source = ToolArgs.str(args, "source")
                if (source.isBlank()) return@tool McpToolResult.error("MISSING_SOURCE", "source 必填")
                val r = JsMemorySsaBuilder().build(source)
                if (!r.ok) return@tool McpToolResult.error("MEMORY_SSA_FAILED", r.error)
                McpToolResult.json(buildJsonObject {
                    put("ok", true); put("locationCount", r.locationCount); put("memoryOps", r.memoryOps)
                    put("phiCount", r.phiCount); put("wildcardReads", r.wildcardReads); put("escapedLocations", r.escapedLocations); put("precision", r.precision)
                    put("warnings", JsonArray(r.warnings.map(::JsonPrimitive)))
                    put("functions", JsonArray(r.functions.take(200).map { fn ->
                        buildJsonObject {
                            put("id", fn.functionId); put("name", fn.functionName)
                            put("accesses", fn.accesses.take(500).size); put("versions", fn.versions.size); put("phis", fn.phis.size)
                            put("escaped", JsonArray(fn.escapeLocations.map(::JsonPrimitive)))
                            put("defUse", JsonArray(fn.defUse.entries.take(100).map { (k,v) -> JsonPrimitive("$k -> ${v.joinToString(" | ")}") }))
                        }
                    }))
                })
            },
            f.tool(
                "reverse.wasm_provenance",
                "构建 WASM JS↔linear-memory provenance 图：data segment→write→read→call→export 边界，并标出 ptr/len 参数候选。",
                ToolCategory.REVERSE, PermissionScope.READ_PAGE, RiskLevel.LOW,
                timeoutMs = 30_000,
                capabilities = "wasm,memory-provenance,js-wasm,boundary",
                cost = 5, reliability = 93,
                inputSchema = Schemas.objectSchema("bytesBase64" to Schemas.strSchema("WASM Base64")),
            ) { args ->
                val b64 = ToolArgs.str(args, "bytesBase64")
                val bytes = runCatching { android.util.Base64.decode(b64, android.util.Base64.DEFAULT) }.getOrNull()
                    ?: return@tool McpToolResult.error("INVALID_WASM", "bytesBase64 无法解码")
                val r = WasmProvenanceEngine().analyze(bytes)
                if (!r.ok) return@tool McpToolResult.error("WASM_PROVENANCE_FAILED", r.error)
                McpToolResult.json(buildJsonObject {
                    put("ok", true); put("confidence", r.confidence); put("rangeCount", r.ranges.size); put("edgeCount", r.edges.size)
                    put("hotMemoryFunctions", JsonArray(r.hotMemoryFunctions.map(::JsonPrimitive)))
                    put("warnings", JsonArray(r.warnings.map(::JsonPrimitive)))
                    put("boundaries", JsonArray(r.boundaries.map { b -> buildJsonObject { put("export", b.export); put("functionIndex", b.functionIndex); put("pointerParams", JsonArray(b.likelyPtrParams.map(::JsonPrimitive))); put("memoryHints", JsonArray(b.memoryRangeHints.map(::JsonPrimitive))) } }))
                    put("edges", JsonArray(r.edges.take(500).map { e -> buildJsonObject { put("from", e.from); put("to", e.to); put("relation", e.relation); put("confidence", e.confidence); put("evidence", JsonArray(e.evidence.map(::JsonPrimitive))) } }))
                })
            },
            f.tool(
                "reverse.js_wasm_provenance_chain",
                "自动构建完整 JS↔WASM provenance：TypedArray→ptr/len→WASM 指令级 memory range→export→返回值 fingerprint→fetch/XHR Network sink，并保留 alias/证据链。",
                ToolCategory.REVERSE, PermissionScope.READ_PAGE, RiskLevel.LOW,
                timeoutMs = 40_000,
                capabilities = "js-wasm,instruction-provenance,pointer-range,alias,typedarray,network-sink,causality",
                cost = 7, reliability = 94,
                inputSchema = Schemas.objectSchema(
                    "source" to Schemas.strSchema("JS 源码"),
                    "wasmBase64" to Schemas.strSchema("可选 WASM Base64"),
                    "includeRuntime" to Schemas.boolSchema("合并当前 Trace"),
                ),
            ) { args ->
                val source = ToolArgs.str(args, "source")
                if (source.isBlank()) return@tool McpToolResult.error("MISSING_SOURCE", "source 必填")
                val wasmB64 = ToolArgs.str(args, "wasmBase64")
                val wasm = if (wasmB64.isBlank()) null else runCatching { android.util.Base64.decode(wasmB64, android.util.Base64.DEFAULT) }.getOrNull()
                val events = if (ToolArgs.bool(args, "includeRuntime", true)) deps.evidenceStore.traceBuffer.all() else emptyList()
                val r = JsWasmProvenanceChain().analyze(source, wasm, events)
                if (!r.ok) return@tool McpToolResult.error("JS_WASM_PROVENANCE_FAILED", r.error)
                McpToolResult.json(buildJsonObject {
                    put("ok", true)
                    put("typedArrayCount", r.typedArrays.size)
                    put("instructionCount", r.instructions.size)
                    put("aliasCount", r.aliases.size)
                    put("chainCount", r.chains.size)
                    put("warnings", JsonArray(r.warnings.map(::JsonPrimitive)))
                    put("typedArrays", JsonArray(r.typedArrays.take(200).map { x -> buildJsonObject { put("variable", x.variable); put("type", x.type); put("offset", x.byteOffsetExpr); put("length", x.byteLengthExpr); put("line", x.line); put("confidence", x.confidence) } }))
                    put("instructions", JsonArray(r.instructions.take(1000).map { x -> buildJsonObject { put("func", x.functionIndex); put("function", x.functionName); put("offset", x.offset); put("opcode", x.opcode); put("mnemonic", x.mnemonic); put("callTarget", x.callTarget ?: -1); x.memoryRange?.let { rr -> put("rangeStart", rr.start); put("rangeEnd", rr.end) }; put("evidence", JsonArray(x.evidence.map(::JsonPrimitive))) } }))
                    put("aliases", JsonArray(r.aliases.take(1000).map { x -> buildJsonObject { put("func", x.wasmFunctionIndex); put("instructionOffset", x.wasmInstructionOffset); put("start", x.range.start); put("end", x.range.end); put("source", x.source); put("relation", x.relation); put("confidence", x.confidence); put("evidence", JsonArray(x.evidence.map(::JsonPrimitive))) } }))
                    put("chains", JsonArray(r.chains.take(100).map { c -> buildJsonObject { put("status", c.status); put("endpoint", c.endpoint); put("confidence", c.confidence); put("explanation", c.explanation); put("nodes", JsonArray(c.nodes.map { n -> buildJsonObject { put("id", n.id); put("kind", n.kind); put("label", n.label); put("detail", n.detail); put("confidence", n.confidence) } })); put("edges", JsonArray(c.edges.map { e -> buildJsonObject { put("from", e.from); put("to", e.to); put("relation", e.relation); put("confidence", e.confidence); put("evidence", JsonArray(e.evidence.map(::JsonPrimitive))) } })) } }))
                })
            },
            f.tool(
                "reverse.worker_dataflow",
                "分析 Worker/SharedWorker/ServiceWorker/iframe/BroadcastChannel/postMessage 跨上下文数据流，并可把运行时 Trace lineage 合并进结果。",
                ToolCategory.WORKER, PermissionScope.READ_PAGE, RiskLevel.LOW,
                timeoutMs = 20_000,
                capabilities = "worker-dataflow,iframe,service-worker,async-lineage",
                cost = 4, reliability = 89,
                inputSchema = Schemas.objectSchema("source" to Schemas.strSchema("JS 源码"), "includeRuntime" to Schemas.boolSchema("合并当前 Trace")),
            ) { args ->
                val source = ToolArgs.str(args, "source")
                val r = WorkerDataFlow().analyze(source)
                val runtime = if (ToolArgs.bool(args, "includeRuntime", true)) WorkerDataFlow().mergeRuntimeLineage(deps.evidenceStore.traceBuffer.all()) else emptyList()
                McpToolResult.json(buildJsonObject {
                    put("ok", true); put("precision", r.precision)
                    put("contexts", JsonArray(r.contexts.map { c -> buildJsonObject { put("id", c.id); put("kind", c.kind.name); put("script", c.script); put("line", c.line) } }))
                    put("channels", JsonArray(r.channels.map { c -> buildJsonObject { put("from", c.from); put("to", c.to); put("kind", c.kind.name); put("line", c.line); put("confidence", c.confidence); put("label", c.label) } }))
                    put("staticFlows", JsonArray(r.flows.map { x -> buildJsonObject { put("from", x.from); put("to", x.to); put("value", x.value); put("line", x.line); put("confidence", x.confidence) } }))
                    put("runtimeFlows", JsonArray(runtime.take(1000).map { x -> buildJsonObject { put("from", x.from); put("to", x.to); put("fingerprint", x.value); put("line", x.line); put("confidence", x.confidence); put("evidence", JsonArray(x.evidence.map(::JsonPrimitive))) } }))
                    put("warnings", JsonArray(r.warnings.map(::JsonPrimitive)))
                })
            },
            f.tool(
                "reverse.jsvmp_vm_ssa",
                "把 JSVMP Handler Micro-IR lowering 成 VM-SSA：虚拟栈、ctx/register、memory、CALL/BRANCH/RETURN 统一版本化。",
                ToolCategory.REVERSE, PermissionScope.READ_PAGE, RiskLevel.LOW,
                timeoutMs = 30_000,
                capabilities = "jsvmp,vm-ssa,micro-ir,semantic-recovery",
                cost = 5, reliability = 90,
                inputSchema = Schemas.objectSchema("source" to Schemas.strSchema("JSVMP JS 源码")),
            ) { args ->
                val source = ToolArgs.str(args, "source")
                val candidates = VmpDetector().detect(source)
                val handlers = candidates.flatMap { it.handlers }.distinctBy { it.key }
                if (handlers.isEmpty()) return@tool McpToolResult.error("NO_VMP_FOUND", "没有可供 VM-SSA lowering 的 handler")
                val r = JsvmpVmSsa().build(handlers)
                if (!r.ok) return@tool McpToolResult.error("VM_SSA_FAILED", r.error)
                McpToolResult.json(buildJsonObject {
                    put("ok", true); put("handlerCount", r.handlers.size); put("uniqueSignatures", r.uniqueSignatures); put("averageConfidence", r.averageConfidence)
                    put("handlers", JsonArray(r.handlers.take(300).map { h ->
                        buildJsonObject {
                            put("opcode", h.opcode); put("normalizedOpcode", h.normalizedOpcode); put("inputs", h.inputs); put("outputs", h.outputs); put("stackDelta", h.stackDelta); put("signature", h.signature); put("confidence", h.confidence)
                            put("warnings", JsonArray(h.warnings.map(::JsonPrimitive)))
                            put("blocks", JsonArray(h.blocks.map { b -> buildJsonObject { put("id", b.id); put("preds", JsonArray(b.preds.map(::JsonPrimitive))); put("succs", JsonArray(b.succs.map(::JsonPrimitive))); put("phis", b.phis.size); put("instrs", b.instrs.take(80).size) } }))
                        }
                    }))
                })
            },
            f.tool(
                "reverse.unified_causal_graph",
                "统一因果图：把 JS 数据流 / Memory SSA / WASM instruction provenance / Worker 数据流 / JSVMP VM-SSA 五类分析汇入同一张图，自动生成跨层因果边（JS→WASM 导出、指针别名、Worker→JS、handler→站点），输出分层覆盖度、跨层连通度与统一因果分；并自动提取可执行差分假设，配合 samples 做多样本差分执行。",
                ToolCategory.REVERSE, PermissionScope.READ_PAGE, RiskLevel.LOW,
                timeoutMs = 60_000,
                capabilities = "unified-causal-graph,causality,memory-ssa,wasm,worker,jsvmp,differential,quality",
                cost = 10, reliability = 95,
                inputSchema = Schemas.objectSchema(
                    "source" to Schemas.strSchema("JS 源码（必填）"),
                    "wasmBase64" to Schemas.strSchema("可选 WASM Base64（启用指令级 provenance）"),
                    "samples" to Schemas.strSchema("可选差分样本 JSON：[{\"inputs\":{\"k\":1,\"d\":2},\"observed\":\"..\"}]，observed 可省（纯差分）"),
                    "hypotheses" to Schemas.strSchema("可选假设族覆盖自动提取：[{\"name\":\"h\",\"formulas\":[{\"name\":\"f\",\"formula\":\"atob({d})\"}]}]"),
                    "includeRuntime" to Schemas.boolSchema("合并当前 Trace（默认 true）"),
                ),
            ) { args ->
                val source = ToolArgs.str(args, "source")
                if (source.isBlank()) return@tool McpToolResult.error("MISSING_SOURCE", "source 必填")
                val wasmB64 = ToolArgs.str(args, "wasmBase64")
                val wasmBytes = if (wasmB64.isBlank()) null else runCatching { android.util.Base64.decode(wasmB64, android.util.Base64.DEFAULT) }.getOrNull()
                val events = if (ToolArgs.bool(args, "includeRuntime", true)) deps.evidenceStore.traceBuffer.all() else emptyList()
                val graph = UnifiedCausalGraph().build(source, wasmBytes, null, events)
                if (!graph.ok) return@tool McpToolResult.error("UNIFIED_GRAPH_FAILED", graph.error)
                // 多样本差分执行：用户提供 samples 时自动跑 differentialRun
                var diff: ValidationEngine.DifferentialReport? = null
                val samplesJson = ToolArgs.str(args, "samples")
                if (samplesJson.isNotBlank()) {
                    val diffSamples = parseDifferentialSamples(samplesJson)
                    val groups = if (ToolArgs.str(args, "hypotheses").isNotBlank()) {
                        parseHypothesisGroups(ToolArgs.str(args, "hypotheses"))
                    } else {
                        graph.differentialTargets.map { t ->
                            ValidationEngine.HypothesisGroup(t.label, t.formulas.map { f -> t.label to f })
                        }
                    }
                    if (diffSamples.isNotEmpty() && groups.isNotEmpty()) {
                        val executor = ValidationEngine.JsExecutor { code, inputs ->
                            kotlinx.coroutines.runBlocking { unifiedGraphExecutor(deps, code, inputs) }
                        }
                        diff = ValidationEngine().differentialRun(executor, diffSamples, groups)
                    }
                }
                McpToolResult.json(buildJsonObject {
                    put("ok", true)
                    put("unifiedScore", graph.unifiedScore)
                    put("nodeCount", graph.nodes.size)
                    put("edgeCount", graph.edges.size)
                    put("layers", JsonArray(graph.layers.map { l ->
                        buildJsonObject {
                            put("layer", l.layer.name); put("nodes", l.nodeCount); put("edges", l.edgeCount)
                            put("linked", l.linked); put("coverage", l.coverage)
                        }
                    }))
                    put("crossLayer", buildJsonObject {
                        put("totalCross", graph.crossLayer.totalCross)
                        put("connectivity", graph.crossLayer.connectivity)
                        put("byPair", JsonObject(graph.crossLayer.byPair.map { (k, v) -> k to JsonPrimitive(v) }.toMap()))
                    })
                    put("nodes", JsonArray(graph.nodes.take(2000).map { n ->
                        buildJsonObject {
                            put("id", n.id); put("layer", n.layer.name); put("kind", n.kind); put("label", n.label)
                            put("line", n.line); put("confidence", n.confidence); put("detail", n.detail)
                        }
                    }))
                    put("edges", JsonArray(graph.edges.take(3000).map { e ->
                        buildJsonObject {
                            put("from", e.from); put("to", e.to); put("relation", e.relation)
                            put("confidence", e.confidence); put("source", e.source.name); put("crossLayer", e.crossLayer)
                        }
                    }))
                    put("differentialTargets", JsonArray(graph.differentialTargets.take(30).map { t ->
                        buildJsonObject {
                            put("id", t.id); put("kind", t.kind); put("label", t.label)
                            put("formulas", JsonArray(t.formulas.map(::JsonPrimitive)))
                            put("sampleKeys", JsonArray(t.sampleKeys.map(::JsonPrimitive)))
                        }
                    }))
                    if (diff != null) {
                        val r = diff!!
                        put("differential", buildJsonObject {
                            put("ok", r.ok); put("sampleCount", r.sampleCount); put("groupCount", r.groupCount)
                            put("hasObserved", r.hasObserved); put("winner", r.winner)
                            put("winnerConfidence", r.winnerConfidence)
                            put("observedAccuracy", JsonObject(r.observedAccuracy.map { (k, v) -> k to JsonPrimitive("%.0f".format(v * 100)) }.toMap()))
                            put("internalConsistency", JsonObject(r.internalConsistency.map { (k, v) -> k to JsonPrimitive("%.0f".format(v * 100)) }.toMap()))
                            put("divergenceSamples", JsonArray(r.divergenceSamples.map(::JsonPrimitive)))
                            put("needsMoreSamples", r.needsMoreSamples)
                            put("summary", r.summary)
                        })
                    }
                    put("warnings", JsonArray(graph.warnings.map(::JsonPrimitive)))
                    put("recommendedNext", JsonArray(graph.recommendedNext.map(::JsonPrimitive)))
                })
            },
        )
    }

    // ---------------- helpers ----------------

    private fun parseDifferentialSamples(json: String): List<ValidationEngine.DifferentialSample> {
        return runCatching {
            val arr = kotlinx.serialization.json.Json.parseToJsonElement(json) as? kotlinx.serialization.json.JsonArray ?: return@runCatching emptyList()
            arr.mapNotNull { el ->
                val obj = (el as? kotlinx.serialization.json.JsonObject) ?: return@mapNotNull null
                val inputsObj = (obj["inputs"] as? kotlinx.serialization.json.JsonObject)
                    ?.mapValues { (_, v) -> (v as? kotlinx.serialization.json.JsonPrimitive)?.let { prim -> prim.content.toLongOrNull() ?: prim.content } ?: v }
                    ?: emptyMap()
                if (inputsObj.isEmpty()) return@mapNotNull null
                val observed = (obj["observed"] as? kotlinx.serialization.json.JsonPrimitive)?.content
                ValidationEngine.DifferentialSample(inputsObj, observed)
            }
        }.getOrDefault(emptyList())
    }

    private fun parseHypothesisGroups(json: String): List<ValidationEngine.HypothesisGroup> {
        return runCatching {
            val arr = kotlinx.serialization.json.Json.parseToJsonElement(json) as? kotlinx.serialization.json.JsonArray ?: return@runCatching emptyList()
            arr.mapNotNull { el ->
                val obj = (el as? kotlinx.serialization.json.JsonObject) ?: return@mapNotNull null
                val name = (obj["name"] as? kotlinx.serialization.json.JsonPrimitive)?.content ?: return@mapNotNull null
                val formulasArr = (obj["formulas"] as? kotlinx.serialization.json.JsonArray) ?: return@mapNotNull null
                val formulas = formulasArr.mapNotNull { fe ->
                    val fo = (fe as? kotlinx.serialization.json.JsonObject) ?: return@mapNotNull null
                    val fn = (fo["name"] as? kotlinx.serialization.json.JsonPrimitive)?.content ?: return@mapNotNull null
                    val ff = (fo["formula"] as? kotlinx.serialization.json.JsonPrimitive)?.content ?: return@mapNotNull null
                    fn to ff
                }
                if (formulas.isEmpty()) return@mapNotNull null
                ValidationEngine.HypothesisGroup(name, formulas)
            }
        }.getOrDefault(emptyList())
    }

    /** 浏览器 JS 执行器（页面内可求值 auto-extracted 调用表达式） */
    private suspend fun unifiedGraphExecutor(
        deps: ToolDependencies,
        code: String,
        inputs: Map<String, Any>,
    ): String? {
        val session = runCatching { deps.activeSession() }.getOrNull() ?: return null
        val engine = session.engine ?: return null
        val bindings = inputs.entries.joinToString(", ") { (k, v) ->
            val js = when (v) {
                is Long -> v.toString()
                is Int -> v.toString()
                is Double -> v.toString()
                is Boolean -> v.toString()
                else -> kotlinx.serialization.json.JsonPrimitive(v.toString()).toString()
            }
            "var $k = $js"
        }
        return runCatching {
            kotlinx.coroutines.runBlocking {
                engine.evaluateJavascript("(function(){ $bindings; return String($code); })()")
            }
        }.getOrNull()
    }
}
