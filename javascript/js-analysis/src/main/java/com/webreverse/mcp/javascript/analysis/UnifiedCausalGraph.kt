package com.webreverse.mcp.javascript.analysis

import com.webreverse.mcp.core.common.model.TraceEvent

/**
 * Unified Causal Graph：把五类独立分析汇入同一张可解释因果图。
 *
 * 目标（对齐「从 9.5 往 9.7+ 冲」的关键路径）：
 * 1. **pointer alias**：WASM 指令内存区间 ↔ JS TypedArray/ptr 的别名绑定（来自
 *    [JsWasmProvenanceChain] 的 PointerAlias 与 [WasmProvenanceEngine] 的 range）。
 * 2. **Memory SSA**：JS heap 属性位置的版本化 def-use/phi（来自 [JsMemorySsaBuilder]）。
 * 3. **WASM instruction semantics**：指令级 load/store/call 的 memarg 区间与导出边界。
 * 4. **Worker dataflow**：postMessage/BroadcastChannel/ServiceWorker 跨上下文流。
 * 5. **JSVMP VM-SSA**：handler 的虚拟栈/寄存器/PC 版本化中间表示。
 *
 * 这些引擎原本各自产出一份孤立图；本类把它们合并成统一的节点/边模型，
 * 并**自动生成跨层因果边**（JS 流↔Memory SSA、JS 流→WASM 导出、WASM↔Memory、
 * Worker→JS 流、JSVMP handler→JS 站点），据此计算分层覆盖度、跨层连通度与
 * 统一因果分（0..10），并**自动提取可执行差分假设**（页面内 crypto/decoder 调用
 * 表达式），交给 [ValidationEngine.differentialRun] 做多样本差分执行。
 *
 * 纯 Kotlin，无运行时依赖（trace 事件可选）。
 */
class UnifiedCausalGraph {

    enum class Layer { JS_FLOW, MEMORY_SSA, WASM, WORKER, JSVMP }

    /** 统一图节点 */
    data class UNode(
        val id: String,
        val layer: Layer,
        val kind: String,        // def/call/network-sink/memory-location/wasm-export/worker-context/vm-handler...
        val label: String,
        val line: Int,
        val confidence: Double,
        val detail: String = "",
    )

    /** 统一图边；crossLayer=true 表示跨分析层因果边 */
    data class UEdge(
        val from: String,
        val to: String,
        val relation: String,     // ALIAS / MEMORY_FLOW / WASM_CALL / EXPORT_TO_NETWORK / WORKER_CHANNEL / VM_HANDLER_SITE / DEF_USE ...
        val confidence: Double,
        val evidence: List<String> = emptyList(),
        val source: Layer,
        val crossLayer: Boolean = false,
    )

    data class LayerCoverage(
        val layer: Layer,
        val nodeCount: Int,
        val edgeCount: Int,
        val linked: Int,          // 参与跨层边且入度/出度>0 的节点数
        val coverage: Double,     // 0..1
    )

    data class CrossLayerStats(
        val totalCross: Int,
        val connectivity: Double,          // 参与跨层链路的节点 / 总节点
        val byPair: Map<String, Int>,      // "JS_FLOW->WASM" -> 边数
    )

    /** 差分执行目标：页面内可直接求值的调用表达式（工具层用浏览器执行器跑多样本） */
    data class DifferentialTarget(
        val id: String,
        val kind: String,          // crypto-decoder / decoder / jsvmp-handler
        val label: String,
        val formulas: List<String>,   // 可直接求值的 JS 表达式（占位符 {key} 已按源码参数名命名）
        val sampleKeys: List<String>, // 建议样本输入键
        val confidence: Double,
    )

    data class Result(
        val ok: Boolean,
        val error: String = "",
        val nodes: List<UNode> = emptyList(),
        val edges: List<UEdge> = emptyList(),
        val layers: List<LayerCoverage> = emptyList(),
        val crossLayer: CrossLayerStats = CrossLayerStats(0, 0.0, emptyMap()),
        val unifiedScore: Double = 0.0,
        val differentialTargets: List<DifferentialTarget> = emptyList(),
        val recommendedNext: List<String> = emptyList(),
        val warnings: List<String> = emptyList(),
    )

    // 各层达到“富覆盖”的期望节点数
    private val expectedNodes = mapOf(
        Layer.JS_FLOW to 30, Layer.MEMORY_SSA to 15, Layer.WASM to 10,
        Layer.WORKER to 5, Layer.JSVMP to 8,
    )

    private val cryptoCallee = Regex("(?i)(encrypt|decrypt|encode|decode|sign|verify|hash|hmac|cipher|aes|rsa|md5|sha-?\\d|digest|atob|btoa)")
    private val identifier = Regex("[a-zA-Z_$][\\w$]*")

    /**
     * @param source JS 源码（必填）
     * @param wasmBytes 可选 WASM 字节（提供则启用 WASM instruction semantics + provenance）
     * @param handlers 可选 JSVMP handler 列表；缺省时从 [source] 自动检测
     * @param events 可选运行时 Trace（JS↔WASM export / 网络请求指纹）
     */
    fun build(
        source: String,
        wasmBytes: ByteArray? = null,
        handlers: List<VmpDetector.OpHandler>? = null,
        events: List<TraceEvent> = emptyList(),
    ): Result {
        if (source.isBlank()) return Result(false, error = "source 为空")
        return try {
            val warnings = mutableListOf<String>()
            val nodes = LinkedHashMap<String, UNode>()
            val edges = mutableListOf<UEdge>()

            // ---- 1. JS_FLOW：DeepReverseAnalyzer ----
            val deep = DeepReverseAnalyzer().analyze(source)
            if (deep.ok) {
                for (n in deep.nodes) {
                    nodes[n.id] = UNode(n.id, Layer.JS_FLOW, n.kind, n.label, n.line, n.confidence)
                }
                for (e in deep.edges) {
                    edges += UEdge(e.from, e.to, e.kind.name, e.confidence, e.evidence, Layer.JS_FLOW)
                }
            } else warnings += "JS flow: ${deep.error}"

            // ---- 2. MEMORY_SSA：JsMemorySsaBuilder ----
            val memSsa = JsMemorySsaBuilder().build(source)
            if (memSsa.ok && memSsa.locationCount > 0) {
                val seen = LinkedHashSet<String>()
                for (fn in memSsa.functions) {
                    for (a in fn.accesses) {
                        val key = a.location.toString()
                        if (!seen.add(key)) continue
                        val id = "mem:$key"
                        nodes[id] = UNode(id, Layer.MEMORY_SSA, "memory-location", key, a.line, a.confidence,
                            detail = "aliasClass=${a.location.aliasClass}")
                    }
                }
            } else warnings += "Memory SSA: ${memSsa.error.ifBlank { "无内存访问" }}"

            // ---- 3. WASM：ProvenanceEngine + JsWasmProvenanceChain ----
            var chain: JsWasmProvenanceChain.Report? = null
            if (wasmBytes != null && wasmBytes.size >= 8) {
                val prov = WasmProvenanceEngine().analyze(wasmBytes)
                if (prov.ok) {
                    for (b in prov.boundaries) {
                        val id = "wasm-export:${b.export}"
                        nodes[id] = UNode(id, Layer.WASM, "wasm-export", b.export, 0, 0.95,
                            detail = "func#${b.functionIndex} ptrParams=${b.likelyPtrParams.joinToString(",")}")
                    }
                    for ((i, r) in prov.ranges.withIndex()) {
                        if (r.kind == "DATA") {
                            val id = "wasm-data:$i"
                            nodes[id] = UNode(id, Layer.WASM, "wasm-data-segment", r.label, 0, 0.9,
                                detail = "0x${r.start.toString(16)}..0x${r.end.toString(16)}")
                        }
                    }
                    for (e in prov.edges) {
                        edges += UEdge(e.from, e.to, e.relation, e.confidence, e.evidence, Layer.WASM)
                    }
                } else warnings += "WASM provenance: ${prov.error}"
                chain = JsWasmProvenanceChain().analyze(source, wasmBytes, events)
                if (chain.ok) {
                    for (t in chain.typedArrays) {
                        val id = "js-typed:${t.variable}:${t.line}"
                        nodes[id] = UNode(id, Layer.WASM, "typed-array", t.variable, t.line, t.confidence,
                            detail = "${t.type} off=${t.byteOffsetExpr} len=${t.byteLengthExpr} calls=${t.wasmCalls.joinToString(",")}")
                    }
                    for (c in chain.chains) {
                        for (n in c.nodes) {
                            if (!nodes.containsKey(n.id)) {
                                nodes[n.id] = UNode(n.id, Layer.WASM, n.kind, n.label, 0, n.confidence, n.detail)
                            }
                        }
                        for (e in c.edges) {
                            edges += UEdge(e.from, e.to, e.relation, e.confidence, e.evidence, Layer.WASM)
                        }
                    }
                } else warnings += "JS↔WASM chain: ${chain.error}"
            }

            // ---- 4. WORKER：WorkerDataFlow ----
            val worker = WorkerDataFlow().analyze(source)
            if (worker.ok) {
                for (c in worker.contexts) {
                    val id = "ctx:${c.id}"
                    nodes[id] = UNode(id, Layer.WORKER, "worker-context", c.id, c.line, 0.9, detail = c.kind.name)
                }
                for (c in worker.channels) {
                    val id = "chan:${c.from}->${c.to}:${c.line}"
                    nodes[id] = UNode(id, Layer.WORKER, "worker-channel", c.label, c.line, c.confidence,
                        detail = "${c.kind.name}")
                    edges += UEdge("ctx:${c.from}", id, "CHANNEL_SRC", c.confidence, emptyList(), Layer.WORKER)
                    edges += UEdge(id, "ctx:${c.to}", "CHANNEL_DST", c.confidence, emptyList(), Layer.WORKER)
                }
                for (f in worker.flows) {
                    edges += UEdge("ctx:${f.from}", "ctx:${f.to}", "DATA_FLOW", f.confidence,
                        listOf("value=${f.value}"), Layer.WORKER)
                }
            }

            // ---- 5. JSVMP：JsvmpVmSsa ----
            var vm: JsvmpVmSsa.ProgramReport? = null
            val usedHandlers = handlers ?: VmpDetector().detect(source).flatMap { it.handlers }.distinctBy { it.key }
            if (usedHandlers.isNotEmpty()) {
                vm = JsvmpVmSsa().build(usedHandlers)
                if (vm.ok) {
                    for (h in vm.handlers) {
                        val id = "vm:${h.opcode}"
                        nodes[id] = UNode(id, Layer.JSVMP, "vm-handler", h.opcode, 0, h.confidence,
                            detail = "sig=${h.signature} stackDelta=${h.stackDelta}")
                    }
                } else warnings += "JSVMP VM-SSA: ${vm.error}"
            }

            // ---- 跨层因果边 ----
            val linked = LinkedHashSet<String>()
            fun link(from: String, to: String, relation: String, conf: Double, ev: List<String>) {
                if (from == to) return
                if (nodes.containsKey(from) && nodes.containsKey(to)) {
                    edges += UEdge(from, to, relation, conf, ev, nodes[from]!!.layer, crossLayer = true)
                    linked += from; linked += to
                }
            }

            // JS_FLOW ↔ MEMORY_SSA：属性路径共享（pointer alias 的 JS 侧）
            val jsNodes = nodes.values.filter { it.layer == Layer.JS_FLOW }
            for (m in nodes.values.filter { it.layer == Layer.MEMORY_SSA }) {
                val path = m.label
                val base = path.substringBefore('.')
                for (j in jsNodes) {
                    if (j.label.contains(path) || j.label.contains(base)) {
                        link(j.id, m.id, "ALIAS", (0.7 + 0.2 * m.confidence).coerceAtMost(0.95), listOf("shared property path"))
                    }
                }
            }

            // JS_FLOW → WASM：wasm-boundary 节点 -> 导出名；typed-array -> wasm-export
            val wasmExports = nodes.values.filter { it.layer == Layer.WASM && it.kind == "wasm-export" }
            for (j in jsNodes) {
                if (j.kind == "wasm-boundary") {
                    val exportName = Regex("""exports\.([\w$]+)""").find(j.label)?.groupValues?.getOrNull(1)
                    if (exportName != null) {
                        val target = wasmExports.firstOrNull { it.label == exportName }
                        if (target != null) link(j.id, target.id, "JS_TO_WASM_EXPORT", 0.9, listOf("instance.exports.$exportName"))
                    }
                }
            }
            val typedArrays = nodes.values.filter { it.layer == Layer.WASM && it.kind == "typed-array" }
            for (t in typedArrays) {
                val calls = Regex("calls=([^ ]*)").find(t.detail)?.groupValues?.getOrNull(1).orEmpty().split(",").filter { it.isNotBlank() }
                for (c in calls) {
                    val target = wasmExports.firstOrNull { it.label == c }
                    if (target != null) link(t.id, target.id, "TYPED_ARRAY_TO_WASM", 0.88, listOf("typed-array passed to export '$c'"))
                }
            }

            // WASM ↔ MEMORY_SSA：TypedArray 变量名与 memory location base 共享
            for (t in typedArrays) {
                for (m in nodes.values.filter { it.layer == Layer.MEMORY_SSA }) {
                    if (m.label.substringBefore('.').let { it.isNotEmpty() && it != "*" && t.label == it }) {
                        link(t.id, m.id, "POINTER_ALIAS", 0.86, listOf("shared buffer identifier"))
                    }
                }
            }

            // WORKER → JS_FLOW：worker 数据流值名与 JS 流节点共享
            for (w in edges.filter { it.source == Layer.WORKER && it.relation == "DATA_FLOW" }) {
                val valName = w.evidence.firstOrNull { it.startsWith("value=") }?.removePrefix("value=") ?: continue
                val clean = valName.trim('"', '\'', ' ')
                for (j in jsNodes) {
                    if (j.label.contains(clean) || j.label == clean) {
                        link(w.from, j.id, "WORKER_TO_JS", 0.82, listOf("shared message value"))
                    }
                }
            }

            // JSVMP → JS_FLOW：handler 行号邻近的 JS 站点
            if (vm != null && vm.ok) {
                for (h in vm.handlers) {
                    val hNode = nodes["vm:${h.opcode}"] ?: continue
                    val hLine = usedHandlers.firstOrNull { it.key == h.opcode }?.line ?: 0
                    for (j in jsNodes) {
                        if (hLine > 0 && kotlin.math.abs(j.line - hLine) <= 4) {
                            link(hNode.id, j.id, "VM_HANDLER_SITE", 0.8, listOf("handler line $hLine near JS line ${j.line}"))
                        }
                    }
                }
            }

            // ---- 分层覆盖度 ----
            val layers = Layer.entries.map { layer ->
                val ls = nodes.values.filter { it.layer == layer }
                val lEdges = edges.filter { it.source == layer }
                val lLinked = ls.count { it.id in linked }
                val maxN = expectedNodes[layer] ?: 8
                val richness = if (ls.isEmpty()) 0.0 else (ls.size.toDouble() / maxN).coerceAtMost(1.0)
                val linkRatio = if (ls.isEmpty()) 0.0 else lLinked.toDouble() / ls.size
                val coverage = (0.6 * richness + 0.4 * linkRatio).coerceIn(0.0, 1.0)
                LayerCoverage(layer, ls.size, lEdges.size, lLinked, coverage)
            }

            // ---- 跨层连通度 ----
            val crossEdges = edges.filter { it.crossLayer }
            val byPair = crossEdges.groupingBy { "${it.source}->${nodes[it.to]?.layer}" }.eachCount()
            val totalNodes = nodes.size.coerceAtLeast(1)
            val connectivity = (linked.size.toDouble() / totalNodes).coerceIn(0.0, 1.0)
            val crossLayerStats = CrossLayerStats(crossEdges.size, connectivity, byPair)

            // ---- 统一因果分 ----
            val scoreParts = layers.map { it.coverage } + connectivity
            val unifiedScore = (scoreParts.average() * 10.0).coerceIn(0.0, 10.0)

            // ---- 差分执行目标（自动提取）----
            val targets = extractDifferentialTargets(source, usedHandlers)

            // ---- 建议 ----
            val next = mutableListOf<String>()
            if (crossEdges.size < 3) next += "跨层链路稀疏：补充 WASM 字节或 runtime Trace 以建立 JS→WASM→Network 因果链"
            val wasmLayer = layers.firstOrNull { it.layer == Layer.WASM }
            if (wasmBytes == null || wasmLayer == null || wasmLayer.nodeCount == 0) next += "提供 wasmBase64 + runtime WASM_EXPORT Trace 以启用 WASM instruction provenance"
            val vmLayer = layers.firstOrNull { it.layer == Layer.JSVMP }
            if (vmLayer == null || vmLayer.nodeCount == 0) next += "检测到 JSVMP 后对每个 handler 补多样本差分执行以收敛 opcode 语义"
            val workerLayer = layers.firstOrNull { it.layer == Layer.WORKER }
            if (workerLayer != null && workerLayer.nodeCount >= 2) next += "对 postMessage 值做运行时 parentEventId/fingerprint 绑定，确定跨上下文生产者"
            if (targets.isNotEmpty()) next += "对 ${targets.take(3).joinToString { it.label }} 注入多样本（0/负数/边界）跑 differentialRun"
            else next += "未提取到可差分目标：优先定位 crypto/decoder 调用表达式后进入差分验证"
            if (deep.ok && deep.networkSinks.isNotEmpty() && deep.cryptoBindings.isNotEmpty() && unifiedScore >= 9.5) next += "统一因果图达到 9.5+：可进入 CONFIRMED 级验证闭环"

            Result(
                ok = true,
                nodes = nodes.values.take(20_000),
                edges = edges.distinctBy { "${it.from}|${it.to}|${it.relation}" }.take(40_000),
                layers = layers,
                crossLayer = crossLayerStats,
                unifiedScore = unifiedScore,
                differentialTargets = targets.take(50),
                recommendedNext = next.distinct().take(10),
                warnings = warnings.distinct().take(12),
            )
        } catch (t: Throwable) {
            Result(false, error = "${t::class.simpleName}: ${t.message ?: "unified graph failed"}")
        }
    }

    /** 从源码自动提取可在浏览器内直接求值的差分目标（crypto/decoder 调用表达式 + JSVMP handler 语义） */
    private fun extractDifferentialTargets(
        source: String,
        handlers: List<VmpDetector.OpHandler>,
    ): List<DifferentialTarget> {
        val out = mutableListOf<DifferentialTarget>()
        // 1) crypto/decoder 调用表达式：页面内可求值
        val decoderNames = runCatching {
            StaticAnalyzer().analyze(source).decryptChain.let { if (it.found) listOf(it.decoderName) else emptyList() }
        }.getOrDefault(emptyList())
        val lines = source.lines()
        for ((i, raw) in lines.withIndex()) {
            val line = raw.trim()
            val callRe = Regex("""\b([a-zA-Z_$][\w$]*)\s*\(([^()]*)\)""")
            for (m in callRe.findAll(line)) {
                val name = m.groupValues[1]
                val args = m.groupValues[2].trim()
                if (args.isBlank()) continue
                val isCrypto = cryptoCallee.containsMatchIn(name)
                val isDecoder = decoderNames.contains(name)
                if (!isCrypto && !isDecoder) continue
                val expr = "$name($args)"
                val keys = identifier.findAll(args).map { it.value }.distinct().filter { !JS_KEYWORDS.contains(it) }.toList()
                if (keys.isEmpty()) continue
                val id = "diff:${name}:${i + 1}"
                val existing = out.indexOfFirst { it.id == id }
                if (existing >= 0) {
                    val e = out[existing]
                    out[existing] = e.copy(
                        formulas = (e.formulas + expr).distinct(),
                        sampleKeys = (e.sampleKeys + keys).distinct(),
                    )
                } else {
                    out += DifferentialTarget(id, if (isCrypto) "crypto-decoder" else "decoder", name,
                        mutableListOf(expr), keys, 0.85)
                }
            }
        }
        // 2) JSVMP handler：每个 opcode 作为一个语义假设目标
        if (handlers.isNotEmpty()) {
            val micro = runCatching { JsvmpMicroIr().translate(handlers) }.getOrDefault(emptyList())
            for (u in micro) {
                val id = "diff:handler:${u.normalizedKey}"
                if (out.any { it.id == id }) continue
                val keys = u.ops.flatMap { identifier.findAll(it.detail).map { x -> x.value } }
                    .distinct().filter { !JS_KEYWORDS.contains(it) }
                out += DifferentialTarget(id, "jsvmp-handler", "opcode=${u.key}",
                    listOf("${u.signature} :: ${u.summary}"), keys, u.ops.maxOfOrNull { 0.9 } ?: 0.85)
            }
        }
        return out
    }

    private companion object {
        val JS_KEYWORDS = setOf(
            "var", "let", "const", "function", "return", "if", "else", "for", "while", "new",
            "this", "typeof", "in", "of", "true", "false", "null", "undefined", "do", "switch",
            "case", "break", "continue", "try", "catch", "finally", "throw", "class", "extends",
            "async", "await", "yield", "static", "import", "export", "from", "default", "void",
            "delete", "instanceof", "with", "debugger",
        )
    }
}
