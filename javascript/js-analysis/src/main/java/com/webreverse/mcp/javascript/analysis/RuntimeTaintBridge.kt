package com.webreverse.mcp.javascript.analysis

/**
 * 运行时污点 → 静态污点 桥接（v1）。
 *
 * 运行时注入侧（js-runtime 的 TaintTracker）上报的运行时就地标签（来源、传播
 * 中间步、汇、路径），经此把标签合并进静态 [TaintEngine] 的结果，形成
 * “静态传播主路径 + 运行时观测”的联合视图。
 *
 * 设计约束：js-analysis 不依赖 js-runtime（避免模块依赖反转），因此本桥接
 * 定义**中立的运行时标签输入结构**（[RuntimeTaintBridgeInput]），任何来源
 * （js-runtime 上报 JSON / 日志 / 手工）都可填充进它，再交给
 * [RuntimeTaintBridge.merge] 并入静态 [TaintEngine.TaintReport]。
 *
 * 不改动 TaintEngine 既有静态传播主路径：仅在外部用新方法分析（见
 * [TaintEngine.analyzeBridged]）。
 */
class RuntimeTaintBridge {

    /** 运行时污点路径步（来源→中间→汇中的一节）。 */
    data class Step(val kind: String, val label: String, val seq: Long)

    /** 单条运行时污点流。 */
    data class Flow(val tagId: String, val sourceLabel: String, val sinkLabel: String, val path: List<Step>)

    /** 运行时污点标签输入（桥接入口的数据结构）。 */
    data class Input(val flows: List<Flow>)

    /**
     * 把运行时流转成静态 [TaintEngine.TaintFlow]。
     * 缺行/列信息时以 0 占位，并将运行时传播步映射为 TaintStep。
     */
    fun toFlows(input: Input, severity: TaintEngine.Severity = TaintEngine.Severity.HIGH): List<TaintEngine.TaintFlow> =
        input.flows.map { f ->
            val steps = if (f.path.isEmpty()) {
                listOf(
                    TaintEngine.TaintStep(f.sourceLabel, 0, "◎ runtime source ${f.sourceLabel}", "runtime", "运行时"),
                    TaintEngine.TaintStep(f.sinkLabel, 0, "▶ runtime sink ${f.sinkLabel}", "runtime", "运行时"),
                )
            } else {
                f.path.map { p ->
                    val isHop = p.kind != "source" && p.kind != "sink"
                    TaintEngine.TaintStep(
                        funcName = p.label,
                        line = p.seq.toInt(),
                        desc = p.label,
                        varName = p.label,
                        hop = if (isHop) "运行时(${p.kind})" else "",
                    )
                }
            }
            TaintEngine.TaintFlow(
                sourceLabel = f.sourceLabel,
                sourceLine = 0,
                sourceFunc = "runtime:${f.tagId}",
                sinkLabel = f.sinkLabel,
                sinkLine = 0,
                sinkFunc = "runtime",
                path = steps,
                crossFunction = true,
                severity = severity,
                transforms = steps.map { it.desc }.distinct().take(10),
            )
        }

    /**
     * 把 [runtime] 上报的标签合并进已算好的静态 [static] 报告，返回新的合并报告。
     * 去重键 = 来源|汇|路径，运行时的流追加到静态流之后。
     */
    fun merge(
        static: TaintEngine.TaintReport,
        runtime: Input,
        severity: TaintEngine.Severity = TaintEngine.Severity.HIGH,
    ): TaintEngine.TaintReport {
        val merged = static.flows.toMutableList()
        merged.addAll(toFlows(runtime, severity))
        // 尽量去重：完全同源同汇同路径的流只保留一次（静态优先）
        val dedup = LinkedHashMap<String, TaintEngine.TaintFlow>()
        for (f in merged) dedup.putIfAbsent("${f.sourceLabel}|${f.sinkLabel}|${f.path}", f)
        val ordered = static.flows.size.takeIf { it > 0 }?.let {
            dedup.values.toList()
        } ?: dedup.values.toList()
        return TaintEngine.TaintReport(
            flows = ordered.sortedWith(compareByDescending<TaintEngine.TaintFlow> { it.severity }.thenBy { it.sinkLine }),
            sourceCount = static.sourceCount + runtime.flows.size,
            sinkCount = static.sinkCount + runtime.flows.size,
            taintedVarCount = static.taintedVarCount + runtime.flows.size,
            iterations = static.iterations,
        )
    }

    /**
     * 把运行时 `RuntimeTaint`（其它模块/串）解析成 [Input]，逐条宽容解析。
     * @param rawFlows 每项至少包含 source / sink / path 元素；path 元素含 kind/label/seq。
     */
    fun fromRaw(rawFlows: List<Map<String, Any?>>): Input {
        val flows = rawFlows.mapNotNull { row ->
            val source = row["sourceLabel"] as? String ?: row["source"] as? String ?: return@mapNotNull null
            val sink = row["sinkLabel"] as? String ?: row["sink"] as? String ?: ""
            val tagId = (row["tagId"] as? String) ?: "runtime"
            val path = (row["path"] as? List<*>)?.mapNotNull { p ->
                if (p is Map<*, *>) {
                    Step(
                        kind = p["kind"]?.toString() ?: "",
                        label = p["label"]?.toString() ?: "",
                        seq = (p["seq"] as? Number)?.toLong() ?: 0L,
                    )
                } else null
            } ?: emptyList()
            Flow(tagId, source, sink, path)
        }
        return Input(flows)
    }
}