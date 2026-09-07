package com.webreverse.mcp.javascript.analysis

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * JSVMP 轨迹驱动 CFG 恢复 v1（ 新增）。
 *
 * 核心思路：
 * 当静态字节码载体不足以恢复跳转时，用运行时虚拟 pc 执行序列补全控制流——
 * 输入一段 (pc0, pc1, pc2, ...) 序列，输出：
 *   1. **节点统计**：distinct pc、频率、入/出度（热点/枢纽/循环成员）
 *   2. **转移边**：pc -> successor + 计数（动态 CFG 边）
 *   3. **循环识别**：Tarjan 强连通分量 -> 非平凡 SCC = 循环体（JSVMP 加密主循环通常落于此）
 *   4. **回边**：同 SCC 内边 = 循环回边
 *   5. **热区**：最高频 pc / 最高度枢纽 = VM 签名主循环的入口候选
 *
 * 配合 debugger.trace_vmp（采样表达式输出对象 {pc:...,sp:...}）或
 * jsvmp.resolve_vpc（槽位评分）产出的 pc 序列使用；Alignment 到 jsvmp.decompile 的
 * L<n> 标签即可定位目标动作的代码区段（白盒 diff 定位签名路径的前置步骤）。
 */
class VmpTraceCfg {

    data class EdgeInfo(val from: Long, val to: Long, val count: Int)

    data class NodeStat(
        val pc: Long,
        val freq: Int,
        val outDegree: Int,
        val inDegree: Int,
        val inLoop: Boolean,
    )

    data class Report(
        val ok: Boolean,
        val error: String = "",
        val sampleCount: Int = 0,
        val distinctPcs: Int = 0,
        val nodes: List<NodeStat> = emptyList(),
        val edges: List<EdgeInfo> = emptyList(),
        val backEdges: List<EdgeInfo> = emptyList(),
        val loops: List<List<Long>> = emptyList(),
        val loopPcs: List<Long> = emptyList(),
        val hotPcs: List<Pair<Long, Int>> = emptyList(),
        val hubs: List<Long> = emptyList(),
        val entryPc: Long = -1,
        val exitPc: Long = -1,
        val listing: String = "",
    )

    private val json = Json { ignoreUnknownKeys = true }

    /**
     * 从 trace 原始样本行提取 pc 序列。
     * @param rawSamples 每行：JSON 对象（取 pc/vpc/_vpc 内嵌套 pc / 首个数值字段）或纯数值字符串
     * @param pcSlot 指定取值槽（如 "op"）；空则自动
     */
    fun extractPcSequence(rawSamples: List<String>, pcSlot: String = ""): List<Long> {
        val out = ArrayList<Long>(rawSamples.size)
        rawSamples.forEach { s ->
            val t = s.trim()
            if (t.isEmpty()) return@forEach
            val v = parsePcValue(t, pcSlot) ?: return@forEach
            out.add(v)
        }
        return out
    }

    /** 单行解析为一个 pc 数值（对象/裸值均可），解析失败返回 null */
    private fun parsePcValue(line: String, pcSlot: String): Long? {
        // 裸数值（十进制或 0x）
        if (!line.startsWith("{")) {
            return line.trim().toLongOrNull(16)?.let { it } ?: line.trim().toLongOrNull()
        }
        return try {
            val el = json.parseToJsonElement(line)
            if (el !is JsonObject) return (el as? JsonPrimitive)?.content?.toLongOrNull()
            // 优先使用者指定槽
            if (pcSlot.isNotBlank()) {
                (el[pcSlot] as? JsonPrimitive)?.content?.toLongOrNull()?.let { return it }
            }
            // 常见槽名
            for (key in listOf("pc", "vpc", "op", "_vpc")) {
                val v = (el[key] as? JsonPrimitive)?.content?.toLongOrNull()
                if (v != null) return v
            }
            // _vpc 嵌套 {l:[...], a:[...]}
            (el["_vpc"] as? JsonObject)?.let { obj ->
                (obj["pc"] as? JsonPrimitive)?.content?.toLongOrNull()?.let { return it }
            }
            // 兜底：取第一个数值槽
            el.entries.forEach { (_, value) ->
                (value as? JsonPrimitive)?.content?.toLongOrNull()?.let { return it }
            }
            null
        } catch (e: Exception) {
            null
        }
    }

    /**
     * 由 pc 序列构建动态 CFG。
     */
    fun build(seq: List<Long>): Report {
        if (seq.size < 2) {
            return Report(ok = false, error = "样本 pc 序列不足（<2）：请先用 debugger.trace_vmp 以对象表达式采样多变量，或补充 resolve_vpc 槽位样本", sampleCount = seq.size)
        }
        // 节点 + 频率（保持首现顺序）
        val order = LinkedHashMap<Long, Int>()
        seq.forEach { order[it] = (order[it] ?: 0) + 1 }
        // 边
        val edgeMap = HashMap<Pair<Long, Long>, Int>()
        for (i in 0 until seq.size - 1) {
            val k = seq[i] to seq[i + 1]
            edgeMap[k] = (edgeMap[k] ?: 0) + 1
        }
        // 出入度
        val outDeg = HashMap<Long, Int>()
        val inDeg = HashMap<Long, Int>()
        edgeMap.forEach { (e, c) ->
            outDeg[e.first] = (outDeg[e.first] ?: 0) + c
            inDeg[e.second] = (inDeg[e.second] ?: 0) + c
        }
        // 去重邻接表
        val adj = HashMap<Long, MutableSet<Long>>()
        edgeMap.keys.forEach { adj.getOrPut(it.first) { HashSet() }.add(it.second) }

        // Tarjan 强连通分量
        val index = HashMap<Long, Int>()
        val low = HashMap<Long, Int>()
        val stack = ArrayList<Long>()
        val onStack = HashSet<Long>()
        var counter = 0
        val sccs = ArrayList<List<Long>>()

        fun strongConnect(v: Long) {
            index[v] = counter
            low[v] = counter
            counter++
            stack.add(v)
            onStack.add(v)
            adj[v]?.forEach { w ->
                if (w !in index) {
                    strongConnect(w)
                    low[v] = minOf(low[v] ?: Int.MAX_VALUE, low[w] ?: Int.MAX_VALUE)
                } else if (w in onStack) {
                    low[v] = minOf(low[v] ?: Int.MAX_VALUE, index[w] ?: Int.MAX_VALUE)
                }
            }
            if (low[v] == index[v]) {
                val comp = ArrayList<Long>()
                while (true) {
                    val w = stack.removeAt(stack.size - 1)
                    onStack.remove(w)
                    comp.add(w)
                    if (w == v) break
                }
                sccs.add(comp)
            }
        }
        val nodeOrder = ArrayList(order.keys)
        nodeOrder.forEach { if (it !in index) strongConnect(it) }

        // 循环 = 非平凡 SCC（>1 节点）或自环
        val loopSet = HashSet<Long>()
        val loops = ArrayList<List<Long>>()
        sccs.forEach { comp ->
            val isLoop = comp.size > 1 || adj[comp[0]]?.contains(comp[0]) == true
            if (isLoop) {
                loops.add(comp)
                loopSet.addAll(comp)
            }
        }
        // 回边 = 同一非平凡 SCC 内的边
        val sccOf = HashMap<Long, List<Long>>()
        sccs.forEach { comp -> comp.forEach { sccOf[it] = comp } }
        val backEdges = edgeMap.entries
            .filter { (e, _) -> loopSet.contains(e.first) && loopSet.contains(e.second) && sccOf[e.first] == sccOf[e.second] }
            .map { (e, c) -> EdgeInfo(e.first, e.second, c) }

        val edges = edgeMap.entries.map { (e, c) -> EdgeInfo(e.first, e.second, c) }
        val nodes = nodeOrder.map { pc ->
            NodeStat(pc, order[pc] ?: 0, outDeg[pc] ?: 0, inDeg[pc] ?: 0, pc in loopSet)
        }
        val hotPcs = order.entries.sortedByDescending { it.value }.map { it.key to it.value }
        val hubs = nodeOrder
            .map { it to ((outDeg[it] ?: 0) + (inDeg[it] ?: 0)) }
            .filter { it.second >= 2 }
            .sortedByDescending { it.second }
            .map { it.first }

        val listing = buildString {
            appendLine(";; JSVMP dynamic CFG (${seq.size} samples, ${order.size} pcs)")
            appendLine(";; entry=${seq.first()} exit=${seq.last()}")
            if (loops.isNotEmpty()) {
                appendLine(";; loops=${loops.size} loopPcs=${loops.flatten().size}")
                loops.forEachIndexed { i, comp ->
                    appendLine(";;   L${i}: ${comp.sorted().joinToString(" ")}")
                }
            }
            appendLine(";; hot pcs: ${hotPcs.take(10).joinToString(" ") { "${it.first}x${it.second}" }}")
            appendLine(";; hubs: ${hubs.take(10).joinToString(" ")}")
            appendLine("")
            nodes.forEach { n ->
                val flag = when {
                    n.inLoop -> "loop"
                    n.pc == seq.first() -> "entry"
                    n.pc == seq.last() -> "exit"
                    else -> ""
                }
                appendLine("pc ${n.pc}\t(freq=${n.freq} out=${n.outDegree} in=${n.inDegree}${if (flag.isNotEmpty()) " $flag" else ""})")
                edges.filter { it.from == n.pc }.sortedByDescending { it.count }.forEach { e ->
                    val be = if (loopSet.contains(e.from) && loopSet.contains(e.to) && sccOf[e.from] == sccOf[e.to]) " <back>" else ""
                    appendLine("    -> ${e.to}\tx${e.count}$be")
                }
            }
        }

        return Report(
            ok = true,
            sampleCount = seq.size,
            distinctPcs = order.size,
            nodes = nodes,
            edges = edges,
            backEdges = backEdges,
            loops = loops,
            loopPcs = loopSet.toList().sorted(),
            hotPcs = hotPcs,
            hubs = hubs,
            entryPc = seq.first(),
            exitPc = seq.last(),
            listing = listing,
        )
    }
}