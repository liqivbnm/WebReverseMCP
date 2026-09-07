package com.webreverse.mcp.javascript.analysis

/**
 * WASM byte-range provenance graph。在 WasmMemoryProvenance 的静态访问谱之上，
 * 增加函数调用图、data segment、读写重叠和导出边界的多跳传播。
 */
class WasmProvenanceEngine {
    data class RangeNode(val id: String, val start: Long, val end: Long, val kind: String, val label: String)
    data class ProvenanceEdge(val from: String, val to: String, val relation: String, val confidence: Double, val evidence: List<String>)
    data class BoundaryNode(val export: String, val functionIndex: Int, val likelyPtrParams: List<Int>, val memoryRangeHints: List<String>)
    data class Report(
        val ok: Boolean,
        val error: String = "",
        val ranges: List<RangeNode> = emptyList(),
        val edges: List<ProvenanceEdge> = emptyList(),
        val boundaries: List<BoundaryNode> = emptyList(),
        val hotMemoryFunctions: List<String> = emptyList(),
        val confidence: Double = 0.0,
        val warnings: List<String> = emptyList(),
    )

    fun analyze(bytes: ByteArray): Report = runCatching {
        val memory = WasmMemoryProvenance().analyze(bytes)
        if (!memory.ok) return Report(false, memory.error)
        val wasm = WasmParser().parse(bytes)
        if (!wasm.ok) return Report(false, wasm.error)
        val cg = WasmAnalyzer().callGraph(bytes)
        val ranges = mutableListOf<RangeNode>()
        val edges = mutableListOf<ProvenanceEdge>()

        wasm.dataSegments.filter { it.mode == "active" && it.offset >= 0 }.forEachIndexed { i, d ->
            if (d.length > 0) ranges += RangeNode("data:$i", d.offset, d.offset + d.length - 1, "DATA", "data segment #$i")
        }
        memory.funcs.forEach { f ->
            f.writes.forEachIndexed { i, r -> ranges += RangeNode("w:${f.funcIndex}:$i", r.start, r.end, "WRITE", f.funcName) }
            f.reads.forEachIndexed { i, r -> ranges += RangeNode("r:${f.funcIndex}:$i", r.start, r.end, "READ", f.funcName) }
        }
        for (w in ranges.filter { it.kind == "WRITE" }) {
            val relatedData = ranges.firstOrNull { it.kind == "DATA" && overlaps(w, it) }
            if (relatedData != null) edges += ProvenanceEdge(relatedData.id, w.id, "SEEDS", 0.90, listOf("static data overlap"))
        }
        val writes = ranges.filter { it.kind == "WRITE" }
        val reads = ranges.filter { it.kind == "READ" }
        for (w in writes) for (r in reads) if (overlaps(w, r)) {
            edges += ProvenanceEdge(w.id, r.id, "MEMORY_FLOW", 0.86, listOf("overlapping byte range"))
        }
        for ((caller, callees) in cg.adjacency) for (callee in callees) {
            val from = memory.funcs.firstOrNull { it.funcIndex == caller }
            val to = memory.funcs.firstOrNull { it.funcIndex == callee }
            if (from != null && to != null) edges += ProvenanceEdge("func:$caller", "func:$callee", "CALLS", 0.95, listOf("WASM call instruction"))
        }
        val boundaries = wasm.exports.filter { it.kind == "func" }.map { e ->
            val importedFuncCount = wasm.imports.count { it.kind == "func" }
            val sig = if (e.index < importedFuncCount) {
                val imp = wasm.imports.filter { it.kind == "func" }.getOrNull(e.index)
                wasm.types.getOrNull(imp?.typeIndex ?: -1)
            } else {
                wasm.localFunctions.getOrNull(e.index - importedFuncCount)
            }
            val ptrs = sig?.params?.mapIndexedNotNull { i, p -> if (p == "i32") i else null } ?: emptyList()
            BoundaryNode(e.name, e.index, ptrs, memory.funcs.firstOrNull { it.funcIndex == e.index }?.writes?.take(6)?.map { it.toString() } ?: emptyList())
        }
        val hot = memory.topWriters.take(12).map { it.funcName }
        val precision = ((edges.count { it.confidence >= 0.85 }.toDouble() / edges.size.coerceAtLeast(1)) * 0.3 + 0.7).coerceIn(0.0, 1.0)
        Report(true, ranges = ranges.take(20_000), edges = edges.take(40_000), boundaries = boundaries,
            hotMemoryFunctions = hot, confidence = precision,
            warnings = listOfNotNull(if (memory.boundary.pointerExports.isEmpty()) "未识别明显 ptr 导出，可能需要 runtime memory trace" else null))
    }.getOrElse { Report(false, error = it.message ?: "WASM provenance failed") }

    private fun overlaps(a: RangeNode, b: RangeNode): Boolean = a.start <= b.end && b.start <= a.end
}
