package com.webreverse.mcp.javascript.analysis

/**
 * JS Memory/Object SSA：面向逆向的 Heap SSA。
 *
 * 目标不是模拟完整 JS 引擎，而是把最容易破坏签名/Token 数据流的 heap side effect
 * 显式化：obj.x、obj["x"]、arr[i]、Object.assign、spread、delete 以及未知动态属性。
 *
 * 设计：
 * - 对象位置采用 field-sensitive abstract location；动态 key 归入 wildcard。
 * - 每个写入产生 MemoryDef(version)，每个读取关联 MemoryUse(version)。
 * - 基于 CFG predecessor 在 join 点插入 MemoryPhi；循环使用 fixpoint 收敛。
 * - 对未知 alias 使用 conservative TopHeap，确保“不误报精确来源”优先于假精确。
 */
class JsMemorySsaBuilder {
    companion object {
        const val MAX_MEMORY_OPS = 20_000
        const val MAX_LOCATIONS = 8_192
        const val MAX_PHIS = 4_096
    }

    enum class AccessKind { READ, WRITE, READ_WRITE, ESCAPE }

    data class MemoryLocation(
        val base: String,
        val field: String,
        val aliasClass: String,
    ) {
        override fun toString(): String = "$base.$field"
    }

    data class MemoryAccess(
        val functionId: Int,
        val blockId: Int,
        val line: Int,
        val order: Int,
        val kind: AccessKind,
        val location: MemoryLocation,
        val expression: String,
        val confidence: Double,
    )

    data class MemoryVersion(
        val location: MemoryLocation,
        val version: Int,
        val functionId: Int,
        val blockId: Int,
        val line: Int,
        val producerOrder: Int,
        val producer: String,
    )

    data class MemoryPhi(
        val location: MemoryLocation,
        val functionId: Int,
        val blockId: Int,
        val version: Int,
        val incoming: Map<Int, MemoryVersion>,
        val confidence: Double,
    )

    data class FunctionMemorySsa(
        val functionId: Int,
        val functionName: String,
        val accesses: List<MemoryAccess>,
        val versions: List<MemoryVersion>,
        val phis: List<MemoryPhi>,
        val defUse: Map<String, List<String>>,
        val escapeLocations: Set<String>,
    )

    data class Report(
        val ok: Boolean,
        val error: String = "",
        val functions: List<FunctionMemorySsa> = emptyList(),
        val locationCount: Int = 0,
        val memoryOps: Int = 0,
        val phiCount: Int = 0,
        val wildcardReads: Int = 0,
        val escapedLocations: Int = 0,
        val precision: Double = 0.0,
        val warnings: List<String> = emptyList(),
    )

    fun build(source: String): Report {
        return runCatching {
            val ssa = JsSsaBuilder().build(source)
            val out = mutableListOf<FunctionMemorySsa>()
            var totalAccesses = 0
            var totalPhis = 0
            var wildcard = 0
            var escapes = 0
            val allLocations = LinkedHashSet<MemoryLocation>()
            val warnings = mutableListOf<String>()

            for (fn in ssa.functions) {
                val accesses = mutableListOf<MemoryAccess>()
                var order = 0
                for (block in fn.blocks) {
                    for (ins in block.instrs) {
                        if (accesses.size >= MAX_MEMORY_OPS) break
                        val expr = ins.expr ?: continue
                        collectExpr(expr, fn.info.id, block.id, ins.line, order++, accesses)
                    }
                }
                if (accesses.isEmpty()) continue
                allLocations.addAll(accesses.map { it.location })
                wildcard += accesses.count { it.location.field == "*" }
                escapes += accesses.count { it.kind == AccessKind.ESCAPE }
                val result = buildFunction(fn, accesses)
                totalAccesses += accesses.size
                totalPhis += result.phis.size
                out += result
                if (allLocations.size > MAX_LOCATIONS) break
            }
            val precision = if (totalAccesses == 0) 1.0 else {
                val exact = totalAccesses - wildcard
                (exact.toDouble() / totalAccesses.toDouble()).coerceIn(0.0, 1.0)
            }
            if (wildcard > 0) warnings += "$wildcard 次动态属性访问使用 wildcard alias，结果为保守近似"
            if (totalPhis >= MAX_PHIS) warnings += "MemoryPhi 达到上限，部分超大函数被截断"
            Report(true, functions = out, locationCount = allLocations.size, memoryOps = totalAccesses,
                phiCount = totalPhis, wildcardReads = wildcard, escapedLocations = escapes,
                precision = precision, warnings = warnings)
        }.getOrElse { Report(false, error = it.message ?: "Memory SSA failed") }
    }

    private fun buildFunction(fn: JsSsaBuilder.SsaFunctionResult, accesses: List<MemoryAccess>): FunctionMemorySsa {
        val byBlock = accesses.groupBy { it.blockId }
        val orderedBlocks = fn.blocks.sortedBy { if (it.id == fn.entry) 0 else it.id }
        val phis = mutableListOf<MemoryPhi>()
        val versions = mutableListOf<MemoryVersion>()
        val counters = mutableMapOf<MemoryLocation, Int>()
        val inState = mutableMapOf<Int, Map<MemoryLocation, MemoryVersion>>()
        val outState = mutableMapOf<Int, Map<MemoryLocation, MemoryVersion>>()

        fun newVersion(loc: MemoryLocation, block: Int, line: Int, order: Int, producer: String): MemoryVersion {
            val n = (counters[loc] ?: 0) + 1
            counters[loc] = n
            return MemoryVersion(loc, n, fn.info.id, block, line, order, producer)
        }

        // First establish a stable reaching-definition state. A maximum of 12 iterations is enough
        // for normal JS loops; a loop-carried memory location converges to the same abstract version.
        repeat(12) {
            var changed = false
            for (block in orderedBlocks) {
                val incoming = mergeMemoryPred(block, outState)
                if (incoming != inState[block.id]) { inState[block.id] = incoming; changed = true }
                val state = incoming.toMutableMap()
                for (a in byBlock[block.id].orEmpty()) {
                    when (a.kind) {
                        AccessKind.WRITE, AccessKind.READ_WRITE, AccessKind.ESCAPE -> {
                            val existing = versions.firstOrNull { it.functionId == fn.info.id && it.blockId == a.blockId && it.line == a.line && it.producerOrder == a.order && it.location == a.location }
                            val v = existing ?: newVersion(a.location, a.blockId, a.line, a.order, a.expression).also { versions += it }
                            state[a.location] = v
                        }
                        AccessKind.READ -> Unit
                    }
                }
                if (state != outState[block.id]) { outState[block.id] = state; changed = true }
            }
            if (!changed) return@repeat
        }

        // Materialize MemoryPhi only where predecessor reaching defs differ, and feed the phi
        // back into the join block state so subsequent reads really consume the merged version.
        for (block in orderedBlocks) {
            if (block.preds.size < 2) continue
            val predMaps = block.preds.mapNotNull { outState[it] }
            val locations = predMaps.flatMap { it.keys }.toSet()
            val state = inState[block.id]?.toMutableMap() ?: mutableMapOf()
            for (loc in locations) {
                val incoming = block.preds.mapNotNull { p -> outState[p]?.get(loc)?.let { p to it } }.toMap()
                if (incoming.values.map { it.version to it.functionId }.distinct().size > 1) {
                    val existing = phis.firstOrNull { it.functionId == fn.info.id && it.blockId == block.id && it.location == loc }
                    val phi = existing?.let { versions.firstOrNull { v -> v.location == loc && v.version == it.version } }
                        ?: newVersion(loc, block.id, 0, -1, "MemoryPhi").also { versions += it }
                    if (existing == null) phis += MemoryPhi(loc, fn.info.id, block.id, phi.version, incoming, 0.97)
                    state[loc] = phi
                }
            }
            inState[block.id] = state
        }

        val defUse = LinkedHashMap<String, MutableList<String>>()
        val escapeLocations = LinkedHashSet<String>()
        for (block in orderedBlocks) {
            val state = (inState[block.id] ?: emptyMap()).toMutableMap()
            for (a in byBlock[block.id].orEmpty()) {
                val key = a.location.toString()
                when (a.kind) {
                    AccessKind.READ -> {
                        state[a.location]?.let { v ->
                            defUse.getOrPut("${key}.${v.version}") { mutableListOf() }.add("read@${a.line}:${a.expression}")
                        }
                    }
                    AccessKind.WRITE, AccessKind.READ_WRITE, AccessKind.ESCAPE -> {
                        val v = versions.firstOrNull { it.functionId == fn.info.id && it.blockId == a.blockId && it.line == a.line && it.producerOrder == a.order && it.location == a.location }
                        if (v != null) state[a.location] = v
                        if (a.kind == AccessKind.ESCAPE) escapeLocations += key
                    }
                }
            }
        }
        return FunctionMemorySsa(
            fn.info.id, fn.info.name, accesses, versions.distinctBy { it.location to it.version },
            phis.distinctBy { Triple(it.functionId, it.blockId, it.location) },
            defUse.mapValues { it.value.toList() }, escapeLocations,
        )
    }

    private fun mergeMemoryPred(
        block: JsSsaBuilder.SsaBlock,
        outState: Map<Int, Map<MemoryLocation, MemoryVersion>>,
    ): Map<MemoryLocation, MemoryVersion> {
        if (block.preds.isEmpty()) return emptyMap()
        val states = block.preds.mapNotNull { outState[it] }
        if (states.isEmpty()) return emptyMap()
        val locations = states.flatMap { it.keys }.toSet()
        val result = LinkedHashMap<MemoryLocation, MemoryVersion>()
        for (loc in locations) {
            val vals = states.mapNotNull { it[loc] }
            if (vals.isNotEmpty()) result[loc] = vals.first()
        }
        return result
    }

    private fun collectExpr(e: Expr, fnId: Int, blockId: Int, line: Int, order: Int, out: MutableList<MemoryAccess>) {
        fun add(kind: AccessKind, loc: MemoryLocation, expr: String, confidence: Double) {
            if (out.size < MAX_MEMORY_OPS) out += MemoryAccess(fnId, blockId, line, order, kind, loc, expr, confidence)
        }
        fun visit(x: Expr) {
            when (x) {
                is Expr.Member -> {
                    val loc = locationOf(x)!!
                    add(AccessKind.READ, loc, AstRender.expr(x), if (loc.field == "*") 0.68 else 0.96)
                    visit(x.obj); x.computed?.let(::visit)
                }
                is Expr.Assign -> {
                    val targetLoc = locationOf(x.target)
                    if (targetLoc != null) {
                        val kind = if (x.op == "=") AccessKind.WRITE else AccessKind.READ_WRITE
                        add(kind, targetLoc, AstRender.expr(x.target), if (targetLoc.field == "*") 0.70 else 0.97)
                    } else add(AccessKind.ESCAPE, MemoryLocation("<unknown>", "*", "TopHeap"), AstRender.expr(x.target), 0.52)
                    visit(x.target); visit(x.value)
                }
                is Expr.Call -> {
                    // Object.assign({}, src) / Reflect.set / Object.defineProperty are heap writes.
                    val callee = AstRender.expr(x.callee)
                    if (callee.matches(Regex("(?i).*(Object\\.assign|Reflect\\.set|defineProperty)$"))) {
                        x.args.firstOrNull()?.let { base ->
                            val name = exprBase(base)
                            add(AccessKind.ESCAPE, MemoryLocation(name, "*", "TopHeap"), callee, 0.72)
                        }
                    }
                    visit(x.callee); x.args.forEach(::visit)
                }
                is Expr.New -> { visit(x.callee); x.args.forEach(::visit); add(AccessKind.ESCAPE, MemoryLocation(AstRender.expr(x.callee), "*", "HeapObject"), AstRender.expr(x), 0.74) }
                is Expr.ObjectLit -> {
                    x.props.forEach { p -> p.value?.let(::visit); p.computed?.let(::visit) }
                    add(AccessKind.ESCAPE, MemoryLocation("<object@${x.pos.offset}>", "*", "HeapObject"), AstRender.expr(x), 0.78)
                }
                is Expr.ArrayLit -> { x.elements.forEach(::visit); add(AccessKind.ESCAPE, MemoryLocation("<array@${x.pos.offset}>", "*", "HeapArray"), AstRender.expr(x), 0.78) }
                is Expr.FunctionExpr -> x.body.stmts.forEach { collectStmt(it, fnId, blockId, line, order, out) }
                is Expr.Binary -> { visit(x.left); visit(x.right) }
                is Expr.Conditional -> { visit(x.test); visit(x.consequent); visit(x.alternate) }
                is Expr.Unary -> visit(x.operand)
                is Expr.TaggedTemplate -> { visit(x.tag); visit(x.template) }
                is Expr.TemplateLit -> x.exprs.forEach(::visit)
                is Expr.Spread -> visit(x.arg)
                is Expr.Sequence -> x.exprs.forEach(::visit)
                is Expr.AwaitExpr -> visit(x.arg)
                is Expr.YieldExpr -> x.arg?.let(::visit)
                else -> Unit
            }
        }
        visit(e)
    }

    private fun collectStmt(s: Stmt, fnId: Int, blockId: Int, line: Int, order: Int, out: MutableList<MemoryAccess>) {
        when (s) {
            is Stmt.ExprStmt -> collectExpr(s.expr, fnId, blockId, line, order, out)
            is Stmt.VarDecl -> s.init?.let { collectExpr(it, fnId, blockId, line, order, out) }
            is Stmt.Return -> s.arg?.let { collectExpr(it, fnId, blockId, line, order, out) }
            is Stmt.Throw -> s.arg?.let { collectExpr(it, fnId, blockId, line, order, out) }
            is Stmt.Block -> s.stmts.forEach { collectStmt(it, fnId, blockId, line, order, out) }
            else -> Unit
        }
    }

    private fun locationOf(e: Expr): MemoryLocation? = if (e is Expr.Member) {
        val base = exprBase(e.obj)
        val field = e.property ?: e.computed?.let { constantKey(it) } ?: "*"
        MemoryLocation(base, field, if (field == "*") "TopHeap" else "Field:$base.$field")
    } else null

    private fun exprBase(e: Expr): String = when (e) {
        is Expr.Identifier -> e.name
        is Expr.ThisRef -> "this"
        is Expr.Member -> "${exprBase(e.obj)}.${e.property ?: "*"}"
        else -> "<expr@${e.pos.offset}>"
    }

    private fun constantKey(e: Expr): String? = when (e) {
        is Expr.StringLit -> e.value
        is Expr.Number -> e.value
        else -> null
    }
}
