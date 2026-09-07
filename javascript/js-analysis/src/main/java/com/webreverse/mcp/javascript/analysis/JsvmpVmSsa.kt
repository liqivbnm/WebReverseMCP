package com.webreverse.mcp.javascript.analysis

/**
 * JSVMP VM-SSA：在 Micro-IR 之上显式建模虚拟栈/寄存器/PC/环境状态。
 * 每条 handler 的微操作被 lower 到统一 VM 指令，再做版本化与 phi 合并，
 * 为后续 opcode equivalence、控制流恢复、动态 differential validation 提供稳定 IR。
 */
class JsvmpVmSsa {
    enum class VmOp { CONST, LOAD, STORE, STACK_PUSH, STACK_POP, BINOP, CMP, BRANCH, CALL, READ_MEM, WRITE_MEM, READ_CTX, WRITE_CTX, RETURN, UNKNOWN }
    data class VmValue(val name: String, val version: Int, val kind: String) { override fun toString() = "$name.$version" }
    data class VmInstr(val op: VmOp, val result: VmValue?, val uses: List<VmValue>, val detail: String, val sourceAddr: Int, val confidence: Double)
    data class VmBlock(val id: Int, val preds: List<Int>, val succs: List<Int>, val instrs: List<VmInstr>, val phis: List<VmInstr>)
    data class HandlerVmSsa(val opcode: String, val normalizedOpcode: String, val blocks: List<VmBlock>, val inputs: Int, val outputs: Int, val stackDelta: Int, val signature: String, val confidence: Double, val warnings: List<String>)
    data class ProgramReport(val ok: Boolean, val handlers: List<HandlerVmSsa> = emptyList(), val uniqueSignatures: Int = 0, val averageConfidence: Double = 0.0, val error: String = "")

    fun build(handlers: List<VmpDetector.OpHandler>): ProgramReport = runCatching {
        val micro = JsvmpMicroIr().translate(handlers)
        val byNormalized = micro.associateBy { it.normalizedKey }
        val out = handlers.mapNotNull { h ->
            val key = JsvmpMicroIr().normalizeKey(h.key) ?: return@mapNotNull null
            val u = byNormalized[key] ?: return@mapNotNull null
            lower(h, u)
        }
        ProgramReport(true, out, out.map { it.signature }.toSet().size, out.map { it.confidence }.average().takeIf { !it.isNaN() } ?: 1.0)
    }.getOrElse { ProgramReport(false, error = it.message ?: "VM SSA failed") }

    private fun lower(handler: VmpDetector.OpHandler, unit: JsvmpMicroIr.MicroUnit): HandlerVmSsa {
        val versions = mutableMapOf<String, Int>()
        val current = mutableMapOf<String, VmValue>()
        val blocksInstr = mutableListOf<MutableList<VmInstr>>()
        val blockSucc = mutableMapOf<Int, MutableList<Int>>()
        val blockPred = mutableMapOf<Int, MutableList<Int>>()
        var blockId = 0
        blocksInstr.add(mutableListOf<VmInstr>())

        fun newValue(name: String, kind: String = "value"): VmValue {
            val v = (versions[name] ?: 0) + 1
            versions[name] = v
            return VmValue(name, v, kind)
        }
        fun read(name: String): VmValue = current[name] ?: VmValue(name, 0, "unknown")
        fun connect(from: Int, to: Int) {
            blockSucc.getOrPut(from) { mutableListOf() }.add(to)
            blockPred.getOrPut(to) { mutableListOf() }.add(from)
        }

        var stackDepth = 0
        var minDepth = 0
        var hasBranch = false
        for (op in unit.ops) {
            val list = blocksInstr[blockId]
            when (op.op) {
                JsvmpMicroIr.MicroOp.LOAD_CONST, JsvmpMicroIr.MicroOp.PUSH_STR -> {
                    val r = newValue("s$stackDepth", "stack"); current[r.name] = r; stackDepth++
                    list += VmInstr(VmOp.CONST, r, emptyList(), op.detail, op.addr, 0.95)
                }
                JsvmpMicroIr.MicroOp.READ_CTX, JsvmpMicroIr.MicroOp.MEMBER -> {
                    val r = newValue("s$stackDepth", "stack"); current[r.name] = r; stackDepth++
                    list += VmInstr(if (op.op == JsvmpMicroIr.MicroOp.MEMBER) VmOp.READ_MEM else VmOp.READ_CTX, r, emptyList(), op.detail, op.addr, 0.92)
                }
                JsvmpMicroIr.MicroOp.WRITE_CTX -> list += VmInstr(VmOp.WRITE_CTX, null, listOf(read("s${(stackDepth - 1).coerceAtLeast(0)}")), op.detail, op.addr, 0.92)
                JsvmpMicroIr.MicroOp.ARITH, JsvmpMicroIr.MicroOp.COMPARE -> {
                    val b = read("s${(stackDepth - 1).coerceAtLeast(0)}")
                    val a = read("s${(stackDepth - 2).coerceAtLeast(0)}")
                    val r = newValue("s${(stackDepth - 2).coerceAtLeast(0)}", "stack")
                    current[r.name] = r; stackDepth = (stackDepth - 1).coerceAtLeast(0)
                    list += VmInstr(if (op.op == JsvmpMicroIr.MicroOp.ARITH) VmOp.BINOP else VmOp.CMP, r, listOf(a, b), op.detail, op.addr, 0.95)
                }
                JsvmpMicroIr.MicroOp.STACK -> {
                    if (op.detail.contains("pop")) {
                        stackDepth--; minDepth = minOf(minDepth, stackDepth)
                        list += VmInstr(VmOp.STACK_POP, null, listOf(read("s${(stackDepth + 1).coerceAtLeast(0)}")), op.detail, op.addr, 0.90)
                    } else {
                        val r = newValue("s$stackDepth", "stack"); current[r.name] = r; stackDepth++
                        list += VmInstr(VmOp.STACK_PUSH, r, emptyList(), op.detail, op.addr, 0.90)
                    }
                }
                JsvmpMicroIr.MicroOp.BRANCH -> {
                    hasBranch = true
                    list += VmInstr(VmOp.BRANCH, null, listOf(read("s${(stackDepth - 1).coerceAtLeast(0)}")), op.detail, op.addr, 0.91)
                    val taken = ++blockId
                    val fall = ++blockId
                    blocksInstr.add(mutableListOf<VmInstr>())
                    blocksInstr.add(mutableListOf<VmInstr>())
                    connect(blockId - 2, taken)
                    connect(blockId - 2, fall)
                    // Both branch outcomes join at an explicit merge block. This is conservative when
                    // the original handler hides target arithmetic, but it gives downstream SSA a sound join.
                    val merge = ++blockId
                    blocksInstr.add(mutableListOf<VmInstr>())
                    connect(taken, merge); connect(fall, merge)
                    blockId = merge
                }
                JsvmpMicroIr.MicroOp.CALL -> {
                    val r = newValue("ret${versions.size}")
                    current[r.name] = r
                    list += VmInstr(VmOp.CALL, r, emptyList(), op.detail, op.addr, 0.88)
                }
                JsvmpMicroIr.MicroOp.RETURN -> list += VmInstr(VmOp.RETURN, null, listOf(read("s${(stackDepth - 1).coerceAtLeast(0)}")), op.detail, op.addr, 0.96)
                else -> list += VmInstr(VmOp.UNKNOWN, null, emptyList(), op.detail, op.addr, 0.58)
            }
        }

        val phiBlocks = blockPred.filter { (_, preds) -> preds.size > 1 }.keys
        val allBlocks = (0 until blocksInstr.size).map { id ->
            val preds = blockPred[id].orEmpty().distinct()
            val succs = blockSucc[id].orEmpty().distinct()
            val phis = if (id in phiBlocks) {
                current.map { (name, value) ->
                    VmInstr(VmOp.LOAD, VmValue(name, value.version + 1, value.kind), preds.map { VmValue(name, value.version, value.kind) }, "phi($name)", 0, 0.94)
                }
            } else emptyList()
            VmBlock(id, preds, succs, blocksInstr[id].toList(), phis)
        }
        val instructionList = allBlocks.flatMap { it.instrs }
        val confidence = instructionList.map { it.confidence }.average().takeIf { !it.isNaN() } ?: 0.5
        val warnings = buildList {
            if (instructionList.any { it.op == VmOp.UNKNOWN }) add("存在 UNKNOWN micro-op，需 runtime differential trace 补语义")
            if (hasBranch) add("存在分支：已生成 branch/merge VM block 与保守 phi")
        }
        return HandlerVmSsa(handler.key, unit.normalizedKey, allBlocks, unit.arity, instructionList.count { it.op == VmOp.RETURN }, stackDepth - minDepth, unit.signature, confidence, warnings)
    }

}
