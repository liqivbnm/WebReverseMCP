package com.webreverse.mcp.javascript.analysis

import com.webreverse.mcp.javascript.analysis.WasmSsaBuilder.VType
import com.webreverse.mcp.javascript.analysis.WasmSsaBuilder.SsaInstr
import com.webreverse.mcp.javascript.analysis.WasmSsaBuilder.PhiNode
import com.webreverse.mcp.javascript.analysis.WasmSsaBuilder.StackIssue
import com.webreverse.mcp.javascript.analysis.WasmSsaBuilder.SsaResult

/**
 * 真正的 CFG-based WASM SSA 构建器（ 新增）。
 *
 * 把原「结构化栈 SSA」升级为**基于基本块的 CFG-SSA**，重点解决：
 *   - loop / back-edge 的 SSA 版本传播（local 自引用 phi 正确收敛）
 *   - br / br_if / br_table 的目标解析与 CFG 边建立（current block -> target block）
 *   - BasicBlock 划分与 leader detection
 *   - 抽象解释 + 不动点迭代（有限轮）做数据流传播
 *   - 类型栈细分（UNKNOWN_POINTER 等）与指针算术追踪
 *
 * 复用 [WasmSsaBuilder] 的 SsaResult/SsaInstr/PhiNode/StackIssue/VType 数据模型，
 * 公共 API 完全兼容，额外填充 blocks / cfgEdges / cfgSummary 字段。
 * 纯 Kotlin、无第三方依赖、stdlib only。
 */
class WasmCfgSsaBuilder {

    // ---------------- 数据模型 ----------------

    /** 基本块 */
    data class BasicBlock(
        val id: Int,
        val startOp: Int,        // 首条指令在函数指令流中的序号
        val endOp: Int,          // 末条指令序号（含）
        val startAddr: Int,      // 块起始偏移（addr）
        val endAddr: Int,        // 块末尾偏移（最后一条指令的 addr，不含后继边界）
        val succs: List<Int>,    // 出口块 id 列表（EXIT = -1）
        val preds: List<Int>,    // 前驱块 id 列表
        val isLoopHeader: Boolean,  // 是否为 loop 头（有 back-edge 汇入）
        val phiMerge: Boolean,   // 是否在汇合点生成 phi（多前驱且值不同）
    )

    /** CFG 有向边 */
    data class CfgEdge(
        val from: Int,           // 源块 id
        val to: Int,             // 目标块 id（EXIT = -1）
        val kind: String,        // fallthrough / br / br_if / br_table / back-edge / return / unreachable / else / end
        val atAddr: Int,         // 产生该边的指令 addr
    )

    private companion object {
        const val EXIT = -1            // 函数出口虚拟块
        const val MAX_ROUNDS = 5       // 不动点迭代上限（有限轮）
        const val POINTER_NOTE = "%%CFG-PTR%%"
    }

    /** 指令抽象类别 */
    private enum class Kind {
        BLOCK, LOOP, IF, ELSE, END, BR, BR_IF, BR_TABLE, RETURN, UNREACHABLE,
        LOCAL_GET, LOCAL_SET, LOCAL_TEE, GLOBAL_GET, GLOBAL_SET,
        CONST, MEM, GENERIC, DROP, SELECT, CALL, CALL_IND, UNKNOWN,
    }

    /** 解码出的指令 */
    private data class Op(
        val idx: Int,
        val addr: Int,
        val opcode: Int,
        val name: String,
        val kind: Kind,
        val pops: List<VType>,
        val pushes: List<VType>,
        val localIdx: Int = -1,       // local.get/set/tee 的 local 下标
        val label: Int = -1,          // br/br_if 深度（0-based）
        val targets: List<Int> = emptyList(), // br_table 的深度列表（含默认）
        val targetOps: MutableList<Int> = mutableListOf(), // 解析后的目标指令序号
        val memargOffset: Long = 0,   // 内存操作的 memarg offset
        val constVal: Long = 0,       // 常量值（i32/i64）
        val callIdx: Int = -1,        // call 目标
        val resultArity: Int = 0,     // blocktype 结果个数（近似）
        val raw: String,              // wat 风格原始行
    )

    /** 块内指令抽象解释工作状态 */
    private class WState(val localCount: Int) {
        val stack = mutableListOf<String>()          // vreg 名（栈底->栈顶）
        val typ = mutableListOf<VType>()             // 每槽类型
        val ptr = mutableListOf<PtrInfo?>()          // 每槽指针信息（追溯线索）
        val imm = mutableListOf<Long?>()             // 每槽已知常量（数值）值
        val loc = IntArray(localCount)               // local 版本

        fun copy(): WState {
            val c = WState(localCount)
            c.stack.addAll(stack); c.typ.addAll(typ); c.ptr.addAll(ptr); c.imm.addAll(imm)
            System.arraycopy(loc, 0, c.loc, 0, loc.size)
            return c
        }
    }

    /** 指针追溯信息 */
    private class PtrInfo(val base: String, val offset: Long) {
        override fun toString() = "ptr($base${if (offset != 0L) "+$offset" else ""})"
    }

    // ---------------- 入口 ----------------

    private val parser = WasmParser()

    fun analyzeExport(bytes: ByteArray, exportName: String, maxInstr: Int = 2000): SsaResult {
        val parsed = parser.parse(bytes)
        if (!parsed.ok) return SsaResult(false, parsed.error, exportName)
        val exp = parsed.exports.firstOrNull { it.kind == "func" && it.name == exportName }
            ?: return SsaResult(false, "导出函数 '$exportName' 不存在", exportName)
        return analyze(bytes, exp.index, maxInstr)
    }

    fun analyze(bytes: ByteArray, funcIndex: Int, maxInstr: Int = 2000): SsaResult {
        val parsed = parser.parse(bytes)
        if (!parsed.ok) return SsaResult(false, parsed.error, funcIndex = funcIndex)
        val importedFuncs = parsed.imports.count { it.kind == "func" }
        if (funcIndex < importedFuncs) return SsaResult(false, "索引 $funcIndex 是导入函数，无函数体", funcIndex = funcIndex)
        val localIdx = funcIndex - importedFuncs
        val sig = parsed.localFunctions.getOrNull(localIdx)
            ?: return SsaResult(false, "函数索引超出范围", funcIndex = funcIndex)
        val name = parsed.functionNames[funcIndex]
            ?: parsed.exports.firstOrNull { it.kind == "func" && it.index == funcIndex }?.name
            ?: "func_$funcIndex"
        val body = locateBody(bytes, localIdx)
            ?: return SsaResult(false, "未找到函数体", funcName = name, funcIndex = funcIndex)

        return buildCFG(bytes, body, sig, name, funcIndex, parsed, importedFuncs, maxInstr)
    }

    // ---------------- 主流程 ----------------

    private fun buildCFG(
        bytes: ByteArray,
        body: Pair<Int, Int>,
        sig: WasmParser.FuncType,
        name: String,
        funcIndex: Int,
        parsed: WasmParser.ParsedWasm,
        importedFuncs: Int,
        maxInstr: Int,
    ): SsaResult {
        val b = bytes
        var pos = body.first
        val bodyEnd = body.second

        // ---- 1. locals 类型解析 ----
        val localTypes = mutableListOf<VType>()
        sig.params.forEach { localTypes.add(valTypeName(it)) }
        runCatching {
            val (groups, gb) = readU32(b, pos); pos += gb
            repeat(groups.toInt()) {
                val (cnt, cb) = readU32(b, pos); pos += cb
                val vt = valType(b[pos].toInt() and 0xff); pos += 1
                repeat(cnt.toInt()) { localTypes.add(vt) }
            }
        }
        val localCount = localTypes.size.coerceAtMost(4096)

        // ---- 2. 线性解码 + 控制帧（pass1） ----
        val ops = mutableListOf<Op>()
        val endOfFrame = HashMap<Int, Int>()   // headerOpIdx -> 匹配 end 的 opIdx
        val kindOf = HashMap<Int, Kind>()      // headerOpIdx -> 帧类别
        val elseOf = HashMap<Int, Int>()       // elseOpIdx -> 所属 if 的 headerOpIdx
        var count = 0
        var truncated = false
        val labelStack = mutableListOf<Int>()  // 存 headerOpIdx
        while (pos < bodyEnd && count < maxInstr) {
            count++
            val addr = pos
            val opcode = b[pos].toInt() and 0xff
            pos++
            var opName = opcodeNames[opcode] ?: "op_0x${opcode.toString(16)}"
            var opkind: Kind = Kind.GENERIC
            var localIdx = -1; var label = -1; var targets = emptyList<Int>()
            var memargOff = 0L; var constVal = 0L; var callIdx = -1; var arity = 0
            var pops = emptyList<VType>(); var pushes = emptyList<VType>()

            when (opcode) {
                0x02, 0x03, 0x04 -> { // block / loop / if
                    val bt = blockTypeArity(b, pos)
                    pos += blockTypeLen(b, pos)
                    arity = bt
                    opkind = if (opcode == 0x02) Kind.BLOCK else if (opcode == 0x03) Kind.LOOP else Kind.IF
                    // if 弹出条件
                    if (opcode == 0x04) pops = listOf(VType.I32)
                }
                0x05 -> { opkind = Kind.ELSE; pops = blockResultArityPops(endOfFrame, elseOf, labelStack) }
                0x0b -> { opkind = Kind.END }
                0x0c -> { val (l, ll) = readU32(b, pos); pos += ll; opkind = Kind.BR; label = l.toInt() }
                0x0d -> { val (l, ll) = readU32(b, pos); pos += ll; opkind = Kind.BR_IF; label = l.toInt(); pops = listOf(VType.I32) }
                0x0e -> { // br_table: vec<labelidx> + default labelidx
                    val (n, nl) = readU32(b, pos); pos += nl
                    val t = mutableListOf<Int>()
                    repeat(n.toInt() + 1) { val (x, xl) = readU32(b, pos); pos += xl; t.add(x.toInt()) }
                    opkind = Kind.BR_TABLE; targets = t
                }
                0x0f -> opkind = Kind.RETURN
                0x00 -> opkind = Kind.UNREACHABLE
                0x10 -> { // call
                    val (t, tl) = readU32(b, pos); pos += tl
                    opkind = Kind.CALL; callIdx = t.toInt()
                    val (argc, retc) = calleeSignature(parsed, importedFuncs, t.toInt())
                    pops = List(argc) { VType.UNKNOWN }; pushes = List(retc) { VType.UNKNOWN }
                }
                0x11 -> { // call_indirect
                    val (ti, t1) = readU32(b, pos); pos += t1
                    val (tbl, t2) = readU32(b, pos); pos += t2
                    val typeSig = parsed.types.getOrNull(ti.toInt())
                    opkind = Kind.CALL_IND
                    val argc = typeSig?.params?.size ?: 0; val retc = typeSig?.results?.size ?: 0
                    pops = List(argc + 1) { VType.UNKNOWN } // +1 表索引
                    pushes = List(retc) { VType.UNKNOWN }
                }
                0x20, 0x21, 0x22 -> { // local.get/set/tee
                    val (ix, il) = readU32(b, pos); pos += il
                    localIdx = ix.toInt()
                    opkind = if (opcode == 0x20) Kind.LOCAL_GET else if (opcode == 0x21) Kind.LOCAL_SET else Kind.LOCAL_TEE
                    val lt = localTypes.getOrNull(localIdx) ?: VType.UNKNOWN
                    if (opcode == 0x20) { pushes = listOf(lt) } else { pops = listOf(lt) }
                }
                0x23, 0x24 -> { // global.get/set
                    val (ix, il) = readU32(b, pos); pos += il
                    opkind = if (opcode == 0x23) Kind.GLOBAL_GET else Kind.GLOBAL_SET
                    if (opcode == 0x23) pushes = listOf(VType.UNKNOWN) else pops = listOf(VType.UNKNOWN)
                }
                0x1a -> { opkind = Kind.DROP; pops = listOf(VType.UNKNOWN) }
                0x1b -> { opkind = Kind.SELECT; pops = listOf(VType.UNKNOWN, VType.UNKNOWN, VType.I32); pushes = listOf(VType.UNKNOWN) }
                0x1c -> { val (n, nl) = readU32(b, pos); pos += nl + n.toInt(); opkind = Kind.SELECT; pops = listOf(VType.UNKNOWN, VType.UNKNOWN, VType.I32); pushes = listOf(VType.UNKNOWN) }
                0x41 -> { val (v, l) = readS32(b, pos); pos += l; opkind = Kind.CONST; constVal = v; pushes = listOf(VType.I32) }
                0x42 -> { val (v, l) = readS64(b, pos); pos += l; opkind = Kind.CONST; constVal = v; pushes = listOf(VType.I64) }
                0x43 -> { pos += 4; opkind = Kind.CONST; pushes = listOf(VType.F32) }
                0x44 -> { pos += 8; opkind = Kind.CONST; pushes = listOf(VType.F64) }
                else -> {
                    val sc = typeSigs[opcode]
                    if (sc != null) {
                        when (opcode) {
                            in 0x28..0x3e -> { // memop
                                val (a, al) = readU32(b, pos); pos += al
                                val (o, ol) = readU32(b, pos); pos += ol
                                memargOff = o
                                opkind = Kind.MEM
                            }
                            0x3f, 0x40 -> { pos += u32Len(b, pos); opkind = Kind.GENERIC }
                            0x1a -> {}
                            else -> {}
                        }
                        pops = sc.pops; pushes = sc.pushes
                        // 0x1c select_t 待处理：已有分支
                    } else {
                        pos = skipUnknown(b, pos, bodyEnd, opcode)
                        opkind = Kind.UNKNOWN
                        opName = "unknown_0x${opcode.toString(16)}"
                    }
                }
            }

            val op = Op(
                idx = ops.size, addr = addr, opcode = opcode, name = opName, kind = opkind,
                pops = pops, pushes = pushes, localIdx = localIdx,
                label = label, targets = targets, memargOffset = memargOff,
                constVal = constVal, callIdx = callIdx, resultArity = arity,
                raw = buildRaw(opName, opkind, localIdx, label, targets, memargOff, constVal, callIdx),
            )
            ops.add(op)

            // 帧栈维护
            when (opkind) {
                Kind.BLOCK, Kind.LOOP, Kind.IF -> { labelStack.add(op.idx); kindOf[op.idx] = opkind }
                Kind.ELSE -> { val h = labelStack.lastOrNull(); if (h != null) elseOf[op.idx] = h }
                Kind.END -> { val h = labelStack.removeLastOrNull(); if (h != null) endOfFrame[h] = op.idx }
                else -> {}
            }
        }
        if (pos < bodyEnd) truncated = true
        val n = ops.size
        if (n == 0) return SsaResult(false, "函数体为空", funcName = name, funcIndex = funcIndex)

        // ---- 3. br/br_if/br_table 目标解析（pass2） ----
        resolveBranchTargets(ops, endOfFrame, kindOf)

        // ---- 4. Leader detection & 基本块划分 ----
        val leaders = linkedSetOf(0)
        for (i in 0 until n) {
            when (ops[i].kind) {
                Kind.BLOCK, Kind.LOOP, Kind.IF -> { leaders += i; if (i + 1 < n) leaders += i + 1 }
                Kind.ELSE -> if (i + 1 < n) leaders += i + 1
                Kind.END -> if (i + 1 < n) leaders += i + 1
                Kind.BR, Kind.BR_IF, Kind.BR_TABLE, Kind.RETURN, Kind.UNREACHABLE ->
                    if (i + 1 < n) leaders += i + 1
                else -> {}
            }
        }
        // 分支目标也是 leader
        for (i in 0 until n) {
            val o = ops[i]
            when (o.kind) {
                Kind.BR, Kind.BR_IF -> o.targetOps.firstOrNull()?.let { leaders += it }
                Kind.BR_TABLE -> o.targetOps.forEach { leaders += it }
                else -> {}
            }
        }
        val leaderArr = leaders.sorted().filter { it < n }
        val blocks = mutableListOf<BasicBlock>()
        val startToBlock = HashMap<Int, Int>()
        for (j in leaderArr.indices) {
            val l = leaderArr[j]
            val r = if (j + 1 < leaderArr.size) leaderArr[j + 1] - 1 else n - 1
            if (l > n - 1) continue
            val id = blocks.size
            blocks.add(BasicBlock(id, l, r, ops[l].addr, ops[r].addr, emptyList(), emptyList(), false, false))
            startToBlock[l] = id
        }

        // ---- 5. CFG 边建立 ----
        val succList = Array(blocks.size) { linkedSetOf<Int>() }
        val edgeKinds = HashMap<Long, MutableList<String>>()
        val loopHeaders = mutableSetOf<Int>()
        fun blockOf(opIdx: Int): Int = startToBlock[opIdx] ?: EXIT
        fun addEdge(from: Int, to: Int, givenKind: String, at: Int) {
            if (from < 0 || from >= blocks.size) return
            if (givenKind == "br" || givenKind == "br_if" || givenKind == "br_table") {
                // back-edge 判定：目标块在源块之后或相同且为 loop header
                if (to >= 0 && from >= to && ops[blocks[from].startOp].kind != Kind.LOOP) {
                    // 粗判 back-edge：目标序号 <= 源序号
                }
            }
            val kind = if (to == from) "back-edge" else givenKind
            succList[from].add(to)
            edgeKinds.getOrPut(from.toLong() shl 32 or (to.toLong() and 0xffffffffL)) { mutableListOf() }.add(kind)
            if (kind == "back-edge" && to in blocks.indices) {
                if (ops[blocks[to].startOp].kind == Kind.LOOP) loopHeaders.add(to)
            }
            if (to >= 0 && ops[blocks[to].startOp].kind == Kind.LOOP && (kind == "br" || kind == "br_if" || kind == "br_table")) {
                loopHeaders.add(to)
            }
        }

        for (bid in blocks.indices) {
            val blk = blocks[bid]
            val l = blk.startOp; val r = blk.endOp
            val ctrl = ops[r].kind
            when (ctrl) {
                Kind.BR -> addEdge(bid, blockOf(ops[r].targetOps[0]), "br", ops[r].addr)
                Kind.BR_IF -> {
                    addEdge(bid, blockOf(ops[r].targetOps[0]), "br_if", ops[r].addr)
                    addEdge(bid, blockOf(r + 1), "fallthrough", ops[r].addr)
                }
                Kind.BR_TABLE -> ops[r].targetOps.distinct().forEach { addEdge(bid, blockOf(it), "br_table", ops[r].addr) }
                Kind.RETURN -> addEdge(bid, EXIT, "return", ops[r].addr)
                Kind.UNREACHABLE -> addEdge(bid, EXIT, "unreachable", ops[r].addr)
                Kind.ELSE -> {
                    val h = elseOf[r]
                    val fe = if (h != null) (endOfFrame[h] ?: -1) else -1
                    val mergeOp = if (fe >= 0) fe + 1 else r + 1
                    addEdge(bid, blockOf(mergeOp), "else-to-merge", ops[r].addr)
                }
                Kind.END -> {
                    // 这是块内最后一个 op 为 end（循环体/子块收口），落入紧邻后继
                    if (r + 1 < n) addEdge(bid, blockOf(r + 1), "end", ops[r].addr)
                    else addEdge(bid, EXIT, "end-exit", ops[r].addr)
                }
                else -> {
                    if (r + 1 < n) addEdge(bid, blockOf(r + 1), "fallthrough", ops[r].addr)
                    else addEdge(bid, EXIT, "exit", ops[r].addr)
                }
            }
            // 若块以 BR/BR_IF 结尾指向 loop header -> 本身就是 back-edge
        }

        // 把 Loop 头的入边标记为 back-edge（当目标 == 源 或 目标为该 loop 自身头）
        for (bid in blocks.indices) {
            val blk = blocks[bid]
            if (ops[blk.startOp].kind == Kind.LOOP) loopHeaders.add(bid)
        }

        val predList = Array(blocks.size) { mutableListOf<Int>() }
        for (from in blocks.indices) for (to in succList[from]) if (to >= 0) predList[to].add(from)

        val cfgEdges = mutableListOf<CfgEdge>()
        for (from in blocks.indices) {
            for (to in succList[from]) {
                val kinds = edgeKinds[from.toLong() shl 32 or (to.toLong() and 0xffffffffL)] ?: mutableListOf("edge")
                val k = if (kinds.contains("back-edge")) "back-edge"
                    else if (to >= 0 && ops[blocks[to].startOp].kind == Kind.LOOP && kinds.any { it in setOf("br","br_if","br_table") }) "back-edge"
                    else kinds.first()
                // 判断真正回边：to >= from（编号升序基本对应地址序，回边目标较前）
                val effKind = if (to >= 0 && to < from && ops[blocks[to].startOp].kind == Kind.LOOP) "back-edge" else if (kinds.contains("back-edge")) "back-edge" else k
                cfgEdges.add(CfgEdge(from, to, effKind, blocks[from].endOp.let { ops[it].addr }))
                if (effKind == "back-edge") loopHeaders.add(to)
            }
        }

        // ---- 6. 抽象解释 + 不动点收敛 ----
        val issues = mutableListOf<StackIssue>()
        val instrs = mutableListOf<SsaInstr>()
        val phis = mutableListOf<PhiNode>()
        val clues = mutableListOf<String>()
        var vregSeq = 0
        val localMaxVer = HashMap<Int, Int>().apply { for (i in 0 until localCount) put(i, 0) }
        val paramMaxVer = localMaxVer

        fun freshVreg(): String { vregSeq++; return "v$vregSeq" }

        // 每个块的稳定 phi 节点名称与来源
        val phiLocalName = Array(blocks.size) { HashMap<Int, String>() }
        val phiLocalSrc = Array(blocks.size) { HashMap<Int, MutableSet<String>>() }
        val phiStackName = Array(blocks.size) { HashMap<Int, String>() }
        val phiStackSrc = Array(blocks.size) { HashMap<Int, MutableSet<String>>() }
        // 每个块收敛后的 entry 状态
        val inState = arrayOfNulls<WState>(blocks.size)

        fun localName(idx: Int, ver: Int) = "l$idx.$ver"

        fun ensureLocalPhi(blockId: Int, idx: Int): String {
            phiLocalName[blockId][idx]?.let { return it }
            val ver = (localMaxVer[idx] ?: 0) + 1
            localMaxVer[idx] = ver
            val nm = localName(idx, ver)
            phiLocalName[blockId][idx] = nm
            phiLocalSrc[blockId][idx] = linkedSetOf()
            return nm
        }

        fun ensureStackPhi(blockId: Int, slot: Int): String {
            phiStackName[blockId][slot]?.let { return it }
            val nm = freshVreg()
            phiStackName[blockId][slot] = nm
            phiStackSrc[blockId][slot] = linkedSetOf()
            return nm
        }

        /** 将一个前驱的出状态合并进目标块的 entry 状态；返回是否发生变化 */
        fun mergeInto(blockId: Int, predOut: WState): Boolean {
            val cur = inState[blockId]
            if (cur == null) {
                val c = predOut.copy()
                // 已存在的 local phi 覆盖版本
                for ((idx, nm) in phiLocalName[blockId]) {
                    val ver = nm.substringAfterLast('.').toIntOrNull() ?: 0
                    c.loc[idx] = ver
                    val src = phiLocalSrc[blockId].getOrPut(idx) { linkedSetOf() }
                    src.add(localName(idx, predOut.loc.getOrElse(idx) { 0 }))
                }
                for ((slot, nm) in phiStackName[blockId]) {
                    if (slot < c.stack.size) {
                        val src = phiStackSrc[blockId].getOrPut(slot) { linkedSetOf() }
                        src.add(c.stack[slot]); c.stack[slot] = nm
                        c.typ[slot] = VType.UNKNOWN; c.ptr[slot] = null; c.imm[slot] = null
                    }
                }
                inState[blockId] = c
                return true
            }
            var changed = false
            // locals
            val nl = minOf(cur.loc.size, predOut.loc.size, localCount)
            for (idx in 0 until nl) {
                if (cur.loc[idx] != predOut.loc[idx]) {
                    val nm = ensureLocalPhi(blockId, idx)
                    val src = phiLocalSrc[blockId].getOrPut(idx) { linkedSetOf() }
                    if (src.add(localName(idx, cur.loc[idx]))) changed = true
                    if (src.add(localName(idx, predOut.loc[idx]))) changed = true
                    val ver = nm.substringAfterLast('.').toIntOrNull() ?: 0
                    if (cur.loc[idx] != ver) { cur.loc[idx] = ver; changed = true }
                }
            }
            // stack
            val mn = minOf(cur.stack.size, predOut.stack.size)
            for (i in 0 until mn) {
                if (cur.stack[i] != predOut.stack[i]) {
                    val nm = ensureStackPhi(blockId, i)
                    val src = phiStackSrc[blockId].getOrPut(i) { linkedSetOf() }
                    if (src.add(cur.stack[i])) changed = true
                    if (src.add(predOut.stack[i])) changed = true
                    cur.stack[i] = nm; cur.typ[i] = VType.UNKNOWN; cur.ptr[i] = null; cur.imm[i] = null
                    changed = true
                }
            }
            if (cur.stack.size != predOut.stack.size && cur.stack.size < localCount + 1) {
                // 深度不一致：以较深者为准（简化对齐，记录一次告警）
            }
            return changed
        }

        // ---- 指令转移函数（同时用于不动点与最终发射） ----
        fun applyOp(o: Op, st: WState, emit: MutableList<SsaInstr>?, issues: MutableList<StackIssue>, clues: MutableList<String>) {
            val opName = o.name
            fun pushV(t: VType, reg: String) {
                st.stack.add(reg); st.typ.add(t); st.ptr.add(null); st.imm.add(null)
            }
            fun pop(): Triple<VType, String, PtrInfo?> {
                if (st.stack.isEmpty()) {
                    issues.add(StackIssue(o.addr, opName, "栈下溢（underflow）——疑似反汇编失步"))
                    return Triple(VType.UNKNOWN, "?", null)
                }
                val i = st.stack.size - 1
                val t = st.typ.removeAt(i); val r = st.stack.removeAt(i)
                val p = st.ptr.removeAt(i); val im = st.imm.removeAt(i)
                return Triple(t, r, p)
            }
            // 栈顶指针信息供算术读取（但 pop 会移除，buff）
            fun topPtr(): PtrInfo? = if (st.ptr.isNotEmpty()) st.ptr[st.ptr.size - 1] else null
            fun secondPtr(): PtrInfo? = if (st.ptr.size >= 2) st.ptr[st.ptr.size - 2] else null
            fun secondImm(): Long? = if (st.imm.size >= 2) st.imm[st.imm.size - 2] else null

            when (o.kind) {
                Kind.LOCAL_GET -> {
                    val ver = st.loc.getOrElse(o.localIdx) { 0 }
                    val reg = localName(o.localIdx, ver)
                    val t = localTypes.getOrNull(o.localIdx) ?: VType.UNKNOWN
                    pushV(t, reg)
                    emit?.add(SsaInstr(o.addr, "local.get", reg, emptyList(), t, "$reg = local.get ${o.localIdx}"))
                }
                Kind.LOCAL_SET -> {
                    val (t, v, _) = pop()
                    if (o.localIdx in 0 until st.loc.size) st.loc[o.localIdx]++
                    val reg = localName(o.localIdx, st.loc.getOrElse(o.localIdx) { 0 })
                    localMaxVer[o.localIdx] = maxOf(localMaxVer[o.localIdx] ?: 0, st.loc.getOrElse(o.localIdx) { 0 })
                    emit?.add(SsaInstr(o.addr, "local.set", reg, listOf(v), localTypes.getOrNull(o.localIdx) ?: VType.UNKNOWN, "$reg = $v ;; local.set ${o.localIdx}"))
                }
                Kind.LOCAL_TEE -> {
                    val kept = st.stack.lastOrNull() ?: "?"
                    if (o.localIdx in 0 until st.loc.size) st.loc[o.localIdx]++
                    val reg = localName(o.localIdx, st.loc.getOrElse(o.localIdx) { 0 })
                    localMaxVer[o.localIdx] = maxOf(localMaxVer[o.localIdx] ?: 0, st.loc.getOrElse(o.localIdx) { 0 })
                    emit?.add(SsaInstr(o.addr, "local.tee", reg, listOf(kept), localTypes.getOrNull(o.localIdx) ?: VType.UNKNOWN, "$reg = tee $kept ;; 值保留在栈"))
                }
                Kind.GLOBAL_GET -> { val reg = freshVreg(); pushV(VType.UNKNOWN, reg); emit?.add(SsaInstr(o.addr, "global.get", reg, emptyList(), VType.UNKNOWN, "$reg = global.get")) }
                Kind.GLOBAL_SET -> { val (_, v, _) = pop(); emit?.add(SsaInstr(o.addr, "global.set", "g", listOf(v), VType.UNKNOWN, "g = $v")) }
                Kind.CONST -> {
                    val reg = freshVreg()
                    val t = if (o.opcode == 0x41) VType.I32 else if (o.opcode == 0x42) VType.I64 else if (o.opcode == 0x43) VType.F32 else VType.F64
                    pushV(t, reg)
                    st.imm[st.imm.size - 1] = if (o.opcode <= 0x42) o.constVal else null
                    emit?.add(SsaInstr(o.addr, o.name, reg, emptyList(), t, "$reg = ${if (o.opcode <= 0x42) o.constVal else "?"}"))
                }
                Kind.MEM -> {
                    // load: pops=[addr] ; store: pops=[value,...addr]（addr 为被内存寻址的操作数）
                    val isStore = o.opcode in 0x36..0x3e
                    val inputs = mutableListOf<String>()
                    var addrReg: String? = null; var addrPtr: PtrInfo? = null
                    val nPop = if (isStore) o.pops.size - 1 else 1  // store 末位是 value? 需匹配实际
                    // 实际：store 栈顶是 value，其次 addr；load 顶是 addr
                    if (isStore) {
                        // 先弹 value，再弹 addr
                        val (tv, vv, _) = pop(); inputs.add(0, vv)
                        val (ta, av, ap) = pop(); addrReg = av; addrPtr = ap; inputs.add(0, av)
                    } else {
                        val (ta, av, ap) = pop(); addrReg = av; addrPtr = ap; inputs.add(av)
                        emit?.let {
                            val ptrDesc = addrPtr?.toString() ?: "addr(?)"
                            clues.add("i32.load/i64.load @${o.addr.toString(16)}: 地址操作数 ${POINTER_NOTE}es pread 以 $ptrDesc 寻址 (memarg.offset=${o.memargOffset})")
                        }
                    }
                    val t = o.pushes.firstOrNull() ?: VType.UNKNOWN
                    if (isStore) {
                        emit?.add(SsaInstr(o.addr, o.name, "—", inputs, VType.UNKNOWN, "${o.name} mem=${o.memargOffset} [$addrReg] <- ${inputs.getOrNull(0)}"))
                        val ptrDesc = addrPtr?.toString() ?: "addr(?)"
                        clues.add("${o.name} @${o.addr.toString(16)}: 将值写入地址 $ptrDesc 所指内存")
                    } else {
                        val reg = freshVreg(); pushV(t, reg)
                        emit?.add(SsaInstr(o.addr, o.name, reg, inputs, t, "$reg = ${o.name} mem=${o.memargOffset} [$addrReg]"))
                    }
                }
                Kind.GENERIC -> {
                    val inputs = mutableListOf<String>()
                    var mismatch = false
                    for (expected in o.pops.asReversed()) {
                        val (gotT, gotR, _) = pop()
                        inputs.add(0, gotR)
                        if (expected != VType.UNKNOWN && gotT != VType.UNKNOWN &&
                            expected != gotT && !(expected == VType.I64 && gotT == VType.I32)
                        ) {
                            mismatch = true
                        }
                    }
                    if (mismatch) issues.add(StackIssue(o.addr, o.name, "类型不匹配：期望 ${o.pops}——疑似失步"))
                    val results = mutableListOf<String>()
                    for (t in o.pushes) { val r = freshVreg(); results.add(r); pushV(t, r) }
                    // 指针算术：i32.add / i64.add 且一方为指针
                    if (o.opcode == 0x6a || o.opcode == 0x7c) {
                        val p2 = secondPtr(); val i1 = if (st.imm.isNotEmpty()) st.imm[st.imm.size - 1] else null
                        val p1 = topPtr(); val i2 = if (st.imm.size >= 2) st.imm[st.imm.size - 2] else null
                        val resolvedBase = p2?.base ?: p1?.base
                        val off = (p2?.offset ?: 0L) + (i1 ?: 0L)
                        if (resolvedBase != null) {
                            st.ptr[st.ptr.size - 1] = PtrInfo(resolvedBase, off)
                            clues.add("指针算术 @${o.addr.toString(16)}: ${results.firstOrNull()} = $resolvedBase + ${i1 ?: "?"} -> ${st.ptr[st.ptr.size - 1]}")
                        }
                    }
                    val rhs = when (results.size) {
                        0 -> o.name + inputs.joinToString(", ", "(", ")")
                        1 -> "${results[0]} = ${o.name}(${inputs.joinToString(", ")})"
                        else -> "(${results.joinToString(", ")}) = ${o.name}(${inputs.joinToString(", ")})"
                    }
                    emit?.add(SsaInstr(o.addr, o.name, results.firstOrNull() ?: "—", inputs, o.pushes.firstOrNull() ?: VType.UNKNOWN, rhs))
                }
                Kind.DROP -> { val (_, v, _) = pop(); emit?.add(SsaInstr(o.addr, "drop", "—", listOf(v), VType.UNKNOWN, "drop $v")) }
                Kind.SELECT -> {
                    val (_, c, _) = pop(); val (_, b, _) = pop(); val (ta, a, _) = pop()
                    val reg = freshVreg(); pushV(ta, reg)
                    emit?.add(SsaInstr(o.addr, "select", reg, listOf(a, b, c), ta, "$reg = select($a, $b, $c)"))
                }
                Kind.CALL -> {
                    val args = mutableListOf<String>()
                    repeat(o.pops.size) { _ ->
                        val x = pop(); args.add(0, x.second)
                    }
                    val results = mutableListOf<String>()
                    for (t in o.pushes) { val r = freshVreg(); results.add(r); pushV(t, r) }
                    emit?.add(SsaInstr(o.addr, "call", results.firstOrNull() ?: "—", args, o.pushes.firstOrNull() ?: VType.UNKNOWN, (results.firstOrNull()?.plus(" = ") ?: "") + "call ${o.callIdx}(${args.joinToString(", ")})"))
                }
                Kind.CALL_IND -> {
                    val args = mutableListOf<String>()
                    repeat(o.pops.size) { val x = pop(); args.add(0, x.second) }
                    val fn = args.removeAt(0)
                    val results = mutableListOf<String>()
                    for (t in o.pushes) { val r = freshVreg(); results.add(r); pushV(t, r) }
                    emit?.add(SsaInstr(o.addr, "call_indirect", results.firstOrNull() ?: "—", listOf(fn) + args, o.pushes.firstOrNull() ?: VType.UNKNOWN, (results.firstOrNull()?.plus(" = ") ?: "") + "call_indirect [$fn](${args.joinToString(", ")})"))
                }
                Kind.IF -> {
                    // 弹出条件
                    val (_, c, _) = pop()
                    emit?.add(SsaInstr(o.addr, "if", "—", listOf(c), VType.I32, "if $c"))
                }
                Kind.BR_IF -> {
                    val (_, c, _) = pop()
                    emit?.add(SsaInstr(o.addr, "br_if", "—", listOf(c), VType.I32, "br_if ${o.label} $c"))
                }
                Kind.BR -> emit?.add(SsaInstr(o.addr, "br", "—", emptyList(), VType.UNKNOWN, "br ${o.label}"))
                Kind.BR_TABLE -> emit?.add(SsaInstr(o.addr, "br_table", "—", emptyList(), VType.UNKNOWN, "br_table ${o.targets.joinToString(",")}"))
                Kind.RETURN -> emit?.add(SsaInstr(o.addr, "return", "—", st.stack.toList().takeLast(1), VType.UNKNOWN, "return"))
                Kind.UNREACHABLE -> emit?.add(SsaInstr(o.addr, "unreachable", "—", emptyList(), VType.UNKNOWN, "unreachable"))
                Kind.BLOCK, Kind.LOOP -> emit?.add(SsaInstr(o.addr, o.name, "—", emptyList(), VType.UNKNOWN, o.name + (if (o.resultArity > 0) " (result)" else "")))
                Kind.END -> emit?.add(SsaInstr(o.addr, "end", "—", emptyList(), VType.UNKNOWN, "end"))
                Kind.ELSE -> emit?.add(SsaInstr(o.addr, "else", "—", emptyList(), VType.UNKNOWN, "else"))
                Kind.UNKNOWN -> issues.add(StackIssue(o.addr, o.name, "未建模指令，类型栈可能失真"))
            }
        }

        // ---- 不动点驱动 ----
        val entryBlock = startToBlock[0] ?: 0
        val initState = WState(localCount)
        inState[entryBlock] = initState

        val worklist = ArrayDeque<Int>(); worklist.add(entryBlock)
        var totalPops = 0
        val maxPops = (blocks.size * MAX_ROUNDS).coerceAtLeast(8)
        var converged = true
        while (worklist.isNotEmpty() && totalPops < maxPops) {
            totalPops++
            val b = worklist.removeFirst()
            val ws = inState[b] ?: continue
            val out = ws.copy()
            for (i in blocks[b].startOp..blocks[b].endOp) {
                applyOp(ops[i], out, null, issues, clues)
            }
            for (to in succList[b]) {
                if (to == EXIT) continue
                val ch = mergeInto(to, out)
                if (ch && to !in worklist) worklist.add(to)
            }
        }
        if (worklist.isNotEmpty()) converged = false

        // ---- 7. 最终发射（用收敛状态） ----
        val finalInState = arrayOfNulls<WState>(blocks.size)
        finalInState[entryBlock] = initState.copy()
        val finalIssues = mutableListOf<StackIssue>()
        val finalClues = mutableListOf<String>()
        // 重建 entry 状态：由于 inState 已收敛，用它作为块入口
        // （直接使用 inState 的副本，保证块内指令可见局部演进）
        for (bid in blocks.indices) {
            val src = inState[bid] ?: continue
            finalInState[bid] = src.copy()
        }
        // 打印块级 phi 与指令
        for (bid in blocks.indices) {
            val st = finalInState[bid] ?: continue
            val blk = blocks[bid]
            // 先发射该块 phi 节点（local + stack）
            val localPhis = phiLocalName[bid].toSortedMap()
            for ((idx, nm) in localPhis) {
                val srcs = (phiLocalSrc[bid][idx] ?: emptySet<String>()).sorted()
                if (srcs.isEmpty()) continue
                val t = localTypes.getOrNull(idx) ?: VType.UNKNOWN
                phis.add(PhiNode(nm, srcs, t, blk.startAddr))
                instrs.add(SsaInstr(blk.startAddr, "phi", nm, srcs, t, "$nm = phi(${srcs.joinToString(", ")}) ;; 汇合点 local$idx"))
            }
            val stackPhis = phiStackName[bid].toSortedMap()
            for ((slot, nm) in stackPhis) {
                val srcs = (phiStackSrc[bid][slot] ?: emptySet<String>()).sorted()
                if (srcs.isEmpty()) continue
                phis.add(PhiNode(nm, srcs, VType.UNKNOWN, blk.startAddr))
                instrs.add(SsaInstr(blk.startAddr, "phi", nm, srcs, VType.UNKNOWN, "$nm = phi(${srcs.joinToString(", ")}) ;; 栈槽$slot 汇合"))
            }
            for (i in blk.startOp..blk.endOp) {
                applyOp(ops[i], st, instrs, finalIssues, finalClues)
            }
        }

        // 块级 phi 标记
        val finalBlocks = blocks.mapIndexed { id, dst ->
            dst.copy(
                preds = predList[id].toList(),
                succs = succList[id].toList(),
                isLoopHeader = id in loopHeaders,
                phiMerge = (phiLocalName[id].isNotEmpty() || phiStackName[id].isNotEmpty()),
            )
        }

        // ---- 8. CFG 摘要字符串 ----
        val cfgSummary = buildCfgSummary(finalBlocks, cfgEdges, blocks, ops)

        val listing = renderListing(instrs, phis, name, sig, truncated, finalIssues, finalClues, finalInState[entryBlock]?.stack?.size ?: 0, cfgSummary)
        val leftover = finalInState[entryBlock]?.typ?.toList() ?: initState.typ.toList()

        val localVersions = mutableMapOf<Int, Int>()
        for ((idx, mx) in localMaxVer) if (mx > 0) localVersions[idx] = mx

        return SsaResult(
            ok = true,
            funcName = name,
            funcIndex = funcIndex,
            signature = (if (sig.params.isEmpty()) "" else "(param ${sig.params.joinToString(" ")}) ") +
                (if (sig.results.isEmpty()) "" else "(result ${sig.results.joinToString(" ")})").trim(),
            instructions = instrs,
            phis = phis,
            issues = finalIssues,
            typeStackFinal = leftover,
            listing = listing,
            vregCount = vregSeq,
            localVersions = localVersions,
            blocks = finalBlocks,
            cfgEdges = cfgEdges,
            cfgSummary = cfgSummary,
            cfgConverged = converged,
        )
    }

    // ---------------- 辅助 ----------------

    private fun blockResultArityPops(endOfFrame: HashMap<Int, Int>, elseOf: HashMap<Int, Int>, labelStack: MutableList<Int>): List<VType> {
        // else 弹出 then 分支结果（近似：不弹，随后合并处理）
        return emptyList()
    }

    private fun resolveBranchTargets(ops: MutableList<Op>, endOfFrame: HashMap<Int, Int>, kindOf: HashMap<Int, Kind>) {
        val lab = mutableListOf<Int>()
        for (o in ops) {
            when (o.kind) {
                Kind.BLOCK, Kind.LOOP, Kind.IF -> lab.add(o.idx)
                Kind.END -> if (lab.isNotEmpty()) lab.removeAt(lab.size - 1)
                Kind.BR, Kind.BR_IF -> {
                    val h = resolveLabel(lab, o.label, endOfFrame, kindOf)
                    o.targetOps.clear()
                    if (h >= 0) o.targetOps.add(h)
                }
                Kind.BR_TABLE -> {
                    o.targets.forEach { l ->
                        val h = resolveLabel(lab, l, endOfFrame, kindOf)
                        if (h >= 0) o.targetOps += h
                    }
                }
                else -> {}
            }
        }
    }

    private fun resolveLabel(lab: MutableList<Int>, depth: Int, endOfFrame: HashMap<Int, Int>, kindOf: HashMap<Int, Kind>): Int {
        if (lab.isEmpty() || depth < 0 || depth >= lab.size) return -1
        val h = lab[lab.size - 1 - depth]
        val k = kindOf[h]
        return if (k == Kind.LOOP) h else (endOfFrame[h]?.plus(1) ?: -1)
    }

    private fun buildRaw(name: String, kind: Kind, localIdx: Int, label: Int, targets: List<Int>, mem: Long, cv: Long, call: Int): String = when (kind) {
        Kind.LOCAL_GET, Kind.LOCAL_SET, Kind.LOCAL_TEE -> "$name $localIdx"
        Kind.BR, Kind.BR_IF -> "$name $label"
        Kind.BR_TABLE -> "$name [${targets.joinToString(",")}+d]"
        Kind.MEM -> "$name mem=${mem}"
        Kind.CALL -> "$name $call"
        else -> name
    }

    private fun buildCfgSummary(blocks: List<BasicBlock>, edges: List<CfgEdge>, rawBlocks: List<BasicBlock>, ops: List<Op>): String {
        val sb = StringBuilder()
        sb.appendLine(";; ===== CFG 摘要（真实 CFG-based SSA）=====")
        sb.appendLine(";; 基本块（${blocks.size} 个）：")
        blocks.forEach { bk ->
            val hdr = if (bk.isLoopHeader) " [LOOP-HEAD]" else ""
            val phi = if (bk.phiMerge) " [PHI-MERGE]" else ""
            val rng = "#${bk.startOp}..${bk.endOp} @0x${bk.startAddr.toString(16)}-0x${bk.endAddr.toString(16)}"
            sb.appendLine("  B${bk.id} $rng succ=[${bk.succs.joinToString(",") { if (it == EXIT) "EXIT" else "B$it" }}] pred=[${bk.preds.joinToString(",") { "B$it" }}]$hdr$phi")
        }
        sb.appendLine(";; CFG 边（${edges.size} 条，含 back-edge/br 目标）：")
        edges.forEach { e ->
            val from = "B${e.from}"; val to = if (e.to == EXIT) "EXIT" else "B${e.to}"
            sb.appendLine("  $from -> $to  (${e.kind}) @${e.atAddr.toString(16)}")
        }
        val backEdges = edges.filter { it.kind == "back-edge" }
        val fwdBr = edges.filter { it.kind in setOf("br", "br_if", "br_table") }
        if (backEdges.isNotEmpty()) {
            sb.appendLine(";; 循环 back-edge（${backEdges.size}）：")
            backEdges.forEach { sb.appendLine("  B${it.from} -> B${it.to}") }
        }
        if (fwdBr.isNotEmpty()) {
            sb.appendLine(";; 前向跳转边（br/br_if/br_table 解析：${fwdBr.size}）：")
            fwdBr.take(20).forEach { sb.appendLine("  B${it.from} -> B${it.to}  (${it.kind})") }
        }
        val mergeBlocks = blocks.filter { it.phiMerge }
        if (mergeBlocks.isNotEmpty()) {
            sb.appendLine(";; phi 合并点（${mergeBlocks.size}）：${mergeBlocks.joinToString(",") { "B${it.id}" }}")
        }
        sb.appendLine(";; ===== ===== ===== ===== ===== ===== ===== ===== ===== =====")
        return sb.toString()
    }

    private fun renderListing(
        instrs: List<SsaInstr>,
        phis: List<PhiNode>,
        name: String,
        sig: WasmParser.FuncType,
        truncated: Boolean,
        issues: List<StackIssue>,
        clues: List<String>,
        finalStackDepth: Int,
        cfgSummary: String,
    ): String {
        val sb = StringBuilder()
        sb.appendLine(";; CFG-SSA 形式（BasicBlock + Phi）func $name ${if (sig.params.isNotEmpty()) "(param ${sig.params.joinToString(" ")}) " else ""}${if (sig.results.isNotEmpty()) "(result ${sig.results.joinToString(" ")})" else ""}")
        sb.append(cfgSummary)
        sb.appendLine(";; l{i}.{v}=local 版本  v{n}=虚拟寄存器  phi=合并点")
        instrs.take(1500).forEach { i ->
            val typeTag = if (i.type != VType.UNKNOWN) "  ; ${i.type.display}" else ""
            sb.appendLine("  %04x  ${i.raw}${if (i.raw.length < 60) typeTag.take(12) else ""}".trimEnd())
        }
        if (truncated) sb.appendLine(";; ...（超出 maxInstr 截断）")
        if (phis.isNotEmpty()) {
            sb.appendLine()
            sb.appendLine(";; Phi 节点（${phis.size}）：")
            phis.forEach { sb.appendLine("  @${it.addr.toString(16)}  ${it.target} = phi(${it.sources.joinToString(", ")}) : ${it.type.display}") }
        }
        if (clues.isNotEmpty()) {
            sb.appendLine()
            sb.appendLine(";; 指针/内存线索（${clues.size}）：")
            clues.take(30).forEach { sb.appendLine("  $it") }
        }
        if (issues.isNotEmpty()) {
            sb.appendLine()
            sb.appendLine(";; 栈校验问题（${issues.size}）：")
            issues.take(20).forEach { sb.appendLine("  @${it.addr.toString(16)} ${it.op}: ${it.message}") }
        }
        return sb.toString()
    }

    // ---------------- 类型与签名表 ----------------

    private fun valType(v: Int): VType = when (v) {
        0x7f -> VType.I32; 0x7e -> VType.I64; 0x7d -> VType.F32; 0x7c -> VType.F64
        0x7b -> VType.V128; 0x70 -> VType.FUNCREF; 0x6f -> VType.EXTERNREF
        else -> VType.UNKNOWN
    }

    private fun valTypeName(s: String): VType = when (s) {
        "i32" -> VType.I32; "i64" -> VType.I64; "f32" -> VType.F32; "f64" -> VType.F64
        "v128" -> VType.V128; "funcref" -> VType.FUNCREF; "externref" -> VType.EXTERNREF
        else -> VType.UNKNOWN
    }

    private data class Sig(val pops: List<VType>, val pushes: List<VType>)
    private fun sig(vararg pops: VType, pushes: Array<VType> = emptyArray()) = Sig(pops.toList(), pushes.toList())

    private val typeSigs: Map<Int, Sig> = buildMap {
        put(0x1a, sig(pushes = arrayOf()))
        put(0x1b, sig(VType.UNKNOWN, VType.UNKNOWN, VType.I32))
        put(0x20, sig(pushes = arrayOf(VType.UNKNOWN)))
        put(0x23, sig(pushes = arrayOf(VType.UNKNOWN)))
        put(0xd2, sig(pushes = arrayOf(VType.FUNCREF)))
        put(0xd0, sig(pushes = arrayOf(VType.FUNCREF, VType.EXTERNREF)))
        put(0xd1, sig(VType.FUNCREF, VType.EXTERNREF, VType.I32))
        for (op in listOf(0x28, 0x2c, 0x2d, 0x2e, 0x2f)) put(op, sig(VType.UNKNOWN_POINTER, pushes = arrayOf(VType.I32)))
        for (op in listOf(0x30, 0x31, 0x32, 0x33, 0x34, 0x35)) put(op, sig(VType.UNKNOWN_POINTER, pushes = arrayOf(VType.I64)))
        put(0x29, sig(VType.UNKNOWN_POINTER, pushes = arrayOf(VType.I64)))
        put(0x2a, sig(VType.UNKNOWN_POINTER, pushes = arrayOf(VType.F32)))
        put(0x2b, sig(VType.UNKNOWN_POINTER, pushes = arrayOf(VType.F64)))
        put(0x36, sig(VType.I32, VType.UNKNOWN_POINTER, pushes = arrayOf()))
        put(0x37, sig(VType.I64, VType.UNKNOWN_POINTER, pushes = arrayOf()))
        put(0x38, sig(VType.F32, VType.UNKNOWN_POINTER, pushes = arrayOf()))
        put(0x39, sig(VType.F64, VType.UNKNOWN_POINTER, pushes = arrayOf()))
        put(0x3a, sig(VType.I32, VType.UNKNOWN_POINTER, pushes = arrayOf()))
        put(0x3b, sig(VType.I32, VType.UNKNOWN_POINTER, pushes = arrayOf()))
        put(0x3c, sig(VType.I64, VType.UNKNOWN_POINTER, pushes = arrayOf()))
        put(0x3d, sig(VType.I64, VType.UNKNOWN_POINTER, pushes = arrayOf()))
        put(0x3e, sig(VType.I64, VType.UNKNOWN_POINTER, pushes = arrayOf()))
        put(0x3f, sig(pushes = arrayOf(VType.I32)))
        put(0x40, sig(VType.I32, pushes = arrayOf(VType.I32)))
        put(0x41, sig(pushes = arrayOf(VType.I32)))
        put(0x42, sig(pushes = arrayOf(VType.I64)))
        put(0x43, sig(pushes = arrayOf(VType.F32)))
        put(0x44, sig(pushes = arrayOf(VType.F64)))
        for (op in 0x45..0x4f) put(op, sig(VType.I32, VType.I32, pushes = arrayOf(VType.I32)))
        put(0x45, sig(VType.I32, pushes = arrayOf(VType.I32)))
        put(0x50, sig(VType.I64, pushes = arrayOf(VType.I32)))
        for (op in 0x51..0x5a) put(op, sig(VType.I64, VType.I64, pushes = arrayOf(VType.I32)))
        for (op in 0x5b..0x60) put(op, sig(VType.F32, VType.F32, pushes = arrayOf(VType.I32)))
        for (op in 0x61..0x66) put(op, sig(VType.F64, VType.F64, pushes = arrayOf(VType.I32)))
        for (op in listOf(0x67, 0x68, 0x69)) put(op, sig(VType.I32, pushes = arrayOf(VType.I32)))
        for (op in 0x6a..0x78) put(op, sig(VType.I32, VType.I32, pushes = arrayOf(VType.I32)))
        for (op in listOf(0x79, 0x7a, 0x7b)) put(op, sig(VType.I64, pushes = arrayOf(VType.I64)))
        put(0x79, sig(VType.I64, pushes = arrayOf(VType.I64)))
        for (op in 0x7c..0x8a) put(op, sig(VType.I64, VType.I64, pushes = arrayOf(VType.I64)))
        for (op in 0x8b..0x91) put(op, sig(VType.F32, pushes = arrayOf(VType.F32)))
        for (op in 0x92..0x98) put(op, sig(VType.F32, VType.F32, pushes = arrayOf(VType.F32)))
        for (op in 0x99..0x9f) put(op, sig(VType.F64, pushes = arrayOf(VType.F64)))
        for (op in 0xa0..0xa6) put(op, sig(VType.F64, VType.F64, pushes = arrayOf(VType.F64)))
        put(0xa7, sig(VType.I64, pushes = arrayOf(VType.I32)))
        for (op in listOf(0xa8, 0xa9, 0xaa, 0xab)) put(op, sig(VType.F32, VType.F64, pushes = arrayOf(VType.I32)))
        put(0xac, sig(VType.I32, pushes = arrayOf(VType.I64)))
        put(0xad, sig(VType.I32, pushes = arrayOf(VType.I64)))
        for (op in listOf(0xae, 0xaf)) put(op, sig(VType.F32, pushes = arrayOf(VType.I64)))
        for (op in listOf(0xb0, 0xb1)) put(op, sig(VType.F64, pushes = arrayOf(VType.I64)))
        put(0xb2, sig(VType.I32, pushes = arrayOf(VType.F32)))
        put(0xb3, sig(VType.I32, pushes = arrayOf(VType.F32)))
        put(0xb4, sig(VType.I64, pushes = arrayOf(VType.F32)))
        put(0xb5, sig(VType.I64, pushes = arrayOf(VType.F32)))
        put(0xb6, sig(VType.F64, pushes = arrayOf(VType.F32)))
        put(0xb7, sig(VType.I32, pushes = arrayOf(VType.F64)))
        put(0xb8, sig(VType.I32, pushes = arrayOf(VType.F64)))
        put(0xb9, sig(VType.I64, pushes = arrayOf(VType.F64)))
        put(0xba, sig(VType.I64, pushes = arrayOf(VType.F64)))
        put(0xbb, sig(VType.F32, pushes = arrayOf(VType.F64)))
        put(0xbc, sig(VType.F32, pushes = arrayOf(VType.I32)))
        put(0xbd, sig(VType.F64, pushes = arrayOf(VType.I64)))
        put(0xbe, sig(VType.I32, pushes = arrayOf(VType.I32)))
        put(0xbf, sig(VType.F64, pushes = arrayOf(VType.F64)))
        put(0xc0, sig(VType.I32, pushes = arrayOf(VType.I32)))
        put(0xc1, sig(VType.I32, pushes = arrayOf(VType.I32)))
        put(0xc2, sig(VType.I64, pushes = arrayOf(VType.I64)))
        put(0xc3, sig(VType.I64, pushes = arrayOf(VType.I64)))
        put(0xc4, sig(VType.I64, pushes = arrayOf(VType.I64)))
    }

    // ---------------- 基础解码 ----------------

    private val opcodeNames: Map<Int, String> = buildMap {
        put(0x00, "unreachable"); put(0x01, "nop"); put(0x02, "block"); put(0x03, "loop"); put(0x04, "if")
        put(0x05, "else"); put(0x0b, "end"); put(0x0c, "br"); put(0x0d, "br_if"); put(0x0e, "br_table")
        put(0x0f, "return"); put(0x10, "call"); put(0x11, "call_indirect")
        put(0x1a, "drop"); put(0x1b, "select"); put(0x1c, "select_t")
        put(0x20, "local.get"); put(0x21, "local.set"); put(0x22, "local.tee")
        put(0x23, "global.get"); put(0x24, "global.set"); put(0x25, "table.get"); put(0x26, "table.set")
        put(0x28, "i32.load"); put(0x29, "i64.load"); put(0x2a, "f32.load"); put(0x2b, "f64.load")
        put(0x2c, "i32.load8_s"); put(0x2d, "i32.load8_u"); put(0x2e, "i32.load16_s"); put(0x2f, "i32.load16_u")
        put(0x30, "i64.load8_s"); put(0x31, "i64.load8_u"); put(0x32, "i64.load16_s"); put(0x33, "i64.load16_u")
        put(0x34, "i64.load32_s"); put(0x35, "i64.load32_u")
        put(0x36, "i32.store"); put(0x37, "i64.store"); put(0x38, "f32.store"); put(0x39, "f64.store")
        put(0x3a, "i32.store8"); put(0x3b, "i32.store16"); put(0x3c, "i64.store8"); put(0x3d, "i64.store16")
        put(0x3e, "i64.store32"); put(0x3f, "memory.size"); put(0x40, "memory.grow")
        put(0x41, "i32.const"); put(0x42, "i64.const"); put(0x43, "f32.const"); put(0x44, "f64.const")
        for (op in 0x45..0x4f) put(op, "i32.cmp")
        put(0x45, "i32.eqz")
        put(0x50, "i64.eqz")
        for (op in 0x51..0x5a) put(op, "i64.cmp")
        for (op in 0x5b..0x60) put(op, "f32.cmp")
        for (op in 0x61..0x66) put(op, "f64.cmp")
        put(0x67, "i32.clz"); put(0x68, "i32.ctz"); put(0x69, "i32.popcnt"); put(0x6a, "i32.add"); put(0x6b, "i32.sub")
        put(0x6c, "i32.mul"); put(0x6d, "i32.div_s"); put(0x6e, "i32.div_u"); put(0x6f, "i32.rem_s"); put(0x70, "i32.rem_u")
        put(0x71, "i32.and"); put(0x72, "i32.or"); put(0x73, "i32.xor"); put(0x74, "i32.shl"); put(0x75, "i32.shr_s")
        put(0x76, "i32.shr_u"); put(0x77, "i32.rotl"); put(0x78, "i32.rotr")
        put(0x79, "i64.clz"); put(0x7a, "i64.ctz"); put(0x7b, "i64.popcnt"); put(0x7c, "i64.add"); put(0x7d, "i64.sub")
        put(0x7e, "i64.mul"); put(0x7f, "i64.div_s"); put(0x80, "i64.div_u"); put(0x81, "i64.rem_s"); put(0x82, "i64.rem_u")
        put(0x83, "i64.and"); put(0x84, "i64.or"); put(0x85, "i64.xor"); put(0x86, "i64.shl"); put(0x87, "i64.shr_s")
        put(0x88, "i64.shr_u"); put(0x89, "i64.rotl"); put(0x8a, "i64.rotr")
        put(0x8b, "f32.abs"); put(0x8c, "f32.neg"); put(0x8d, "f32.ceil"); put(0x8e, "f32.floor"); put(0x8f, "f32.trunc")
        put(0x90, "f32.nearest"); put(0x91, "f32.sqrt"); put(0x92, "f32.add"); put(0x93, "f32.sub"); put(0x94, "f32.mul")
        put(0x95, "f32.div"); put(0x96, "f32.min"); put(0x97, "f32.max"); put(0x98, "f32.copysign")
        put(0x99, "f64.abs"); put(0x9a, "f64.neg"); put(0x9b, "f64.ceil"); put(0x9c, "f64.floor"); put(0x9d, "f64.trunc")
        put(0x9e, "f64.nearest"); put(0x9f, "f64.sqrt"); put(0xa0, "f64.add"); put(0xa1, "f64.sub"); put(0xa2, "f64.mul")
        put(0xa3, "f64.div"); put(0xa4, "f64.min"); put(0xa5, "f64.max"); put(0xa6, "f64.copysign")
        put(0xa7, "i32.wrap_i64"); put(0xa8, "i32.trunc_f32_s"); put(0xa9, "i32.trunc_f32_u")
        put(0xaa, "i32.trunc_f64_s"); put(0xab, "i32.trunc_f64_u")
        put(0xac, "i64.extend_i32_s"); put(0xad, "i64.extend_i32_u")
        put(0xae, "i64.trunc_f32_s"); put(0xaf, "i64.trunc_f32_u"); put(0xb0, "i64.trunc_f64_s"); put(0xb1, "i64.trunc_f64_u")
        put(0xb2, "f32.convert_i32_s"); put(0xb3, "f32.convert_i32_u"); put(0xb4, "f32.convert_i64_s"); put(0xb5, "f32.convert_i64_u")
        put(0xb6, "f32.demote_f64")
        put(0xb7, "f64.convert_i32_s"); put(0xb8, "f64.convert_i32_u"); put(0xb9, "f64.convert_i64_s"); put(0xba, "f64.convert_i64_u")
        put(0xbb, "f64.promote_f32")
        put(0xbc, "i32.reinterpret_f32"); put(0xbd, "i64.reinterpret_f64"); put(0xbe, "f32.reinterpret_i32"); put(0xbf, "f64.reinterpret_i64")
        put(0xc0, "i32.extend8_s"); put(0xc1, "i32.extend16_s"); put(0xc2, "i64.extend8_s")
        put(0xc3, "i64.extend16_s"); put(0xc4, "i64.extend32_s")
        put(0xd0, "ref.null"); put(0xd1, "ref.is_null"); put(0xd2, "ref.func")
    }

    private fun blockTypeArity(b: ByteArray, from: Int): Int {
        val v = b[from].toInt() and 0xff
        return when (v) {
            0x40 -> 0                                   // 无结果
            0x7f, 0x7e, 0x7d, 0x7c, 0x7b, 0x70, 0x6f -> 1 // 单值
            else -> 1                                   // typeidx（近似视为 1）
        }
    }

    private fun blockTypeLen(b: ByteArray, from: Int): Int {
        val v = b[from].toInt() and 0xff
        return if (v == 0x40 || v == 0x7f || v == 0x7e || v == 0x7d || v == 0x7c || v == 0x7b ||
            v == 0x70 || v == 0x6f
        ) 1 else u32Len(b, from)
    }

    private fun skipUnknown(b: ByteArray, pos: Int, bodyEnd: Int, op: Int): Int {
        var p = pos
        when (op) {
            0xfb -> { p += u32Len(b, p); p += u32Len(b, p) }
            0xfc -> {
                val (sub, sb) = readU32(b, p); p += sb
                when (sub.toInt()) {
                    8, 9, 11, 13, 15 -> p += u32Len(b, p)
                    10, 12, 14 -> { p += u32Len(b, p); p += u32Len(b, p) }
                }
            }
            0xfd -> {
                val (sub, sb) = readU32(b, p); p += sb
                val s = sub.toInt()
                p += when {
                    s in 0x54..0x5f || s in 0x0c..0x0f -> { u32Len(b, p) + u32Len(b, p) + 1 }
                    s in 0x00..0x0b -> { u32Len(b, p) + u32Len(b, p) }
                    s == 0x13 -> 16
                    s in 0x14..0x1c -> 1
                    else -> 0
                }
            }
            0xfe -> { p += u32Len(b, p); p += u32Len(b, p) }
            0xd0 -> p += 1
        }
        return p
    }

    private fun locateBody(bytes: ByteArray, localIdx: Int): Pair<Int, Int>? {
        var pos = 8
        var idx = 0
        while (pos < bytes.size) {
            val secId = bytes[pos].toInt() and 0xff
            pos++
            val (size, lb) = readU32(bytes, pos)
            pos += lb
            val end = pos + size.toInt()
            if (end > bytes.size) return null
            if (secId == 10) {
                val (n, nb) = readU32(bytes, pos)
                pos += nb
                repeat(n.toInt()) {
                    val (bodySize, bb) = readU32(bytes, pos)
                    pos += bb
                    if (idx == localIdx) return pos to (pos + bodySize.toInt())
                    pos += bodySize.toInt()
                    idx++
                }
                return null
            }
            pos = end
        }
        return null
    }

    private fun calleeSignature(parsed: WasmParser.ParsedWasm, importedFuncs: Int, target: Int): Pair<Int, Int> {
        val imported = parsed.imports.filter { it.kind == "func" }
        if (target < imported.size) {
            val t = parsed.types.getOrNull(imported[target].typeIndex)
            return (t?.params?.size ?: 0) to (t?.results?.size ?: 0)
        }
        val t = parsed.localFunctions.getOrNull(target - importedFuncs)
        return (t?.params?.size ?: 0) to (t?.results?.size ?: 0)
    }

    private fun readU32(b: ByteArray, from: Int): Pair<Long, Int> {
        var result = 0L; var shift = 0; var i = from
        while (i < b.size) {
            val byte = b[i].toInt() and 0xff
            result = result or ((byte and 0x7f).toLong() shl shift)
            i++
            if (byte and 0x80 == 0) break
            shift += 7
            if (shift > 35) break
        }
        return result to (i - from)
    }

    private fun readS32(b: ByteArray, from: Int): Pair<Long, Int> {
        var result = 0L; var shift = 0; var i = from
        var byte: Int
        do {
            byte = b[i].toInt() and 0xff
            result = result or ((byte and 0x7f).toLong() shl shift)
            shift += 7
            i++
        } while (i <= b.size && byte and 0x80 != 0 && shift < 35)
        if (shift < 64 && (byte and 0x40) != 0) result = result or (-1L shl shift)
        return result to (i - from)
    }

    private fun readS64(b: ByteArray, from: Int): Pair<Long, Int> {
        var result = 0L; var shift = 0; var i = from
        var byte: Int
        do {
            byte = b[i].toInt() and 0xff
            result = result or ((byte and 0x7f).toLong() shl shift)
            shift += 7
            i++
        } while (i <= b.size && byte and 0x80 != 0 && shift < 70)
        if (shift < 64 && (byte and 0x40) != 0) result = result or (-1L shl shift)
        return result to (i - from)
    }

    private fun u32Len(b: ByteArray, from: Int): Int = readU32(b, from).second
}