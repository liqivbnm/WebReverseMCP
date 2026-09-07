package com.webreverse.mcp.javascript.analysis

/**
 * WASM CFG + SSA + 污点分析器（纯 Kotlin，无第三方依赖）。
 *
 * 在 WasmParser（section/函数体定位、name section 函数名、函数签名）与 WasmDisassembler
 * （指令即时数解码风格）的基础上补充「程序分析」视角：
 *
 * 1. **CFG**：自行解码函数体指令，按结构化控制流（block/loop/if/else/end）与分支
 *    （br/br_if/br_table/return）把函数切成基本块（basic block），并生成控制流边：
 *    - 顺序 `next`（前驱最后一个指令非 terminator 且不属于 loop 回边）
 *    - `if-then` / `if-else` / join
 *    - `loop` 回边 `backedge`（loop 尾部 end -> loop head）
 *    - `br` / `br_if` / `br_table` 经块栈 `knotStack` 解析出口地址（label -> 目标块）
 *    - `return` -> 虚拟函数出口（-1）
 *
 * 2. **SSA 版本**：local.set / local.tee 每次赋值产生新版本号，local.get 取当前版本，
 *    输出每个 local 的版本序列（版本号 + 定义指令地址）。
 *
 * 3. **污点传播**：用单遍栈机传播 taint——
 *    - 源：内存 load（i32.load 等，0x28..0x35）与「导入函数调用」的返回值
 *    - 汇：内存 store（0x36..0x3e）、memory.grow（0x40）、return
 *    - 沿数值运算/select/local 版本传递；block/if 的条件不参与污点
 *
 * 输出 WasmFuncAnalysis（ok/error/funcIndex/funcName/blocks/cfgEdges/ssaVersions/taintPath/summary），
 * 供 wasm.cfg_ssa 工具做「敏感数据流定位」（解密/校验函数里的输入 -> 输出/写内存/返回值路径）。
 */
class WasmCfgAnalyzer {

    // ---------------- 公共数据模型 ----------------

    /** 单个基本块：指令字节区间 [start, end) */
    data class CfgBlockInfo(
        val id: Int,
        val start: Int,
        val end: Int,
        val depth: Int = 0,
        val kind: String = "basic",
        val instrCount: Int = 0,
        val addrRange: String = "", // 形如 "0x10..0x3a"
    )

    /** 控制流边 */
    data class CfgEdgeInfo(
        val from: Int,
        val to: Int,
        val kind: String,     // next / br / br_if / br_table / if-then / if-else / end-then / backedge / return
        val label: Int = -1,
    )

    /** 单个 local 的 SSA 版本 */
    data class SsaVersion(
        val version: Int,
        val addr: Int,
        val op: String,
    )

    /** 某个 local 的版本序列 */
    data class SsaLocal(
        val local: Int,
        val versions: List<SsaVersion> = emptyList(),
    )

    /** 一条污点传播路径：源 load/import -> 汇 store/grow/return */
    data class TaintInfo(
        val source: String,
        val sink: String,
        val sourceAddr: Int,
        val sinkAddr: Int,
        val via: List<Int> = emptyList(),   // 传播途中的指令地址
        val locals: List<Int> = emptyList(), // 携带污点的 local
    )

    /** 函数级分析结果 */
    data class WasmFuncAnalysis(
        val ok: Boolean,
        val error: String = "",
        val funcIndex: Int = -1,
        val funcName: String = "",
        val signature: String = "",
        val blocks: List<CfgBlockInfo> = emptyList(),
        val cfgEdges: List<CfgEdgeInfo> = emptyList(),
        val ssaVersions: List<SsaLocal> = emptyList(),
        val taintPath: List<TaintInfo> = emptyList(),
        val summary: String = "",
    )

    // ---------------- 入口 ----------------

    private val parser = WasmParser()

    /** 按导出函数名分析 */
    fun analyzeExport(bytes: ByteArray, exportName: String): WasmFuncAnalysis {
        val parsed = parser.parse(bytes)
        if (!parsed.ok) return WasmFuncAnalysis(false, parsed.error)
        val exp = parsed.exports.firstOrNull { it.kind == "func" && it.name == exportName }
            ?: return WasmFuncAnalysis(false, "导出函数 '$exportName' 不存在", funcName = exportName)
        return analyze(bytes, exp.index)
    }

    /** 按函数索引分析（索引含导入函数计数偏移） */
    fun analyze(bytes: ByteArray, funcIndex: Int): WasmFuncAnalysis {
        val parsed = parser.parse(bytes)
        if (!parsed.ok) return WasmFuncAnalysis(false, parsed.error, funcIndex = funcIndex)
        val importedCount = parsed.imports.count { it.kind == "func" }
        if (funcIndex < importedCount) {
            val imp = parsed.imports.filter { it.kind == "func" }.getOrNull(funcIndex)
            return WasmFuncAnalysis(
                false, "索引 $funcIndex 是导入函数（${imp?.module ?: "?"}.${imp?.name ?: "?"}），无本地函数体",
                funcIndex = funcIndex,
            )
        }
        val localIdx = funcIndex - importedCount
        val sig = parsed.localFunctions.getOrNull(localIdx)
            ?: return WasmFuncAnalysis(false, "函数索引 $funcIndex 超出范围（本地函数 ${parsed.localFunctions.size} 个）", funcIndex = funcIndex)
        val body = findBody(bytes, localIdx)
            ?: return WasmFuncAnalysis(false, "未找到函数体（code section 解析失败）", funcIndex = funcIndex)
        val name = parsed.functionNames[funcIndex]
            ?: parsed.exports.firstOrNull { it.kind == "func" && it.index == funcIndex }?.name
            ?: "func_$funcIndex"
        return analyzeInternal(bytes, body, funcIndex, name, sig, parsed)
    }

    /** 分析全部本地函数（不含导入函数） */
    fun analyzeAll(bytes: ByteArray): List<WasmFuncAnalysis> {
        val parsed = parser.parse(bytes)
        if (!parsed.ok) return listOf(WasmFuncAnalysis(false, parsed.error))
        val importedCount = parsed.imports.count { it.kind == "func" }
        val out = ArrayList<WasmFuncAnalysis>(parsed.localFunctions.size)
        parsed.localFunctions.forEachIndexed { i, _ ->
            out.add(analyze(bytes, importedCount + i))
        }
        return out
    }

    // ---------------- 分析主流程 ----------------

    private fun analyzeInternal(
        bytes: ByteArray,
        body: Body,
        funcIndex: Int,
        name: String,
        sig: WasmParser.FuncType,
        parsed: WasmParser.ParsedWasm,
    ): WasmFuncAnalysis {
        val (funcInfos, _) = buildFuncInfos(parsed)
        val decoded = decodeBody(bytes, body.from, body.to)
        if (decoded.isEmpty()) {
            return WasmFuncAnalysis(false, "函数体为空", funcIndex, name, signature = sigString(sig))
        }
        val cfg = buildCfg(decoded)
        val (ssa, taints) = runAnalysis(decoded, sig, funcInfos)

        val entry = ssa.sumOf { it.versions.size }
        val summary = buildSummary(name, funcIndex, sig, cfg, ssa, taints, entry, decoded.size)

        return WasmFuncAnalysis(
            ok = true,
            funcIndex = funcIndex,
            funcName = name,
            signature = sigString(sig),
            blocks = cfg.blocks,
            cfgEdges = cfg.edges,
            ssaVersions = ssa,
            taintPath = taints,
            summary = summary,
        )
    }

    /** 供 wasm.cfg_ssa 复用：构造函数级摘要文本 */
    private fun buildSummary(
        name: String,
        funcIndex: Int,
        sig: WasmParser.FuncType,
        cfg: CfgBuild,
        ssa: List<SsaLocal>,
        taints: List<TaintInfo>,
        ssaDefCount: Int,
        instrCount: Int,
    ): String {
        val sb = StringBuilder("func[$funcIndex] $name${sigString(sig)}")
        sb.append(" | instrs=$instrCount blocks=${cfg.blocks.size} edges=${cfg.edges.size}")
        sb.append(" ssaDefs=$ssaDefCount over ${ssa.size} locals")
        if (taints.isEmpty()) {
            sb.append(" | taint: none")
        } else {
            val unique = taints.groupingBy { it.source }.eachCount().map { (k, v) -> "$k(x$v)" }
            sb.append(" | taint: ${unique.joinToString(",")} -> sinks={${
                taints.map { it.sink }.toSet().joinToString(",")
            }}")
        }
        return sb.toString()
    }

    // ---------------- code section 定位（同 WasmDisassembler.findBody 风格） ----------------

    private data class Body(val from: Int, val to: Int)

    private fun findBody(bytes: ByteArray, localIdx: Int): Body? {
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
                for (k in 0 until n.toInt()) {
                    val (bodySize, bb) = readU32(bytes, pos)
                    pos += bb
                    val bodyEnd = pos + bodySize.toInt()
                    if (idx == localIdx) return Body(pos, bodyEnd)
                    pos = bodyEnd
                    idx++
                }
                return null
            }
            pos = end
        }
        return null
    }

    // ---------------- 指令解码 ----------------

    private class Ins(
        var addr: Int = 0,
        var size: Int = 0,
        var opcode: Int = 0,
        var name: String = "",
        var memArg: Pair<Long, Long>? = null, // offset, align（仅 load/store）
        var immed: List<Long> = emptyList(),
    )

    private fun decodeBody(b: ByteArray, from: Int, to: Int): List<Ins> {
        var pos = from
        val list = ArrayList<Ins>()
        val (groups, gl) = readU32(b, pos); pos += gl
        repeat(groups.toInt()) {
            val (cnt, cl) = readU32(b, pos); pos += cl
            b[pos].toInt(); pos += 1 // valtype
        }
        while (pos < to) {
            val start = pos
            val op = b[pos].toInt() and 0xff; pos++
            val dec = readDecodedImm(b, pos, op)
            pos = dec.newPos
            list.add(
                Ins(
                    addr = start,
                    size = pos - start,
                    opcode = op,
                    name = opName(op),
                    memArg = dec.memArg,
                    immed = dec.immed,
                ),
            )
        }
        return list
    }

    private class Decoded(val newPos: Int, val memArg: Pair<Long, Long>? = null, val immed: List<Long> = emptyList())

    private fun readDecodedImm(b: ByteArray, pos: Int, op: Int): Decoded {
        var p = pos
        val immed = ArrayList<Long>()
        when (op) {
            0x02, 0x03, 0x04, 0xd0 -> { // block/loop/if/ref.null blocktype
                p = p + blockTypeLen(b, p)
            }
            0x0c, 0x0d, 0x10, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0xd2 -> {
                val (v, l) = readU32(b, p); p += l; immed.add(v)
            }
            0x0e -> { // br_table: labelidx vec + default
                val (n, l) = readU32(b, p); p += l
                repeat(n.toInt() + 1) {
                    val (t, tl) = readU32(b, p); p += tl; immed.add(t)
                }
            }
            0x11 -> { // call_indirect
                val (t, l1) = readU32(b, p); p += l1; immed.add(t)
                val (tb, l2) = readU32(b, p); p += l2; immed.add(tb)
            }
            0x1c -> { // select_t
                val (vn, ln) = readU32(b, p); p += ln
                repeat(vn.toInt()) {
                    val (x, l) = readU32(b, p); p += l; immed.add(x)
                }
            }
            in 0x28..0x3e -> { // memarg (load/store)
                val (a, la) = readU32(b, p); p += la
                val (o, lo) = readU32(b, p); p += lo
                return Decoded(p, memArg = (o to a))
            }
            0x3f, 0x40 -> { val (v, l) = readU32(b, p); p += l; immed.add(v) }
            0x41 -> { val (v, l) = readS32(b, p); p += l; immed.add(v) }
            0x42 -> { val (v, l) = readS64(b, p); p += l; immed.add(v) }
            0x43 -> p += 4
            0x44 -> p += 8
            0xfb, 0xfc -> {
                val (sub, sl) = readU32(b, p); p += sl; immed.add(sub)
                when (sub.toInt()) {
                    0, 2, 4, 6 -> { val (x, l1) = readU32(b, p); p += l1; val (y, l2) = readU32(b, p); p += l2 }
                    1, 3, 5, 7, 8, 9 -> { val (x, l1) = readU32(b, p); p += l1 }
                }
            }
            // 其余 opcode 无 immediate
        }
        return Decoded(p, immed = immed)
    }

    // ---------------- CFG 构建 ----------------

    private class Knot(
        val kind: String,       // func / block / loop / if
        val startAddr: Int,
        val depth: Int,
        var headBlock: Int = -1, // loop/block 体头块、if 的 then 块
        var exitBlock: Int = -1, // 匹配 end 之后的块（join / 出口）
        var elseBlock: Int = -1, // if 的 else 块
        var enter: Int = -1,     // 构造指令的指令下标
        var elseI: Int = -1,     // else 指令下标
        var endI: Int = -1,      // end 指令下标
    )

    private class CfgBuild(
        val blocks: List<CfgBlockInfo>,
        val edges: List<CfgEdgeInfo>,
        val blockOf: IntArray,
        val starts: IntArray,
    )

    private fun buildCfg(decoded: List<Ins>): CfgBuild {
        val n = decoded.size
        val splitSet = intArrayOf(0x02, 0x03, 0x04, 0x05, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f)

        // --- 1. 基本块切分：在 if/else/loop/block/end/br/br_table/return 之后新起一块 ---
        val starts = ArrayList<Int>(); starts.add(0)
        for (i in 0 until n) {
            if (i + 1 < n && decoded[i].opcode in splitSet) starts.add(i + 1)
        }
        val m = starts.size
        val blockOf = IntArray(n)
        for (i in 0 until n) {
            var k = m - 1
            while (k > 0 && i < starts[k]) k--
            blockOf[i] = k
        }

        // --- 2. 结构化 knot 栈（Pass 1）：解析每个构造的 head/else/exit 块 ---
        val blockKind = HashMap<Int, String>()
        val endIsLoop = BooleanArray(n)
        val backedges = ArrayList<Pair<Int, Int>>() // (tailBlock, headBlock)
        val ifNodes = ArrayList<Knot>()

        val root = Knot("func", decoded[0].addr, 0).apply {
            headBlock = 0; enter = 0
        }
        val stack = ArrayDeque<Knot>()
        stack.add(root)
        val knotByEnter = HashMap<Int, Knot>()

        for (i in 0 until n) {
            val op = decoded[i].opcode
            when (op) {
                0x02, 0x03, 0x04 -> {
                    val kind = when (op) { 0x03 -> "loop"; 0x04 -> "if"; else -> "block" }
                    val k = Knot(kind, decoded[i].addr, stack.size)
                    k.enter = i
                    k.headBlock = if (i + 1 < n) blockOf[i + 1] else -1
                    stack.add(k)
                    knotByEnter[i] = k
                    if (op == 0x04) ifNodes.add(k)
                    if (k.headBlock >= 0) blockKind[k.headBlock] = when (kind) {
                        "loop" -> "loop"
                        "if" -> "if-then"
                        else -> "block-body"
                    }
                }
                0x05 -> {
                    val cur = stack.lastOrNull()
                    if (cur != null && cur.kind == "if") {
                        cur.elseI = i
                        cur.elseBlock = if (i + 1 < n) blockOf[i + 1] else -1
                        if (cur.elseBlock >= 0) blockKind[cur.elseBlock] = "if-else"
                    }
                }
                0x0b -> {
                    val k = stack.removeLastOrNull() ?: continue
                    k.endI = i
                    k.exitBlock = if (i + 1 < n) blockOf[i + 1] else -1
                    if (k.kind == "loop") {
                        endIsLoop[i] = true
                        if (k.headBlock >= 0) backedges.add(blockOf[i] to k.headBlock)
                    }
                    if (stack.isEmpty()) stack.add(root) // 防御：函数底端意外再遇 end
                }
            }
        }

        // --- 3. 边构建（Pass 2）：用块栈解析 br/br_if/br_table + 结构化边 + 顺序边 ---
        val edges = ArrayList<CfgEdgeInfo>()
        val stack2 = ArrayDeque<Knot>()
        stack2.add(root)

        // 顺序边
        for (b in 0 until m - 1) {
            val lastIdx = starts[b + 1] - 1
            val op = decoded[lastIdx].opcode
            val skip = when (op) {
                0x0c, 0x0e, 0x0f, 0x04 -> true              // br/br_table/return/if
                0x00 -> true                                // unreachable
                0x0b -> endIsLoop[lastIdx]                 // loop 尾 end：回边，非下溢顺序边
                0x05 -> true                               // else 尾：then 由 end-then 边连接
                else -> false
            }
            if (!skip) edges.add(CfgEdgeInfo(b, b + 1, "next"))
        }

        // if 结构化边
        for (k in ifNodes) {
            val a = if (k.enter >= 0) blockOf[k.enter] else -1
            if (a < 0) continue
            val thenB = k.headBlock
            val exitB = if (k.exitBlock >= 0) k.exitBlock else -1
            if (thenB >= 0) edges.add(CfgEdgeInfo(a, thenB, "if-then"))
            if (k.elseBlock >= 0) {
                edges.add(CfgEdgeInfo(a, k.elseBlock, "if-else"))
                // 无 else 分支的 then 尾用 end-then 汇合；有 else 时 then 与 else 都汇到 exitBlock
                val thenTail = if (k.elseI >= 0) blockOf[k.elseI] else -1
                if (thenTail >= 0) edges.add(CfgEdgeInfo(thenTail, exitB, "end-then"))
            } else {
                edges.add(CfgEdgeInfo(a, exitB, "if-else"))
            }
        }

        // loop 回边
        for ((tail, head) in backedges) {
            if (head >= 0) edges.add(CfgEdgeInfo(tail, head, "backedge"))
        }

        // 分支指令（br/br_if/br_table/return）——遍历时同步维护构造栈，保证 br label 正确解析
        for (i in 0 until n) {
            val op = decoded[i].opcode
            when (op) {
                0x02, 0x03, 0x04 -> { // 入栈（block/loop/if）
                    val k = knotByEnter[i]
                    if (k != null) stack2.add(k)
                }
                0x0b -> stack2.removeLastOrNull() // end 出栈
                0x0c, 0x0d -> { // br / br_if
                    val lab = decoded[i].immed.firstOrNull()?.toInt() ?: 0
                    val t = resolveTarget(stack2, i, lab, knotByEnter)
                    if (t != null) edges.add(CfgEdgeInfo(blockOf[i], t.first, if (op == 0x0c) "br" else "br_if", lab))
                }
                0x0e -> { // br_table
                    val labels = decoded[i].immed
                    labels.forEach { lb ->
                        val t = resolveTarget(stack2, i, lb.toInt(), knotByEnter)
                        if (t != null) edges.add(CfgEdgeInfo(blockOf[i], t.first, "br_table", lb.toInt()))
                    }
                }
                0x0f -> edges.add(CfgEdgeInfo(blockOf[i], -1, "return")) // 虚拟函数出口
            }
        }

        // --- 4. 组装块信息 ---
        val blocks = ArrayList<CfgBlockInfo>(m)
        for (k in 0 until m) {
            val startInstr = starts[k]
            val endInstr = if (k < m - 1) starts[k + 1] - 1 else n - 1
            val sAddr = decoded[startInstr].addr
            val eAddr = decoded[endInstr].addr + decoded[endInstr].size
            val kind = blockKind[k] ?: if (k == 0) "entry" else "basic"
            blocks.add(
                CfgBlockInfo(
                    id = k, start = sAddr, end = eAddr,
                    depth = 0, kind = kind,
                    instrCount = endInstr - startInstr + 1,
                    addrRange = "0x%x..0x%x".format(sAddr, eAddr),
                ),
            )
        }
        return CfgBuild(blocks, edges, blockOf, starts.toIntArray())
    }

    /** 按 label 在块栈中定位目标：loop -> head；block/if/root -> exit；无法解析返回 null */
    private fun resolveTarget(
        stack: ArrayDeque<Knot>,
        instrIndex: Int,
        label: Int,
        knotByEnter: Map<Int, Knot>,
    ): Pair<Int, String>? {
        if (stack.isEmpty()) return null
        val idx = stack.count() - 1 - label
        if (idx < 0 || idx >= stack.count()) return null
        val target = stack.elementAt(idx)
        return if (target.kind == "loop") {
            if (target.headBlock >= 0) target.headBlock to "loop" else null
        } else {
            (if (target.exitBlock >= 0) target.exitBlock else -1) to "exit"
        }
    }

    // ---------------- SSA + 污点分析 ----------------

    private class St(val tainted: Boolean, val origin: Int = 0, val via: List<Int> = emptyList())

    private class FuncInfo(
        val isImport: Boolean,
        val params: Int,
        val results: Int,
        val importName: String = "",
    )

    private fun buildFuncInfos(parsed: WasmParser.ParsedWasm): Pair<HashMap<Int, FuncInfo>, Int> {
        val importedFuncs = parsed.imports.filter { it.kind == "func" }
        val map = HashMap<Int, FuncInfo>()
        importedFuncs.forEachIndexed { i, imp ->
            val t = parsed.types.getOrNull(imp.typeIndex)
            map[i] = FuncInfo(true, t?.params?.size ?: 0, t?.results?.size ?: 0, "${imp.module}.${imp.name}")
        }
        parsed.localFunctions.forEachIndexed { idx, sig ->
            map[importedFuncs.size + idx] = FuncInfo(false, sig.params.size, sig.results.size)
        }
        return map to importedFuncs.size
    }

    private fun runAnalysis(
        decoded: List<Ins>,
        sig: WasmParser.FuncType,
        funcInfos: Map<Int, FuncInfo>,
    ): Pair<List<SsaLocal>, List<TaintInfo>> {
        val stack = ArrayList<St>()
        val versions = HashMap<Int, Int>()
        val defs = HashMap<Int, MutableList<SsaVersion>>()
        val localState = HashMap<Int, St>()
        val taintedLocals = HashSet<Int>()
        val taints = ArrayList<TaintInfo>()
        val results = sig.results.size

        fun push(s: St) = stack.add(s)
        fun pop(): St = if (stack.isNotEmpty()) stack.removeAt(stack.size - 1) else St(false)
        fun capVia(v: List<Int>): List<Int> = if (v.size > 32) v.takeLast(32) else v
        fun report(src: St, sink: String, sinkAddr: Int) {
            if (!src.tainted) return
            taints.add(
                TaintInfo(
                    source = opName(decoded.firstOrNull { it.addr == src.origin }?.opcode ?: -1),
                    sink = sink,
                    sourceAddr = src.origin,
                    sinkAddr = sinkAddr,
                    via = capVia(src.via),
                    locals = taintedLocals.toList(),
                ),
            )
        }

        for (ins in decoded) {
            val op = ins.opcode
            when {
                // ---- 源：内存 load ----
                op in 0x28..0x35 -> {
                    pop() // 地址
                    push(St(true, ins.addr, listOf(ins.addr)))
                }
                // ---- 汇：内存 store ----
                op in 0x36..0x3e -> {
                    val v = pop()
                    pop() // 地址
                    report(v, ins.name, ins.addr)
                }
                // ---- 汇：memory.grow ----
                op == 0x40 -> {
                    val v = pop()
                    report(v, "memory.grow", ins.addr)
                    push(St(false))
                }
                op == 0x41 || op == 0x42 || op == 0x43 || op == 0x44 -> push(St(false)) // const
                op == 0x3f -> push(St(false)) // memory.size

                // ---- local 访问与 SSA ----
                op == 0x20 -> { // local.get
                    val lo = ins.immed.firstOrNull()?.toInt() ?: 0
                    val st = localState[lo] ?: St(false)
                    push(st)
                }
                op == 0x21 || op == 0x22 -> { // local.set / local.tee
                    val lo = ins.immed.firstOrNull()?.toInt() ?: 0
                    val v = pop()
                    val ver = (versions[lo] ?: 0) + 1
                    versions[lo] = ver
                    defs.getOrPut(lo) { ArrayList() }.add(SsaVersion(ver, ins.addr, ins.name))
                    localState[lo] = v
                    if (v.tainted) taintedLocals.add(lo) else taintedLocals.remove(lo)
                    if (op == 0x22) push(v) // tee 即存即用，压回
                }
                op == 0x23 -> push(St(false)) // global.get
                op == 0x24 -> pop()           // global.set

                // ---- 分类器/段规 ----
                op == 0x1a -> pop()           // drop
                op == 0x1b -> { val c = pop(); val b = pop(); val a = pop()
                    push(St(a.tainted || b.tainted, if (a.tainted) a.origin else b.origin, (a.via + b.via) ))
                }
                op == 0x1c -> { // select_t
                    val cond = pop()
                    val n = ins.immed.size
                    val vals = ArrayList<St>()
                    repeat(n) { vals.add(pop()) }
                    val any = vals.firstOrNull { it.tainted }
                    push(St(any != null, any?.origin ?: 0, any?.via ?: emptyList()))
                }

                // ---- 调用 ----
                op == 0x10 -> { // call
                    val target = ins.immed.firstOrNull()?.toInt() ?: 0
                    val fi = funcInfos[target]
                    repeat(fi?.params ?: 0) { pop() }
                    val nRes = fi?.results ?: 0
                    repeat(nRes) {
                        if (fi?.isImport == true) push(St(true, ins.addr, listOf(ins.addr))) // 导入调用返回值=源
                        else push(St(false))
                    }
                }
                op == 0x11 -> { // call_indirect：未知，结果视为不污
                    pop() // 表索引
                    repeat(1) { pop() }
                    push(St(false))
                }

                // ---- 汇：return ----
                op == 0x0f -> {
                    repeat(results) {
                        val v = pop()
                        report(v, "return", ins.addr)
                    }
                }

                // ---- 控制流（不参与污点，仅耗栈） ----
                op == 0x04 -> pop()            // if 条件
                op == 0x0d -> pop()            // br_if 条件
                op == 0x0e -> pop()            // br_table 选择
                op == 0x0c -> { /* br：无操作数处理（block 参数近似忽略） */ }
                op == 0x00 -> stack.clear()    // unreachable

                // ---- 数值/比较/转换：污点随结果传播 ----
                op in 0x45..0xc4 -> {
                    val popc = if (isUnaryNumeric(op)) 1 else 2
                    val a1 = pop()
                    val a2 = if (popc == 2) pop() else St(false)
                    val tainted = a1.tainted || a2.tainted
                    if (tainted) {
                        val via1 = if (a1.tainted) a1.via else emptyList<Int>()
                        val via2 = if (a2.tainted) a2.via else emptyList<Int>()
                        val via = capVia(via1 + via2)
                        val origin = if (a1.tainted) a1.origin else a2.origin
                        push(St(true, origin, via))
                    } else {
                        push(St(false))
                    }
                }
            }
        }

        val ssa = defs.entries.sortedBy { it.key }.map { (lo, vs) ->
            SsaLocal(lo, vs.sortedBy { it.addr })
        }
        return ssa to taints
    }

    // ---------------- opcode 辅助 ----------------

    private fun isLoad(op: Int) = op in 0x28..0x35
    private fun isStore(op: Int) = op in 0x36..0x3e

    private fun isUnaryNumeric(op: Int): Boolean = when (op) {
        // eqz / clz / ctz / popcnt / abs / neg / ceil / floor / trunc / nearest / sqrt / 转换 / 符号扩展
        0x45, 0x50, 0x67, 0x68, 0x69, 0x79, 0x7a, 0x7b,
        0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91,
        0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, // f64 unary (abs neg ceil floor trunc nearest sqrt)
        0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1,
        0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb,
        0xbc, 0xbd, 0xbe, 0xbf,
        0xc0, 0xc1, 0xc2, 0xc3, 0xc4 -> true
        else -> false
    }

    // ---------------- 展示 ----------------

    private fun sigString(t: WasmParser.FuncType): String =
        (if (t.params.isEmpty()) "" else "(param ${t.params.joinToString(" ")}) ") +
            (if (t.results.isEmpty()) "" else "(result ${t.results.joinToString(" ")})").trim()

    // ---------------- LEB128 / block type（同 WasmDisassembler 风格） ----------------

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
        if (shift < 64 && (byte and 0x40) != 0) {
            result = result or (-1L shl shift)
        }
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
        if (shift < 64 && (byte and 0x40) != 0) {
            result = result or (-1L shl shift)
        }
        return result to (i - from)
    }

    /** block 类型字节数（单字节 valtype/void，或多字节 s33 typeidx 的 LEB 长度） */
    private fun blockTypeLen(b: ByteArray, from: Int): Int {
        val v = b[from].toInt() and 0xff
        if (v == 0x40 || v == 0x7f || v == 0x7e || v == 0x7d || v == 0x7c ||
            v == 0x6f || v == 0x70 || v == 0x6b) return 1
        if (v and 0x80 == 0) return 1
        var i = from
        do {
            val nb = b[i].toInt() and 0xff
            i++
            if (nb and 0x80 == 0) break
        } while (i < b.size)
        return i - from
    }

    // ---------------- opcode 名称表（展示用） ----------------

    private fun opName(op: Int): String = opcodeNames[op] ?: when (op) {
        in 0x28..0x35 -> "load"
        in 0x36..0x3e -> "store"
        in 0x45..0xc4 -> "num"
        0xd1 -> "ref.is_null"
        0xfb -> "prefix_fb"
        0xfc -> "prefix_fc"
        else -> "op_0x${op.toString(16)}"
    }

    private val opcodeNames: Map<Int, String> = buildMap {
        put(0x00, "unreachable"); put(0x01, "nop"); put(0x02, "block"); put(0x03, "loop"); put(0x04, "if")
        put(0x05, "else"); put(0x0b, "end"); put(0x0c, "br"); put(0x0d, "br_if"); put(0x0e, "br_table")
        put(0x0f, "return"); put(0x10, "call"); put(0x11, "call_indirect")
        put(0x1a, "drop"); put(0x1b, "select"); put(0x1c, "select_t")
        put(0x20, "local.get"); put(0x21, "local.set"); put(0x22, "local.tee")
        put(0x23, "global.get"); put(0x24, "global.set")
        put(0x28, "i32.load"); put(0x29, "i64.load"); put(0x2a, "f32.load"); put(0x2b, "f64.load")
        put(0x2c, "i32.load8_s"); put(0x2d, "i32.load8_u"); put(0x2e, "i32.load16_s"); put(0x2f, "i32.load16_u")
        put(0x30, "i64.load8_s"); put(0x31, "i64.load8_u"); put(0x32, "i64.load16_s"); put(0x33, "i64.load16_u")
        put(0x34, "i64.load32_s"); put(0x35, "i64.load32_u")
        put(0x36, "i32.store"); put(0x37, "i64.store"); put(0x38, "f32.store"); put(0x39, "f64.store")
        put(0x3a, "i32.store8"); put(0x3b, "i32.store16"); put(0x3c, "i64.store8"); put(0x3d, "i64.store16")
        put(0x3e, "i64.store32"); put(0x3f, "memory.size"); put(0x40, "memory.grow")
        put(0x41, "i32.const"); put(0x42, "i64.const"); put(0x43, "f32.const"); put(0x44, "f64.const")
        put(0x45, "i32.eqz"); put(0x46, "i32.eq"); put(0x47, "i32.ne"); put(0x48, "i32.lt_s"); put(0x49, "i32.lt_u")
        put(0x4a, "i32.gt_s"); put(0x4b, "i32.gt_u"); put(0x4c, "i32.le_s"); put(0x4d, "i32.le_u")
        put(0x4e, "i32.ge_s"); put(0x4f, "i32.ge_u")
        put(0x50, "i64.eqz"); put(0x51, "i64.eq"); put(0x52, "i64.ne"); put(0x53, "i64.lt_s"); put(0x54, "i64.lt_u")
        put(0x55, "i64.gt_s"); put(0x56, "i64.gt_u"); put(0x57, "i64.le_s"); put(0x58, "i64.le_u")
        put(0x59, "i64.ge_s"); put(0x5a, "i64.ge_u")
        put(0x67, "i32.clz"); put(0x68, "i32.ctz"); put(0x69, "i32.popcnt")
        put(0x6a, "i32.add"); put(0x6b, "i32.sub"); put(0x6c, "i32.mul"); put(0x6d, "i32.div_s"); put(0x6e, "i32.div_u")
        put(0x6f, "i32.rem_s"); put(0x70, "i32.rem_u"); put(0x71, "i32.and"); put(0x72, "i32.or")
        put(0x73, "i32.xor"); put(0x74, "i32.shl"); put(0x75, "i32.shr_s"); put(0x76, "i32.shr_u")
        put(0x77, "i32.rotl"); put(0x78, "i32.rotr")
        put(0x79, "i64.clz"); put(0x7a, "i64.ctz"); put(0x7b, "i64.popcnt")
        put(0x7c, "i64.add"); put(0x7d, "i64.sub"); put(0x7e, "i64.mul"); put(0x7f, "i64.div_s"); put(0x80, "i64.div_u")
        put(0x81, "i64.rem_s"); put(0x82, "i64.rem_u"); put(0x83, "i64.and"); put(0x84, "i64.or")
        put(0x85, "i64.xor"); put(0x86, "i64.shl"); put(0x87, "i64.shr_s"); put(0x88, "i64.shr_u")
        put(0x89, "i64.rotl"); put(0x8a, "i64.rotr")
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
}