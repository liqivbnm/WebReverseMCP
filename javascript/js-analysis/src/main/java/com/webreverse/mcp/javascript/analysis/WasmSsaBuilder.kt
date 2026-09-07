package com.webreverse.mcp.javascript.analysis

/**
 * WASM Stack-SSA 构建器（ 新增）。
 *
 * 解决评审报告指出的两个核心缺陷：
 *
 * 1. **类型栈分析（Type Stack）**：WASM 是强类型栈机——每条指令 pop/push 的类型
 *    固定。逐指令模拟抽象类型栈（i32/i64/f32/f64/v128/ref/unknown），可：
 *    - 发现「无效栈状态」（反汇编失步/指令表缺失的可靠信号）
 *    - 为每条指令标注操作数类型，直接输出类型化伪代码
 *
 * 2. **Stack-SSA + Phi**：线性版本号在 if/else/loop/br 合并点会丢语义。
 *    本构建器把栈机「寄存器化」：
 *    - 栈上每个槽位 → 虚拟寄存器 v{n}
 *    - local 变量 → 带版本号 l{i}.{v}
 *    - 结构化控制流的合并点（end of if / loop latch）→ phi 节点：
 *      ```
 *      v1 = 10
 *      v2 = 20
 *      v3 = phi(v1, v2)      ;; if/else 汇合
 *      return v3
 *      ```
 *
 * 输出：类型化 SSA 伪代码 + 栈校验报告（失步告警），配合 wasm.cfg_ssa 的
 * 基本块/污点分析形成完整的 WASM 逆向视图。
 */
class WasmSsaBuilder {

    // ---------------- 数据模型 ----------------

    /** 抽象值类型 */
    enum class VType(val display: String) {
        I32("i32"), I64("i64"), F32("f32"), F64("f64"),
        V128("v128"), FUNCREF("funcref"), EXTERNREF("externref"), UNKNOWN("?"),
        // ---- CFG-SSA 精细化未知类型（新增独立枚举值，保留 UNKNOWN 兼容旧引用） ----
        UNKNOWN_NUMERIC("?num"), UNKNOWN_REF("?ref"), UNKNOWN_VECTOR("?vec"),
        UNKNOWN_POINTER("?ptr"), UNKNOWN_FUNCREF("?fn"),
    }

    /** 一条 SSA 指令 */
    data class SsaInstr(
        val addr: Int,          // 函数体内偏移
        val op: String,         // wat 风格指令名
        val result: String,     // 目标虚拟寄存器（v3 / l1.2 / phi）
        val inputs: List<String>, // 输入寄存器列表
        val type: VType,        // 结果类型
        val raw: String,        // 原始 wat 行
    )

    /** Phi 节点 */
    data class PhiNode(
        val target: String,     // 合并目标寄存器
        val sources: List<String>, // 来源寄存器（各前驱路径的值）
        val type: VType,
        val addr: Int,
    )

    /** 栈校验问题 */
    data class StackIssue(
        val addr: Int,
        val op: String,
        val message: String,    // underflow / type-mismatch / leftover
    )

    data class SsaResult(
        val ok: Boolean,
        val error: String = "",
        val funcName: String = "",
        val funcIndex: Int = -1,
        val signature: String = "",
        val instructions: List<SsaInstr> = emptyList(),
        val phis: List<PhiNode> = emptyList(),
        val issues: List<StackIssue> = emptyList(),
        val typeStackFinal: List<VType> = emptyList(),   // 结束时残留栈（应为函数返回类型）
        val listing: String = "",                        // 类型化 SSA 伪代码
        val vregCount: Int = 0,
        val localVersions: Map<Int, Int> = emptyMap(),   // local idx -> 版本数
        // ---- CFG-SSA 增强字段（可选，旧调用方传默认值即无需改动） ----
        val blocks: List<WasmCfgSsaBuilder.BasicBlock> = emptyList(),
        val cfgEdges: List<WasmCfgSsaBuilder.CfgEdge> = emptyList(),
        val cfgSummary: String = "",                     // CFG 文本摘要（块 + 边 + back-edge + phi 点）
        val cfgConverged: Boolean = true,                // 不动点是否收敛（false = 达到伦次上限）
    )

    // ---------------- 指令类型签名表 ----------------

    /** 指令 -> (popTypes 逆序, pushTypes)；null = 控制流指令单独处理 */
    private data class Sig(val pops: List<VType>, val pushes: List<VType>)

    private fun sig(vararg pops: VType, pushes: Array<VType> = emptyArray()) =
        Sig(pops.toList(), pushes.toList())

    private val typeSigs: Map<Int, Sig> = buildMap {
        // 参量指令
        put(0x1a, sig(pushes = arrayOf()))                        // drop
        put(0x1b, sig(VType.UNKNOWN, VType.UNKNOWN, VType.I32))   // select
        // 变量指令
        put(0x20, sig(pushes = arrayOf(VType.UNKNOWN)))           // local.get（类型依 local 声明）
        put(0x23, sig(pushes = arrayOf(VType.UNKNOWN)))           // global.get
        put(0xd2, sig(pushes = arrayOf(VType.FUNCREF)))           // ref.func
        put(0xd0, sig(pushes = arrayOf(VType.FUNCREF, VType.EXTERNREF))) // ref.null（heaptype 区分）
        put(0xd1, sig(VType.FUNCREF, VType.EXTERNREF, VType.I32)) // ref.is_null（近似）
        // 内存 load（地址 i32 -> 值）
        for (op in listOf(0x28, 0x2c, 0x2d, 0x2e, 0x2f)) put(op, sig(VType.I32, pushes = arrayOf(VType.I32)))
        put(0x29, sig(VType.I32, pushes = arrayOf(VType.I64)))
        put(0x2a, sig(VType.I32, pushes = arrayOf(VType.F32)))
        put(0x2b, sig(VType.I32, pushes = arrayOf(VType.F64)))
        for (op in listOf(0x30, 0x31, 0x32, 0x33, 0x34, 0x35)) put(op, sig(VType.I32, pushes = arrayOf(VType.I64)))
        // 内存 store
        put(0x36, sig(VType.I32, VType.I32, pushes = arrayOf()))
        put(0x37, sig(VType.I32, VType.I64, pushes = arrayOf()))
        put(0x38, sig(VType.I32, VType.F32, pushes = arrayOf()))
        put(0x39, sig(VType.I32, VType.F64, pushes = arrayOf()))
        put(0x3a, sig(VType.I32, VType.I32, pushes = arrayOf()))
        put(0x3b, sig(VType.I32, VType.I32, pushes = arrayOf()))
        put(0x3c, sig(VType.I32, VType.I64, pushes = arrayOf()))
        put(0x3d, sig(VType.I32, VType.I64, pushes = arrayOf()))
        put(0x3e, sig(VType.I32, VType.I64, pushes = arrayOf()))
        put(0x3f, sig(pushes = arrayOf(VType.I32)))               // memory.size
        put(0x40, sig(VType.I32, pushes = arrayOf(VType.I32)))    // memory.grow
        // 常量
        put(0x41, sig(pushes = arrayOf(VType.I32)))
        put(0x42, sig(pushes = arrayOf(VType.I64)))
        put(0x43, sig(pushes = arrayOf(VType.F32)))
        put(0x44, sig(pushes = arrayOf(VType.F64)))
        // i32 比较（i32,i32 -> i32）
        for (op in 0x45..0x4f) put(op, sig(VType.I32, VType.I32, pushes = arrayOf(VType.I32)))
        put(0x45, sig(VType.I32, pushes = arrayOf(VType.I32)))    // i32.eqz
        // i64 比较
        put(0x50, sig(VType.I64, pushes = arrayOf(VType.I32)))
        for (op in 0x51..0x5a) put(op, sig(VType.I64, VType.I64, pushes = arrayOf(VType.I32)))
        // f32 比较
        for (op in 0x5b..0x60) put(op, sig(VType.F32, VType.F32, pushes = arrayOf(VType.I32)))
        // f64 比较
        for (op in 0x61..0x66) put(op, sig(VType.F64, VType.F64, pushes = arrayOf(VType.I32)))
        // i32 一元
        for (op in listOf(0x67, 0x68, 0x69)) put(op, sig(VType.I32, pushes = arrayOf(VType.I32)))
        // i32 二元
        for (op in 0x6a..0x78) put(op, sig(VType.I32, VType.I32, pushes = arrayOf(VType.I32)))
        // i64 一元
        for (op in listOf(0x79, 0x7a, 0x7b)) put(op, sig(VType.I64, pushes = arrayOf(VType.I64)))
        put(0x79, sig(VType.I64, pushes = arrayOf(VType.I64)))
        // i64 二元
        for (op in 0x7c..0x8a) put(op, sig(VType.I64, VType.I64, pushes = arrayOf(VType.I64)))
        // f32 一元
        for (op in 0x8b..0x91) put(op, sig(VType.F32, pushes = arrayOf(VType.F32)))
        // f32 二元
        for (op in 0x92..0x98) put(op, sig(VType.F32, VType.F32, pushes = arrayOf(VType.F32)))
        // f64 一元
        for (op in 0x99..0x9f) put(op, sig(VType.F64, pushes = arrayOf(VType.F64)))
        // f64 二元
        for (op in 0xa0..0xa6) put(op, sig(VType.F64, VType.F64, pushes = arrayOf(VType.F64)))
        // 转换指令
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
        // 符号扩展
        put(0xc0, sig(VType.I32, pushes = arrayOf(VType.I32)))
        put(0xc1, sig(VType.I32, pushes = arrayOf(VType.I32)))
        put(0xc2, sig(VType.I64, pushes = arrayOf(VType.I64)))
        put(0xc3, sig(VType.I64, pushes = arrayOf(VType.I64)))
        put(0xc4, sig(VType.I64, pushes = arrayOf(VType.I64)))
    }

    private fun valType(v: Int): VType = when (v) {
        0x7f -> VType.I32; 0x7e -> VType.I64; 0x7d -> VType.F32; 0x7c -> VType.F64
        0x7b -> VType.V128; 0x70 -> VType.FUNCREF; 0x6f -> VType.EXTERNREF
        else -> VType.UNKNOWN
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
        if (funcIndex < importedFuncs) {
            return SsaResult(false, "索引 $funcIndex 是导入函数，无函数体", funcIndex = funcIndex)
        }
        val localIdx = funcIndex - importedFuncs
        val sig = parsed.localFunctions.getOrNull(localIdx)
            ?: return SsaResult(false, "函数索引超出范围", funcIndex = funcIndex)
        val name = parsed.functionNames[funcIndex]
            ?: parsed.exports.firstOrNull { it.kind == "func" && it.index == funcIndex }?.name
            ?: "func_$funcIndex"

        val body = locateBody(bytes, localIdx)
            ?: return SsaResult(false, "未找到函数体", funcName = name, funcIndex = funcIndex)

        return build(bytes, body, sig, name, funcIndex, parsed, importedFuncs, maxInstr)
    }

    /**
     * CFG-based SSA（真正的基于基本块的 SSA，含 loop/back-edge/br/br_table 数据流传播）。
     * 委托给 [WasmCfgSsaBuilder]，返回同样式 [SsaResult]，额外填充 blocks/cfgEdges/cfgSummary。
     * 公共 API 与 [analyze] 完全兼容。
     */
    fun analyzeCfg(bytes: ByteArray, funcIndex: Int, maxInstr: Int = 2000): SsaResult {
        val cfg = WasmCfgSsaBuilder()
        return cfg.analyze(bytes, funcIndex, maxInstr)
    }

    /** CFG-based SSA：按导出名定位函数。 */
    fun analyzeCfgExport(bytes: ByteArray, exportName: String, maxInstr: Int = 2000): SsaResult {
        val cfg = WasmCfgSsaBuilder()
        return cfg.analyzeExport(bytes, exportName, maxInstr)
    }

    // ---------------- SSA 构建 ----------------

    private fun build(
        bytes: ByteArray,
        body: Pair<Int, Int>, // (from, to)
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

        // locals 声明展开（local 类型序列）
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

        // 状态：类型栈 + 值栈（虚拟寄存器名）+ local 版本
        val typeStack = ArrayDeque<VType>()
        val vregStack = ArrayDeque<String>()
        val localVersion = IntArray(localTypes.size.coerceAtMost(4096)) { 0 }
        var vregSeq = 0
        val instrs = mutableListOf<SsaInstr>()
        val phis = mutableListOf<PhiNode>()
        val issues = mutableListOf<StackIssue>()

        // 结构化控制流合并点追踪：块栈（addr 栈深度快照，end 时生成 phi）
        data class BlockFrame(
            val kind: String,          // block/loop/if/else
            val entryDepth: Int,       // 进入时栈深
            val entryRegs: List<String>, // 进入时栈寄存器快照
            val elseRegs: List<String>?, // else 分支前快照（if 用）
            val pendingPhi: Boolean,
        )
        val blockStack = mutableListOf<BlockFrame>()

        fun freshVreg(type: VType): String {
            vregSeq++
            return "v$vregSeq"
        }

        fun pushV(type: VType, reg: String) {
            typeStack.addLast(type)
            vregStack.addLast(reg)
        }

        fun popV(op: String, addr: Int): Pair<VType, String>? {
            if (typeStack.isEmpty()) {
                issues.add(StackIssue(addr, op, "栈下溢（underflow）——疑似反汇编失步"))
                return null
            }
            return typeStack.removeLast() to vregStack.removeLast()
        }

        fun localRead(idx: Int): String {
            val v = localVersion.getOrNull(idx) ?: 0
            return "l$idx.${if (v == 0) "0" else v.toString()}"
        }

        fun localWrite(idx: Int): String {
            if (idx < localVersion.size) localVersion[idx]++
            return "l$idx.${(localVersion.getOrNull(idx) ?: 0)}"
        }

        var count = 0
        var truncated = false
        while (pos < bodyEnd && count < maxInstr) {
            count++
            val addr = pos
            val op = b[pos].toInt() and 0xff
            pos++
            var opName = opcodeNames[op] ?: "op_0x${op.toString(16)}"

            when (op) {
                // ---- 控制流 ----
                0x02, 0x03 -> { // block / loop
                    pos += blockTypeLen(b, pos)
                    blockStack.add(BlockFrame(opName, typeStack.size, vregStack.toList(), null, false))
                }
                0x04 -> { // if（条件在栈顶）
                    pos += blockTypeLen(b, pos)
                    val cond = popV("if", addr)
                    val fr = BlockFrame("if", typeStack.size, vregStack.toList(), null, false)
                    blockStack.add(fr)
                    if (cond != null) {
                        instrs.add(SsaInstr(addr, "br_if", "—", listOf(cond.second), VType.I32, "if ${cond.second}"))
                    }
                }
                0x05 -> { // else：快照 then 分支出口，回滚到 if 入口深度
                    val fr = blockStack.lastOrNull()
                    if (fr != null && fr.kind == "if") {
                        val thenRegs = vregStack.toList()
                        val frIdx = blockStack.size - 1
                        blockStack[frIdx] = fr.copy(elseRegs = thenRegs)
                        // 回滚栈到 if 入口深度
                        while (vregStack.size > fr.entryDepth) {
                            if (typeStack.isNotEmpty()) typeStack.removeLast()
                            if (vregStack.isNotEmpty()) vregStack.removeLast()
                        }
                    }
                }
                0x0b -> { // end：合并点 -> phi
                    val fr = blockStack.removeLastOrNull()
                    if (fr != null && fr.kind == "if" && fr.elseRegs != null) {
                        // if/else 合并：栈深不一致时告警；一致时逐槽位生成 phi
                        val elseRegs = vregStack.toList()
                        val thenRegs = fr.elseRegs!!
                        if (elseRegs.size != thenRegs.size || elseRegs.size != fr.entryDepth) {
                            issues.add(
                                StackIssue(
                                    addr, "end",
                                    "if/else 出口栈深不一致（then=${thenRegs.size}, else=${elseRegs.size}, 入口=${fr.entryDepth}）",
                                ),
                            )
                        } else {
                            for (i in fr.entryDepth until elseRegs.size) {
                                val a = thenRegs.getOrNull(i)
                                val e = elseRegs.getOrNull(i)
                                if (a != null && e != null && a != e) {
                                    val phiTarget = freshVreg(typeStack.getOrNull(i) ?: VType.UNKNOWN)
                                    phis.add(PhiNode(phiTarget, listOf(a, e), typeStack.getOrNull(i) ?: VType.UNKNOWN, addr))
                                    // 替换栈槽
                                    val old = vregStack.removeAt(i)
                                    vregStack.add(i, phiTarget)
                                    instrs.add(
                                        SsaInstr(
                                            addr, "phi", phiTarget, listOf(a, e),
                                            typeStack.getOrNull(i) ?: VType.UNKNOWN, "$phiTarget = phi($a, $e)  ;; old $old",
                                        ),
                                    )
                                }
                            }
                        }
                    }
                    // block/loop 的 end：栈深应回到 entry + blocktype 结果（简化校验）
                    if (fr != null && fr.kind in listOf("block", "loop")) {
                        if (vregStack.size < fr.entryDepth) {
                            issues.add(StackIssue(addr, "end", "${fr.kind} 出口栈深（${vregStack.size}）低于入口（${fr.entryDepth}）"))
                        }
                    }
                }
                0x0c -> { // br
                    val (label, l) = readU32(b, pos); pos += l
                    instrs.add(SsaInstr(addr, "br", "—", emptyList(), VType.UNKNOWN, "br $label"))
                }
                0x0d -> { // br_if
                    val (label, l) = readU32(b, pos); pos += l
                    val cond = popV("br_if", addr)
                    instrs.add(
                        SsaInstr(
                            addr, "br_if", "—", listOfNotNull(cond?.second),
                            VType.I32, "br_if $label ${cond?.second ?: "?"}",
                        ),
                    )
                }
                0x0e -> { // br_table
                    val (n, l) = readU32(b, pos); pos += l
                    repeat(n.toInt() + 1) { pos += u32Len(b, pos) }
                    val idxV = popV("br_table", addr)
                    instrs.add(
                        SsaInstr(addr, "br_table", "—", listOfNotNull(idxV?.second), VType.I32, "br_table[$n] ${idxV?.second ?: "?"}"),
                    )
                }
                0x0f -> { // return
                    instrs.add(SsaInstr(addr, "return", "—", vregStack.toList().takeLast(1), VType.UNKNOWN, "return"))
                }
                0x10 -> { // call
                    val (target, l) = readU32(b, pos); pos += l
                    val targetName = callTargetName(parsed, importedFuncs, target.toInt())
                    val calleeSig = calleeSignature(parsed, importedFuncs, target.toInt())
                    // pop 参数个数个值
                    val args = mutableListOf<String>()
                    repeat(calleeSig.first) { popV("call", addr)?.let { args.add(0, it.second) } }
                    val results = mutableListOf<String>()
                    repeat(calleeSig.second) {
                        val r = freshVreg(VType.UNKNOWN)
                        results.add(r)
                        pushV(VType.UNKNOWN, r)
                    }
                    instrs.add(
                        SsaInstr(
                            addr, "call", results.firstOrNull() ?: "—", args,
                            VType.UNKNOWN, (results.firstOrNull()?.plus(" = ") ?: "") + "call $target${if (targetName != null) " ;; $targetName" else ""}(${args.joinToString(", ")})",
                        ),
                    )
                }
                0x11 -> { // call_indirect
                    val (typeIdx, l1) = readU32(b, pos); pos += l1
                    val (tbl, l2) = readU32(b, pos); pos += l2
                    val fnPtr = popV("call_indirect", addr)
                    val typeSig = parsed.types.getOrNull(typeIdx.toInt())
                    val argc = typeSig?.params?.size ?: 0
                    val retc = typeSig?.results?.size ?: 0
                    val args = mutableListOf<String>()
                    repeat(argc) { popV("call_indirect", addr)?.let { args.add(0, it.second) } }
                    val results = mutableListOf<String>()
                    repeat(retc) {
                        val r = freshVreg(VType.UNKNOWN)
                        results.add(r)
                        pushV(VType.UNKNOWN, r)
                    }
                    instrs.add(
                        SsaInstr(
                            addr, "call_indirect", results.firstOrNull() ?: "—",
                            listOfNotNull(fnPtr?.second) + args, VType.UNKNOWN,
                            (results.firstOrNull()?.plus(" = ") ?: "") + "call_indirect [${fnPtr?.second ?: "?"}](${args.joinToString(", ")}) ;; type $typeIdx table $tbl",
                        ),
                    )
                }

                // ---- 变量 ----
                0x20 -> { // local.get
                    val (idx, l) = readU32(b, pos); pos += l
                    val reg = localRead(idx.toInt())
                    pushV(localTypes.getOrNull(idx.toInt()) ?: VType.UNKNOWN, reg)
                    instrs.add(SsaInstr(addr, opName, reg, emptyList(), localTypes.getOrNull(idx.toInt()) ?: VType.UNKNOWN, "$reg = local.get $idx"))
                }
                0x21 -> { // local.set
                    val (idx, l) = readU32(b, pos); pos += l
                    val v = popV(opName, addr)
                    val reg = localWrite(idx.toInt())
                    instrs.add(
                        SsaInstr(
                            addr, opName, reg, listOfNotNull(v?.second),
                            localTypes.getOrNull(idx.toInt()) ?: VType.UNKNOWN,
                            "$reg = ${v?.second ?: "?"}  ;; local.set $idx",
                        ),
                    )
                }
                0x22 -> { // local.tee
                    val (idx, l) = readU32(b, pos); pos += l
                    val reg = localWrite(idx.toInt())
                    instrs.add(
                        SsaInstr(
                            addr, opName, reg, listOf(vregStack.lastOrNull() ?: "?"),
                            localTypes.getOrNull(idx.toInt()) ?: VType.UNKNOWN,
                            "$reg = tee ${vregStack.lastOrNull() ?: "?"}  ;; 值保留在栈",
                        ),
                    )
                }
                0x23 -> { // global.get
                    val (idx, l) = readU32(b, pos); pos += l
                    val reg = freshVreg(VType.UNKNOWN)
                    pushV(VType.UNKNOWN, reg)
                    instrs.add(SsaInstr(addr, opName, reg, emptyList(), VType.UNKNOWN, "$reg = global.get $idx"))
                }
                0x24 -> { // global.set
                    val (idx, l) = readU32(b, pos); pos += l
                    val v = popV(opName, addr)
                    instrs.add(SsaInstr(addr, opName, "g$idx", listOfNotNull(v?.second), VType.UNKNOWN, "g$idx = ${v?.second ?: "?"}"))
                }

                // ---- 常量 ----
                0x41 -> {
                    val (v, l) = readS32(b, pos); pos += l
                    val reg = freshVreg(VType.I32)
                    pushV(VType.I32, reg)
                    instrs.add(SsaInstr(addr, opName, reg, emptyList(), VType.I32, "$reg = $v"))
                }
                0x42 -> {
                    val (v, l) = readS64(b, pos); pos += l
                    val reg = freshVreg(VType.I64)
                    pushV(VType.I64, reg)
                    instrs.add(SsaInstr(addr, opName, reg, emptyList(), VType.I64, "$reg = ${v}L"))
                }
                0x43 -> {
                    val bits = readLeInt(b, pos); pos += 4
                    val reg = freshVreg(VType.F32)
                    pushV(VType.F32, reg)
                    instrs.add(SsaInstr(addr, opName, reg, emptyList(), VType.F32, "$reg = ${java.lang.Float.intBitsToFloat(bits)}"))
                }
                0x44 -> {
                    val bits = readLeLong(b, pos); pos += 8
                    val reg = freshVreg(VType.F64)
                    pushV(VType.F64, reg)
                    instrs.add(SsaInstr(addr, opName, reg, emptyList(), VType.F64, "$reg = ${java.lang.Double.longBitsToDouble(bits)}"))
                }

                // ---- 类型化通用指令 ----
                else -> {
                    val s = typeSigs[op]
                    if (s != null) {
                        // 跳过 immediate（memarg 等）
                        when (op) {
                            in 0x28..0x3e -> { pos += u32Len(b, pos); pos += u32Len(b, pos) }
                            0x3f, 0x40 -> pos += u32Len(b, pos)
                            0x1a -> { /* drop */ }
                            0x1b -> { /* select */ }
                            0x1c -> { val (n, l) = readU32(b, pos); pos += l + n.toInt() }
                        }
                        // drop：弹出
                        if (op == 0x1a) {
                            val v = popV(opName, addr)
                            instrs.add(SsaInstr(addr, "drop", "—", listOfNotNull(v?.second), VType.UNKNOWN, "drop ${v?.second ?: "?"}"))
                        } else {
                            val inputs = mutableListOf<String>()
                            var mismatch = false
                            for (expected in s.pops.asReversed()) {
                                val got = popV(opName, addr) ?: break
                                inputs.add(0, got.second)
                                if (expected != VType.UNKNOWN && got.first != VType.UNKNOWN &&
                                    expected != got.first && !(expected == VType.I64 && got.first == VType.I32)
                                ) {
                                    mismatch = true
                                }
                            }
                            if (mismatch) {
                                issues.add(StackIssue(addr, opName, "类型不匹配：期望 ${s.pops} 实得不符——疑似失步"))
                            }
                            val results = mutableListOf<String>()
                            for (t in s.pushes) {
                                val reg = freshVreg(t)
                                results.add(reg)
                                pushV(t, reg)
                            }
                            val rhs = when (results.size) {
                                0 -> opName + inputs.joinToString(", ", "(", ")")
                                1 -> "${results[0]} = ${opName}(${inputs.joinToString(", ")})"
                                else -> "(${results.joinToString(", ")}) = ${opName}(${inputs.joinToString(", ")})"
                            }
                            instrs.add(
                                SsaInstr(addr, opName, results.firstOrNull() ?: "—", inputs, s.pushes.firstOrNull() ?: VType.UNKNOWN, rhs),
                            )
                        }
                    } else {
                        // 未知指令（含 SIMD/GC/Atomics 前缀）：跳过子操作码并告警
                        pos = skipUnknown(b, pos, bodyEnd, op)
                        issues.add(StackIssue(addr, "0x${op.toString(16)}", "未建模指令（SIMD/前缀类），类型栈在该点可能失真"))
                        opName = "unknown_0x${op.toString(16)}"
                    }
                }
            }
        }
        if (pos < bodyEnd) truncated = true

        // 函数结束：残留栈应等于返回类型
        val leftover = typeStack.toList()

        val listing = renderListing(instrs, phis, name, sig, truncated, issues, leftover)
        return SsaResult(
            ok = true,
            funcName = name,
            funcIndex = funcIndex,
            signature = (if (sig.params.isEmpty()) "" else "(param ${sig.params.joinToString(" ")}) ") +
                (if (sig.results.isEmpty()) "" else "(result ${sig.results.joinToString(" ")})").trim(),
            instructions = instrs,
            phis = phis,
            issues = issues,
            typeStackFinal = leftover,
            listing = listing,
            vregCount = vregSeq,
            localVersions = localTypes.indices.take(localVersion.size)
                .associateWith { localVersion[it] }.filterValues { it > 0 },
        )
    }

    // ---------------- 辅助 ----------------

    private fun valTypeName(s: String): VType = when (s) {
        "i32" -> VType.I32; "i64" -> VType.I64; "f32" -> VType.F32; "f64" -> VType.F64
        "v128" -> VType.V128; "funcref" -> VType.FUNCREF; "externref" -> VType.EXTERNREF
        else -> VType.UNKNOWN
    }

    private fun callTargetName(parsed: WasmParser.ParsedWasm, importedFuncs: Int, target: Int): String? =
        parsed.functionNames[target]
            ?: parsed.exports.firstOrNull { it.kind == "func" && it.index == target }?.name
            ?: parsed.imports.filter { it.kind == "func" }.getOrNull(target)?.let { "${it.module}.${it.name}" }

    /** 被调函数 (参数个数, 返回个数) */
    private fun calleeSignature(parsed: WasmParser.ParsedWasm, importedFuncs: Int, target: Int): Pair<Int, Int> {
        val imported = parsed.imports.filter { it.kind == "func" }
        if (target < imported.size) {
            val t = parsed.types.getOrNull(imported[target].typeIndex)
            return (t?.params?.size ?: 0) to (t?.results?.size ?: 0)
        }
        val t = parsed.localFunctions.getOrNull(target - importedFuncs)
        return (t?.params?.size ?: 0) to (t?.results?.size ?: 0)
    }

    private fun blockTypeLen(b: ByteArray, from: Int): Int {
        val v = b[from].toInt() and 0xff
        return if (v == 0x40 || v == 0x7f || v == 0x7e || v == 0x7d || v == 0x7c || v == 0x7b ||
            v == 0x70 || v == 0x6f
        ) 1
        else u32Len(b, from)
    }

    /** 未知指令（前缀类）跳过：尽力同步 */
    private fun skipUnknown(b: ByteArray, pos: Int, bodyEnd: Int, op: Int): Int {
        var p = pos
        when (op) {
            0xfb -> { p += u32Len(b, p); p += u32Len(b, p) }                       // GC
            0xfc -> {                                                              // bulk memory
                val (sub, sb) = readU32(b, p); p += sb
                when (sub.toInt()) {
                    8, 9, 11, 13, 15 -> p += u32Len(b, p)
                    10, 12, 14 -> { p += u32Len(b, p); p += u32Len(b, p) }
                    else -> { /* sat trunc 无 immediate */ }
                }
            }
            0xfd -> {                                                              // SIMD
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
            0xfe -> { p += u32Len(b, p); p += u32Len(b, p) }                       // Atomics memarg
            0xd0 -> p += 1
            else -> { /* 无 immediate */ }
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

    private fun renderListing(
        instrs: List<SsaInstr>,
        phis: List<PhiNode>,
        name: String,
        sig: WasmParser.FuncType,
        truncated: Boolean,
        issues: List<StackIssue>,
        leftover: List<VType>,
    ): String {
        val sb = StringBuilder()
        sb.appendLine(";; SSA 形式（Stack-SSA + Phi）func $name ${if (sig.params.isNotEmpty()) "(param ${sig.params.joinToString(" ")}) " else ""}${if (sig.results.isNotEmpty()) "(result ${sig.results.joinToString(" ")})" else ""}")
        sb.appendLine(";; v{n}=栈虚拟寄存器  l{i}.{v}=local 版本  phi=控制流合并")
        instrs.take(1500).forEach { i ->
            val typeTag = if (i.type != VType.UNKNOWN) "  ; ${i.type.display}" else ""
            sb.appendLine("  %04x  ${i.raw}${if (i.raw.length < 60) typeTag.take(12) else ""}".trimEnd())
        }
        if (truncated) sb.appendLine(";; ...（超出 maxInstr 截断）")
        if (phis.isNotEmpty()) {
            sb.appendLine()
            sb.appendLine(";; Phi 节点（控制流合并点）：")
            phis.forEach { sb.appendLine("  @${it.addr.toString(16)}  ${it.target} = phi(${it.sources.joinToString(", ")}) : ${it.type.display}") }
        }
        if (leftover.isNotEmpty()) {
            sb.appendLine()
            sb.appendLine(";; 函数结束残留类型栈: ${leftover.joinToString(" ") { it.display }}（应等于 result 类型）")
        }
        if (issues.isNotEmpty()) {
            sb.appendLine()
            sb.appendLine(";; 栈校验问题（${issues.size}）：")
            issues.take(20).forEach { sb.appendLine("  @${it.addr.toString(16)} ${it.op}: ${it.message}") }
        }
        return sb.toString()
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

    private fun readLeInt(b: ByteArray, from: Int): Int {
        var v = 0
        for (i in 0 until 4) v = v or ((b[from + i].toInt() and 0xff) shl (8 * i))
        return v
    }

    private fun readLeLong(b: ByteArray, from: Int): Long {
        var v = 0L
        for (i in 0 until 8) v = v or ((b[from + i].toLong() and 0xff) shl (8 * i))
        return v
    }

    private fun u32Len(b: ByteArray, from: Int): Int = readU32(b, from).second
}
