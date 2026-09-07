package com.webreverse.mcp.javascript.analysis

/**
 * WASM 结构化反编译器（ 新增）。
 *
 * 与 [WasmDisassembler]（逐条 wat 直译）互补：本类把线性 opcode 流还原为
 * **结构化高级伪代码**（控制流树 + 表达式树折叠），主体能力：
 *
 *  - 控制流：if/else/end 分支、block/loop 嵌套、br/br_if/br_table 跳转（转译成
 *    `goto L` / `if (c) goto L` / `switch`），并自动编号块标签。
 *  - 局部变量：解析 locals 声明，输出 `local i : type` 定义；
 *    `local.set/tee` 折叠为赋值语句，`local.get` 折叠为表达式操作数。
 *  - 表达式树：维护虚拟操作数栈，把 const / local.get / 二元运算 / 一元运算 /
 *    比较 / 内存 load / call 结果逐层折叠为嵌套字符串表达式。
 *  - 内存操作：load 折叠为 `mem[addr]`，store 输出 `mem[addr] = value;`。
 *  - 调用：call/call_indirect 输出朗读者友好文本并解析函数索引为符号名。
 *  - 字符串常量关联：i32.const 指向 data 段时自动注解 `; "str"`（复用 [WasmParser]）。
 *
 * 输出为结构化伪代码树 [Node]，并提供 [StructuredWasmDecompiler.toReadableText] /
 * [DecompResult.toReadableText] 返回可读字符串。
 *
 * 纯 Kotlin、零第三方依赖，类名/包名与本目录一致，编译自洽。
 */
class StructuredWasmDecompiler {

    /** 结构化伪代码节点 */
    sealed class Node {
        /** 叶子语句行 */
        data class Line(val text: String) : Node()

        /** if/else 分支 */
        data class If(val cond: String, val thenBody: List<Node>, val elseBody: List<Node>) : Node()

        /** block / loop 嵌套块（[kind] 为 "block"/"loop"，[label] 为自动编号） */
        data class Block(val label: String, val kind: String, val body: List<Node>) : Node()

        fun toText(prefix: String = "  "): String = when (this) {
            is Line -> prefix + text
            is If -> {
                val sb = StringBuilder()
                sb.append(prefix).append("if (").append(cond).appendLine(") {")
                thenBody.forEach { sb.appendLine(it.toText(prefix + "  ")) }
                if (elseBody.isNotEmpty()) {
                    sb.append(prefix).appendLine("} else {")
                    elseBody.forEach { sb.appendLine(it.toText(prefix + "  ")) }
                }
                sb.append(prefix).appendLine("}")
                sb.toString().trimEnd()
            }
            is Block -> {
                val sb = StringBuilder()
                if (kind == "loop") sb.append(prefix).append(label).append(": while (true) {").appendLine()
                else sb.append(prefix).append("block ").append(label).appendLine(" {")
                body.forEach { sb.appendLine(it.toText(prefix + "  ")) }
                sb.append(prefix).appendLine("}")
                sb.toString().trimEnd()
            }
        }
    }

    /** 反编译结果 */
    data class DecompResult(
        val ok: Boolean,
        val error: String = "",
        val funcName: String = "",
        val funcIndex: Int = -1,
        val signature: String = "",
        val locals: Int = 0,
        val instructionCount: Int = 0,
        val rootNode: Node? = null,
        val text: String = "",
    ) {
        /** 结构化伪代码可读字符串 */
        fun toReadableText(): String = text
    }

    /** 控制流容器（block/loop/if），用于在解码时动态积累子节点 */
    private class Cont(
        var kind: String, // block/loop/if
        var cond: String,
        val label: String,
        var elseOn: Boolean,
    ) {
        val thenBody = mutableListOf<Node>()
        val elseBody = mutableListOf<Node>()
    }

    private val wasmParser = WasmParser()

    /** 最近一次反编译结果的文本（供外部便捷读取） */
    @Volatile
    private var lastText: String = ""

    /** 便捷入口：按导出名反编译 */
    fun decompileExport(bytes: ByteArray, exportName: String): DecompResult {
        val parsed = wasmParser.parse(bytes)
        if (!parsed.ok) return DecompResult(false, parsed.error)
        val exp = parsed.exports.firstOrNull { it.kind == "func" && it.name == exportName }
            ?: return DecompResult(false, "导出 '$exportName' 不存在", funcName = exportName)
        return decompile(bytes, exp.index)
    }

    /** 主入口：按函数索引反编译 */
    fun decompile(bytes: ByteArray, funcIndex: Int): DecompResult {
        val parsed = wasmParser.parse(bytes)
        if (!parsed.ok) return DecompResult(false, parsed.error)
        val importedFuncs = parsed.imports.count { it.kind == "func" }
        if (funcIndex < importedFuncs) {
            val imp = parsed.imports.filter { it.kind == "func" }.getOrNull(funcIndex)
            return DecompResult(false, "索引 $funcIndex 是导入函数（${imp?.module ?: "?"}.${imp?.name ?: "?"}），无本地函数体")
        }
        val localIdx = funcIndex - importedFuncs
        val sig = parsed.localFunctions.getOrNull(localIdx)
            ?: return DecompResult(false, "函数索引 $funcIndex 超出范围（本地函数 ${parsed.localFunctions.size} 个）")

        val displayName = parsed.functionNames[funcIndex]
            ?: parsed.exports.firstOrNull { it.kind == "func" && it.index == funcIndex }?.name
            ?: "f$funcIndex"

        val body = findBody(bytes, localIdx)
            ?: return DecompResult(false, "未找到函数体（code section 解析失败）")

        // 构建函数索引 -> (paramCount, resultCount) 映射，用于 call 参数解析
        val funcTypes = HashMap<Int, Pair<Int, Int>>()
        parsed.imports.filter { it.kind == "func" }.forEachIndexed { i, imp ->
            val t = parsed.types.getOrNull(imp.typeIndex)
            funcTypes[i] = (t?.params?.size ?: 0) to (t?.results?.size ?: 0)
        }
        parsed.localFunctions.forEachIndexed { i, t ->
            funcTypes[importedFuncs + i] = t.params.size to t.results.size
        }

        val res = buildPseudo(
            bytes, body, parsed, funcIndex, importedFuncs, funcTypes, displayName, sig,
        )
        lastText = res.text
        return res.copy(text = res.text)
    }

    /** 返回最近一次反编译的可读字符串（便捷方法） */
    fun toReadableText(): String = lastText

    // ---------------- 结构构建 ----------------

    private class Cursor(private val b: ByteArray) {
        var pos = 0
        fun u8(): Int {
            if (pos >= b.size) throw IllegalStateException("EOF")
            return b[pos++].toInt() and 0xff
        }
        fun u32(): Long {
            var result = 0L
            var shift = 0
            while (true) {
                val byte = u8()
                result = result or ((byte and 0x7f).toLong() shl shift)
                if (byte and 0x80 == 0) break
                shift += 7
                if (shift > 35) throw IllegalStateException("LEB 溢出")
            }
            return result
        }
        fun s32(): Long {
            var result = 0L
            var shift = 0
            var byte = 0
            do {
                byte = u8()
                result = result or ((byte and 0x7f).toLong() shl shift)
                shift += 7
            } while (byte and 0x80 != 0 && shift < 38)
            if (shift < 64 && byte and 0x40 != 0) result = result or (-1L shl shift)
            return result
        }
        fun s64(): Long = s32()
        fun fixed(n: Int) { pos += n }
    }

    /** code section 中定位本地函数体 */
    private data class BodyRange(val from: Int, val to: Int)

    private fun findBody(bytes: ByteArray, localIdx: Int): BodyRange? {
        var pos = 8
        var idx = 0
        while (pos < bytes.size) {
            val secId = bytes[pos].toInt() and 0xff
            pos++
            val c = Cursor(bytes)
            c.pos = pos
            val size = c.u32()
            pos = c.pos
            val end = pos + size.toInt()
            if (end > bytes.size) return null
            if (secId == 10) {
                val c2 = Cursor(bytes)
                c2.pos = pos
                val n = c2.u32()
                pos = c2.pos
                repeat(n.toInt()) {
                    val c3 = Cursor(bytes)
                    c3.pos = pos
                    val bodySize = c3.u32()
                    val bodyStart = c3.pos
                    val bodyEnd = bodyStart + bodySize.toInt()
                    if (idx == localIdx) return BodyRange(bodyStart, bodyEnd)
                    pos = bodyEnd
                    idx++
                }
                return null
            }
            pos = end
        }
        return null
    }

    /** 结构化伪代码构建主体 */
    private fun buildPseudo(
        bytes: ByteArray,
        body: BodyRange,
        parsed: WasmParser.ParsedWasm,
        funcIndex: Int,
        importedFuncs: Int,
        funcTypes: Map<Int, Pair<Int, Int>>,
        displayName: String,
        sig: WasmParser.FuncType,
    ): DecompResult {
        val sb = StringBuilder()
        sb.appendLine("func[$funcIndex] $displayName ${sigS(sig)}")
        var pos = body.from
        val bodyEnd = body.to
        val c = Cursor(bytes)
        c.pos = pos

        // ---- locals 声明 ----
        val localLines = mutableListOf<String>()
        var totalLocals = 0
        try {
            val groups = c.u32()
            repeat(groups.toInt()) {
                val cnt = c.u32().toInt()
                val vt = c.u8()
                val tname = valType(vt)
                repeat(cnt) { localLines.add("local ${totalLocals + it} : $tname") }
                totalLocals += cnt
            }
        } catch (e: Exception) {
            // locals 解析失败，继续
        }
        if (totalLocals > 0) {
            sb.appendLine("// 局部变量")
            localLines.forEach { sb.appendLine("  $it;") }
        }

        // ---- 控制流/表达式折叠 ----
        val root = mutableListOf<Node>()
        val stack = ArrayDeque<String>()
        var labelCounter = 0

        val containers = ArrayDeque<Cont>()
        fun currentBody(): MutableList<Node> {
            val top = containers.lastOrNull() ?: return root
            return if (top.kind == "if" && top.elseOn) top.elseBody else top.thenBody
        }
        fun pushLine(text: String) { currentBody().add(Node.Line(text)) }
        fun popOperand(): String = if (stack.isNotEmpty()) stack.removeLast() else "?"
        // 把堆积的操作数作为语句冲刷，避免丢失（如无消费者的 call/const）
        fun flushOperands() {
            val items = mutableListOf<String>()
            while (stack.isNotEmpty()) items.add(stack.removeLast())
            if (items.isNotEmpty()) items.reversed().forEach { pushLine("~ $it;") }
        }
        fun labelFor(code: Int): String {
            // 相对深度 label：从容器栈顶往上数 N 层
            val name = "L_${code}"
            return name
        }

        val localIds = (0 until totalLocals).map { "local$it" }

        var instrCount = 0
        try {
            while (c.pos < bodyEnd) {
                val op = c.u8()
                instrCount++
                when (op) {
                    // ---------- 控制流 ----------
                    0x02, 0x03 -> { // block / loop
                        blockType(c)
                        labelCounter++
                        val kind = if (op == 0x03) "loop" else "block"
                        containers.addLast(Cont(kind, "", "$kind$labelCounter", false))
                        // 进入 loop / block 前冲刷跨块遗留操作数
                        flushOperands()
                    }
                    0x04 -> { // if
                        blockType(c)
                        labelCounter++
                        val cond = popOperand()
                        containers.addLast(Cont("if", cond, "if$labelCounter", false))
                        flushOperands()
                    }
                    0x05 -> { // else
                        val top = containers.lastOrNull()
                        if (top == null) { pushLine("else;") }
                        else if (top.kind == "if") top.elseOn = true
                        else pushLine("else;")
                        flushOperands()
                    }
                    0x0b -> { // end
                        val top = containers.removeLastOrNull()
                        if (top == null) { pushLine("end;") }
                        else {
                            val node: Node = if (top.kind == "if") {
                                Node.If(top.cond.trim(), top.thenBody, top.elseBody)
                            } else {
                                Node.Block(top.label, top.kind, top.thenBody)
                            }
                            (containers.lastOrNull()?.let { if (it.kind == "if" && it.elseOn) it.elseBody else it.thenBody }
                                ?: root).add(node)
                        }
                        flushOperands()
                    }
                    0x0c -> { // br depth
                        val depth = c.u32().toInt()
                        pushLine("goto ${labelFor(depth)};")
                    }
                    0x0d -> { // br_if depth
                        val depth = c.u32().toInt()
                        val cond = popOperand()
                        pushLine("if ($cond) goto ${labelFor(depth)};")
                    }
                    0x0e -> { // br_table
                        val n = c.u32().toInt()
                        val targets = mutableListOf<Long>()
                        repeat(n + 1) { targets.add(c.u32()) }
                        val idx = popOperand()
                        pushLine("switch ($idx) { /* br_table targets: ${targets.joinToString()} */ }")
                    }
                    0x0f -> { // return
                        val ret = if (stack.isNotEmpty()) popOperand() else null
                        pushLine(if (ret != null) "return $ret;" else "return;")
                    }
                    0x10 -> { // call
                        val idx = c.u32().toInt()
                        val n = funcTypes[idx]?.first ?: minOf(3, stack.size)
                        val args = ArrayList<String>()
                        repeat(n) { args.add(popOperand()) }
                        val callName = nameHints(parsed, funcIndex, idx)
                        val rendered = "$callName(${args.reversed().joinToString(", ")})"
                        // 若函数有返回值则入栈，否则作为语句
                        val results = funcTypes[idx]?.second ?: 0
                        if (results > 0) stack.addLast(rendered)
                        else pushLine("$rendered;")
                    }
                    0x11 -> { // call_indirect
                        c.u32(); c.u32() // type + table
                        val idx = popOperand()
                        pushLine("call_indirect($idx /* table */);")
                    }
                    0x1a -> { popOperand(); }          // drop
                    0x1b -> { // select: pop cond, then false, true -> push(cond?t:f)
                        val cond = popOperand(); val f = popOperand(); val t = popOperand()
                        stack.addLast("($cond ? $t : $f)")
                    }
                    0x1c -> { // select_t
                        val nv = c.u32().toInt(); repeat(nv) { c.u8() }
                        val cond = popOperand(); val f = popOperand(); val t = popOperand()
                        stack.addLast("($cond ? $t : $f)")
                    }
                    // ---------- 局部/全局变量 ----------
                    0x20 -> { val i = c.u32().toInt(); stack.addLast(localName(i, localIds)) } // local.get
                    0x21 -> { val i = c.u32().toInt(); val v = popOperand(); pushLine("${localName(i, localIds)} = $v;") } // local.set
                    0x22 -> { val i = c.u32().toInt(); val v = popOperand(); pushLine("${localName(i, localIds)} = $v;"); stack.addLast(v) } // local.tee
                    0x23 -> { val i = c.u32().toInt(); stack.addLast("global$i") }
                    0x24 -> { val i = c.u32().toInt(); val v = popOperand(); pushLine("global$i = $v;") }
                    0x25 -> { val i = c.u32().toInt(); stack.addLast("table[$i]") }
                    0x26 -> { val i = c.u32().toInt(); val v = popOperand(); pushLine("table[$i] = $v;") }
                    0xd2 -> { val i = c.u32().toInt(); stack.addLast("funcref$i") }
                    // ---------- 内存 load ----------
                    in 0x28..0x35 -> {
                        memArg(c)
                        val addr = popOperand()
                        stack.addLast("mem[$addr${memLoadNote(op)}]")
                    }
                    // ---------- 内存 store ----------
                    in 0x36..0x3e -> {
                        memArg(c)
                        val value = popOperand(); val addr = popOperand()
                        pushLine("mem[$addr]${memStoreNote(op)} = $value;")
                    }
                    0x3f -> { c.u32(); stack.addLast("memory.size") }
                    0x40 -> { c.u32(); val k = popOperand(); stack.addLast("memory.grow($k)") }
                    // ---------- 常量 ----------
                    0x41 -> { // i32.const
                        val v = c.s32()
                        val strAnnot = if (v >= 0) readString(bytes, parsed, v) else null
                        stack.addLast("$v${strAnnot ?: ""}")
                    }
                    0x42 -> { val v = c.s64(); stack.addLast("${v}L") }
                    0x43 -> { val bits = readLeInt(bytes, c.pos); c.fixed(4); stack.addLast(java.lang.Float.intBitsToFloat(bits).toString()) }
                    0x44 -> { val bits = readLeLong(bytes, c.pos); c.fixed(8); stack.addLast(java.lang.Double.longBitsToDouble(bits).toString()) }
                    0xd0 -> { blockType(c); stack.addLast("null") }
                    0xd1 -> { val v = popOperand(); stack.addLast("($v == null)") }
                    // ---------- 一元/比较/二元运算（表达式折叠） ----------
                    else -> {
                        if (!foldDynOp(op, stack, ::pushLine)) {
                            // 未知 opcode：透传为语句（含 ref 等）
                            pushLine("${opName(op)};")
                        }
                    }
                }
            }
        } catch (e: Exception) {
            // 截断解码：异常处停止，保留已构建结构
        }

        // 关闭所有未闭合容器
        while (containers.isNotEmpty()) {
            val top = containers.removeLast()
            if (top.kind == "if") root.add(Node.If(top.cond.trim(), top.thenBody, top.elseBody))
            else root.add(Node.Block(top.label, top.kind, top.thenBody))
        }
        flushOperands()

        // 输出根节点列表文本
        root.forEach { n ->
            n.toText().lines().forEach { sb.appendLine("  $it") }
        }
        sb.appendLine("// end func[$funcIndex]  instructions=$instrCount")

        val text = sb.toString().trimEnd()
        return DecompResult(
            ok = true,
            funcName = displayName,
            funcIndex = funcIndex,
            signature = sigS(sig),
            locals = totalLocals,
            instructionCount = instrCount,
            rootNode = if (root.isEmpty()) null else root.last(),
            text = text,
        )
    }

    // ---------------- 表达式折叠辅助 ----------------

    /** 返回 true 表示已被折叠处理（一元/比较/二元数值运算） */
    private fun foldDynOp(op: Int, stack: ArrayDeque<String>, pushLine: (String) -> Unit): Boolean {
        binOps[op]?.let { symbol ->
            val r = if (stack.isNotEmpty()) stack.removeLast() else "?"
            val l = if (stack.isNotEmpty()) stack.removeLast() else "?"
            stack.addLast("($l $symbol $r)")
            return true
        }
        cmpOps[op]?.let { symbol ->
            val r = if (stack.isNotEmpty()) stack.removeLast() else "?"
            val l = if (stack.isNotEmpty()) stack.removeLast() else "?"
            stack.addLast("($l $symbol $r)")
            return true
        }
        unaryOps[op]?.let { fn ->
            val x = if (stack.isNotEmpty()) stack.removeLast() else "?"
            if (fn == "==0") stack.addLast("($x == 0)")
            else stack.addLast("$fn($x)")
            return true
        }
        return false
    }

    private fun localName(i: Int, ids: List<String>): String = ids.getOrNull(i) ?: "local$i"

    /** 函数索引 -> 可读名 */
    private fun nameHints(parsed: WasmParser.ParsedWasm, ctxFuncIndex: Int, idx: Int): String {
        parsed.functionNames[idx]?.let { return it }
        val imp = parsed.imports.filter { it.kind == "func" }
        if (idx < imp.size) return "${imp[idx].module}.${imp[idx].name}"
        parsed.exports.firstOrNull { it.kind == "func" && it.index == idx }?.let { return it.name }
        return "fn$idx"
    }

    private fun memArg(c: Cursor) { c.u32(); c.u32() }
    private fun blockType(c: Cursor) {
        val v = c.u8()
        if (v == 0x40 || v == 0x7f || v == 0x7e || v == 0x7d || v == 0x7c || v == 0x70 || v == 0x6f || v == 0x6b) return
        // 多字节 s33 typeidx
        while (true) { val b = c.u8(); if (b and 0x80 == 0) break }
    }

    private fun sigS(t: WasmParser.FuncType): String =
        (if (t.params.isEmpty()) "" else "(param ${t.params.joinToString(" ")}) ") +
            (if (t.results.isEmpty()) "" else "(result ${t.results.joinToString(" ")})").trim()

    private fun valType(v: Int): String = when (v) {
        0x7f -> "i32"; 0x7e -> "i64"; 0x7d -> "f32"; 0x7c -> "f64"; 0x7b -> "v128"
        0x70 -> "funcref"; 0x6f -> "externref"; else -> "t0x${v.toString(16)}"
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

    /** i32.const 指向 data 段时的字符串注解 */
    private fun readString(bytes: ByteArray, parsed: WasmParser.ParsedWasm, vaddr: Long): String? {
        val s = try { wasmParser.readStringAtVaddr(bytes, parsed, vaddr, 80) } catch (e: Exception) { null } ?: return null
        if (s.length < 1) return null
        val esc = s.replace("\"", "\\\"").take(48)
        return " ;; \"$esc\""
    }

    private fun memLoadNote(op: Int): String = when (op) {
        0x29 -> " i64"; 0x2a -> " f32"; 0x2b -> " f64"; 0x2c -> " i8_s"; 0x2d -> " u8"
        0x2e -> " i16_s"; 0x2f -> " u16"; 0x30 -> " i64.8s"; 0x31 -> " u8"; 0x32 -> " i16s"
        0x33 -> " u16"; 0x34 -> " i32_s"; 0x35 -> " u32"; else -> ""
    }
    private fun memStoreNote(op: Int): String = when (op) {
        0x37 -> " i64"; 0x38 -> " f32"; 0x39 -> " f64"; 0x3a -> " u8"; 0x3b -> " u16"
        0x3c -> " u8"; 0x3d -> " u16"; 0x3e -> " u32"; else -> ""
    }

    private fun opName(op: Int): String = when (op) {
        0x00 -> "unreachable"; 0x01 -> "nop"
        else -> "op_0x${op.toString(16)}"
    }

    // ---------------- 运算表 ----------------

    private val binOps: Map<Int, String> = mapOf(
        0x6a to "+", 0x6b to "-", 0x6c to "*", 0x6d to "/(s)", 0x6e to "/(u)", 0x6f to "%(s)", 0x70 to "%(u)",
        0x71 to "&", 0x72 to "|", 0x73 to "^", 0x74 to "<<", 0x75 to ">>(s)", 0x76 to ">>(u)",
        0x7c to "+", 0x7d to "-", 0x7e to "*", 0x7f to "/(s)", 0x80 to "/(u)", 0x81 to "%(s)", 0x82 to "%(u)",
        0x83 to "&", 0x84 to "|", 0x85 to "^", 0x86 to "<<", 0x87 to ">>(s)", 0x88 to ">>(u)",
        0x92 to "+", 0x93 to "-", 0x94 to "*", 0x95 to "/", 0x9a to "neg", 0x9f to "sqrt",
        0xa0 to "+", 0xa1 to "-", 0xa2 to "*", 0xa3 to "/",
    )

    private val cmpOps: Map<Int, String> = mapOf(
        0x46 to "==", 0x47 to "!=", 0x48 to "<(s)", 0x49 to "<(u)", 0x4a to ">(s)", 0x4b to ">(u)",
        0x4c to "<=(s)", 0x4d to "<=(u)", 0x4e to ">=(s)", 0x4f to ">=(u)",
        0x51 to "==", 0x52 to "!=", 0x53 to "<(s)", 0x54 to "<(u)", 0x55 to ">(s)", 0x56 to ">(u)",
        0x57 to "<=(s)", 0x58 to "<=(u)", 0x59 to ">=(s)", 0x5a to ">=(u)",
        0x5b to "==(f)", 0x5c to "!=(f)", 0x5d to "<(f)", 0x5e to ">(f)",
        0x61 to "==(f)", 0x62 to "!=(f)", 0x63 to "<(f)", 0x64 to ">(f)",
    )

    private val unaryOps: Map<Int, String> = mapOf(
        0x45 to "==0", 0x50 to "==0",
        0x67 to "clz", 0x68 to "ctz", 0x69 to "popcnt",
        0x79 to "clz", 0x7a to "ctz", 0x7b to "popcnt",
        0x8b to "abs", 0x8c to "neg", 0x8d to "ceil", 0x8e to "floor", 0x8f to "trunc",
        0x90 to "nearest", 0x91 to "sqrt",
        0x99 to "abs", 0x9b to "ceil", 0x9c to "floor", 0x9d to "trunc", 0x9e to "nearest",
        0xa7 to "i32.wrap_i64", 0xac to "i64.extend_i32_s", 0xad to "i64.extend_i32_u",
        0xbc to "i32.reinterpret_f32", 0xbe to "f32.reinterpret_i32",
    )
}