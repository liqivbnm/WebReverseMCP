package com.webreverse.mcp.javascript.analysis

/**
 * WASM 反汇编器 v1（ 新增）。
 *
 * WasmAnalyzer 只给画像（调用图/字符串/加密评分），本类补上「看指令」的最后一层：
 * 把指定函数体解码为 wat 风格伪代码（纯 Kotlin，无 wabt 依赖）：
 *
 * - 全量标准 opcode 名称表（control/variable/memory/numeric/conversion/ref）
 * - immediate 解码：LEB 有符号/无符号、memarg、br_table 向量、块类型
 * - 结构缩进：block/loop/if 进入一层，end/else 退出一层
 * - 符号注释：call N 解析为导入名/name section 名/$fN
 *
 * 配合 exportProfiles 的 cryptoScore 排序，先挑热点函数再反汇编，
 * 逆向 WASM 加密函数的标准工作流。
 */
class WasmDisassembler {

    data class DisasmResult(
        val ok: Boolean,
        val error: String = "",
        val funcName: String = "",
        val funcIndex: Int = -1,
        val signature: String = "",
        val localsCount: Int = 0,
        val instructionCount: Int = 0,
        val listing: String = "",
        val truncated: Boolean = false,
    )

    private val parser = WasmParser()

    // ---------------- 入口 ----------------

    /** 按导出名反汇编 */
    fun disassembleExport(bytes: ByteArray, exportName: String, maxInstructions: Int = 800): DisasmResult {
        val parsed = parser.parse(bytes)
        if (!parsed.ok) return DisasmResult(false, parsed.error)
        val exp = parsed.exports.firstOrNull { it.kind == "func" && it.name == exportName }
            ?: return DisasmResult(
                false, "导出 '$exportName' 不存在",
                funcName = exportName,
            )
        return disassemble(bytes, exp.index, maxInstructions)
    }

    /** 按函数索引反汇编（含导入函数计数偏移） */
    fun disassemble(bytes: ByteArray, funcIndex: Int, maxInstructions: Int = 800): DisasmResult {
        val parsed = parser.parse(bytes)
        if (!parsed.ok) return DisasmResult(false, parsed.error)
        val importedFuncs = parsed.imports.count { it.kind == "func" }
        if (funcIndex < importedFuncs) {
            val imp = parsed.imports.filter { it.kind == "func" }.getOrNull(funcIndex)
            return DisasmResult(false, "索引 $funcIndex 是导入函数（${imp?.module ?: "?"}.${imp?.name ?: "?"}），无本地函数体")
        }
        val localIdx = funcIndex - importedFuncs
        val sig = parsed.localFunctions.getOrNull(localIdx)
            ?: return DisasmResult(false, "函数索引 $funcIndex 超出范围（本地函数 ${parsed.localFunctions.size} 个）")

        val body = findBody(bytes, localIdx)
            ?: return DisasmResult(false, "未找到函数体（code section 解析失败）")

        val displayName = parsed.functionNames[funcIndex] ?: parsed.exports
            .firstOrNull { it.kind == "func" && it.index == funcIndex }?.name ?: "f$funcIndex"

        val nameHints = buildNameHints(parsed, importedFuncs)

        val (listing, count, truncated) = renderBody(
            bytes, body, sig, displayName, funcIndex, nameHints, maxInstructions, parsed,
        )
        return DisasmResult(
            ok = true,
            funcName = displayName,
            funcIndex = funcIndex,
            signature = sigString(sig),
            localsCount = count.second,
            instructionCount = count.first,
            listing = listing,
            truncated = truncated,
        )
    }

    // ---------------- 元数据 ----------------

    private fun sigString(t: WasmParser.FuncType): String =
        (if (t.params.isEmpty()) "" else "(param ${t.params.joinToString(" ")}) ") +
            (if (t.results.isEmpty()) "" else "(result ${t.results.joinToString(" ")})").trim()

    /** wasm-bindgen 导入函数的语义注解（逆向时快速理解调用意图） */
    private fun wasmBindgenSemantic(importFullName: String): String? {
        // importFullName 格式如 "wbg.__wbg_document_d249400bd7bd996d"
        val name = importFullName.substringAfter('.')
        return when {
            name == "__wbindgen_malloc" -> "[内存分配] malloc(len) → ptr"
            name == "__wbindgen_free" -> "[内存释放] free(ptr, len)"
            name == "__wbindgen_realloc" -> "[内存重分配] realloc(ptr, old, new) → ptr"
            name == "__wbindgen_string_new" -> "[创建JS字符串] (ptr, len) → JSValue ref"
            name == "__wbindgen_string_get" -> "[读取JS字符串] (JSValue, out_ptr, out_len)"
            name == "__wbindgen_object_drop_ref" -> "[引用计数-1] drop_ref(ref)"
            name == "__wbindgen_object_clone_ref" -> "[引用计数+1] clone_ref(ref)"
            name == "__wbindgen_is_undefined" -> "[类型检查] is_undefined(ref) → bool"
            name == "__wbindgen_is_null" -> "[类型检查] is_null(ref) → bool"
            name == "__wbindgen_is_object" -> "[类型检查] is_object(ref) → bool"
            name == "__wbindgen_is_string" -> "[类型检查] is_string(ref) → bool"
            name == "__wbindgen_is_function" -> "[类型检查] is_function(ref) → bool"
            name == "__wbindgen_jsval_loose_eq" -> "[JS相等] loose_eq(a, b) → bool"
            name == "__wbindgen_throw" -> "[抛出异常] throw(ptr, len)"
            name == "__wbindgen_number_new" -> "[创建数字] number_new(f64) → ref"
            name == "__wbindgen_number_get" -> "[读取数字] number_get(ref) → f64"
            name == "__wbindgen_boolean_get" -> "[读取布尔] boolean_get(ref) → i32"
            name.startsWith("__wbg_self_") -> "[获取全局] self → JSValue"
            name.startsWith("__wbg_window_") -> "[获取全局] window → JSValue"
            name.startsWith("__wbg_globalThis_") -> "[获取全局] globalThis → JSValue"
            name.startsWith("__wbg_document_") -> "[DOM] get document → JSValue"
            name.startsWith("__wbg_querySelector_") -> "[DOM] querySelector(elem, sel_ptr, sel_len) → elem"
            name.startsWith("__wbg_getAttribute_") -> "[DOM] getAttribute(elem, name_ptr, name_len) → string"
            name.startsWith("__wbg_setAttribute_") -> "[DOM] setAttribute(elem, name, value)"
            name.startsWith("__wbg_getRandomValues_") -> "[WebCrypto] getRandomValues(crypto, u8arr)"
            name.startsWith("__wbg_subarray_") -> "[TypedArray] subarray(arr, start, end)"
            name.startsWith("__wbg_buffer_") -> "[ArrayBuffer] buffer(arr) → buffer"
            name.startsWith("__wbg_newU8_") -> "[TypedArray] new Uint8Array(len) → ref"
            name.startsWith("__wbg_newU8len_") -> "[TypedArray] new Uint8Array(len) → ref"
            name.startsWith("__wbg_set_") && name.contains("_u8") -> "[TypedArray] set(arr, src, offset)"
            name.startsWith("__wbg_get_") -> "[JS属性读] Reflect.get(obj, prop) → value"
            name.startsWith("__wbg_set_") -> "[JS属性写] Reflect.set(obj, prop, value)"
            name.startsWith("__wbg_call_") -> "[JS函数调用] call(this, fn, ...args)"
            name.startsWith("__wbg_new_") -> "[JS构造] new Constructor(...args)"
            name.startsWith("__wbg_instanceof_") -> "[类型判断] instanceof(ref) → bool"
            name.startsWith("__wbg_crypto_") -> "[WebCrypto] get crypto → ref"
            name.startsWith("__wbg_length_") -> "[集合] length(ref) → number"
            name.startsWith("__wbg_push_") -> "[数组] push(arr, value)"
            name.startsWith("__wbg_join_") -> "[数组] join(arr, sep) → string"
            name.startsWith("__wbg_now_") -> "[时间] Date.now() → f64"
            name.startsWith("__wbg_decodeURIComponent_") -> "[编码] decodeURIComponent(str)"
            name.startsWith("__wbg_encodeURIComponent_") -> "[编码] encodeURIComponent(str)"
            name.startsWith("__wbg_log_") || name.startsWith("__wbg_error_") -> "[console] log/error(...)"
            else -> null
        }
    }

    /** funcIdx -> 符号名（导入名/name section/导出名） */
    private fun buildNameHints(parsed: WasmParser.ParsedWasm, importedFuncs: Int): Map<Int, String> {
        val hints = HashMap<Int, String>()
        parsed.imports.filter { it.kind == "func" }.forEachIndexed { i, imp ->
            hints[i] = "${imp.module}.${imp.name}"
        }
        parsed.functionNames.forEach { (idx, nm) -> hints[idx] = nm }
        parsed.exports.filter { it.kind == "func" }.forEach { hints[it.index] = it.name }
        hints[-1] = "" // 占位防未用警告
        return hints
    }

    // ---------------- code section 定位 ----------------

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
                repeat(n.toInt()) {
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

    // ---------------- 渲染 ----------------

    private fun renderBody(
        bytes: ByteArray,
        body: Body,
        sig: WasmParser.FuncType,
        name: String,
        funcIndex: Int,
        nameHints: Map<Int, String>,
        maxInstructions: Int,
        parsed: WasmParser.ParsedWasm,
    ): Triple<String, Pair<Int, Int>, Boolean> {
        val b = bytes
        val sb = StringBuilder()
        // wasm-bindgen 检测：导入包含 __wbindgen_ 前缀
        val isWasmBindgen = parsed.imports.any { it.name.startsWith("__wbindgen_") }
        if (isWasmBindgen) sb.appendLine(";; ⚙ wasm-bindgen module detected")
        sb.appendLine(";; func[$funcIndex] $name  ${sigString(sig)}")
        var pos = body.from
        val bodyEnd = body.to
        // locals
        val (groups, gb) = readU32(b, pos); pos += gb
        var locals = 0
        val localDesc = mutableListOf<String>()
        repeat(groups.toInt()) {
            val (cnt, cb) = readU32(b, pos); pos += cb
            val vt = b[pos].toInt() and 0xff; pos += 1
            locals += cnt.toInt()
            localDesc.add("${cnt.toInt()}x${valType(vt)}")
        }
        if (locals > 0) sb.appendLine(";; locals: ${localDesc.joinToString(", ")}")

        var indent = 0
        var instrCount = 0
        var truncated = false
        // 上下文追踪：上一条指令（用于模式识别注释）
        var prevOp = -1
        var prevPrevOp = -1
        while (pos < bodyEnd) {
            if (instrCount >= maxInstructions) { truncated = true; break }
            val op = b[pos].toInt() and 0xff
            pos++
            val (text, newPos, newIndent) = decodeInstr(b, pos, bodyEnd, op, indent, nameHints, parsed, bytes, prevOp, prevPrevOp)
            pos = newPos
            indent = newIndent
            if (text != null) {
                val pad = "  ".repeat(indent.coerceIn(0, 10))
                sb.appendLine("$pad$text")
            }
            prevPrevOp = prevOp
            prevOp = op
            instrCount++
        }
        sb.appendLine(";; end func[$funcIndex]  instructions=$instrCount")
        return Triple(sb.toString(), instrCount to locals, truncated)
    }

    /** 单条指令解码：返回 (wat 行 | null, 新 pos, 新 indent) */
    private fun decodeInstr(
        b: ByteArray,
        pos: Int,
        bodyEnd: Int,
        op: Int,
        indent: Int,
        nameHints: Map<Int, String>,
        parsed: WasmParser.ParsedWasm,
        bytes: ByteArray,
        prevOp: Int,
        prevPrevOp: Int,
    ): Triple<String?, Int, Int> {
        var p = pos
        var ind = indent
        val name = opcodeNames[op] ?: "unknown_0x${op.toString(16)}"
        return when (op) {
            0x02, 0x03, 0x04 -> { // block/loop/if + blocktype
                val (bt, len) = readBlockType(b, p)
                p += len
                ind += 1
                Triple("$name $bt", p, ind)
            }
            0x05 -> Triple("else", p, (ind - 1).coerceAtLeast(0)) // else：同层，先退再进由 end 平衡
            0x0b -> Triple("end", p, (ind - 1).coerceAtLeast(0))
            0x0c, 0x0d -> { // br / br_if
                val (v, l) = readU32(b, p); p += l
                Triple("$name $v", p, ind)
            }
            0x0e -> { // br_table
                val (n, l) = readU32(b, p); p += l
                val targets = mutableListOf<Long>()
                repeat(n.toInt() + 1) {
                    val (t, tl) = readU32(b, p); p += tl
                    targets.add(t)
                }
                Triple("$name ${targets.joinToString(" ")}", p, ind)
            }
            0x10 -> { // call
                val (v, l) = readU32(b, p); p += l
                val hint = nameHints[v.toInt()]
                val semantic = hint?.let { wasmBindgenSemantic(it) }
                val line = buildString {
                    append("call $v")
                    if (hint != null) append("  ;; $hint")
                    if (semantic != null) append(" → $semantic")
                }
                Triple(line, p, ind)
            }
            0x11 -> { // call_indirect type table
                val (t, l1) = readU32(b, p); p += l1
                val (tbl, l2) = readU32(b, p); p += l2
                Triple("call_indirect (type $t) (table $tbl)", p, ind)
            }
            0x1c -> { // select_t
                val (n, l) = readU32(b, p); p += l
                p += n.toInt()
                Triple("select_t", p, ind)
            }
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0xd2 -> {
                val (v, l) = readU32(b, p); p += l
                Triple("$name $v", p, ind)
            }
            in 0x28..0x3e -> { // memarg
                val (a, l1) = readU32(b, p); p += l1
                val (o, l2) = readU32(b, p); p += l2
                Triple("$name offset=$o align=2^$a", p, ind)
            }
            0x3f, 0x40 -> {
                val (v, l) = readU32(b, p); p += l
                Triple("$name $v", p, ind)
            }
            0x41 -> { // i32.const s32
                val (v, l) = readS32(b, p); p += l
                // 尝试注解：若常量值落在 data 段内，读取字符串注释
                val strAnnot = if (v >= 0) {
                    parser.readStringAtVaddr(bytes, parsed, v, 80)?.let { s ->
                        val escaped = s.replace("\"", "\\\"").take(60)
                        " ;; str: \"$escaped\""
                    }
                } else null
                // wasm-bindgen 栈帧模式检测：global.get 0 → i32.const N → i32.sub
                // （上一条是 global.get 0，且本条是 i32.const，大概率是栈帧分配大小）
                val spAnnot = if (prevOp == 0x23 && v > 0 && v < 65536) {
                    " ;; wasm-bindgen: stack frame size ~$v bytes"
                } else null
                Triple("$name $v${strAnnot ?: ""}${spAnnot ?: ""}", p, ind)
            }
            0x42 -> { // i64.const s64
                val (v, l) = readS64(b, p); p += l
                Triple("$name ${v}L", p, ind)
            }
            0x43 -> { // f32.const
                val bits = readLeInt(b, p); p += 4
                Triple("f32.const ${java.lang.Float.intBitsToFloat(bits)}", p, ind)
            }
            0x44 -> { // f64.const
                val bits = readLeLong(b, p); p += 8
                Triple("f64.const ${java.lang.Double.longBitsToDouble(bits)}", p, ind)
            }
            0xd0 -> { // ref.null ht
                val (bt, l) = readBlockType(b, p); p += l
                Triple("ref.null $bt", p, ind)
            }
            0xfb, 0xfc -> { // 前缀指令
                val (sub, l) = readU32(b, p); p += l
                val subName = prefixNames[op]?.get(sub.toInt()) ?: "prefix_0x${op.toString(16)}_$sub"
                when (sub.toInt()) {
                    0 -> { val (m, l1) = readU32(b, p); p += l1; val (d, l2) = readU32(b, p); p += l2; Triple("$subName $m $d", p, ind) } // memory.init
                    2 -> { val (d, l1) = readU32(b, p); p += l1; val (s, l2) = readU32(b, p); p += l2; Triple("$subName $d $s", p, ind) } // memory.copy
                    1, 3, 5 -> { val (x, l1) = readU32(b, p); p += l1; Triple("$subName $x", p, ind) }
                    4, 6 -> { val (d, l1) = readU32(b, p); p += l1; val (s, l2) = readU32(b, p); p += l2; Triple("$subName $d $s", p, ind) } // table.init/copy
                    7, 8, 9 -> { val (t, l1) = readU32(b, p); p += l1; Triple("$subName $t", p, ind) }   // table.grow/size/fill
                    else -> Triple(subName, p, ind)
                }
            }
            // SIMD（0xFD）完整支持——子操作码解码 + immediate 跳过 + 助记符
            0xfd -> {
                val (sub, l) = readU32(b, p); p += l
                val subName = simdNames[sub.toInt()] ?: "simd_$sub"
                val s = sub.toInt()
                when {
                    // v128 load/store（0x00..0x0B）：memarg
                    s in 0x00..0x0b -> {
                        val (a, l1) = readU32(b, p); p += l1
                        val (o, l2) = readU32(b, p); p += l2
                        Triple("$subName offset=$o align=2^$a", p, ind)
                    }
                    // v128.const（0x0C）：16 字节字面量
                    s == 0x0c -> {
                        val hex = (0 until 16).joinToString("") { "%02x".format(b[p + it]) }
                        p += 16
                        Triple("$subName 0x$hex", p, ind)
                    }
                    // i8x16.shuffle（0x0D）：16 个 lane 索引
                    s == 0x0d -> {
                        val lanes = (0 until 16).joinToString(" ") { (b[p + it].toInt() and 0xff).toString() }
                        p += 16
                        Triple("$subName $lanes", p, ind)
                    }
                    // extract/replace lane（0x15..0x22）：单 lane 字节
                    s in 0x15..0x22 -> {
                        val lane = b[p].toInt() and 0xff; p += 1
                        Triple("$subName lane=$lane", p, ind)
                    }
                    // load/store lane（0x54..0x5B）：memarg + lane 字节
                    s in 0x54..0x5b -> {
                        val (a, l1) = readU32(b, p); p += l1
                        val (o, l2) = readU32(b, p); p += l2
                        val lane = b[p].toInt() and 0xff; p += 1
                        Triple("$subName offset=$o lane=$lane", p, ind)
                    }
                    // load32_zero/load64_zero（0x5C..0x5D）：memarg
                    s == 0x5c || s == 0x5d -> {
                        val (a, l1) = readU32(b, p); p += l1
                        val (o, l2) = readU32(b, p); p += l2
                        Triple("$subName offset=$o align=2^$a", p, ind)
                    }
                    else -> Triple(subName, p, ind) // swizzle/splat/算术/比较/位运算：无 immediate
                }
            }
            // Atomics（0xFE）——memarg immediate
            0xfe -> {
                val (sub, l) = readU32(b, p); p += l
                val subName = atomicsNames[sub.toInt()] ?: "atomic_$sub"
                val (a, l1) = readU32(b, p); p += l1
                val (o, l2) = readU32(b, p); p += l2
                Triple("$subName offset=$o align=2^$a", p, ind)
            }
            else -> Triple(name, p, ind) // 无 immediate
        }
    }

    private fun readBlockType(b: ByteArray, from: Int): Pair<String, Int> {
        val v = b[from].toInt() and 0xff
        return when {
            v == 0x40 -> "void" to 1
            v == 0x7f -> "i32" to 1
            v == 0x7e -> "i64" to 1
            v == 0x7d -> "f32" to 1
            v == 0x7c -> "f64" to 1
            else -> { // s33 typeidx（负数不太可能出现在合法块类型此处按多字节处理）
                val (_, l) = readS32(b, from)
                "(type)" to l
            }
        }
    }

    private fun valType(v: Int): String = when (v) {
        0x7f -> "i32"; 0x7e -> "i64"; 0x7d -> "f32"; 0x7c -> "f64"; 0x7b -> "v128"
        0x70 -> "funcref"; 0x6f -> "externref"; else -> "t0x${v.toString(16)}"
    }

    // ---------------- LEB128 ----------------

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

    // ---------------- opcode 名称表 ----------------

    private val opcodeNames: Map<Int, String> = buildMap {
        // control
        put(0x00, "unreachable"); put(0x01, "nop"); put(0x02, "block"); put(0x03, "loop"); put(0x04, "if")
        put(0x05, "else"); put(0x0b, "end"); put(0x0c, "br"); put(0x0d, "br_if"); put(0x0e, "br_table")
        put(0x0f, "return"); put(0x10, "call"); put(0x11, "call_indirect")
        // parametric
        put(0x1a, "drop"); put(0x1b, "select"); put(0x1c, "select_t")
        // variable
        put(0x20, "local.get"); put(0x21, "local.set"); put(0x22, "local.tee")
        put(0x23, "global.get"); put(0x24, "global.set"); put(0x25, "table.get"); put(0x26, "table.set")
        // memory
        put(0x28, "i32.load"); put(0x29, "i64.load"); put(0x2a, "f32.load"); put(0x2b, "f64.load")
        put(0x2c, "i32.load8_s"); put(0x2d, "i32.load8_u"); put(0x2e, "i32.load16_s"); put(0x2f, "i32.load16_u")
        put(0x30, "i64.load8_s"); put(0x31, "i64.load8_u"); put(0x32, "i64.load16_s"); put(0x33, "i64.load16_u")
        put(0x34, "i64.load32_s"); put(0x35, "i64.load32_u")
        put(0x36, "i32.store"); put(0x37, "i64.store"); put(0x38, "f32.store"); put(0x39, "f64.store")
        put(0x3a, "i32.store8"); put(0x3b, "i32.store16"); put(0x3c, "i64.store8"); put(0x3d, "i64.store16")
        put(0x3e, "i64.store32"); put(0x3f, "memory.size"); put(0x40, "memory.grow")
        // const
        put(0x41, "i32.const"); put(0x42, "i64.const"); put(0x43, "f32.const"); put(0x44, "f64.const")
        // i32 compare
        put(0x45, "i32.eqz"); put(0x46, "i32.eq"); put(0x47, "i32.ne"); put(0x48, "i32.lt_s"); put(0x49, "i32.lt_u")
        put(0x4a, "i32.gt_s"); put(0x4b, "i32.gt_u"); put(0x4c, "i32.le_s"); put(0x4d, "i32.le_u")
        put(0x4e, "i32.ge_s"); put(0x4f, "i32.ge_u")
        // i64 compare
        put(0x50, "i64.eqz"); put(0x51, "i64.eq"); put(0x52, "i64.ne"); put(0x53, "i64.lt_s"); put(0x54, "i64.lt_u")
        put(0x55, "i64.gt_s"); put(0x56, "i64.gt_u"); put(0x57, "i64.le_s"); put(0x58, "i64.le_u")
        put(0x59, "i64.ge_s"); put(0x5a, "i64.ge_u")
        // f32/f64 compare
        put(0x5b, "f32.eq"); put(0x5c, "f32.ne"); put(0x5d, "f32.lt"); put(0x5e, "f32.gt"); put(0x5f, "f32.le"); put(0x60, "f32.ge")
        put(0x61, "f64.eq"); put(0x62, "f64.ne"); put(0x63, "f64.lt"); put(0x64, "f64.gt"); put(0x65, "f64.le"); put(0x66, "f64.ge")
        // i32 arith
        put(0x67, "i32.clz"); put(0x68, "i32.ctz"); put(0x69, "i32.popcnt"); put(0x6a, "i32.add"); put(0x6b, "i32.sub")
        put(0x6c, "i32.mul"); put(0x6d, "i32.div_s"); put(0x6e, "i32.div_u"); put(0x6f, "i32.rem_s"); put(0x70, "i32.rem_u")
        put(0x71, "i32.and"); put(0x72, "i32.or"); put(0x73, "i32.xor"); put(0x74, "i32.shl"); put(0x75, "i32.shr_s")
        put(0x76, "i32.shr_u"); put(0x77, "i32.rotl"); put(0x78, "i32.rotr")
        // i64 arith
        put(0x79, "i64.clz"); put(0x7a, "i64.ctz"); put(0x7b, "i64.popcnt"); put(0x7c, "i64.add"); put(0x7d, "i64.sub")
        put(0x7e, "i64.mul"); put(0x7f, "i64.div_s"); put(0x80, "i64.div_u"); put(0x81, "i64.rem_s"); put(0x82, "i64.rem_u")
        put(0x83, "i64.and"); put(0x84, "i64.or"); put(0x85, "i64.xor"); put(0x86, "i64.shl"); put(0x87, "i64.shr_s")
        put(0x88, "i64.shr_u"); put(0x89, "i64.rotl"); put(0x8a, "i64.rotr")
        // f32 arith
        put(0x8b, "f32.abs"); put(0x8c, "f32.neg"); put(0x8d, "f32.ceil"); put(0x8e, "f32.floor"); put(0x8f, "f32.trunc")
        put(0x90, "f32.nearest"); put(0x91, "f32.sqrt"); put(0x92, "f32.add"); put(0x93, "f32.sub"); put(0x94, "f32.mul")
        put(0x95, "f32.div"); put(0x96, "f32.min"); put(0x97, "f32.max"); put(0x98, "f32.copysign")
        // f64 arith
        put(0x99, "f64.abs"); put(0x9a, "f64.neg"); put(0x9b, "f64.ceil"); put(0x9c, "f64.floor"); put(0x9d, "f64.trunc")
        put(0x9e, "f64.nearest"); put(0x9f, "f64.sqrt"); put(0xa0, "f64.add"); put(0xa1, "f64.sub"); put(0xa2, "f64.mul")
        put(0xa3, "f64.div"); put(0xa4, "f64.min"); put(0xa5, "f64.max"); put(0xa6, "f64.copysign")
        // conversion
        put(0xa7, "i32.wrap_i64"); put(0xa8, "i32.trunc_f32_s"); put(0xa9, "i32.trunc_f32_u")
        put(0xaa, "i32.trunc_f64_s"); put(0xab, "i32.trunc_f64_u")
        put(0xac, "i64.extend_i32_s"); put(0xad, "i64.extend_i32_u")
        put(0xae, "i64.trunc_f32_s"); put(0xaf, "i64.trunc_f32_u"); put(0xb0, "i64.trunc_f64_s"); put(0xb1, "i64.trunc_f64_u")
        put(0xb2, "f32.convert_i32_s"); put(0xb3, "f32.convert_i32_u"); put(0xb4, "f32.convert_i64_s"); put(0xb5, "f32.convert_i64_u")
        put(0xb6, "f32.demote_f64")
        put(0xb7, "f64.convert_i32_s"); put(0xb8, "f64.convert_i32_u"); put(0xb9, "f64.convert_i64_s"); put(0xba, "f64.convert_i64_u")
        put(0xbb, "f64.promote_f32")
        put(0xbc, "i32.reinterpret_f32"); put(0xbd, "i64.reinterpret_f64"); put(0xbe, "f32.reinterpret_i32"); put(0xbf, "f64.reinterpret_i64")
        // sign extension
        put(0xc0, "i32.extend8_s"); put(0xc1, "i32.extend16_s"); put(0xc2, "i64.extend8_s")
        put(0xc3, "i64.extend16_s"); put(0xc4, "i64.extend32_s")
        // ref
        put(0xd0, "ref.null"); put(0xd1, "ref.is_null"); put(0xd2, "ref.func")
    }

    // SIMD（0xFD 子操作码）完整助记符表——加密 WASM 常用 v128 向量化实现
    private val simdNames: Map<Int, String> = buildMap {
        // v128 load/store
        put(0x00, "v128.load"); put(0x01, "v128.load8x8_s"); put(0x02, "v128.load8x8_u")
        put(0x03, "v128.load16x4_s"); put(0x04, "v128.load16x4_u"); put(0x05, "v128.load32x2_s")
        put(0x06, "v128.load32x2_u"); put(0x07, "v128.load8_splat"); put(0x08, "v128.load16_splat")
        put(0x09, "v128.load32_splat"); put(0x0a, "v128.load64_splat"); put(0x0b, "v128.store")
        put(0x0c, "v128.const"); put(0x0d, "i8x16.shuffle"); put(0x0e, "i8x16.swizzle")
        // splat
        put(0x0f, "i8x16.splat"); put(0x10, "i16x8.splat"); put(0x11, "i32x4.splat")
        put(0x12, "i64x2.splat"); put(0x13, "f32x4.splat"); put(0x14, "f64x2.splat")
        // extract/replace lane
        put(0x15, "i8x16.extract_lane_s"); put(0x16, "i8x16.extract_lane_u"); put(0x17, "i8x16.replace_lane")
        put(0x18, "i16x8.extract_lane_s"); put(0x19, "i16x8.extract_lane_u"); put(0x1a, "i16x8.replace_lane")
        put(0x1b, "i32x4.extract_lane"); put(0x1c, "i32x4.replace_lane")
        put(0x1d, "i64x2.extract_lane"); put(0x1e, "i64x2.replace_lane")
        put(0x1f, "f32x4.extract_lane"); put(0x20, "f32x4.replace_lane")
        put(0x21, "f64x2.extract_lane"); put(0x22, "f64x2.replace_lane")
        // i8x16 比较
        put(0x23, "i8x16.eq"); put(0x24, "i8x16.ne"); put(0x25, "i8x16.lt_s"); put(0x26, "i8x16.lt_u")
        put(0x27, "i8x16.gt_s"); put(0x28, "i8x16.gt_u"); put(0x29, "i8x16.le_s"); put(0x2a, "i8x16.le_u")
        put(0x2b, "i8x16.ge_s"); put(0x2c, "i8x16.ge_u")
        // i16x8 比较
        put(0x2d, "i16x8.eq"); put(0x2e, "i16x8.ne"); put(0x2f, "i16x8.lt_s"); put(0x30, "i16x8.lt_u")
        put(0x31, "i16x8.gt_s"); put(0x32, "i16x8.gt_u"); put(0x33, "i16x8.le_s"); put(0x34, "i16x8.le_u")
        put(0x35, "i16x8.ge_s"); put(0x36, "i16x8.ge_u")
        // i32x4 比较
        put(0x37, "i32x4.eq"); put(0x38, "i32x4.ne"); put(0x39, "i32x4.lt_s"); put(0x3a, "i32x4.lt_u")
        put(0x3b, "i32x4.gt_s"); put(0x3c, "i32x4.gt_u"); put(0x3d, "i32x4.le_s"); put(0x3e, "i32x4.le_u")
        put(0x3f, "i32x4.ge_s"); put(0x40, "i32x4.ge_u")
        // f32x4/f64x2 比较
        put(0x41, "f32x4.eq"); put(0x42, "f32x4.ne"); put(0x43, "f32x4.lt"); put(0x44, "f32x4.gt")
        put(0x45, "f32x4.le"); put(0x46, "f32x4.ge")
        put(0x47, "f64x2.eq"); put(0x48, "f64x2.ne"); put(0x49, "f64x2.lt"); put(0x4a, "f64x2.gt")
        put(0x4b, "f64x2.le"); put(0x4c, "f64x2.ge")
        // v128 位运算
        put(0x4d, "v128.not"); put(0x4e, "v128.and"); put(0x4f, "v128.andnot"); put(0x50, "v128.or")
        put(0x51, "v128.xor"); put(0x52, "v128.bitselect"); put(0x53, "v128.any_true")
        // load/store lane
        put(0x54, "v128.load8_lane"); put(0x55, "v128.load16_lane"); put(0x56, "v128.load32_lane"); put(0x57, "v128.load64_lane")
        put(0x58, "v128.store8_lane"); put(0x59, "v128.store16_lane"); put(0x5a, "v128.store32_lane"); put(0x5b, "v128.store64_lane")
        put(0x5c, "v128.load32_zero"); put(0x5d, "v128.load64_zero")
        put(0x5e, "f32x4.demote_f64x2_zero"); put(0x5f, "f64x2.promote_low_f32x4")
        // i8x16 算术
        put(0x60, "i8x16.abs"); put(0x61, "i8x16.neg"); put(0x62, "i8x16.popcnt"); put(0x63, "i8x16.all_true")
        put(0x64, "i8x16.bitmask"); put(0x65, "i8x16.narrow_i16x8_s"); put(0x66, "i8x16.narrow_i16x8_u")
        put(0x67, "f32x4.ceil"); put(0x68, "f32x4.floor"); put(0x69, "f32x4.trunc"); put(0x6a, "f32x4.nearest")
        put(0x6b, "i8x16.shl"); put(0x6c, "i8x16.shr_s"); put(0x6d, "i8x16.shr_u")
        put(0x6e, "i8x16.add"); put(0x6f, "i8x16.add_sat_s"); put(0x70, "i8x16.add_sat_u")
        put(0x71, "i8x16.sub"); put(0x72, "i8x16.sub_sat_s"); put(0x73, "i8x16.sub_sat_u")
        put(0x74, "f64x2.ceil"); put(0x75, "f64x2.floor")
        put(0x76, "i8x16.min_s"); put(0x77, "i8x16.min_u"); put(0x78, "i8x16.max_s"); put(0x79, "i8x16.max_u")
        put(0x7a, "f64x2.trunc"); put(0x7b, "i8x16.avgr_u")
        put(0x7c, "i16x8.extadd_pairwise_i8x16_s"); put(0x7d, "i16x8.extadd_pairwise_i8x16_u")
        put(0x7e, "i32x4.extadd_pairwise_i16x8_s"); put(0x7f, "i32x4.extadd_pairwise_i16x8_u")
        // i16x8 算术
        put(0x80, "i16x8.abs"); put(0x81, "i16x8.neg"); put(0x82, "i16x8.q15mulr_sat_s")
        put(0x83, "i16x8.all_true"); put(0x84, "i16x8.bitmask")
        put(0x85, "i16x8.narrow_i32x4_s"); put(0x86, "i16x8.narrow_i32x4_u")
        put(0x87, "i16x8.extend_low_i8x16_s"); put(0x88, "i16x8.extend_high_i8x16_s")
        put(0x89, "i16x8.extend_low_i8x16_u"); put(0x8a, "i16x8.extend_high_i8x16_u")
        put(0x8b, "i16x8.shl"); put(0x8c, "i16x8.shr_s"); put(0x8d, "i16x8.shr_u")
        put(0x8e, "i16x8.add"); put(0x8f, "i16x8.add_sat_s"); put(0x90, "i16x8.add_sat_u")
        put(0x91, "i16x8.sub"); put(0x92, "i16x8.sub_sat_s"); put(0x93, "i16x8.sub_sat_u")
        put(0x94, "f64x2.nearest"); put(0x95, "i16x8.mul")
        put(0x96, "i16x8.min_s"); put(0x97, "i16x8.min_u"); put(0x98, "i16x8.max_s"); put(0x99, "i16x8.max_u")
        put(0x9b, "i16x8.avgr_u")
        put(0x9c, "i16x8.extmul_low_i8x16_s"); put(0x9d, "i16x8.extmul_high_i8x16_s")
        put(0x9e, "i16x8.extmul_low_i8x16_u"); put(0x9f, "i16x8.extmul_high_i8x16_u")
        // i32x4 算术
        put(0xa0, "i32x4.abs"); put(0xa1, "i32x4.neg"); put(0xa3, "i32x4.all_true"); put(0xa4, "i32x4.bitmask")
        put(0xa7, "i32x4.extend_low_i16x8_s"); put(0xa8, "i32x4.extend_high_i16x8_s")
        put(0xa9, "i32x4.extend_low_i16x8_u"); put(0xaa, "i32x4.extend_high_i16x8_u")
        put(0xab, "i32x4.shl"); put(0xac, "i32x4.shr_s"); put(0xad, "i32x4.shr_u"); put(0xae, "i32x4.add")
        put(0xb1, "i32x4.sub"); put(0xb5, "i32x4.mul")
        put(0xb6, "i32x4.min_s"); put(0xb7, "i32x4.min_u"); put(0xb8, "i32x4.max_s"); put(0xb9, "i32x4.max_u")
        put(0xba, "i32x4.dot_i16x8_s")
        put(0xbc, "i32x4.extmul_low_i16x8_s"); put(0xbd, "i32x4.extmul_high_i16x8_s")
        put(0xbe, "i32x4.extmul_low_i16x8_u"); put(0xbf, "i32x4.extmul_high_i16x8_u")
        // i64x2 算术
        put(0xc0, "i64x2.abs"); put(0xc1, "i64x2.neg"); put(0xc3, "i64x2.all_true"); put(0xc4, "i64x2.bitmask")
        put(0xc7, "i64x2.extend_low_i32x4_s"); put(0xc8, "i64x2.extend_high_i32x4_s")
        put(0xc9, "i64x2.extend_low_i32x4_u"); put(0xca, "i64x2.extend_high_i32x4_u")
        put(0xcb, "i64x2.shl"); put(0xcc, "i64x2.shr_s"); put(0xcd, "i64x2.shr_u"); put(0xce, "i64x2.add")
        put(0xd1, "i64x2.sub"); put(0xd5, "i64x2.mul")
        put(0xd6, "i64x2.eq"); put(0xd7, "i64x2.ne"); put(0xd8, "i64x2.lt_s"); put(0xd9, "i64x2.gt_s")
        put(0xda, "i64x2.le_s"); put(0xdb, "i64x2.ge_s")
        put(0xdc, "i64x2.extmul_low_i32x4_s"); put(0xdd, "i64x2.extmul_high_i32x4_s")
        put(0xde, "i64x2.extmul_low_i32x4_u"); put(0xdf, "i64x2.extmul_high_i32x4_u")
        // f32x4/f64x2 算术
        put(0xe0, "f32x4.abs"); put(0xe1, "f32x4.neg"); put(0xe3, "f32x4.sqrt")
        put(0xe4, "f32x4.add"); put(0xe5, "f32x4.sub"); put(0xe6, "f32x4.mul"); put(0xe7, "f32x4.div")
        put(0xe8, "f32x4.min"); put(0xe9, "f32x4.max"); put(0xea, "f32x4.pmin"); put(0xeb, "f32x4.pmax")
        put(0xec, "f64x2.abs"); put(0xed, "f64x2.neg"); put(0xef, "f64x2.sqrt")
        put(0xf0, "f64x2.add"); put(0xf1, "f64x2.sub"); put(0xf2, "f64x2.mul"); put(0xf3, "f64x2.div")
        put(0xf4, "f64x2.min"); put(0xf5, "f64x2.max"); put(0xf6, "f64x2.pmin"); put(0xf7, "f64x2.pmax")
        // 转换
        put(0xf8, "i32x4.trunc_sat_f32x4_s"); put(0xf9, "i32x4.trunc_sat_f32x4_u")
        put(0xfa, "f32x4.convert_i32x4_s"); put(0xfb, "f32x4.convert_i32x4_u")
        put(0xfc, "i32x4.trunc_sat_f64x2_s_zero"); put(0xfd, "i32x4.trunc_sat_f64x2_u_zero")
        put(0xfe, "f64x2.convert_low_i32x4_s"); put(0xff, "f64x2.convert_low_i32x4_u")
    }

    // Atomics（0xFE 子操作码）——共享内存原子操作
    private val atomicsNames: Map<Int, String> = buildMap {
        put(0x00, "memory.atomic.notify"); put(0x01, "memory.atomic.wait32"); put(0x02, "memory.atomic.wait64")
        put(0x03, "atomic.fence")
        put(0x10, "i32.atomic.load"); put(0x11, "i64.atomic.load")
        put(0x12, "i32.atomic.load8_u"); put(0x13, "i32.atomic.load16_u")
        put(0x14, "i64.atomic.load8_u"); put(0x15, "i64.atomic.load16_u"); put(0x16, "i64.atomic.load32_u")
        put(0x17, "i32.atomic.store"); put(0x18, "i64.atomic.store")
        put(0x19, "i32.atomic.store8"); put(0x1a, "i32.atomic.store16")
        put(0x1b, "i64.atomic.store8"); put(0x1c, "i64.atomic.store16"); put(0x1d, "i64.atomic.store32")
        put(0x1e, "i32.atomic.rmw.add"); put(0x1f, "i64.atomic.rmw.add")
        put(0x20, "i32.atomic.rmw8.add_u"); put(0x21, "i32.atomic.rmw16.add_u")
        put(0x22, "i64.atomic.rmw8.add_u"); put(0x23, "i64.atomic.rmw16.add_u"); put(0x24, "i64.atomic.rmw32.add_u")
        put(0x25, "i32.atomic.rmw.sub"); put(0x26, "i64.atomic.rmw.sub")
        put(0x27, "i32.atomic.rmw8.sub_u"); put(0x28, "i32.atomic.rmw16.sub_u")
        put(0x29, "i64.atomic.rmw8.sub_u"); put(0x2a, "i64.atomic.rmw16.sub_u"); put(0x2b, "i64.atomic.rmw32.sub_u")
        put(0x2c, "i32.atomic.rmw.and"); put(0x2d, "i64.atomic.rmw.and")
        put(0x2e, "i32.atomic.rmw8.and_u"); put(0x2f, "i32.atomic.rmw16.and_u")
        put(0x30, "i64.atomic.rmw8.and_u"); put(0x31, "i64.atomic.rmw16.and_u"); put(0x32, "i64.atomic.rmw32.and_u")
        put(0x33, "i32.atomic.rmw.or"); put(0x34, "i64.atomic.rmw.or")
        put(0x35, "i32.atomic.rmw8.or_u"); put(0x36, "i32.atomic.rmw16.or_u")
        put(0x37, "i64.atomic.rmw8.or_u"); put(0x38, "i64.atomic.rmw16.or_u"); put(0x39, "i64.atomic.rmw32.or_u")
        put(0x3a, "i32.atomic.rmw.xor"); put(0x3b, "i64.atomic.rmw.xor")
        put(0x3c, "i32.atomic.rmw8.xor_u"); put(0x3d, "i32.atomic.rmw16.xor_u")
        put(0x3e, "i64.atomic.rmw8.xor_u"); put(0x3f, "i64.atomic.rmw16.xor_u"); put(0x40, "i64.atomic.rmw32.xor_u")
        put(0x41, "i32.atomic.rmw.xchg"); put(0x42, "i64.atomic.rmw.xchg")
        put(0x43, "i32.atomic.rmw8.xchg_u"); put(0x44, "i32.atomic.rmw16.xchg_u")
        put(0x45, "i64.atomic.rmw8.xchg_u"); put(0x46, "i64.atomic.rmw16.xchg_u"); put(0x47, "i64.atomic.rmw32.xchg_u")
        put(0x48, "i32.atomic.rmw.cmpxchg"); put(0x49, "i64.atomic.rmw.cmpxchg")
        put(0x4a, "i32.atomic.rmw8.cmpxchg_u"); put(0x4b, "i32.atomic.rmw16.cmpxchg_u")
        put(0x4c, "i64.atomic.rmw8.cmpxchg_u"); put(0x4d, "i64.atomic.rmw16.cmpxchg_u"); put(0x4e, "i64.atomic.rmw32.cmpxchg_u")
    }

    private val prefixNames: Map<Int, Map<Int, String>> = mapOf(
        0xfc to mapOf(
            0 to "memory.init", 1 to "data.drop", 2 to "memory.copy", 3 to "memory.fill",
            4 to "table.init", 5 to "elem.drop", 6 to "table.copy", 7 to "table.grow",
            8 to "table.size", 9 to "table.fill",
        ),
    )
}
