package com.webreverse.mcp.javascript.analysis

/**
 * WASM 二进制解析器 v2（纯 Kotlin，无第三方依赖）。
 *
 * v2 新增（对应评审报告第一档 #5 + 二档前置）：
 * 1. **name section 完整解析**：还原函数名（emscripten/rust 产物自带），
 *    逆向时 export "a" 背后的真实符号直接可读，低成本高收益。
 * 2. **code section 函数体解析**：每函数字节大小 + local 声明计数
 *    （最大函数 ≈ 主逻辑，定位分析入口）。
 * 3. **opcode 直方图**：按函数统计加密相关指令密度
 *    （i32.xor/rotl/rotr、i64.mul、shl/shr_u 等）——没有完整反汇编器时
 *    定位加密热点的实用近似。
 * 4. **data section 真实解析**：offset 表 + 长度 + 前 N 字节预览
 *    （密钥表/常量表所在地）。
 */
class WasmParser {

    data class FuncType(val params: List<String>, val results: List<String>)

    data class WasmImport(
        val module: String,
        val name: String,
        val kind: String, // func / table / memory / global
        val typeIndex: Int = -1,
        val desc: String = "",
    )

    data class WasmExport(val name: String, val kind: String, val index: Int)

    data class MemDecl(val initial: Long, val maximum: Long = -1, val shared: Boolean = false)

    /** code section 中单个函数的元数据 */
    data class FuncBodyInfo(
        val index: Int,        // 全局函数索引（含 import func）
        val bodySize: Int,     // 函数体字节数（含 locals 声明）
        val localDeclCount: Int,
        val name: String? = null,
        val cryptoScore: Int = 0,   // 加密相关 opcode 加权计数
        val topOpcodes: List<Pair<String, Int>> = emptyList(),
    )

    /** data section 单条目 */
    data class DataSegment(
        val mode: String,       // active / passive
        val memoryIndex: Int,   // active 时目标内存
        val offsetExpr: String, // active 时的 offset 表达式描述
        val offset: Long = -1,  // active 时的虚拟内存起始地址（i32.const 解析结果，passive 时为 -1）
        val fileOffset: Int = -1, // 数据字节在 WASM 二进制文件中的偏移（便于读取原始字节）
        val length: Int,
        val previewHex: String, // 前 32 字节 hex
        val previewUtf8: String,
    )

    data class ParsedWasm(
        val ok: Boolean,
        val version: Int = 0,
        val error: String = "",
        val types: List<FuncType> = emptyList(),
        val imports: List<WasmImport> = emptyList(),
        val exports: List<WasmExport> = emptyList(),
        /** 本地函数（code section）签名，按索引顺序 */
        val localFunctions: List<FuncType> = emptyList(),
        val memories: List<MemDecl> = emptyList(),
        val importedMemories: List<MemDecl> = emptyList(),
        val codeCount: Int = 0,
        val dataCount: Long = 0,
        val dataSize: Long = 0,
        val customSections: List<String> = emptyList(),
        val totalBytes: Int = 0,
        // v2 新增
        val functionNames: Map<Int, String> = emptyMap(),
        val funcBodies: List<FuncBodyInfo> = emptyList(),
        val dataSegments: List<DataSegment> = emptyList(),
        val histogramIncomplete: Boolean = false,
    )

    fun parse(bytes: ByteArray): ParsedWasm {
        val r = Reader(bytes)
        return try {
            if (bytes.size < 8 || !r.hasMagic()) {
                return ParsedWasm(ok = false, error = "非 WASM 模块（magic \\0asm 不匹配）", totalBytes = bytes.size)
            }
            val version = r.u32().toInt()
            var types = emptyList<FuncType>()
            var imports = emptyList<WasmImport>()
            var exports = emptyList<WasmExport>()
            var localTypes = emptyList<FuncType>()
            var memories = emptyList<MemDecl>()
            var importedMemories = emptyList<MemDecl>()
            var codeCount = 0
            var dataCount = 0L
            var dataSize = 0L
            val customs = mutableListOf<String>()
            var functionNames = emptyMap<Int, String>()
            var funcBodies = emptyList<FuncBodyInfo>()
            var dataSegments = emptyList<DataSegment>()
            var histogramIncomplete = false

            while (r.remaining() > 0) {
                val secId = r.u8().toInt()
                val size = r.u32().toInt()
                val end = r.pos + size
                if (end > bytes.size) break
                when (secId) {
                    0 -> { // custom
                        val nm = r.name()
                        customs.add(nm)
                        if (nm == "name") {
                            val parsed = parseNameSection(r, end)
                            functionNames = parsed
                        }
                    }
                    1 -> { // type
                        val n = r.u32().toInt()
                        types = (0 until n).map { r.funcType() }
                    }
                    2 -> { // import
                        val n = r.u32().toInt()
                        val list = mutableListOf<WasmImport>()
                        repeat(n) {
                            val mod = r.name()
                            val nm = r.name()
                            when (val kind = r.u8().toInt()) {
                                0 -> {
                                    val ti = r.u32().toInt()
                                    list.add(WasmImport(mod, nm, "func", ti))
                                }
                                1 -> {
                                    r.valTypeOrNull() // reftype
                                    val m = r.limits()
                                    list.add(WasmImport(mod, nm, "table", desc = "min=${m.first}"))
                                }
                                2 -> {
                                    val m = r.limits()
                                    list.add(WasmImport(mod, nm, "memory", desc = "min=${m.first} pages"))
                                    importedMemories = importedMemories + MemDecl(m.first, m.second)
                                }
                                3 -> {
                                    r.valTypeOrNull()
                                    r.u8()
                                    list.add(WasmImport(mod, nm, "global"))
                                }
                                else -> list.add(WasmImport(mod, nm, "kind$kind"))
                            }
                        }
                        imports = list
                    }
                    3 -> { // function
                        val n = r.u32().toInt()
                        localTypes = (0 until n).map { types.getOrElse(r.u32().toInt()) { FuncType(emptyList(), emptyList()) } }
                    }
                    4 -> { // table：跳过
                        r.skipVec()
                    }
                    5 -> { // memory
                        val n = r.u32().toInt()
                        memories = (0 until n).map { val m = r.limits(); MemDecl(m.first, m.second) }
                    }
                    6 -> { // global：跳过
                        r.skipVec()
                    }
                    7 -> { // export
                        val n = r.u32().toInt()
                        exports = (0 until n).map {
                            val nm = r.name()
                            val kind = when (val k = r.u8().toInt()) {
                                0 -> "func"; 1 -> "table"; 2 -> "memory"; 3 -> "global"; else -> "kind$k"
                            }
                            WasmExport(nm, kind, r.u32().toInt())
                        }
                    }
                    8 -> { // start
                        r.u32()
                    }
                    9 -> { // element：跳过
                        r.skipVec()
                    }
                    10 -> { // code
                        codeCount = r.u32().toInt()
                        val importedFuncs = imports.count { it.kind == "func" }
                        val bodies = mutableListOf<FuncBodyInfo>()
                        var bi = 0
                        while (bi < codeCount && r.pos < end) {
                            val bodySize = r.u32().toInt()
                            val bodyEnd = r.pos + bodySize
                            val stats = try {
                                scanBody(r, bodyEnd)
                            } catch (e: Exception) {
                                if (e.message == "SIMD") histogramIncomplete = true
                                BodyScan(0, emptyMap(), 0, skipped = true)
                            }
                            bodies.add(
                                FuncBodyInfo(
                                    index = importedFuncs + bi,
                                    bodySize = bodySize,
                                    localDeclCount = stats.localDecls,
                                    name = functionNames[importedFuncs + bi],
                                    cryptoScore = stats.cryptoScore,
                                    topOpcodes = stats.histogram.entries
                                        .sortedByDescending { it.value }
                                        .take(6)
                                        .map { it.key to it.value },
                                ),
                            )
                            r.seek(bodyEnd)
                            bi++
                        }
                        funcBodies = bodies
                    }
                    11 -> { // data
                        val n = r.u32().toInt()
                        dataCount = n.toLong()
                        val segs = mutableListOf<DataSegment>()
                        var si = 0
                        while (si < n && r.pos < end) {
                            val flags = r.u32().toInt()
                            when {
                                flags == 0 -> { // active, memory 0
                                    val (offExpr, offVal) = readInitExprWithValue(r)
                                    val len = r.u32().toInt()
                                    val fileOff = r.pos
                                    val preview = readPreview(r, end, len)
                                    dataSize += len
                                    segs.add(
                                        DataSegment(
                                            "active", 0, offExpr, offVal, fileOff, len,
                                            preview.first, preview.second,
                                        ),
                                    )
                                }
                                flags == 1 -> { // passive
                                    val len = r.u32().toInt()
                                    val fileOff = r.pos
                                    val preview = readPreview(r, end, len)
                                    dataSize += len
                                    segs.add(
                                        DataSegment(
                                            "passive", -1, "", -1, fileOff, len,
                                            preview.first, preview.second,
                                        ),
                                    )
                                }
                                flags == 2 -> { // active, explicit memidx
                                    val memIdx = r.u32().toInt()
                                    val (offExpr, offVal) = readInitExprWithValue(r)
                                    val len = r.u32().toInt()
                                    val fileOff = r.pos
                                    val preview = readPreview(r, end, len)
                                    dataSize += len
                                    segs.add(
                                        DataSegment(
                                            "active", memIdx, offExpr, offVal, fileOff, len,
                                            preview.first, preview.second,
                                        ),
                                    )
                                }
                                else -> break // 未知格式，放弃剩余段
                            }
                            si++
                        }
                        dataSegments = segs
                    }
                    12 -> { // data count
                        r.u32()
                    }
                }
                r.seek(maxOf(end, r.pos))
            }
            // name section（custom）通常在文件尾部、code 之后，此处回填函数名
            if (functionNames.isNotEmpty()) {
                funcBodies = funcBodies.map { it.copy(name = it.name ?: functionNames[it.index]) }
            }
            ParsedWasm(
                ok = true,
                version = version,
                types = types,
                imports = imports,
                exports = exports,
                localFunctions = localTypes,
                memories = memories,
                importedMemories = importedMemories,
                codeCount = if (codeCount > 0) codeCount else localTypes.size,
                dataCount = dataCount,
                dataSize = dataSize,
                customSections = customs,
                totalBytes = bytes.size,
                functionNames = functionNames,
                funcBodies = funcBodies,
                dataSegments = dataSegments,
                histogramIncomplete = histogramIncomplete,
            )
        } catch (e: Exception) {
            ParsedWasm(ok = false, error = "解析失败于 offset ${r.pos}: ${e.message}", totalBytes = bytes.size)
        }
    }

    /**
     * 输出简化 WAT v2：带 name section 函数名与加密热点标注。
     * LLM 拿到它即可理解模块接口，相比二进制流 token 效率高两个数量级。
     */
    fun toWat(p: ParsedWasm, maxFuncs: Int = 300): String {
        if (!p.ok) return ";; ${p.error}"
        val sb = StringBuilder("(module\n")
        p.types.take(50).forEachIndexed { i, t ->
            sb.append("  (type (;$i;) (func${sig(t)}))\n")
        }
        p.imports.take(100).forEach { im ->
            when (im.kind) {
                "func" -> {
                    val t = p.types.getOrNull(im.typeIndex)
                    sb.append("  (import \"${im.module}\" \"${im.name}\" (func ${'$'}${im.module}.${im.name}${t?.let { " (type ${im.typeIndex})" } ?: ""}))\n")
                }
                else -> sb.append("  (import \"${im.module}\" \"${im.name}\" (${im.kind}${if (im.desc.isNotBlank()) " (;${im.desc};)" else ""}))\n")
            }
        }
        (p.importedMemories + p.memories).take(10).forEachIndexed { i, m ->
            sb.append("  (memory (;$i;) ${m.initial}${if (m.maximum >= 0) " ${m.maximum}" else ""})\n")
        }
        p.exports.take(100).forEach { e ->
            val name = if (e.kind == "func") p.functionNames[e.index]?.let { " ;; $it" } ?: "" else ""
            sb.append("  (export \"${e.name}\" (${e.kind} ${e.index}))$name\n")
        }
        val importedFuncs = p.imports.count { it.kind == "func" }
        p.localFunctions.take(maxFuncs).forEachIndexed { i, t ->
            val idx = importedFuncs + i
            val nm = p.functionNames[idx]
            val body = p.funcBodies.firstOrNull { it.index == idx }
            val crypto = if ((body?.cryptoScore ?: 0) >= 20) " ;; ⚡crypto hotspot(${body?.cryptoScore})" else ""
            sb.append("  (func (;$idx;) ${nm ?: ""}${sig(t)}${crypto})\n")
        }
        if (p.localFunctions.size > maxFuncs) sb.append("  ;; ...另有 ${p.localFunctions.size - maxFuncs} 个函数签名省略\n")
        p.dataSegments.take(20).forEach { d ->
            sb.append("  (data (;${d.mode}${if (d.memoryIndex >= 0) " mem${d.memoryIndex}" else ""};) ${d.offsetExpr} len=${d.length})\n")
        }
        sb.append(")\n")
        return sb.toString()
    }

    private fun sig(t: FuncType): String {
        val params = if (t.params.isEmpty()) "" else " (param ${t.params.joinToString(" ")})"
        val results = if (t.results.isEmpty()) "" else " (result ${t.results.joinToString(" ")})"
        return "$params$results"
    }

    // ---------------- 虚拟地址 -> data 段字节读取 ----------------

    /** 查找包含指定虚拟地址的 active data 段（返回段索引，找不到返回 -1） */
    fun findDataSegmentForVaddr(parsed: ParsedWasm, vaddr: Long): Int {
        if (!parsed.ok) return -1
        parsed.dataSegments.forEachIndexed { i, seg ->
            if (seg.mode == "active" && seg.offset >= 0) {
                if (vaddr >= seg.offset && vaddr < seg.offset + seg.length) {
                    return i
                }
            }
        }
        return -1
    }

    /** 按虚拟内存地址读取 data 段字节（hex + utf8 双视图）。
     *  若地址不在任何 data 段内，返回 error 信息。 */
    fun readDataAtVaddr(bytes: ByteArray, parsed: ParsedWasm, vaddr: Long, length: Int = 64): DataReadResult {
        if (!parsed.ok) return DataReadResult(false, error = parsed.error)
        val segIdx = findDataSegmentForVaddr(parsed, vaddr)
        if (segIdx < 0) return DataReadResult(false, error = "虚拟地址 0x${vaddr.toString(16)} 不在任何 active data 段范围内")
        val seg = parsed.dataSegments[segIdx]
        val relOffset = (vaddr - seg.offset).toInt()
        val actualLen = minOf(length, seg.length - relOffset)
        if (actualLen <= 0) return DataReadResult(false, error = "读取长度越界")
        if (seg.fileOffset < 0) return DataReadResult(false, error = "data 段文件偏移未知")
        val fileStart = seg.fileOffset + relOffset
        if (fileStart + actualLen > bytes.size) return DataReadResult(false, error = "文件偏移越界")
        val hex = StringBuilder()
        val utf8 = StringBuilder()
        for (i in 0 until actualLen) {
            val b = bytes[fileStart + i].toInt() and 0xff
            hex.append("%02x".format(b))
            utf8.append(if (b in 0x20..0x7e) b.toChar() else '.')
        }
        return DataReadResult(
            true,
            segmentIndex = segIdx,
            segmentOffset = seg.offset,
            relativeOffset = relOffset,
            length = actualLen,
            hex = hex.toString(),
            utf8 = utf8.toString(),
        )
    }

    data class DataReadResult(
        val ok: Boolean,
        val error: String = "",
        val segmentIndex: Int = -1,
        val segmentOffset: Long = -1,
        val relativeOffset: Int = 0,
        val length: Int = 0,
        val hex: String = "",
        val utf8: String = "",
    )

    /** 尝试在虚拟地址处读取一个 C 风格/UTF-8 字符串（最长 maxLen 字节），
     *  用于反汇编时自动注解 i32.const 指向的字符串常量。 */
    fun readStringAtVaddr(bytes: ByteArray, parsed: ParsedWasm, vaddr: Long, maxLen: Int = 128): String? {
        val result = readDataAtVaddr(bytes, parsed, vaddr, maxLen)
        if (!result.ok) return null
        // 从 utf8 中提取可打印前缀（遇到不可打印字符截断）
        val s = result.utf8
        val end = s.indexOfFirst { it.code < 0x20 }
        val printable = if (end < 0) s else s.substring(0, end)
        if (printable.length < 2) return null
        return printable
    }

    // ---------------- name section ----------------

    /** name section: subsection 1 = function names map */
    private fun parseNameSection(r: Reader, sectionEnd: Int): Map<Int, String> {
        val names = mutableMapOf<Int, String>()
        try {
            while (r.pos < sectionEnd) {
                val subId = r.u8().toInt()
                val subSize = r.u32().toInt()
                val subEnd = r.pos + subSize
                if (subId == 1) {
                    val n = r.u32().toInt()
                    repeat(n) {
                        val idx = r.u32().toInt()
                        val nm = r.name()
                        if (nm.isNotBlank()) names[idx] = nm
                    }
                }
                r.seek(subEnd.coerceAtMost(sectionEnd))
            }
        } catch (e: Exception) {
            // name section 损坏时返回已解析部分
        }
        return names
    }

    // ---------------- code body 扫描（opcode 直方图） ----------------

    private class BodyScan(
        val localDecls: Int,
        val histogram: Map<String, Int>,
        val cryptoScore: Int,
        val skipped: Boolean = false,
    )

    /** 加密相关 opcode 加权表 */
    private val cryptoOpcodes = mapOf(
        0x73 to 3, // i32.xor
        0x85 to 3, // i64.xor
        0x77 to 4, // i32.rotl
        0x78 to 4, // i32.rotr
        0x89 to 4, // i64.rotl
        0x8a to 4, // i64.rotr
        0x7e to 2, // i64.mul
        0x6c to 1, // i32.mul
        0x74 to 1, // i32.shl
        0x76 to 1, // i32.shr_u
        0x86 to 2, // i64.shl
        0x88 to 2, // i64.shr_u
        0x71 to 2, // i32.and
        0x72 to 2, // i32.or
    )

    /** 需要读 memarg（align+offset 两个 LEB）的 opcode 区间 */
    private val opcodeNames = mapOf(
        0x00 to "unreachable", 0x01 to "nop", 0x02 to "block", 0x03 to "loop", 0x04 to "if", 0x05 to "else",
        0x0b to "end", 0x0c to "br", 0x0d to "br_if", 0x0e to "br_table", 0x0f to "return",
        0x10 to "call", 0x11 to "call_indirect",
        0x1a to "drop", 0x1b to "select",
        0x20 to "local.get", 0x21 to "local.set", 0x22 to "local.tee",
        0x23 to "global.get", 0x24 to "global.set",
        0x25 to "table.get", 0x26 to "table.set",
        0x41 to "i32.const", 0x42 to "i64.const", 0x43 to "f32.const", 0x44 to "f64.const",
        0x6a to "i32.add", 0x6b to "i32.sub", 0x6c to "i32.mul",
        0x71 to "i32.and", 0x72 to "i32.or", 0x73 to "i32.xor",
        0x74 to "i32.shl", 0x75 to "i32.shr_s", 0x76 to "i32.shr_u",
        0x77 to "i32.rotl", 0x78 to "i32.rotr",
        0x7c to "i64.add", 0x7d to "i64.sub", 0x7e to "i64.mul",
        0x83 to "i64.and", 0x84 to "i64.or", 0x85 to "i64.xor",
        0x86 to "i64.shl", 0x87 to "i64.shr_s", 0x88 to "i64.shr_u",
        0x89 to "i64.rotl", 0x8a to "i64.rotr",
        0xa7 to "i32.wrap_i64", 0xac to "i64.extend_i32_s", 0xad to "i64.extend_i32_u",
        0xc0 to "i32.extend8_s", 0xc1 to "i32.extend16_s", 0xc2 to "i64.extend8_s", 0xc3 to "i64.extend16_s", 0xc4 to "i64.extend32_s",
    )

    private fun scanBody(r: Reader, bodyEnd: Int): BodyScan {
        // locals 声明
        val declGroups = r.u32().toInt()
        var localDecls = 0
        repeat(declGroups) {
            val cnt = r.u32().toInt()
            r.valTypeOrNull()
            localDecls += cnt
        }
        val hist = HashMap<String, Int>()
        var crypto = 0
        while (r.pos < bodyEnd) {
            val op = r.u8().toInt() and 0xff
            if (op == 0xfd) throw Exception("SIMD") // SIMD 区间放弃精确解析
            val name = opcodeNames[op] ?: when (op) {
                in 0x28..0x3e -> "memop"
                in 0x45..0xc4 -> "op0x${op.toString(16)}"
                0xd0 -> "ref.null"; 0xd1 -> "ref.is_null"; 0xd2 -> "ref.func"
                0x1c -> "select_t"
                else -> "op0x${op.toString(16)}"
            }
            hist[name] = (hist[name] ?: 0) + 1
            cryptoOpcodes[op]?.let { crypto += it }
            // immediate 跳过
            when (op) {
                0x02, 0x03, 0x04 -> r.blockType()      // block/loop/if
                0x0c, 0x0d, 0x10, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0xd2 -> r.u32()
                0x0e -> { // br_table: vec of labelidx + default
                    val n = r.u32().toInt(); repeat(n + 1) { r.u32() }
                }
                0x11 -> { r.u32(); r.u32() }           // call_indirect
                0x1c -> { val n = r.u32().toInt(); repeat(n) { r.valTypeOrNull() } }
                in 0x28..0x3e -> { r.u32(); r.u32() }  // memarg
                0x3f, 0x40 -> r.u32()                  // memory.size/grow
                0x41 -> r.s32()
                0x42 -> r.s64()
                0x43 -> r.fixed(4)
                0x44 -> r.fixed(8)
                0xd0 -> r.blockType()
                0xfb, 0xfc -> { // bulk-memory / sat-trunc 前缀：按子 opcode 处理
                    val sub = r.u32().toInt()
                    when (sub) {
                        8, 9 -> r.u32()                // memory.init / data.drop
                        10 -> { r.u32(); r.u32() }     // memory.copy
                        11 -> r.u32()                  // memory.fill
                        12, 14 -> r.u32()              // table.init / table.copy
                        13, 15 -> r.u32()
                    }
                }
            }
        }
        return BodyScan(localDecls, hist, crypto)
    }

    /** 常量初始化表达式（i32.const LEB end / i64.const ... / global.get idx end）
     *  返回 (表达式字符串, i32.const 的数值 或 -1 如果不是简单 i32.const) */
    private fun readInitExprWithValue(r: Reader): Pair<String, Long> = try {
        val sb = StringBuilder()
        var value: Long = -1
        while (true) {
            val op = r.u8().toInt()
            when (op) {
                0x41 -> {
                    val v = r.s32()
                    sb.append("i32.const ").append(v)
                    value = v
                }
                0x42 -> { sb.append("i64.const ").append(r.s64()); }
                0x43 -> { r.fixed(4); sb.append("f32.const") }
                0x44 -> { r.fixed(8); sb.append("f64.const") }
                0x23 -> { sb.append("global.get ").append(r.u32()); }
                0x0b -> break
                else -> break
            }
            sb.append(' ')
        }
        sb.toString().trim() to value
    } catch (e: Exception) {
        "(unreadable)" to -1
    }

    /** 旧版兼容：仅返回表达式字符串 */
    private fun readInitExpr(r: Reader): String = readInitExprWithValue(r).first

    /** data 段内容预览（hex 32B + 可见字符），跳过剩余字节 */
    private fun readPreview(r: Reader, sectionEnd: Int, len: Int): Pair<String, String> {
        val avail = (r.pos + len).coerceAtMost(sectionEnd) - r.pos
        if (avail <= 0 || len < 0) return "" to ""
        val previewN = minOf(32, avail)
        val hex = StringBuilder()
        val utf = StringBuilder()
        for (i in 0 until previewN) {
            val b = r.u8().toInt() and 0xff
            hex.append("%02x".format(b))
            utf.append(if (b in 0x20..0x7e) b.toChar() else '.')
        }
        // 跳过剩余
        r.seek((r.pos + (len - previewN).coerceAtLeast(0)).coerceAtMost(sectionEnd))
        return hex.toString() to utf.toString()
    }

    // ---------------- 底层读取 ----------------

    private class Reader(val b: ByteArray) {
        var pos = 0

        fun remaining() = b.size - pos

        fun hasMagic(): Boolean {
            if (b.size < 4) return false
            val magic = b[0] == 0x00.toByte() && b[1] == 0x61.toByte() && b[2] == 0x73.toByte() && b[3] == 0x6d.toByte()
            if (magic) pos = 4
            return magic
        }

        fun u8(): Byte = if (pos < b.size) b[pos++] else throw IllegalStateException("EOF")

        fun u32(): Long {
            var result = 0L
            var shift = 0
            while (true) {
                val byte = u8().toInt() and 0xff
                result = result or ((byte and 0x7f).toLong() shl shift)
                if (byte and 0x80 == 0) break
                shift += 7
                if (shift > 63) throw IllegalStateException("LEB128 溢出")
            }
            return result
        }

        fun s32(): Long {
            var result = 0L
            var shift = 0
            while (true) {
                val byte = u8().toInt() and 0xff
                result = result or ((byte and 0x7f).toLong() shl shift)
                shift += 7
                if (byte and 0x80 == 0) {
                    if (shift < 64 && byte and 0x40 != 0) result = result or (-1L shl shift)
                    break
                }
                if (shift > 63) throw IllegalStateException("LEB128 溢出")
            }
            return result
        }

        fun s64(): Long = s32()

        fun fixed(n: Int) {
            pos += n
        }

        fun name(): String {
            val len = u32().toInt()
            val end = pos + len
            if (end > b.size) throw IllegalStateException("name 越界")
            val s = String(b, pos, len, Charsets.UTF_8)
            pos = end
            return s
        }

        fun valTypeOrNull(): String? {
            val v = u8().toInt() and 0xff
            val t = when (v) {
                0x7f -> "i32"; 0x7e -> "i64"; 0x7d -> "f32"; 0x7c -> "f64"
                0x70 -> "funcref"; 0x6f -> "externref"; 0x6b -> "v128"
                else -> null
            }
            return t ?: "?0x${v.toString(16)}"
        }

        /** blocktype：单字节 0x40/valtype 或 s33 typeidx（近似处理） */
        fun blockType() {
            val v = u8().toInt() and 0xff
            if (v == 0x40 || v == 0x7f || v == 0x7e || v == 0x7d || v == 0x7c || v == 0x6f || v == 0x70 || v == 0x6b) return
            // s33 multi-byte 场景：读剩余 LEB 字节
            if (v and 0x80 != 0) {
                while (true) {
                    val nb = u8().toInt() and 0xff
                    if (nb and 0x80 == 0) break
                }
            }
        }

        /** limits: flags + min (+max)；返回 (min, max or -1) */
        fun limits(): Pair<Long, Long> {
            val flags = u8().toInt()
            val min = u32()
            val max = if (flags and 0x01 != 0) u32() else -1
            return min to max
        }

        /** 跳过一个 vec（读取计数后按剩余 section 尺寸直接越过） */
        fun skipVec() {
            u32()
        }

        fun funcType(): FuncType {
            val tag = u8().toInt()
            if (tag != 0x60) throw IllegalStateException("functype tag 异常: $tag")
            val pn = u32().toInt()
            val params = (0 until pn).map { valTypeOrNull() ?: "?" }
            val rn = u32().toInt()
            val results = (0 until rn).map { valTypeOrNull() ?: "?" }
            return FuncType(params, results)
        }

        fun seek(p: Int) {
            pos = p.coerceIn(0, b.size)
        }
    }
}
