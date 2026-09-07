package com.webreverse.mcp.javascript.analysis

/**
 * 轨迹驱动符号执行器 v1（ P1-7 新增）。
 *
 * 静态反编译的补集：当字节码载体不可静态提取（运行时解密 / split carrier）
 * 时，运行时 trace 的 opcode 序列是唯一可用的"真实指令流"。
 * 本类把 trace 样本序列翻译为符号伪代码：
 *
 * 1. **样本解析**：支持对象采样 {"op":x,"pc":y} 与标量采样两种形态；
 * 2. **指令切分**：按 ISA 的 arity（override > pc 推进量 > 默认）消费内联
 *    操作数——与 VmpDecompiler 相同的遍历语义，但数据来自运行时；
 * 3. **循环折叠**：连续重复的 opcode/短块折叠为 `×N`（数万样本 -> 数百行）；
 * 4. **块级重复检测**：长度 2~8 的连续重复块识别为 `repeat k: [...]`。
 *
 * 输出与 jsvmp.decompile 的静态 listing 互为印证：两份伪代码的 opcode
 * 语义一致、块结构吻合 => ISA 重建正确；静态多出的块 = 未执行路径，
 * trace 多出的块 = 运行时解密指令。
 */
class TraceSymbolizer {

    data class Symbolized(
        val ok: Boolean,
        val error: String = "",
        val samples: Int = 0,               // 输入样本数
        val opCodesUsed: Int = 0,           // 不同 opcode 数
        val instructions: Int = 0,          // 切分出的指令数
        val loopsFolded: Int = 0,           // RLE 折叠次数
        val blocksFolded: Int = 0,          // 块级折叠次数
        val hotOpcodes: List<Pair<String, Int>> = emptyList(), // top 热点
        val listing: String = "",
        val coverage: Map<String, Int> = emptyMap(),  // ISA 命中统计（命中/未命中）
    )

    /**
     * @param samples 原始样本串（collectVmpTraceRaw 的输出：JSON 对象串或标量串）
     * @param isa opcode（十进制串或 0x hex）-> 助记名（如 "LOAD_CONST"）
     * @param arity opcode -> 操作数字长（用于切分内联操作数）
     */
    fun symbolize(
        samples: List<String>,
        isa: Map<String, String>,
        arity: Map<String, Int> = emptyMap(),
        maxLines: Int = 800,
    ): Symbolized {
        if (samples.isEmpty()) {
            return Symbolized(ok = false, error = "无样本：先 debugger.trace_vmp 采样并传入 get_vmp_trace 的原始序列")
        }

        // 1. 解析样本 -> (op, pc?) 序列
        val ops = mutableListOf<Int>()
        val pcs = mutableListOf<Long?>()
        var parsed = 0
        var nonObject = 0
        for (s in samples) {
            val t = s.trim()
            when {
                t.startsWith("{") -> {
                    val op = extractJsonNum(t, "op") ?: extractJsonNum(t, "opcode")
                    val pc = extractJsonNum(t, "pc") ?: extractJsonNum(t, "ip")
                    if (op != null) {
                        ops.add(op.toInt()); pcs.add(pc); parsed++
                    }
                }
                else -> {
                    val v = t.toLongOrNull() ?: t.removePrefix("0x").toLongOrNull(16)
                    if (v != null) {
                        ops.add(v.toInt()); pcs.add(null); parsed++; nonObject++
                    }
                }
            }
        }
        if (ops.isEmpty()) {
            return Symbolized(ok = false, error = "样本无法解析为 opcode 序列（既非 {op:..} 对象也非数字标量）")
        }

        // 2. ISA 归一化（"0x1a" -> "26"）
        val normIsa = isa.mapNotNull { (k, v) -> normalize(k)?.let { it to v } }.toMap()
        val normArity = arity.mapNotNull { (k, v) -> normalize(k)?.let { it to v } }.toMap()

        // 3. 指令切分（arity 感知）
        data class Sym(val idx: Int, val op: Int, val operands: List<Int>, val pc: Long?)
        val syms = mutableListOf<Sym>()
        var i = 0
        var isaHit = 0
        var isaMiss = 0
        val hitSet = mutableSetOf<String>()
        while (i < ops.size && syms.size < maxLines * 2) {
            val op = ops[i]
            val key = op.toString()
            val a = (normArity[key] ?: 0).coerceIn(0, 4)
            val operands = if (i + a < ops.size) ops.subList(i + 1, i + 1 + a).toList() else emptyList()
            syms.add(Sym(syms.size, op, operands, pcs.getOrNull(i)))
            if (key in normIsa) { isaHit++; hitSet.add(key) } else isaMiss++
            i += 1 + a
        }

        // 4. 渲染（RLE + 块折叠）
        val lines = syms.map { s ->
            val mnem = normIsa[s.op.toString()] ?: "UNKNOWN_0x${s.op.toString(16)}"
            val pcTag = s.pc?.let { "pc=$it " } ?: ""
            val opsTag = if (s.operands.isEmpty()) "" else " " + s.operands.joinToString(" ")
            SymLine("$pcTag$mnem$opsTag", s.op.toString())
        }
        val folded = foldRepeats(lines)
        val hot = syms.groupingBy { it.op.toString() }.eachCount()
            .entries.sortedByDescending { it.value }.take(10)
            .map { (normIsa[it.key] ?: "0x${it.key.toIntOrNull(16)}") to it.value }

        val sb = StringBuilder()
        sb.appendLine("; trace-symbolic: samples=${ops.size} (object=$parsed, scalar=$nonObject) insns=${syms.size}")
        sb.appendLine("; ISA 命中 ${hitSet.size}/${normIsa.size}，未识别执行 ${isaMiss} 次")
        sb.appendLine("; 热点: ${hot.joinToString(", ") { (n, c) -> "$n×$c" }}")
        sb.appendLine()
        folded.lines.take(maxLines).forEach { sb.appendLine(it) }
        if (folded.lines.size > maxLines) sb.appendLine("; ...（其余 ${folded.lines.size - maxLines} 行省略，加大 maxLines 查看）")
        sb.appendLine()
        sb.appendLine("; 提示：与 jsvmp.decompile 静态 listing 对照——语义一致即 ISA 正确；")
        sb.appendLine("; 本结果独有的块 = 运行时解密指令；静态独有 = 未执行路径（补测试触发）")

        return Symbolized(
            ok = true,
            samples = ops.size,
            opCodesUsed = ops.distinct().size,
            instructions = syms.size,
            loopsFolded = folded.rleFolds,
            blocksFolded = folded.blockFolds,
            hotOpcodes = hot,
            listing = sb.toString(),
            coverage = mapOf("isaHit" to isaHit, "isaMiss" to isaMiss),
        )
    }

    // ---------------- 内部 ----------------

    private data class SymLine(val text: String, val op: String)
    private data class Folded(val lines: List<String>, val rleFolds: Int, val blockFolds: Int)

    /** 连续重复折叠：单条 ×N 与块 repeat k: [...]（按 opcode 比较，pc 标签不参与） */
    private fun foldRepeats(lines: List<SymLine>): Folded {
        val out = mutableListOf<String>()
        var rleFolds = 0
        var blockFolds = 0
        var i = 0
        while (i < lines.size) {
            // 单条 RLE：同一 opcode 连续出现（pc 不同也折叠）
            var run = 1
            while (i + run < lines.size && lines[i + run].op == lines[i].op) run++
            if (run >= 3) {
                out.add("${lines[i].text}   ; ×$run")
                rleFolds++
                i += run
                continue
            }
            // 块折叠（块长 2..8，重复 >= 3 次；按 opcode 序列比较）
            var foldedBlock = false
            blockLoop@ for (len in 2..8) {
                if (i + len * 3 > lines.size) continue
                val block = lines.subList(i, i + len).map { it.op }
                var reps = 1
                while (i + (reps + 1) * len <= lines.size &&
                    lines.subList(i + reps * len, i + (reps + 1) * len).map { it.op } == block
                ) reps++
                if (reps >= 3) {
                    out.add("repeat $reps:")
                    lines.subList(i, i + len).forEach { out.add("  ${it.text}") }
                    out.add("end")
                    blockFolds++
                    i += reps * len
                    foldedBlock = true
                    break@blockLoop
                }
            }
            if (!foldedBlock) {
                out.add(lines[i].text)
                i++
            }
        }
        return Folded(out, rleFolds, blockFolds)
    }

    /** 从 JSON 对象串提取数值字段（无 JSON 解析器依赖的轻量方案） */
    private fun extractJsonNum(s: String, field: String): Long? {
        val m = Regex(""""$field"\s*:\s*("?)(-?\d+|0x[0-9a-fA-F]+)\1""").find(s) ?: return null
        val v = m.groupValues[2]
        return if (v.startsWith("0x") || v.startsWith("0X")) v.substring(2).toLongOrNull(16) else v.toLongOrNull()
    }

    /** "0x1a" -> "26"；数字串原样；其他 null */
    private fun normalize(k: String): String? {
        val t = k.trim()
        return when {
            t.startsWith("0x") || t.startsWith("0X") -> t.substring(2).toIntOrNull(16)?.toString()
            t.toIntOrNull() != null -> t.toIntOrNull().toString()
            else -> null
        }
    }
}
