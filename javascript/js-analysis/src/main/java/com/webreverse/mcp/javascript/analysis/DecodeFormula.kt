package com.webreverse.mcp.javascript.analysis

/**
 * P1-6：dispatch 判别式 decode 公式提取。
 *
 * 真实站点的 JSVMP 字节码常有一层「原始字节 -> opcode」映射，而非元素即 opcode：
 * - `switch((0x1f * bc[pc++]) % 0xf1)`  乘法取模（javascript-obfuscator 常见）
 * - `switch(bc[pc++] ^ 0x5a)`           异或
 * - `switch(bc[pc++] - 0x104)`          偏移
 * - `switch(parseInt(bc[pc++], 16))`    hex 解释
 * - `switch(bc[pc++].charCodeAt(0))`    字符码
 *
 * 本类从判别式提取公式，枚举 byte 0..255 生成 decode_table，
 * 仅当映射输出大量命中 case 键集合时才采用（防误判）。
 * 采用「运行导航器枚举」思想，
 * 此处用纯 Kotlin 枚举实现（无 JS 引擎依赖）。
 */
class DecodeFormula private constructor(
    val description: String,
    private val table: Map<Int, Int>?,
    val mappedCount: Int,
) {

    /** byte -> opcode 映射；null 表直通（原样返回） */
    fun map(ops: List<Int>): List<Int> {
        if (table == null) return ops
        return ops.map { table[it] ?: it }
    }

    val isActive: Boolean get() = table != null

    companion object {

        private data class Formula(
            val desc: String,
            val apply: (Int) -> Int,
        )

        /**
         * @param dispatchExpr switch 判别式原文（如 "(0x1f * _0xbc[_0xpc++]) % 0xf1"）
         * @param caseKeys 全部 case 键的十进制集合（判断映射命中率的锚点）
         */
        fun extract(dispatchExpr: String, caseKeys: Set<Int>): DecodeFormula {
            val expr = dispatchExpr.trim()
            if (expr.isBlank()) return passthrough()

            // 尝试各公式形态；命中 caseKeys 比例最高者胜出
            val candidates = mutableListOf<Formula>()
            findMulMod(expr)?.let { candidates.add(it) }
            findXor(expr)?.let { candidates.add(it) }
            findOffset(expr)?.let { candidates.add(it) }
            findHexParse(expr)?.let { candidates.add(it) }

            if (candidates.isEmpty()) return passthrough()

            var best: Pair<Formula, Int>? = null   // formula -> hits
            var bestTable: Map<Int, Int>? = null
            candidates.forEach { f ->
                val table = HashMap<Int, Int>()
                var hits = 0
                for (b in 0..255) {
                    val mapped = f.apply(b)
                    if (mapped in caseKeys) {
                        table[b] = mapped
                        hits++
                    }
                }
                // 可信门槛：至少 3 个命中，且覆盖 case 键空间一半以上（防偶然命中误判）
                if (hits >= 3 && hits >= caseKeys.size / 2 && (best == null || hits > best!!.second)) {
                    best = f to hits
                    bestTable = table
                }
            }
            return if (best != null && bestTable != null) {
                DecodeFormula(
                    description = best!!.first.desc,
                    table = bestTable,
                    mappedCount = bestTable.size,
                )
            } else passthrough()
        }

        private fun passthrough() = DecodeFormula("直通（元素即 opcode）", null, 0)

        // ---------------- 公式形态识别 ----------------

        /** (K * X[pc++]) % M  /  K * x % M */
        private fun findMulMod(expr: String): Formula? {
            val m = Regex(
                """\(\s*(0x[0-9a-fA-F]{1,4}|\d{1,5})\s*\*\s*[^)]*?\)\s*%\s*(0x[0-9a-fA-F]{1,4}|\d{1,5})""",
            ).find(expr) ?: return null
            val k = num(m.groupValues[1])
            val mod = num(m.groupValues[2])
            if (k == 0L || mod == 0L) return null
            return Formula("(byte * $k) % $mod") { b -> ((b * k) % mod).toInt() }
        }

        /** X ^ K（判别式内非比较位置的异或） */
        private fun findXor(expr: String): Formula? {
            val m = Regex("""\^\s*(0x[0-9a-fA-F]{1,4}|\d{1,5})""").find(expr) ?: return null
            val k = num(m.groupValues[1])
            return if (k == 0L) null else Formula("byte ^ $k") { b -> (b xor k.toInt()) }
        }

        /** X - K / X + K（加减偏移；排除 -= 复合赋值） */
        private fun findOffset(expr: String): Formula? {
            val m = Regex("""(?<![<>=!])\s*([+-])\s*(0x[0-9a-fA-F]{1,4}|\d{1,5})\s*\)?\s*$""").find(expr) ?: return null
            val sign = if (m.groupValues[1] == "-") -1L else 1L
            val k = num(m.groupValues[2])
            if (k == 0L) return null
            return Formula("byte ${m.groupValues[1]} $k") { b -> (b + sign * k).toInt() }
        }

        /** parseInt(X, 16) */
        private fun findHexParse(expr: String): Formula? {
            if (!Regex("""parseInt\s*\([^)]*,\s*16\s*\)""").containsMatchIn(expr)) return null
            return Formula("parseInt(byte, 16)") { b -> b }
        }

        private fun num(s: String): Long =
            if (s.startsWith("0x") || s.startsWith("0X")) s.substring(2).toLongOrNull(16) ?: 0
            else s.toLongOrNull() ?: 0
    }
}
