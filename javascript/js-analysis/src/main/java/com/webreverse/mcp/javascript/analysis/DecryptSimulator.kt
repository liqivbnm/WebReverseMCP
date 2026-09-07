package com.webreverse.mcp.javascript.analysis

/**
 * 字符串解密链真实还原器 v1（ 新增）。
 *
 * StaticAnalyzer 只能「猜测」解码值（decodedGuess = 数组直取），本类把猜测升级为
 * 真实还原，两条腿走路：
 *
 * 1. **本地模拟（离线，纯 Kotlin）**：识别 javascript-obfuscator 系解码器的三大
 *    原型并逐一还原调用点：
 *    - INDEX_OFFSET：`array[a + b]` / `array[a - b]` 带偏移索引（最常见）
 *    - BASE64：数组元素本身是 base64，decoder 内 atob
 *    - XOR_CONST：`charCodeAt(i) ^ K` / `fromCharCode(c ^ K)` 常量异或
 *    - CAESAR：`charCodeAt(i) ± K` 常量位移
 * 2. **页面沙箱（在线，生成的 JS 在目标页 eval）**：`sandboxScript()` 把原始
 *    数组声明 + 解码函数声明 + 全部调用点打包成自包含 IIFE，在页面上下文里
 *    重执行解码器拿真实明文（本地原型不匹配时的兜底，100% 还原任意解码器）。
 */
class DecryptSimulator {

    // ---------------- 数据模型 ----------------

    enum class Method(val display: String) {
        INDEX_OFFSET("数组偏移索引"),
        BASE64("base64 解码"),
        XOR_CONST("常量异或"),
        CAESAR("常量位移"),
        DIRECT("数组直取（无运算）"),
        RUNTIME("需页面沙箱/运行时"),
    }

    data class ResolvedSite(
        val line: Int,
        val expression: String,
        val value: String,          // 还原出的明文
        val method: Method,
        val confidence: Int,        // 0-100
    )

    data class SimResult(
        val found: Boolean,
        val arrayName: String,
        val decoderName: String,
        val decoderArchetype: String,   // 命中的原型描述
        val totalSites: Int,
        val resolved: List<ResolvedSite>,
        val unresolvedCount: Int,
        val sandboxScript: String,      // 兜底沙箱脚本（resolve 失败时用）
        val notes: List<String>,
    )

    // ---------------- 入口 ----------------

    fun simulate(source: String, maxSites: Int = 100): SimResult {
        val chain = StaticAnalyzer().analyze(source).decryptChain
        if (!chain.found) {
            return SimResult(false, "", "", "", 0, emptyList(), 0, "", listOf("未识别到字符串数组三件套布局"))
        }

        val notes = mutableListOf<String>()
        val elements = parseArrayElements(chain.arrayDecl)

        // 原型识别
        val decoder = chain.decoderDecl
        val archetypes = detectArchetypes(decoder, chain.arrayName)
        if (archetypes.isEmpty()) notes.add("解码器未命中已知原型，调用点需走沙箱重执行")

        // 还原调用点
        val sites = extractCallArgs(source, chain.decoderName).take(maxSites)
        val resolved = mutableListOf<ResolvedSite>()
        var unresolved = 0
        val lineStarts = buildLineIndex(source)
        for ((expr, args, offset) in sites) {
            val idx = args.firstOrNull() ?: -1
            if (idx < 0 || idx >= 100_000) { unresolved++; continue }
            val n = elements.size
            val r = when {
                // atob 原型优先：元素本身是 base64 密文，直接取下标得到的是密文而非明文
                archetypes.containsKey(Archetype.BASE64) ->
                    elements.getOrNull(idx % n)?.let { el ->
                        decodeBase64(el)?.let { ResolvedSite(0, expr, it, Method.BASE64, 85) }
                    }
                archetypes.containsKey(Archetype.XOR_CONST) -> {
                    val k = archetypes[Archetype.XOR_CONST]!!.key
                    elements.getOrNull(idx % n)?.let { el ->
                        xorDecode(el, k)?.let { ResolvedSite(0, expr, it, Method.XOR_CONST, 85) }
                    }
                }
                archetypes.containsKey(Archetype.CAESAR) -> {
                    val k = archetypes[Archetype.CAESAR]!!.key
                    elements.getOrNull(idx % n)?.let { el ->
                        caesarDecode(el, k)?.let { ResolvedSite(0, expr, it, Method.CAESAR, 80) }
                    }
                }
                archetypes.containsKey(Archetype.INDEX_OFFSET) -> {
                    val info = archetypes[Archetype.INDEX_OFFSET]!!.offset!!
                    // effective = idx ± b实参 + constSum（模长回环，兼容 shuffle 旋转）
                    val b = (offset ?: 0).toLong() * info.offsetSign
                    val real = (((idx + b + info.constSum) % n + n) % n).toInt()
                    elements.getOrNull(real)?.let {
                        ResolvedSite(0, expr, it, Method.INDEX_OFFSET, 90)
                    }
                }
                n > idx -> ResolvedSite(0, expr, elements[idx], Method.DIRECT, 40)
                else -> null
            }
            if (r != null) {
                val m = Regex(Regex.escape(expr)).find(source)
                resolved.add(r.copy(line = if (m != null) offsetToLine(lineStarts, m.range.first) else 0))
            } else {
                unresolved++
            }
        }

        if (chain.offsetsPattern && archetypes.containsKey(Archetype.INDEX_OFFSET)) {
            notes.add("检测到偏移自解 IIFE：本地已按 (idx+b) 修正；若结果仍乱码，以沙箱重执行为准")
        }
        if (unresolved > 0) notes.add("$unresolved 个调用点未还原——运行 sandboxScript（static.decrypt_execute）兜底")

        return SimResult(
            found = true,
            arrayName = chain.arrayName,
            decoderName = chain.decoderName,
            decoderArchetype = archetypes.entries.joinToString(" + ") { (k, v) ->
                "${k.display}(${v.offset?.let { "const=${it.constSum},sign=${it.offsetSign}" } ?: if (v.key != 0L) "K=${v.key}" else ""})"
            }.ifBlank { "未识别" },
            totalSites = sites.size,
            resolved = resolved,
            unresolvedCount = unresolved,
            sandboxScript = sandboxScript(chain, sites.map { it.expr }),
            notes = notes,
        )
    }

    // ---------------- 原型识别 ----------------

    private enum class Archetype(val display: String) { INDEX_OFFSET("索引偏移"), BASE64("base64"), XOR_CONST("异或"), CAESAR("位移") }

    /** INDEX_OFFSET 的解析结果：effective = idx ± b实参 + constSum */
    private data class OffsetInfo(val constSum: Long, val offsetSign: Int)

    private data class ArchetypeInfo(val offset: OffsetInfo? = null, val key: Long = 0L)

    /**
     * 识别解码器原型。
     * INDEX_OFFSET：解析 `array[<idx> ± <b> ± 常量]` 的完整偏移表达式
     * （首个动态项=idx 形参；第二个动态项=b 形参，其符号决定实参方向；
     * 常量项求和进 constSum——javascript-obfuscator 的 `- 0x104` 即在此捕获）
     */
    private fun detectArchetypes(decoderDecl: String, arrayName: String): Map<Archetype, ArchetypeInfo> {
        val out = LinkedHashMap<Archetype, ArchetypeInfo>()
        if (decoderDecl.isBlank()) return out
        val esc = Regex.escape(arrayName)

        // array[...] 内层表达式
        val idxMatch = Regex("""$esc\s*\[\s*([^]]{1,80})\]""").find(decoderDecl)
        if (idxMatch != null) {
            val inner = idxMatch.groupValues[1]
            val terms = Regex("""([+-]?)\s*(0x[0-9a-fA-F]{1,6}|\d{1,7}|[A-Za-z_$][\w$]{0,12})""")
                .findAll(inner).toList()
            if (terms.isNotEmpty()) {
                var constSum = 0L
                var offsetSign = 0
                var dynamicSeen = 0
                terms.forEach { t ->
                    val sign = if (t.groupValues[1] == "-") -1L else 1L
                    val token = t.groupValues[2]
                    val num = if (token.startsWith("0x")) token.substring(2).toLongOrNull(16)
                    else token.toLongOrNull()
                    if (num != null) {
                        constSum += sign * num
                    } else {
                        dynamicSeen++
                        if (dynamicSeen == 2) offsetSign = sign.toInt() // 第二个动态项 = b 形参
                    }
                }
                if (dynamicSeen >= 1) {
                    out[Archetype.INDEX_OFFSET] = ArchetypeInfo(OffsetInfo(constSum, offsetSign))
                }
            }
        }
        // fromCharCode(x ^ K) / charCodeAt(i) ^ K
        Regex("""\^\s*(0x[0-9a-fA-F]{1,4}|\d{1,5})""").find(decoderDecl)?.let {
            out[Archetype.XOR_CONST] = ArchetypeInfo(key = parseNum(it.groupValues[1]))
        }
        // charCodeAt(i) + K / - K（非异或的位移）
        Regex("""charCodeAt\s*\([^)]*\)\s*([+-])\s*(0x[0-9a-fA-F]{1,4}|\d{1,5})""").find(decoderDecl)?.let {
            val sign = if (it.groupValues[1] == "-") -1L else 1L
            out[Archetype.CAESAR] = ArchetypeInfo(key = sign * parseNum(it.groupValues[2]))
        }
        // atob(...)
        if (Regex("""\batob\s*\(""").containsMatchIn(decoderDecl)) out[Archetype.BASE64] = ArchetypeInfo()
        return out
    }

    private fun parseNum(s: String): Long =
        if (s.startsWith("0x") || s.startsWith("0X")) s.substring(2).toLongOrNull(16) ?: 0L
        else s.toLongOrNull() ?: 0L

    // ---------------- 调用点参数提取 ----------------

    private data class CallSite(val expr: String, val args: List<Int>, val offset: Int?)

    /** 解码器调用点：(idx[, b]) 实参；返回 (原文表达式, 实参, 偏移实参) */
    private fun extractCallArgs(source: String, decoderName: String): List<CallSite> {
        if (decoderName.isBlank()) return emptyList()
        val re = Regex(
            Regex.escape(decoderName) + """\s*\(\s*(0x[0-9a-fA-F]{1,6}|\d{1,7})\s*(?:,\s*(0x[0-9a-fA-F]{1,6}|\d{1,7}))?\s*\)""",
        )
        return re.findAll(source).take(300).map { m ->
            val a = parseNum(m.groupValues[1]).toInt()
            val b = m.groupValues[2].takeIf { it.isNotBlank() }?.let { parseNum(it).toInt() }
            CallSite(m.value, listOf(a), b)
        }.toList()
    }

    // ---------------- 解码实现 ----------------

    private fun parseArrayElements(arrayDecl: String): List<String> =
        Regex("""(['"`])((?:\\.|(?!\1).)*)\1""")
            .findAll(arrayDecl)
            .map { unescapeJs(it.groupValues[2]) }
            .toList()

    private fun unescapeJs(s: String): String = s
        .replace("\\\\", "\\")
        .replace("\\'", "'")
        .replace("\\\"", "\"")
        .replace("\\n", "\n")
        .replace("\\r", "\r")
        .replace("\\t", "\t")
        .replace(Regex("""\\x([0-9a-fA-F]{2})""")) { it.groupValues[1].toInt(16).toChar().toString() }
        .replace(Regex("""\\u([0-9a-fA-F]{4})""")) { it.groupValues[1].toInt(16).toChar().toString() }

    private fun decodeBase64(el: String): String? {
        if (el.length < 4 || el.length % 4 != 0) return null
        if (!Regex("""^[A-Za-z0-9+/]+={0,2}$""").matches(el)) return null
        val bytes = runCatching { java.util.Base64.getDecoder().decode(el) }.getOrNull() ?: return null
        val text = bytes.map { it.toInt().toChar() }.joinToString("")
        return if (text.all { it.code == 9 || it.code in 32..126 }) text else null
    }

    private fun xorDecode(el: String, k: Long): String? {
        if (k <= 0 || k > 0xFFFF) return null
        val sb = StringBuilder()
        el.forEach { c ->
            val d = c.code.toLong() xor k
            if (d < 9 || d > 126) return null
            sb.append(d.toInt().toChar())
        }
        return if (sb.isEmpty()) null else sb.toString()
    }

    private fun caesarDecode(el: String, k: Long): String? {
        if (k == 0L) return null
        val sb = StringBuilder()
        el.forEach { c ->
            val d = c.code + k.toInt()
            if (d < 9 || d > 126) return null
            sb.append(d.toChar())
        }
        return if (sb.isEmpty()) null else sb.toString()
    }

    // ---------------- 沙箱脚本生成 ----------------

    /**
     * 生成自包含 IIFE：重放数组声明 + 解码函数声明 + 逐调用点求值。
     * 在目标页面 eval 后返回 JSON（含全部真实明文）。
     */
    fun sandboxScript(chain: StaticAnalyzer.DecryptChain, expressions: List<String>): String {
        val exprs = expressions.ifEmpty { chain.decodeCallSites.map { it.expression } }.take(200)
        val exprJson = exprs.joinToString(",") { jsQuote(it) }
        return buildString {
            append("(function(){\n")
            append("  var out = {ok:false, resolved:[], error:''};\n")
            append("  try {\n")
            append("    ").append(chain.arrayDecl.ifBlank { "/* 数组声明缺失 */" }).append("\n")
            append("    ").append(chain.decoderDecl.ifBlank { "/* 解码函数缺失 */" }).append("\n")
            append("    var exprs = [").append(exprJson).append("];\n")
            append("    for (var i = 0; i < exprs.length; i++) {\n")
            append("      try {\n")
            append("        var v = eval(exprs[i]);\n")
            append("        out.resolved.push({expr: exprs[i], value: (typeof v === 'string') ? v : String(v)});\n")
            append("      } catch(e) { out.resolved.push({expr: exprs[i], error: String(e && e.message || e)}); }\n")
            append("    }\n")
            append("    out.ok = true;\n")
            append("  } catch(e) { out.error = String(e && e.message || e); }\n")
            append("  return JSON.stringify(out);\n")
            append("})()")
        }
    }

    private fun jsQuote(s: String): String =
        "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r") + "\""

    // ---------------- 工具 ----------------

    private fun buildLineIndex(source: String): IntArray = buildList {
        add(0)
        var i = 0
        while (i < source.length) {
            if (source[i] == '\n' && i + 1 < source.length) add(i + 1)
            i++
        }
    }.toIntArray()

    private fun offsetToLine(lineStarts: IntArray, offset: Int): Int {
        var lo = 0; var hi = lineStarts.size - 1
        while (lo < hi) {
            val mid = (lo + hi + 1) / 2
            if (lineStarts[mid] <= offset) lo = mid else hi = mid - 1
        }
        return lo + 1
    }
}
