package com.webreverse.mcp.javascript.analysis

/**
 * 动态脱壳引擎（De-obfuscation Pass 管道）。
 *
 * 核心思路（静态+动态结合）：obfuscator.io 类壳的字符串解密函数
 * `_0x4a3f('0x1a')` 在页面运行时是活的——不需要逆向解密算法本身，
 * 直接在页面上下文调用它拿明文，然后回填源码。这是最高性价比的
 * "脱壳"：LLM 拿到的代码体积与噪音大幅下降。
 *
 * Pass 列表：
 * 1. 字符串解密还原：识别 `fn('0x1a')` / `fn(123)` 调用，页面内求值替换字面量
 * 2. 字符串拼接折叠："a"+"b" → "ab"（保守正则，仅纯字面量两侧）
 * 3. 十六进制数字归一：0x1a4 → 420（可选，默认关闭）
 * 4. 噪音剥离：debugger; 语句与 console 调用（可选）
 */
class Deobfuscator(
    /** 页面上下文求值回调：输入 JS 表达式，返回 JSON 字符串结果或 null */
    private val evaluate: suspend (String) -> String?,
) {

    data class Result(
        val code: String,
        val stringCallsDecrypted: Int,
        val stringsFolded: Int,
        val debuggerRemoved: Int,
        val notes: List<String>,
    )

    /** 解密调用模式：_0x1234('0x1a') / _0x1234(123) / xx(_0x12('a','b')) 只取直接形态 */
    private val callRe = Regex(
        """([A-Za-z_$][\w$]*)\(\s*(['"])(0x[0-9a-fA-F]+|\d{1,5})\2\s*\)""",
    )

    suspend fun deobfuscate(
        source: String,
        foldConcat: Boolean = true,
        removeDebugger: Boolean = false,
        hexToDecimal: Boolean = false,
    ): Result {
        val notes = mutableListOf<String>()
        // ---------- Pass 1: 字符串解密还原 ----------
        // 候选：调用名在源码中"像"解密函数（含 fromCharCode / parseInt / push/shift 特征）
        val candidates = callRe.findAll(source).groupBy { it.groupValues[1] }.filterKeys { it.length >= 3 }
        var decrypted = 0
        var out = source

        for ((fn, matches) in candidates) {
            // 全同名调用共享一次页面求值（批量 map）
            val args = matches.map { it.groupValues[3] }.distinct().take(400)
            if (args.isEmpty()) continue
            val arr = "[" + args.joinToString(",") { "\"$it\"" } + "]"
            val expr = "JSON.stringify((function(){try{var r={},a=$arr;for(var i=0;i<a.length;i++){try{r[String(a[i])]=String($fn(a[i]))}catch(e){}}return r}catch(e){return null}})())"
            val raw = evaluate(expr) ?: continue
            val map = parseSimpleMap(raw) ?: continue
            if (map.isEmpty()) continue
            // 命中率高才替换（防止把普通函数当解密器）
            val hitRatio = map.size.toDouble() / args.size
            if (hitRatio < 0.5) {
                notes.add("$fn: 命中率 ${"%.0f".format(hitRatio * 100)}%，跳过")
                continue
            }
            for ((arg, plain) in map) {
                val callPattern = Regex(
                    """${Regex.escape(fn)}\(\s*(['"])${Regex.escape(arg)}\1\s*\)""",
                )
                val literal = plain
                    .replace("\\", "\\\\")
                    .replace("\"", "\\\"")
                    .replace("\n", "\\n")
                    .replace("\r", "")
                out = callPattern.replace(out) { "\"$literal\"" }
                decrypted++
            }
            notes.add("$fn: 还原 ${map.size} 个字符串")
        }

        // ---------- Pass 2: 字符串拼接折叠 ----------
        var folded = 0
        if (foldConcat) {
            val concatRe = Regex(""""((?:[^"\\\n]|\\.)*)"\s*\+\s*"((?:[^"\\\n]|\\.)*)"""")
            var prev: String
            do {
                prev = out
                out = concatRe.replace(out) { m ->
                    folded++
                    "\"${m.groupValues[1]}${m.groupValues[2]}\""
                }
            } while (out != prev && folded < 5000)
        }

        // ---------- Pass 3: 噪音剥离 ----------
        var removed = 0
        if (removeDebugger) {
            out = out.replace(Regex("""\bdebugger\b\s*;?""")) { removed++; "" }
            out = out.replace(Regex("""\bconsole\.(log|debug|info|warn)\s*\([^)]{0,300}\)\s*;?""")) { removed++; "" }
        }

        // ---------- Pass 4: 十六进制归一 ----------
        if (hexToDecimal) {
            out = out.replace(Regex("""\b0x[0-9a-fA-F]{2,8}\b""")) { m ->
                m.value.toLongOrNull(16)?.toString() ?: m.value
            }
        }

        return Result(
            code = out,
            stringCallsDecrypted = decrypted,
            stringsFolded = folded,
            debuggerRemoved = removed,
            notes = notes,
        )
    }

    /** 解析 evaluate 返回的 {"arg": "plain"} JSON（容错） */
    private fun parseSimpleMap(raw: String): Map<String, String>? {
        // evaluateJavascript 返回的是 JSON 编码值（字符串会带外层引号且内部转义），
        // removeSurrounding 只去引号不反转义会解析失败 —— 必须走一次真正的 JSON 解码
        val trimmed = raw.trim()
        if (trimmed.isEmpty() || trimmed == "null") return null
        val decoded = runCatching {
            when (val el = kotlinx.serialization.json.Json.parseToJsonElement(trimmed)) {
                is kotlinx.serialization.json.JsonPrimitive -> el.content
                else -> trimmed
            }
        }.getOrDefault(trimmed)
        val element = runCatching {
            kotlinx.serialization.json.Json.parseToJsonElement(decoded).let { it as? kotlinx.serialization.json.JsonObject }
        }.getOrNull() ?: return null
        val out = LinkedHashMap<String, String>()
        for ((k, v) in element) {
            val value = (v as? kotlinx.serialization.json.JsonPrimitive)?.content ?: continue
            out[k] = value
        }
        return out
    }

    // ---------------- P2-10：纯 Kotlin 离线 pass ----------------

    /**
     * 离线反混淆结果（无需页面运行时，全部纯静态变换）。
     */
    data class OfflineResult(
        val code: String,
        val memberNotationFixed: Int,   // X['prop'] -> X.prop
        val booleanFolded: Int,         // !![] -> true / ![] -> false
        val voidFolded: Int,            // void 0x0 -> undefined
        val commaSequences: Int,        // (0,atob)(x) 逗号序列 -> atob(x)
        val deadBranchRemoved: Int,     // if(false){...} / if(!0){...} else 分支
        val notes: List<String>,
    )

    /**
     * 纯离线反混淆（ P2-10）：不依赖页面运行时的静态 pass 集。
     *
     * obfuscator.io 家族除字符串加密外的另一层噪音——成员访问括号化、
     * 布尔字面量替换、逗号序列间接调用（绕静态分析）——全部可用
     * 纯文本变换还原。适合：
     * - 无 CDP 会话的离线分析（file.read + 静态链）；
     * - 大文件预处理：先把噪音去掉，再喂 jsvmp.analyze 提高检测信噪比。
     */
    fun deobfuscateOffline(
        source: String,
        fixMemberNotation: Boolean = true,
        foldBoolean: Boolean = true,
        foldCommaSequence: Boolean = true,
        removeDeadBranch: Boolean = true,
    ): OfflineResult {
        val notes = mutableListOf<String>()
        var out = source

        // ---------- Pass A: 成员访问括号化还原 ----------
        // X['prop'] -> X.prop（仅还原合法标识符键；数字/表达式键保留）
        var memberFixed = 0
        if (fixMemberNotation) {
            val memberRe = Regex("""([\w$)\]])\s*\[\s*(['"])([A-Za-z_$][\w$]{0,30})\2\s*\]""")
            out = memberRe.replace(out) { m ->
                memberFixed++
                "${m.groupValues[1]}.${m.groupValues[3]}"
            }
            if (memberFixed > 0) notes.add("成员括号还原 $memberFixed 处（X['k'] -> X.k）")
        }

        // ---------- Pass B: 布尔字面量折叠 ----------
        // !![] -> true、![] -> false、!!0 -> false（0 为假）、!!1 -> true
        var bools = 0
        if (foldBoolean) {
            out = out.replace(Regex("""!\!\[\]""")) { bools++; "true" }
            out = out.replace(Regex("""(?<!\w)!\[\]""")) { bools++; "false" }
            out = out.replace(Regex("""(?<!\w)!\!0\b""")) { bools++; "false" }
            out = out.replace(Regex("""(?<!\w)!\!1\b""")) { bools++; "true" }
            if (bools > 0) notes.add("布尔字面量折叠 $bools 处")
        }

        // ---------- Pass C: void 折叠 ----------
        var voids = 0
        out = out.replace(Regex("""\bvoid\s+0x0\b""")) { voids++; "undefined" }
        if (voids > 0) notes.add("void 0x0 -> undefined 共 $voids 处")

        // ---------- Pass D: 逗号序列间接调用还原 ----------
        // (0, atob)(x) -> atob(x)：常见于绕过 this 绑定的反检测写法
        var commas = 0
        if (foldCommaSequence) {
            val commaRe = Regex("""\(\s*(?:0x[0-9a-fA-F]+|\d+)\s*,\s*([\w$.]{1,40})\s*\)\s*\(""")
            out = commaRe.replace(out) { m ->
                commas++
                "${m.groupValues[1]}("
            }
            if (commas > 0) notes.add("逗号序列还原 $commas 处（(0,fn)(x) -> fn(x)）")
        }

        // ---------- Pass E: 常量条件死分支删除 ----------
        // if (false) {...} / if (!0) {...} else {...}（保守：只处理已折叠的布尔）
        var dead = 0
        if (removeDeadBranch) {
            val ifFalseRe = Regex("""if\s*\(\s*false\s*\)\s*\{""")
            while (true) {
                val m = ifFalseRe.find(out) ?: break
                val body = matchBraces(out, m.range.last) ?: break
                val end = body.second
                // 含 else 则保留 else 分支体（去掉 else 关键字，只留体内容）
                val after = out.substring(end + 1)
                val elseM = Regex("""^\s*else\s*\{""").find(after)
                if (elseM != null) {
                    val elseBody = matchBraces(after, elseM.range.last) ?: break
                    val keep = after.substring(elseBody.first + 1, elseBody.second).trim()
                    val cutEnd = end + 1 + elseBody.second
                    out = out.substring(0, m.range.first) + keep + out.substring(cutEnd + 1)
                } else {
                    out = out.substring(0, m.range.first) + out.substring(end + 1)
                }
                dead++
                if (dead > 500) break
            }
            if (dead > 0) notes.add("死分支删除 $dead 处（if(false)）")
        }

        return OfflineResult(
            code = out,
            memberNotationFixed = memberFixed,
            booleanFolded = bools,
            voidFolded = voids,
            commaSequences = commas,
            deadBranchRemoved = dead,
            notes = notes,
        )
    }

    /** 从 `{` 位置配对到 `}`：返回 (openIdx, closeIdx)；不配对返回 null */
    private fun matchBraces(s: String, openIdx: Int): Pair<Int, Int>? {
        if (openIdx < 0 || openIdx >= s.length || s[openIdx] != '{') return null
        var depth = 0
        var inStr: Char? = null
        var i = openIdx
        while (i < s.length) {
            val c = s[i]
            when {
                inStr != null -> {
                    if (c == '\\') i++ // 跳过转义
                    else if (c == inStr) inStr = null
                }
                c == '"' || c == '\'' || c == '`' -> inStr = c
                c == '{' -> depth++
                c == '}' -> {
                    depth--
                    if (depth == 0) return openIdx to i
                }
            }
            i++
        }
        return null
    }
}
