package com.webreverse.mcp.javascript.analysis

/**
 * JSVMP（JS 虚拟机保护）静态探测器 v2。
 *
 * v2 相比 v1 的关键改进（对应评审报告 2.2/2.4）：
 * 1. **输出 column**：minified 单行文件里行断点形同虚设，V8 需要列号才能
 *    打进 dispatch 循环。候选同时携带 line+column，直接喂给
 *    setBreakpointByUrl(columnNumber)。
 * 2. **opcode → case handler 切片**：自动提取 dispatch switch 内每个
 *    `case 0xNN:` 分支的代码体——"这个 opcode 干了什么"的语义信息，
 *    与 trace 的 opcode 频次关联后直接喂 LLM。
 * 3. minified 场景不再整窗统计：特征窗口收敛到 switch 体内部。
 */
class VmpDetector {

    /**
     * 报17：JSVMP/混淆器家族指纹。识别出可能是哪种保护后，
     * 上层可据此选择对应的语义恢复器（JsvmpDeepAnalyzer / VmpDecompiler / DecryptSimulator 等）。
     */
    data class VmpFingerprint(
        val family: String,                    // 判定家族：jsvmp / _0x-obfuscator / sojson / control-flow-flatten / plain
        val confidence: Int,                   // 0-100
        val reasons: List<String>,             // 判定依据
        val dispatchStyle: String = "none",    // 派发风格：switch / if-tree / array / none
        val suggestedRecovery: List<String> = emptyList(), // 建议使用的恢复工具
    )

    /**
     * （验证度量 / 方向1）：对某段源码的"可信判定明细"。
     * reliability 是对 AI 的信任建议：
     * - high-BENIGN：判定为未混淆/轻混淆（验证"不是 VMP"）
     * - high：正证据强且无负证据（可直接采信家族）
     * - medium / low：存在状态机等反误报证据，需人工复核后再投入深水还原
     */
    data class VmpVerdict(
        val family: String,
        val confidence: Int,
        val reliability: String,          // high-BENIGN / high / medium / low
        val supporting: List<String>,     // 正向判定依据
        val contradicting: List<String>,  // 负向（反 VMP）证据，空数组=未发现矛盾
        val dispatchStyle: String = "none",
    )

    data class VmpCandidate(
        val line: Int,          // 1-based，dispatch 循环起始行
        val column: Int,        // 1-based，match 起点（minified 单行时即 offset+1）
        val switchLine: Int,    // switch 语句位置（decision-tree 风格时为首分支位置）
        val switchColumn: Int,
        val score: Int,         // 置信度 0-100
        val reasons: List<String>,
        val suggestedOps: List<String>,      // 疑似 opcode/pc 变量名
        val caseCount: Int,
        val handlers: List<OpHandler>,       // opcode -> case 体切片
        // P1-5：派发风格。switch = while+switch 经典派发；
        // if-tree = if/else-if 比较链派发（switch 检测盲区，混淆器二线形态）
        val dispatchStyle: String = "switch",
    )

    data class OpHandler(
        val key: String,     // "0x1a" / "26" / "default"
        val snippet: String, // case 体源码（截断）
        val line: Int,
        val column: Int,
    )

    /** 最多保留的 handler 数量（防爆内存） */
    private val maxHandlers = 120

    fun detect(source: String): List<VmpCandidate> {
        // 性能修复：超大 minified 脚本（> 400KB）逐个主体做“全源码二次扫描”会导致
        // detectDecisionTree 退化到 O(N×n)，在 MCP 请求超时内无法完成。这里做两层约束：
        // 1) 截断：仅扫描前 SCAN_BUDGET 字符（JSVMP 派发循环通常位于脚本中前部/顶部）；整脚本
        //    行号/列号仍按截断后源码计算，命中行对后续 trace_vmp 是相对行，有据可查。
        // 2) 预算：各检测器内部再按“候选个数/扫描次数”上限提前退出，避免巨源堆量。
        val SCAN_BUDGET = 600_000
        val scoped = if (source.length > SCAN_BUDGET) source.substring(0, SCAN_BUDGET) else source

        val switchCandidates = detectSwitchDispatchWithBudget(scoped)
        val treeCandidates = detectDecisionTreeWithBudget(scoped)
        // 数组派发形态（handlers[bc[pc++]]）——混淆器三线形态
        val arrayCandidates = detectArrayDispatchWithBudget(scoped)
        // 去重：decision-tree 与 switch 位置重叠时保留高分者
        val merged = switchCandidates.toMutableList()
        treeCandidates.forEach { tree ->
            val overlap = merged.any { m ->
                kotlin.math.abs(m.switchLine - tree.switchLine) <= 2 &&
                    kotlin.math.abs(m.switchColumn - tree.switchColumn) < 200
            }
            if (!overlap) merged.add(tree)
        }
        arrayCandidates.forEach { arr ->
            val overlap = merged.any { m ->
                kotlin.math.abs(m.switchLine - arr.switchLine) <= 2 &&
                    kotlin.math.abs(m.switchColumn - arr.switchColumn) < 200
            }
            if (!overlap) merged.add(arr)
        }
        return merged.sortedByDescending { it.score }
    }

    /**
     * 识别"状态机误报"家族——`while+switch` / `if-else` 状态机形态，
     * 常被误判为 JSVMP dispatch，但实为普通库代码：
     * - zlib/inflate 解压状态机（opcode 实为 inflate 状态常量，case 体是位缓冲拆包逻辑）
     * - babel regenerator async/await 编译产物（`_context.n = N; break;` 的协程状态机）
     *
     * 命中即返回家族名（上层直接跳过该候选，避免脏候选污染 fingerprint/detect_vmp 判定）。
     *
     * @param switchBody switch 体窗口源码
     * @param lookBack  heading 循环上下文（含取指表达式）
     */
    private fun stateMachineFamily(switchBody: String, lookBack: String): String? {
        // --- zlib/inflate ---
        // 硬编码解压错误消息是强特异性信号：真 JSVMP 字节码处理器不会内嵌这些英文错误串。
        val zlibErrorMarkers = listOf(
            "unknown compression method", "header crc mismatch", "invalid distance too far back",
            "invalid stored block lengths", "invalid block type", "invalid block type",
            "too many length or distance code", "incorrect length check", "invalid window size",
            "need more distance code", "invalid code lengths set", "unexpected end-of-file",
            "invalid flush mode", "invalid literal/length code", "invalid distance code",
            "invalid previous length", "invalid root symbol", "invalid code",
        )
        val zlibErrHits = zlibErrorMarkers.count { m ->
            switchBody.contains(m) || lookBack.contains(m)
        }
        if (zlibErrHits > 0) return "zlib-inflate"
        // 若干典型 inflate 结构字段同时出现（pako 压缩为 next_out/avail_in 前缀，原版为 n. 前缀）
        val inflateFields = listOf(
            "next_out", "avail_in", "avail_out", "nn.next_out", "n.whave", "n.wnext",
            "n.wsize", "lencode", "distcode", "n.hold", "n.bits", "n.total_out", "t.adler",
            "n.havedict", "n.flags", "n.wrap", "n.sane", "n.dmax", "n.lencode", "n.lendyn",
        )
        val inflateFieldHits = inflateFields.count { switchBody.contains(it) }
        if (inflateFieldHits >= 2) return "zlib-inflate"

        // --- babel regenerator async/await 状态机 ---
        // `_context.n = N; break;` / `_context2.a(2, ...)` / `_callee` / regeneratorRuntime
        if (Regex("""_context\d*\.n\s*=\s*\d+""").containsMatchIn(switchBody) ||
            Regex("""_context\d*\.a\(\s*\d+""").containsMatchIn(switchBody) ||
            switchBody.contains("_callee") ||
            switchBody.contains("regeneratorRuntime") ||
            Regex("""_context\d*\.(prev|next|sent|done|abrupt)\b""").containsMatchIn(switchBody)
        ) {
            return "babel-regenerator"
        }
        return null
    }

    /**
     * 报17：对源码做混淆器/VM 家族指纹判定。
     *
     * 返回 { family, confidence, reasons, dispatchStyle, suggestedRecovery }，
     * 供上层（VmpTools/AI 编排）选择后续恢复策略。
     */
    fun fingerprint(source: String): VmpFingerprint {
        val s = source
        if (s.length < 64) {
            return VmpFingerprint("plain", 90, listOf("源码过短，通常未做 VM/强度混淆"), "none", listOf("normal"))
        }

        val dispatchCandidates = detect(s)
        val style = dispatchCandidates.firstOrNull()?.dispatchStyle ?: "none"
        val reasons = dispatchCandidates.take(3).map { "检测到${it.dispatchStyle}派发：行${it.line} 列${it.column} 分数${it.score}" }.toMutableList()

        val scores = linkedMapOf<String, Int>()
        fun bump(family: String, n: Int) { scores[family] = (scores[family] ?: 0) + n }

        // JSVMP 系
        if (style != "none") bump("jsvmp", 20)
        if (Regex("""\[\s*[a-zA-Z_$][\w$]*\s*\+\+\s*\]""").containsMatchIn(s)) { bump("jsvmp", 16); reasons += "存在 opcode 取址 pc++ 模式" }
        if (Regex("""\b(dispatch|dispatcher|opcode)\b""", RegexOption.IGNORE_CASE).containsMatchIn(s)) { bump("jsvmp", 6) }
        if ((s.count { it == '[' } > 40) && Regex("""=\s*\[[^\];]{60,}\]""").containsMatchIn(s)) { bump("jsvmp", 8); reasons += "存在大型 handler/常量数组" }

        // obfuscator.io / _0x 系列
        val hexVars = Regex("""\b_0x[0-9a-fA-F]{3,5}\b""").findAll(s).count()
        if (hexVars >= 4) { bump("_0x-obfuscator", minOf(12, hexVars)); reasons += "≥4 个 _0x<hex> 变量（obfuscator.io 特征）" }
        if (Regex("""String\s*\[\s*[`'"]*fromCharCode[`'"]*\s*\]""").containsMatchIn(s)) { bump("_0x-obfuscator", 10); reasons += "String.fromCharCode 动态解码" }
        if (Regex("""[`'"]?concat[`'"]?\s*\(|\.concat\(""").containsMatchIn(s)) { bump("_0x-obfuscator", 4) }

        // sojson 系
        if (Regex("""while\s*\(\s*!!\[\]\s*\)""").containsMatchIn(s)) { bump("sojson", 16); reasons += "while(!![]) 防调试大循环（sojson 特征）" }
        if (Regex("""\bde\d+|\bfromCharCode\b|\beval\(""", RegexOption.IGNORE_CASE).containsMatchIn(s) && hexVars > 0) { bump("sojson", 6) }

        // 控制流平坦化（无明确派发但分支极多）
        if (style == "none" && Regex("""\bif\b""").findAll(s).count() >= 12) { bump("control-flow-flatten", 8); reasons += "无派发但分支过多，疑似控制流平坦化" }

        val best = scores.maxByOrNull { it.value }
        if (best == null || best.value < 12) {
            return VmpFingerprint(
                "plain/light-obfuscation", maxOf(20, 100 - (best?.value ?: 0)),
                reasons.ifEmpty { listOf("未发现显著的 VM/混淆特征") }, style, listOf("normal"),
            )
        }
        val recovery = when (best.key) {
            "jsvmp" -> listOf("JsvmpDeepAnalyzer", "VmpDecompiler", "JsvmpSemanticRecovery")
            else -> listOf("DecryptSimulator", "semantic-recovery", "manual-trace")
        }
        return VmpFingerprint(best.key, minOf(99, best.value), reasons, style, recovery)
    }

    /**
     * 可信度校验（验证度量）。在 fingerprint 之上补齐【正/负双向证据】与
     * reliability 分级，供 AI 决定"本次判定能否直接采信、是否需人工复核"。
     * - 负向证据来自 VmpCandidate#handlers 的 case 体切片（zlib/inflate 结构字段、
     *   babel regenerator 协程状态机、regeneratorRuntime/_callee）。
     * - 整档再做一次 stateMachineFamily 反误报扫描作为跨候选兜底。
     */
    fun verify(source: String): VmpVerdict {
        val fp = fingerprint(source)
        val candidates = detect(source)
        val supporting = fp.reasons.toMutableList()
        val contradicting = mutableListOf<String>()
        val top = candidates.firstOrNull()
        if (top != null) {
            supporting.add(
                0,
                "命中 ${top.dispatchStyle} 派发候选：行${top.line}:${top.column}，${top.caseCount} 个 case，score=${top.score}",
            )
            val body = top.handlers.joinToString("\n") { it.snippet }
            val zlibHits = listOf(
                "unknown compression method", "avail_in", "next_out", "lencode", "distcode",
                "inflate", "adler", "n.hold", "n.bits",
            ).count { body.contains(it) }
            if (zlibHits >= 2) contradicting.add(
                "候选含 zlib/inflate 结构字段($zlibHits 处)，疑似解压状态机而非 JSVMP dispatch",
            )
            if (Regex("""_context\d*\.n\s*=\s*\d+""").containsMatchIn(body)) {
                contradicting.add("候选 case 含 babel regenerator 协程状态机（_context.n=N; break;）")
            }
            if (body.contains("_callee") || body.contains("regeneratorRuntime")) {
                contradicting.add("候选含 regeneratorRuntime/_callee，疑似 async/await 编译产物")
            }
        }
        // 整档反误报兜底（仅当顶层候选未覆盖时给出提示）
        val scoped = if (source.length > 600_000) source.substring(0, 600_000) else source
        val fpFam = stateMachineFamily(scoped, "")
        if (fpFam != null && contradicting.isEmpty()) {
            contradicting.add("整档含 ${fpFam} 状态机特征（检测层已内置过滤；若家族置信度不高建议人工复核）")
        }
        val reliability = when {
            fp.family.contains("plain") || fp.family.contains("light") -> "high-BENIGN"
            contradicting.isEmpty() && fp.confidence >= 70 -> "high"
            contradicting.size == 1 -> "medium"
            else -> "low"
        }
        return VmpVerdict(fp.family, fp.confidence, reliability, supporting, contradicting, fp.dispatchStyle)
    }

    /**
     * 数组派发（array-of-handlers）检测。
     *
     * 混淆器对抗 switch/if-tree 特征扫描的三线形态：把 handler 函数放进一个数组，
     * 派发循环用 opcode 直接索引调用：
     * ```
     * var _h = [function(){...}, function(){...}, ...];   // handler 数组
     * while (1) { _h[_bc[_pc++]](); }                      // 数组派发
     * ```
     * 识别要点：
     * - 数组字面量含大量函数引用（函数表达式或 handler 标识符）
     * - 存在 `arr[bc[pc++]]()` / `arr[opcode]()` 派发调用
     * - 外层无条件循环包裹
     */
    private fun detectArrayDispatchWithBudget(source: String): List<VmpCandidate> {
        if (source.isBlank()) return emptyList()

        val lineStarts = buildList {
            add(0)
            var i = 0
            while (i < source.length) {
                if (source[i] == '\n' && i + 1 < source.length) add(i + 1)
                i++
            }
        }
        fun offsetToLineCol(offset: Int): Pair<Int, Int> {
            var lo = 0; var hi = lineStarts.size - 1
            while (lo < hi) {
                val mid = (lo + hi + 1) / 2
                if (lineStarts[mid] <= offset) lo = mid else hi = mid - 1
            }
            return (lo + 1) to (offset - lineStarts[lo] + 1)
        }

        val loopRe = Regex("""while\s*\(\s*(!!?\s*[]\d]|1\b|true\b|_?[a-zA-Z_$][\w$.]*\s*[<>=!]+\s*)|for\s*\(\s*;;\s*\)""")
        // 数组声明：var NAME = [ ... ]
        val arrayDeclRe = Regex("""(?:var|let|const)\s+([A-Za-z_$][\w$]{0,20})\s*=\s*\[""")
        // 派发调用：NAME[bc[pc++]]() / NAME[opcode]() / NAME[bc[pc]]()
        val dispatchRe = Regex(
            """([A-Za-z_$][\w$]{0,20})\s*\[\s*([A-Za-z_$][\w$]{0,20})\s*\[\s*([A-Za-z_$][\w$]{0,20})\s*(?:\+\+)?\s*\]\s*\]\s*\(\s*\)""",
        )

        val out = mutableListOf<VmpCandidate>()
        val seenArrays = mutableSetOf<String>()

        // 性能预算：超大 minified 脚本里 `var X = [` 声明可能成百上千，
        // 每个候选都要 findArrayEnd 前向扫描 + full-source 的 dispatch 调用扫描（O(N)）。
        // 限制参与评估的数组总数，并在数组声明附近范围内搜索派发调用点，
        // 收紧：minified 大包 `var X = [` 可成百上千，每个候选都要 findArrayEnd 前向扫描
        // + 数组后窗口调用点扫描。限制评估总数与前向扫描距离，确保无派发巨源在请求超时内完成。
        var arrayBudget = 24
        val callSearchSpan = 250_000

        for (decl in arrayDeclRe.findAll(source)) {
            if (arrayBudget-- <= 0) break
            val arrName = decl.groupValues[1]
            if (arrName in seenArrays) continue

            // 提取数组字面量内容（到匹配的 ]）
            val arrStart = decl.range.last + 1
            val arrEnd = findArrayEnd(source, arrStart)
            if (arrEnd <= arrStart) continue
            val arrBody = source.substring(arrStart, arrEnd)

            // 统计数组内函数引用（function 表达式 / 标识符）
            val fnExprCount = Regex("""function\s*\(""").findAll(arrBody).count()
            val idRefs = Regex("""[A-Za-z_$][\w$]{0,20}""").findAll(arrBody)
                .map { it.value }.distinct().count()
            val totalElements = Regex(""",""").findAll(arrBody).count() + 1
            if (fnExprCount < 4 && idRefs < 4) continue
            if (totalElements < 6) continue

            // 找该数组的派发调用点（数组名被 `arr[expr]()` 索引调用）
            val esc = Regex.escape(arrName)
            val callRe = Regex("""$esc\s*\[\s*[^\]]{1,60}\]\s*\(\s*\)""")
            // 性能约束：不在整源码上做调用点扫描（对每个候选数组都是 O(N)），
            // 只在「数组字面量结束 + 前向一个固定窗口」内搜索派发调用，派发循环通常在
            // handler 数组声明之后的紧邻循环里，窗口足够覆盖。
            val callStart = arrEnd.coerceAtMost(source.length)
            val callSearchEnd = (callStart + callSearchSpan).coerceAtMost(source.length)
            val callWindow = source.substring(callStart, callSearchEnd)
            val windowCall = callRe.findAll(callWindow).firstOrNull()
            if (windowCall == null) continue
            val firstCall = windowCall.range.first + callStart

            // 检查任一调用点在无条件循环内
            val lookBack = source.substring((firstCall - 600).coerceAtLeast(0), firstCall)
            val loopMatch = loopRe.findAll(lookBack).lastOrNull()
            if (loopMatch == null) continue

            // 确认是字节码索引派发（下标含数组访问）或 opcode 变量
            val dispatchSample = windowCall.value
            val isBytecodeIndexed = dispatchRe.containsMatchIn(dispatchSample) ||
                dispatchSample.contains('[') && dispatchSample.contains(']')

            // 提取 handler 切片（数组元素）
            val handlers = extractArrayHandlers(arrBody)

            var score = 25
            val reasons = mutableListOf<String>()
            reasons.add("array-of-handlers dispatch：handler 数组 $totalElements 元素（函数表达式×$fnExprCount）")
            if (totalElements >= 30) { score += 30; reasons.add("数组规模 $totalElements（典型 JSVMP 规模）") }
            else if (totalElements >= 12) { score += 20; reasons.add("数组规模 $totalElements") }
            else score += 12
            score += 20; reasons.add("无条件循环 ${loopMatch.value.trim()} 内数组索引调用 $arrName[expr]()")
            if (isBytecodeIndexed) { score += 10; reasons.add("下标为字节码数组访问（bc[pc++] 型）——强特征") }
            if (source.contains("Math.imul")) { score += 5; reasons.add("Math.imul（VM 常用乘法原语）") }
            if (source.contains("fromCharCode")) { score += 5; reasons.add("fromCharCode（字符串表解密）") }

            val (sLine, sCol) = offsetToLineCol(decl.range.first)
            val (lLine, lCol) = offsetToLineCol(lookBackStartOf(lookBack, loopMatch))
            seenArrays.add(arrName)
            out.add(
                VmpCandidate(
                    line = lLine,
                    column = lCol,
                    switchLine = sLine,
                    switchColumn = sCol,
                    score = score.coerceAtMost(100),
                    reasons = reasons,
                    suggestedOps = extractArrayVars(dispatchSample),
                    caseCount = totalElements,
                    handlers = handlers,
                    dispatchStyle = "array",
                ),
            )
            if (out.size >= 3) break
        }
        return out
    }

    /** 从 `var X = [` 起始 offset 找到匹配的数组结束 `]`；maxScan 限制前向扫描距离，防巨源内假候选拖垮。 */
    private fun findArrayEnd(source: String, start: Int, maxScan: Int = 120_000): Int {
        val limit = (start + maxScan).coerceAtMost(source.length)
        var depth = 0
        var i = start
        var strip = '\u0000'
        while (i < limit) {
            val c = source[i]
            if (strip != '\u0000') {
                if (c == '\\') i++
                else if (c == strip) strip = '\u0000'
            } else {
                when (c) {
                    '"', '\'' -> strip = c
                    '[' -> depth++
                    ']' -> {
                        depth--
                        if (depth == 0) return i
                    }
                }
            }
            i++
        }
        return -1
    }

    /** 提取 handler 数组元素为 OpHandler 切片 */
    private fun extractArrayHandlers(arrBody: String): List<OpHandler> {
        val handlers = mutableListOf<OpHandler>()
        val parts = splitTopLevelCommas(arrBody)
        parts.take(maxHandlers).forEachIndexed { idx, p ->
            val t = p.trim()
            if (t.isEmpty()) return@forEachIndexed
            handlers.add(
                OpHandler(
                    key = idx.toString(),
                    snippet = t.take(220),
                    line = 0,
                    column = 0,
                ),
            )
        }
        return handlers
    }

    /** 顶层逗号切分（尊重 ()[]{} 与字符串） */
    private fun splitTopLevelCommas(s: String): List<String> {
        val out = mutableListOf<String>()
        val sb = StringBuilder()
        var depth = 0
        var i = 0
        var strip = '\u0000'
        while (i < s.length) {
            val c = s[i]
            if (strip != '\u0000') {
                sb.append(c)
                if (c == '\\') { i++; if (i < s.length) sb.append(s[i]) }
                else if (c == strip) strip = '\u0000'
            } else {
                when {
                    c == '"' || c == '\'' -> { strip = c; sb.append(c) }
                    c == '(' || c == '[' || c == '{' -> { depth++; sb.append(c) }
                    c == ')' || c == ']' || c == '}' -> { depth = maxOf(0, depth - 1); sb.append(c) }
                    c == ',' && depth == 0 -> { if (sb.isNotBlank()) out.add(sb.toString()); sb.clear() }
                    else -> sb.append(c)
                }
            }
            i++
        }
        if (sb.isNotBlank()) out.add(sb.toString())
        return out
    }

    /** 计算循环匹配在 lookBack 内的绝对 offset（用于行号） */
    private fun lookBackStartOf(lookBack: String, loopMatch: MatchResult): Int {
        return loopMatch.range.first
    }

    /**
     * P1-5：decision-tree dispatcher 检测。
     *
     * 混淆器对抗 switch 特征扫描的二线形态：同一变量与一串常量做
     * 相等比较的 if/else-if 链（编译器视角就是手写跳转表）：
     * `if(bc[pc]===0x1){...}else if(bc[pc]===0x2){...}...`
     * 识别要点：
     * - 同一比较主体（如 bc[pc++]）重复出现 >= 6 次
     * - 比较常量各不相同且均为小整数/hex
     * - 外层有无条件循环包裹（与 switch 版同要求）
     */
    private fun detectDecisionTreeWithBudget(source: String): List<VmpCandidate> {
        if (source.isBlank()) return emptyList()

        // 行首 offset 表（复用 switch 版逻辑）
        val lineStarts = buildList {
            add(0)
            var i = 0
            while (i < source.length) {
                if (source[i] == '\n' && i + 1 < source.length) add(i + 1)
                i++
            }
        }
        fun offsetToLineCol(offset: Int): Pair<Int, Int> {
            var lo = 0; var hi = lineStarts.size - 1
            while (lo < hi) {
                val mid = (lo + hi + 1) / 2
                if (lineStarts[mid] <= offset) lo = mid else hi = mid - 1
            }
            return (lo + 1) to (offset - lineStarts[lo] + 1)
        }

        // if (X === K) / if (K === X) / if (X == K)，X 为任意标识符表达式（含取值）
        val condRe = Regex(
            """if\s*\(\s*([A-Za-z_$][\w$.\[\]]{1,30}?)\s*(?:={2,3}|!==?)\s*(0x[0-9a-fA-F]{1,6}|\d{1,6})\s*\)|if\s*\(\s*(0x[0-9a-fA-F]{1,6}|\d{1,6})\s*(?:={2,3}|!==?)\s*([A-Za-z_$][\w$.\[\]]{1,30}?)\s*\)""",
        )
        val loopRe = Regex("""while\s*\(\s*(!!?\s*[]\d]|1\b|true\b)|for\s*\(\s*;;\s*\)""")

        data class Branch(val const: String, val offset: Int, val nextOffset: Int)

        val out = mutableListOf<VmpCandidate>()
        // 性能修复：原实现每个主体都对全源码做 sameSubjectRe 二次扫描（O(N×n)），
        // 在 1.7MB minified 分批大包（如 mihuashi index.DNkyQQNg.js）上必然 30s 超时。
        // 改单遍分组：一次 condRe 全量匹配先按「比较主体」归组，再对分支数最多的候选组做评估，
        // 整体从 O(N×n) 退化为 O(N)。代价：只认 `if (X === K)` 形式的比较链（决策树派发主流形态），
        // 不再捕获 `X===K1||X===K2` 内联三元链——换取在 MCP 请求超时内必须完成的确定性。
        val groups = linkedMapOf<String, MutableList<Branch>>()
        for (m in condRe.findAll(source)) {
            val subject = (m.groupValues[1].ifBlank { m.groupValues[4] }).trim()
            if (subject.isBlank()) continue
            val const = m.groupValues[2].ifBlank { m.groupValues[3] }
            groups.getOrPut(subject) { mutableListOf() }.add(Branch(const, m.range.first, m.range.last + 1))
        }
        // 预算：只评估「至少有 6 个不同常量」且分支数最多的候选组，限定组总数
        val subjectBudget = 24
        val rankedGroups = groups.entries
            .filter { it.value.map { b -> b.const }.distinct().size >= 6 }
            .sortedByDescending { it.value.size }
            .take(subjectBudget)

        for ((subject, branches) in rankedGroups) {
            val distinctConsts = branches.map { it.const }.distinct()
            if (distinctConsts.size < 6) continue

            // 外层循环上下文（向前 600 字符）
            val firstOffset = branches.first().offset
            val lookBack = source.substring((firstOffset - 600).coerceAtLeast(0), firstOffset)
            val hasLoop = loopRe.containsMatchIn(lookBack)
            if (!hasLoop) continue

            // 分支体：当前比较结束 -> 下一分支开始
            val handlers = branches.withIndex().mapNotNull { (idx, b) ->
                val bodyEnd = branches.getOrNull(idx + 1)?.offset
                    ?: (b.nextOffset + 1200).coerceAtMost(source.length)
                val raw = source.substring(b.nextOffset, bodyEnd)
                    .replace(Regex("""^\s*(\?\s*)?"""), "")
                    .replace(Regex("""\s+"""), " ")
                    .trim()
                    .trimStart(':').trim()
                if (raw.isEmpty()) null
                else OpHandler(
                    key = b.const,
                    snippet = raw.take(220),
                    line = offsetToLineCol(b.offset).first,
                    column = offsetToLineCol(b.offset).second,
                )
            }

            // 状态机误报过滤（在 decision-tree 中同样可能命中 zlib/babel 状态机）
            val regionSource = source.substring(
                (firstOffset - 400).coerceAtLeast(0),
                (branches.last().offset + 400).coerceAtMost(source.length),
            )
            val fpFamily = stateMachineFamily(regionSource, lookBack)
            if (fpFamily != null) continue

            var score = 25
            val reasons = mutableListOf<String>()
            reasons.add("decision-tree dispatch：if/else-if 比较链 ${distinctConsts.size} 分支（switch 检测盲区形态）")
            if (distinctConsts.size >= 20) { score += 30; reasons.add("分支规模 ${distinctConsts.size}（典型 JSVMP 规模）") }
            else if (distinctConsts.size >= 12) { score += 20; reasons.add("分支规模 ${distinctConsts.size}") }
            else score += 12
            score += 15; reasons.add("同一比较主体 $subject 重复出现")
            if (distinctConsts.count { it.startsWith("0x") } >= 4) {
                score += 10; reasons.add("hex 比较常量 ${distinctConsts.count { it.startsWith("0x") }} 个（dispatch 强特征）")
            }
            if (source.contains("Math.imul")) { score += 5; reasons.add("Math.imul（VM 常用乘法原语）") }

            // 建议变量：比较主体 + 派发区段内的数组访问（如 _0xbc[_0xpc++]）
            val region = source.substring(
                (firstOffset - 300).coerceAtLeast(0),
                (branches.last().offset + 300).coerceAtMost(source.length),
            )
            val suggested = (extractArrayVars(subject) + extractArrayVars(region)).distinct().take(6)

            val (sLine, sCol) = offsetToLineCol(firstOffset)
            out.add(
                VmpCandidate(
                    line = sLine,
                    column = sCol,
                    switchLine = sLine,
                    switchColumn = sCol,
                    score = score.coerceAtMost(100),
                    reasons = reasons,
                    suggestedOps = suggested,
                    caseCount = distinctConsts.size,
                    handlers = handlers,
                    dispatchStyle = "if-tree",
                ),
            )
            if (out.size >= 3) break
        }
        return out
    }

    /** 从判别式（如 `_0xbc[_0xpc++]`）提取数组/pc 变量名 */
    private fun extractArrayVars(subject: String): List<String> =
        Regex("""([A-Za-z_$][\w$]{0,12})\s*\[|"([A-Za-z_$][\w$]{0,12})"""")
            .findAll(subject)
            .map { it.groupValues[1].ifBlank { it.groupValues[2] } }
            .filter { it.isNotBlank() }
            .distinct()
            .take(6)
            .toList()

    private fun detectSwitchDispatchWithBudget(source: String): List<VmpCandidate> {
        if (source.isBlank()) return emptyList()

        val loopRe = Regex("""while\s*\(\s*(!!?\s*[]\d]|1\b|true\b|_?[a-zA-Z_$][\w$.]*\s*[<>=!]+\s*)|for\s*\(\s*;;\s*\)""")
        val switchRe = Regex("""\bswitch\s*\(""")
        val caseHeadRe = Regex("""\bcase\s+(0x[0-9a-fA-F]{1,6}|\d{1,6}|['"][\w+-]{1,4}['"])\s*:""")
        val hexLitRe = Regex("""0x[0-9a-fA-F]{1,4}\b""")
        val vmpVarRe = Regex(
            """\b(_?0x[0-9a-fA-F]+|(?:op|code|bytecode|opcode|pc|sp|ip|ctx|ins|instr)\w{0,4})\s*\[""",
        )

        // 行首 offset 表：行号 <-> offset 互转（一次构建，O(n)）
        val lineStarts = buildList {
            add(0)
            var i = 0
            while (i < source.length) {
                if (source[i] == '\n' && i + 1 < source.length) add(i + 1)
                i++
            }
        }
        fun offsetToLineCol(offset: Int): Pair<Int, Int> {
            // 二分找所在行
            var lo = 0; var hi = lineStarts.size - 1
            while (lo < hi) {
                val mid = (lo + hi + 1) / 2
                if (lineStarts[mid] <= offset) lo = mid else hi = mid - 1
            }
            return (lo + 1) to (offset - lineStarts[lo] + 1)
        }

        val candidates = mutableListOf<VmpCandidate>()
        // 每个 switch 只评估一次（以 switch offset 为 key 去重）
        val seenSwitches = mutableSetOf<Int>()

        // 性能预算：即使没有派发形态，也不对上千个 switch 逐一做 case/循环判定，
        // 限制评估总数（成本集中在 headRe 窗口扫描与正则匹配）。
        var evalBudget = 40

        for (switchMatch in switchRe.findAll(source)) {
            if (evalBudget-- <= 0) break
            val switchOffset = switchMatch.range.first
            if (!seenSwitches.add(switchOffset)) continue

            // switch 判别式 + 循环上下文：向上回看 400 字符找无条件循环
            val lookBackStart = (switchOffset - 400).coerceAtLeast(0)
            val lookBack = source.substring(lookBackStart, switchOffset)
            val loopMatch = loopRe.findAll(lookBack).lastOrNull() ?: continue

            // case 体窗口：从 switch 判别式开始，到该 switch 后第 3 个 case 结束或 +20000 字符
            val switchRegion = source.substring(switchOffset, (switchOffset + 24_000).coerceAtMost(source.length))
            val caseMatches = caseHeadRe.findAll(switchRegion).take(400).toList()
            // /：最小 case 数从 4 降为 2，避免小规模合法 dispatcher（如
            // while(pc<bytecode.length){switch(op){case 1:...case 255:...}}）漏检。
            if (caseMatches.size < 2) continue

            // 提取 opcode -> handler 切片
            val handlers = mutableListOf<OpHandler>()
            for ((idx, cm) in caseMatches.withIndex()) {
                val bodyStart = cm.range.last + 1
                val bodyEnd = if (idx + 1 < caseMatches.size) {
                    caseMatches[idx + 1].range.first
                } else {
                    (bodyStart + 1200).coerceAtMost(switchRegion.length)
                }
                val raw = switchRegion.substring(bodyStart, bodyEnd)
                    .replace(Regex("""\s+"""), " ")
                    .trim()
                if (raw.isEmpty()) continue
                handlers.add(
                    OpHandler(
                        key = cm.groupValues[1],
                        snippet = raw.take(220),
                        line = offsetToLineCol(switchOffset + cm.range.first).first,
                        column = offsetToLineCol(switchOffset + cm.range.first).second,
                    ),
                )
                if (handlers.size >= maxHandlers) break
            }

            // 评分（特征收敛在 switch 体内部，不再全文件统计）
            val switchBody = switchRegion.substring(
                0,
                (caseMatches.lastOrNull()?.range?.last ?: 0).coerceAtMost(switchRegion.length),
            )
            // 状态机误报过滤——先于评分，命中 zlib/inflate 或 babel regenerator
            // 状态机即跳过，避免低分脏候选污染上层 fingerprint/detect_vmp 判定。
            val fpFamily = stateMachineFamily(switchBody, lookBack)
            if (fpFamily != null) continue

            // 小规模 switch（2-3 case）必须有 VM 证据支持（循环判别式/函数体
            // 内的字节码数组访问或 0x 特征），避免普通 `while(var<bound){ switch }` 误报。
            // lookBack 中通常含 `var op=code[pc++]` 的取指表达式。
            if (caseMatches.size < 4) {
                val vmEvidence = vmpVarRe.containsMatchIn(lookBack) ||
                    vmpVarRe.containsMatchIn(switchBody) ||
                    hexLitRe.containsMatchIn(switchBody)
                if (!vmEvidence) continue
            }
            var score = 0
            val reasons = mutableListOf<String>()
            when {
                caseMatches.size >= 30 -> { score += 40; reasons.add("switch-case ${caseMatches.size} 个（典型 JSVMP 规模）") }
                caseMatches.size >= 12 -> { score += 30; reasons.add("switch-case ${caseMatches.size} 个") }
                caseMatches.size >= 4 -> { score += 20; reasons.add("switch-case ${caseMatches.size} 个") }
                else -> { score += 15; reasons.add("switch-case ${caseMatches.size} 个（小规模 dispatcher）") }
            }
            score += 25; reasons.add("无条件循环 ${loopMatch.value.trim()} 包裹 switch")
            val hexCount = hexLitRe.findAll(switchBody).count()
            if (hexCount >= 40) { score += 15; reasons.add("switch 内 0x 字面量密度高（$hexCount）") }
            else if (hexCount >= 10) { score += 8; reasons.add("switch 内 0x 字面量 $hexCount 个") }
            val arrayOps = vmpVarRe.findAll(switchBody).map { it.groupValues[1] }.distinct().take(6).toList()
            if (arrayOps.isNotEmpty()) { score += 10; reasons.add("疑似字节码数组访问: ${arrayOps.joinToString(",")}") }
            if (source.contains("Math.imul")) { score += 5; reasons.add("Math.imul（VM 常用乘法原语）") }
            if (source.contains("fromCharCode")) { score += 5; reasons.add("fromCharCode（字符串表解密）") }
            // hex case 键（0xNN:）是 JSVMP dispatch 的强特征
            val hexCaseKeys = caseMatches.count { it.groupValues[1].startsWith("0x") }
            if (hexCaseKeys >= 8) { score += 10; reasons.add("十六进制 case 键 $hexCaseKeys 个（dispatch 强特征）") }

            val (sLine, sCol) = offsetToLineCol(switchOffset)
            val (lLine, lCol) = offsetToLineCol(lookBackStart + loopMatch.range.first)
            candidates.add(
                VmpCandidate(
                    line = lLine,
                    column = lCol,
                    switchLine = sLine,
                    switchColumn = sCol,
                    score = score.coerceAtMost(100),
                    reasons = reasons,
                    suggestedOps = arrayOps,
                    caseCount = caseMatches.size,
                    handlers = handlers,
                ),
            )
            if (candidates.size >= 6) break
        }
        return candidates.sortedByDescending { it.score }
    }
}

/**
 * VM 指令 trace 折叠分析器 v2。
 *
 * v2 改进（对应评审报告缺陷 3/4）：
 * 1. analyze 接受真实 total（含被采样率跳过与环形覆盖的部分），百分比不失真
 * 2. n-gram 改滑窗（步长 1）——非重叠采样会漏相位偏移的循环块
 */
class VmpTraceAnalyzer {

    data class TraceReport(
        val totalSamples: Int,       // 真实触发总数（来自计数器，非 tail 长度）
        val sampledCount: Int,       // 实际进入分析的样本数
        val uniqueOpcodes: Int,
        val topOpcodes: List<OpcodeStat>,
        val loops: List<LoopBlock>,
        val sequenceSummary: String,
    )

    data class OpcodeStat(val opcode: String, val count: Int, val percent: Double)

    data class LoopBlock(val sequence: String, val repeats: Int)

    fun analyze(samples: List<String>, realTotal: Int = samples.size): TraceReport {
        if (samples.isEmpty()) {
            return TraceReport(realTotal, 0, 0, emptyList(), emptyList(), "")
        }
        val total = samples.size
        val freq = samples.groupingBy { it }.eachCount()
        val top = freq.entries
            .sortedByDescending { it.value }
            .take(30)
            .map { OpcodeStat(it.key, it.value, it.value * 100.0 / total) }

        // 循环块检测：滑窗 n-gram（步长 1），找高频重复块
        val loopCounts = HashMap<String, Int>()
        for (n in intArrayOf(2, 3, 4, 6, 8, 12)) {
            if (samples.size < n * 2) break
            var i = 0
            while (i + n <= samples.size) {
                val g = samples.subList(i, i + n).joinToString("→")
                loopCounts[g] = (loopCounts[g] ?: 0) + 1
                i += 1
            }
        }
        val loops = loopCounts.entries
            .filter { it.value >= 3 }
            .sortedWith(compareByDescending<Map.Entry<String, Int>> { it.value }.thenBy { it.key.length })
            .take(40)
            .map { (seq, count) ->
                val display = if (seq.length > 120) seq.take(117) + "..." else seq
                LoopBlock(display, count)
            }
            // 去除被更长块完全包含的短块（保留信息量最大的）
            .filterNot { short -> loopsContain(loopCounts, short) }
            .take(10)

        val summary = buildSequence(samples)
        return TraceReport(realTotal, total, freq.size, top, loops, summary)
    }

    /** 短块是否被某个出现次数相同、长度更长的块覆盖 */
    private fun loopsContain(all: Map<String, Int>, candidate: LoopBlock): Boolean =
        all.entries.any { (seq, count) ->
            count >= candidate.repeats && seq.length > candidate.sequence.length && seq.contains(candidate.sequence.removeSuffix("..."))
        }

    /** RLE 压缩序列：A A A B → A×3 B，长序列截断 */
    private fun buildSequence(samples: List<String>): String {
        val rle = mutableListOf<String>()
        var i = 0
        while (i < samples.size) {
            var j = i
            while (j < samples.size && samples[j] == samples[i]) j++
            val run = j - i
            rle.add(if (run > 1) "${samples[i]}×$run" else samples[i])
            i = j
        }
        val flat = rle.joinToString(" ")
        return when {
            flat.length <= 3000 -> flat
            else -> flat.take(1500) + " …[省略中段]… " + flat.takeLast(1200)
        }
    }

    /**
     * 对照组差分（评审报告 P2：实战最快的签名区段定位法）。
     * 对两次采样序列做 LCS 对齐，返回差异区段：
     * baseline 中缺失、testcase 中新增的 opcode 块即疑似签名路径。
     */
    data class TraceDiff(
        val baselineLen: Int,
        val testLen: Int,
        val addedBlocks: List<String>,
        val removedBlocks: List<String>,
        val commonRatio: Double,
    )

    fun diff(baseline: List<String>, test: List<String>): TraceDiff {
        if (baseline.isEmpty() || test.isEmpty()) {
            return TraceDiff(baseline.size, test.size, emptyList(), emptyList(), 0.0)
        }
        // LCS DP（限长防爆内存：>4000 时降级为频次差）
        if (baseline.size > 4000 || test.size > 4000) {
            val fb = baseline.groupingBy { it }.eachCount()
            val ft = test.groupingBy { it }.eachCount()
            val added = (ft.keys - fb.keys).map { "$it (+${ft[it]})" }
            val removed = (fb.keys - ft.keys).map { "$it (-${fb[it]})" }
            val inter = fb.keys.intersect(ft.keys).sumOf { minOf(fb[it] ?: 0, ft[it] ?: 0) }
            return TraceDiff(baseline.size, test.size, added, removed, inter * 2.0 / (baseline.size + test.size))
        }
        val n = baseline.size; val m = test.size
        val dp = Array(n + 1) { IntArray(m + 1) }
        for (i in n - 1 downTo 0) {
            for (j in m - 1 downTo 0) {
                dp[i][j] = if (baseline[i] == test[j]) dp[i + 1][j + 1] + 1
                else maxOf(dp[i + 1][j], dp[i][j + 1])
            }
        }
        // 回溯差异块
        val added = mutableListOf<String>()
        val removed = mutableListOf<String>()
        var i = 0; var j = 0
        while (i < n && j < m) {
            when {
                baseline[i] == test[j] -> { i++; j++ }
                dp[i + 1][j] >= dp[i][j + 1] -> { removed.add(baseline[i]); i++ }
                else -> { added.add(test[j]); j++ }
            }
        }
        while (i < n) { removed.add(baseline[i]); i++ }
        while (j < m) { added.add(test[j]); j++ }
        fun rle(list: List<String>): List<String> {
            if (list.isEmpty()) return emptyList()
            val out = mutableListOf<String>()
            var k = 0
            while (k < list.size) {
                var e = k
                while (e < list.size && list[e] == list[k]) e++
                out.add(if (e - k > 1) "${list[k]}×${e - k}" else list[k])
                k = e
            }
            return out
        }
        val common = dp[0][0]
        return TraceDiff(
            baselineLen = n,
            testLen = m,
            addedBlocks = rle(added).take(60),
            removedBlocks = rle(removed).take(60),
            commonRatio = common * 2.0 / (n + m),
        )
    }
}
