package com.webreverse.mcp.javascript.analysis

/**
 * 验证闭环引擎——「本地复现公式 × 浏览器真实值」的闭环比对。
 *
 * 逆向最大的风险是 EncDec 公式只解「看起来对」：单条样本命中可能纯属巧合，
 * 多条一致也可能因为样本空间太小。本引擎把推断收敛为可度量的置信：
 *
 * 设计目标（与评审报告「验证闭环」对应）：
 * 1. **多候选竞争**：同一批观测值喂给多个候选公式，谁对全部样本预测正确/命中率
 *    最高，谁就赢；输家也不丢弃，供 LLM 复盘漏判原因。
 * 2. **浏览器真实值 = 金标准**：观测样本由工具层从浏览器运行时采集（eval 或
 *    hook 返回值），引擎只拿它当 ground truth，不猜。
 * 3. **差分 vs 直接验证双通道**：
 *    - 直接验证：candidate(inputs) == realOutput ?
 *    - 差分验证：候选 A 与候选 B 在同一 inputs 上的差异，隔离出「哪个环节分歧」。
 * 4. **数值容差 + 边界样本**：支持整数与浮点；鼓励补 0/负数/极大值/boundary 样本，
 *    防「恰好对」伪命中。
 *
 * 引擎本身是纯 Kotlin（无 Android/无网络依赖），只负责编排与判定；真正的
 * JavaScript 求值由注入的 [JsExecutor] 完成——工具层可把它接到浏览器
 * `evaluateJavascript`（真机复现）或宿主 Node/引擎（离线复现）。
 */
class ValidationEngine {

    /** 在引擎内执行一段 JS 表达式并返回字符串结果（由工具层注入：浏览器 eval / node / 内置引擎） */
    fun interface JsExecutor {
        /** @param code 可执行 JS 表达式。@param inputs 占位符字典，引擎会把 {a:..,b:..} 拼进表达式 */
        fun execute(code: String, inputs: Map<String, Any>): String?
    }

    // ---------------- 数据模型 ----------------

    /** 一条浏览器观测样本：命名输入 + 真实输出 */
    data class Sample(
        val inputs: Map<String, Any>,   // 如 {"a":12, "b":4}
        val realOutput: Any,            // 浏览器真实值（金标准）
        val note: String = "",
    )

    /** 单个候选公式的验证结果 */
    data class CandidateVerdict(
        val formula: String,           // 复现公式（含 {a}/{b} 占位符）
        val matchCount: Int,
        val total: Int,
        val matchedSamples: List<Int>, // 命中的样本下标
        val failedSamples: List<Pair<Int, String>>, // (样本下标, 期望vs实际)
        val mismatchRatio: Double,     // 不匹配占比 0~1
        val monotonicPass: Boolean = true, // 是否不含反例（逆向常用的强校验）
    ) {
        val hitRate: Double get() = if (total == 0) 0.0 else matchCount.toDouble() / total
        val passedAll: Boolean get() = matchCount == total && total > 0
    }

    /** 全量验证报告 */
    data class ValidationReport(
        val ok: Boolean,
        val error: String = "",
        val sampleCount: Int = 0,
        val candidateCount: Int = 0,
        val best: CandidateVerdict? = null,
        val winnerNamed: String = "",
        val confirmed: Boolean = false,
        val confidence: Double = 0.0,
        val verdicts: List<CandidateVerdict> = emptyList(),
        val diffTrace: String = "",
        /** 候选第一名与第二名的命中率间隔；用于判断“唯一胜者”是否稳健。 */
        val margin: Double = 0.0,
        /** 输入样本的去重/多样性比例；单一样本不应获得高置信。 */
        val inputDiversity: Double = 0.0,
        /** 结果值是否存在足够的变化，避免常量输出导致伪验证。 */
        val outputDiversity: Double = 0.0,
        /** 是否建议继续采集边界/负向样本。 */
        val needsMoreSamples: Boolean = true,
    )

    // ---------------- 行为 ----------------

    /**
     * 对候选公式做验证。
     *
     * @param executor JS 执行器
     * @param samples 浏览器观测样本（金标准）
     * @param candidates 候选公式，每项为 `(名字, 表达式)`；表达式内用 `{a}`、`{b}` 等
     *   占位符引用 [Sample.inputs] 的键。
     * @param ignoreOrderedTwist 为 true 时允许小浮点误差
     */
    fun validate(
        executor: JsExecutor,
        samples: List<Sample>,
        candidates: List<Pair<String, String>>,
        tolerateFloatEpsilon: Double = 1e-9,
    ): ValidationReport {
        if (samples.isEmpty()) return ValidationReport(false, error = "无观测样本", sampleCount = 0)
        if (candidates.isEmpty()) return ValidationReport(false, error = "无候选公式", sampleCount = samples.size)

        val verdicts = candidates.map { (name, formula) ->
            val matched = mutableListOf<Int>()
            val failed = mutableListOf<Pair<Int, String>>()
            for ((idx, s) in samples.withIndex()) {
                val predicted = executeFormula(executor, formula, s.inputs)
                if (predicted == null) {
                    failed.add(idx to "本地执行失败或返回空")
                    continue
                }
                if (matches(predicted, s.realOutput, tolerateFloatEpsilon)) matched.add(idx)
                else {
                    failed.add(idx to "期望=${fmt(s.realOutput)} 实测=${predicted.trim()}")
                }
            }
            val total = samples.size
            CandidateVerdict(
                formula = name + " :: " + formula,
                matchCount = matched.size,
                total = total,
                matchedSamples = matched,
                failedSamples = failed,
                mismatchRatio = 1.0 - (matched.size.toDouble() / total),
                monotonicPass = failed.isEmpty(),
            )
        }

        val best = verdicts.maxByOrNull { it.hitRate }
        val ranked = verdicts.sortedByDescending { it.hitRate }
        val secondRate = ranked.getOrNull(1)?.hitRate ?: 0.0
        val margin = ((best?.hitRate ?: 0.0) - secondRate).coerceIn(0.0, 1.0)
        val fullMightBeSingle = verdicts.filter { it.passedAll }
        val inputKeys = samples.map { canonicalMap(it.inputs) }.toSet().size
        val outputKeys = samples.map { fmt(it.realOutput) }.toSet().size
        val inputDiversity = inputKeys.toDouble() / samples.size.coerceAtLeast(1)
        val outputDiversity = outputKeys.toDouble() / samples.size.coerceAtLeast(1)
        // 全样本命中 + 唯一全命中 + 至少两个不同输入，才视为“强确认”。
        val confirmed = fullMightBeSingle.size == 1 && best?.passedAll == true &&
            samples.size >= 2 && inputKeys >= 2

        // 置信度不仅取命中率，还考虑样本量、唯一胜者 margin、输入/输出多样性。
        // 这样“所有输入都是 1，输出恒为 8”的伪验证不会轻易被判定。
        val sampleFactor = (kotlin.math.ln((samples.size + 1).toDouble()) / kotlin.math.ln(9.0)).coerceIn(0.0, 1.0)
        val diversityFactor = (0.55 * inputDiversity + 0.45 * outputDiversity).coerceIn(0.0, 1.0)
        val base = best?.hitRate ?: 0.0
        val conf = (0.45 * base + 0.25 * margin + 0.18 * sampleFactor + 0.12 * diversityFactor).coerceIn(0.0, 0.99)
        val needsMore = samples.size < 3 || inputKeys < minOf(3, samples.size) || margin < 0.20 || !confirmed

        return ValidationReport(
            ok = best != null,
            sampleCount = samples.size,
            candidateCount = candidates.size,
            best = best,
            winnerNamed = best?.formula?.substringBefore(" :: ") ?: "",
            confirmed = confirmed,
            confidence = conf,
            verdicts = ranked,
            diffTrace = buildDiffTrace(samples, ranked),
            margin = margin,
            inputDiversity = inputDiversity,
            outputDiversity = outputDiversity,
            needsMoreSamples = needsMore,
        )
    }

    /** 检测两个候选公式的差异发生在哪个样本（差分验证） */
    fun diffTwo(
        executor: JsExecutor,
        samples: List<Sample>,
        formulaA: String,
        formulaB: String,
    ): String {
        val sb = StringBuilder()
        for ((idx, s) in samples.withIndex()) {
            val ra = executeFormula(executor, formulaA, s.inputs)
            val rb = executeFormula(executor, formulaB, s.inputs)
            sb.append("样本$idx: A=${ra?.trim()} B=${rb?.trim()} 真实=${fmt(s.realOutput)}\n")
        }
        return sb.toString().trim()
    }

    // ---------------- 多样本差分执行 ----------------

    /**
     * 多样本差分执行样本：observed 可为空（无金标准，只做候选间差分对比）。
     */
    data class DifferentialSample(
        val inputs: Map<String, Any>,
        /** 金标准（浏览器真实值）；null = 该样本无真实值，仅用于候选间差分 */
        val observed: String?,
        val note: String = "",
    )

    /** 一个假设族：同一 opcode/同一语义下的多条候选公式 */
    data class HypothesisGroup(
        val name: String,
        val formulas: List<Pair<String, String>>,   // (公式名, 表达式，占位符 {key})
    )

    /** 单个 样本×假设组 的执行结果 */
    data class DifferentialCell(
        val sampleIndex: Int,
        val groupName: String,
        /** 与金标准匹配（无金标准时为 false 占位，用 [agreeKey] 做差分） */
        val matched: Boolean,
        /** 组内多条公式输出是否一致（同一样本上无分歧） */
        val consistent: Boolean,
        val outputs: List<Pair<String, String>>,   // (公式名, 输出)
    ) {
        /** 用于组间差分对比的规约输出（排序去重后的输出集合，无金标准时以此判断两假设是否分歧） */
        val agreeKey: String get() = outputs.map { it.second }.sorted().joinToString("|")
    }

    data class DifferentialReport(
        val ok: Boolean,
        val error: String = "",
        val sampleCount: Int = 0,
        val groupCount: Int = 0,
        val hasObserved: Boolean = false,
        val matrix: List<DifferentialCell> = emptyList(),
        /** 组 -> 与金标准的命中率（无金标准时全为 1.0 占位） */
        val observedAccuracy: Map<String, Double> = emptyMap(),
        /** 组 -> 组内公式一致性（同一样本上无分歧的比例） */
        val internalConsistency: Map<String, Double> = emptyMap(),
        /** 组A -> 组B -> 一致率（金标准模式按 matched 一致；差分模式按 agreeKey 相等） */
        val agreement: Map<String, Map<String, Double>> = emptyMap(),
        val winner: String = "",
        val winnerConfidence: Double = 0.0,
        /** 冠军与亚军分歧的样本下标 */
        val divergenceSamples: List<Int> = emptyList(),
        val needsMoreSamples: Boolean = true,
        val summary: String = "",
    )

    /**
     * 多样本差分执行：对多个假设族（每组含多条候选公式）在全部样本上执行，
     * 既与金标准比对（有 realOutput 时），也互相差分（无金标准时靠输出集合分歧定位）。
     * 输出：逐样本矩阵、组间一致率、冠军、分歧样本与置信度。
     */
    fun differentialRun(
        executor: JsExecutor,
        samples: List<DifferentialSample>,
        groups: List<HypothesisGroup>,
        tolerateFloatEpsilon: Double = 1e-9,
    ): DifferentialReport {
        if (samples.isEmpty()) return DifferentialReport(false, error = "无差分样本")
        if (groups.isEmpty()) return DifferentialReport(false, error = "无假设组", sampleCount = samples.size)
        val hasObserved = samples.any { it.observed != null }
        val sampleCount = samples.size
        val groupNames = groups.map { it.name }
        val matrix = mutableListOf<DifferentialCell>()
        for ((si, s) in samples.withIndex()) {
            for (g in groups) {
                val outs = g.formulas.mapNotNull { (name, f) ->
                    executeFormula(executor, f, s.inputs)?.trim()?.takeIf { it.isNotEmpty() }?.let { name to it }
                }
                val distinct = outs.map { it.second }.toSet()
                val consistent = distinct.size <= 1
                val matched = s.observed != null && outs.any { (_, v) -> matches(v, s.observed, tolerateFloatEpsilon) }
                matrix += DifferentialCell(si, g.name, matched, consistent, outs)
            }
        }
        val observedAccuracy = groupNames.associateWith { g ->
            if (!hasObserved) 1.0
            else matrix.filter { it.groupName == g }.count { it.matched }.toDouble() / sampleCount
        }
        val internalConsistency = groupNames.associateWith { g ->
            matrix.filter { it.groupName == g }.count { it.consistent }.toDouble() / sampleCount
        }
        val agreement = groupNames.associateWith { a ->
            groupNames.associateWith { b ->
                if (a == b) 1.0 else {
                    val ca = matrix.filter { it.groupName == a }
                    val cb = matrix.filter { it.groupName == b }
                    if (ca.isEmpty() || cb.isEmpty()) 0.0 else {
                        val agree = ca.zip(cb).count { (x, y) ->
                            if (hasObserved) x.matched == y.matched else x.agreeKey == y.agreeKey
                        }.toDouble() / sampleCount
                        agree
                    }
                }
            }
        }
        // 冠军：金标准模式取命中率最高；纯差分模式取组内一致性最高 + 与其它组区分度最大
        val winner = if (hasObserved) {
            observedAccuracy.maxByOrNull { it.value }?.key ?: ""
        } else {
            groupNames.maxByOrNull { g ->
                val consistency = internalConsistency[g] ?: 0.0
                val avgAgreement = agreement[g].orEmpty().filterKeys { it != g }.values.average()
                consistency * 0.65 + (1.0 - avgAgreement) * 0.35
            } ?: ""
        }
        // 分歧样本：冠军 vs 次名 意见不一致处
        val runner = if (hasObserved) {
            observedAccuracy.entries.filter { it.key != winner }.maxByOrNull { it.value }?.key
        } else {
            agreement[winner].orEmpty().filterKeys { it != winner }.minByOrNull { it.value }?.key
        }
        val divergenceSamples = if (runner != null) {
            val cw = matrix.filter { it.groupName == winner }
            val cr = matrix.filter { it.groupName == runner }
            cw.zip(cr).mapIndexedNotNull { idx, (x, y) ->
                val diverge = if (hasObserved) x.matched != y.matched else x.agreeKey != y.agreeKey
                if (diverge) idx else null
            }
        } else emptyList()
        val sampleFactor = (kotlin.math.ln((sampleCount + 1).toDouble()) / kotlin.math.ln(9.0)).coerceIn(0.0, 1.0)
        val acc = observedAccuracy[winner] ?: 0.0
        val cons = internalConsistency[winner] ?: 0.0
        val margin = if (runner != null) kotlin.math.abs((observedAccuracy[winner] ?: 0.0) - (observedAccuracy[runner] ?: 0.0)) else 1.0
        val distinct = if (runner != null) 1.0 - (agreement[winner].orEmpty()[runner] ?: 0.0) else 1.0
        val confidence = if (hasObserved) {
            (0.50 * acc + 0.25 * margin + 0.15 * cons + 0.10 * sampleFactor).coerceIn(0.0, 0.99)
        } else {
            (0.55 * cons + 0.25 * distinct + 0.20 * sampleFactor).coerceIn(0.0, 0.99)
        }
        val needsMore = sampleCount < 3 || cons < 0.9 || (hasObserved && acc < 1.0) || divergenceSamples.isEmpty()
        val summary = if (hasObserved) {
            "$winner 在 $sampleCount 条样本上命中率 ${(acc * 100).toInt()}%，组内一致性 ${(cons * 100).toInt()}%，与次名分歧样本 ${divergenceSamples.size} 条"
        } else {
            "$winner 组内一致性 ${(cons * 100).toInt()}%，与其它假设区分度 ${(distinct * 100).toInt()}%，分歧样本 ${divergenceSamples.size} 条（无金标准，差分结论需补充真实样本）"
        }
        return DifferentialReport(
            ok = true, sampleCount = sampleCount, groupCount = groups.size, hasObserved = hasObserved,
            matrix = matrix, observedAccuracy = observedAccuracy, internalConsistency = internalConsistency,
            agreement = agreement, winner = winner, winnerConfidence = confidence,
            divergenceSamples = divergenceSamples, needsMoreSamples = needsMore, summary = summary,
        )
    }

    // ---------------- 动态验证闭环：批量候选 + 失败分类 + 统一结果模型 ----------------

    /**
     * 动态验证失败原因分类枚举。
     * 每个候选在一次样本上只会落在唯一一个状态上；
     * [display] 供人类阅读，[actionableHint] 给出可操作的处理方向。
     */
    enum class VerdictState(
        val display: String,
        val actionableHint: String,
    ) {
        PASSED(
            "通过",
            "候选公式在浏览器真实样本上求值一致，可进入 Hook 覆写 / 本地复现",
        ),
        LOCAL_SYNTAX_ERROR(
            "本地语法错误",
            "表达式无法被求值（括号 / 运算符 / 占位符引用非法）。建议先用 JS 语法检查工具校验，再逐段拆分定位出错片段",
        ),
        RUNTIME_ERROR(
            "运行时异常",
            "浏览器执行候选表达式时抛出异常（引用不存在对象 / 除零 / 端点主动抛错等）。请核对候选依赖的全局变量与函数是否已就绪",
        ),
        TIMEOUT(
            "超时",
            "求值超时，疑似死循环 / 递归过深 / 表达式过大。建议给公式补上界、改写为纯函数，或改用 diff 分段验证定位瓶颈",
        ),
        UNDEFINED_RESULT(
            "结果为 undefined",
            "求值结果为 undefined / null / NaN / 空。通常因引用未定义变量、未调用函数或占位符键名与样本 inputs 不符；请核对 {占位符} 与 inputs 键名是否一致",
        ),
        TYPE_MISMATCH(
            "类型不符",
            "求值类型与浏览器真实值类型不一致（数字 vs 字符串 / 布尔）。请核对 typeof 与字符串化（String/String()/toFixed）方式",
        ),
        VALUE_MISMATCH(
            "值不匹配",
            "求值得到确定值但与期望不符。多为公式方向 / 偏移 / 边界 / 分支错误；建议补边界样本（0/负数/大数）或用二分法定位分歧",
        ),
    }

    /**
     * 一次 JS 求值的细化结果，用于失败原因分类；由工具层注入，与基础 [JsExecutor] 互补。
     * 基础 [JsExecutor] 只回传 `String?` 无法区分「空 / 语法错误 / 超时」，故新增该通道。
     */
    sealed class JsEvalOutcome {
        /** 浏览器成功求值并返回字符串（可能形如 "undefined"，交由引擎判定） */
        data class Ok(val value: String) : JsEvalOutcome()
        /** 语法错误：浏览器无法解析候选表达式 */
        data class Syntax(val message: String) : JsEvalOutcome()
        /** 运行时异常：浏览器执行到中途抛错 */
        data class Runtime(val message: String) : JsEvalOutcome()
        /** 求值超时（疑似死循环） */
        data class TimedOut(val message: String) : JsEvalOutcome()
        /** 求值为空 / executor 返回 null（无法区分具体原因） */
        data class Empty(val reason: String) : JsEvalOutcome()
    }

    /** 详细执行器：返回带分类的结果，供引擎做失败原因分类。与现有 [JsExecutor] 兼容共存。 */
    fun interface DetailedJsExecutor {
        fun executeDetailed(code: String, inputs: Map<String, Any>): JsEvalOutcome
    }

    /**
     * 单个候选在单个浏览器样本上的「统一动态验证结果」。
     * 这是动态验证闭环的统一数据模型，供上层工具直接消费：
     * 候选、是否通过、实际值、浏览器侧结论、置信度、耗时、失败原因分类枚举一应俱全。
     */
    data class DynamicRunResult(
        val formula: String,                          // 候选表达式（含占位符的原始字符串）
        val displayName: String,                      // 候选名
        val passed: Boolean,                          // 是否通过（求值成功且值与期望一致）
        val state: VerdictState,                      // 状态 / 失败原因分类枚举
        val actualValue: String?,                     // 候选求得的实际值（可能为 "undefined" 或 null）
        val expectedValue: String?,                   // 浏览器真实值（金标准，格式化后）
        val browserExecutable: Boolean,               // 浏览器侧是否执行出值（能求值出一个字符串）
        val localFailedButBrowserExecutable: Boolean, // 未通过但浏览器仍可执行（值级偏差而非执行失败）
        val browserConclusion: String,                // 浏览器侧结论的可读描述
        val confidence: Double,                       // 单条置信度 0~1（通过取 0.8 基准，样本量/多样性在报告级加权）
        val elapsedMs: Long,                          // 该候选该样本求值耗时（毫秒）
        val retryEligible: Boolean,                   // 是否建议重试（空值 / 超时 / 运行时异常等情况）
        val hint: String,                             // 面向操作的可执行提示
    )

    /** 候选级汇总（批量验证时按候选聚合） */
    data class CandidateRollup(
        val name: String,
        val totalRuns: Int,
        val passedRuns: Int,
        val passed: Boolean,          // 该候选是否全部样本通过
        val confidence: Double,       // 该候选命中率 0~1
        val primaryState: VerdictState,
    )

    /**
     * 批量动态验证报告：一次提交多个候选，统一执行并各自返回 通过/失败、结果值与失败分类；
     * 同时给出全局命中、收敛判定与重试方向。
     */
    data class DynamicBatchReport(
        val ok: Boolean,
        val error: String = "",
        val sampleCount: Int = 0,
        val candidateCount: Int = 0,
        val runCount: Int = 0,
        val results: List<DynamicRunResult> = emptyList(),
        val rollups: List<CandidateRollup> = emptyList(),
        val passedCount: Int = 0,
        val summaryPerReason: Map<VerdictState, Int> = emptyMap(),
        val winner: String = "",
        val winnerConfidence: Double = 0.0,
        val confirmed: Boolean = false,
        val needsMoreSamples: Boolean = true,
        val retrySuggestions: List<String> = emptyList(),
        val summary: String = "",
    )

    companion object {
        /**
         * 从基础 [JsExecutor]（返回 String?）适配出尽力而为的 [DetailedJsExecutor]。
         * 注意：基础执行器无法区分「空 / 语法错误 / 超时」，null 一律按 [JsEvalOutcome.Empty] 归类；
         * 需要精确分类时请由上层注入真正的 [DetailedJsExecutor]（自带语法 / 超时检测）。
         */
        fun detailedFromPlain(plain: JsExecutor): DetailedJsExecutor = DetailedJsExecutor { code, inputs ->
            when (val r = plain.execute(code, inputs)) {
                null -> JsEvalOutcome.Empty("基础执行器返回空（原因未知，未走详细通道）")
                else -> JsEvalOutcome.Ok(r)
            }
        }
    }

    /**
     * 单候选 × 单样本动态执行：闭环中最细粒度的一次求值 + 判定。
     * 返回统一结果模型 [DynamicRunResult]，含失败分类、浏览器结论、耗时与可重试方向。
     */
    fun evaluateDynamic(
        detailed: DetailedJsExecutor,
        name: String,
        formula: String,
        inputs: Map<String, Any>,
        expected: Any,
        tolerateFloatEpsilon: Double = 1e-9,
    ): DynamicRunResult {
        val expectedStr = fmt(expected)
        val bound = formula.withPlaceholders(inputs)
        val start = System.nanoTime()
        val outcome = try {
            detailed.executeDetailed(bound, inputs)
        } catch (e: Throwable) {
            JsEvalOutcome.Runtime(e.message ?: e.javaClass.simpleName)
        }
        val elapsedMs = (System.nanoTime() - start) / 1_000_000L
        return buildRunResult(name, formula, outcome, expectedStr, expected, elapsedMs, tolerateFloatEpsilon)
    }

    /**
     * 批量候选一次提交验证（统一「动态验证闭环」入口）。
     *
     * 对每个候选 × 每个样本统一执行，各自返回 通过/失败 与结果值；
     * 失败原因细化分类；对浏览器侧空值 / 超时/运行时异常返回可重试方向而非静默失败。
     *
     * @param executor 浏览器（金标准）执行器
     * @param samples  浏览器观测样本
     * @param candidates 候选 `(名字, 表达式)`；表达式内 `{a}` 等占位符引用样本 inputs 键
     * @param detailed 可选详细执行器；未提供时用 [detailedFromPlain] 兜底（仅能区分空 / 非空）
     */
    fun validateDynamicBatch(
        executor: JsExecutor,
        samples: List<Sample>,
        candidates: List<Pair<String, String>>,
        detailed: DetailedJsExecutor? = null,
        tolerateFloatEpsilon: Double = 1e-9,
    ): DynamicBatchReport {
        if (samples.isEmpty()) {
            return DynamicBatchReport(false, error = "无观测样本：浏览器真实值缺失，无法闭环比对", sampleCount = 0)
        }
        if (candidates.isEmpty()) {
            return DynamicBatchReport(false, error = "无候选公式：batch 至少提交一个候选字符串 / 表达式", sampleCount = samples.size)
        }

        val detailExecutor = detailed ?: detailedFromPlain(executor)
        val runs = mutableListOf<DynamicRunResult>()
        for ((name, formula) in candidates) {
            for (s in samples) {
                runs += evaluateDynamic(detailExecutor, name, formula, s.inputs, s.realOutput, tolerateFloatEpsilon)
            }
        }

        val sampleCount = samples.size
        val byCandidate = runs.groupBy { it.displayName }
        val rollups = byCandidate.entries.map { (name, list) ->
            val total = list.size
            val passed = list.count { it.passed }
            val rate = if (total == 0) 0.0 else passed.toDouble() / total
            val primary = list.groupingBy { it.state }.eachCount().maxByOrNull { it.value }?.key ?: VerdictState.VALUE_MISMATCH
            CandidateRollup(name, total, passed, passed == total && total > 0, rate, primary)
        }
        val passedCount = runs.count { it.passed }
        val summaryPerReason = runs.groupingBy { it.state }.eachCount()

        val candidatePassedAll = rollups.filter { it.passed }
        val winnerRollup = rollups.maxByOrNull { it.confidence } ?: rollups.firstOrNull()
        val inputKeys = samples.map { canonicalMap(it.inputs) }.toSet().size
        val outputKeys = samples.map { fmt(it.realOutput) }.toSet().size
        val hasEnoughDiversity = samples.size >= 2 && inputKeys >= 2
        // 唯一一个全通过候选 + 足够多样的输入，才视为“强收敛”。
        val confirmed = candidatePassedAll.size == 1 && hasEnoughDiversity

        val sampleFactor = (kotlin.math.ln((samples.size + 1).toDouble()) / kotlin.math.ln(9.0)).coerceIn(0.0, 1.0)
        val inputDiversity = inputKeys.toDouble() / samples.size
        val outputDiversity = outputKeys.toDouble() / samples.size
        val diversityFactor = (0.6 * inputDiversity + 0.4 * outputDiversity).coerceIn(0.0, 1.0)
        val bestRate = winnerRollup?.confidence ?: 0.0
        val conf = (0.45 * bestRate + 0.20 * sampleFactor + 0.20 * diversityFactor + (if (confirmed) 0.15 else 0.0))
            .coerceIn(0.0, 0.99)

        val needsMore = samples.size < 3 || inputKeys < minOf(3, samples.size) || !confirmed

        // 浏览器侧空值 / 超时 / 运行时异常 → 给出可重试方向而非静默失败
        val retrySuggestions = runs.filter { it.retryEligible }.map { it.hint }.distinct().take(6)

        val summary = when {
            confirmed ->
                "${winnerRollup?.name} 在 ${sampleCount} 条浏览器真实样本上全部一致（$inputKeys 组不同输入），动态验证闭环收敛"
            passedCount == 0 ->
                "全部候选未通过：${summaryPerReason.entries.joinToString("; ") { "${it.key.display}×${it.value}" }}。请按上方提示修正后重试或补采集样本"
            else ->
                "${rollups.size} 个候选中共 ${candidatePassedAll.size} 个全通过（命中 ${passedCount}/${runs.size} 次）；样本量/多样性不足，需补充边界样本"
        }

        return DynamicBatchReport(
            ok = true,
            error = "",
            sampleCount = sampleCount,
            candidateCount = rollups.size,
            runCount = runs.size,
            results = runs,
            rollups = rollups,
            passedCount = passedCount,
            summaryPerReason = summaryPerReason,
            winner = winnerRollup?.name ?: "",
            winnerConfidence = conf,
            confirmed = confirmed,
            needsMoreSamples = needsMore,
            retrySuggestions = retrySuggestions,
            summary = summary,
        )
    }

    // ---------------- 动态验证：内部判定 ----------------

    private fun buildRunResult(
        name: String,
        formula: String,
        outcome: JsEvalOutcome,
        expectedStr: String,
        expected: Any,
        elapsedMs: Long,
        eps: Double,
    ): DynamicRunResult {
        val (state, actual, executable) = when (outcome) {
            is JsEvalOutcome.Syntax -> Triple(VerdictState.LOCAL_SYNTAX_ERROR, null, false)
            is JsEvalOutcome.Runtime -> Triple(VerdictState.RUNTIME_ERROR, null, false)
            is JsEvalOutcome.TimedOut -> Triple(VerdictState.TIMEOUT, null, false)
            is JsEvalOutcome.Empty -> Triple(VerdictState.UNDEFINED_RESULT, null, false)
            is JsEvalOutcome.Ok -> {
                val v = outcome.value
                val low = v.trim().lowercase()
                val blankOrUndefined = v.isBlank() || low in setOf("undefined", "null", "nan")
                when {
                    blankOrUndefined -> Triple(VerdictState.UNDEFINED_RESULT, v, true)
                    matches(v, expected, eps) -> Triple(VerdictState.PASSED, v, true)
                    !typeCompatible(v, expected) -> Triple(VerdictState.TYPE_MISMATCH, v, true)
                    else -> Triple(VerdictState.VALUE_MISMATCH, v, true)
                }
            }
        }

        val passed = state == VerdictState.PASSED
        val localFailedButBrowserExecutable = !passed && executable
        val retryEligible = state == VerdictState.TIMEOUT ||
            state == VerdictState.UNDEFINED_RESULT ||
            state == VerdictState.RUNTIME_ERROR

        val browserConclusion = when (outcome) {
            is JsEvalOutcome.Syntax -> "浏览器解析失败（语法错误）：${trunc(outcome.message)}"
            is JsEvalOutcome.Runtime -> "浏览器执行抛异常：${trunc(outcome.message)}"
            is JsEvalOutcome.TimedOut -> "浏览器求值超时（疑似死循环）：${trunc(outcome.message)}"
            is JsEvalOutcome.Empty -> "浏览器求值为空 / 无返回值"
            is JsEvalOutcome.Ok ->
                if (passed) "浏览器可执行，返回 ${actual?.trim() ?: ""}，与期望一致"
                else "浏览器可执行，返回 ${actual?.trim() ?: ""}，与期望 ${expectedStr} 不一致"
        }

        val hint = buildDynamicHint(state, actual, expectedStr, retryEligible, localFailedButBrowserExecutable)
        return DynamicRunResult(
            formula = formula,
            displayName = name,
            passed = passed,
            state = state,
            actualValue = actual,
            expectedValue = expectedStr,
            browserExecutable = executable,
            localFailedButBrowserExecutable = localFailedButBrowserExecutable,
            browserConclusion = browserConclusion,
            confidence = if (passed) 0.8 else 0.0,
            elapsedMs = elapsedMs,
            retryEligible = retryEligible,
            hint = hint,
        )
    }

    /** 判断候选实际值类型是否与期望类型兼容（字符串形态判断） */
    private fun typeCompatible(actual: String, expected: Any): Boolean {
        val a = actual.trim()
        return when (expected) {
            is Number -> a.toDoubleOrNull() != null
            is Boolean -> a == "true" || a == "false"
            else -> true
        }
    }

    /** 组装面向操作的可执行提示（含可重试方向与「浏览器可执行」显式提示） */
    private fun buildDynamicHint(
        state: VerdictState,
        actual: String?,
        expectedStr: String?,
        retryEligible: Boolean,
        localFailedButBrowserExecutable: Boolean,
    ): String {
        val base = state.actionableHint
        if (retryEligible) {
            return "$base。可重试方向：请刷新 / 预热页面、确保依赖的全局变量与 Hook 已就绪后再重新采集样本求值；若持续为空或超时，建议切换 reverse.validate 的 diff 通道分段定位；而非静默丢弃该候选。"
        }
        return if (localFailedButBrowserExecutable) {
            "$base。浏览器仍可执行（有实测值 ${actual?.trim() ?: "?"}），属值级偏差而非执行失败：请核对公式方向 / 偏移 / 边界，必要时以实测值 vs 期望值 ${expectedStr ?: "?"} 反推步长。"
        } else {
            base
        }
    }

    private fun trunc(s: String, max: Int = 160): String =
        if (s.length <= max) s else s.take(max) + "…"

    // ---------------- 内部 ----------------

    /** 用输入占位符填充公式并交给 executor 求值 */
    private fun executeFormula(executor: JsExecutor, formula: String, inputs: Map<String, Any>): String? {
        val bound = formula.withPlaceholders(inputs)
        return executor.execute(bound, inputs)
    }

    private fun String.withPlaceholders(inputs: Map<String, Any>): String {
        var out = this
        for ((k, v) in inputs) {
            out = out.replace("{$k}", fmt(v))
        }
        return out
    }

    /** 字符串/数值宽松匹配（含浮点容差） */
    private fun matches(predicted: String, real: Any, eps: Double): Boolean {
        val p = predicted.trim()
        val rStr = fmt(real).trim()
        if (p == rStr) return true
        val pNum = p.toDoubleOrNull()
        val rNum = rStr.toDoubleOrNull()
        if (pNum != null && rNum != null) return kotlin.math.abs(pNum - rNum) <= eps
        return false
    }

    private fun fmt(v: Any): String = when (v) {
        is Double -> if (v == v.toLong().toDouble()) v.toLong().toString() else v.toString()
        is Float -> fmt(v.toDouble())
        is String -> v
        is Long -> v.toString()
        is Int -> v.toString()
        else -> v.toString()
    }

    /** 输入字典的规范键：键排序后拼 k=v，用于统计输入多样性（同一输入组合不重复计数） */
    private fun canonicalMap(inputs: Map<String, Any>): String =
        inputs.entries.sortedBy { it.key }.joinToString("|") { "${it.key}=${fmt(it.value)}" }

    private fun buildDiffTrace(samples: List<Sample>, verdicts: List<CandidateVerdict>): String {
        val sb = StringBuilder()
        val best = verdicts.maxByOrNull { it.hitRate }
        if (best != null) {
            sb.append("最优: ${best.formula}（命中 ${best.matchCount}/${best.total}）\n")
        }
        // 对 bas 候选 0 与其余候选，差分定位分歧样本
        if (verdicts.size >= 2) {
            val b0 = verdicts[0]
            for (i in 0 until minOf(verdicts.size, 3)) {
                val other = verdicts[i]
                if (other === b0) continue
                val diverge = samples.indices.filter { idx ->
                    (idx in b0.matchedSamples) != (idx in other.matchedSamples)
                }
                if (diverge.isNotEmpty()) {
                    sb.append("「${b0.formula.substringBefore(" :: ")}」vs「${other.formula.substringBefore(" :: ")}」分歧于样本: ")
                        .append(diverge.take(8).joinToString(",")).append("\n")
                }
            }
        }
        if (sb.isBlank()) sb.append("所有候选中规中矩，无显著分歧。")
        return sb.toString().trim()
    }
}