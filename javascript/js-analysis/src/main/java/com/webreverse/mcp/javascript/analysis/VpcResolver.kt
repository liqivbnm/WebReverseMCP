package com.webreverse.mcp.javascript.analysis

/**
 * P0-4：VPC（虚拟 PC）槽位评分识别。
 *
 * 引擎级方案在 SpiderMonkey 里按 pc 快照 locals/args，
 * 这里用 CDP 等价物：debugger.trace_vmp 在 dispatch 循环断点反复暂停，每次读全部
 * 局部变量 -> 序列 [{ts, vars: {name: [v1, v2, ...]}}]。本类对该序列做数据驱动评分，
 * 自动认出哪个变量是虚拟 pc，并重建真实跳转边——静态反编译解不出的控制流由此补全。
 *
 * 评分特征（数据驱动，不写死变量名）：
 * 1. 数值覆盖率：非 undefined 采样占比 >= 0.8
 * 2. distinct 取值数 >= 8（pc 会走遍整个字节码）
 * 3. 小正增量比例 >= 0.6（顺序执行的主导模式）
 * 4. 存在少量跳变（后继 != 前值+增量，即真实跳转）
 */
class VpcResolver {

    data class SlotScore(
        val name: String,
        val coverage: Double,        // 数值覆盖率
        val distinct: Int,           // 不同取值数
        val smallStepRatio: Double,  // 小正增量占比
        val jumps: Int,              // 跳变次数
        val rank: Double,            // distinct * smallStepRatio
    )

    data class Resolved(
        val ok: Boolean,
        val error: String = "",
        val vpcSlot: String = "",           // 虚拟 pc 变量名
        val samples: Int = 0,               // 有效采样数
        val pcRange: Pair<Long, Long> = 0L to 0L,
        val distinctPcs: Int = 0,
        val slots: List<SlotScore> = emptyList(),   // 全部槽位评分排行
        val jumpTargets: Map<Long, Int> = emptyMap(), // pc -> 跳入次数（循环头/分支汇合点）
        val transitions: Map<Long, List<Pair<Long, Int>>> = emptyMap(), // pc -> [(后继, 次数)]
        val hottestPc: Long = 0,            // 命中最多的 pc（热点区锚点）
    )

    /**
     * @param varSequence 每次采样的变量快照：List<Map<变量名, 值字符串>>
     *                   值可为 "123" / "undefined" / "0x1f"（自动解析数字）
     */
    fun resolve(varSequence: List<Map<String, String>>): Resolved {
        if (varSequence.size < 8) {
            return Resolved(ok = false, error = "采样不足（${varSequence.size} < 8）：请增大 trace_vmp 的采样次数")
        }

        // 1. 收集每个变量的数值序列
        val series = HashMap<String, MutableList<Long>>()
        varSequence.forEach { snap ->
            snap.forEach { (name, raw) ->
                val v = parseNum(raw)
                if (v != null) series.getOrPut(name) { mutableListOf() }.add(v)
            }
        }
        if (series.isEmpty()) {
            return Resolved(ok = false, error = "采样中无可解析的数值变量")
        }

        // 2. 逐槽位评分
        val scores = series.map { (name, vals) ->
            val distinct = vals.distinct().size
            var smallSteps = 0
            var steps = 0
            var jumps = 0
            for (i in 1 until vals.size) {
                val d = vals[i] - vals[i - 1]
                if (d != 0L) steps++
                if (d in 1..4) smallSteps++
                if (d != 0L && d !in 1..4) jumps++
            }
            val coverage = vals.size.toDouble() / varSequence.size
            val smallRatio = if (steps > 0) smallSteps.toDouble() / steps else 0.0
            SlotScore(
                name = name,
                coverage = coverage,
                distinct = distinct,
                smallStepRatio = smallRatio,
                jumps = jumps,
                rank = distinct * smallRatio,
            )
        }.filter { it.coverage >= 0.5 && it.distinct >= 4 }
            .sortedByDescending { it.rank }

        val vpc = scores.firstOrNull { it.smallStepRatio >= 0.5 && it.distinct >= 8 }
            ?: return Resolved(
                ok = false,
                error = "未发现 pc 特征变量（要求 distinct>=8 且小增量占比>=0.5）；候选: " +
                    scores.take(3).joinToString { "${it.name}(d=${it.distinct},sr=%.2f)".format(it.smallStepRatio) },
                slots = scores,
                samples = varSequence.size,
            )

        // 3. 用 vpc 序列重建转移边
        val vals = series[vpc.name]!!
        val trans = HashMap<Long, HashMap<Long, Int>>()
        for (i in 1 until vals.size) {
            val from = vals[i - 1]
            val to = vals[i]
            if (from == to) continue
            trans.getOrPut(from) { HashMap() }.merge(to, 1, Int::plus)
        }
        val jumpTargets = HashMap<Long, Int>()
        trans.forEach { (_, succs) ->
            succs.forEach { (to, cnt) -> jumpTargets.merge(to, cnt, Int::plus) }
        }
        val hottest = vals.groupingBy { it }.eachCount().maxByOrNull { it.value }?.key ?: 0L

        return Resolved(
            ok = true,
            vpcSlot = vpc.name,
            samples = varSequence.size,
            pcRange = (vals.min() ?: 0) to (vals.max() ?: 0),
            distinctPcs = vals.distinct().size,
            slots = scores,
            jumpTargets = jumpTargets,
            transitions = trans.mapValues { (_, s) -> s.map { (k, v) -> k to v } },
            hottestPc = hottest,
        )
    }

    /** "123" / "0x1f" -> Long；"undefined"/对象串 -> null */
    private fun parseNum(raw: String): Long? {
        val s = raw.trim().removePrefix("\"").removeSuffix("\"")
        return when {
            s.startsWith("0x", ignoreCase = true) -> s.substring(2).toLongOrNull(16)
            else -> s.toLongOrNull()
        }
    }
}
