package com.webreverse.mcp.workspace.core

/**
 * 自适应调查规划器（ChatGPT 报告 P0：Adaptive Investigation Planner）。
 *
 * 与 [com.webreverse.mcp.mcp.tools.InvestigationTools] 的差异：
 * 后者是「目标 → 固定阶段顺序」（REVERSE_API 永远是 侦察→断点→hook→…），
 * 本规划器是 **目标驱动状态机**：根据「已收集证据量 / 已确认信号数 / 置信度 / 阻塞点」
 * 动态决定下一步最优行动，并基于每次行动后的反馈（证据是否增长、置信度是否提升）
 * **自适应调权**，避免在死胡同（如某个 hook 始终不命中）上浪费回合。
 *
 * 核心概念：
 * 1. **[InvestigationGoal]**：用户目标（还原签名 / 追踪 token / 定位加密算法 …）；
 * 2. **[Tactic]**：一批同构行动（观察 / Hook / 断点 / 静态 / 动态 / 跨数据流 / 验证），
 *    每个行动带前置条件（precondition）与产出信号类型（produces）；
 * 3. **认知状态 [PlannerState]**：已用行动、已确认信号、累计置信度、阻塞计数；
 * 4. **打分器**：对每个候选行动打分 = 收益(目标相关性 + 互信息/新颖性) × 存活权重 × 可用性，
 *    其中**存活权重**随「上次执行是否带来新信号」动态上下浮动（类比对抗多臂老虎机）。
 *
 * 输出：[planNext] 给出下一步行动 + Agent Hints（调用哪个 reverse.* 工具、期望看到什么）。
 * 纯 Kotlin、零第三方依赖，可单测。
 */
class AdaptiveInvestigationPlanner {

    // ---------------- 模型 ----------------

    /** 调查目标 */
    enum class Goal(
        val display: String,
        val keySignals: List<String>,
    ) {
        SIGNATURE(
            "定位签名算法并验证输入输出",
            listOf("crypto_found", "signature_endpoint", "input_chain", "output_reproduced"),
        ),
        TOKEN_TRACE(
            "追踪令牌的生成/消费位置",
            listOf("token_source", "token_consumer", "token_stored"),
        ),
        REVERSE_API(
            "还原接口完整请求链（参数/签名来源）",
            listOf("endpoint_chain", "param_source", "header_sign", "flow_map"),
        ),
        CRYPTO_LOCATE(
            "定位加密/解密算法实现",
            listOf("crypto_found", "algorithm_identified", "wasm_bridge"),
        ),
        GENERAL(
            "全景侦察与能力盘点",
            listOf("recon_done", "endpoint_chain", "storage_map"),
        ),
    }

    /** 行动类型 */
    enum class ActionType {
        OBSERVE,       // 被动采集（网络/控制台/证据库）
        HOOK,          // 运行时包装函数/属性
        BREAKPOINT,    // 断点定位执行点
        STATIC,        // 静态分析（AST/SSA/污点）
        DYNAMIC_TRACE, // 动态追踪（调用链/值指纹）
        CROSS_FLOW,    // 跨数据流（JS↔WASM/异步谱系/值指纹联动）
        VALIDATE,      // 验证闭环（本地复现对比真实值）
    }

    /** 一次规划出的行动 */
    data class PlannedAction(
        val type: ActionType,
        val action: String,             // 做什么
        val toolHint: String,           // 调用哪个 reverse.* 工具
        val expectation: String,        // 期望看到什么信号
        val precedence: Int,            // 优先级（越高越该先做）
        val weight: Double,             // 存活权重（自适应）
        val novelty: Double,            // 新颖性：与已用行动的差异度
        val reason: String,             // 为什么这样规划
    )

    /** 认知状态 */
    data class PlannerState(
        val goal: Goal,
        val confirmedSignals: Set<String> = emptySet(),
        val confidence: Double = 0.0,
        val actionsTaken: List<ActionType> = emptyList(),
        val blockedActions: Map<ActionType, Int> = emptyMap(),
        val iterations: Int = 0,
        /** 最近行动带来的新信号数量，作为动作可靠度反馈。 */
        val lastGain: Int = 0,
        /** 连续无增益次数；连续失败时主动切换策略。 */
        val stalled: Int = 0,
    )

    // ---------------- 行动定义（带前置条件，可扩展） ----------------

    private data class ActionDef(
        val type: ActionType,
        val name: String,
        val tool: String,
        val produces: List<String>,
        val precondition: (PlannerState) -> Boolean,
        val baseWeight: Double,
    )

    private fun actionsFor(goal: Goal): List<ActionDef> {
        val signal = goal.keySignals
        fun has(s: String) = { st: PlannerState -> st.confirmedSignals.contains(s) }
        fun notHas(s: String) = { st: PlannerState -> !st.confirmedSignals.contains(s) }

        return listOf(
            ActionDef(ActionType.OBSERVE, "被动侦察证据库",
                "reverse.introspect", listOf("recon_done"),
                notHas("recon_done"), 1.0),
            ActionDef(ActionType.STATIC, "静态分析敏感函数与数据流",
                "reverse.analyze_script", signal.firstOrNull { s -> s == "crypto_found" || s == "token_source" || s == "endpoint_chain" }?.let { listOf(it) } ?: emptyList(),
                { st -> st.confirmedSignals.contains("recon_done") }, 0.9),
            ActionDef(ActionType.DYNAMIC_TRACE, "动态追踪关键函数-值指纹",
                "reverse.trace_value", listOf("input_chain", "token_source", "crypto_found"),
                anySignal(signal, "recon_done"), 0.85),
            ActionDef(ActionType.HOOK, "Hook 敏感/加密函数",
                "reverse.hook_crypto", listOf("crypto_found", "token_source"),
                { st -> st.confirmedSignals.isNotEmpty() && st.iterations > 0 }, 0.8),
            ActionDef(ActionType.CROSS_FLOW, "跨数据流-JS↔WASM/异步谱系联动",
                "reverse.wasm_flow", listOf("wasm_bridge", "flow_map"),
                anySignal(signal, "crypto_found"), 0.75),
            ActionDef(ActionType.BREAKPOINT, "断点定位执行现场",
                "reverse.break_hit", listOf("input_chain", "param_source"),
                { st -> st.confirmedSignals.size >= 2 }, 0.7),
            ActionDef(ActionType.VALIDATE, "验证闭环-本地复现对比",
                "reverse.validate", listOf("output_reproduced"),
                { st -> st.confidence >= 0.4 }, 0.65),
        )
    }

    // ---------------- 状态推进 ----------------

    /** 应用「信号已确认」更新状态，并缓存置信度估算 */
    fun advance(state: PlannerState, newSignals: Set<String>, lastAction: ActionType? = null): PlannerState {
        val confirmed = state.confirmedSignals + newSignals
        val gain = confirmed.size - state.confirmedSignals.size
        // 目标信号完成度 + 边际增益；避免只因“执行过几个动作”就升高置信度。
        val keyTarget = state.goal.keySignals
        val covered = keyTarget.count { it in confirmed }
        val coverage = covered.toDouble() / maxOf(1, keyTarget.size)
        val confidence = (coverage * 0.86 + (gain.coerceAtMost(3) / 3.0) * 0.14).coerceIn(0.0, 1.0)
        val actionsTaken = state.actionsTaken + listOfNotNull(lastAction)
        val blocked = if (lastAction != null && gain == 0) {
            state.blockedActions + (lastAction to (state.blockedActions[lastAction] ?: 0) + 1)
        } else {
            state.blockedActions
        }
        val stalled = if (gain == 0) state.stalled + 1 else 0
        return state.copy(
            confirmedSignals = confirmed,
            confidence = confidence,
            actionsTaken = actionsTaken,
            blockedActions = blocked,
            iterations = state.iterations + 1,
            lastGain = gain,
            stalled = stalled,
        )
    }

    // ---------------- 规划核心 ----------------

    /**
     * 规划下一步行动。
     *
     * 打分 = 目标收益（produces 是否含未确认的关键信号）× 存活权重（惩罚被阻塞行动，
     * 鼓励换策略）× 新颖性（未用过的行动优先）× 覆盖率（避开已确认信号）
     */
    fun planNext(state: PlannerState, topN: Int = 3): List<PlannedAction> {
        val used = state.actionsTaken.toSet()
        val output = mutableListOf<PlannedAction>()

        for (def in actionsFor(state.goal)) {
            if (!def.precondition(state)) continue

            // 1. 目标收益：produces 中含未确认的关键信号的行动更优先
            val goalHit = def.produces.count { it in state.goal.keySignals && it !in state.confirmedSignals }
            // 2. 覆盖收益：产出全新信号（任何）也加分
            val novelOut = def.produces.count { it !in state.confirmedSignals }
            // 3. 存活权重：被阻塞则大幅降权
            var weight = def.baseWeight
            val blocks = state.blockedActions[def.type] ?: 0
            if (blocks > 0) weight *= (0.4 / blocks) // 被阻塞 2 次 → 权重剩 0.2
            // 4. 新颖性：已用过的行动降权
            val novelty = if (def.type in used) 0.3 else 1.0
            // 5. 覆盖率：全部产出信号已确认 → 不值得再做
            val saturation = if (def.produces.isNotEmpty() && def.produces.all { it in state.confirmedSignals }) 0.2 else 1.0

            // 连续卡住时，主动提高“换路线”的价值：静态→动态→跨流→验证，而不是重复同一种动作。
            val exploration = if (state.stalled >= 2 && def.type !in used) 1.35 else 1.0
            val stalePenalty = if (state.stalled >= 3 && def.type in used) 0.55 else 1.0
            val score = (goalHit * 2.0 + novelOut * 1.0) * weight * novelty * saturation * exploration * stalePenalty
            val precedence = ((goalHit * 2.0 + novelOut * 1.0 + weight * novelty) * exploration * stalePenalty).toInt().coerceIn(1, 100)
            output += PlannedAction(
                type = def.type,
                action = def.name,
                toolHint = def.tool,
                expectation = def.produces.joinToString(" / ") { it },
                precedence = precedence,
                weight = weight,
                novelty = novelty,
                reason = reasonFor(def, state, goalHit),
            )
        }

        return output.sortedByDescending { it.precedence }.take(topN)
    }

    private fun reasonFor(def: ActionDef, state: PlannerState, goalHit: Int): String {
        val blocks = state.blockedActions[def.type] ?: 0
        return when {
            goalHit > 0 -> "直击目标关键信号（${def.produces.filter { it in state.goal.keySignals }.joinToString("/")}）"
            blocks > 0 -> "已连续阻塞 $blocks 次，自动降低该路线权重并鼓励切换证据来源"
            def.type in state.actionsTaken -> "已执行过一轮，适配当前置信度 ${(state.confidence * 100).toInt()}%"
            else -> "该行动的前置条件已满足，推进认知状态"
        }
    }

}

/** 前置条件：signals 里任一信号已确认，或 anchor 已确认 */
private fun anySignal(signals: List<String>, anchor: String) = { st: AdaptiveInvestigationPlanner.PlannerState ->
    (signals.any { it in st.confirmedSignals } || anchor in st.confirmedSignals)
}