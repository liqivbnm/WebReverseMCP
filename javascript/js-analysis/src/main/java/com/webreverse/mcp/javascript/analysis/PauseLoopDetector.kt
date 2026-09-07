package com.webreverse.mcp.javascript.analysis

import kotlinx.serialization.Serializable
import java.util.concurrent.ConcurrentHashMap

/**
 * 反调试暂停循环检测器 + 四级恢复状态机（ 新增，参考 ChatGPT 报告 §9/§10/§12）。
 *
 * 背景：网页反调试最常见的形态是 "debugger 语句 + 循环"——AI/调试器一附加就被反复
 * 暂停（pause），普通 Debugger.resume 会立即再次被暂停，形成死循环。仅靠"事后恢复"
 * 治标不治本（报告 §4/§5 强调：唯一可靠路径是"执行前拦截改写"）。
 *
 * 本检测器负责"感知"坏局面并给出递进的处置建议：
 *   一级 skip_all_pauses : 短时间内同一脚本 pause 次数超阈值 → 忽略该脚本所有后续暂停
 *   二级 auto_resume     : 连续 pause 间隔极短且无用户断点 → 说明是反调试自触发 → 建议自动恢复
 *   三级 mark_and_advise : 标记脚本 URL，建议对随后的网络响应做执行前拦截改写（ScriptInterceptor）
 *   四级 source_patch    : 若同一脚本被命中多次且确有 debugger 反调试特征 → 进入源码补丁状态
 *
 * 纯内存、无第三方依赖，可离线单测。线程安全（ConcurrentHashMap + AtomicInteger）。
 */
class PauseLoopDetector {

    /** 检测参数（可调，便于测试） */
    data class Params(
        /** 触发"暂停循环"的窗口内暂停次数阈值 */
        val pauseThreshold: Int = 3,
        /** 统计窗口（毫秒）：窗口内 pause 次数超过阈值即判定循环 */
        val windowMs: Long = 3_000L,
        /** 判定"autoresume 级"的最小连续暂停次数 */
        val autoResumeThreshold: Int = 2,
        /** 判定需要"源码补丁级"的累计命中次数 */
        val patchThreshold: Int = 6,
    )

    /** 四级恢复级别 */
    @Serializable
    enum class RecoveryLevel(val label: String, val severity: Int) {
        NORMAL("正常，无暂停循环", 0),
        SKIP_ALL_PAUSES("检测到暂停循环：忽略目标脚本后续所有暂停", 1),
        AUTO_RESUME("连续暂停过密：建议自动恢复并暂停该脚本", 2),
        MARK_ADVISE_INTERCEPT("反调试锁定：标记脚本并建议执行前拦截改写", 3),
        SOURCE_PATCH("高危反调试：进入源码补丁恢复", 4),
    }

    /** 单脚本观测快照 */
    @Serializable
    data class ScriptObservation(
        val url: String,
        val pauseCount: Int = 0,
        val lastPauseAtMs: Long = 0L,
        val level: RecoveryLevel = RecoveryLevel.NORMAL,
        val interceptedAdvice: String = "",
    )

    /** 聚合诊断结果 */
    @Serializable
    data class PauseLoopReport(
        val inLoop: Boolean = false,
        val overallLevel: RecoveryLevel = RecoveryLevel.NORMAL,
        val scripts: List<ScriptObservation> = emptyList(),
        val totalPauses: Int = 0,
        val recommendation: String = "",
    )

    /** 每个脚本的暂停时间戳（环形/滑动，仅保留窗口内） */
    private data class ScriptState(
        val url: String,
        val pauses: ArrayDeque<Long> = ArrayDeque(),
        var totalHits: Int = 0,
    )

    private val states = ConcurrentHashMap<String, ScriptState>()
    private val params: Params

    constructor(params: Params = Params()) {
        this.params = params
    }

    /** 触发一次暂停事件。url：当前执行到的脚本；isUserBreakpoint：是否为用户显式断点。 */
    fun onPause(url: String, isUserBreakpoint: Boolean = false): RecoveryLevel {
        if (isUserBreakpoint) return RecoveryLevel.NORMAL // 用户手动断点不计数
        val key = url.ifBlank { "__anonymous__" }
        val now = System.currentTimeMillis()
        val st = states.computeIfAbsent(key) { ScriptState(url) }
        synchronized(st) {
            st.totalHits++
            st.pauses.addLast(now)
            // 裁剪窗口外的时间戳
            while (st.pauses.isNotEmpty() && st.pauses.first() < now - params.windowMs) {
                st.pauses.removeFirst()
            }
            return levelOf(st)
        }
    }

    /** 根据当前状态计算恢复级别 */
    private fun levelOf(st: ScriptState): RecoveryLevel {
        val windowCount = st.pauses.size
        return when {
            st.totalHits >= params.patchThreshold &&
                windowCount >= params.pauseThreshold -> RecoveryLevel.SOURCE_PATCH
            windowCount >= params.pauseThreshold &&
                windowCount >= params.autoResumeThreshold -> RecoveryLevel.MARK_ADVISE_INTERCEPT
            windowCount >= params.autoResumeThreshold -> RecoveryLevel.AUTO_RESUME
            windowCount >= params.pauseThreshold -> RecoveryLevel.SKIP_ALL_PAUSES
            else -> RecoveryLevel.NORMAL
        }
    }

    /** 重置单个脚本的观测（例如已对该脚本成功执行拦截改写后） */
    fun reset(url: String) {
        states.remove(url.ifBlank { "__anonymous__" })
    }

    /** 清空所有状态（切换目标/会话时） */
    fun clear() {
        states.clear()
    }

    /** 获取指定脚本的观测快照 */
    fun observe(url: String): ScriptObservation {
        val key = url.ifBlank { "__anonymous__" }
        val st = states[key] ?: return ScriptObservation(url = url)
        val now = System.currentTimeMillis()
        synchronized(st) {
            while (st.pauses.isNotEmpty() && st.pauses.first() < now - params.windowMs) {
                st.pauses.removeFirst()
            }
            return ScriptObservation(
                url = url,
                pauseCount = st.pauses.size,
                lastPauseAtMs = st.pauses.lastOrNull() ?: 0L,
                level = levelOf(st),
                interceptedAdvice = adviceFor(levelOf(st)),
            )
        }
    }

    /** 聚合诊断：供 reverse.detect_protection / debugger workflow 直接返回 */
    fun report(): PauseLoopReport {
        val observations = states.keys.map { observe(it) }
        val total = observations.sumOf { it.pauseCount }
        val maxLevel = observations.maxByOrNull { it.level.severity }?.level ?: RecoveryLevel.NORMAL
        val inLoop = maxLevel.severity >= RecoveryLevel.SKIP_ALL_PAUSES.severity
        return PauseLoopReport(
            inLoop = inLoop,
            overallLevel = maxLevel,
            scripts = observations.sortedByDescending { it.pauseCount },
            totalPauses = total,
            recommendation = adviceFor(maxLevel),
        )
    }

    private fun adviceFor(level: RecoveryLevel): String = when (level) {
        RecoveryLevel.NORMAL -> "无暂停循环，可正常调试"
        RecoveryLevel.SKIP_ALL_PAUSES -> "检测到反调试暂停循环：建议跳过该脚本所有暂停（debugger.skip_all_pauses）"
        RecoveryLevel.AUTO_RESUME -> "连续暂停过密：建议自动恢复（debugger.resume 并临时暂停该脚本）"
        RecoveryLevel.MARK_ADVISE_INTERCEPT ->
            "反调试锁定：标记该脚本为反调试目标；建议对后续网络响应启用执行前拦截改写（ScriptInterceptor 中和 debugger），" +
                "这是唯一可根治的路径"
        RecoveryLevel.SOURCE_PATCH -> "高危反调试：已进入源码补丁级恢复，需结合 AntiDebugDetector 定位 debugger 类别并对 JS 响应打补丁后重载"
    }

    /** 便捷：单 URL 是否已进入需要拦截改写的级别 */
    fun shouldIntercept(url: String): Boolean {
        val lv = observe(url).level
        return lv.severity >= RecoveryLevel.MARK_ADVISE_INTERCEPT.severity
    }
}