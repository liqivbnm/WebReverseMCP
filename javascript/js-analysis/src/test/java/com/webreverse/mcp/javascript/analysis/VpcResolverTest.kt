package com.webreverse.mcp.javascript.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * VpcResolver 单元测试（ P0-4）。
 *
 * 覆盖：
 * - 从多变量对象采样中识别虚拟 pc（distinct 多 + 小增量占比高）
 * - 重建控制流转移边 / 跳转目标 / 热点 pc
 * - 采样不足 / 无可解析数值变量时的失败路径
 */
class VpcResolverTest {

    /** 构造模拟 trace：pc 序列 + 干扰槽位（sp 单调小步、ctx 随机） */
    private fun buildSamples(pcSeq: List<Long>): List<Map<String, String>> {
        var sp = 0L
        return pcSeq.mapIndexed { i, pc ->
            sp += if (i % 3 == 0) 1 else 0
            mapOf(
                "op" to (pc % 7 + 1).toString(),
                "pc" to pc.toString(),
                "sp" to sp.toString(),
                "ctx" to ((pc * 31) % 97).toString(),
            )
        }
    }

    @Test
    fun `resolves vpc from object samples`() {
        // pc 序列：小步推进 + 两次跳变（模拟循环 + 分支）
        val pcSeq = buildList {
            repeat(6) { add(it.toLong()) }            // 0..5
            add(0); add(1); add(2); add(3); add(4)    // 回边到 0
            repeat(5) { add((it + 10).toLong()) }     // 跳变到 10..14
            add(10); add(11); add(12)                 // 再回边
        }
        val samples = buildSamples(pcSeq)
        val r = VpcResolver().resolve(samples)

        assertTrue("应成功识别 vpc，错误: ${r.error}", r.ok)
        assertEquals("vpc 槽位应为 pc", "pc", r.vpcSlot)
        assertEquals("distinct pc 应为 11", 11, r.distinctPcs)
        assertEquals("pc 范围 min 应为 0", 0L, r.pcRange.first)
        assertEquals("pc 范围 max 应为 14", 14L, r.pcRange.second)
        // 跳转目标：0 被回边命中多次，10 被跳变命中
        assertTrue("跳转目标应含 pc=0", r.jumpTargets.containsKey(0L))
        assertTrue("跳转目标应含 pc=10", r.jumpTargets.containsKey(10L))
        assertTrue("热点 pc 应非空", r.hottestPc >= 0)
    }

    @Test
    fun `fails on insufficient samples`() {
        val samples = buildSamples(listOf(0, 1, 2, 3))
        val r = VpcResolver().resolve(samples)
        assertFalse("采样不足应失败", r.ok)
        assertTrue("错误信息应提示采样不足", r.error.contains("采样不足"))
    }

    @Test
    fun `fails when no numeric variables`() {
        val samples = List(20) { mapOf("x" to "undefined", "y" to "[object Object]") }
        val r = VpcResolver().resolve(samples)
        assertFalse("无可解析数值变量应失败", r.ok)
        assertTrue("错误信息应提示无可解析数值变量", r.error.contains("数值变量"))
    }

    @Test
    fun `rejects non-pc-like slot`() {
        // 所有槽位都是随机跳变（无小增量特征）→ 不应识别出 pc
        val samples = List(20) { i ->
            mapOf("a" to ((i * 13) % 97).toString(), "b" to ((i * 29) % 89).toString())
        }
        val r = VpcResolver().resolve(samples)
        assertFalse("无 pc 特征槽位应失败", r.ok)
        assertTrue("错误信息应提示未发现 pc 特征变量", r.error.contains("pc 特征"))
    }
}
