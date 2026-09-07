package com.webreverse.mcp.javascript.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * TraceSymbolizer 单元测试（ P1-7）。
 *
 * 覆盖：
 * - 对象采样（{op,pc}）与标量采样解析
 * - arity 感知切分（内联操作数消费）
 * - RLE 单条折叠与块级 repeat 折叠
 * - 空样本 / 不可解析样本失败路径
 */
class TraceSymbolizerTest {

    @Test
    fun `symbolizes object samples with arity`() {
        // op=1 消费 1 个操作数；op=2 无操作数。ISA: 1->PUSH, 2->ADD
        // 未知 opcode 55 需作为独立指令出现（不被 PUSH 当作操作数消费）
        val samples = listOf(
            """{"op":1,"pc":0}""",
            """{"op":2,"pc":1}""",   // PUSH 的操作数
            """{"op":1,"pc":2}""",
            """{"op":2,"pc":3}""",   // PUSH 的操作数
            """{"op":55,"pc":4}""",  // 独立未知指令
            """{"op":2,"pc":5}""",   // ADD
        )
        val r = TraceSymbolizer().symbolize(
            samples,
            isa = mapOf("1" to "PUSH", "2" to "ADD"),
            arity = mapOf("1" to 1),
        )
        assertTrue("应成功符号化", r.ok)
        assertEquals("样本数应为 6", 6, r.samples)
        assertTrue("伪代码应含 PUSH 助记", r.listing.contains("PUSH"))
        assertTrue("伪代码应含 ADD 助记", r.listing.contains("ADD"))
        assertTrue("未识别 opcode 应标注 UNKNOWN", r.listing.contains("UNKNOWN_0x37")) // 55
        assertTrue("ISA 命中统计应含 isaHit", r.coverage.containsKey("isaHit"))
    }

    @Test
    fun `scalar samples parsed`() {
        val samples = listOf("1", "2", "1", "2", "1", "2", "1", "2", "1", "2")
        val r = TraceSymbolizer().symbolize(samples, isa = mapOf("1" to "PUSH", "2" to "ADD"))
        assertTrue(r.ok)
        assertEquals(10, r.samples)
        // 1,2 交替重复 >=3 次 → 块折叠
        assertTrue("应发生块级折叠", r.blocksFolded >= 1)
        assertTrue("伪代码应含 repeat", r.listing.contains("repeat"))
    }

    @Test
    fun `rle folds single repeated op`() {
        val samples = List(12) { """{"op":7,"pc":$it}""" }
        val r = TraceSymbolizer().symbolize(samples, isa = mapOf("7" to "NOP"))
        assertTrue(r.ok)
        assertTrue("单条重复应折叠为 ×N", r.listing.contains("×12"))
        assertTrue("RLE 折叠计数应为 1", r.loopsFolded >= 1)
    }

    @Test
    fun `fails on empty samples`() {
        val r = TraceSymbolizer().symbolize(emptyList(), isa = emptyMap())
        assertFalse(r.ok)
        assertTrue("错误信息应提示先采样", r.error.contains("trace_vmp"))
    }

    @Test
    fun `fails on unparsable samples`() {
        val r = TraceSymbolizer().symbolize(listOf("hello", "world", "foo"), isa = emptyMap())
        assertFalse(r.ok)
        assertTrue("错误信息应提示无法解析", r.error.contains("无法解析"))
    }
}
