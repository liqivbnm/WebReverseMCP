package com.webreverse.mcp.javascript.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * DecodeFormula 单元测试（ P1-6）。
 *
 * 覆盖：
 * - (K*byte)%M 乘法取模公式提取与 byte->opcode 建表
 * - byte^K 异或公式
 * - 直通（无映射）场景
 * - 判别式为空 / 无候选公式
 */
class DecodeFormulaTest {

    @Test
    fun `extracts mul-mod formula`() {
        // 判别式 (0x1f * _0xbc[_0xpc++]) % 0xf1，case 键覆盖映射后的 opcode 空间
        val caseKeys = (0..40).map { (it * 31) % 241 }.toSet() // 31 的倍数模 241
        val f = DecodeFormula.extract("(0x1f * _0xbc[_0xpc++]) % 0xf1", caseKeys)
        assertTrue("应提取到乘法取模公式", f.isActive)
        assertTrue("公式描述应含乘法", f.description.contains("*"))
        assertTrue("映射表应非空", f.mappedCount > 0)
        // 验证映射正确性：byte=1 -> (1*31)%241 = 31
        val mapped = f.map(listOf(1, 2, 3))
        assertEquals("byte=1 应映射为 31", 31, mapped[0])
        assertEquals("byte=2 应映射为 62", 62, mapped[1])
        assertEquals("byte=3 应映射为 93", 93, mapped[2])
    }

    @Test
    fun `extracts xor formula`() {
        // case 键 = 解码后的 opcode 空间（0..20）；字节 0x5a..0x6e 经 ^0x5a 映射到该空间
        val caseKeys = (0..20).toSet()
        val f = DecodeFormula.extract("_0xbc[_0xpc++] ^ 0x5a", caseKeys)
        assertTrue("应提取到异或公式", f.isActive)
        val mapped = f.map(listOf(0x5a, 0x5b, 0x5c))
        assertEquals("byte^0x5a 应为 0", 0, mapped[0])
        assertEquals("0x5b^0x5a 应为 1", 1, mapped[1])
        assertEquals("0x5c^0x5a 应为 6", 6, mapped[2])
    }

    @Test
    fun `passthrough when no formula matches`() {
        val f = DecodeFormula.extract("_0xbc[_0xpc++]", setOf(1, 2, 3))
        assertFalse("无公式时应直通", f.isActive)
        assertEquals("直通映射应原样返回", listOf(1, 2, 3), f.map(listOf(1, 2, 3)))
        assertTrue("描述应为直通", f.description.contains("直通"))
    }

    @Test
    fun `passthrough on blank dispatch`() {
        val f = DecodeFormula.extract("", setOf(1))
        assertFalse(f.isActive)
        assertEquals("空判别式应直通", listOf(5), f.map(listOf(5)))
    }

    @Test
    fun `low hit ratio falls back to passthrough`() {
        // case 键落在公式映射空间之外（(31*byte)%241 的值域为 0..240）→ 无交集，不应误判
        val caseKeys = setOf(250, 251, 252, 253)
        val f = DecodeFormula.extract("(0x1f * _0xbc[_0xpc++]) % 0xf1", caseKeys)
        assertFalse("映射率过低应直通", f.isActive)
    }
}
