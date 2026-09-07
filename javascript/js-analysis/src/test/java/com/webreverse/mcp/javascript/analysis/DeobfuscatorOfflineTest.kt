package com.webreverse.mcp.javascript.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Deobfuscator 离线反混淆 pass 单元测试（ P2-10）。
 *
 * 覆盖：
 * - 成员访问括号化还原 X['k'] -> X.k
 * - 布尔字面量折叠 !![] -> true / ![] -> false
 * - void 0x0 -> undefined
 * - 逗号序列 (0,fn)(x) -> fn(x)
 * - if(false) 死分支删除（含 else 保留）
 */
class DeobfuscatorOfflineTest {

    private val deob = Deobfuscator(evaluate = { null })

    @Test
    fun `fixes member notation`() {
        val src = "var a = _0xbc['length']; var b = obj['push'](x);"
        val r = deob.deobfuscateOffline(src)
        assertTrue("应还原成员括号", r.memberNotationFixed >= 2)
        assertTrue(r.code.contains("_0xbc.length"))
        assertTrue(r.code.contains("obj.push(x)"))
    }

    @Test
    fun `folds boolean literals`() {
        val src = "if (!![]) { x = ![]; } var y = !!0;"
        val r = deob.deobfuscateOffline(src)
        assertTrue("应折叠布尔字面量", r.booleanFolded >= 3)
        assertTrue(r.code.contains("if (true)"))
        assertTrue(r.code.contains("x = false"))
        assertTrue(r.code.contains("var y = false"))
    }

    @Test
    fun `folds void zero`() {
        val src = "var u = void 0x0;"
        val r = deob.deobfuscateOffline(src)
        assertTrue("应折叠 void 0x0", r.voidFolded >= 1)
        assertTrue(r.code.contains("var u = undefined"))
    }

    @Test
    fun `folds comma sequence call`() {
        val src = "var r = (0, atob)(s); var q = (0x0, _0x1a)(x);"
        val r = deob.deobfuscateOffline(src)
        assertTrue("应还原逗号序列", r.commaSequences >= 2)
        assertTrue(r.code.contains("atob(s)"))
        assertTrue(r.code.contains("_0x1a(x)"))
    }

    @Test
    fun `removes dead false branch keeping else`() {
        val src = "if (false) { a(); } else { b(); } c();"
        val r = deob.deobfuscateOffline(src)
        assertTrue("应删除死分支", r.deadBranchRemoved >= 1)
        assertTrue("应保留 else 分支体", r.code.contains("b()"))
        assertFalse("应删除死分支体", r.code.contains("a()"))
        assertTrue("后续语句应保留", r.code.contains("c()"))
    }

    private fun assertFalse(msg: String, cond: Boolean) {
        org.junit.Assert.assertFalse(msg, cond)
    }
}
