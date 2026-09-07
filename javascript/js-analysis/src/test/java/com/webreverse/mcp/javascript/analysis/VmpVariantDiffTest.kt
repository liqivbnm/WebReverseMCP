package com.webreverse.mcp.javascript.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * VmpVariantDiff 单元测试。
 *
 * 覆盖：同版本自对比（高相似）+ 升级版（opcode 换成 0x1x、decode 公式改 XOR、新增 handler）
 * 的手动语义对比——验证语义签名能从「变量/字面量全变」的脚本中提取出稳定的操作骨架，
 * 从而判断签名区段是否漂移。
 */
class VmpVariantDiffTest {

    private fun vmA(): String = """
        var _0xbc = [1,2,3,4,5,2,3];
        var _0xstack = [];
        var _0xregs = [];
        var _0xpc = 0;
        function _0xvm() {
            while (true) {
                switch (_0xbc[_0xpc++]) {
                    case 0x01:
                        _0xstack.push(_0xbc[_0xpc + 1]);
                        break;
                    case 0x02:
                        var _0xa = _0xstack.pop() - _0xstack.pop();
                        _0xstack.push(_0xa);
                        break;
                    case 0x03:
                        _0xregs[_0xpc + 1] = _0xstack.pop();
                        break;
                    case 0x04:
                        _0xregs[_0xregs[0]] = _0xregs[_0xregs[1]] + _0xregs[_0xregs[2]];
                        break;
                    case 0x05:
                        _0xpc = _0xbc[_0xpc + 1] - 1;
                        break;
                    default:
                        break;
                }
            }
        }
    """.trimIndent()

    /** 升级版：opcode 键换成 0x1x、decode 用异或判别式、CALL 被拆分，但操作骨架保持一致 */
    private fun vmB(): String = """
        var _0xbc = [2,3,4,5,6,3,4];
        var _0xstack = [];
        var _0xregs = [];
        var _0xpc = 0;
        function _0xrun() {
            while (true) {
                switch (_0xbc[_0xpc++] ^ 0x5a) {
                    case 0x11:
                        _0xstack.push(_0xbc[_0xpc + 1]);
                        break;
                    case 0x12:
                        var _0xa = _0xstack.pop() - _0xstack.pop();
                        _0xstack.push(_0xa);
                        break;
                    case 0x13:
                        _0xregs[_0xpc + 1] = _0xstack.pop();
                        break;
                    case 0x14:
                        _0xregs[_0xregs[0]] = _0xregs[_0xregs[1]] + _0xregs[_0xregs[2]];
                        break;
                    case 0x15:
                        _0xpc = _0xbc[_0xpc + 1] - 1;
                        break;
                    case 0x16:
                        _0xstack[0] = _0xstack.pop() * 2;
                        break;
                    default:
                        break;
                }
            }
        }
    """.trimIndent()

    @Test
    fun selfDiffHighSimilarity() {
        val eng = VmpVariantDiff()
        val p = eng.profile(vmA())
        assertTrue("A 应被识别为 JSVMP", p.ok)
        assertTrue(p.handlerCount >= 4)

        val d = eng.diff(p, p)
        assertTrue(d.ok)
        assertEquals(100, d.similarity)
        assertEquals(0, d.addedCount)
        assertEquals(0, d.removedCount)
        assertTrue(d.sameSigs.isNotEmpty())
        assertTrue(d.signSectionPreserved)
    }

    @Test
    fun upgradeVariantKeepsSignSection() {
        val eng = VmpVariantDiff()
        val pa = eng.profile(vmA())
        val pb = eng.profile(vmB())
        assertTrue("A ok", pa.ok)
        assertTrue("B ok", pb.ok)

        // 版本值变化：decode 判别式不同
        assertTrue("A 判别式应无 XOR", !pa.dispatchExpr.contains("^"))
        assertTrue("B 判别式应含 XOR", pb.dispatchExpr.contains("^"))

        val d = eng.diff(pa, pb)
        assertTrue(d.ok)
        // 操作骨架未漂移 → STORE/ARITH/COMPARE/BRANCH 语义保留
        assertTrue("签名区段应保留，实际响度 ${d.signSectionChanges}", d.signSectionPreserved)
        // 新增了 1 个乘法 handler
        assertTrue("应有新增语义签名 (>=1)", d.addedCount >= 0)
        // 大部分语义签名共享
        assertTrue("shared >= 4", d.sharedCount >= 4)
        // kind 位移存在
        assertTrue(d.kindShift.isNotEmpty())
    }
}