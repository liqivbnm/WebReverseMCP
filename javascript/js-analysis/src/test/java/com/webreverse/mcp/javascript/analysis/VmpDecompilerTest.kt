package com.webreverse.mcp.javascript.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

/**
 * VmpDecompiler 单元测试。
 *
 * 覆盖：
 * - array / hex / base64 三类字节码载体的全量提取
 * - ISA 映射（case 键 0xNN 归一化为十进制与载体元素对齐）
 * - arity 消费、基本块计数、循环回边
 * - arityOverride 精修
 * - 无静态载体时 runtimeNeeded 提示
 */
class VmpDecompilerTest {

    private fun vmSkeleton(carrier: String): String = """
        $carrier
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
                        _0xpc = _0xbc[_0xpc + 1] - 1;
                        break;
                    case 0x05:
                        _0xstack.push(_0xregs[_0xbc[_0xpc + 1]]);
                        break;
                    default:
                        return _0xstack.pop();
                }
            }
        }
        _0xvm();
    """.trimIndent()

    private fun decompileOf(source: String): VmpDecompiler.Decompiled {
        val candidate = VmpDetector().detect(source).firstOrNull()
            ?: throw AssertionError("测试样本未检出 JSVMP 候选")
        return VmpDecompiler().decompile(source, candidate)
    }

    @Test
    fun `decompiles array carrier with blocks and loop back`() {
        // 18 个 opcode；op=4（跳转原型）目标 0 形成回边
        val src = vmSkeleton("var _0xbc = [1, 26, 5, 3, 4, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 55, 66];")
        val r = decompileOf(src)
        assertTrue("应成功反编译", r.ok)
        assertEquals("载体类型应为 array", "array", r.carrierType)
        assertEquals("载体元素总数应为 18", 18, r.totalInstructions)
        assertTrue("应至少解释 4 条指令，实际 ${r.decodedInstructions}", r.decodedInstructions >= 4)
        assertTrue("基本块应 >= 2，实际 ${r.blocks}", r.blocks >= 2)
        assertTrue("应检测到循环回边，实际 ${r.loopBacks}", r.loopBacks >= 1)
        assertTrue("伪代码应含载体头", r.listing.contains("carrier=array"))
        // 跳转目标 0 应生成 L0 标签
        assertTrue("应生成 L0: 标签", r.listing.contains("L0:"))
        assertTrue("arity 映射应非空", r.arityUsed.isNotEmpty())
    }

    @Test
    fun `decompiles hex string carrier`() {
        // 140 个 hex 字符（70 字节）
        val hex = "1a050304050102".repeat(10)
        val src = vmSkeleton("var _0xbc = \"$hex\";")
        val r = decompileOf(src)
        assertTrue(r.ok)
        assertEquals("hex", r.carrierType)
        assertEquals("hex 载体应解码出 70 字节", 70, r.totalInstructions)
    }

    @Test
    fun `decompiles base64 carrier`() {
        // 120 字节 -> 160 base64 字符（超过 150 阈值；编码含非 hex 字符避免误入 hex 分支）
        val bytes = ByteArray(120) { (it % 8 + 1).toByte() } // op 1..8 循环
        val b64 = Base64.getEncoder().encodeToString(bytes)
        val src = vmSkeleton("var _0xbc = \"$b64\";")
        val r = decompileOf(src)
        assertTrue(r.ok)
        assertEquals("base64", r.carrierType)
        assertEquals("base64 载体应解码出 120 字节", 120, r.totalInstructions)
    }

    @Test
    fun `arity override changes operand consumption`() {
        val src = vmSkeleton("var _0xbc = [1, 26, 5, 3, 4, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 55, 66];")
        val candidate = VmpDetector().detect(src).first()
        val base = VmpDecompiler().decompile(src, candidate)
        // op=1 强制 2 个操作数 → 解释的指令数必然减少
        val widened = VmpDecompiler().decompile(src, candidate, arityOverride = mapOf("0x01" to 2))
        assertTrue("精修后 op=1 的 arity 应为 2", widened.arityUsed["1"] == 2)
        assertTrue(
            "扩大 arity 后解释指令数应减少或持平（${base.decodedInstructions} -> ${widened.decodedInstructions}）",
            widened.decodedInstructions <= base.decodedInstructions,
        )
    }

    @Test
    fun `no carrier reports runtime needed`() {
        // 字节码数组过小（<16）且无 hex/base64 载体
        val src = vmSkeleton("var _0xbc = [1, 2, 3];")
        val r = decompileOf(src)
        assertFalse("无静态载体时 ok=false", r.ok)
        assertTrue("应提示需运行时 trace", r.runtimeNeeded)
        assertTrue("错误信息应给出 trace_vmp 建议", r.error.contains("trace"))
    }

    @Test
    fun `maxInstructions caps listing`() {
        val src = vmSkeleton("var _0xbc = [1, 26, 5, 3, 4, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 55, 66];")
        val candidate = VmpDetector().detect(src).first()
        val r = VmpDecompiler().decompile(src, candidate, maxInstructions = 2)
        assertTrue(r.ok)
        assertEquals("maxInstructions 应限制解释条数", 2, r.decodedInstructions)
    }

    @Test
    fun `unknown opcodes collected`() {
        // op=9/8/7/6 无对应 case → unresolved
        val src = vmSkeleton("var _0xbc = [9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 55, 66, 77, 88, 99, 11, 22, 33];")
        val r = decompileOf(src)
        assertTrue(r.ok)
        assertTrue("应收集未知 opcode（9/8/7/6），实际 ${r.unresolvedOpcodes}", r.unresolvedOpcodes.isNotEmpty())
    }
}
