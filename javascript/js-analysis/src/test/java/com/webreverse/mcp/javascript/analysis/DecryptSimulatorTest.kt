package com.webreverse.mcp.javascript.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * DecryptSimulator + StaticAnalyzer.decryptChain 单元测试。
 *
 * 覆盖 javascript-obfuscator 四大解码器原型的真实还原：
 * - INDEX_OFFSET：array[idx - 0x104]（最常见，含偏移自解）
 * - BASE64：atob(array[idx])（原型优先级最高）
 * - XOR_CONST：charCodeAt ^ K
 * - CAESAR：charCodeAt ± K
 * - 三件套识别（StaticAnalyzer）与沙箱脚本生成
 */
class DecryptSimulatorTest {

    // ---------------- INDEX_OFFSET ----------------

    @Test
    fun `resolves index offset archetype with const`() {
        // effective = idx + 0*b + (-0x104)；10 元素模回环
        val src = """
            var _0x4e2c = ['alpha','bravo','charlie','delta','echo','foxtrot','golf','hotel','india','juliet'];
            function _0x5c8f(_0x3fa2, _0x4b1d) {
                var _0x9e1f = parseInt(_0x4b1d, 16);
                return _0x4e2c[_0x3fa2 - 0x104];
            }
            console.log(_0x5c8f(0x105, 0x0));
            console.log(_0x5c8f(0x108, 0x0));
        """.trimIndent()
        val r = DecryptSimulator().simulate(src)
        assertTrue("应识别到解密链", r.found)
        assertEquals("_0x4e2c", r.arrayName)
        assertEquals("_0x5c8f", r.decoderName)
        assertEquals("应还原 2 个调用点，实际 ${r.resolved.size}", 2, r.resolved.size)
        // (0x105 - 0x104) % 10 = 1 -> bravo；(0x108 - 0x104) % 10 = 4 -> echo
        assertEquals("bravo", r.resolved[0].value)
        assertEquals("echo", r.resolved[1].value)
        assertEquals(DecryptSimulator.Method.INDEX_OFFSET, r.resolved[0].method)
        assertTrue("原型描述应含 const=-260", r.decoderArchetype.contains("const=-260"))
    }

    // ---------------- BASE64 ----------------

    @Test
    fun `resolves base64 archetype with priority`() {
        // 元素本身是 base64 密文；BASE64 原型优先于 INDEX_OFFSET
        val src = """
            var _0x7b2a = ['Y2F0','ZG9n','YmlyZA==','Zm9vZA==','bG9n','Y2Fy','Ym9vaw==','aGVsbG8='];
            function _0x4f1c(_0x22a1, _0x22b3) {
                var _0x88f = atob(_0x7b2a[_0x22a1]);
                return _0x88f;
            }
            console.log(_0x4f1c(0x0));
            console.log(_0x4f1c(0x1));
        """.trimIndent()
        val r = DecryptSimulator().simulate(src)
        assertTrue(r.found)
        assertEquals("应还原 2 个调用点，实际 ${r.resolved.size}", 2, r.resolved.size)
        assertEquals("cat", r.resolved[0].value)
        assertEquals("dog", r.resolved[1].value)
        assertEquals(DecryptSimulator.Method.BASE64, r.resolved[0].method)
        assertTrue("原型应标注 base64", r.decoderArchetype.contains("base64"))
    }

    // ---------------- XOR_CONST ----------------

    @Test
    fun `resolves xor const archetype`() {
        // element = plaintext ^ 0x1f：cat->|~k, dog->{px, ...
        val src = """
            var _0x9a3f = ['|~k','{px','ljq','ozq','r~o','}pg','tzf','spx'];
            function _0x6d21(_0x11a2, _0x22b3) {
                var _0x77f = String.fromCharCode(_0x9a3f[_0x11a2].charCodeAt(0) ^ 0x1f);
                return _0x77f;
            }
            console.log(_0x6d21(0x0));
            console.log(_0x6d21(0x1));
        """.trimIndent()
        val r = DecryptSimulator().simulate(src)
        assertTrue(r.found)
        assertEquals(2, r.resolved.size)
        assertEquals("cat", r.resolved[0].value)
        assertEquals("dog", r.resolved[1].value)
        assertEquals(DecryptSimulator.Method.XOR_CONST, r.resolved[0].method)
    }

    // ---------------- CAESAR ----------------

    @Test
    fun `resolves caesar archetype with negative shift`() {
        // element = plaintext + 2；decoder 用 charCodeAt - 2 还原
        val src = """
            var _0xb1c4 = ['ecv','fqi','uwp','rgp','ocr','dqz','mg{','nqi'];
            function _0x3e8a(_0x44c1, _0x55d2) {
                var _0x2f1b = _0xb1c4[_0x44c1].charCodeAt(0) - 0x2;
                return String.fromCharCode(_0x2f1b);
            }
            console.log(_0x3e8a(0x0));
            console.log(_0x3e8a(0x1));
        """.trimIndent()
        val r = DecryptSimulator().simulate(src)
        assertTrue(r.found)
        assertEquals(2, r.resolved.size)
        assertEquals("cat", r.resolved[0].value)
        assertEquals("dog", r.resolved[1].value)
        assertEquals(DecryptSimulator.Method.CAESAR, r.resolved[0].method)
    }

    // ---------------- 兜底 ----------------

    @Test
    fun `no chain in plain code`() {
        val plain = "function add(a, b) { return a + b; }\nconsole.log(add(1, 2));\n"
        val r = DecryptSimulator().simulate(plain)
        assertFalse("普通代码不应识别出解密链", r.found)
        assertTrue("应给出提示", r.notes.isNotEmpty())
    }

    @Test
    fun `sandbox script is self-contained iife`() {
        val src = """
            var _0x4e2c = ['alpha','bravo','charlie','delta','echo','foxtrot','golf','hotel','india','juliet'];
            function _0x5c8f(_0x3fa2, _0x4b1d) {
                var _0x9e1f = parseInt(_0x4b1d, 16);
                return _0x4e2c[_0x3fa2 - 0x104];
            }
            console.log(_0x5c8f(0x105, 0x0));
        """.trimIndent()
        val r = DecryptSimulator().simulate(src)
        assertTrue(r.found)
        val script = r.sandboxScript
        assertTrue("沙箱脚本应是 IIFE", script.startsWith("(function()"))
        assertTrue("应重放数组声明", script.contains("var _0x4e2c"))
        assertTrue("应重放解码函数", script.contains("function _0x5c8f"))
        assertTrue("应逐调用点 eval", script.contains("eval"))
        assertTrue("应返回 JSON", script.contains("JSON.stringify"))
    }

    // ---------------- StaticAnalyzer 三件套 ----------------

    @Test
    fun `static analyzer exposes full declarations`() {
        val src = """
            var _0x4e2c = ['alpha','bravo','charlie','delta','echo','foxtrot','golf','hotel','india','juliet'];
            function _0x5c8f(_0x3fa2, _0x4b1d) {
                var _0x9e1f = parseInt(_0x4b1d, 16);
                return _0x4e2c[_0x3fa2 - 0x104];
            }
            console.log(_0x5c8f(0x105, 0x0));
        """.trimIndent()
        val chain = StaticAnalyzer().analyze(src).decryptChain
        assertTrue("三件套应被识别", chain.found)
        assertEquals(10, chain.arraySize)
        assertTrue("完整数组声明应导出", chain.arrayDecl.contains("'alpha'"))
        assertTrue("完整解码器声明应导出", chain.decoderDecl.contains("0x104"))
        assertEquals("调用点应被提取", 1, chain.decodeCallSites.size)
        assertEquals("_0x5c8f(0x105, 0x0)", chain.decodeCallSites[0].expression)
    }

    @Test
    fun `resolved site carries source line`() {
        val src = """
            var _0x4e2c = ['alpha','bravo','charlie','delta','echo','foxtrot','golf','hotel','india','juliet'];
            function _0x5c8f(_0x3fa2, _0x4b1d) {
                var _0x9e1f = parseInt(_0x4b1d, 16);
                return _0x4e2c[_0x3fa2 - 0x104];
            }
            console.log(_0x5c8f(0x105, 0x0));
        """.trimIndent()
        val r = DecryptSimulator().simulate(src)
        assertTrue(r.found)
        // 调用点在 console.log 行（1-based 第 6 行）
        assertEquals("调用点行号应为 6，实际 ${r.resolved.first().line}", 6, r.resolved.first().line)
        assertTrue("置信度应在 0-100", r.resolved.first().confidence in 0..100)
    }
}
