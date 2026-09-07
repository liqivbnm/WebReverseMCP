package com.webreverse.mcp.javascript.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * VmpDetector + JsvmpDeepAnalyzer 单元测试。
 *
 * 覆盖：
 * - dispatch 循环定位（while+switch+case>=4）
 * - case handler 切片提取
 * - VM 状态变量识别（pc/sp/ctx/字节码数组，覆盖 _0x 混淆名）
 * - handler 语义分类与直方图
 */
class VmpAnalyzerTest {

    /** 典型 JSVMP 骨架：while(true)+switch(_0xbc[_0xpc++])，5 个 case + default */
    private val vmpSource = """
        var _0xbc = [1, 26, 5, 3, 4, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 55, 66, 77, 88, 99, 11, 22, 33];
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

    // ---------------- VmpDetector ----------------

    @Test
    fun `detects dispatch loop with handlers`() {
        val candidates = VmpDetector().detect(vmpSource)
        assertTrue("应检测到至少 1 个 JSVMP 候选", candidates.isNotEmpty())
        val c = candidates.first()
        assertTrue("case 数应 >= 5，实际 ${c.caseCount}", c.caseCount >= 5)
        assertTrue("handler 切片应 >= 5，实际 ${c.handlers.size}", c.handlers.size >= 5)
        assertTrue("置信度应 > 0", c.score > 0)
        // handler 键应包含十六进制 opcode
        val keys = c.handlers.map { it.key }
        assertTrue("应包含 case 0x01 键，实际 $keys", keys.any { it == "0x01" || it == "1" })
    }

    @Test
    fun `no vmp in plain code`() {
        val plain = """
            function add(a, b) { return a + b; }
            switch (process(x)) { case 1: break; }
        """.trimIndent()
        // case 数不足 4，不应产生候选
        val candidates = VmpDetector().detect(plain)
        assertTrue("普通代码不应误报 JSVMP", candidates.none { it.caseCount >= 4 })
    }

    @Test
    fun `for-loop dispatch also detected`() {
        val forLoop = """
            var _0xops = [11, 22, 33, 44, 55, 66, 77, 88, 99, 10, 11, 12, 13, 14, 15, 16];
            var _0xpc = 0;
            for (;;) {
                switch (_0xops[_0xpc++]) {
                    case 0x10: _0xpc = 0; break;
                    case 0x11: break;
                    case 0x12: break;
                    case 0x13: break;
                    case 0x14: return;
                }
            }
        """.trimIndent()
        val candidates = VmpDetector().detect(forLoop)
        assertTrue("for(;;) dispatch 应被检测到", candidates.isNotEmpty())
    }

    // ---------------- JsvmpDeepAnalyzer ----------------

    @Test
    fun `classifies handlers and builds histogram`() {
        val candidate = VmpDetector().detect(vmpSource).first()
        val profile = JsvmpDeepAnalyzer().analyze(vmpSource, candidate)
        assertEquals("handler 分类数应等于 case 数", candidate.caseCount, profile.handlers.size)
        assertTrue("直方图应非空", profile.kindHistogram.isNotEmpty())
        // 所有 case 体都有强特征，不应落入 UNKNOWN
        val unknown = profile.handlers.filter { it.kind == JsvmpDeepAnalyzer.HandlerKind.UNKNOWN }
        assertTrue("不应有 UNKNOWN 分类，实际 $unknown", unknown.isEmpty())
        // case 0x02 体 pop()+pop()+push() 特征最突出 -> STACK_OP 语义应在直方图中
        assertTrue(
            "应识别出栈操作语义，实际 ${profile.kindHistogram.keys}",
            profile.kindHistogram.keys.any { it.contains("栈操作") },
        )
    }

    @Test
    fun `identifies vm state variables with obfuscated names`() {
        val candidate = VmpDetector().detect(vmpSource).first()
        val vars = JsvmpDeepAnalyzer().analyze(vmpSource, candidate).variables
        // 判别式 _0xbc[_0xpc++]
        assertTrue("dispatch 判别式应包含 _0xbc", vars.dispatchExpr.contains("_0xbc"))
        assertTrue("字节码数组候选应含 _0xbc，实际 ${vars.bytecodeCandidates}", vars.bytecodeCandidates.contains("_0xbc"))
        assertTrue("pc 候选应含 _0xpc，实际 ${vars.pcCandidates}", vars.pcCandidates.contains("_0xpc"))
        assertTrue("栈候选应含 _0xstack，实际 ${vars.spCandidates}", vars.spCandidates.contains("_0xstack"))
        assertTrue("上下文候选应含 _0xregs，实际 ${vars.ctxCandidates}", vars.ctxCandidates.contains("_0xregs"))
    }

    @Test
    fun `extracts instruction stream from array carrier`() {
        val candidate = VmpDetector().detect(vmpSource).first()
        val ins = JsvmpDeepAnalyzer().analyze(vmpSource, candidate).instructions
        assertEquals("载体类型应为 array", "array", ins.carrierType)
        assertEquals("指令数应为 24", 24, ins.instructionCount)
        assertTrue("opcode 预览非空", ins.opcodePreview.isNotEmpty())
    }

    @Test
    fun `isa summary is human readable`() {
        val candidate = VmpDetector().detect(vmpSource).first()
        val summary = JsvmpDeepAnalyzer().analyze(vmpSource, candidate).isaSummary
        assertTrue("ISA 摘要应非空", summary.isNotBlank())
    }
}
