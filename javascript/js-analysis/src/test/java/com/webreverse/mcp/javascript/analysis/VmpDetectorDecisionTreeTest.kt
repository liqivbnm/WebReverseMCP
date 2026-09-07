package com.webreverse.mcp.javascript.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * VmpDetector decision-tree dispatcher 检测单元测试（ P1-5）。
 *
 * 覆盖：
 * - if/else-if 比较链派发（switch 检测盲区形态）识别
 * - dispatchStyle 标注为 if-tree
 * - handler 切片提取（分支体）
 * - 分支规模不足 / 无循环包裹时不误报
 */
class VmpDetectorDecisionTreeTest {

    /** 构造 decision-tree 风格 VM：while(true) + if/else-if 链 */
    private fun treeSkeleton(branchCount: Int): String {
        val sb = StringBuilder()
        sb.appendLine("var _0xbc = [1,2,3,4,5,6,7,8,9,10];")
        sb.appendLine("var _0xpc = 0;")
        sb.appendLine("function _0xvm() {")
        sb.appendLine("  while (true) {")
        sb.appendLine("    var _0xop = _0xbc[_0xpc++];")
        for (i in 1..branchCount) {
            if (i == 1) {
                sb.appendLine("    if (_0xop === 0x$i) { _0xstack.push(_0xbc[_0xpc + 1]); }")
            } else {
                sb.appendLine("    else if (_0xop === 0x$i) { _0xstack.push(_0xbc[_0xpc + 1]); }")
            }
        }
        sb.appendLine("    else { return _0xstack.pop(); }")
        sb.appendLine("  }")
        sb.appendLine("}")
        return sb.toString()
    }

    @Test
    fun `detects decision-tree dispatch`() {
        val src = treeSkeleton(8)
        val candidates = VmpDetector().detect(src)
        val tree = candidates.firstOrNull { it.dispatchStyle == "if-tree" }
        assertTrue("应检出 decision-tree 候选", tree != null)
        assertEquals("分支规模应为 8", 8, tree!!.caseCount)
        assertTrue("应提取 handler 切片", tree.handlers.isNotEmpty())
        assertTrue("handler 键应含 hex 常量", tree.handlers.any { it.key.startsWith("0x") })
        assertTrue("建议变量应含 _0xbc", tree.suggestedOps.contains("_0xbc"))
    }

    @Test
    fun `does not flag small branch chain`() {
        val src = treeSkeleton(4)
        val candidates = VmpDetector().detect(src)
        assertTrue("分支 <6 不应误报为 decision-tree", candidates.none { it.dispatchStyle == "if-tree" })
    }

    @Test
    fun `does not flag without loop wrapper`() {
        // 无 while 包裹的普通 if/else-if 链（如状态机单次判断）
        val src = """
            var x = getVal();
            if (x === 0x1) { a(); }
            else if (x === 0x2) { b(); }
            else if (x === 0x3) { c(); }
            else if (x === 0x4) { d(); }
            else if (x === 0x5) { e(); }
            else if (x === 0x6) { f(); }
            else if (x === 0x7) { g(); }
        """.trimIndent()
        val candidates = VmpDetector().detect(src)
        assertTrue("无循环包裹不应误报", candidates.none { it.dispatchStyle == "if-tree" })
    }
}
