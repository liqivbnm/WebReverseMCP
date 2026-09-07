package com.webreverse.mcp.javascript.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * PauseLoopDetector 四级恢复状态机单元测试（报告 §9/§12）。
 */
class PauseLoopDetectorTest {

    @Test
    fun `normal until threshold within window`() {
        val p = PauseLoopDetector(PauseLoopDetector.Params())
        assertEquals(PauseLoopDetector.RecoveryLevel.NORMAL, p.onPause("a.js"))
        assertEquals(PauseLoopDetector.RecoveryLevel.AUTO_RESUME, p.onPause("a.js"))
    }

    @Test
    fun `escalates to skip all pauses on repeated pauses`() {
        val p = PauseLoopDetector(PauseLoopDetector.Params(pauseThreshold = 3))
        p.onPause("a.js")
        p.onPause("a.js")
        val lv = p.onPause("a.js")
        assertTrue(lv.severity >= PauseLoopDetector.RecoveryLevel.SKIP_ALL_PAUSES.severity)
    }

    @Test
    fun `user breakpoints do not count`() {
        val p = PauseLoopDetector(PauseLoopDetector.Params(pauseThreshold = 2))
        repeat(5) { p.onPause("u.js", isUserBreakpoint = true) }
        assertEquals(0, p.report().totalPauses)
        assertTrue(p.report().overallLevel == PauseLoopDetector.RecoveryLevel.NORMAL)
    }

    @Test
    fun `reaches source patch on heavy recurrence`() {
        val p = PauseLoopDetector(PauseLoopDetector.Params(pauseThreshold = 2, patchThreshold = 6))
        repeat(6) { p.onPause("x.js") }
        val r = p.report()
        assertTrue(r.overallLevel == PauseLoopDetector.RecoveryLevel.SOURCE_PATCH)
        assertTrue(r.inLoop)
    }

    @Test
    fun `reset clears observation`() {
        val p = PauseLoopDetector(PauseLoopDetector.Params(pauseThreshold = 2))
        p.onPause("y.js")
        p.onPause("y.js")
        assertEquals(2, p.report().totalPauses)
        p.reset("y.js")
        assertEquals(0, p.report().totalPauses)
    }

    @Test
    fun `shouldIntercept flags marked scripts`() {
        val p = PauseLoopDetector(PauseLoopDetector.Params(pauseThreshold = 3, patchThreshold = 6))
        p.onPause("z.js")
        p.onPause("z.js")
        p.onPause("z.js")
        assertTrue(p.shouldIntercept("z.js"))
    }
}