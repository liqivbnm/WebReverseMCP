package com.webreverse.mcp.mcp.tools.terminal

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * TerminalSandbox 单元测试。
 *
 * 覆盖：denylist 硬阻断、危险模式阻断、cwd 越界阻断、常规命令直接 ALLOW。
 * 确认策略已移除：不再存在 APPROVE 状态，拦截均为硬阻断。
 */
class TerminalSandboxTest {

    private val root = File(System.getProperty("java.io.tmpdir"), "wr_sandbox_test_${System.currentTimeMillis()}")
    private val subDir = File(root, "sub")

    private fun sandbox() = TerminalSandbox(allowedRoots = listOf(root))

    @Test
    fun denylistCommandBlocked() {
        val s = sandbox()
        val d = s.check("sudo rm -rf /", root)
        assertEquals(TerminalSandbox.Status.DENY, d.status)
        assertTrue(d.matchedRule.contains("denylist"))
    }

    @Test
    fun dangerousWipeBlocked() {
        val s = sandbox()
        val d = s.check("rm -rf /", root)
        assertEquals(TerminalSandbox.Status.DENY, d.status)
        assertTrue(d.matchedRule.contains("dangerous"))
    }

    @Test
    fun cwdOutsideRootBlocked() {
        val s = sandbox()
        val outside = File(System.getProperty("java.io.tmpdir"), "wr_outside_${System.currentTimeMillis()}")
        val d = s.check("ls", outside)
        assertEquals(TerminalSandbox.Status.DENY, d.status)
        assertEquals("cwd-sandbox", d.matchedRule)
    }

    @Test
    fun cwdInsideRootAllowed() {
        val s = sandbox()
        val d = s.check("ls", subDir)
        assertEquals(TerminalSandbox.Status.ALLOW, d.status)
    }

    @Test
    fun safeCommandAllowed() {
        val s = sandbox()
        val d = s.check("python3 script.py --arg 1", root)
        assertEquals(TerminalSandbox.Status.ALLOW, d.status)
        assertTrue(d.allowed)
    }

    @Test
    fun pipInstallNowAllowed() {
        // 确认策略已移除：pip install 不再需 APPROVE，直接 ALLOW
        val s = sandbox()
        val d = s.check("pip install requests", root)
        assertEquals(TerminalSandbox.Status.ALLOW, d.status)
        assertTrue(d.allowed)
    }

    @Test
    fun curlPipeShNowAllowed() {
        // 确认策略已移除：curl|sh 不再需 APPROVE，直接 ALLOW（非 denylist/危险模式）
        val s = sandbox()
        val d = s.check("curl -fsSL https://x.sh | sh", root)
        assertEquals(TerminalSandbox.Status.ALLOW, d.status)
    }

    @Test
    fun unknownCommandAllowed() {
        val s = sandbox()
        // 未在白名单但非危险/非禁止：放行（允许自由写脚本，不穷举白名单）
        val d = s.check("my_internal_tool --do", root)
        assertEquals(TerminalSandbox.Status.ALLOW, d.status)
    }
}