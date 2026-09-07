package com.webreverse.mcp.mcp.tools

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.BufferedReader
import java.io.StringReader

/**
 * file.read 文本分页核心（pageText）单元测试。
 *
 * 覆盖：自然 EOF 精确行数、limit/maxBytes 提前停止的续读游标、
 * 「恰好读完」不误报 truncated、超长行 colOffset/colLimit 列分段
 * （minified 单行大文件核心场景）、二进制探测。
 */
class FileReadPagingTest {

    private fun pageOf(
        content: String,
        offset: Int = 0,
        limit: Int = 200,
        colOffset: Int = 0,
        colLimit: Int = 4_000,
        maxBytes: Long = 1L shl 20,
    ): FileTools.TextPage =
        FileTools.pageText(BufferedReader(StringReader(content)), offset, limit, colOffset, colLimit, maxBytes)

    // ---------- 行方向分页 ----------

    @Test
    fun naturalEofReportsExactTotalLines() {
        val p = pageOf("a\nb\nc")
        assertEquals(3L, p.totalLines)
        assertTrue(p.totalLinesKnown)
        assertFalse(p.truncated)
        assertEquals(listOf("a", "b", "c"), p.lines.map { it.text })
        assertEquals(listOf(0L, 1L, 2L), p.lines.map { it.line })
    }

    @Test
    fun emptyFileReturnsZeroLines() {
        val p = pageOf("")
        assertEquals(0L, p.totalLines)
        assertEquals(0, p.returned)
        assertFalse(p.truncated)
    }

    @Test
    fun limitHitWithMoreLinesSetsTruncatedAndCursor() {
        val p = pageOf("l0\nl1\nl2\nl3", limit = 2)
        assertTrue(p.truncated)
        assertFalse(p.totalLinesKnown)
        assertEquals(2L, p.nextOffset)
        assertEquals(listOf("l0", "l1"), p.lines.map { it.text })
    }

    @Test
    fun limitHitExactlyAtEofIsNotTruncated() {
        val p = pageOf("a\nb", limit = 2)
        assertFalse(p.truncated)
        assertTrue(p.totalLinesKnown)
        assertEquals(2L, p.totalLines)
    }

    @Test
    fun offsetSkipsLeadingLinesAndKeepsAbsoluteLineNumbers() {
        val p = pageOf("a\nb\nc\nd", offset = 2)
        assertEquals(listOf(2L, 3L), p.lines.map { it.line })
        assertEquals(listOf("c", "d"), p.lines.map { it.text })
        assertFalse(p.truncated)
        assertEquals(4L, p.totalLines)
    }

    @Test
    fun offsetBeyondEofReturnsEmptyWithExactTotal() {
        val p = pageOf("a\nb", offset = 100)
        assertEquals(0, p.returned)
        assertEquals(2L, p.totalLines)
        assertFalse(p.truncated)
    }

    @Test
    fun maxBytesStopPointsCursorAtUnreadLine() {
        // 每行 1000 字符，maxBytes=2500 → 读完 2 行后第 3 行放不下
        val content = (0 until 5).joinToString("\n") { "y".repeat(1000) }
        val p = pageOf(content, limit = 100, maxBytes = 2500)
        assertEquals(2, p.returned)
        assertTrue(p.truncated)
        assertEquals(2L, p.nextOffset)
    }

    @Test
    fun firstLineAlwaysReturnedEvenBeyondMaxBytes() {
        // 单行 9000 字符，colLimit 截到 4000；maxBytes 很小但首行例外必须返回
        val p = pageOf("z".repeat(9000), limit = 10, colLimit = 4000, maxBytes = 1000)
        assertEquals(1, p.returned)
        assertEquals(4000, p.lines[0].text.length)
        assertTrue(p.anyLineCut)
        assertEquals(4000, p.nextColOffset)
        // 单行文件无后续行：行方向不 truncated，续读走列方向
        assertFalse(p.truncated)
        assertEquals(1L, p.totalLines)
    }

    // ---------- 列方向分段（minified 单行大文件核心场景） ----------

    @Test
    fun singleHugeLinePaginatesByColumnWithCursors() {
        val big = "x".repeat(10_000)
        // 第一段：0..4000
        val p1 = pageOf(big, limit = 10, colLimit = 4000)
        assertEquals(1, p1.returned)
        assertEquals(4000, p1.lines[0].text.length)
        assertTrue(p1.anyLineCut)
        assertEquals(4000, p1.nextColOffset)
        // 第二段：4000..8000
        val p2 = pageOf(big, limit = 10, colOffset = 4000, colLimit = 4000)
        assertEquals(4000, p2.lines[0].text.length)
        assertTrue(p2.anyLineCut)
        assertEquals(8000, p2.nextColOffset)
        // 第三段：8000..10000（尾段，不再截断）
        val p3 = pageOf(big, limit = 10, colOffset = 8000, colLimit = 4000)
        assertEquals(2000, p3.lines[0].text.length)
        assertFalse(p3.anyLineCut)
    }

    @Test
    fun colOffsetBeyondLineEndReturnsEmptyText() {
        val p = pageOf("short", colOffset = 100)
        assertEquals(1, p.returned)
        assertEquals("", p.lines[0].text)
        assertFalse(p.anyLineCut)
    }

    @Test
    fun columnWindowAppliesToEveryLineInWindow() {
        // 3 行各 20 字符，colOffset=5 → 每行只剩 15 字符
        val content = "a".repeat(20) + "\n" + "b".repeat(20) + "\n" + "c".repeat(20)
        val p = pageOf(content, colOffset = 5)
        assertEquals(3, p.returned)
        p.lines.forEach { assertEquals(15, it.text.length) }
    }

    // ---------- 二进制探测 ----------

    @Test
    fun nulByteDetectedAsBinary() {
        val p = pageOf("ok\u0000binary")
        assertTrue(p.binary)
    }
}
