package com.webreverse.mcp.javascript.analysis

import kotlinx.serialization.Serializable

/** 差异结果 */
@Serializable
data class DiffResult(
    val additions: List<DiffLine> = emptyList(),
    val deletions: List<DiffLine> = emptyList(),
    val unchanged: Int = 0,
    val similarity: Double = 0.0,
)

@Serializable
data class DiffLine(
    val lineNumber: Int,
    val content: String,
)

/** 文本差异引擎（简化 LCS） */
class DiffEngine {

    fun diff(a: String, b: String): DiffResult {
        val aLines = a.lines()
        val bLines = b.lines()
        val lcs = lcsLength(aLines, bLines)
        val similarity = if (aLines.isEmpty() && bLines.isEmpty()) 1.0
        else (2.0 * lcs) / (aLines.size + bLines.size)

        // 简单逐行 diff
        val additions = mutableListOf<DiffLine>()
        val deletions = mutableListOf<DiffLine>()
        val maxLen = maxOf(aLines.size, bLines.size)
        for (i in 0 until maxLen) {
            val aLine = aLines.getOrNull(i)
            val bLine = bLines.getOrNull(i)
            if (aLine != null && bLine != null && aLine != bLine) {
                deletions.add(DiffLine(i + 1, aLine))
                additions.add(DiffLine(i + 1, bLine))
            } else if (aLine == null && bLine != null) {
                additions.add(DiffLine(i + 1, bLine))
            } else if (bLine == null && aLine != null) {
                deletions.add(DiffLine(i + 1, aLine))
            }
        }

        return DiffResult(
            additions = additions,
            deletions = deletions,
            unchanged = lcs,
            similarity = similarity,
        )
    }

    private fun lcsLength(a: List<String>, b: List<String>): Int {
        if (a.isEmpty() || b.isEmpty()) return 0
        val n = a.size
        val m = b.size
        var prev = IntArray(m + 1)
        var curr = IntArray(m + 1)
        for (i in 1..n) {
            for (j in 1..m) {
                curr[j] = if (a[i - 1] == b[j - 1]) prev[j - 1] + 1
                else maxOf(prev[j], curr[j - 1])
            }
            val tmp = prev
            prev = curr
            curr = tmp
        }
        return prev[m]
    }
}
