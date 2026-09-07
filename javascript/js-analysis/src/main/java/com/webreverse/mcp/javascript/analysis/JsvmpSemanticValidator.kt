package com.webreverse.mcp.javascript.analysis

/**
 * JSVMP 语义验证器 。
 * 不执行不可信脚本，只对现有 Micro-IR / handler metadata 做一致性检查，
 * 用于把“静态恢复的 opcode 语义”与结构约束互相校验。
 */
class JsvmpSemanticValidator {
    data class Issue(val severity: String, val message: String, val handler: String = "")
    data class Report(val ok: Boolean, val handlers: Int, val validated: Int, val confidence: Double, val issues: List<Issue>, val recommendations: List<String>)

    fun validate(handlers: List<JsvmpDeepAnalyzer.HandlerInfo>): Report {
        if (handlers.isEmpty()) return Report(false, 0, 0, 0.0, listOf(Issue("INFO", "没有可验证的 handler")), listOf("先执行 jsvmp.handlers / jsvmp.semantics"))
        var good = 0
        val issues = mutableListOf<Issue>()
        handlers.forEach { h ->
            var score = 0
            if (h.key.isNotBlank()) score++
            if (h.kind != JsvmpDeepAnalyzer.HandlerKind.UNKNOWN) score++
            if (h.confidence >= 70) score++
            if (h.evidence.isNotEmpty()) score++
            if (h.snippet.isNotBlank()) score++
            if (score >= 4) good++
            if (h.kind == JsvmpDeepAnalyzer.HandlerKind.UNKNOWN) {
                issues += Issue("WARN", "handler 语义仍为 UNKNOWN，请做动态差分验证", h.key)
            }
            if (h.confidence < 50) issues += Issue("WARN", "handler 语义置信度较低", h.key)
        }
        val confidence = (0.35 * good.toDouble() / handlers.size + 0.65 * handlers.map { (it.confidence / 100.0).coerceIn(0.0, 1.0) }.average()).coerceIn(0.0, 0.995)
        val recommendations = mutableListOf<String>()
        if (confidence < 0.90) recommendations += "对低置信 handler 做动态差分输入验证"
        recommendations += "建立 opcode → VM-IR → VM-SSA → trace 的单一语义来源"
        recommendations += "对 branch/load/store/call opcode 增加微程序级单元测试"
        return Report(true, handlers.size, good, confidence, issues.take(200), recommendations)
    }
}
