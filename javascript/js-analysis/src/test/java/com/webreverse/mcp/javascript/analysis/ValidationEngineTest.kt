package com.webreverse.mcp.javascript.analysis

import org.junit.Assert.assertEquals
import org.junit.Test

class ValidationEngineTest {
    @Test
    fun confidence_increases_with_more_full_match_samples() {
        // executor 直接把绑定后的表达式原样返回：formula "{n}" 在输入 n=5 时求出 "5"
        val executor = ValidationEngine.JsExecutor { code, _ -> code }
        val engine = ValidationEngine()
        val candidate = listOf("identity" to "{n}")

        val one = engine.validate(executor, listOf(ValidationEngine.Sample(mapOf("n" to 5), 5)), candidate)
        val three = engine.validate(executor, listOf(
            ValidationEngine.Sample(mapOf("n" to 5), 5),
            ValidationEngine.Sample(mapOf("n" to 7), 7),
            ValidationEngine.Sample(mapOf("n" to 11), 11),
        ), candidate)

        // 契约：confirmed 需 ≥2 个不同输入组合（防“恰好对”伪命中），单样本不应确认
        assertEquals(false, one.confirmed)
        assertEquals(true, three.confirmed)
        org.junit.Assert.assertTrue("更多多样本满命中应提升置信", three.confidence > one.confidence)
    }
}
