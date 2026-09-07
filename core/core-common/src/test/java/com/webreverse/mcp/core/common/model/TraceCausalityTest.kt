package com.webreverse.mcp.core.common.model

import org.junit.Assert.assertTrue
import org.junit.Test

class TraceCausalityTest {
    @Test
    fun fingerprint_builds_value_flow() {
        val fp = ValueFingerprint.of("signed-value")!!
        val events = listOf(
            TraceEvent(1, 100, TraceSource.TRACER, TraceKind.CALL, "sign", listOf(ValueRef("signed-value", fp, ValueRole.OUTPUT))),
            TraceEvent(2, 120, TraceSource.NETWORK, TraceKind.REQUEST, "/api/search", listOf(ValueRef("signed-value", fp, ValueRole.INPUT))),
        )
        val edges = TraceCausality.build(events)
        assertTrue(edges.any { it.relation == TraceCausality.Relation.VALUE_FLOW && it.fromSeq == 1L && it.toSeq == 2L })
    }
}
