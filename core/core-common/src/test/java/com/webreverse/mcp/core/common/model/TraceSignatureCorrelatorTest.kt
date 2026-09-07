package com.webreverse.mcp.core.common.model

import org.junit.Assert.assertTrue
import org.junit.Test

class TraceSignatureCorrelatorTest {
    @Test fun `correlates signer output with request input`() {
        val fp = ValueFingerprint.of("signed-value")!!
        val events = listOf(
            TraceEvent(1, 100, TraceSource.TRACER, TraceKind.CALL, "sign", listOf(ValueRef("signed-value", fp, ValueRole.OUTPUT))),
            TraceEvent(2, 120, TraceSource.NETWORK, TraceKind.REQUEST, "/api/search", listOf(ValueRef("signed-value", fp, ValueRole.INPUT)))
        )
        val r = TraceSignatureCorrelator.analyze(events)
        assertTrue(r.requests == 1)
        assertTrue(r.candidates.isNotEmpty())
        assertTrue(r.candidates.first().score >= 0.82)
    }
}
