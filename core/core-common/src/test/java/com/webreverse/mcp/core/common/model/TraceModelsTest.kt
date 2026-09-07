package com.webreverse.mcp.core.common.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TraceModelsTest {
    @Test
    fun fingerprint_is_stable_for_trimmed_value() {
        assertEquals(ValueFingerprint.of("  abc123  "), ValueFingerprint.of("abc123"))
    }

    @Test
    fun ring_buffer_removes_evicted_indexes() {
        val fp = ValueFingerprint.of("abcdef")!!
        val e1 = TraceEvent(1, 1, TraceSource.HOOK, TraceKind.CALL, "a", listOf(ValueRef("abcdef", fp)))
        val e2 = TraceEvent(2, 2, TraceSource.HOOK, TraceKind.CALL, "b")
        val buf = TraceEventBuffer(capacity = 1)
        buf.append(e1)
        buf.append(e2)
        assertTrue(buf.findByFingerprint(fp).isEmpty())
        assertEquals(1, buf.all().size)
    }

    @Test
    fun duplicate_sequence_is_not_inserted_twice() {
        val e = TraceEvent(7, 7, TraceSource.TRACER, TraceKind.CALL, "f")
        val buf = TraceEventBuffer(capacity = 8)
        buf.append(e)
        buf.append(e)
        assertEquals(1, buf.all().size)
        assertEquals(1L, buf.stats().dropped)
    }
}
