package com.webreverse.mcp.javascript.analysis

import org.junit.Assert.assertTrue
import org.junit.Test

class DeepReverseAnalyzerTest {
    @Test fun `bind crypto output to network and async path`() {
        val src = """
            async function sign(x){ const y = crypto.subtle.digest('SHA-256', x); return y; }
            function go(v){ const payload = {token:v}; Promise.resolve(payload).then(sign); return fetch('/api', {body:v}); }
        """.trimIndent()
        val r = DeepReverseAnalyzer().analyze(src)
        assertTrue(r.ok)
        assertTrue(r.networkSinks.isNotEmpty())
        assertTrue(r.asyncFacts.isNotEmpty())
        assertTrue(r.cryptoBindings.isNotEmpty())
    }
}
