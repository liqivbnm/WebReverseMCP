package com.webreverse.mcp.javascript.analysis

import org.junit.Assert.assertTrue
import org.junit.Test

class ReverseAnalysisEngineTest {
    @Test
    fun unified_analysis_finds_crypto_endpoint_and_hot_function() {
        val source = """
            function sign(token, body) { return btoa(token + JSON.stringify(body)); }
            function callApi(token, body) {
              var sig = sign(token, body);
              return fetch('/api/search', {method:'POST', headers:{'X-Sign':sig}, body:body});
            }
        """.trimIndent()
        val r = ReverseAnalysisEngine().analyze(source)
        assertTrue(r.ok)
        assertTrue(r.functionCount >= 3)
        assertTrue(r.endpointCount >= 1)
        assertTrue(r.hotFunctions.any { it.name == "sign" || it.name == "callApi" })
    }
}
