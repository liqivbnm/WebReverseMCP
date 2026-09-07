package com.webreverse.mcp.javascript.analysis

import org.junit.Assert.assertTrue
import org.junit.Test

class ApiDiscoveryEngineTest {
    @Test
    fun resolves_string_concat_url_and_fetch_sink() {
        val source = """
            const base = '/api/';
            const path = base + 'v1/' + 'sign';
            async function go(token) {
              return fetch(path, {method:'POST', headers:{Authorization: token}});
            }
        """.trimIndent()
        val r = ApiDiscoveryEngine().discoverFromJs(source)
        assertTrue(r.endpoints.any { it.url == "/api/v1/sign" })
        assertTrue(r.endpoints.any { it.url == "/api/v1/sign" && it.confidence >= 0.80 })
    }
}
