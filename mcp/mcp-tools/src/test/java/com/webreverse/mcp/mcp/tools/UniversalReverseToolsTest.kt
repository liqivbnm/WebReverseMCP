package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.common.model.NetworkEntry
import com.webreverse.mcp.core.common.model.ResourceType
import com.webreverse.mcp.core.common.model.HttpMethod
import com.webreverse.mcp.javascript.analysis.UniversalTargetProfiler
import org.junit.Assert.assertTrue
import org.junit.Test

class UniversalReverseToolsTest {
    @Test
    fun genericSiteSignalsAreRanked() {
        val source = """
            const sig = crypto.subtle.digest('SHA-256', payload);
            const ws = new WebSocket('wss://example.invalid/socket');
            const token = localStorage.getItem('access_token');
            WebAssembly.instantiate(buf);
            function vm(op){ switch(op){ case 0x12: return token; default: return 0; } }
            fetch('/api/login', {headers:{Authorization:'Bearer '+token}});
        """.trimIndent()
        val network = listOf(NetworkEntry("1", "t", "r", "https://example.invalid/api/login", HttpMethod.POST, resourceType = ResourceType.FETCH))
        val profile = UniversalTargetProfiler().profile(source, network, "{\"webAssembly\":true}")
        val kinds = profile.detected.map { it.kind }.toSet()
        assertTrue(kinds.contains(UniversalTargetProfiler.Kind.API_CLIENT))
        assertTrue(kinds.contains(UniversalTargetProfiler.Kind.TOKEN))
        assertTrue(kinds.contains(UniversalTargetProfiler.Kind.CRYPTO_SIGNATURE))
        assertTrue(kinds.contains(UniversalTargetProfiler.Kind.WASM))
        assertTrue(kinds.contains(UniversalTargetProfiler.Kind.JSVMP))
        assertTrue(profile.coverage >= 50)
    }
}
