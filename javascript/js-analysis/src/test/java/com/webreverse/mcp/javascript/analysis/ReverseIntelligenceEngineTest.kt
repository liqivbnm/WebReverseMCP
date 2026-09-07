package com.webreverse.mcp.javascript.analysis

import org.junit.Assert.assertTrue
import org.junit.Test

class ReverseIntelligenceEngineTest {

    @Test
    fun recovers_concat_endpoint_and_auth_crypto_pipeline() {
        val source = """
            const base = '/api/';
            const path = base + 'v1/' + 'search';
            function sign(token, body) {
              const nonce = Date.now().toString(16);
              const sig = CryptoJS.SHA256(token + nonce + JSON.stringify(body)).toString();
              return btoa(sig);
            }
            async function send(accessToken, body) {
              const signature = sign(accessToken, body);
              return fetch(path, {method:'POST', headers:{Authorization: 'Bearer ' + accessToken, 'X-Signature': signature}, body});
            }
        """.trimIndent()

        val r = ReverseIntelligenceEngine().analyze(source)
        assertTrue(r.ok)
        assertTrue(r.endpointsRecovered >= 1)
        assertTrue(r.cryptoSignals >= 1)
        assertTrue(r.tokenSignals >= 1)
        assertTrue(r.strings.any { it.value.contains("/api/v1/search") })
        assertTrue(r.targets.any { it.kind == ReverseIntelligenceEngine.Kind.CRYPTO_PIPELINE })
        assertTrue(r.targets.any { it.kind == ReverseIntelligenceEngine.Kind.TOKEN_SINK })
    }

    @Test
    fun survives_mangled_dynamic_js_and_detects_special_layers() {
        val source = """
            const x = Function('return eval("console.log(1)")')();
            WebAssembly.instantiateStreaming(fetch('/x.wasm'));
            while(pc++ < 0x10) switch (bc[pc]) { case 0x2a: stack.push(reg[pc]); break; }
            debugger;
            const a = '\x2f\x61\x70\x69';
        """.trimIndent()

        val r = ReverseIntelligenceEngine().analyze(source)
        assertTrue(r.ok)
        assertTrue(r.wasmSignals >= 1)
        assertTrue(r.jsvmpSignals >= 1)
        assertTrue(r.antiDebugSignals >= 1)
        assertTrue(r.strings.any { it.value == "/api" })
        assertTrue(r.targets.isNotEmpty())
    }
}
