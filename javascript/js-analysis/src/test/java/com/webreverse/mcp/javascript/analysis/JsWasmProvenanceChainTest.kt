package com.webreverse.mcp.javascript.analysis

import com.webreverse.mcp.core.common.model.TraceEvent
import com.webreverse.mcp.core.common.model.TraceKind
import com.webreverse.mcp.core.common.model.TraceSource
import com.webreverse.mcp.core.common.model.ValueFingerprint
import com.webreverse.mcp.core.common.model.ValueRef
import com.webreverse.mcp.core.common.model.ValueRole
import org.junit.Assert.assertTrue
import org.junit.Test

class JsWasmProvenanceChainTest {
    @Test fun `links typed array wasm instruction export and network sink`() {
        val js = """
            const u = new Uint8Array(buf, 16, 8);
            instance.sign(u, 8);
            fetch('/api/sign', {headers:{'X-Sign':'abcd'}});
        """.trimIndent()
        val fp = ValueFingerprint.of("abcd")!!
        val wasm = "0061736d0100000001070160027f7f017f030201000503010001071102066d656d6f72790200047369676e00000a0901070020002d00000b"
            .chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val events = listOf(
            TraceEvent(
                seq = 1, ts = 1000, source = TraceSource.WASM, kind = TraceKind.WASM_EXPORT, name = "sign",
                values = listOf(ValueRef("abcd", fp, ValueRole.OUTPUT)),
                meta = mapOf("memoryStart" to "16", "memoryEnd" to "23", "ptr0" to "16", "len0" to "8"), line = 2,
            ),
            TraceEvent(
                seq = 2, ts = 1001, source = TraceSource.NETWORK, kind = TraceKind.REQUEST, name = "https://x/api/sign",
                values = listOf(ValueRef(fp, fp, ValueRole.OUTPUT, "string", "fpHeader_X_Sign")), line = 3,
            ),
        )
        val r = JsWasmProvenanceChain().analyze(js, wasm, events)
        assertTrue(r.ok)
        assertTrue(r.instructions.any { it.mnemonic == "i32.load8_u" })
        assertTrue(r.typedArrays.first().wasmCalls.contains("sign"))
        assertTrue(r.aliases.any { it.relation == "RUNTIME_EXPORT_TO_INSTRUCTION" })
        assertTrue(r.chains.any { it.endpoint.contains("/api/sign") && it.status == "VALIDATED_CHAIN_CANDIDATE" })
    }
}
