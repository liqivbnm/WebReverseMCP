package com.webreverse.mcp.javascript.analysis

import org.junit.Test
import com.google.common.truth.Truth.assertThat

class DeepReverseCoreTest {
    @Test fun memorySsa_builds_phi_for_branching_heap_state() {
        val source = """
            function sign(input) {
              const o = {};
              if (input) o.token = input; else o.token = "fallback";
              const p = o;
              p.token = transform(p.token);
              return p;
            }
        """.trimIndent()
        val r = JsMemorySsaBuilder().build(source)
        assertThat(r.ok).isTrue()
        assertThat(r.locationCount).isGreaterThan(0)
        assertThat(r.phiCount).isAtLeast(1)
    }

    @Test fun workerDataflow_finds_worker_and_message_channel() {
        val r = WorkerDataFlow().analyze("""
            const w = new Worker('/w.js');
            w.postMessage(token);
            w.onmessage = e => send(e.data);
        """.trimIndent())
        assertThat(r.ok).isTrue()
        assertThat(r.contexts.any { it.kind == WorkerDataFlow.ContextKind.DEDICATED_WORKER }).isTrue()
        assertThat(r.channels.any { it.kind == WorkerDataFlow.ChannelKind.POST_MESSAGE }).isTrue()
    }
}
