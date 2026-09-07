package com.webreverse.mcp.javascript.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unified Causal Graph与 ValidationEngine 多样本差分执行的端到端单测。
 * 验证：五类分析汇入同一张图、跨层因果边生成、统一因果分计算、差分执行冠军收敛。
 */
class UnifiedCausalGraphTest {

    @Test
    fun `build produces unified graph with cross-layer edges`() {
        val source = """
            function _0xdec(offset, delta) {
                var _0xarr = ["Y29uc29sZQ==", "aGVsbG8=", "d29ybGQ="];
                var i = offset + delta;
                return atob(_0xarr[i]);
            }
            function workerBridge(msg) {
                self.postMessage({ value: _0xdec(1, msg) });
            }
            var heap = new Uint8Array(4096);
            var inst = new WebAssembly.Instance(mod, { env: { mem: heap.buffer } });
            var out = inst.exports.encrypt(heap, 12, 256);
            console.log(out);
        """.trimIndent()

        val g = UnifiedCausalGraph().build(source)

        assertTrue("graph should build ok: ${g.error}", g.ok)
        assertTrue("nodes should exist", g.nodes.isNotEmpty())
        assertTrue("edges should exist", g.edges.isNotEmpty())
        assertTrue("JS flow layer should be covered", g.layers.any { it.layer == UnifiedCausalGraph.Layer.JS_FLOW && it.nodeCount > 0 })
        assertTrue("unifiedScore should be > 0", g.unifiedScore > 0.0)
    }

    @Test
    fun `differential run converges on champion hypothesis across samples`() {
        val engine = ValidationEngine()
        // 简单解释器：直接把占位符替换后的表达式求值为 (a ^ b)
        val executor = ValidationEngine.JsExecutor { code, inputs ->
            val parts = code.split(" ")
            val a = parts.getOrNull(0)?.toLongOrNull()
            val b = parts.getOrNull(1)?.toLongOrNull()
            if (a != null && b != null) (a xor b).toString() else null
        }

        val samples = listOf(
            ValidationEngine.DifferentialSample(mapOf("a" to 12L, "b" to 5L), "9"),
            ValidationEngine.DifferentialSample(mapOf("a" to 7L, "b" to 3L), "4"),
            ValidationEngine.DifferentialSample(mapOf("a" to 255L, "b" to 1L), "254"),
            ValidationEngine.DifferentialSample(mapOf("a" to 64L, "b" to 32L), "96"),
        )
        val groups = listOf(
            ValidationEngine.HypothesisGroup(
                "xor", listOf("x" to "{a} {b}", "alt" to "{a} {b}")
            ),
            ValidationEngine.HypothesisGroup(
                "add", listOf("plus" to "{a} + {b}", "minus" to "{a} - {b}")
            ),
        )

        val rep = engine.differentialRun(executor, samples, groups)

        assertTrue("differential report should be ok: ${rep.error}", rep.ok)
        assertEquals("xor champion on observed samples", "xor", rep.winner)
        assertEquals(1.0, rep.observedAccuracy["xor"] ?: 0.0, 0.0)
        assertTrue("xor internal consistency high", (rep.internalConsistency["xor"] ?: 0.0) >= 0.9)
        assertTrue("divergence samples found vs add", rep.divergenceSamples.isNotEmpty())
    }

    @Test
    fun `differential run works without ground truth using output-set agreement`() {
        val engine = ValidationEngine()
        val executor = ValidationEngine.JsExecutor { code, _ ->
            when (code.trim()) {
                "1 1", "2 2", "3 3" -> "0"
                else -> null
            }
        }
        val samples = listOf(
            ValidationEngine.DifferentialSample(mapOf("x" to 1L, "y" to 1L), observed = null),
            ValidationEngine.DifferentialSample(mapOf("x" to 2L, "y" to 2L), observed = null),
            ValidationEngine.DifferentialSample(mapOf("x" to 3L, "y" to 3L), observed = null),
        )
        val groups = listOf(
            ValidationEngine.HypothesisGroup("same", listOf("f1" to "{x} {y}", "f2" to "{x} {y}")),
            ValidationEngine.HypothesisGroup("other", listOf("g1" to "{x} * {y}", "g2" to "{x} + {y}")),
        )
        val rep = engine.differentialRun(executor, samples, groups)
        assertTrue(rep.ok)
        assertEquals(false, rep.hasObserved)
        assertEquals("same", rep.winner)
    }
}
