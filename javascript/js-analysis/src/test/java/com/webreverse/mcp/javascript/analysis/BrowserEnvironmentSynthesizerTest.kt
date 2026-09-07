package com.webreverse.mcp.javascript.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * BrowserEnvironmentSynthesizer 单元测试。
 *
 * 覆盖：
 *  - AST 通道：点访问 / 括号访问 / 连续链式访问 / 注释与字符串不误报
 *  - 网络推断：NONE / CAPTURED_ONLY / TARGET_ONLY
 *  - shim 语法：atob/btoa 分支配平（历史 bug 回归）、validateShim 能捕获未闭合
 *  - 正则回退：AST 解析失败时仍能识别
 */
class BrowserEnvironmentSynthesizerTest {

    private val synth = BrowserEnvironmentSynthesizer()

    // ---- AST 通道：全局与路径识别 ----

    @Test
    fun `detects dot-access member chain`() {
        val src = "function h(){ return window.crypto.subtle.digest('SHA-256', data); }"
        val inf = synth.infer(src)
        assertTrue("window 应在 requiredGlobals", "window" in inf.requiredGlobals)
        assertTrue("crypto 应在 requiredGlobals", "crypto" in inf.requiredGlobals)
        assertTrue("window.crypto.subtle 应在 requiredPaths", "window.crypto.subtle" in inf.requiredPaths)
    }

    @Test
    fun `detects bracket-access member chain`() {
        val src = "var x = window['crypto']['subtle'];"
        val inf = synth.infer(src)
        assertTrue("括号访问应识别 window", "window" in inf.requiredGlobals)
        assertTrue("括号访问应识别 crypto", "crypto" in inf.requiredGlobals)
        assertTrue("括号访问应识别 window.crypto.subtle", "window.crypto.subtle" in inf.requiredPaths)
    }

    @Test
    fun `ignores globals mentioned only in comments or strings`() {
        val src = """
            // 这里提到 window.document.navigator 只是注释
            var s = "window.location.href 是字符串，不是真实访问";
            var a = 1;
        """.trimIndent()
        val inf = synth.infer(src)
        assertTrue("注释/字符串中的伪代码不应误报 window", "window" !in inf.requiredGlobals)
        assertTrue("注释/字符串中的伪代码不应误报 document", "document" !in inf.requiredGlobals)
    }

    @Test
    fun `detects navigator and location subpaths`() {
        val src = "var ua = navigator.userAgent; var o = location.origin;"
        val inf = synth.infer(src)
        assertTrue("navigator 应在 requiredGlobals", "navigator" in inf.requiredGlobals)
        assertTrue("navigator.userAgent 应在 requiredPaths", "navigator.userAgent" in inf.requiredPaths)
        assertTrue("location.origin 应在 requiredPaths", "location.origin" in inf.requiredPaths)
    }

    @Test
    fun `detects globals in malformed code via recovery`() {
        // 畸形代码：解析器按「尽量恢复」策略处理，仍应识别 window.crypto.subtle
        val src = "window.crypto.subtle; }}}}} 乱码(((("
        val inf = synth.infer(src)
        assertTrue("恢复解析应识别 window", "window" in inf.requiredGlobals)
        assertTrue("恢复解析应识别 window.crypto.subtle", "window.crypto.subtle" in inf.requiredPaths)
    }

    // ---- 网络推断 ----

    @Test
    fun `network none when no network call`() {
        val inf = synth.infer("var a = window.innerWidth;")
        assertEquals(NetworkUsageKind.NONE, inf.networkUsage)
    }

    @Test
    fun `network captured only when sensitive auth present`() {
        val src = "fetch('/api/data', {headers:{'Authorization':'Bearer x'}});"
        val inf = synth.infer(src)
        assertEquals(NetworkUsageKind.CAPTURED_ONLY, inf.networkUsage)
    }

    @Test
    fun `network target only when no sensitive auth`() {
        val src = "fetch('/api/data');"
        val inf = synth.infer(src)
        assertEquals(NetworkUsageKind.TARGET_ONLY, inf.networkUsage)
    }

    // ---- shim 语法 ----

    @Test
    fun `atob and btoa shim branches are balanced`() {
        val caps = mapOf("atob" to true, "btoa" to true, "window" to true)
        val shim = synth.buildShim(caps)
        val v = synth.validateShim(shim)
        assertTrue("atob/btoa 分支应配平，实际问题：${v.issues}", v.valid)
    }

    @Test
    fun `full shim for common globals is balanced`() {
        val caps = mapOf(
            "window" to true, "document" to true, "navigator" to true, "location" to true,
            "history" to true, "screen" to true, "performance" to true, "crypto" to true,
            "localStorage" to true, "sessionStorage" to true, "fetch" to true,
            "XMLHttpRequest" to true, "atob" to true, "btoa" to true,
            "TextEncoder" to true, "TextDecoder" to true, "URL" to true, "URLSearchParams" to true,
            "window.crypto.subtle" to true, "navigator.userAgent" to true, "location.origin" to true,
        )
        val shim = synth.buildShim(caps)
        val v = synth.validateShim(shim)
        assertTrue("常见全局 shim 应配平，实际问题：${v.issues}", v.valid)
    }

    @Test
    fun `validateShim catches unbalanced braces`() {
        val v = synth.validateShim("if(typeof a==='undefined'){a=function(){return 1;};")
        assertFalse("缺闭合大括号应被检出", v.valid)
        assertTrue("应报告未闭合定界符", v.issues.any { it.contains("未闭合") })
    }

    @Test
    fun `validateShim ignores braces inside strings and comments`() {
        val v = synth.validateShim("var s = '{not a block}'; // } 注释里的括号\nvar ok = {a:1};")
        assertTrue("字符串/注释中的括号不应误报，实际问题：${v.issues}", v.valid)
    }

    @Test
    fun `generic fallback branch handles unknown globals and paths`() {
        // 错误驱动回填的基础：未知全局/路径也能补成空对象或回填捕获值
        val caps = mapOf(
            "myCustomGlobal" to true,
            "foo.bar.baz" to true,
            "window" to true,
        )
        val shim = synth.buildShim(caps)
        val v = synth.validateShim(shim)
        assertTrue("未知全局通用兜底应配平，实际问题：${v.issues}", v.valid)
        assertTrue("未知全局应生成空对象兜底", shim.contains("myCustomGlobal"))
        assertTrue("未知路径应走 __set 兜底", shim.contains("foo.bar.baz"))
    }

    @Test
    fun `shim with captured real values is balanced`() {
        val caps = mapOf(
            "window" to true,
            "navigator.userAgent" to true,
            "location.origin" to true,
            "screen.width" to true,
            "crypto" to true,
        )
        val captured = mapOf(
            "navigator.userAgent" to "\"Mozilla/5.0 (Linux; Android 13)\"",
            "location.origin" to "\"https://example.com\"",
            "screen.width" to "1920",
        )
        val shim = synth.buildShim(caps, captured)
        val v = synth.validateShim(shim)
        assertTrue("带真实捕获值的 shim 应配平，实际问题：${v.issues}", v.valid)
        assertTrue("应内嵌捕获的真实 UA", shim.contains("Mozilla/5.0"))
    }

    // ---- 合并语义 ----

    @Test
    fun `mergeShim unions existing and newly required`() {
        val merged = synth.mergeShim(mapOf("window" to true), listOf("crypto", "navigator"))
        assertEquals(setOf("window", "crypto", "navigator"), merged.keys)
        assertTrue(merged["crypto"] == true)
    }

    @Test
    fun `captureableKeys covers globals and subpaths`() {
        val keys = synth.captureableKeys()
        assertTrue("window" in keys)
        assertTrue("window.crypto.subtle" in keys)
        assertTrue("navigator.userAgent" in keys)
    }

    // ---- 几何指纹一致性 ----

    @Test
    fun `fingerprint heuristic adds canvas capability on toDataURL usage`() {
        // 指纹脚本典型形态：运行时 createElement('canvas') 后取指纹
        val src = """
            function fp(){
              var c = document.createElement('canvas');
              var ctx = c.getContext('2d');
              ctx.fillText('probe', 0, 0);
              return c.toDataURL().substring(0, 64);
            }
        """.trimIndent()
        val inf = synth.infer(src)
        assertTrue("toDataURL 使用应补 canvas.data2d 能力", inf.capabilities["canvas.data2d"] == true)
    }

    @Test
    fun `fingerprint heuristic adds webgl capability on getParameter usage`() {
        val src = """
            var gl = canvas.getContext('webgl');
            var ext = gl.getExtension('WEBGL_debug_renderer_info');
            var v = gl.getParameter(ext.UNMASKED_RENDERER_WEBGL);
        """.trimIndent()
        val inf = synth.infer(src)
        assertTrue("getParameter/getExtension 使用应补 webgl.params 能力", inf.capabilities["webgl.params"] == true)
    }

    @Test
    fun `fingerprint heuristic adds measureText capability`() {
        val src = "var w = ctx.measureText('probe').width;"
        val inf = synth.infer(src)
        assertTrue("measureText 使用应补 canvas.measureText 能力", inf.capabilities["canvas.measureText"] == true)
    }

    @Test
    fun `canvas and webgl shim is balanced and installs fingerprint stubs`() {
        val caps = mapOf(
            "window" to true, "document" to true,
            "canvas.data2d" to true, "canvas.measureText" to true,
            "webgl.vendor" to true, "webgl.renderer" to true, "webgl.params" to true,
        )
        val shim = synth.buildShim(caps)
        val v = synth.validateShim(shim)
        assertTrue("canvas/WebGL shim 应配平，实际问题：${v.issues}", v.valid)
        assertTrue("应安装指纹桩", shim.contains("__installFingerprint"))
        assertTrue("应挂 HTMLCanvasElement", shim.contains("HTMLCanvasElement"))
        assertTrue("应挂 WebGLRenderingContext", shim.contains("WebGLRenderingContext"))
    }

    @Test
    fun `captured fingerprint values are embedded into shim`() {
        val caps = mapOf(
            "window" to true, "document" to true,
            "canvas.data2d" to true, "canvas.measureText" to true,
            "webgl.vendor" to true, "webgl.renderer" to true,
        )
        val captured = mapOf(
            "canvas.data2d" to "\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUg==\"",
            "canvas.measureText" to """{"13px Arial":123.45}""",
            "webgl.vendor" to "\"Qualcomm\"",
            "webgl.renderer" to "\"Adreno (TM) 660\"",
        )
        val shim = synth.buildShim(caps, captured)
        val v = synth.validateShim(shim)
        assertTrue("带指纹捕获值的 shim 应配平，实际问题：${v.issues}", v.valid)
        assertTrue("应内嵌真实 canvas 指纹", shim.contains("iVBORw0KGgo"))
        assertTrue("应内嵌字体宽度表", shim.contains("123.45"))
        assertTrue("应内嵌 GPU vendor", shim.contains("Qualcomm"))
        assertTrue("应内嵌 GPU renderer", shim.contains("Adreno"))
    }

    @Test
    fun `numeric subpath defaults are type correct`() {
        // devicePixelRatio 兜 1（数字）而非空对象；colorDepth 兜 24
        val caps = mapOf(
            "window.devicePixelRatio" to true,
            "screen.colorDepth" to true,
            "window" to true,
        )
        val shim = synth.buildShim(caps)
        val v = synth.validateShim(shim)
        assertTrue("数值子路径 shim 应配平，实际问题：${v.issues}", v.valid)
        assertTrue("devicePixelRatio 应兜数字 1", shim.contains(":1))"))
        assertTrue("colorDepth 应兜 24", shim.contains(":24))"))
    }

    @Test
    fun `captureableKeys includes fingerprint keys`() {
        val keys = synth.captureableKeys()
        assertTrue("canvas.data2d 应可采集", "canvas.data2d" in keys)
        assertTrue("canvas.measureText 应可采集", "canvas.measureText" in keys)
        assertTrue("canvas.fonts 应可采集", "canvas.fonts" in keys)
        assertTrue("webgl.vendor 应可采集", "webgl.vendor" in keys)
        assertTrue("webgl.renderer 应可采集", "webgl.renderer" in keys)
        assertTrue("webgl.params 应可采集", "webgl.params" in keys)
        assertTrue("webgl.data 应可采集", "webgl.data" in keys)
    }
}
