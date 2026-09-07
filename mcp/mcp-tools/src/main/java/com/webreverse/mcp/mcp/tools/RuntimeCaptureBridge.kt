package com.webreverse.mcp.mcp.tools

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive

/**
 * 运行时数据捕获桥接。
 *
 * 「静态 ←→ 运行时打通」系列的共享底层：
 * - JSVMP 字节码数组 dump（jsvmp.bytecode_dump）
 * - WASM 导出函数调用记录 / 定向追踪（wasm.trace_calls / trace_export / trace_read）
 * - Hook 自动生成捕获读取（hook.gen_read）
 *
 * 统一解决两类胶水问题：
 * 1. WebView evaluateJavascript 返回值的「双层 JSON 编码」（见 [parseJsObject]）；
 * 2. 大数组 / 大对象无法一次 stringify 返回（evaluate 回调长度受限），
 *    用 [pullArrayChunked] 分块 btoa 拉取。
 */
object RuntimeCaptureBridge {

    private val json = Json { ignoreUnknownKeys = true }

    /** 单块拉取字节数（与 WasmTools.PULL_CHUNK 同量级；64KB 块在低端 WebView 更稳） */
    private const val PULL_CHUNK = 128 * 1024

    /** JS 侧单次 fromCharCode 追加步长（避免栈溢出） */
    private const val JS_STEP = 0x8000

    /**
     * 解析 evaluateJavascript 的返回值为 JsonObject。
     *
     * WebView evaluateJavascript 回调返回的是「JSON 编码后」的结果：
     * JS 表达式返回字符串 "{...}" 时，Kotlin 侧实际收到 "\"{\\\"chunk\\\":...}\""
     * （外层再包一层引号）。直接 as JsonObject 必然 ClassCastException。
     */
    fun parseJsObject(raw: String?): JsonObject? {
        if (raw.isNullOrBlank() || raw.trim() == "null") return null
        return try {
            when (val el = json.parseToJsonElement(raw.trim())) {
                is JsonObject -> el
                // 外层被引号包裹：剥一层再解析
                is JsonPrimitive -> runCatching { json.parseToJsonElement(el.content) }
                    .getOrNull() as? JsonObject
                else -> null
            }
        } catch (e: Exception) {
            null
        }
    }

    /** 拉取失败原因（供调用方给出精确错误信息） */
    @Volatile
    var lastPullError: String? = null
        private set

    /**
     * 分块拉取页面中某个数值数组 / TypedArray / 类数组 / 数字字符串。
     *
     * [arrayExpr] 必须是页面内可求值表达式（返回数组或 TypedArray）。
     * 返回原始「字节值」（0-255）；若元素为 double/int32 由 JS 侧 clamp。
     *
     * 探测阶段返回 {found, length, kind}，kind ∈ array/typedArray/string/other。
     */
    suspend fun pullArrayChunked(
        engine: com.webreverse.mcp.browser.engine.BrowserEngine,
        arrayExpr: String,
        maxElements: Int = 4_000_000,
    ): PullArrayResult? {
        lastPullError = null
        val safeExpr = arrayExpr.trim()
        if (safeExpr.isBlank()) {
            lastPullError = "数组表达式为空"
            return null
        }
        // 1) 探测：长度 + 类型
        val probe = parseJsObject(
            engine.evaluateJavascript(
                """
                (function(){
                  try {
                    var a = ($safeExpr);
                    if (a === null || a === undefined) return JSON.stringify({found:false, reason:'nullish'});
                    var len = (a.length !== undefined) ? a.length : -1;
                    var kind = Object.prototype.toString.call(a);
                    if (len < 0) return JSON.stringify({found:false, reason:'no_length', kind:kind});
                    if (len > $maxElements) return JSON.stringify({found:false, reason:'too_large', length:len});
                    var sample = [];
                    for (var i = 0; i < Math.min(8, len); i++) sample.push(typeof a[i] === 'number' ? a[i] : String(typeof a[i]));
                    return JSON.stringify({found:true, length:len, kind:kind, sample:sample});
                  } catch(e) { return JSON.stringify({found:false, reason:'throw:'+String(e).slice(0,120)}); }
                })()
                """.trimIndent(),
            ),
        ) ?: run {
            lastPullError = "探测求值失败（页面已跳转 / 表达式不可达 / 返回非 JSON）"
            return null
        }
        if (probe["found"]?.jsonPrimitive?.content != "true") {
            val reason = (probe["reason"] as? JsonPrimitive)?.content ?: "unknown"
            lastPullError = when {
                reason.startsWith("throw:") -> "表达式求值异常: ${reason.removePrefix("throw:")}"
                reason == "nullish" -> "表达式求值为 null/undefined"
                reason == "no_length" -> "目标不是数组（无 length 属性）"
                reason == "too_large" -> "数组过大（>$maxElements 元素），可调大 maxElements 或分段 dump"
                else -> reason
            }
            return null
        }
        val length = (probe["length"] as? JsonPrimitive)?.content?.toIntOrNull() ?: 0
        val kind = (probe["kind"] as? JsonPrimitive)?.content ?: "unknown"

        // 2) 分块拉取（btoa 分块 base64，规避长字符串拼接与回调截断）
        val out = java.io.ByteArrayOutputStream()
        var offset = 0
        while (offset < length) {
            val n = minOf(PULL_CHUNK, length - offset)
            val script = """
                (function(){
                  try {
                    var a = ($safeExpr);
                    if (!a || a.length === undefined) return JSON.stringify({error:'GONE'});
                    var o = $offset, n = Math.min($n, a.length - o);
                    var s = '';
                    for (var i = o; i < o + n; i += $JS_STEP) {
                      s += String.fromCharCode.apply(null,
                        (a.subarray ? a.subarray(i, Math.min(i + $JS_STEP, o + n)) : a.slice(i, Math.min(i + $JS_STEP, o + n))));
                    }
                    return JSON.stringify({chunk: btoa(s), next: o + n, done: (o + n) >= a.length});
                  } catch(e) { return JSON.stringify({error:'throw:'+String(e).slice(0,120)}); }
                })()
            """.trimIndent()
            val obj = parseJsObject(engine.evaluateJavascript(script)) ?: run {
                lastPullError = "分块拉取失败 @offset=$offset（页面求值超时/跳转）"
                return null
            }
            if (obj.containsKey("error")) {
                lastPullError = "拉取中断: ${(obj["error"] as? JsonPrimitive)?.content}"
                return null
            }
            val chunkB64 = (obj["chunk"] as? JsonPrimitive)?.content ?: break
            val chunk = runCatching { android.util.Base64.decode(chunkB64, android.util.Base64.DEFAULT) }
                .getOrNull() ?: run {
                lastPullError = "base64 解码失败 @offset=$offset"
                return null
            }
            out.write(chunk)
            offset = (obj["next"] as? JsonPrimitive)?.content?.toIntOrNull() ?: (offset + chunk.size)
            if (obj["done"]?.jsonPrimitive?.content == "true") break
        }
        val bytes = out.toByteArray()
        if (bytes.isEmpty() && length > 0) {
            lastPullError = "拉取到 0 字节（预期 $length 元素）"
            return null
        }
        return PullArrayResult(bytes = bytes, declaredLength = length, kind = kind, truncated = offset < length)
    }

    /**
     * 分页拉取页面 JSON 记录数组（如 __WRMCP_WASM_TRACE__ / hook 生成器记录）。
     *
     * [storeExpr] 为页面数组表达式（数组形态，[nameExpr] 传 "null"）；
     * 或对象表达式（对象形态，[nameExpr] 传 JS 字符串字面量如 `'sign'`，
     * 读取 `store[name].records`）。drain=true 时读取后删除已返回记录。
     */
    suspend fun pullRecordsPage(
        engine: com.webreverse.mcp.browser.engine.BrowserEngine,
        storeExpr: String,
        nameExpr: String?, // "null" = 数组形态；"'name'" = 对象形态 key
        start: Int,
        count: Int,
        drain: Boolean,
    ): JsonObject? {
        val nameAccess = nameExpr ?: "null"
        val drainJs = if (drain) {
            if (nameExpr == null) {
                "store.splice(0, ${start + count});"
            } else {
                "store[$nameAccess].records = list.slice(${start + count});"
            }
        } else {
            ";"
        }
        val script = """
            (function(){
              try {
                var store = $storeExpr;
                var list;
                if ($nameAccess === null) { list = store || []; }
                else {
                  var rec = (store || {})[$nameAccess];
                  list = rec && rec.records ? rec.records : null;
                  if (list === null) return JSON.stringify({ok:false, error:'NOT_FOUND',
                    installed: Object.keys(store || {})});
                }
                var total = list.length;
                var out = list.slice($start, $start + $count);
                if ($drain) { $drainJs }
                return JSON.stringify({ok:true, total:total, start:$start, returned:out.length, records:out});
              } catch(e) { return JSON.stringify({ok:false, error:'throw:'+String(e).slice(0,160)}); }
            })()
        """.trimIndent()
        val obj = parseJsObject(engine.evaluateJavascript(script)) ?: return null
        if (obj["ok"]?.jsonPrimitive?.content == "false") {
            lastPullError = (obj["error"] as? JsonPrimitive)?.content ?: "读取失败"
        } else {
            lastPullError = null
        }
        return obj
    }

    /** pullArrayChunked 结果 */
    data class PullArrayResult(
        val bytes: ByteArray,
        val declaredLength: Int,
        val kind: String,
        val truncated: Boolean,
    )
}
