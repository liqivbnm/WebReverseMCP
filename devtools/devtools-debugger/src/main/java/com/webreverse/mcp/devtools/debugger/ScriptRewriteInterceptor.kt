package com.webreverse.mcp.devtools.debugger

import android.util.Base64
import com.webreverse.mcp.devtools.protocol.cdp.CdpEvent
import com.webreverse.mcp.devtools.protocol.cdp.CdpSession
import com.webreverse.mcp.javascript.analysis.ScriptInterceptor
import com.webreverse.mcp.javascript.analysis.ScriptTransformResult
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/**
 * CDP Fetch Response 阶段脚本改写闭环（报告 §7：HTTP 响应 → patch → 浏览器执行）。
 *
 * 这是「执行前拦截改写」的完整闭环： 之前 ScriptInterceptor 只有
 * transform()（静态改写器）但没有把它接进浏览器数据通路——改写结果无处生效。
 * 本类把改写闭环接进 CDP Fetch domain：
 *
 *   浏览器请求脚本 → [Fetch.enable Response 阶段拦截] → 响应到达时暂停 →
 *   Fetch.getResponseBody 取原始体 → ScriptInterceptor.transform 改写 →
 *   Fetch.fulfillRequest 以改写后体放行 → 浏览器编译执行 patched 脚本
 *
 * 与注入式 Hook 的差别（报告 §4/§5/§9）：改写发生在脚本进入 V8 之前，
 * parse 期 debugger / 构造器检测 / 无限断点循环在源头即被中和，
 * 不依赖运行时包装，也不怕脚本保存原始引用。
 *
 * 规则模型：
 * - RewriteRule(urlPattern)：命中 URL 的脚本响应才改写（空=全部脚本）；
 * - 每条规则独立开关 neutralizeDebugger（eval/Function/constructor 中和）；
 * - 可选 prepend/append 注入代码（在改写后源码前后拼接，如注入探针）。
 *
 * 限制（如实声明）：
 * - SRI（integrity 属性）声明的脚本改写后会被浏览器拒绝（ScriptInterceptor
 *   已标记 PATCHED_VIOLATES_SRI，记录透出给工具层提示）；
 * - 流式响应（resp streaming）getResponseBody 可能失败 → 该条放行不改写；
 * - 同一会话上 CdpNetworkMonitor 的 Request 阶段 Fetch.enable 与本类
 *   Response 阶段共用 Fetch domain（patterns 合并语义），二者同时开启时
 *   以最后一次 enable 为准（Chromium 行为）。
 */
class ScriptRewriteInterceptor(
    private val session: CdpSession,
    private val scope: CoroutineScope,
    private val transformer: ScriptInterceptor = ScriptInterceptor(),
) {

    /** 一条改写规则 */
    data class RewriteRule(
        val id: String,
        val urlPattern: String = "",
        val neutralizeDebugger: Boolean = true,
        val prepend: String? = null,
        val append: String? = null,
        val enabled: Boolean = true,
        /** 注入探针/前置代码是否生效于 worker 响应（默认同主文档） */
        val applyToWorkers: Boolean = true,
    )

    /** 一次改写记录（证据链：URL/哈希/中和数/时间） */
    data class RewriteRecord(
        val url: String,
        val requestId: String,
        val originalHash: String,
        val transformedHash: String,
        val neutralized: Int,
        val sriWarning: String?,
        val timestamp: Long = System.currentTimeMillis(),
    )

    private val rules = LinkedHashMap<String, RewriteRule>()
    private val records = java.util.concurrent.ConcurrentLinkedDeque<RewriteRecord>()

    private var watchJob: Job? = null

    @Volatile
    var enabled: Boolean = false
        private set

    /** 改写记录回调（宿主转发 EventBus / Evidence Graph） */
    var onRewritten: ((RewriteRecord) -> Unit)? = null

    // ---------------- 规则管理 ----------------

    /** 添加规则（返回规则 id） */
    fun addRule(
        urlPattern: String = "",
        neutralizeDebugger: Boolean = true,
        prepend: String? = null,
        append: String? = null,
    ): String {
        val id = java.util.UUID.randomUUID().toString().substring(0, 8)
        // （P2-1 修复）：rules 由 MCP 工具协程与事件处理协程并发访问，
        // 原 LinkedHashMap 无同步保护（可能 ConcurrentModificationException/撕裂读）
        synchronized(rules) { rules[id] = RewriteRule(id, urlPattern, neutralizeDebugger, prepend, append) }
        return id
    }

    fun removeRule(id: String): Boolean = synchronized(rules) { rules.remove(id) != null }

    fun listRules(): List<RewriteRule> = synchronized(rules) { rules.values.toList() }

    /** 命中判定：pattern 空=全命中；否则 URL 子串匹配 */
    private fun matchRule(url: String): RewriteRule? = synchronized(rules) {
        rules.values.firstOrNull { it.enabled && (it.urlPattern.isBlank() || url.contains(it.urlPattern)) }
    }

    fun recordsSnapshot(limit: Int = 100): List<RewriteRecord> =
        records.toList().asReversed().take(limit)

    // ---------------- 启停 ----------------

    /**
     * 启用响应阶段拦截（Fetch.enable，requestStage=Response，resourceType=Script）。
     * 需要至少一条规则；无规则时启用只透传不改写（合法：先观察后改写的工作流）。
     */
    suspend fun enable(): Boolean {
        if (enabled) return true
        val patterns = buildJsonArray {
            add(
                buildJsonObject {
                    put("requestStage", "Response")
                    put("resourceType", "Script")
                },
            )
        }
        val ok = session.call("Fetch.enable", buildJsonObject { put("patterns", patterns) }) != null
        if (!ok) return false
        enabled = true
        watchJob?.cancel()
        watchJob = scope.launch {
            session.events.collect { event -> onEvent(event) }
        }
        return true
    }

    suspend fun disable() {
        // （P1-5 修复）：先停止新暂停（Fetch.disable），保留事件循环
        // drain 缓冲中的 Fetch.requestPaused（handlePaused 对 enabled=false
        // 走 continueResponse 放行），最后才停循环。原实现直接 cancel——
        // SharedFlow 缓冲中未消费的 requestPaused 事件被丢弃，
        // 浏览器侧对应脚本响应永久悬挂，页面脚本加载卡死。
        enabled = false
        session.call("Fetch.disable")
        kotlinx.coroutines.delay(600)
        watchJob?.cancel()
        watchJob = null
    }

    // ---------------- 事件处理（Response 阶段闭环） ----------------

    private fun onEvent(event: CdpEvent) {
        if (event.method != "Fetch.requestPaused") return
        scope.launch { handlePaused(event.params) }
    }

    private suspend fun handlePaused(params: JsonObject) {
        val requestId = params["requestId"]?.jsonPrimitive?.contentOrNull ?: return
        // Response 阶段暂停标志：responseStatusCode 存在
        val responseStatusCode = params["responseStatusCode"]?.jsonPrimitive?.intOrNull
        if (responseStatusCode == null) return // Request 阶段（CdpNetworkMonitor 域），不动

        // （P1-5 修复）：已 disable（drain 阶段）到达的暂停请求直接放行，
        // 不再改写，防浏览器侧悬挂
        if (!enabled) {
            continueResponse(requestId)
            return
        }

        val request = params["request"]?.jsonObject
        val url = request?.get("url")?.jsonPrimitive?.contentOrNull ?: ""

        val rule = matchRule(url)
        if (rule == null) {
            continueResponse(requestId)
            return
        }

        // 1) 取原始响应体（已解压后的文本/base64）
        //    流式/未就绪时 getResponseBody 抛错 → 走 takeResponseBodyAsStream 兜底
        var bodyResult = session.call(
            "Fetch.getResponseBody",
            buildJsonObject { put("requestId", requestId) },
        )
        if (bodyResult == null) {
            val streamed = fetchBodyStreaming(requestId)
            if (streamed == null) {
                // 流式且无法读取 → 放行（不改写，保持页面可用）
                continueResponse(requestId)
                return
            }
            bodyResult = buildJsonObject {
                put("base64Encoded", "false")
                put("body", streamed)
            }
        }
        val base64Encoded = bodyResult["base64Encoded"]?.jsonPrimitive?.contentOrNull == "true"
        val bodyRaw = bodyResult["body"]?.jsonPrimitive?.contentOrNull ?: ""
        val source = if (base64Encoded) decodeBase64(bodyRaw) else bodyRaw
        if (source.isEmpty()) {
            continueResponse(requestId)
            return
        }

        // 2) 改写（ScriptInterceptor：debugger 中和 + 附加注入）
        var transformed: ScriptTransformResult = transformer.transform(source)
        if (rule.prepend != null || rule.append != null) {
            val patched = (rule.prepend?.let { "$it\n" } ?: "") + transformed.transformed + (rule.append?.let { "\n$it" } ?: "")
            transformed = transformed.copy(transformed = patched)
        }
        // 改写后若与原文一致（无 debugger 也无注入），直接放行省一次 fulfill
        if (transformed.transformed == source) {
            continueResponse(requestId)
            return
        }

        // 3) 响应头透传 + 摘除 content-encoding/content-length（体已解压且长度变化）
        val headers = passthroughHeaders(params["responseHeaders"]?.jsonArray)
        val body64 = encodeBase64(transformed.transformed)
        val fulfilled = session.call(
            "Fetch.fulfillRequest",
            buildJsonObject {
                put("requestId", requestId)
                put("responseCode", responseStatusCode)
                put("responseHeaders", headers)
                put("body", body64)
            },
        )
        if (fulfilled == null) {
            continueResponse(requestId) // fulfill 失败兜底放行
            return
        }
        val record = RewriteRecord(
            url = url,
            requestId = requestId,
            originalHash = transformed.originalHash,
            transformedHash = transformed.transformedHash,
            neutralized = transformed.debuggerNeutralized,
            sriWarning = buildSriWarning(params, transformed),
        )
        records.add(record)
        if (records.size > MAX_RECORDS) records.pollFirst()
        onRewritten?.invoke(record)
    }

    /**
     * 流式响应兜底（报告缺口）：Fetch.getResponseBody 对流式/未缓冲的响应不返回，
     * 此时改走 takeResponseBodyAsStream + IO.read 分块拼接，仍可在执行前拿到改写的唯一机会。
     */
    private suspend fun fetchBodyStreaming(requestId: String): String? {
        val streamResp = session.call(
            "Fetch.takeResponseBodyAsStream",
            buildJsonObject { put("requestId", requestId) },
        ) ?: return null
        val streamId = streamResp["stream"]?.jsonPrimitive?.contentOrNull ?: return null
        // （P2-2 修复）：
        // 1) 按块累积原始字节，读完统一按 UTF-8 解码——原实现每块独立
        //    String(bytes, UTF_8)，多字节 UTF-8 字符跨块边界时被 U+FFFD
        //    破坏，改写后的脚本语法可能直接损坏；
        // 2) finally 关闭 IO stream 句柄——原实现从不调 IO.close，
        //    浏览器侧 stream 句柄泄漏。
        val chunks = mutableListOf<ByteArray>()
        try {
            var guard = 0
            while (guard++ < 256) { // 防死循环上限（约 128MB @512KB/块）
                val readResp = session.call(
                    "IO.read",
                    buildJsonObject {
                        put("handle", streamId)
                        put("size", 512 * 1024)
                    },
                ) ?: break
                val data = readResp["data"]?.jsonPrimitive?.contentOrNull ?: ""
                val isB64 = readResp["base64Encoded"]?.jsonPrimitive?.contentOrNull == "true"
                val bytes = if (isB64) {
                    runCatching { Base64.decode(data, Base64.DEFAULT) }.getOrDefault(ByteArray(0))
                } else {
                    data.toByteArray(Charsets.UTF_8)
                }
                if (bytes.isNotEmpty()) chunks.add(bytes)
                if (readResp["eof"]?.jsonPrimitive?.contentOrNull == "true") break
            }
        } finally {
            session.call("IO.close", buildJsonObject { put("handle", streamId) })
        }
        if (chunks.isEmpty()) return null
        val total = chunks.sumOf { it.size }
        val all = ByteArray(total)
        var pos = 0
        chunks.forEach {
            System.arraycopy(it, 0, all, pos, it.size)
            pos += it.size
        }
        return String(all, Charsets.UTF_8)
    }

    /**
     * 真实 SRI 风险提示（报告 §37 闭环）：不再恒传 null。
     * - 优先从响应头提取真实 integrity / Content-Security-Policy: require-sri-for；
     * - SRI 通常声明在 HTML <script integrity="..."> 属性（响应头拿不到），
     *   此时若发生了改写，给出"可能违反 HTML 级 integrity"的显式提醒。
     */
    private fun buildSriWarning(params: JsonObject, transformed: ScriptTransformResult): String? {
        if (transformed.debuggerNeutralized <= 0) return null
        // 响应头级 SRI 策略
        var integrityHeader: String? = null
        params["responseHeaders"]?.jsonArray?.forEach { h ->
            val ho = h as? JsonObject ?: return@forEach
            val name = ho["name"]?.jsonPrimitive?.contentOrNull?.lowercase() ?: return@forEach
            val value = ho["value"]?.jsonPrimitive?.contentOrNull ?: ""
            when (name) {
                "integrity" -> integrityHeader = value
                "content-security-policy" -> if (value.contains("require-sri-for", ignoreCase = true)) {
                    integrityHeader = "CSP require-sri-for"
                }
            }
        }
        val viaHeader = integrityHeader?.let { transformer.sriWarning(it, transformed) }
        if (viaHeader != null) return viaHeader
        // 缺省：很可能是 HTML <script integrity> 属性的跨头 SRI，显式提醒
        return "脚本已被改写（中和 ${transformed.debuggerNeutralized} 处调试语句），可能违反页面 HTML 中声明的 " +
            "<script integrity>/SRI 校验——浏览器可能因哈希失配拒绝执行，仅在实验/逆向模式可用。"
    }

    /** continueResponse（Chromium 114+）；旧内核回退 continueRequest */
    private suspend fun continueResponse(requestId: String) {
        val ok = session.call(
            "Fetch.continueResponse",
            buildJsonObject { put("requestId", requestId) },
        )
        if (ok == null) {
            session.call("Fetch.continueRequest", buildJsonObject { put("requestId", requestId) })
        }
    }

    private fun passthroughHeaders(headers: JsonArray?): JsonArray {
        if (headers == null) return buildJsonArray { }
        return buildJsonArray {
            for (h in headers) {
                val ho = h as? JsonObject ?: continue
                val name = ho["name"]?.jsonPrimitive?.contentOrNull ?: continue
                val lower = name.lowercase()
                if (lower == "content-encoding" || lower == "content-length") continue
                add(
                    buildJsonObject {
                        put("name", name)
                        put("value", ho["value"]?.jsonPrimitive?.contentOrNull ?: "")
                    },
                )
            }
        }
    }

    private fun decodeBase64(b64: String): String =
        runCatching { String(Base64.decode(b64, Base64.DEFAULT), Charsets.UTF_8) }.getOrDefault("")

    private fun encodeBase64(text: String): String =
        runCatching { Base64.encodeToString(text.toByteArray(Charsets.UTF_8), Base64.NO_WRAP) }
            .getOrDefault("")

    companion object {
        private const val MAX_RECORDS = 200
    }
}
