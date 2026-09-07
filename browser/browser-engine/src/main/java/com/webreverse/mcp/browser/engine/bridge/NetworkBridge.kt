package com.webreverse.mcp.browser.engine.bridge

import android.net.Uri
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import com.webreverse.mcp.core.common.event.EventBus
import com.webreverse.mcp.core.common.event.NetworkEvent
import com.webreverse.mcp.core.common.model.HttpMethod
import com.webreverse.mcp.core.common.model.NetworkEntry
import com.webreverse.mcp.core.common.model.ResourceType
import com.webreverse.mcp.core.common.model.Timing
import com.webreverse.mcp.core.common.util.Ids
import com.webreverse.mcp.core.common.util.Redactor
import java.io.ByteArrayInputStream
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * 网络采集 Bridge：通过 shouldInterceptRequest 捕获请求/响应。
 * 支持 Hook 规则匹配（Block/Redirect/Mock/Modify）。
 *
 * 合并注入式 fetch/XHR hook 上报的事件（[onJsNetEvent]）。
 * shouldInterceptRequest 只能看到请求发起阶段（status=0、无时长），
 * 响应状态码/耗时/响应体由页面内 hook 通过 __MCP__.netEvent 回传补全——
 * 这样无需 CDP 也能在 network.list / network.get 中看到完整请求信息。
 */
class NetworkBridge(
    private val eventBus: EventBus,
    private val hookMatcher: HookMatcher? = null,
) {
    private val entries = ConcurrentHashMap<String, MutableList<NetworkEntry>>()
    private val lock = ReentrantLock()

    /**
     * rid → entryId（ Request Identity）：JS hook 的唯一请求标识
     * 到本地条目 id 的映射。三阶段（request/response/body）经它精确归并。
     */
    private val ridIndex = ConcurrentHashMap<String, String>()

    fun intercept(tabId: String, request: WebResourceRequest): WebResourceResponse? {
        val url = request.url.toString()
        val method = request.method
        val headers = request.requestHeaders
        val entryId = Ids.short()

        // Hook 规则匹配
        hookMatcher?.let { matcher ->
            val action = matcher.match(tabId, url, method, headers)
            if (action != null) {
                when (action.type) {
                    HookActionType.BLOCK -> {
                        record(
                            tabId, entryId, url, method, 0, "Blocked",
                            headers, emptyMap(), null, null, ResourceType.OTHER, true, "blocked by rule ${action.ruleName}",
                        )
                        return WebResourceResponse("text/plain", "utf-8", 403, "Blocked", emptyMap(), ByteArrayInputStream("Blocked by hook rule".toByteArray()))
                    }
                    HookActionType.REDIRECT -> {
                        // 返回重定向响应
                        val redirectUrl = action.payload.ifBlank { url }
                        record(tabId, entryId, url, method, 302, "Redirect", headers, emptyMap(), null, null, ResourceType.OTHER, false, null, redirectUrl = redirectUrl)
                        return WebResourceResponse("text/html", "utf-8", 302, "Redirect", mapOf("Location" to redirectUrl), ByteArrayInputStream(ByteArray(0)))
                    }
                    HookActionType.MOCK -> {
                        val body = action.payload.toByteArray()
                        record(tabId, entryId, url, method, 200, "OK", headers, emptyMap(), null, String(body), ResourceType.OTHER, false, null, isMocked = true)
                        return WebResourceResponse("application/json", "utf-8", 200, "OK", emptyMap(), ByteArrayInputStream(body))
                    }
                    HookActionType.DELAY -> {
                        Thread.sleep(action.payload.toLongOrNull() ?: 1000L)
                    }
                    else -> Unit
                }
            }
        }

        record(tabId, entryId, url, method, 0, "", headers, emptyMap(), null, null, ResourceType.OTHER)
        return null
    }

    fun interceptLegacy(tabId: String, url: String): WebResourceResponse? {
        // 旧版 API 兜底
        return null
    }

    /**
     * 安全提取 query 参数。Uri.getQueryParameterNames 对非层级 URI
     * （data:、blob:、about:、javascript: 等）会抛 UnsupportedOperationException——
     * 页面经 data: URI 加载资源（如响应体预览）时，shouldInterceptRequest
     * 会拦到这类请求并进入本桥接，直接解析即崩溃。
     * 此类 URI 无 query 概念，返回空表即可。
     */
    private fun queryParamsOf(uri: Uri): Map<String, String> = try {
        uri.queryParameterNames.associateWith { uri.getQueryParameter(it).orEmpty() }
    } catch (_: UnsupportedOperationException) {
        emptyMap()
    } catch (_: Exception) {
        emptyMap()
    }

    /** 记录被拦截的自定义 scheme 跳转（baiduboxapp:// 等 App 唤起），供网络面板查看 */
    fun recordBlockedScheme(tabId: String, url: String) {
        val entryId = Ids.short()
        record(
            tabId, entryId, url, "GET", 0, "Blocked Scheme",
            emptyMap(), emptyMap(), null, null, ResourceType.OTHER, true, "custom scheme intercepted",
        )
    }

    private fun record(
        tabId: String,
        entryId: String,
        url: String,
        method: String,
        status: Int,
        statusText: String,
        requestHeaders: Map<String, String>,
        responseHeaders: Map<String, String>,
        requestBody: String?,
        responseBody: String?,
        resourceType: ResourceType,
        isBlocked: Boolean = false,
        blockedReason: String? = null,
        redirectUrl: String? = null,
        isMocked: Boolean = false,
    ) {
        val uri = Uri.parse(url)
        val entry = NetworkEntry(
            id = entryId,
            tabId = tabId,
            requestId = entryId,
            url = Redactor.redactUrl(url),
            method = HttpMethod.from(method),
            status = status,
            statusText = statusText,
            protocol = uri.scheme ?: "",
            resourceType = resourceType,
            requestHeaders = Redactor.redactHeaders(requestHeaders),
            responseHeaders = Redactor.redactHeaders(responseHeaders),
            queryParams = queryParamsOf(uri),
            requestBody = requestBody?.let { Redactor.redactText(it) },
            responseBody = responseBody?.let { Redactor.redactText(it) },
            timing = Timing(total = 0),
            initiator = "",
            isBlocked = isBlocked,
            blockedReason = blockedReason,
            redirectUrl = redirectUrl,
            isMocked = isMocked,
            startedAt = System.currentTimeMillis(),
        )
        lock.withLock {
            entries.getOrPut(tabId) { mutableListOf() }.add(entry)
            trimLocked(tabId)
        }
        eventBus.tryEmit(NetworkEvent.RequestStarted(entryId, tabId, entry.url, method))
        if (status > 0) {
            eventBus.tryEmit(NetworkEvent.ResponseReceived(entryId, tabId, entry.url, status))
            eventBus.tryEmit(NetworkEvent.RequestCompleted(entryId, tabId, entry.url, status, 0))
        }
    }

    // ---------------- 注入式 hook 事件合并 ----------------

    /**
     * 页面内 fetch/XHR hook 上报的网络事件。
     *
     * JSON 协议（JsScripts 内生成）：
     * - {"phase":"request","rid","src":"fetch|xhr","url","method","body"?}
     * - {"phase":"response","rid","src","url","method","status","durationMs"?,"contentType"?}
     * - {"phase":"body","rid","src","url","method","status","body"}
     *
     * 匹配策略（ 报告 §12 Request Identity）：
     * - 首选 rid 精确归并：JS hook 每条请求生成唯一 rid，三阶段（request/response/
     *   body）同 rid 归并到同一条目——同 URL 并发请求（轮询/批量提交）不再错配；
     * - 兼容旧脚本（无 rid）：退回 "协议+主机+路径"（不含 query，避免脱敏差异）
     *   匹配最近一条未完成条目；找不到则新建（覆盖 Service Worker 等
     *   shouldInterceptRequest 不可见的请求）。
     */
    fun onJsNetEvent(tabId: String, json: String) {
        runCatching {
            val obj = org.json.JSONObject(json)
            val phase = obj.optString("phase")
            val url = obj.optString("url")
            if (phase.isBlank() || url.isBlank()) return
            when (phase) {
                "request" -> onJsRequest(tabId, url, obj)
                "response" -> onJsResponse(tabId, url, obj)
                "body" -> onJsBody(tabId, url, obj)
            }
        }
    }

    private fun onJsRequest(tabId: String, url: String, obj: org.json.JSONObject) {
        val method = obj.optString("method").ifBlank { "GET" }
        val body = obj.optString("body").takeIf { it.isNotBlank() }
        val rid = obj.optString("rid").takeIf { it.isNotBlank() }
        lock.withLock {
            val list = entries.getOrPut(tabId) { mutableListOf() }
            val idx = indexOfMatchLocked(list, url, method, rid = rid)
            if (idx >= 0) {
                val e = list[idx]
                if (rid != null) ridIndex[rid] = e.id
                if (body != null && e.requestBody == null) {
                    list[idx] = e.copy(requestBody = Redactor.redactText(body))
                }
            } else {
                val uri = Uri.parse(url)
                val entryId = Ids.short()
                if (rid != null) ridIndex[rid] = entryId
                val entry = NetworkEntry(
                    id = entryId,
                    tabId = tabId,
                    requestId = rid ?: Ids.short(),
                    url = Redactor.redactUrl(url),
                    method = HttpMethod.from(method),
                    protocol = uri.scheme ?: "",
                    queryParams = queryParamsOf(uri),
                    requestBody = body?.let { Redactor.redactText(it) },
                    resourceType = ResourceType.XHR,
                    initiator = "js:" + obj.optString("src").ifBlank { "hook" },
                )
                list.add(entry)
                trimLocked(tabId)
                eventBus.tryEmit(NetworkEvent.RequestStarted(entry.id, tabId, entry.url, method))
            }
        }
    }

    private fun onJsResponse(tabId: String, url: String, obj: org.json.JSONObject) {
        val method = obj.optString("method").ifBlank { "GET" }
        val status = obj.optInt("status", 0)
        val duration = obj.optLong("durationMs", 0L).coerceIn(0, 10 * 60_000L)
        val contentType = obj.optString("contentType").substringBefore(';')
        val rid = obj.optString("rid").takeIf { it.isNotBlank() }
        lock.withLock {
            val list = entries.getOrPut(tabId) { mutableListOf() }
            val idx = indexOfMatchLocked(list, url, method, rid = rid, allowCompleted = true)
            if (idx >= 0) {
                val e = list[idx]
                val endedAt = System.currentTimeMillis()
                list[idx] = e.copy(
                    status = if (status > 0) status else e.status,
                    statusText = statusPhrase(status).ifBlank { e.statusText },
                    endedAt = endedAt,
                    timing = e.timing.copy(total = duration, responseEnd = duration),
                    mimeType = contentType.ifBlank { e.mimeType },
                    resourceType = ResourceType.fromMime(contentType.ifBlank { null }).let {
                        if (e.resourceType == ResourceType.OTHER) it else e.resourceType
                    },
                )
                eventBus.tryEmit(NetworkEvent.ResponseReceived(e.id, tabId, e.url, status))
                eventBus.tryEmit(NetworkEvent.RequestCompleted(e.id, tabId, e.url, status, duration))
            }
        }
    }

    private fun onJsBody(tabId: String, url: String, obj: org.json.JSONObject) {
        val method = obj.optString("method").ifBlank { "GET" }
        val body = obj.optString("body")
        val rid = obj.optString("rid").takeIf { it.isNotBlank() }
        if (body.isBlank()) return
        lock.withLock {
            val list = entries[tabId] ?: return
            val idx = indexOfMatchLocked(list, url, method, rid = rid, allowCompleted = true)
            if (idx >= 0) {
                val e = list[idx]
                if (e.responseBody == null) {
                    list[idx] = e.copy(
                        responseBody = Redactor.redactText(body),
                        responseBodySize = body.length.toLong(),
                    )
                }
            }
        }
    }

    /**
     * 请求条目匹配（ Request Identity）：
     * 1) rid 精确匹配（JS hook 每请求唯一 id，三阶段同 rid 归并）；
     * 2) 兼容无 rid 旧路径：按 "协议+主机+路径" 匹配最近一条未完成条目。
     */
    private fun indexOfMatchLocked(
        list: List<NetworkEntry>,
        url: String,
        method: String,
        rid: String? = null,
        allowCompleted: Boolean = false,
    ): Int {
        // rid 精确归并（response/body 阶段优先）
        if (rid != null) {
            val entryId = ridIndex[rid]
            if (entryId != null) {
                for (i in list.indices.reversed()) {
                    if (list[i].id == entryId) return i
                }
            }
            // rid 未登记（条目被 trim/清理）：按 URL 补建场景走 pathKey 路径
        }
        val key = pathKeyOf(url)
        if (key.isBlank()) return -1
        val methodM = HttpMethod.from(method)
        // 倒序找最近一条：路径一致 + 方法一致 + 未完成
        for (i in list.indices.reversed()) {
            val e = list[i]
            if (e.method != methodM) continue
            if (pathKeyOf(e.url) != key) continue
            if (!allowCompleted && e.status != 0) continue
            return i
        }
        return -1
    }

    private fun pathKeyOf(url: String): String = try {
        val uri = Uri.parse(url)
        (uri.scheme?.lowercase() ?: "") + "://" + (uri.host?.lowercase() ?: "") + (uri.path ?: "")
    } catch (e: Exception) {
        url.substringBefore('?')
    }

    private fun statusPhrase(status: Int): String = when (status) {
        200 -> "OK"; 201 -> "Created"; 204 -> "No Content"
        301 -> "Moved Permanently"; 302 -> "Found"; 304 -> "Not Modified"
        400 -> "Bad Request"; 401 -> "Unauthorized"; 403 -> "Forbidden"
        404 -> "Not Found"; 405 -> "Method Not Allowed"; 429 -> "Too Many Requests"
        500 -> "Internal Server Error"; 502 -> "Bad Gateway"; 503 -> "Service Unavailable"
        504 -> "Gateway Timeout"
        else -> ""
    }

    /** 单 Tab 条目上限，防止长时间会话内存膨胀（同步清理被丢弃条目的 rid 映射） */
    private fun trimLocked(tabId: String) {
        val list = entries[tabId] ?: return
        if (list.size > MAX_ENTRIES_PER_TAB) {
            val removed = list.removeAt(0)
            ridIndex.entries.removeAll { it.value == removed.id }
        }
    }

    fun getEntries(tabId: String): List<NetworkEntry> =
        entries[tabId]?.toList() ?: emptyList()

    fun getAllEntries(): List<NetworkEntry> = entries.values.flatten()

    fun clear(tabId: String) {
        entries.remove(tabId)?.let { removed ->
            // 该 Tab 全部条目的 rid 映射一并清理，防止长期会话无限增长
            val ids = removed.mapTo(HashSet()) { it.id }
            ridIndex.entries.removeAll { it.value in ids }
        }
    }

    fun clearAll() {
        entries.clear()
        ridIndex.clear()
    }

    companion object {
        private const val MAX_ENTRIES_PER_TAB = 2000
    }
}

/** Hook 动作类型 */
enum class HookActionType { LOG, BLOCK, REDIRECT, MOCK, DELAY, MODIFY, TRACE }

/** Hook 匹配结果 */
data class HookMatchResult(
    val type: HookActionType,
    val ruleName: String,
    val payload: String = "",
)

/** Hook 匹配器接口 */
interface HookMatcher {
    fun match(tabId: String, url: String, method: String, headers: Map<String, String>): HookMatchResult?
}
