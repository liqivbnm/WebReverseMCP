package com.webreverse.mcp.core.common.model

import kotlinx.serialization.Serializable

/** HTTP 方法 */
@Serializable
enum class HttpMethod(val wire: String) {
    GET("GET"), POST("POST"), PUT("PUT"), DELETE("DELETE"),
    PATCH("PATCH"), HEAD("HEAD"), OPTIONS("OPTIONS"), CONNECT("CONNECT"), TRACE("TRACE");

    companion object {
        fun from(value: String?): HttpMethod =
            entries.firstOrNull { it.wire.equals(value, ignoreCase = true) } ?: GET
    }
}

/** 资源类型 */
@Serializable
enum class ResourceType(val display: String) {
    DOCUMENT("Document"), STYLESHEET("Stylesheet"), SCRIPT("Script"),
    IMAGE("Image"), FONT("Font"), MEDIA("Media"), MANIFEST("Manifest"),
    XHR("XHR"), FETCH("Fetch"), WEBSOCKET("WebSocket"), EVENTSOURCE("EventSource"),
    OTHER("Other");

    companion object {
        fun fromMime(mime: String?): ResourceType = when {
            mime == null -> OTHER
            mime.contains("html") -> DOCUMENT
            mime.contains("css") -> STYLESHEET
            mime.contains("javascript") || mime.contains("ecmascript") -> SCRIPT
            mime.contains("image") -> IMAGE
            mime.contains("font") || mime.contains("woff") -> FONT
            mime.contains("audio") || mime.contains("video") -> MEDIA
            mime.contains("json") || mime.contains("xml") -> XHR
            else -> OTHER
        }
    }
}

/** 网络请求/响应条目 */
@Serializable
data class NetworkEntry(
    val id: String,
    val tabId: String,
    val requestId: String,
    val url: String,
    val method: HttpMethod = HttpMethod.GET,
    val status: Int = 0,
    val statusText: String = "",
    val protocol: String = "",
    val mimeType: String = "",
    val resourceType: ResourceType = ResourceType.OTHER,
    val requestHeaders: Map<String, String> = emptyMap(),
    val responseHeaders: Map<String, String> = emptyMap(),
    val queryParams: Map<String, String> = emptyMap(),
    val requestBody: String? = null,
    val responseBody: String? = null,
    val requestBodySize: Long = 0,
    val responseBodySize: Long = 0,
    val timing: Timing = Timing(),
    val initiator: String = "",
    val initiatorStack: String = "",
    val remoteAddress: String = "",
    val serverIpAddress: String = "",
    val isRedirect: Boolean = false,
    val redirectUrl: String? = null,
    val fromCache: Boolean = false,
    val fromServiceWorker: Boolean = false,
    val isBlocked: Boolean = false,
    val blockedReason: String? = null,
    val isMocked: Boolean = false,
    val startedAt: Long = System.currentTimeMillis(),
    val endedAt: Long = 0,
    val cookies: List<Cookie> = emptyList(),
) {
    /**
     * 安全时长：endedAt 未回填（仍进行中或仅发起阶段捕获）时返回 0，
     * 而非 endedAt(0) - startedAt 产生的巨大负数。
     */
    val durationMs: Long get() = if (endedAt > startedAt) endedAt - startedAt else 0L
}

/** 网络时序 */
@Serializable
data class Timing(
    val dnsStart: Long = 0,
    val dnsEnd: Long = 0,
    val connectStart: Long = 0,
    val connectEnd: Long = 0,
    val sslStart: Long = 0,
    val sslEnd: Long = 0,
    val requestStart: Long = 0,
    val responseStart: Long = 0,
    val responseEnd: Long = 0,
    val sendStart: Long = 0,
    val sendEnd: Long = 0,
    val total: Long = 0,
) {
    val dns: Long get() = dnsEnd - dnsStart
    val connect: Long get() = connectEnd - connectStart
    val ssl: Long get() = sslEnd - sslStart
    val ttfb: Long get() = responseStart - requestStart
    val download: Long get() = responseEnd - responseStart
}

/** Cookie */
@Serializable
data class Cookie(
    val name: String,
    val value: String,
    val domain: String = "",
    val path: String = "/",
    val expires: Long = 0,
    val isSecure: Boolean = false,
    val isHttpOnly: Boolean = false,
    val isSession: Boolean = true,
)

/** HAR 导出 */
@Serializable
data class HarExport(
    val log: HarLog = HarLog(),
)

@Serializable
data class HarLog(
    val version: String = "1.2",
    val creator: HarCreator = HarCreator(),
    val entries: List<HarEntry> = emptyList(),
)

@Serializable
data class HarCreator(
    val name: String = "WebReverseMCP",
    val version: String = "1.0.0",
)

@Serializable
data class HarEntry(
    val startedDateTime: String,
    val time: Long,
    val request: HarRequest,
    val response: HarResponse,
    val cache: Map<String, String> = emptyMap(),
    val timings: Map<String, Long> = emptyMap(),
)

@Serializable
data class HarRequest(
    val method: String,
    val url: String,
    val httpVersion: String = "HTTP/1.1",
    val headers: List<HarNameValue> = emptyList(),
    val queryString: List<HarNameValue> = emptyList(),
    val cookies: List<HarNameValue> = emptyList(),
    val headersSize: Long = -1,
    val bodySize: Long = -1,
    val postData: HarPostData? = null,
)

@Serializable
data class HarResponse(
    val status: Int,
    val statusText: String,
    val httpVersion: String = "HTTP/1.1",
    val headers: List<HarNameValue> = emptyList(),
    val cookies: List<HarNameValue> = emptyList(),
    val content: HarContent = HarContent(),
    val redirectURL: String = "",
    val headersSize: Long = -1,
    val bodySize: Long = -1,
)

@Serializable
data class HarPostData(
    val mimeType: String = "",
    val text: String = "",
)

@Serializable
data class HarContent(
    val size: Long = 0,
    val mimeType: String = "",
    val text: String? = null,
)

@Serializable
data class HarNameValue(
    val name: String,
    val value: String,
)
