package com.webreverse.mcp.devtools.network

import com.webreverse.mcp.browser.engine.BrowserEngine
import com.webreverse.mcp.core.common.model.HarExport
import com.webreverse.mcp.core.common.model.HarEntry
import com.webreverse.mcp.core.common.model.HarNameValue
import com.webreverse.mcp.core.common.model.HarPostData
import com.webreverse.mcp.core.common.model.HarRequest
import com.webreverse.mcp.core.common.model.HarResponse
import com.webreverse.mcp.core.common.model.NetworkEntry
import kotlinx.serialization.json.Json

/** 网络检查器：过滤、搜索、HAR 导入导出、cURL 生成 */
class NetworkInspector {

    private val json = Json { prettyPrint = true; ignoreUnknownKeys = true }

    suspend fun getEntries(engine: BrowserEngine): List<NetworkEntry> = engine.getNetworkEntries()

    suspend fun search(engine: BrowserEngine, query: String): List<NetworkEntry> =
        engine.getNetworkEntries().filter {
            it.url.contains(query, ignoreCase = true) ||
                it.method.wire.contains(query, ignoreCase = true) ||
                it.status.toString() == query ||
                it.requestBody?.contains(query, ignoreCase = true) == true ||
                it.responseBody?.contains(query, ignoreCase = true) == true
        }

    suspend fun filter(
        engine: BrowserEngine,
        resourceType: String? = null,
        status: Int? = null,
        method: String? = null,
        host: String? = null,
    ): List<NetworkEntry> =
        engine.getNetworkEntries().filter { entry ->
            (resourceType == null || entry.resourceType.display.equals(resourceType, ignoreCase = true)) &&
                (status == null || entry.status == status) &&
                (method == null || entry.method.wire.equals(method, ignoreCase = true)) &&
                (host == null || entry.url.contains(host, ignoreCase = true))
        }

    suspend fun exportHar(engine: BrowserEngine): HarExport {
        val entries = engine.getNetworkEntries().map { entry ->
            HarEntry(
                startedDateTime = java.time.Instant.ofEpochMilli(entry.startedAt).toString(),
                time = entry.durationMs,
                request = HarRequest(
                    method = entry.method.wire,
                    url = entry.url,
                    headers = entry.requestHeaders.map { (k, v) -> HarNameValue(k, v) },
                    queryString = entry.queryParams.map { (k, v) -> HarNameValue(k, v) },
                    cookies = entry.cookies.map { HarNameValue(it.name, it.value) },
                    postData = entry.requestBody?.let { HarPostData(entry.mimeType, it) },
                ),
                response = HarResponse(
                    status = entry.status,
                    statusText = entry.statusText,
                    headers = entry.responseHeaders.map { (k, v) -> HarNameValue(k, v) },
                    content = com.webreverse.mcp.core.common.model.HarContent(
                        size = entry.responseBodySize,
                        mimeType = entry.mimeType,
                        text = entry.responseBody,
                    ),
                    redirectURL = entry.redirectUrl.orEmpty(),
                ),
                timings = mapOf(
                    "dns" to entry.timing.dns,
                    "connect" to entry.timing.connect,
                    "ssl" to entry.timing.ssl,
                    "wait" to entry.timing.ttfb,
                    "receive" to entry.timing.download,
                    "total" to entry.timing.total,
                ),
            )
        }
        return HarExport(log = com.webreverse.mcp.core.common.model.HarLog(entries = entries))
    }

    fun exportHarJson(har: HarExport): String = json.encodeToString(HarExport.serializer(), har)

    fun importHar(harJson: String): HarExport = json.decodeFromString(HarExport.serializer(), harJson)

    fun toCurl(entry: NetworkEntry): String {
        val sb = StringBuilder("curl -X ${entry.method.wire} '${entry.url}'")
        entry.requestHeaders.forEach { (k, v) ->
            sb.append(" -H '").append(k).append(": ").append(v).append("'")
        }
        entry.requestBody?.let { body ->
            sb.append(" -d '").append(body).append("'")
        }
        return sb.toString()
    }

    fun toCurlJson(entry: NetworkEntry): String = json.encodeToString(
        kotlinx.serialization.json.JsonObject.serializer(),
        kotlinx.serialization.json.buildJsonObject {
            put("curl", kotlinx.serialization.json.JsonPrimitive(toCurl(entry)))
        },
    )
}
