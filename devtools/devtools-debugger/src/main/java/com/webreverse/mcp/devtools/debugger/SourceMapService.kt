package com.webreverse.mcp.devtools.debugger

import android.util.Base64
import com.webreverse.mcp.devtools.protocol.cdp.CdpScript
import com.webreverse.mcp.javascript.analysis.GeneratedLocation
import com.webreverse.mcp.javascript.analysis.OriginalLocation
import com.webreverse.mcp.javascript.analysis.SourceMapInfo
import com.webreverse.mcp.javascript.analysis.SourceMapParser
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URI

/**
 * SourceMap 服务：桥接 CDP Debugger 与原始源码（桌面 DevTools Sources 面板语义）。
 *
 * - 下载并缓存脚本 sourceMap（http(s) 与 data: 内嵌 base64 两种形态）
 * - 原始源码断点：src/api/sign.ts:87 -> bundle 反查 -> Debugger.setBreakpointByUrl
 * - bundle 位置反查：bundle.js:183742 -> src/api/sign.ts:87（暂停调用栈映射回源码）
 */
class SourceMapService(private val parser: SourceMapParser = SourceMapParser()) {

    /** 单个脚本的 sourcemap 加载状态 */
    data class SourceMapEntry(
        val scriptUrl: String,
        val sourceMapUrl: String,
        val info: SourceMapInfo? = null,
        val sources: List<String> = emptyList(),
        val error: String? = null,
    )

    private val cache = LinkedHashMap<String, SourceMapEntry>()
    private val mutex = Mutex()

    private val _entries = MutableStateFlow<List<SourceMapEntry>>(emptyList())
    val entries: StateFlow<List<SourceMapEntry>> = _entries.asStateFlow()

    /** 加载（或命中缓存）指定脚本的 sourcemap；失败也记录状态避免反复下载 */
    suspend fun load(script: CdpScript): SourceMapEntry = mutex.withLock {
        val mapUrl = script.sourceMapUrl ?: return SourceMapEntry(
            scriptUrl = script.url,
            sourceMapUrl = "",
            error = "脚本未声明 sourceMappingURL",
        )
        cache[script.url]?.let { return it }
        val entry = runCatching { fetch(script.url, mapUrl) }
            .fold(
                onSuccess = { json ->
                    val info = parser.parse(json)
                    SourceMapEntry(
                        scriptUrl = script.url,
                        sourceMapUrl = resolvedMapUrl(script.url, mapUrl).orEmpty(),
                        info = info,
                        sources = parser.sourcesOf(info),
                        error = if (info.parsed) null else "sourcemap 解析失败",
                    )
                },
                onFailure = { SourceMapEntry(script.url, mapUrl, error = "下载失败: ${it.message}") },
            )
        cache[script.url] = entry
        _entries.value = cache.values.toList()
        entry
    }

    /** 已缓存条目（不触发下载） */
    fun cached(): List<SourceMapEntry> = _entries.value

    /** 原始源码位置 -> bundle 位置（在该脚本的 sourcemap 内） */
    fun reverseLocate(entry: SourceMapEntry, sourceFile: String, sourceLine: Int): GeneratedLocation? =
        entry.info?.let { parser.reverseLocate(it, sourceFile, sourceLine) }

    /** bundle 位置 -> 原始源码位置 */
    fun locateOriginal(entry: SourceMapEntry, generatedLine: Int, generatedColumn: Int): OriginalLocation? =
        entry.info?.let { parser.locateOriginal(it, generatedLine - 1, generatedColumn) }

    // ---------------- 下载 ----------------

    private suspend fun fetch(scriptUrl: String, mapUrl: String): String = withContext(Dispatchers.IO) {
        val data = mapUrl.removePrefix("data:")
        if (mapUrl.startsWith("data:") && data.contains("base64,")) {
            val payload = data.substringAfter("base64,")
            return@withContext String(Base64.decode(payload, Base64.DEFAULT), Charsets.UTF_8)
        }
        val absolute = resolvedMapUrl(scriptUrl, mapUrl)
            ?: throw IllegalArgumentException("无法解析 sourcemap URL: $mapUrl")
        val conn = (URI(absolute).toURL() as HttpURLConnection).apply {
            connectTimeout = 10_000
            readTimeout = 15_000
            requestMethod = "GET"
            setRequestProperty(
                "User-Agent",
                "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
            )
            setRequestProperty("Accept", "*/*")
            instanceFollowRedirects = true
        }
        try {
            val code = conn.responseCode
            if (code !in 200..299) throw IllegalArgumentException("HTTP $code")
            conn.inputStream.use { input ->
                val bytes = input.readBytes()
                if (bytes.size > 20_000_000) throw IllegalArgumentException("sourcemap 超过 20MB")
                String(bytes, Charsets.UTF_8)
            }
        } finally {
            conn.disconnect()
        }
    }

    /** sourcemap URL 归一化为绝对地址（data: 原样返回） */
    private fun resolvedMapUrl(scriptUrl: String, mapUrl: String): String? {
        if (mapUrl.startsWith("data:")) return mapUrl
        return runCatching {
            if (mapUrl.startsWith("http://") || mapUrl.startsWith("https://")) {
                mapUrl
            } else {
                URI(scriptUrl).resolve(mapUrl).toString()
            }
        }.getOrNull()
    }
}
