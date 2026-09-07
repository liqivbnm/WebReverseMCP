package com.webreverse.mcp.javascript.analysis

import com.webreverse.mcp.core.common.model.ApiEndpoint
import com.webreverse.mcp.core.common.model.NetworkEntry
import com.webreverse.mcp.core.common.model.ResourceType
import com.webreverse.mcp.javascript.parser.CallExpressionInfo
import com.webreverse.mcp.javascript.parser.JsParser
import kotlinx.serialization.Serializable

/** API 发现结果。 */
@Serializable
data class ApiDiscoveryResult(
    val endpoints: List<ApiEndpoint> = emptyList(),
    val totalSources: Int = 0,
    val totalStrings: Int = 0,
)

/**
 * API Discovery Engine：
 * HTML / JS / SourceMap / Network / Runtime 多来源 Endpoint 提取。
 *
 * improvements:
 * - resolve simple const/let/var string concatenation and aliases
 * - decode common JS string escapes before matching
 * - inspect fetch/axios/request call arguments even when a literal is hidden behind a variable
 * - raw-source fetch fallback when the lightweight parser misses a call
 */
class ApiDiscoveryEngine(private val parser: JsParser = JsParser()) {

    private val apiPathPattern = Regex("""[\"'](/[A-Za-z0-9_\-./{}?=&%:+$]+)[\"']""")
    private val apiUrlPattern = Regex("""(https?://[A-Za-z0-9_.\-]+(?::\d+)?(/[A-Za-z0-9_\-./{}?=&%:+$]*))""")
    private val stringAssignmentPattern = Regex("""(?m)\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*([^;\n]{1,1000})""")
    private val rawFetchPattern = Regex("""(?i)\bfetch\s*\(([^\n)]{1,1200})\)""")

    fun discoverFromJs(source: String, sourceName: String = "inline"): ApiDiscoveryResult {
        val endpoints = mutableListOf<ApiEndpoint>()
        val strings = parser.extractStrings(source)
        val calls = parser.extractCallExpressions(source)
        val constants = recoverStringConstants(source)

        // 1) Literal and reconstructed constants.
        (strings + constants.values).distinct().forEach { s ->
            val path = s.takeIf { it.startsWith("/") || it.startsWith("http") }
            if (path != null && looksLikeApiPath(path)) {
                endpoints += ApiEndpoint(
                    method = inferMethod(s, calls),
                    url = path,
                    source = sourceName,
                    caller = findCallerForString(source, s),
                    confidence = if (constants.values.contains(s)) 0.78 else 0.70,
                )
            }
        }

        // 2) Parsed call expressions, including variable/concat URL arguments.
        calls.forEach { call ->
            val callee = call.callee.lowercase()
            if (!looksLikeHttpCaller(callee)) return@forEach
            call.arguments.forEach { arg ->
                val clean = resolveStringExpression(arg, constants)?.trim('"', '\'', '`') ?: arg.trim('"', '\'', '`')
                if (clean.startsWith("/") || clean.startsWith("http")) {
                    endpoints += ApiEndpoint(
                        method = inferMethodFromCallee(callee),
                        url = clean,
                        source = sourceName,
                        line = call.line,
                        caller = callee,
                        confidence = if (constants.values.contains(clean)) 0.92 else 0.85,
                    )
                }
            }
        }

        // 3) Raw-source fallback for parser recovery gaps.
        rawFetchPattern.findAll(source).take(400).forEach { m ->
            val arg = topLevelFirstArg(m.groupValues[1])
            val url = resolveStringExpression(arg, constants)?.trim('"', '\'', '`') ?: arg.trim('"', '\'', '`')
            if (url.startsWith("/") || url.startsWith("http")) {
                val line = source.substring(0, m.range.first).count { it == '\n' } + 1
                endpoints += ApiEndpoint("GET", url, sourceName, line, "fetch", confidence = 0.80)
            }
        }

        val deduped = endpoints
            .filter { looksLikeApiPath(it.url) }
            .groupBy { "${it.method} ${it.url}" }
            .map { (_, list) ->
                list.maxBy { it.confidence }.copy(
                    relatedFunction = list.firstOrNull { it.relatedFunction.isNotBlank() }?.relatedFunction.orEmpty(),
                )
            }
            .sortedBy { it.url }

        return ApiDiscoveryResult(deduped, totalSources = 1, totalStrings = strings.size + constants.size)
    }

    fun discoverFromHtml(html: String, sourceName: String = "html"): ApiDiscoveryResult {
        val endpoints = mutableListOf<ApiEndpoint>()
        apiUrlPattern.findAll(html).forEach { m ->
            val url = m.groupValues[1]
            if (looksLikeApiPath(url)) endpoints += ApiEndpoint("GET", url, sourceName, confidence = 0.50)
        }
        return ApiDiscoveryResult(endpoints.distinctBy { it.url }, totalSources = 1)
    }

    fun discoverFromNetwork(entries: List<NetworkEntry>): ApiDiscoveryResult {
        val endpoints = entries
            .filter { it.resourceType == ResourceType.XHR || it.resourceType == ResourceType.FETCH }
            .map { entry ->
                ApiEndpoint(
                    method = entry.method.wire,
                    url = entry.url,
                    source = entry.initiator,
                    requestBody = entry.requestBody.orEmpty(),
                    responseBody = entry.responseBody.orEmpty(),
                    confidence = 0.90,
                )
            }
            .groupBy { "${it.method} ${it.url}" }
            .map { (_, list) -> list.maxBy { it.confidence } }
        return ApiDiscoveryResult(endpoints, totalSources = entries.size)
    }

    fun merge(vararg results: ApiDiscoveryResult): ApiDiscoveryResult {
        val all = results.flatMap { it.endpoints }
        val deduped = all.groupBy { "${it.method} ${it.url}" }
            .map { (_, list) -> list.maxBy { it.confidence } }
            .sortedBy { it.url }
        return ApiDiscoveryResult(
            endpoints = deduped,
            totalSources = results.sumOf { it.totalSources },
            totalStrings = results.sumOf { it.totalStrings },
        )
    }

    private fun looksLikeHttpCaller(callee: String): Boolean =
        callee.contains("fetch") || callee.contains("axios") || callee.contains("request") ||
            callee.contains("post") || callee.contains("get") || callee.contains("put") ||
            callee.contains("delete") || callee.contains("patch") ||
            callee.contains("xmlhttprequest")

    private fun recoverStringConstants(source: String): Map<String, String> {
        val env = linkedMapOf<String, String>()
        repeat(5) {
            stringAssignmentPattern.findAll(source).forEach { m ->
                resolveStringExpression(m.groupValues[2], env)?.let { value ->
                    if (value.length <= 4096) env[m.groupValues[1]] = value
                }
            }
        }
        return env
    }

    private fun resolveStringExpression(expr: String, env: Map<String, String>): String? {
        val pieces = splitTopLevelPlus(expr)
        if (pieces.isEmpty()) return null
        val out = StringBuilder()
        for (raw in pieces) {
            val t = raw.trim()
            val value = when {
                isQuoted(t) -> decodeQuoted(t)
                env.containsKey(t) -> env[t]!!
                else -> return null
            }
            out.append(value)
            if (out.length > 4096) return null
        }
        return out.toString()
    }

    private fun splitTopLevelPlus(expr: String): List<String> {
        val out = mutableListOf<String>()
        var start = 0
        var depth = 0
        var quote: Char? = null
        var escaped = false
        expr.forEachIndexed { i, c ->
            if (quote != null) {
                if (escaped) escaped = false
                else if (c == '\\') escaped = true
                else if (c == quote) quote = null
                return@forEachIndexed
            }
            when (c) {
                '\'', '"', '`' -> quote = c
                '(', '[', '{' -> depth++
                ')', ']', '}' -> depth = (depth - 1).coerceAtLeast(0)
                '+' -> if (depth == 0) { out += expr.substring(start, i); start = i + 1 }
            }
        }
        out += expr.substring(start)
        return out.map { it.trim() }.filter { it.isNotEmpty() }
    }

    private fun isQuoted(text: String): Boolean = text.length >= 2 &&
        ((text.first() == '\'' && text.last() == '\'') ||
            (text.first() == '"' && text.last() == '"') ||
            (text.first() == '`' && text.last() == '`'))

    private fun decodeQuoted(s: String): String {
        if (!isQuoted(s)) return s
        var body = s.substring(1, s.length - 1)
        body = Regex("""\\\\u([0-9a-fA-F]{4})""").replace(body) { it.groupValues[1].toInt(16).toChar().toString() }
        body = Regex("""\\\\x([0-9a-fA-F]{2})""").replace(body) { it.groupValues[1].toInt(16).toChar().toString() }
        return body
            .replace("\\\\/", "/")
            .replace("\\\\'", "'")
            .replace("\\\"", "\"")
            .replace("\\\\", "\\")
    }

    private fun topLevelFirstArg(text: String): String {
        var quote: Char? = null
        var escaped = false
        var depth = 0
        text.forEachIndexed { i, c ->
            if (quote != null) {
                if (escaped) escaped = false
                else if (c == '\\') escaped = true
                else if (c == quote) quote = null
                return@forEachIndexed
            }
            when (c) {
                '\'', '"', '`' -> quote = c
                '(', '[', '{' -> depth++
                ')', ']', '}' -> depth = (depth - 1).coerceAtLeast(0)
                ',' -> if (depth == 0) return text.substring(0, i)
            }
        }
        return text
    }

    private fun looksLikeApiPath(path: String): Boolean {
        if (path.length < 4) return false
        val lower = path.lowercase()
        if (listOf(".js", ".css", ".png", ".jpg", ".svg", ".ico", ".woff", ".gif", ".webp").any(lower::contains)) return false
        return lower.startsWith("/api") || lower.contains("/api/") ||
            listOf("login", "auth", "token", "user", "config", "v1/", "v2/", "graphql", "query", "sign", "verify").any(lower::contains)
    }

    private fun inferMethod(string: String, calls: List<CallExpressionInfo>): String {
        val lower = string.lowercase()
        return when {
            lower.contains("login") || lower.contains("register") || lower.contains("submit") || lower.contains("create") || lower.contains("add") -> "POST"
            lower.contains("delete") || lower.contains("remove") -> "DELETE"
            lower.contains("update") || lower.contains("edit") || lower.contains("save") -> "PUT"
            else -> calls.firstOrNull()?.let { inferMethodFromCallee(it.callee) } ?: "GET"
        }
    }

    private fun inferMethodFromCallee(callee: String): String = when {
        callee.contains("post", true) -> "POST"
        callee.contains("put", true) -> "PUT"
        callee.contains("delete", true) -> "DELETE"
        callee.contains("patch", true) -> "PATCH"
        else -> "GET"
    }

    private fun findCallerForString(source: String, target: String): String {
        val idx = source.indexOf(target)
        if (idx < 0) return ""
        val context = source.substring(maxOf(0, idx - 300), idx)
        val funcRegex = Regex("""(?:function\s+([A-Za-z_$][A-Za-z0-9_$]*)|([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?(?:function|\([^)]*\)\s*=>))""")
        val match = funcRegex.findAll(context).lastOrNull()
        return match?.groupValues?.drop(1)?.firstOrNull { it.isNotBlank() }.orEmpty()
    }
}
