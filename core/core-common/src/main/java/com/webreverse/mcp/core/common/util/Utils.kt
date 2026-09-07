package com.webreverse.mcp.core.common.util

import android.content.Context
import java.security.SecureRandom
import java.util.UUID

/** ID 生成器 */
object Ids {
    private val random = SecureRandom()

    fun uuid(): String = UUID.randomUUID().toString()

    fun short(): String {
        val chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        return buildString(12) {
            repeat(12) { append(chars[random.nextInt(chars.length)]) }
        }
    }

    fun token(length: Int = 32): String {
        val chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        return buildString(length) {
            repeat(length) { append(chars[random.nextInt(chars.length)]) }
        }
    }

    fun numeric(length: Int = 6): String {
        val chars = "0123456789"
        return buildString(length) {
            repeat(length) { append(chars[random.nextInt(chars.length)]) }
        }
    }
}

/** 时间工具 */
object Time {
    fun now(): Long = System.currentTimeMillis()

    fun formatDuration(ms: Long): String = when {
        ms < 1_000 -> "${ms}ms"
        ms < 60_000 -> String.format("%.2fs", ms / 1000.0)
        else -> String.format("%dm %ds", ms / 60_000, (ms % 60_000) / 1000)
    }

    fun formatBytes(bytes: Long): String = when {
        bytes < 1024 -> "$bytes B"
        bytes < 1024 * 1024 -> String.format("%.1f KB", bytes / 1024.0)
        bytes < 1024 * 1024 * 1024 -> String.format("%.1f MB", bytes / (1024.0 * 1024))
        else -> String.format("%.2f GB", bytes / (1024.0 * 1024 * 1024))
    }
}

/**
 * 敏感数据脱敏器。
 * 开关默认关闭：工具输出原始数据，不做脱敏；
 * 用户可在「权限管理」或「设置」页面手动开启，开启后
 * Cookie / Token / Authorization / API Key / 密码等字段输出为 [REDACTED]。
 */
object Redactor {

    /** 脱敏总开关：false = 输出原始数据（默认），true = 输出脱敏数据 */
    @Volatile
    var enabled: Boolean = false
        private set

    private const val PREFS_NAME = "webreverse_prefs"
    private const val KEY_ENABLED = "redaction_enabled"

    /** 初始化：读取持久化的开关状态（应用启动时调用一次） */
    fun init(context: Context) {
        enabled = context.applicationContext
            .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getBoolean(KEY_ENABLED, false)
    }

    /** 设置开关并持久化 */
    fun setEnabled(context: Context, value: Boolean) {
        enabled = value
        context.applicationContext
            .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(KEY_ENABLED, value)
            .apply()
    }

    private val sensitiveKeys = listOf(
        "password", "passwd", "pwd", "token", "access_token", "refresh_token",
        "authorization", "auth", "secret", "api_key", "apikey", "apisecret",
        "cookie", "set-cookie", "credit_card", "card_number", "cvv", "cvc",
        "ssn", "id_card", "bank_account", "private_key", "session", "sessionid",
        "jwt", "bearer", "x-api-key", "client_secret", "pin", "otp", "2fa",
    )

    private val sensitiveValues = listOf(
        "password", "passwd", "secret", "token", "authorization", "api key", "apikey",
    )

    private val redactionPatterns = listOf(
        Regex("""(?i)(password|passwd|pwd|token|secret|api[_-]?key|authorization|bearer)\s*[:=]\s*["']?[^"'\s,;&]+"""),
        Regex("""(?i)set-cookie:\s*[^;\r\n]+"""),
        Regex("""(?i)cookie:\s*[^;\r\n]+"""),
    )

    fun isSensitiveKey(key: String): Boolean {
        val normalized = key.lowercase().replace("_", "").replace("-", "").replace(" ", "")
        return sensitiveKeys.any { normalized.contains(it.replace("_", "").replace("-", "")) }
    }

    fun redactKey(key: String): String =
        if (!enabled) key
        else if (isSensitiveKey(key)) "[REDACTED_${key.uppercase()}]" else key

    fun redactValue(key: String, value: String): String =
        if (!enabled) value
        else if (isSensitiveKey(key)) "[REDACTED]" else value

    /** 脱敏整个请求/响应文本 */
    fun redactText(text: String): String {
        if (!enabled) return text
        var result = text
        for (pattern in redactionPatterns) {
            result = pattern.replace(result) { match ->
                val raw = match.value
                val separator = raw.indexOfFirst { it == ':' || it == '=' }
                if (separator > 0) {
                    val key = raw.substring(0, separator)
                    val value = raw.substring(separator)
                    if (isSensitiveKey(key)) {
                        key + value.firstOrNull()?.toString().orEmpty() + "[REDACTED]"
                    } else {
                        raw
                    }
                } else {
                    raw
                }
            }
        }
        return result
    }

    /** 脱敏 headers */
    fun redactHeaders(headers: Map<String, String>): Map<String, String> {
        if (!enabled) return headers
        return headers.mapKeys { (k, _) -> redactKey(k) }
            .mapValues { (k, v) -> if (k.startsWith("[REDACTED_")) "[REDACTED]" else v }
    }

    /** 脱敏 URL 中的 query 参数 */
    fun redactUrl(url: String): String {
        if (!enabled) return url
        return try {
            val uri = android.net.Uri.parse(url)
            val builder = uri.buildUpon()
            builder.clearQuery()
            uri.queryParameterNames.forEach { name ->
                val value = uri.getQueryParameter(name) ?: ""
                val safeValue = if (isSensitiveKey(name)) "[REDACTED]" else value
                builder.appendQueryParameter(name, safeValue)
            }
            builder.build().toString()
        } catch (e: Exception) {
            url
        }
    }
}
