package com.webreverse.mcp.core.common.model

import kotlinx.serialization.Serializable

/** 分析结果类型 */
@Serializable
enum class FindingType(val display: String) {
    INTERESTING("Interesting"), WARNING("Warning"), SECURITY("Security"),
    API("API"), FUNCTION("Function"), OBFUSCATION("Obfuscation"),
    ANTI_DEBUG("AntiDebug"), CRYPTO("Crypto"), STORAGE("Storage"),
    NETWORK("Network"), FRAMEWORK("Framework"), PERFORMANCE("Performance")
}

/** 严重程度 */
@Serializable
enum class Severity(val display: String) {
    INFO("Info"), LOW("Low"), MEDIUM("Medium"), HIGH("High"), CRITICAL("Critical")
}

/** 置信度 */
@Serializable
enum class Confidence(val display: String) {
    LOW("Low"), MEDIUM("Medium"), HIGH("High"), CONFIRMED("Confirmed")
}

/** 分析发现（Finding） */
@Serializable
data class Finding(
    val id: String,
    val workspaceId: String? = null,
    val type: FindingType,
    val title: String,
    val description: String = "",
    val evidence: String = "",
    val source: String = "",
    val line: Int = 0,
    val confidence: Confidence = Confidence.MEDIUM,
    val severity: Severity = Severity.INFO,
    val relatedTool: String? = null,
    val relatedRequest: String? = null,
    val relatedFunction: String? = null,
    val createdAt: Long = System.currentTimeMillis(),
    val data: Map<String, String> = emptyMap(),
)

/** 结构化 AI 分析结果 */
@Serializable
data class AnalysisResult(
    val id: String,
    val workspaceId: String? = null,
    val type: String,
    val title: String,
    val summary: String = "",
    val content: String = "",
    val confidence: Double = 0.0,
    val findings: List<Finding> = emptyList(),
    val relatedUrls: List<String> = emptyList(),
    val createdAt: Long = System.currentTimeMillis(),
    val data: Map<String, String> = emptyMap(),
)

/** API 清单条目 */
@Serializable
data class ApiEndpoint(
    val method: String,
    val url: String,
    val source: String = "",
    val line: Int = 0,
    val caller: String = "",
    val callStack: String = "",
    val requestBody: String = "",
    val responseBody: String = "",
    val auth: String = "",
    val confidence: Double = 0.0,
    val relatedFunction: String = "",
)

/** 环境信息 */
@Serializable
data class EnvironmentInfo(
    val userAgent: String = "",
    val platform: String = "",
    val language: String = "",
    val timezone: String = "",
    val screen: String = "",
    val viewport: String = "",
    val devicePixelRatio: Double = 0.0,
    val touchSupport: Boolean = false,
    val cpuCores: Int = 0,
    val deviceMemory: Double = 0.0,
    val connection: String = "",
    val battery: String = "",
    val webgl: Boolean = false,
    val canvas: Boolean = false,
    val audio: Boolean = false,
    val fonts: List<String> = emptyList(),
    val permissions: Map<String, String> = emptyMap(),
    val serviceWorker: Boolean = false,
    val webAssembly: Boolean = false,
    val webRTC: Boolean = false,
    val cookiesEnabled: Boolean = false,
    val indexedDB: Boolean = false,
    val localStorage: Boolean = false,
    val sessionStorage: Boolean = false,
    val raw: Map<String, String> = emptyMap(),
)
