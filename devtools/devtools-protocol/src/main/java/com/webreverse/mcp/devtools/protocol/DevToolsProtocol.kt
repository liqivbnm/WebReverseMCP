package com.webreverse.mcp.devtools.protocol

import kotlinx.serialization.Serializable

/** DevTools 协议类型（CDP 风格子集） */

@Serializable
data class DomNode(
    val nodeId: Int = 0,
    val parentId: Int? = null,
    val nodeType: Int = 1,
    val nodeName: String = "",
    val localName: String = "",
    val nodeValue: String = "",
    val attributes: Map<String, String> = emptyMap(),
    val children: List<DomNode> = emptyList(),
    val childNodeCount: Int = 0,
    val shadowRoots: List<DomNode> = emptyList(),
    val frameId: String? = null,
    val backendNodeId: Int = 0,
    val isClickable: Boolean = false,
    val xpath: String = "",
    val selector: String = "",
)

@Serializable
data class CssRule(
    val selectorText: String,
    val style: Map<String, String> = emptyMap(),
    val origin: String = "regular",
    val styleSheetId: String? = null,
    val sourceUrl: String? = null,
    val lineNumber: Int = 0,
)

@Serializable
data class ComputedStyle(
    val properties: Map<String, String> = emptyMap(),
)

@Serializable
data class BoxModel(
    val content: List<Int> = emptyList(),
    val padding: List<Int> = emptyList(),
    val border: List<Int> = emptyList(),
    val margin: List<Int> = emptyList(),
    val width: Int = 0,
    val height: Int = 0,
)

@Serializable
data class AccessibilityNode(
    val nodeId: Int = 0,
    val role: String = "",
    val name: String = "",
    val value: String = "",
    val description: String = "",
    val properties: Map<String, String> = emptyMap(),
    val children: List<AccessibilityNode> = emptyList(),
)

@Serializable
data class EventListenerInfo(
    val type: String,
    val handler: String = "",
    val location: String = "",
    val useCapture: Boolean = false,
)

@Serializable
data class ScriptInfo(
    val scriptId: String,
    val url: String,
    val startLine: Int,
    val startColumn: Int,
    val endLine: Int,
    val endColumn: Int,
    val isModule: Boolean = false,
    val sourceMapUrl: String? = null,
    val hasSourceURL: Boolean = false,
    val isLiveEdit: Boolean = false,
)

@Serializable
data class FrameInfo(
    val frameId: String,
    val parentId: String? = null,
    val url: String,
    val name: String = "",
    val securityOrigin: String = "",
    val isMainFrame: Boolean = false,
    val isCrossOrigin: Boolean = false,
)

@Serializable
data class WorkerInfo(
    val workerId: String,
    val url: String,
    val type: String = "dedicated",
    val isServiceWorker: Boolean = false,
    val isSharedWorker: Boolean = false,
)

@Serializable
data class PerformanceTiming(
    val navigationStart: Long = 0,
    val domContentLoaded: Long = 0,
    val loadEvent: Long = 0,
    val firstPaint: Long = 0,
    val firstContentfulPaint: Long = 0,
    val domInteractive: Long = 0,
    val domComplete: Long = 0,
    val redirectCount: Int = 0,
    val transferSize: Long = 0,
    val resources: List<ResourceTiming> = emptyList(),
)

@Serializable
data class ResourceTiming(
    val name: String,
    val initiatorType: String,
    val duration: Long,
    val transferSize: Long,
    val startTime: Long,
)

@Serializable
data class MemoryInfo(
    val usedJSHeapSize: Long = 0,
    val totalJSHeapSize: Long = 0,
    val jsHeapSizeLimit: Long = 0,
)
