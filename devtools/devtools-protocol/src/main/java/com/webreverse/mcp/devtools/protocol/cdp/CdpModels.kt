package com.webreverse.mcp.devtools.protocol.cdp

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

/**
 * Chrome DevTools Protocol 基础模型。
 *
 * 本模块提供真实 CDP 接入能力：
 * WebView.setWebContentsDebuggingEnabled(true) 后，Chromium 会在进程内创建
 * abstract unix socket `webview_devtools_remote_<pid>`，通过该 socket 可完成
 * HTTP /json/list 发现页面，再升级为 WebSocket 会话，收发 CDP JSON-RPC 消息。
 * 这是真实 V8 Debugger 能力（而非 evaluateJavascript 模拟）的传输基础。
 */

/**
 * CDP 事件（method + params + 来源子会话）。
 *
 * flatten 模式下 Worker/ServiceWorker/iframe 子会话的事件在消息根级
 * 携带 sessionId；[sessionId] 为 null 表示根会话（Page target 本体）事件。
 */
data class CdpEvent(
    val method: String,
    val params: JsonObject,
    val sessionId: String? = null,
)

/** CDP 会话异常 */
class CdpException(message: String) : Exception(message)

/** DevTools /json/list 返回的页面描述符 */
@Serializable
data class DevToolsPageInfo(
    val id: String = "",
    val type: String = "page",
    val title: String = "",
    val url: String = "",
    val webSocketDebuggerUrl: String = "",
    val description: String = "",
    val faviconUrl: String = "",
    val devtoolsFrontendUrl: String = "",
)

/** 已解析脚本（Debugger.scriptParsed） */
@Serializable
data class CdpScript(
    val scriptId: String,
    val url: String,
    val startLine: Int = 0,
    val endLine: Int = 0,
    val sourceMapUrl: String? = null,
    val hasSourceURL: Boolean = false,
    val length: Long = 0,
)

/**
 * CDP Target（报告 §三/§四 Target domain）。
 *
 * 描述一个 Chromium 执行目标：Page / iframe / Worker / SharedWorker /
 * ServiceWorker / DedicatedWorker 等。由 CdpTargetManager 通过
 * Target.setDiscoverTargets + Target.setAutoAttach(flatten=true) 维护。
 */
@Serializable
data class CdpTargetInfo(
    val targetId: String,
    val type: String,
    val title: String = "",
    val url: String = "",
    val attached: Boolean = false,
    /** flatten 模式下 attach 后分配的子会话 id（发命令时路由用） */
    val sessionId: String? = null,
    /** 目标是否可直接执行 Runtime.evaluate（worker/service_worker 可以，iframe 走页面会话） */
    val canDebug: Boolean = false,
    val browserContextId: String? = null,
    val openerId: String? = null,
    val subtype: String? = null,
)
