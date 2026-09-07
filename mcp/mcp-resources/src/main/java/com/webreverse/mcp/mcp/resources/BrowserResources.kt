package com.webreverse.mcp.mcp.resources

import com.webreverse.mcp.browser.engine.BrowserService
import com.webreverse.mcp.core.common.util.Redactor
import com.webreverse.mcp.core.mcp.McpResource
import com.webreverse.mcp.core.mcp.McpResourceContent
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Browser Resources：向 AI Agent 暴露浏览器内部状态。
 * 所有资源默认脱敏，禁止把 Cookie/Token/Authorization 等敏感数据直接发送。
 */
class BrowserResources(private val browserService: BrowserService) {

    fun all(): List<McpResource> = listOf(
        currentPage(),
        dom(),
        console(),
        network(),
        cookies(),
        localStorage(),
        sources(),
        tabs(),
        debugger(),
        performance(),
        hooks(),
        workspace(),
    )

    private fun currentPage(): McpResource = resource(
        "browser://current-page",
        "当前页面",
        "当前活动标签页的 URL、标题、加载状态与页面摘要",
        "application/json",
    ) {
        val session = browserService.getOrCreateActiveSession()
        val engine = session.engine
        McpResourceContent(
            uri = "browser://current-page",
            mimeType = "application/json",
            structured = buildJsonObject {
                put("url", JsonPrimitive(engine.currentUrl() ?: ""))
                put("title", JsonPrimitive(engine.currentTitle() ?: ""))
                put("canGoBack", JsonPrimitive(engine.canGoBack()))
                put("canGoForward", JsonPrimitive(engine.canGoForward()))
                put("state", JsonPrimitive(engine.state.value.toString()))
                put("tabId", JsonPrimitive(session.tabId))
            },
        )
    }

    private fun dom(): McpResource = resource(
        "browser://dom",
        "DOM 结构",
        "当前页面的 DOM 树（HTML 源码）",
        "text/html",
    ) {
        val session = browserService.getOrCreateActiveSession()
        McpResourceContent(uri = "browser://dom", mimeType = "text/html", text = session.engine.getPageSource())
    }

    private fun console(): McpResource = resource(
        "browser://console",
        "控制台日志",
        "当前页面的 Console 消息列表",
        "application/json",
    ) {
        val session = browserService.getOrCreateActiveSession()
        McpResourceContent(
            uri = "browser://console",
            mimeType = "application/json",
            structured = buildJsonObject {
                put("messages", JsonArray(session.consoleMessages.value.map { JsonPrimitive(it) }))
            },
        )
    }

    private fun network(): McpResource = resource(
        "browser://network",
        "网络请求",
        "当前页面的网络请求列表（脱敏）",
        "application/json",
    ) {
        val session = browserService.getOrCreateActiveSession()
        val entries = session.engine.getNetworkEntries()
        McpResourceContent(
            uri = "browser://network",
            mimeType = "application/json",
            structured = buildJsonObject {
                put(
                    "entries",
                    JsonArray(
                        entries.map { e ->
                            buildJsonObject {
                                put("id", JsonPrimitive(e.id))
                                put("url", JsonPrimitive(Redactor.redactUrl(e.url)))
                                put("method", JsonPrimitive(e.method.wire))
                                put("status", JsonPrimitive(e.status))
                                put("resourceType", JsonPrimitive(e.resourceType.display))
                                put("total", JsonPrimitive(e.timing.total))
                                put("requestBody", JsonPrimitive(Redactor.redactText(e.requestBody ?: "")))
                                put("responseBody", JsonPrimitive(Redactor.redactText(e.responseBody ?: "")))
                            }
                        },
                    ),
                )
            },
        )
    }

    private fun cookies(): McpResource = resource(
        "browser://cookies",
        "Cookies",
        "当前页面的 Cookie 列表（值已脱敏）",
        "application/json",
    ) {
        val session = browserService.getOrCreateActiveSession()
        val cookies = session.engine.getCookies()
        McpResourceContent(
            uri = "browser://cookies",
            mimeType = "application/json",
            structured = buildJsonObject {
                put(
                    "cookies",
                    JsonArray(
                        cookies.map { c ->
                            buildJsonObject {
                                put("name", JsonPrimitive(c["name"] ?: ""))
                                put("value", JsonPrimitive("[REDACTED_COOKIE]"))
                                put("domain", JsonPrimitive(c["domain"] ?: ""))
                                put("path", JsonPrimitive(c["path"] ?: "/"))
                            }
                        },
                    ),
                )
            },
        )
    }

    private fun localStorage(): McpResource = resource(
        "browser://local-storage",
        "LocalStorage",
        "当前页面的 LocalStorage 键值（值已脱敏）",
        "application/json",
    ) {
        val session = browserService.getOrCreateActiveSession()
        val storage = session.engine.getLocalStorage()
        McpResourceContent(
            uri = "browser://local-storage",
            mimeType = "application/json",
            structured = buildJsonObject {
                put(
                    "localStorage",
                    buildJsonObject {
                        storage.forEach { (k, v) ->
                            put(k, JsonPrimitive(if (Redactor.isSensitiveKey(k)) "[REDACTED]" else v))
                        }
                    },
                )
            },
        )
    }

    private fun sources(): McpResource = resource(
        "browser://sources",
        "页面源码",
        "当前页面的 HTML 源码与脚本列表",
        "application/json",
    ) {
        val session = browserService.getOrCreateActiveSession()
        val source = session.engine.getPageSource() ?: ""
        McpResourceContent(
            uri = "browser://sources",
            mimeType = "application/json",
            structured = buildJsonObject {
                put("html", JsonPrimitive(source.take(200_000)))
                put("size", JsonPrimitive(source.length))
            },
        )
    }

    private fun tabs(): McpResource = resource(
        "browser://tabs",
        "标签页列表",
        "所有打开的标签页及其状态",
        "application/json",
    ) {
        McpResourceContent(
            uri = "browser://tabs",
            mimeType = "application/json",
            structured = buildJsonObject {
                put(
                    "tabs",
                    JsonArray(
                        browserService.tabs.value.map { t ->
                            buildJsonObject {
                                put("id", JsonPrimitive(t.id))
                                put("url", JsonPrimitive(Redactor.redactUrl(t.url)))
                                put("title", JsonPrimitive(t.title))
                                put("active", JsonPrimitive(t.id == browserService.activeTabId.value))
                            }
                        },
                    ),
                )
            },
        )
    }

    private fun debugger(): McpResource = resource(
        "browser://debugger",
        "调试器状态",
        "当前断点、Watch 表达式与调试状态",
        "application/json",
    ) {
        McpResourceContent(
            uri = "browser://debugger",
            mimeType = "application/json",
            structured = buildJsonObject {
                put("status", JsonPrimitive("idle"))
                put("breakpoints", JsonArray(emptyList()))
                put("watchExpressions", JsonArray(emptyList()))
            },
        )
    }

    private fun performance(): McpResource = resource(
        "browser://performance",
        "性能数据",
        "当前页面的性能指标（Navigation/Resource Timing）",
        "application/json",
    ) {
        McpResourceContent(
            uri = "browser://performance",
            mimeType = "application/json",
            structured = buildJsonObject {
                put("navigationTiming", JsonObject(emptyMap()))
                put("resourceTiming", JsonArray(emptyList()))
                put("longTasks", JsonArray(emptyList()))
            },
        )
    }

    private fun hooks(): McpResource = resource(
        "browser://hooks",
        "Hook 列表",
        "当前安装的 Runtime Hook 与 Network Hook 规则",
        "application/json",
    ) {
        McpResourceContent(
            uri = "browser://hooks",
            mimeType = "application/json",
            structured = buildJsonObject {
                put("runtimeHooks", JsonArray(emptyList()))
                put("networkHooks", JsonArray(emptyList()))
            },
        )
    }

    private fun workspace(): McpResource = resource(
        "browser://workspace",
        "工作区",
        "当前 Workspace 的目标、发现与笔记概览",
        "application/json",
    ) {
        McpResourceContent(
            uri = "browser://workspace",
            mimeType = "application/json",
            structured = buildJsonObject {
                put("targets", JsonArray(emptyList()))
                put("findings", JsonArray(emptyList()))
                put("notes", JsonArray(emptyList()))
            },
        )
    }

    private fun resource(
        uri: String,
        name: String,
        description: String,
        mimeType: String,
        block: suspend () -> McpResourceContent,
    ): McpResource = object : McpResource {
        override val uri = uri
        override val name = name
        override val description = description
        override val mimeType = mimeType

        override suspend fun read(arguments: Map<String, String>): McpResourceContent = try {
            block()
        } catch (e: Exception) {
            McpResourceContent(
                uri = uri,
                mimeType = "application/json",
                structured = buildJsonObject {
                    put("error", JsonPrimitive(e.message ?: "resource read failed"))
                },
            )
        }
    }
}
