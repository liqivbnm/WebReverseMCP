package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import com.webreverse.mcp.core.common.util.Redactor
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** Storage Tools：Cookies / LocalStorage / SessionStorage / IndexedDB / Cache / ServiceWorker */
object StorageTools {

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)
        return listOf(
            f.tool(
                "storage.cookies", "读取页面 Cookie", ToolCategory.STORAGE,
                PermissionScope.READ_COOKIES, RiskLevel.HIGH,
            ) { _ ->
                val session = deps.activeSession()
                val result = deps.storageInspector.getCookies(session.engine)
                result.fold(
                    onSuccess = { cookies ->
                        McpToolResult.json(
                            buildJsonObject {
                                put(
                                    "cookies",
                                    JsonArray(
                                        cookies.map { c ->
                                            buildJsonObject {
                                                put("name", JsonPrimitive(c["name"] ?: ""))
                                                put("value", JsonPrimitive(Redactor.redactValue(c["name"] ?: "", c["value"] ?: "")))
                                                put("domain", JsonPrimitive(c["domain"] ?: ""))
                                                put("path", JsonPrimitive(c["path"] ?: "/"))
                                            }
                                        },
                                    ),
                                )
                            },
                        )
                    },
                    onFailure = { McpToolResult.error("STORAGE_READ_FAILED", it.message) },
                )
            },
            f.tool(
                "storage.local", "读取 LocalStorage", ToolCategory.STORAGE,
                PermissionScope.READ_STORAGE, RiskLevel.MEDIUM,
            ) { _ ->
                val session = deps.activeSession()
                val result = deps.storageInspector.getLocalStorage(session.engine)
                result.fold(
                    onSuccess = { data ->
                        McpToolResult.json(
                            buildJsonObject {
                                data.forEach { (k, v) -> put(k, JsonPrimitive(Redactor.redactValue(k, v))) }
                            },
                        )
                    },
                    onFailure = { McpToolResult.error("STORAGE_READ_FAILED", it.message) },
                )
            },
            f.tool(
                "storage.session", "读取 SessionStorage", ToolCategory.STORAGE,
                PermissionScope.READ_STORAGE, RiskLevel.MEDIUM,
            ) { _ ->
                val session = deps.activeSession()
                val result = deps.storageInspector.getSessionStorage(session.engine)
                result.fold(
                    onSuccess = { data ->
                        McpToolResult.json(
                            buildJsonObject {
                                data.forEach { (k, v) -> put(k, JsonPrimitive(Redactor.redactValue(k, v))) }
                            },
                        )
                    },
                    onFailure = { McpToolResult.error("STORAGE_READ_FAILED", it.message) },
                )
            },
            f.tool(
                "storage.set_local", "写入 LocalStorage", ToolCategory.STORAGE,
                PermissionScope.MODIFY_STORAGE, RiskLevel.HIGH,
                inputSchema = Schemas.objectSchema(
                    "key" to Schemas.strSchema("键"),
                    "value" to Schemas.strSchema("值"),
                ),
            ) { args ->
                val key = ToolArgs.str(args, "key")
                val value = ToolArgs.str(args, "value")
                val session = deps.activeSession()
                val result = deps.storageInspector.setLocalStorage(session.engine, key, value)
                result.fold(
                    onSuccess = { McpToolResult.text("已写入 localStorage.$key") },
                    onFailure = { McpToolResult.error("STORAGE_WRITE_FAILED", it.message) },
                )
            },
            f.tool(
                "storage.delete_local", "删除 LocalStorage 项", ToolCategory.STORAGE,
                PermissionScope.MODIFY_STORAGE, RiskLevel.HIGH,
                inputSchema = Schemas.objectSchema("key" to Schemas.strSchema("键")),
            ) { args ->
                val key = ToolArgs.str(args, "key")
                val session = deps.activeSession()
                val result = deps.storageInspector.deleteLocalStorage(session.engine, key)
                result.fold(
                    onSuccess = { McpToolResult.text("已删除 localStorage.$key") },
                    onFailure = { McpToolResult.error("STORAGE_WRITE_FAILED", it.message) },
                )
            },
            f.tool(
                "storage.indexeddb", "列出 IndexedDB 数据库", ToolCategory.STORAGE,
                PermissionScope.READ_STORAGE, RiskLevel.MEDIUM,
            ) { _ ->
                val session = deps.activeSession()
                val result = deps.storageInspector.getIndexedDB(session.engine)
                result.fold(
                    onSuccess = { dbs ->
                        McpToolResult.json(
                            buildJsonObject {
                                put(
                                    "databases",
                                    JsonArray(
                                        dbs.map { db ->
                                            buildJsonObject {
                                                put("name", JsonPrimitive(db["name"]?.toString() ?: ""))
                                                put("version", JsonPrimitive(db["version"]?.toString() ?: ""))
                                                put("stores", JsonPrimitive(db["stores"]?.toString() ?: "[]"))
                                            }
                                        },
                                    ),
                                )
                            },
                        )
                    },
                    onFailure = { McpToolResult.error("STORAGE_READ_FAILED", it.message) },
                )
            },
            f.tool(
                "storage.cache", "列出 Cache Storage", ToolCategory.STORAGE,
                PermissionScope.READ_STORAGE, RiskLevel.MEDIUM,
            ) { _ ->
                val session = deps.activeSession()
                val result = deps.storageInspector.getCacheStorage(session.engine)
                result.fold(
                    onSuccess = { caches ->
                        McpToolResult.json(
                            buildJsonObject {
                                put(
                                    "caches",
                                    JsonArray(
                                        caches.map { c ->
                                            buildJsonObject {
                                                put("name", JsonPrimitive(c["name"] ?: ""))
                                                put("count", JsonPrimitive(c["count"] ?: "0"))
                                                put("urls", JsonPrimitive(c["urls"] ?: "[]"))
                                            }
                                        },
                                    ),
                                )
                            },
                        )
                    },
                    onFailure = { McpToolResult.error("STORAGE_READ_FAILED", it.message) },
                )
            },
            f.tool(
                "storage.service_workers", "列出 Service Workers", ToolCategory.STORAGE,
                PermissionScope.READ_STORAGE, RiskLevel.MEDIUM,
            ) { _ ->
                val session = deps.activeSession()
                val result = deps.storageInspector.getServiceWorkers(session.engine)
                result.fold(
                    onSuccess = { workers ->
                        McpToolResult.json(
                            buildJsonObject {
                                put(
                                    "serviceWorkers",
                                    JsonArray(
                                        workers.map { w ->
                                            buildJsonObject {
                                                put("scope", JsonPrimitive(w["scope"] ?: ""))
                                                put("active", JsonPrimitive(w["active"] ?: ""))
                                                put("installing", JsonPrimitive(w["installing"] ?: ""))
                                                put("waiting", JsonPrimitive(w["waiting"] ?: ""))
                                            }
                                        },
                                    ),
                                )
                            },
                        )
                    },
                    onFailure = { McpToolResult.error("STORAGE_READ_FAILED", it.message) },
                )
            },
            f.tool(
                "storage.search", "跨存储搜索", ToolCategory.STORAGE,
                PermissionScope.READ_STORAGE, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema("query" to Schemas.strSchema("搜索关键词")),
            ) { args ->
                val query = ToolArgs.str(args, "query")
                val session = deps.activeSession()
                val result = deps.storageInspector.searchStorage(session.engine, query)
                result.fold(
                    onSuccess = { data ->
                        McpToolResult.json(
                            buildJsonObject {
                                put("localStorage", JsonPrimitive(Redactor.redactText(data["localStorage"].toString())))
                                put("sessionStorage", JsonPrimitive(Redactor.redactText(data["sessionStorage"].toString())))
                                put("cookies", JsonPrimitive(Redactor.redactText(data["cookies"].toString())))
                            },
                        )
                    },
                    onFailure = { McpToolResult.error("STORAGE_READ_FAILED", it.message) },
                )
            },
            f.tool(
                "storage.clear", "清空存储", ToolCategory.STORAGE,
                PermissionScope.MODIFY_STORAGE, RiskLevel.HIGH,
                inputSchema = Schemas.objectSchema(
                    "local" to Schemas.boolSchema("清空 LocalStorage"),
                    "session" to Schemas.boolSchema("清空 SessionStorage"),
                    "cache" to Schemas.boolSchema("清空 Cache"),
                    "cookies" to Schemas.boolSchema("清空 Cookie"),
                ),
            ) { args ->
                val session = deps.activeSession()
                if (ToolArgs.bool(args, "local")) session.engine.clearLocalStorage()
                if (ToolArgs.bool(args, "session")) session.engine.clearSessionStorage()
                if (ToolArgs.bool(args, "cache")) session.engine.clearCache()
                if (ToolArgs.bool(args, "cookies")) session.engine.clearCookies()
                McpToolResult.text("存储已清空")
            },
            f.tool(
                "storage.export", "导出全部存储", ToolCategory.STORAGE,
                PermissionScope.READ_STORAGE, RiskLevel.HIGH,
            ) { _ ->
                val session = deps.activeSession()
                val cookies = deps.storageInspector.getCookies(session.engine).getOrNull() ?: emptyList()
                val local = deps.storageInspector.getLocalStorage(session.engine).getOrNull() ?: emptyMap()
                val sessionStorage = deps.storageInspector.getSessionStorage(session.engine).getOrNull() ?: emptyMap()
                McpToolResult.json(
                    buildJsonObject {
                        put("cookies", JsonPrimitive(Redactor.redactText(cookies.toString())))
                        put("localStorage", JsonPrimitive(Redactor.redactText(local.toString())))
                        put("sessionStorage", JsonPrimitive(Redactor.redactText(sessionStorage.toString())))
                    },
                )
            },
        )
    }
}
