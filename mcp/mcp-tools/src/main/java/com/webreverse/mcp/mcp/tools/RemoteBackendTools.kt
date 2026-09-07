package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.devtools.protocol.cdp.RemoteCdpEngine
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * 可插拔真 Chrome / CDP 后端工具（方向6 / ）。
 *
 * 把外部真实浏览器作为可插拔 CDP 后端接入，与本地 WebView 后端互斥切换：
 * `browser.attach_remote` 一次性完成「发现 → 选择 target → 附加 → Runtime 启用」，
 * 附加成功后可插拔后端的会话即成为当前调试链路；`detach_remote` 分离并切回本地。
 *
 * 价值：本 App 原生 WebView 受 ROM/内核限制时（部分系统禁止自连 abstract socket、
 * X5/深度定制内核无 DevTools socket），可经由外部 Chrome —— 或内网里一台
 * 已开启 `--remote-debugging-port` 的 Chromium（含 headless）——复用同一套
 * CDP 命令/事件链路做网络抓取、脚本 hook、内存取证、动态追踪。
 *
 * 工具均为只读/连接性质（不注入页面），风险 LOW；附加远端需 MEDIUM 权限
 * （会建立一条到任意 host:port 的调试连接）。
 */
object RemoteBackendTools {

    /** Map<String,String>（如后端描述）→ JsonObject，供 put 直接写入 */
    private fun strMap(o: Map<String, String>): JsonObject =
        buildJsonObject { o.forEach { (k, v) -> put(k, v) } }

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)
        return listOf(
            // ---------------- browser.attach_remote ----------------
            f.tool(
                "browser.attach_remote",
                "附加外部真实 Chrome/Chromium/CDP 后端（可插拔切换，与本地 WebView 互斥）：发现 host:port 的调试 target → 选中一个 → 连其 WebSocket 并启用 Runtime，附加成功后当前调试链路切到远端", ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                timeoutMs = 60_000,
                inputSchema = Schemas.objectSchema(
                    "host" to Schemas.strSchema("远端浏览器 CDP 主机（默认 127.0.0.1）"),
                    "port" to Schemas.intSchema("远端 CDP 端口（Chrome 需 --remote-debugging-port 暴露，默认 9222）"),
                    "targetFilter" to Schemas.strSchema("可选，URL/标题子串过滤目标（不区分大小写）"),
                    "action" to Schemas.strSchema("list=仅发现不附加(默认)，attach=发现并附加第一个匹配目标，detach=分离并切回本地，status=当前后端状态"),
                ),
            ) { args ->
                val action = ToolArgs.str(args, "action", "list")
                val host = ToolArgs.str(args, "host", "127.0.0.1")
                val port = ToolArgs.int(args, "port", 9222).coerceIn(1, 65535)
                val filter = ToolArgs.str(args, "targetFilter")
                when (action.lowercase()) {
                    "detach" -> {
                        RemoteCdpEngine.detach()
                        return@tool McpToolResult.json(
                            buildJsonObject {
                                put("ok", true)
                                put("action", "detach")
                                put("backend", "local")
                            },
                        )
                    }
                    "status" -> {
                        val active = RemoteCdpEngine.active
                        return@tool McpToolResult.json(
                            buildJsonObject {
                                put("ok", true)
                                put("action", "status")
                                put("attached", active != null)
                                put("healthy", RemoteCdpEngine.healthy())
                                put(
                                    "backend",
                                    if (active != null) strMap(active.describe())
                                    else buildJsonObject { put("backend", "local") },
                                )
                            },
                        )
                    }
                    "attach" -> {
                        val targets = RemoteCdpEngine.discover(host, port, filter)
                        if (targets.isEmpty()) {
                            return@tool McpToolResult.error(
                                "NO_TARGET",
                                RemoteCdpEngine.lastError ?: "远端 $host:$port 无匹配的调试 target（请确认以 --remote-debugging-port 启动）",
                            )
                        }
                        val page = targets.firstOrNull { it.type == "page" } ?: targets.first()
                        val probe = RemoteCdpEngine.probe(host, port)
                        val browser = probe["Browser"] ?: ""
                        val backend = RemoteCdpEngine.attach(host, port, page, browser)
                            ?: return@tool McpToolResult.error(
                                "ATTACH_FAILED",
                                RemoteCdpEngine.lastError ?: "远端附加失败",
                            )
                        // 附加成功后报告可执行性验证：对远端 target 求一次值，证明链路可用
                        return@tool McpToolResult.json(
                            buildJsonObject {
                                put("ok", true)
                                put("action", "attach")
                                put("backend", strMap(backend.describe()))
                                put("hint", "已切到远端后端：当前调试/网络/内存工具均作用于该 target")
                            },
                        )
                    }
                    else -> {
                        // default = list
                        val targets = RemoteCdpEngine.discover(host, port, filter)
                        val probe = RemoteCdpEngine.probe(host, port)
                        McpToolResult.json(
                            buildJsonObject {
                                put("ok", true)
                                put("action", "list")
                                put("host", host)
                                put("port", port)
                                put("count", targets.size)
                                put("browser", JsonPrimitive(probe["Browser"] ?: "未知/不可达"))
                                put(
                                    "targets",
                                    JsonArray(
                                        targets.map { t ->
                                            buildJsonObject {
                                                put("id", t.id)
                                                put("type", t.type)
                                                put("title", t.title)
                                                put("url", t.url)
                                            }
                                        },
                                    ),
                                )
                                if (RemoteCdpEngine.active != null) {
                                    put(
                                        "activeBackend",
                                        strMap(RemoteCdpEngine.active!!.describe()),
                                    )
                                }
                                put(
                                    "hint",
                                    if (targets.isEmpty()) "无 target：按 list → attach 循序接入；命令后再走 debugger/network 系列工具（作用于远端）"
                                    else "已发现 ${targets.size} 个 target，用 action=attach 附加其中任意一个即可把调试链路切到远端",
                                )
                            },
                        )
                    }
                }
            },
        )
    }
}