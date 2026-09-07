package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.common.util.WorkDir
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Reverse Engineering Tools：API 发现、Token 分析、登录流程、函数追踪、报告生成 */
object ReverseEngineeringTools {

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)
        return listOf(
            f.tool(
                "re.search", "在页面源码中搜索关键词", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("query" to Schemas.strSchema("搜索关键词")),
            ) { args ->
                val query = ToolArgs.str(args, "query")
                val session = deps.activeSession()
                val source = session.engine.getPageSource() ?: ""
                val matches = deps.jsParser.detectPatterns(source, listOf(query))
                val occurrences = matches.firstOrNull()?.matches ?: emptyList()
                McpToolResult.json(
                    buildJsonObject {
                        put("count", JsonPrimitive(occurrences.size))
                        put(
                            "matches",
                            JsonArray(
                                occurrences.take(100).map { m ->
                                    buildJsonObject {
                                        put("line", JsonPrimitive(m.line))
                                        put("context", JsonPrimitive(m.context.take(300)))
                                    }
                                },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "re.find_api", "发现页面所有 API 端点", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val source = session.engine.getPageSource() ?: ""
                val fromHtml = deps.apiDiscoveryEngine.discoverFromHtml(source)
                val fromJs = deps.apiDiscoveryEngine.discoverFromJs(source, "html")
                val fromNetwork = deps.apiDiscoveryEngine.discoverFromNetwork(session.engine.getNetworkEntries())
                val merged = deps.apiDiscoveryEngine.merge(fromHtml, fromJs, fromNetwork)
                McpToolResult.json(
                    buildJsonObject {
                        put(
                            "endpoints",
                            JsonArray(
                                merged.endpoints.map { e ->
                                    buildJsonObject {
                                        put("method", JsonPrimitive(e.method))
                                        put("url", JsonPrimitive(e.url))
                                        put("source", JsonPrimitive(e.source))
                                        put("caller", JsonPrimitive(e.caller))
                                        put("line", JsonPrimitive(e.line))
                                        put("confidence", JsonPrimitive(e.confidence))
                                    }
                                },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "re.find_fetch", "查找页面中的 fetch 调用", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val source = session.engine.getPageSource() ?: ""
                val calls = deps.jsParser.extractCallExpressions(source)
                    .filter { it.callee.contains("fetch", ignoreCase = true) }
                McpToolResult.json(
                    buildJsonObject {
                        put(
                            "fetchCalls",
                            JsonArray(
                                calls.take(200).map { c ->
                                    buildJsonObject {
                                        put("callee", JsonPrimitive(c.callee))
                                        put("args", JsonPrimitive(c.arguments.joinToString(", ").take(300)))
                                        put("line", JsonPrimitive(c.line))
                                    }
                                },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "re.find_xhr", "查找页面中的 XHR 调用", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val source = session.engine.getPageSource() ?: ""
                val calls = deps.jsParser.extractCallExpressions(source)
                    .filter { it.callee.contains("XMLHttpRequest", ignoreCase = true) || it.callee.contains("xhr", ignoreCase = true) }
                McpToolResult.json(
                    buildJsonObject {
                        put(
                            "xhrCalls",
                            JsonArray(
                                calls.take(200).map { c ->
                                    buildJsonObject {
                                        put("callee", JsonPrimitive(c.callee))
                                        put("line", JsonPrimitive(c.line))
                                    }
                                },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "re.find_websocket", "查找页面中的 WebSocket 调用", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val source = session.engine.getPageSource() ?: ""
                val urls = deps.jsParser.extractUrls(source).filter { it.startsWith("ws") }
                val calls = deps.jsParser.extractCallExpressions(source)
                    .filter { it.callee.contains("WebSocket", ignoreCase = true) }
                McpToolResult.json(
                    buildJsonObject {
                        put("urls", JsonArray(urls.map { JsonPrimitive(it) }))
                        put(
                            "calls",
                            JsonArray(
                                calls.map { c ->
                                    buildJsonObject {
                                        put("callee", JsonPrimitive(c.callee))
                                        put("line", JsonPrimitive(c.line))
                                    }
                                },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "re.find_crypto", "查找页面中的 Crypto 相关代码", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val source = session.engine.getPageSource() ?: ""
                val patterns = deps.jsParser.detectPatterns(
                    source,
                    listOf(
                        "crypto.subtle", "CryptoJS", "AES", "SHA256", "MD5", "RSA",
                        "encrypt", "decrypt", "sign", "hmac", "pbkdf2", "btoa", "atob",
                    ),
                )
                McpToolResult.json(
                    buildJsonObject {
                        put(
                            "patterns",
                            JsonArray(
                                patterns.map { p ->
                                    buildJsonObject {
                                        put("pattern", JsonPrimitive(p.pattern))
                                        put("count", JsonPrimitive(p.matches.size))
                                        put(
                                            "occurrences",
                                            JsonArray(
                                                p.matches.take(20).map { m ->
                                                    buildJsonObject {
                                                        put("line", JsonPrimitive(m.line))
                                                        put("context", JsonPrimitive(m.context.take(200)))
                                                    }
                                                },
                                            ),
                                        )
                                    }
                                },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "re.find_token", "查找页面中 Token 生成/存储相关代码", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val source = session.engine.getPageSource() ?: ""
                val patterns = deps.jsParser.detectPatterns(
                    source,
                    listOf("token", "access_token", "refresh_token", "jwt", "session", "authorization", "Bearer"),
                )
                McpToolResult.json(
                    buildJsonObject {
                        put(
                            "patterns",
                            JsonArray(
                                patterns.map { p ->
                                    buildJsonObject {
                                        put("pattern", JsonPrimitive(p.pattern))
                                        put("count", JsonPrimitive(p.matches.size))
                                        put(
                                            "occurrences",
                                            JsonArray(
                                                p.matches.take(50).map { m ->
                                                    buildJsonObject {
                                                        put("line", JsonPrimitive(m.line))
                                                        put("context", JsonPrimitive(m.context.take(200)))
                                                    }
                                                },
                                            ),
                                        )
                                    }
                                },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "re.find_auth_flow", "分析页面认证流程", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val source = session.engine.getPageSource() ?: ""
                val authPatterns = deps.jsParser.detectPatterns(
                    source,
                    listOf("login", "signin", "sign-in", "authenticate", "auth", "logout", "register", "session"),
                )
                val authCalls = deps.jsParser.extractCallExpressions(source)
                    .filter { it.callee.contains("login", true) || it.callee.contains("auth", true) }
                McpToolResult.json(
                    buildJsonObject {
                        put(
                            "authPatterns",
                            JsonArray(
                                authPatterns.map { p ->
                                    buildJsonObject {
                                        put("pattern", JsonPrimitive(p.pattern))
                                        put("count", JsonPrimitive(p.matches.size))
                                    }
                                },
                            ),
                        )
                        put(
                            "authFunctions",
                            JsonArray(
                                authCalls.take(100).map { c ->
                                    buildJsonObject {
                                        put("callee", JsonPrimitive(c.callee))
                                        put("line", JsonPrimitive(c.line))
                                    }
                                },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "re.find_login_flow", "分析登录流程（按钮→函数→请求）", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val source = session.engine.getPageSource() ?: ""
                // 查找登录按钮
                val buttons = session.engine.evaluateJavascript(
                    "(function(){var out=[];document.querySelectorAll('button,input[type=submit],a').forEach(function(el){var t=(el.textContent||el.value||'').trim();if(/login|sign\\s*in|登录|登入|signin/i.test(t)){out.push({tag:el.tagName,text:t.substring(0,50),id:el.id,className:el.className})}});return JSON.stringify(out.slice(0,20))})()"
                ) ?: "[]"
                // 查找 login 相关函数
                val functions = deps.jsParser.extractFunctions(source)
                    .filter { it.name.contains("login", true) || it.name.contains("auth", true) }
                // 查找 login 相关网络请求
                val network = deps.networkInspector.getEntries(session.engine)
                    .filter { it.url.contains("login", true) || it.url.contains("auth", true) }
                McpToolResult.json(
                    buildJsonObject {
                        put("loginButtons", JsonPrimitive(buttons))
                        put(
                            "loginFunctions",
                            JsonArray(
                                functions.take(50).map { fn ->
                                    buildJsonObject {
                                        put("name", JsonPrimitive(fn.name))
                                        put("line", JsonPrimitive(fn.line))
                                        put("params", JsonPrimitive(fn.params.joinToString(",")))
                                    }
                                },
                            ),
                        )
                        put(
                            "loginRequests",
                            JsonArray(
                                network.take(50).map { e ->
                                    buildJsonObject {
                                        put("method", JsonPrimitive(e.method.wire))
                                        put("url", JsonPrimitive(e.url))
                                        put("status", JsonPrimitive(e.status))
                                    }
                                },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "re.find_sensitive_api", "查找敏感 API（涉及支付/用户数据）", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val source = session.engine.getPageSource() ?: ""
                val patterns = deps.jsParser.detectPatterns(
                    source,
                    listOf("payment", "pay", "charge", "order", "balance", "transfer", "withdraw", "user/info", "profile"),
                )
                McpToolResult.json(
                    buildJsonObject {
                        put(
                            "patterns",
                            JsonArray(
                                patterns.map { p ->
                                    buildJsonObject {
                                        put("pattern", JsonPrimitive(p.pattern))
                                        put("count", JsonPrimitive(p.matches.size))
                                        put(
                                            "occurrences",
                                            JsonArray(
                                                p.matches.take(30).map { m ->
                                                    buildJsonObject {
                                                        put("line", JsonPrimitive(m.line))
                                                        put("context", JsonPrimitive(m.context.take(200)))
                                                    }
                                                },
                                            ),
                                        )
                                    }
                                },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "re.find_strings", "提取页面所有字符串", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("query" to Schemas.strSchema("过滤关键词（可选）")),
            ) { args ->
                val query = ToolArgs.str(args, "query")
                val session = deps.activeSession()
                val source = session.engine.getPageSource() ?: ""
                var strings = deps.jsParser.extractStrings(source)
                if (query.isNotBlank()) strings = strings.filter { it.contains(query, ignoreCase = true) }
                McpToolResult.json(
                    buildJsonObject {
                        put("count", JsonPrimitive(strings.size))
                        put("strings", JsonArray(strings.take(500).map { JsonPrimitive(it) }))
                    },
                )
            },
            f.tool(
                "re.find_endpoints", "查找页面所有 URL 端点", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val source = session.engine.getPageSource() ?: ""
                val urls = deps.jsParser.extractUrls(source)
                McpToolResult.json(
                    buildJsonObject {
                        put("count", JsonPrimitive(urls.size))
                        put("urls", JsonArray(urls.map { JsonPrimitive(it) }))
                    },
                )
            },
            f.tool(
                "re.find_interesting_functions", "查找页面中值得关注的函数", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val source = session.engine.getPageSource() ?: ""
                val functions = deps.jsParser.extractFunctions(source)
                val interesting = functions.filter { fn ->
                    val name = fn.name.lowercase()
                    name.contains("token") || name.contains("auth") || name.contains("login") ||
                        name.contains("encrypt") || name.contains("decrypt") || name.contains("sign") ||
                        name.contains("payment") || name.contains("secret") || name.contains("key") ||
                        name.contains("session") || name.contains("request") || name.contains("fetch")
                }
                McpToolResult.json(
                    buildJsonObject {
                        put(
                            "functions",
                            JsonArray(
                                interesting.take(100).map { fn ->
                                    buildJsonObject {
                                        put("name", JsonPrimitive(fn.name))
                                        put("line", JsonPrimitive(fn.line))
                                        put("params", JsonPrimitive(fn.params.joinToString(",")))
                                        put("body", JsonPrimitive(fn.body.take(300)))
                                    }
                                },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "re.detect_framework", "检测页面框架", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val source = session.engine.getPageSource() ?: ""
                val detection = deps.frameworkDetector.detectFromJs(source)
                McpToolResult.json(
                    buildJsonObject {
                        put("frameworks", JsonArray(detection.frameworks.map { JsonPrimitive(it) }))
                        put("bundlers", JsonArray(detection.bundlers.map { JsonPrimitive(it) }))
                        put("obfuscators", JsonArray(detection.obfuscators.map { JsonPrimitive(it) }))
                        put("architecture", JsonArray(detection.architecture.map { JsonPrimitive(it) }))
                    },
                )
            },
            f.tool(
                "re.detect_bundler", "检测页面构建工具", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val source = session.engine.getPageSource() ?: ""
                val detection = deps.frameworkDetector.detectFromJs(source)
                McpToolResult.json(
                    buildJsonObject {
                        put("bundlers", JsonArray(detection.bundlers.map { JsonPrimitive(it) }))
                    },
                )
            },
            f.tool(
                "re.detect_obfuscator", "检测页面混淆器", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val source = session.engine.getPageSource() ?: ""
                val detection = deps.frameworkDetector.detectFromJs(source)
                val report = deps.obfuscationAnalyzer.analyze(source)
                McpToolResult.json(
                    buildJsonObject {
                        put("obfuscators", JsonArray(detection.obfuscators.map { JsonPrimitive(it) }))
                        put("obfuscationScore", JsonPrimitive(report.score))
                        put("isObfuscated", JsonPrimitive(report.isObfuscated))
                        put("detected", JsonArray(report.detected.map { JsonPrimitive(it) }))
                    },
                )
            },
            f.tool(
                "re.trace_function", "追踪函数调用链", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("functionName" to Schemas.strSchema("函数名")),
            ) { args ->
                val functionName = ToolArgs.str(args, "functionName")
                val session = deps.activeSession()
                val source = session.engine.getPageSource() ?: ""
                val calls = deps.jsParser.extractCallExpressions(source)
                val related = calls.filter { it.callee.contains(functionName, ignoreCase = true) }
                val functions = deps.jsParser.extractFunctions(source)
                    .filter { it.name.contains(functionName, ignoreCase = true) }
                McpToolResult.json(
                    buildJsonObject {
                        put("function", JsonPrimitive(functionName))
                        put(
                            "callSites",
                            JsonArray(
                                related.take(100).map { c ->
                                    buildJsonObject {
                                        put("callee", JsonPrimitive(c.callee))
                                        put("line", JsonPrimitive(c.line))
                                        put("args", JsonPrimitive(c.arguments.joinToString(", ").take(200)))
                                    }
                                },
                            ),
                        )
                        put(
                            "definitions",
                            JsonArray(
                                functions.map { fn ->
                                    buildJsonObject {
                                        put("name", JsonPrimitive(fn.name))
                                        put("line", JsonPrimitive(fn.line))
                                        put("params", JsonPrimitive(fn.params.joinToString(",")))
                                    }
                                },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "re.trace_network", "追踪网络请求调用链", ToolCategory.REVERSE,
                PermissionScope.READ_NETWORK, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("urlPattern" to Schemas.strSchema("URL 匹配")),
            ) { args ->
                val pattern = ToolArgs.str(args, "urlPattern")
                val session = deps.activeSession()
                val entries = deps.networkInspector.getEntries(session.engine)
                    .filter { pattern.isBlank() || it.url.contains(pattern, ignoreCase = true) }
                McpToolResult.json(
                    buildJsonObject {
                        put(
                            "requests",
                            JsonArray(
                                entries.take(100).map { e ->
                                    buildJsonObject {
                                        put("method", JsonPrimitive(e.method.wire))
                                        put("url", JsonPrimitive(e.url))
                                        put("status", JsonPrimitive(e.status))
                                        put("initiator", JsonPrimitive(e.initiator))
                                        put("initiatorStack", JsonPrimitive(e.initiatorStack.take(500)))
                                    }
                                },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "re.trace_event", "追踪 DOM 事件调用链", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("selector" to Schemas.strSchema("CSS 选择器")),
            ) { args ->
                val selector = ToolArgs.str(args, "selector", "body")
                val session = deps.activeSession()
                val result = deps.domInspector.getEventListeners(session.engine, selector)
                result.fold(
                    onSuccess = { listeners ->
                        McpToolResult.json(
                            buildJsonObject {
                                put(
                                    "listeners",
                                    JsonArray(
                                        listeners.map { l ->
                                            buildJsonObject {
                                                put("type", JsonPrimitive(l.type))
                                                put("handler", JsonPrimitive(l.handler.take(500)))
                                                put("location", JsonPrimitive(l.location))
                                            }
                                        },
                                    ),
                                )
                            },
                        )
                    },
                    onFailure = { McpToolResult.error("DOM_READ_FAILED", it.message) },
                )
            },
            f.tool(
                "re.trace_dom", "追踪 DOM 变更", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("selector" to Schemas.strSchema("CSS 选择器")),
            ) { args ->
                val selector = ToolArgs.str(args, "selector", "body")
                val session = deps.activeSession()
                val html = deps.domInspector.getOuterHTML(session.engine, selector)
                html.fold(
                    onSuccess = { McpToolResult.text(it.take(50_000)) },
                    onFailure = { McpToolResult.error("DOM_READ_FAILED", it.message) },
                )
            },
            f.tool(
                "re.compare_sources", "比较两份源码差异", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "sourceA" to Schemas.strSchema("源码 A"),
                    "sourceB" to Schemas.strSchema("源码 B"),
                ),
            ) { args ->
                val sourceA = ToolArgs.str(args, "sourceA")
                val sourceB = ToolArgs.str(args, "sourceB")
                val diff = deps.diffEngine.diff(sourceA, sourceB)
                McpToolResult.json(
                    buildJsonObject {
                        put("additions", JsonPrimitive(diff.additions.size))
                        put("deletions", JsonPrimitive(diff.deletions.size))
                        put("unchanged", JsonPrimitive(diff.unchanged))
                        put("similarity", JsonPrimitive(diff.similarity))
                        put(
                            "additionLines",
                            JsonArray(
                                diff.additions.take(100).map { c ->
                                    buildJsonObject {
                                        put("line", JsonPrimitive(c.lineNumber))
                                        put("content", JsonPrimitive(c.content.take(200)))
                                    }
                                },
                            ),
                        )
                        put(
                            "deletionLines",
                            JsonArray(
                                diff.deletions.take(100).map { c ->
                                    buildJsonObject {
                                        put("line", JsonPrimitive(c.lineNumber))
                                        put("content", JsonPrimitive(c.content.take(200)))
                                    }
                                },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "re.diff_runtime", "比较运行时状态差异", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                McpToolResult.text("运行时差异分析")
            },
            f.tool(
                "re.generate_report", "生成逆向分析报告", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("format" to Schemas.strSchema("markdown/json/html")),
            ) { args ->
                val format = ToolArgs.str(args, "format", "markdown")
                val session = deps.activeSession()
                val url = session.engine.currentUrl() ?: ""
                val title = session.engine.currentTitle() ?: ""
                val source = session.engine.getPageSource() ?: ""
                val framework = deps.frameworkDetector.detectFromJs(source)
                val obfuscation = deps.obfuscationAnalyzer.analyze(source)
                val apis = deps.apiDiscoveryEngine.merge(
                    deps.apiDiscoveryEngine.discoverFromHtml(source),
                    deps.apiDiscoveryEngine.discoverFromJs(source),
                    deps.apiDiscoveryEngine.discoverFromNetwork(session.engine.getNetworkEntries()),
                )
                val sb = StringBuilder()
                sb.appendLine("# 逆向分析报告")
                sb.appendLine()
                sb.appendLine("## 目标")
                sb.appendLine("- URL: $url")
                sb.appendLine("- Title: $title")
                sb.appendLine()
                sb.appendLine("## 技术栈")
                sb.appendLine("- Frameworks: ${framework.frameworks.joinToString(", ").ifEmpty { "未知" }}")
                sb.appendLine("- Bundlers: ${framework.bundlers.joinToString(", ").ifEmpty { "未知" }}")
                sb.appendLine("- Architecture: ${framework.architecture.joinToString(", ").ifEmpty { "未知" }}")
                sb.appendLine()
                sb.appendLine("## 混淆分析")
                sb.appendLine("- Obfuscation Score: ${obfuscation.score}/100")
                sb.appendLine("- Detected: ${obfuscation.detected.joinToString(", ").ifEmpty { "无" }}")
                sb.appendLine()
                sb.appendLine("## API 清单 (${apis.endpoints.size})")
                apis.endpoints.take(50).forEach { e ->
                    sb.appendLine("- ${e.method} ${e.url} (source: ${e.source}, confidence: ${e.confidence})")
                }
                val report = sb.toString()
                when (format.lowercase()) {
                    "json" -> McpToolResult.json(
                        buildJsonObject {
                            put("url", JsonPrimitive(url))
                            put("title", JsonPrimitive(title))
                            put("frameworks", JsonArray(framework.frameworks.map { JsonPrimitive(it) }))
                            put("obfuscationScore", JsonPrimitive(obfuscation.score))
                            put("apiCount", JsonPrimitive(apis.endpoints.size))
                        },
                    )
                    "html" -> McpToolResult.text("<pre>${report.replace("<", "&lt;").replace(">", "&gt;")}</pre>")
                    else -> McpToolResult.text(report)
                }
            },
            f.tool(
                "re.sourcemap", "解析 Source Map 定位源码", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "sourceMapJson" to Schemas.strSchema("Source Map JSON"),
                    "line" to Schemas.intSchema("压缩后行号"),
                    "column" to Schemas.intSchema("压缩后列号"),
                ),
            ) { args ->
                val sourceMapJson = ToolArgs.str(args, "sourceMapJson")
                val line = ToolArgs.int(args, "line")
                val column = ToolArgs.int(args, "column")
                if (sourceMapJson.isBlank()) return@tool McpToolResult.error("INVALID_ARGUMENTS", "sourceMapJson 不能为空")
                val parsed = deps.sourceMapParser.parse(sourceMapJson)
                val mapped = deps.sourceMapParser.locateOriginal(parsed, line, column)
                McpToolResult.json(
                    buildJsonObject {
                        put("source", JsonPrimitive(mapped?.source ?: ""))
                        put("line", JsonPrimitive(mapped?.line ?: 0))
                        put("column", JsonPrimitive(mapped?.column ?: 0))
                        put("originalSources", JsonArray(parsed.sources.map { JsonPrimitive(it) }))
                    },
                )
            },

            // P2-8：证据链与还原包导出
            f.tool(
                "re.export_case",
                "导出逆向证据链还原包：把工作区 findings/analysis/notes + 当前页面源码 + 网络请求链打包为 Markdown 报告与 JSON 证据包落盘，供归档/交接/复现",
                ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW, timeoutMs = 60_000,
                inputSchema = Schemas.objectSchema(
                    "workspaceId" to Schemas.strSchema("工作区 ID（留空则仅导出当前页面证据）"),
                    "includePageSource" to Schemas.boolSchema("是否包含当前页面源码（默认 true）"),
                    "includeNetwork" to Schemas.boolSchema("是否包含网络请求链（默认 true）"),
                    "caseName" to Schemas.strSchema("案件名（默认 目标域名+时间戳）"),
                ),
            ) { args ->
                val workspaceId = ToolArgs.str(args, "workspaceId")
                val includeSource = ToolArgs.bool(args, "includePageSource", true)
                val includeNetwork = ToolArgs.bool(args, "includeNetwork", true)
                val caseName = ToolArgs.str(args, "caseName")

                val session = deps.activeSession()
                val url = session.engine.currentUrl() ?: ""
                val title = session.engine.currentTitle() ?: ""
                val ts = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
                val safeName = (caseName.ifBlank { url.substringAfter("://").substringBefore("/").ifBlank { "case" } })
                    .replace(Regex("""[^\w.-]"""), "_")
                val base = "$safeName-$ts"

                // 收集证据
                val findings = if (workspaceId.isNotBlank()) {
                    runCatching { deps.workspaceManager.observeFindings(workspaceId).first() }.getOrDefault(emptyList())
                } else emptyList()
                val analysis = if (workspaceId.isNotBlank()) {
                    runCatching { deps.workspaceManager.observeAnalysis(workspaceId).first() }.getOrDefault(emptyList())
                } else emptyList()
                val notes = if (workspaceId.isNotBlank()) {
                    runCatching { deps.workspaceManager.observeNotes(workspaceId).first() }.getOrDefault(emptyList())
                } else emptyList()
                val pageSource = if (includeSource) {
                    runCatching { session.engine.getPageSource() }.getOrNull() ?: ""
                } else ""
                val network = if (includeNetwork) {
                    runCatching { deps.networkInspector.getEntries(session.engine) }.getOrDefault(emptyList())
                } else emptyList()

                // Markdown 报告
                val md = buildString {
                    appendLine("# 逆向证据链报告 — $safeName")
                    appendLine()
                    appendLine("- 目标: $url")
                    appendLine("- 标题: $title")
                    appendLine("- 导出时间: $ts")
                    appendLine("- 工作区: ${workspaceId.ifBlank { "（未指定）" }}")
                    appendLine()
                    appendLine("## 发现 (${findings.size})")
                    findings.forEach { f ->
                        appendLine("- [${f.severity}/${f.confidence}] ${f.title} — ${f.description.take(200)}")
                        if (f.evidence.isNotBlank()) appendLine("  - 证据: ${f.evidence.take(300)}")
                    }
                    if (findings.isEmpty()) appendLine("（无）")
                    appendLine()
                    appendLine("## 分析记录 (${analysis.size})")
                    analysis.forEach { a ->
                        appendLine("- [${a.type}] ${a.title} — ${a.summary.take(200)}")
                    }
                    if (analysis.isEmpty()) appendLine("（无）")
                    appendLine()
                    appendLine("## 笔记 (${notes.size})")
                    notes.forEach { n -> appendLine("- ${n.title}: ${n.content.take(200)}") }
                    if (notes.isEmpty()) appendLine("（无）")
                    appendLine()
                    appendLine("## 网络请求链 (${network.size})")
                    network.take(100).forEach { e ->
                        appendLine("- ${e.method.wire} ${e.status} ${e.url.take(200)}")
                    }
                    if (network.isEmpty()) appendLine("（无）")
                    appendLine()
                    appendLine("## 页面源码")
                    appendLine("```html")
                    appendLine(pageSource.take(20_000))
                    appendLine("```")
                }

                // JSON 证据包
                val jsonBundle = buildJsonObject {
                    put("case", JsonPrimitive(safeName))
                    put("targetUrl", JsonPrimitive(url))
                    put("exportedAt", JsonPrimitive(ts))
                    put("workspaceId", JsonPrimitive(workspaceId))
                    put("findings", JsonArray(findings.map { f ->
                        buildJsonObject {
                            put("id", JsonPrimitive(f.id))
                            put("title", JsonPrimitive(f.title))
                            put("severity", JsonPrimitive(f.severity))
                            put("confidence", JsonPrimitive(f.confidence))
                            put("evidence", JsonPrimitive(f.evidence.take(500)))
                        }
                    }))
                    put("analysis", JsonArray(analysis.map { a ->
                        buildJsonObject {
                            put("id", JsonPrimitive(a.id))
                            put("type", JsonPrimitive(a.type))
                            put("title", JsonPrimitive(a.title))
                            put("summary", JsonPrimitive(a.summary.take(500)))
                        }
                    }))
                    put("network", JsonArray(network.take(200).map { e ->
                        buildJsonObject {
                            put("method", JsonPrimitive(e.method.wire))
                            put("url", JsonPrimitive(e.url))
                            put("status", JsonPrimitive(e.status))
                            put("initiator", JsonPrimitive(e.initiator))
                        }
                    }))
                }

                // 落盘
                val ctx = deps.browserService.appContext()
                val dir = WorkDir.directory(ctx)
                val mdFile = File(dir, "$base.md")
                val jsonFile = File(dir, "$base.evidence.json")
                withContext(Dispatchers.IO) {
                    mdFile.writeText(md)
                    jsonFile.writeText(jsonBundle.toString())
                }
                McpToolResult.json(
                    buildJsonObject {
                        put("caseName", JsonPrimitive(safeName))
                        put("reportPath", JsonPrimitive(mdFile.absolutePath))
                        put("evidencePath", JsonPrimitive(jsonFile.absolutePath))
                        put("reportBytes", JsonPrimitive(mdFile.length()))
                        put("evidenceBytes", JsonPrimitive(jsonFile.length()))
                        put("counts", buildJsonObject {
                            put("findings", JsonPrimitive(findings.size))
                            put("analysis", JsonPrimitive(analysis.size))
                            put("notes", JsonPrimitive(notes.size))
                            put("network", JsonPrimitive(network.size))
                            put("pageSourceBytes", JsonPrimitive(pageSource.length))
                        })
                    },
                )
            },

            // ================= 全景分析 =================

            f.tool(
                "re.analyze_page",
                "页面逆向全景分析（一次调用返回全部）：技术栈+API端点+加密函数候选+敏感存储+网络摘要+CDP脚本清单+推荐下一步。逆向新页面的第一步。" +
                    "总耗时受控（默认约 50s 内返回，各阶段超预算即跳过并在结果中标注），不会因页面脚本过多而超时",
                ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW, timeoutMs = 120_000,
                inputSchema = Schemas.objectSchema(
                    "attachCdp" to Schemas.boolSchema("未附加 CDP 时自动附加（默认 true，获得脚本清单与加密候选定位能力）"),
                    "maxApis" to Schemas.intSchema("API 端点最多返回数（默认 30）"),
                    "maxScripts" to Schemas.intSchema("脚本最多返回数（默认 30）"),
                    "maxCryptoScanMs" to Schemas.intSchema("加密候选扫描的时间预算毫秒（默认 20000，到点即停并返回已扫描结果）"),
                ),
            ) { args ->
                val session = deps.activeSession()
                val engine = session.engine
                // 修复（实测问题：AI 客户端对单次请求有约 60s 等待上限，原实现
                // 预算从进入扫描阶段才起算，前置取源码/框架检测/CDP 附加耗时会叠加越界，
                // 导致整体 "Request timed out" 且无任何部分结果）。现改为：
                // 1) 从工具进入起算总墙钟预算（50s，留 10s 余量给序列化与传输）；
                // 2) 每个阶段开工前检查剩余时间，不够就跳过该阶段并在响应里标注；
                // 3) 加密扫描的 deadline 取「用户预算」与「总预算剩余」的较小值；
                // 4) 单次 CDP searchInContent 限时 3s，防单个慢调用击穿预算。
                val entryAt = System.currentTimeMillis()
                val overallDeadline = entryAt + 50_000L
                fun remainingMs(): Long = overallDeadline - System.currentTimeMillis()
                val skippedPhases = mutableListOf<String>()

                val url = engine.currentUrl() ?: ""
                val title = engine.currentTitle() ?: ""
                val source = engine.getPageSource() ?: ""

                // 1. 技术栈与混淆（大页面上 CPU 分析可能秒级，限时保护）
                var framework = com.webreverse.mcp.javascript.analysis.FrameworkDetection()
                var obfuscation = com.webreverse.mcp.javascript.analysis.ObfuscationReport()
                if (remainingMs() > 3_000) {
                    val fw = kotlinx.coroutines.withTimeoutOrNull(10_000L) { deps.frameworkDetector.detectFromJs(source) }
                    if (fw != null) framework = fw else skippedPhases.add("frameworkDetect(10s超时)")
                    val ob = kotlinx.coroutines.withTimeoutOrNull(10_000L) { deps.obfuscationAnalyzer.analyze(source) }
                    if (ob != null) obfuscation = ob else skippedPhases.add("obfuscationAnalyze(10s超时)")
                } else {
                    skippedPhases.add("frameworkDetect/obfuscationAnalyze(总预算不足)")
                }

                // 2. CDP 自动附加（获得 scripts 清单）
                var cdpAttached = deps.debuggerManager.backend == "cdp"
                if (!cdpAttached && ToolArgs.bool(args, "attachCdp", true) && remainingMs() > 5_000) {
                    kotlinx.coroutines.withTimeoutOrNull(15_000L) { runCatching { deps.debuggerManager.attach(engine) }.let { } }
                    cdpAttached = deps.debuggerManager.backend == "cdp"
                    if (!cdpAttached) skippedPhases.add("cdpAttach")
                }
                val scripts = if (cdpAttached && remainingMs() > 1_000) {
                    kotlinx.coroutines.withTimeoutOrNull(10_000L) { deps.debuggerManager.listScripts(engine) } ?: emptyList()
                } else {
                    if (cdpAttached) skippedPhases.add("listScripts(总预算不足)")
                    emptyList()
                }

                // 3. 加密函数候选：在已解析脚本中搜 crypto 特征（searchInContent，只搜大文件最值得）
                // 三重限流：总预算剩余时间 + 用户扫描预算（默认 20s，二者取小）+ 脚本数上限 + 命中数上限。
                // 优先扫大脚本（加密库通常体积大），命中后跳过该脚本剩余模式。
                val scanBudgetMs = ToolArgs.long(args, "maxCryptoScanMs", 20_000L).coerceIn(5_000L, 60_000L)
                val scanDeadline = minOf(System.currentTimeMillis() + scanBudgetMs, overallDeadline - 2_000L)
                val cryptoPatterns = listOf("CryptoJS", "JSEncrypt", "AES", "DES", "RSA", "MD5", "SHA256", "HmacSHA", "encrypt(", "sign(", "getSign", "signature")
                val cryptoHits = mutableListOf<JsonObject>()
                var cryptoScanStopped = false
                var cryptoScanStoppedReason = ""
                if (cdpAttached && scripts.isNotEmpty()) {
                    // 大脚本优先：加密/签名库几乎都是大文件，小脚本命中多为噪音
                    val cdpScripts = scripts.sortedByDescending { it.length }.take(25)
                    for (s in cdpScripts) {
                        if (System.currentTimeMillis() > scanDeadline) {
                            cryptoScanStopped = true
                            cryptoScanStoppedReason = "时间预算"
                            break
                        }
                        if (cryptoHits.size >= 60) {
                            cryptoScanStopped = true
                            cryptoScanStoppedReason = "命中数上限(60)"
                            break
                        }
                        for (pat in cryptoPatterns) {
                            if (System.currentTimeMillis() > scanDeadline) {
                                cryptoScanStopped = true
                                cryptoScanStoppedReason = "时间预算"
                                break
                            }
                            // 单次 CDP 往返限时 3s：防个别慢调用击穿预算（正常 <100ms）
                            val found = kotlinx.coroutines.withTimeoutOrNull(3_000L) {
                                deps.debuggerManager.searchScriptContent(engine, s.scriptId, pat, false, 5)
                            }
                            found?.getOrNull()?.forEach { m ->
                                val mo = m as? JsonObject ?: return@forEach
                                cryptoHits.add(
                                    buildJsonObject {
                                        put("pattern", JsonPrimitive(pat))
                                        put("url", JsonPrimitive(s.url))
                                        put("line", mo["lineNumber"] ?: JsonPrimitive(0))
                                        put("content", mo["lineContent"] ?: JsonPrimitive(""))
                                    },
                                )
                            }
                            if (!found?.getOrNull().isNullOrEmpty()) {
                                // 本脚本已有命中：剩余模式边际价值低，跳过该脚本剩余模式
                                break
                            }
                            if (cryptoHits.size >= 60) break
                        }
                        if (cryptoHits.size >= 60) { cryptoScanStopped = true; cryptoScanStoppedReason = "命中数上限(60)" }
                    }
                }

                // 4. API 端点（网络发现依赖引擎缓存，通常快）
                val maxApis = ToolArgs.int(args, "maxApis", 30)
                val apis = if (remainingMs() > 2_000) {
                    deps.apiDiscoveryEngine.merge(
                        deps.apiDiscoveryEngine.discoverFromHtml(source),
                        deps.apiDiscoveryEngine.discoverFromJs(source, "html"),
                        deps.apiDiscoveryEngine.discoverFromNetwork(engine.getNetworkEntries()),
                    ).endpoints.take(maxApis)
                } else {
                    skippedPhases.add("apiDiscovery(总预算不足)")
                    emptyList()
                }

                // 5. 敏感存储（cookie/localStorage key 名单，值只报长度）
                val cookies = runCatching { engine.getCookies() }.getOrDefault(emptyList())
                val localStorage = runCatching { engine.getLocalStorage() }.getOrDefault(emptyMap())
                val sensitiveKeyPatterns = listOf("token", "session", "sign", "secret", "key", "auth", "credential", "jwt", "csrf", "uid", "device")
                val sensitiveStorage = localStorage.filterKeys { k ->
                    sensitiveKeyPatterns.any { p -> k.lowercase().contains(p) }
                }

                // 6. 网络摘要
                val entries = engine.getNetworkEntries()
                val apiCalls = entries.filter { it.url.contains("/api/") || it.url.contains("json") }
                val xhrHosts = entries.map { it.url.substringAfter("//").substringBefore('/') }
                    .filter { it.isNotBlank() }.distinct().take(15)

                McpToolResult.json(
                    buildJsonObject {
                        put("url", JsonPrimitive(url))
                        put("title", JsonPrimitive(title))
                        put("elapsedMs", JsonPrimitive(System.currentTimeMillis() - entryAt))
                        if (skippedPhases.isNotEmpty()) {
                            put("skippedPhases", JsonArray(skippedPhases.map { JsonPrimitive(it) }))
                            put("phaseNote", JsonPrimitive("以上阶段因时间预算被跳过，可单独调用对应工具补齐（如 debugger.list_scripts / re.find_api）"))
                        }
                        put("framework", buildJsonObject {
                            put("frameworks", JsonArray(framework.frameworks.map { JsonPrimitive(it) }))
                            put("bundlers", JsonArray(framework.bundlers.map { JsonPrimitive(it) }))
                            put("obfuscators", JsonArray(framework.obfuscators.map { JsonPrimitive(it) }))
                        })
                        put("obfuscation", buildJsonObject {
                            put("isObfuscated", JsonPrimitive(obfuscation.isObfuscated))
                            put("isMinified", JsonPrimitive(obfuscation.isMinified))
                            put("score", JsonPrimitive(obfuscation.score))
                            put("detected", JsonArray(obfuscation.detected.map { JsonPrimitive(it) }))
                            put("antiDebug", JsonPrimitive(obfuscation.antiDebug))
                            put("controlFlowFlattening", JsonPrimitive(obfuscation.controlFlowFlattening))
                        })
                        put("cdpAttached", JsonPrimitive(cdpAttached))
                        put("scriptCount", JsonPrimitive(scripts.size))
                        put("scripts", JsonArray(scripts.take(ToolArgs.int(args, "maxScripts", 30)).map { s ->
                            buildJsonObject {
                                put("scriptId", JsonPrimitive(s.scriptId))
                                put("url", JsonPrimitive(s.url))
                                put("sourceMap", JsonPrimitive(s.sourceMapUrl ?: ""))
                            }
                        }))
                        put("cryptoCandidates", JsonArray(cryptoHits))
                        put("cryptoScan", buildJsonObject {
                            put("budgetMs", JsonPrimitive(scanBudgetMs))
                            put("completed", JsonPrimitive(!cryptoScanStopped))
                            put(
                                "note",
                                JsonPrimitive(
                                    if (cryptoScanStopped) "达到时间预算/命中上限提前停止，可提高 maxCryptoScanMs 或缩小目标后用 debugger.search_in_content 精查" else "扫描完成",
                                ),
                            )
                        })
                        put("apiEndpoints", JsonArray(apis.map { e ->
                            buildJsonObject {
                                put("method", JsonPrimitive(e.method))
                                put("url", JsonPrimitive(e.url))
                                put("source", JsonPrimitive(e.source))
                            }
                        }))
                        put("sensitiveStorage", buildJsonObject {
                            put("cookies", JsonArray(cookies.map { c -> JsonPrimitive(c["name"] ?: "?") }))
                            put("localStorageKeys", JsonArray(sensitiveStorage.keys.map { JsonPrimitive(it) }))
                            put("localStorageTotal", JsonPrimitive(localStorage.size))
                        })
                        put("network", buildJsonObject {
                            put("totalRequests", JsonPrimitive(entries.size))
                            put("apiRequests", JsonPrimitive(apiCalls.size))
                            put("hosts", JsonArray(xhrHosts.map { JsonPrimitive(it) }))
                        })
                        put(
                            "nextSteps",
                            JsonArray(
                                buildList {
                                    if (cdpAttached) {
                                        if (cryptoHits.isNotEmpty()) add(JsonPrimitive("cryptoCandidates 有命中：get_script_source 看上下文，再 set_breakpoint 在该行断住"))
                                        add(JsonPrimitive("set_breakpoint 设断点 + 触发操作 + wait_breakpoint 一步拿到暂停现场（调用栈+局部变量）"))
                                        add(JsonPrimitive("network.intercept 拦截签名请求：发出前查看/改写参数放行，或 mock_response 伪造响应"))
                                        add(JsonPrimitive("cpu_profile start=true → 触发加密流程 → start=false，selfTime 霸榜即加密函数"))
                                        add(JsonPrimitive("set_xhr_breakpoint 定位签名生成点；cdp_ws_frames 捕获 WebSocket 实时签名通道"))
                                    } else {
                                        add(JsonPrimitive("CDP 不可用：debugger.attach 重试；注入式降级时 hook.crypto 挂加密调用监控"))
                                    }
                                    add(JsonPrimitive("re.find_login_flow / re.find_auth_flow 深挖鉴权链路"))
                                },
                            ),
                        )
                    },
                )
            },
        )
    }
}
