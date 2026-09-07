package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import com.webreverse.mcp.javascript.analysis.AstRender
import com.webreverse.mcp.javascript.analysis.JsAstParser
import com.webreverse.mcp.javascript.analysis.JsFunction
import com.webreverse.mcp.javascript.analysis.Program
import com.webreverse.mcp.javascript.analysis.Stmt
import com.webreverse.mcp.javascript.analysis.TopLevel
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/** JavaScript Tools：求值、AST、混淆检测、源码搜索 */
object JavaScriptTools {

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)
        return listOf(
            f.tool(
                "js.evaluate", "在当前页面执行 JavaScript 表达式（awaitPromise=true 时等待 Promise 结算）", ToolCategory.JAVASCRIPT,
                PermissionScope.EXECUTE_JS, RiskLevel.HIGH, timeoutMs = 45_000,
                inputSchema = Schemas.objectSchema(
                    "expression" to Schemas.strSchema("要执行的 JS 表达式"),
                    "awaitPromise" to Schemas.boolSchema("是否等待 Promise（默认 false）"),
                ),
            ) { args ->
                val expression = ToolArgs.str(args, "expression")
                if (expression.isBlank()) return@tool McpToolResult.error("INVALID_ARGUMENTS", "expression 不能为空")
                val session = deps.activeSession()
                // awaitPromise 此前被忽略——现在真正路由到异步求值
                //（引擎层等待 Promise 结算，修复返回 {} 的问题）
                val result = if (ToolArgs.bool(args, "awaitPromise", false)) {
                    deps.consoleManager.evaluateAsync(session.engine, expression)
                } else {
                    deps.consoleManager.evaluate(session.engine, expression)
                }
                result.fold(
                    onSuccess = { McpToolResult.text(it) },
                    onFailure = { McpToolResult.error("JS_EXECUTION_FAILED", it.message) },
                )
            },
            f.tool(
                "js.evaluate_async", "异步执行 JavaScript（支持 await，等待 Promise 结算后返回结果）", ToolCategory.JAVASCRIPT,
                PermissionScope.EXECUTE_JS, RiskLevel.HIGH, timeoutMs = 45_000,
                inputSchema = Schemas.objectSchema("expression" to Schemas.strSchema("要执行的 JS 表达式（可用 await）")),
            ) { args ->
                val expression = ToolArgs.str(args, "expression")
                if (expression.isBlank()) return@tool McpToolResult.error("INVALID_ARGUMENTS", "expression 不能为空")
                val session = deps.activeSession()
                val result = deps.consoleManager.evaluateAsync(session.engine, expression)
                result.fold(
                    onSuccess = { McpToolResult.text(it) },
                    onFailure = { McpToolResult.error("JS_EXECUTION_FAILED", it.message) },
                )
            },
            f.tool(
                "js.call_function", "调用页面中的函数", ToolCategory.JAVASCRIPT,
                PermissionScope.EXECUTE_JS, RiskLevel.HIGH,
                inputSchema = Schemas.objectSchema(
                    "functionName" to Schemas.strSchema("函数名或表达式"),
                    "args" to Schemas.strSchema("参数列表（JSON 数组）"),
                ),
            ) { args ->
                val functionName = ToolArgs.str(args, "functionName")
                val argsJson = ToolArgs.str(args, "args", "[]")
                val session = deps.activeSession()
                val argList = runCatching {
                    kotlinx.serialization.json.Json.parseToJsonElement(argsJson).jsonArray.map { it.toString() }
                }.getOrDefault(emptyList())
                val result = deps.consoleManager.callFunction(session.engine, functionName, *argList.toTypedArray())
                result.fold(
                    onSuccess = { McpToolResult.text(it) },
                    onFailure = { McpToolResult.error("JS_EXECUTION_FAILED", it.message) },
                )
            },
            f.tool(
                "js.inspect", "检查表达式的类型与结构", ToolCategory.JAVASCRIPT,
                PermissionScope.EXECUTE_JS, RiskLevel.HIGH,
                inputSchema = Schemas.objectSchema("expression" to Schemas.strSchema("要检查的表达式")),
            ) { args ->
                val expression = ToolArgs.str(args, "expression")
                val session = deps.activeSession()
                val result = deps.consoleManager.inspect(session.engine, expression)
                result.fold(
                    onSuccess = { McpToolResult.text(it) },
                    onFailure = { McpToolResult.error("JS_EXECUTION_FAILED", it.message) },
                )
            },
            f.tool(
                "js.get_global", "获取全局变量", ToolCategory.JAVASCRIPT,
                PermissionScope.EXECUTE_JS, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema("name" to Schemas.strSchema("全局变量名")),
            ) { args ->
                val name = ToolArgs.str(args, "name")
                val session = deps.activeSession()
                val result = deps.consoleManager.getGlobal(session.engine, name)
                result.fold(
                    onSuccess = { McpToolResult.text(it) },
                    onFailure = { McpToolResult.error("JS_EXECUTION_FAILED", it.message) },
                )
            },
            f.tool(
                "js.get_property", "获取对象属性", ToolCategory.JAVASCRIPT,
                PermissionScope.EXECUTE_JS, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "object" to Schemas.strSchema("对象表达式"),
                    "property" to Schemas.strSchema("属性名"),
                ),
            ) { args ->
                val obj = ToolArgs.str(args, "object")
                val property = ToolArgs.str(args, "property")
                val session = deps.activeSession()
                val result = deps.consoleManager.getProperty(session.engine, obj, property)
                result.fold(
                    onSuccess = { McpToolResult.text(it) },
                    onFailure = { McpToolResult.error("JS_EXECUTION_FAILED", it.message) },
                )
            },
            f.tool(
                "js.set_property", "设置对象属性", ToolCategory.JAVASCRIPT,
                PermissionScope.EXECUTE_JS, RiskLevel.HIGH,
                inputSchema = Schemas.objectSchema(
                    "object" to Schemas.strSchema("对象表达式"),
                    "property" to Schemas.strSchema("属性名"),
                    "value" to Schemas.strSchema("属性值（JS 表达式）"),
                ),
            ) { args ->
                val obj = ToolArgs.str(args, "object")
                val property = ToolArgs.str(args, "property")
                val value = ToolArgs.str(args, "value")
                val session = deps.activeSession()
                val result = deps.consoleManager.setProperty(session.engine, obj, property, value)
                result.fold(
                    onSuccess = { McpToolResult.text("已设置 $obj.$property") },
                    onFailure = { McpToolResult.error("JS_EXECUTION_FAILED", it.message) },
                )
            },
            f.tool(
                "js.delete_property", "删除对象属性", ToolCategory.JAVASCRIPT,
                PermissionScope.EXECUTE_JS, RiskLevel.HIGH,
                inputSchema = Schemas.objectSchema(
                    "object" to Schemas.strSchema("对象表达式"),
                    "property" to Schemas.strSchema("属性名"),
                ),
            ) { args ->
                val obj = ToolArgs.str(args, "object")
                val property = ToolArgs.str(args, "property")
                val session = deps.activeSession()
                val result = deps.consoleManager.deleteProperty(session.engine, obj, property)
                result.fold(
                    onSuccess = { McpToolResult.text("已删除 $obj.$property") },
                    onFailure = { McpToolResult.error("JS_EXECUTION_FAILED", it.message) },
                )
            },
            f.tool(
                "js.parse_ast", "解析 JavaScript 源码为 AST/Token 结构", ToolCategory.JAVASCRIPT,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("source" to Schemas.strSchema("JS 源码")),
            ) { args ->
                val source = ToolArgs.str(args, "source")
                if (source.isBlank()) return@tool McpToolResult.error("INVALID_ARGUMENTS", "source 不能为空")
                val tokens = deps.jsParser.tokenize(source)
                val functions = deps.jsParser.extractFunctions(source)
                val calls = deps.jsParser.extractCallExpressions(source)
                McpToolResult.json(
                    buildJsonObject {
                        put("tokenCount", JsonPrimitive(tokens.size))
                        put(
                            "tokens",
                            JsonArray(
                                tokens.take(500).map { t ->
                                    buildJsonObject {
                                        put("type", JsonPrimitive(t.type.name))
                                        put("value", JsonPrimitive(t.value.take(100)))
                                        put("line", JsonPrimitive(t.line))
                                    }
                                },
                            ),
                        )
                        put(
                            "functions",
                            JsonArray(
                                functions.map { fn ->
                                    buildJsonObject {
                                        put("name", JsonPrimitive(fn.name))
                                        put("params", JsonPrimitive(fn.params.joinToString(",")))
                                        put("line", JsonPrimitive(fn.line))
                                    }
                                },
                            ),
                        )
                        put(
                            "calls",
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
                "js.analyze_ast", "分析 JS 源码提取字符串/标识符/URL/变量", ToolCategory.JAVASCRIPT,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("source" to Schemas.strSchema("JS 源码")),
            ) { args ->
                val source = ToolArgs.str(args, "source")
                if (source.isBlank()) return@tool McpToolResult.error("INVALID_ARGUMENTS", "source 不能为空")
                val extraction = deps.jsParser.extractAll(source)
                McpToolResult.json(
                    buildJsonObject {
                        put(
                            "strings",
                            JsonArray(extraction.strings.take(500).map { JsonPrimitive(it) }),
                        )
                        put(
                            "urls",
                            JsonArray(extraction.urls.map { JsonPrimitive(it) }),
                        )
                        put(
                            "identifiers",
                            JsonArray(extraction.identifiers.take(500).map { JsonPrimitive(it) }),
                        )
                        put(
                            "functions",
                            JsonArray(extraction.functionNames.take(300).map { JsonPrimitive(it) }),
                        )
                        put(
                            "variables",
                            JsonArray(extraction.variables.take(300).map { JsonPrimitive(it) }),
                        )
                        put(
                            "memberExpressions",
                            JsonArray(extraction.memberExpressions.take(300).map { JsonPrimitive(it) }),
                        )
                    },
                )
            },
            f.tool(
                "js.ast", "结构化 AST 解析：递归下降解析为 AST（函数/变量/if/for/while/switch/return/调用/成员/赋值/二元），输出函数清单与语句树", ToolCategory.JAVASCRIPT,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("source" to Schemas.strSchema("JS 源码")),
                timeoutMs = 60_000,
            ) { args ->
                val source = ToolArgs.str(args, "source")
                if (source.isBlank()) return@tool McpToolResult.error("INVALID_ARGUMENTS", "source 不能为空")
                val program = JsAstParser().parse(source)
                val functions = collectAstFunctions(program)
                McpToolResult.json(
                    buildJsonObject {
                        put("topLevelCount", JsonPrimitive(program.body.size))
                        put("functionCount", JsonPrimitive(functions.size))
                        put(
                            "functions",
                            JsonArray(
                                functions.take(200).map { fn ->
                                    buildJsonObject {
                                        put("name", JsonPrimitive(fn.name.ifBlank { "(anonymous)" }))
                                        put("params", JsonPrimitive(fn.params.joinToString(",")))
                                        put("line", JsonPrimitive(fn.pos.line))
                                        put("isArrow", JsonPrimitive(fn.isArrow))
                                        put(
                                            "body",
                                            JsonArray(fn.body.stmts.take(100).map { JsonPrimitive(AstRender.stmt(it).take(120)) }),
                                        )
                                    }
                                },
                            ),
                        )
                        put(
                            "topLevel",
                            JsonArray(
                                program.body.take(300).map { tl ->
                                    JsonPrimitive(renderTopLevel(tl).take(160))
                                },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "js.beautify", "美化格式化 JS 源码（词法级格式化：字符串/模板/正则/注释安全，不破坏语义；混淆代码建议用 js.format）", ToolCategory.JAVASCRIPT,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("source" to Schemas.strSchema("JS 源码")),
            ) { args ->
                val source = ToolArgs.str(args, "source")
                if (source.isBlank()) return@tool McpToolResult.error("INVALID_ARGUMENTS", "source 不能为空")
                // 升级为词法级 JsFormatter（原字符级实现会破坏注释/正则/for(;;)）
                val r = com.webreverse.mcp.javascript.parser.JsFormatter(renameObfuscated = false)
                    .format(source)
                McpToolResult.text(r.formatted)
            },
            f.tool(
                "js.format",
                "JavaScript 格式化（ 新增，逆向阅读利器）：把 minified/打包/混淆 JS 格式化为带缩进换行的可读代码。" +
                    "词法级实现——字符串/模板字面量/正则/注释原样保留不破坏；支持把 _0x4a3f 风格混淆标识符批量重命名为 v1/v2/...（附映射表）。" +
                    "可直接传 source，或传 scriptIdOrUrl 从 CDP 拉取脚本（配合 debugger.list_scripts）。输出超长自动截断，支持 startLine/endLine 分段阅读。" +
                    "新增 aroundLine/aroundColumn：传 debugger.search_script / search_in_content 返回的原始行/列坐标，直接返回该位置格式化后的可读代码窗口（不再需要人工换算行号）",
                ToolCategory.JAVASCRIPT,
                PermissionScope.READ_PAGE, RiskLevel.LOW, timeoutMs = 60_000,
                inputSchema = Schemas.objectSchema(
                    "source" to Schemas.strSchema("JS 源码（与 scriptIdOrUrl 二选一）"),
                    "scriptIdOrUrl" to Schemas.strSchema("脚本 scriptId 或 URL 子串（来自 debugger.list_scripts；需要 CDP 已附加，未附加会自动尝试）"),
                    "aroundLine" to Schemas.intSchema("原始（格式化前）源码行号 1-based——直接传 debugger.search_script 命中的 lineNumber，返回该处在格式化结果中的位置及前后 aroundContextLines 行"),
                    "aroundColumn" to Schemas.intSchema("原始源码列号 0-based（可选，配合 aroundLine 精确定位，minified 单行脚本必传才有意义）"),
                    "aroundContextLines" to Schemas.intSchema("aroundLine 模式下锚点前后各返回的行数（默认 60）"),
                    "renameObfuscated" to Schemas.boolSchema("把 _0x 十六进制混淆标识符重命名为 v1/v2/...（默认 true）"),
                    "indentSize" to Schemas.intSchema("缩进空格数（默认 2，可选 2/4/8）"),
                    "maxChars" to Schemas.intSchema("返回最大字符数（默认 150000，上限 400000）"),
                    "startLine" to Schemas.intSchema("格式化结果的起始行号（1-based，用于分段阅读长文件；aroundLine 模式下忽略）"),
                    "endLine" to Schemas.intSchema("格式化结果的结束行号（1-based，含端点；aroundLine 模式下忽略）"),
                ),
            ) { args ->
                var source = ToolArgs.str(args, "source")
                val scriptIdOrUrl = ToolArgs.str(args, "scriptIdOrUrl")
                val session = deps.activeSession()

                // 源码获取：scriptIdOrUrl（CDP）优先
                var resolvedFrom = "inline"
                if (scriptIdOrUrl.isNotBlank()) {
                    if (deps.debuggerManager.backend != "cdp") {
                        runCatching { deps.debuggerManager.attach(session.engine) }
                    }
                    if (deps.debuggerManager.backend != "cdp") {
                        return@tool McpToolResult.error("CDP_NOT_ATTACHED", "scriptIdOrUrl 需要 CDP 会话；或改传 source 参数")
                    }
                    // scriptId 精确匹配优先，否则按 URL 子串取最大脚本
                    val scripts = deps.debuggerManager.listScripts(session.engine)
                    val target = scripts.firstOrNull { it.scriptId == scriptIdOrUrl }
                        ?: scripts.filter { it.url.isNotBlank() && it.url.contains(scriptIdOrUrl) }
                            .maxByOrNull { it.length }
                        ?: return@tool McpToolResult.error("SCRIPT_NOT_FOUND", "未找到脚本：$scriptIdOrUrl（先 debugger.list_scripts）")
                    source = deps.debuggerManager.getScriptSource(session.engine, target.scriptId, 2_000_000)
                        .getOrNull()
                        ?: return@tool McpToolResult.error("SCRIPT_SOURCE_UNAVAILABLE", "脚本源码拉取失败（旧 scriptId 可能已失效，重新 list_scripts）")
                    resolvedFrom = target.url.ifBlank { target.scriptId }
                } else if (source.isBlank()) {
                    return@tool McpToolResult.error("INVALID_ARGUMENTS", "source 与 scriptIdOrUrl 至少提供一个")
                }

                val rename = ToolArgs.bool(args, "renameObfuscated", true)
                val indentSize = ToolArgs.int(args, "indentSize", 2).let { if (it in listOf(2, 4, 8)) it else 2 }
                val maxChars = ToolArgs.int(args, "maxChars", 150_000).coerceIn(10_000, 400_000)
                val startLine = ToolArgs.int(args, "startLine", 1).coerceAtLeast(1)
                val endLineArg = ToolArgs.int(args, "endLine", 0)
                val aroundLine = ToolArgs.int(args, "aroundLine", 0).coerceAtLeast(0)
                val aroundColumn = ToolArgs.int(args, "aroundColumn", -1)
                val aroundCtx = ToolArgs.int(args, "aroundContextLines", 60).coerceIn(5, 500)

                val r = com.webreverse.mcp.javascript.parser.JsFormatter(
                    indentSize = indentSize,
                    renameObfuscated = rename,
                    maxOutputChars = 2_000_000, // 分页截断在行级做，这里先放开
                ).format(source)

                // 行级分页
                val allLines = r.formatted.split('\n')
                val totalLines = allLines.size

                // aroundLine/aroundColumn：原始坐标 → 格式化行号映射。
                // 实测痛点：search_script 在 minified 脚本上命中的永远是「第 1 行第 N 列」，
                // AI 拿着这个坐标面对格式化后的几千行输出完全无法定位，只能整段重读。
                // 现在由 formatter 记录的行首偏移表直接换算，返回锚点前后窗口 + 锚点预览。
                var anchor: JsonObject? = null
                val from: Int
                val to: Int
                if (aroundLine > 0) {
                    fun originalOffset(line1Based: Int, column0Based: Int): Int {
                        var remaining = line1Based - 1
                        var idx = 0
                        while (remaining > 0 && idx < source.length) {
                            if (source[idx] == '\n') remaining--
                            idx++
                        }
                        if (remaining > 0) return source.length
                        return (idx + column0Based.coerceAtLeast(0)).coerceAtMost(source.length)
                    }
                    val offset = originalOffset(aroundLine, aroundColumn)
                    val fmtLine = r.formattedLineFor(offset).let { if (it <= 0) 1 else it.coerceAtMost(totalLines) }
                    anchor = buildJsonObject {
                        put("originalLine", JsonPrimitive(aroundLine))
                        put("originalColumn", JsonPrimitive(aroundColumn.coerceAtLeast(0)))
                        put("formattedLine", JsonPrimitive(fmtLine))
                        put("linePreview", JsonPrimitive(allLines[fmtLine - 1].trim().take(200)))
                    }
                    from = (fmtLine - aroundCtx - 1).coerceAtLeast(0)
                    to = (fmtLine + aroundCtx).coerceAtMost(totalLines)
                } else {
                    from = (startLine - 1).coerceIn(0, totalLines - 1)
                    to = (if (endLineArg > 0) endLineArg else totalLines).coerceIn(from + 1, totalLines)
                }
                val paged = allLines.subList(from, to).joinToString("\n")
                val truncated = paged.length > maxChars
                val output = if (truncated) paged.take(maxChars) else paged

                McpToolResult.json(
                    buildJsonObject {
                        put("sourceFrom", JsonPrimitive(resolvedFrom))
                        put("originalChars", JsonPrimitive(r.originalChars))
                        put("formattedChars", JsonPrimitive(r.formattedChars))
                        put("totalLines", JsonPrimitive(totalLines))
                        if (anchor != null) {
                            put("anchor", anchor)
                            put("anchorHint", JsonPrimitive("原始 ${aroundLine}:${aroundColumn.coerceAtLeast(0)} 位于返回窗口内格式化后的第 ${anchor["formattedLine"]} 行（相对窗口起点偏移 ${((anchor["formattedLine"]?.jsonPrimitive?.intOrNull ?: 1) - from - 1)} 行），锚点行内容见 anchor.linePreview"))
                        }
                        put("lines", buildJsonObject {
                            put("start", JsonPrimitive(from + 1))
                            put("end", JsonPrimitive(to))
                        })
                        put("truncated", JsonPrimitive(truncated))
                        if (truncated) put("truncationHint", JsonPrimitive("已截断到 $maxChars 字符；用 startLine/endLine 翻页继续读"))
                        if (r.degraded) put("degraded", JsonPrimitive(true))
                        if (r.renameMap.isNotEmpty()) {
                            put("renamedCount", JsonPrimitive(r.renameMap.size))
                            // 映射表最多回传 200 条，防止又变成大响应
                            put("renames", buildJsonObject {
                                r.renameMap.entries.take(200).forEach { (k, v) -> put(k, JsonPrimitive(v)) }
                            })
                        }
                        put("formatted", JsonPrimitive(output))
                    },
                )
            },
            f.tool(
                "js.detect_obfuscation", "检测 JS 混淆程度并输出报告", ToolCategory.JAVASCRIPT,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("source" to Schemas.strSchema("JS 源码")),
            ) { args ->
                val source = ToolArgs.str(args, "source")
                if (source.isBlank()) return@tool McpToolResult.error("INVALID_ARGUMENTS", "source 不能为空")
                val report = deps.obfuscationAnalyzer.analyze(source)
                McpToolResult.json(
                    buildJsonObject {
                        put("score", JsonPrimitive(report.score))
                        put("isObfuscated", JsonPrimitive(report.isObfuscated))
                        put("isMinified", JsonPrimitive(report.isMinified))
                        put("entropy", JsonPrimitive(report.entropy))
                        put("identifierCount", JsonPrimitive(report.identifierCount))
                        put("stringArrayCount", JsonPrimitive(report.stringArrayCount))
                        put("controlFlowFlattening", JsonPrimitive(report.controlFlowFlattening))
                        put("antiDebug", JsonPrimitive(report.antiDebug))
                        put("dynamicCode", JsonPrimitive(report.dynamicCode))
                        put("selfIntegrityCheck", JsonPrimitive(report.selfIntegrityCheck))
                        put("environmentDetection", JsonPrimitive(report.environmentDetection))
                        put("detected", JsonArray(report.detected.map { JsonPrimitive(it) }))
                    },
                )
            },
            f.tool(
                "js.extract_strings", "提取 JS 源码中的所有字符串", ToolCategory.JAVASCRIPT,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("source" to Schemas.strSchema("JS 源码")),
            ) { args ->
                val source = ToolArgs.str(args, "source")
                val strings = deps.jsParser.extractStrings(source)
                McpToolResult.json(
                    buildJsonObject {
                        put("count", JsonPrimitive(strings.size))
                        put("strings", JsonArray(strings.take(1000).map { JsonPrimitive(it) }))
                    },
                )
            },
            f.tool(
                "js.extract_urls", "提取 JS 源码中的所有 URL", ToolCategory.JAVASCRIPT,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("source" to Schemas.strSchema("JS 源码")),
            ) { args ->
                val source = ToolArgs.str(args, "source")
                val urls = deps.jsParser.extractUrls(source)
                McpToolResult.json(
                    buildJsonObject {
                        put("count", JsonPrimitive(urls.size))
                        put("urls", JsonArray(urls.map { JsonPrimitive(it) }))
                    },
                )
            },
            f.tool(
                "js.search_source", "在 JS 源码中搜索模式", ToolCategory.JAVASCRIPT,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "source" to Schemas.strSchema("JS 源码"),
                    "pattern" to Schemas.strSchema("搜索模式（支持正则）"),
                ),
            ) { args ->
                val source = ToolArgs.str(args, "source")
                val pattern = ToolArgs.str(args, "pattern")
                if (pattern.isBlank()) return@tool McpToolResult.error("INVALID_ARGUMENTS", "pattern 不能为空")
                val matches = deps.jsParser.detectPatterns(source, listOf(pattern))
                val occurrences = matches.firstOrNull()?.matches ?: emptyList()
                McpToolResult.json(
                    buildJsonObject {
                        put("count", JsonPrimitive(occurrences.size))
                        put(
                            "matches",
                            JsonArray(
                                occurrences.take(200).map { m ->
                                    buildJsonObject {
                                        put("value", JsonPrimitive(m.value.take(200)))
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
                "js.find_function", "查找 JS 源码中的函数定义", ToolCategory.JAVASCRIPT,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "source" to Schemas.strSchema("JS 源码"),
                    "name" to Schemas.strSchema("函数名"),
                ),
            ) { args ->
                val source = ToolArgs.str(args, "source")
                val name = ToolArgs.str(args, "name")
                val functions = deps.jsParser.extractFunctions(source)
                val filtered = if (name.isBlank()) functions else functions.filter { it.name.contains(name, ignoreCase = true) }
                McpToolResult.json(
                    buildJsonObject {
                        put(
                            "functions",
                            JsonArray(
                                filtered.take(100).map { fn ->
                                    buildJsonObject {
                                        put("name", JsonPrimitive(fn.name))
                                        put("params", JsonPrimitive(fn.params.joinToString(",")))
                                        put("line", JsonPrimitive(fn.line))
                                        put("body", JsonPrimitive(fn.body.take(500)))
                                    }
                                },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "js.find_symbol", "查找 JS 源码中的标识符/符号", ToolCategory.JAVASCRIPT,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "source" to Schemas.strSchema("JS 源码"),
                    "symbol" to Schemas.strSchema("符号名"),
                ),
            ) { args ->
                val source = ToolArgs.str(args, "source")
                val symbol = ToolArgs.str(args, "symbol")
                val matches = deps.jsParser.detectPatterns(source, listOf(symbol))
                val occurrences = matches.firstOrNull()?.matches ?: emptyList()
                McpToolResult.json(
                    buildJsonObject {
                        put("count", JsonPrimitive(occurrences.size))
                        put(
                            "matches",
                            JsonArray(
                                occurrences.take(200).map { m ->
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
                "js.detect_patterns", "检测危险/动态 JS 模式（eval/Function/atob 等）", ToolCategory.JAVASCRIPT,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("source" to Schemas.strSchema("JS 源码")),
            ) { args ->
                val source = ToolArgs.str(args, "source")
                val patterns = deps.jsParser.detectDangerousPatterns(source)
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
                "js.get_page_source", "获取当前页面所有脚本源码（内联脚本全文；外链脚本用 debugger.get_script_source 取）", ToolCategory.JAVASCRIPT,
                PermissionScope.READ_PAGE, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "maxChars" to Schemas.intSchema("总字符预算（默认 200000；超出截断并打标，防撑爆上下文）"),
                ),
            ) { args ->
                val session = deps.activeSession()
                // 加总预算（原每脚本 50K × 数十个脚本可达 MB 级）
                val budget = ToolArgs.int(args, "maxChars", 200_000).coerceIn(10_000, 400_000)
                val result = session.engine.evaluateJavascript(
                    "(function(){var out=[];document.querySelectorAll('script').forEach(function(s){if(!s.src){out.push({src:'(inline)',content:(s.textContent||'').substring(0,50000)})}else{out.push({src:s.src,content:''})}});return JSON.stringify(out.slice(0,50))})()",
                ) ?: "[]"
                val trimmed = if (result.length > budget) result.take(budget) + "\"…[截断：共 ${result.length} 字符，超出 $budget 预算]}\"" else result
                McpToolResult.text(trimmed)
            },
            f.tool(
                "js.console", "向页面控制台输出消息", ToolCategory.JAVASCRIPT,
                PermissionScope.EXECUTE_JS, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "level" to Schemas.strSchema("log/warn/error/info"),
                    "message" to Schemas.strSchema("消息内容"),
                ),
            ) { args ->
                val level = ToolArgs.str(args, "level", "log")
                val message = ToolArgs.str(args, "message")
                val session = deps.activeSession()
                session.engine.evaluateJavascript("console.$level(${JsQuote(message)})")
                McpToolResult.text("已输出到控制台")
            },
            f.tool(
                "js.deobfuscate",
                "动态脱壳：在页面上下文调用混淆脚本的字符串解密函数批量还原字面量（_0x1234('0x1a') -> \"明文\"），并做字符串拼接折叠/噪音剥离",
                ToolCategory.JAVASCRIPT,
                PermissionScope.EXECUTE_JS, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "source" to Schemas.strSchema("待脱壳源码（留空则自动取页面最大混淆脚本）"),
                    "scriptId" to Schemas.strSchema("脚本 ID（来自 debugger.list_scripts，优先于 source）"),
                    "foldConcat" to Schemas.boolSchema("字符串拼接折叠（默认 true）"),
                    "removeDebugger" to Schemas.boolSchema("剥离 debugger/console 噪音（默认 false）"),
                    "maxChars" to Schemas.intSchema("返回最大字符数（默认 200000）"),
                ),
            ) { args ->
                var source = ToolArgs.str(args, "source")
                val scriptId = ToolArgs.str(args, "scriptId")
                val session = deps.activeSession()
                if (scriptId.isNotBlank()) {
                    if (deps.debuggerManager.backend != "cdp") return@tool McpToolResult.error("CDP_NOT_ATTACHED", "scriptId 需要 CDP 会话")
                    source = deps.debuggerManager.getScriptSource(session.engine, scriptId, 2_000_000).getOrNull()
                        ?: return@tool McpToolResult.error("SCRIPT_NOT_FOUND", "scriptId 不存在")
                } else if (source.isBlank()) {
                    val raw = session.engine.evaluateJavascript(
                        "(function(){var s='',m=0;document.querySelectorAll('script[src]');" +
                            "var scripts=performance.getEntriesByType('resource').filter(function(e){return e.initiatorType==='script'});" +
                            "return JSON.stringify(scripts.map(function(e){return e.name}).slice(0,20));})()",
                    ) ?: "[]"
                    return@tool McpToolResult.error(
                        "SOURCE_REQUIRED",
                        "请提供 source（内联脚本全文）或 scriptId（CDP）。页面脚本清单：$raw",
                    )
                }
                // 求值回调：CDP 优先（returnByValue），降级 evaluateJavascript（eval 在全局上下文解密函数可达时可用）
                val evaluate: suspend (String) -> String? = { expr ->
                    val viaCdp = deps.debuggerManager.runtimeEvaluate(session.engine, expr, awaitPromise = false).getOrNull()
                    val cdpOk = (viaCdp?.get("ok") as? kotlinx.serialization.json.JsonPrimitive)?.content == "true"
                    if (cdpOk) {
                        (viaCdp?.get("value") as? kotlinx.serialization.json.JsonPrimitive)?.content
                    } else {
                        session.engine.evaluateJavascript(expr)
                    }
                }
                val deob = com.webreverse.mcp.javascript.analysis.Deobfuscator(evaluate).deobfuscate(
                    source = source,
                    foldConcat = ToolArgs.bool(args, "foldConcat", true),
                    removeDebugger = ToolArgs.bool(args, "removeDebugger", false),
                )
                val maxChars = ToolArgs.int(args, "maxChars", 200_000)
                McpToolResult.json(
                    buildJsonObject {
                        put("originalLength", JsonPrimitive(source.length))
                        put("resultLength", JsonPrimitive(deob.code.length))
                        put("stringsDecrypted", JsonPrimitive(deob.stringCallsDecrypted))
                        put("stringsFolded", JsonPrimitive(deob.stringsFolded))
                        put("noiseRemoved", JsonPrimitive(deob.debuggerRemoved))
                        put("notes", JsonPrimitive(deob.notes.joinToString("; ").take(500)))
                        put("code", JsonPrimitive(deob.code.take(maxChars)))
                    },
                )
            },
        )
    }

    private fun JsQuote(s: String): String =
        "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + "\""

    /** 从 Program 收集所有具名函数（顶层声明 + 绑定到 var/const 的匿名函数），供 js.ast 输出 */
    private fun collectAstFunctions(program: Program): List<JsFunction> {
        val out = mutableListOf<JsFunction>()
        val seen = mutableSetOf<String>()
        fun push(list: MutableList<JsFunction>, s: MutableSet<String>, fn: JsFunction) {
            if (seen.add(fn.name.ifBlank { "@${fn.pos.offset}" })) list.add(fn)
        }
        fun collectExpr(e: com.webreverse.mcp.javascript.analysis.Expr) {
            if (e is com.webreverse.mcp.javascript.analysis.Expr.FunctionExpr && !e.name.isNullOrBlank()) e.name?.let { name ->
                push(out, seen, JsFunction(name, e.params, e.body, e.pos, e.isArrow))
            }
            if (e is com.webreverse.mcp.javascript.analysis.Expr.Call) {
                e.args.forEach { collectExpr(it) }
            }
        }
        fun collectStmt(s: Stmt) {
            when (s) {
                is Stmt.VarDecl -> {
                    val init = s.init
                    if (init is com.webreverse.mcp.javascript.analysis.Expr.FunctionExpr) {
                        push(out, seen, JsFunction(s.name, init.params, init.body, init.pos, init.isArrow))
                    } else if (init != null) collectExpr(init)
                }
                is Stmt.ExprStmt -> collectExpr(s.expr)
                is Stmt.If -> { collectStmt(s.thenBody); s.elseBody?.let { collectStmt(it) } }
                is Stmt.For -> { s.init?.let { collectStmt(it) }; collectStmt(s.body) }
                is Stmt.ForEach -> collectStmt(s.body)
                is Stmt.While -> collectStmt(s.body)
                is Stmt.DoWhile -> collectStmt(s.body)
                is Stmt.Switch -> s.cases.forEach { c -> c.body.forEach { collectStmt(it) } }
                is Stmt.Block -> s.stmts.forEach { collectStmt(it) }
                else -> {}
            }
        }
        for (tl in program.body) {
            when (tl) {
                is TopLevel.Function -> push(out, seen, tl.fn)
                is TopLevel.Statement -> collectStmt(tl.stmt)
            }
        }
        return out
    }

    private fun renderTopLevel(tl: TopLevel): String = when (tl) {
        is TopLevel.Function -> "function ${tl.fn.name}(...) @${tl.pos.line}"
        is TopLevel.Statement -> AstRender.stmt(tl.stmt)
    }
}
