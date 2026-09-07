package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import com.webreverse.mcp.javascript.analysis.DecryptSimulator
import com.webreverse.mcp.javascript.analysis.JsCfgBuilder
import com.webreverse.mcp.javascript.analysis.JsDfgAnalyzer
import com.webreverse.mcp.javascript.analysis.StaticAnalyzer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.put

/**
 * 静态深度分析工具链 v1（ 新增）。
 *
 * 面向逆向的函数级静态分析：
 * - static.analyze：一键全量画像（调用图 + 复杂度 + 解密链 + 敏感数据流）
 * - static.callgraph：函数调用图（支持 callers 反查）
 * - static.complexity：圈复杂度排行（定位混淆核心逻辑）
 * - static.decrypt_chain：字符串解密链（javascript-obfuscator 三件套还原）
 * - static.sensitive_flow：敏感数据流（cookie/token/localStorage 读写点）
 */
object StaticTools {

    private suspend fun ensureAttached(deps: ToolDependencies) {
        if (deps.debuggerManager.backend != "cdp") {
            val session = deps.activeSession()
            deps.debuggerManager.attach(session.engine)
        }
    }

    /** 取页面源码：CDP 最大脚本（JS 逆向主战场），失败回退 HTML */
    private suspend fun resolveSource(deps: ToolDependencies): Pair<String, String> { // (source, kind)
        val session = deps.activeSession()
        if (deps.debuggerManager.backend == "cdp") {
            val scripts = deps.debuggerManager.listScripts(session.engine)
                .filter { it.url.isNotBlank() && it.length > 1000 }
            val target = scripts.maxByOrNull { it.length }
            if (target != null) {
                val src = deps.debuggerManager.getScriptSource(session.engine, target.scriptId, 4_000_000).getOrNull()
                if (!src.isNullOrBlank() && src.length > 500) return src to "script:${target.url.takeLast(80)}"
            }
        }
        val html = session.engine.getPageSource() ?: return "" to "none"
        return html to "html"
    }

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)

        suspend fun sourceArg(args: kotlinx.serialization.json.JsonObject): Pair<String, String>? {
            val inline = ToolArgs.str(args, "source")
            if (inline.isNotBlank()) return inline to "inline"
            return resolveSource(deps).takeIf { it.first.isNotBlank() }
        }

        return listOf(
            f.tool(
                "static.analyze",
                "静态全量画像：函数级调用图 + 圈复杂度排行 + 字符串解密链识别 + 敏感数据流定位（一次拿到逆向起点的全套静态情报）",
                ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "source" to Schemas.strSchema("直接传入 JS 源码（优先；适合 file.read 离线分析）"),
                ),
                timeoutMs = 60_000,
            ) { args ->
                val (source, kind) = sourceArg(args)
                    ?: return@tool McpToolResult.error("SOURCE_UNAVAILABLE", "无源码可分析")
                val analyzer = StaticAnalyzer()
                val report = analyzer.analyze(source)

                McpToolResult.json(
                    buildJsonObject {
                        put("sourceKind", JsonPrimitive(kind))
                        put("totalLines", JsonPrimitive(report.totalLines))
                        put("functionCount", JsonPrimitive(report.funcStats.size))
                        // 混淆嫌疑函数 Top（复杂度排行）
                        val suspects = report.funcStats.filter { it.isSuspect }
                            .sortedByDescending { it.cyclomatic }.take(15)
                        put("suspectFunctions", JsonArray(suspects.map { s ->
                            buildJsonObject {
                                put("name", JsonPrimitive(s.name))
                                put("line", JsonPrimitive(s.line))
                                put("cyclomatic", JsonPrimitive(s.cyclomatic))
                                put("reasons", JsonArray(s.suspectReasons.map { JsonPrimitive(it) }))
                                put("calls", JsonPrimitive(s.calls.take(15).joinToString(",")))
                            }
                        }))
                        put("callGraph", buildJsonObject {
                            put("edges", JsonPrimitive(report.callGraph.edges))
                            put("hotspots", JsonArray(report.callGraph.hotspots.take(20).map { JsonPrimitive(it) }))
                            put("orphans", JsonArray(report.callGraph.orphans.take(20).map { JsonPrimitive(it) }))
                        })
                        put("decryptChain", buildJsonObject {
                            put("found", JsonPrimitive(report.decryptChain.found))
                            if (report.decryptChain.found) {
                                put("arrayName", JsonPrimitive(report.decryptChain.arrayName))
                                put("arraySize", JsonPrimitive(report.decryptChain.arraySize))
                                put("decoderName", JsonPrimitive(report.decryptChain.decoderName))
                                put("offsetsPattern", JsonPrimitive(report.decryptChain.offsetsPattern))
                                put("arrayPreview", JsonArray(report.decryptChain.arrayPreview.take(20).map { JsonPrimitive(it) }))
                                put("callSites", report.decryptChain.decodeCallSites.size)
                            }
                        })
                        put("sensitiveFlow", buildJsonObject {
                            put("reads", JsonArray(report.sensitiveFlow.reads.take(15).map { r ->
                                buildJsonObject {
                                    put("kind", JsonPrimitive(r.kind)); put("line", JsonPrimitive(r.line))
                                    put("context", JsonPrimitive(r.context.take(120)))
                                }
                            }))
                            put("writes", JsonArray(report.sensitiveFlow.writes.take(15).map { w ->
                                buildJsonObject {
                                    put("kind", JsonPrimitive(w.kind)); put("line", JsonPrimitive(w.line))
                                    put("context", JsonPrimitive(w.context.take(120)))
                                }
                            }))
                        })
                    },
                )
            },

            f.tool(
                "static.callgraph",
                "函数调用图：caller -> callees 邻接表 + 被调热点 + 孤儿函数；支持 callers 反查「谁调用了目标函数」",
                ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "source" to Schemas.strSchema("直接传入 JS 源码（可选）"),
                    "trace" to Schemas.strSchema("反查该函数的调用链（callers，如 sign；与全图模式二选一）"),
                ),
                timeoutMs = 60_000,
            ) { args ->
                val (source, kind) = sourceArg(args)
                    ?: return@tool McpToolResult.error("SOURCE_UNAVAILABLE", "无源码可分析")
                val analyzer = StaticAnalyzer()
                val report = analyzer.analyze(source)
                val trace = ToolArgs.str(args, "trace")
                if (trace.isNotBlank()) {
                    val chain = analyzer.traceCallers(report.callGraph, trace)
                    return@tool McpToolResult.json(
                        buildJsonObject {
                            put("target", JsonPrimitive(trace))
                            put("callChain", JsonArray(chain.map { JsonPrimitive(it) }))
                            put("directCallers", JsonArray(
                                (report.callGraph.callers[trace] ?: emptyList()).take(20).map { JsonPrimitive(it) },
                            ))
                        },
                    )
                }
                val text = buildString {
                    appendLine("调用图：${report.callGraph.functions} 函数 / ${report.callGraph.edges} 边（源：$kind）")
                    appendLine()
                    appendLine("被调热点（多调用者，优先逆向入口）：")
                    report.callGraph.hotspots.take(15).forEach { h ->
                        val callers = report.callGraph.callers[h]?.take(5)?.joinToString(", ")
                        appendLine("  $h  <- [$callers]")
                    }
                    appendLine()
                    appendLine("邻接表（前 40 函数）：")
                    report.callGraph.adjacency.entries.take(40).forEach { (caller, callees) ->
                        appendLine("  $caller -> ${callees.take(10).joinToString(", ")}")
                    }
                }
                McpToolResult.text(text)
            },

            f.tool(
                "static.complexity",
                "圈复杂度排行：高复杂度 + 机器命名的函数即混淆核心逻辑；返回 top 函数的分支统计",
                ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "source" to Schemas.strSchema("直接传入 JS 源码（可选）"),
                    "top" to Schemas.intSchema("返回前 N 个（默认 30）"),
                ),
                timeoutMs = 60_000,
            ) { args ->
                val (source, _) = sourceArg(args)
                    ?: return@tool McpToolResult.error("SOURCE_UNAVAILABLE", "无源码可分析")
                val top = ToolArgs.int(args, "top", 30)
                val report = StaticAnalyzer().analyze(source)
                val ranked = report.funcStats.sortedByDescending { it.cyclomatic }.take(top)
                McpToolResult.json(
                    buildJsonObject {
                        put("functions", JsonArray(ranked.map { s ->
                            buildJsonObject {
                                put("name", JsonPrimitive(s.name))
                                put("line", JsonPrimitive(s.line))
                                put("cyclomatic", JsonPrimitive(s.cyclomatic))
                                put("branches", JsonPrimitive(s.branches))
                                put("switchCases", JsonPrimitive(s.switchCount))
                                put("loops", JsonPrimitive(s.loops))
                                put("bodyBytes", JsonPrimitive(s.bodyLength))
                                put("suspect", JsonPrimitive(s.isSuspect))
                            }
                        }))
                    },
                )
            },

            f.tool(
                "static.decrypt_chain",
                "字符串解密链分析：识别「字符串数组 + 解码函数 + 引用点」三件套（javascript-obfuscator 标准布局），输出引用点的可还原字符串",
                ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "source" to Schemas.strSchema("直接传入 JS 源码（可选）"),
                    "resolve" to Schemas.boolSchema("输出前 60 个引用点的解码猜测（默认 true）"),
                ),
                timeoutMs = 60_000,
            ) { args ->
                val (source, _) = sourceArg(args)
                    ?: return@tool McpToolResult.error("SOURCE_UNAVAILABLE", "无源码可分析")
                val resolve = ToolArgs.bool(args, "resolve", true)
                val report = StaticAnalyzer().analyze(source)
                val chain = report.decryptChain
                if (!chain.found) {
                    return@tool McpToolResult.json(
                        buildJsonObject {
                            put("found", JsonPrimitive(false))
                            put("hint", JsonPrimitive("未发现字符串数组布局（可能未混淆或使用其他混淆器）；可尝试 dynamic.trace_function 动态观测"))
                        },
                    )
                }
                McpToolResult.json(
                    buildJsonObject {
                        put("found", JsonPrimitive(true))
                        put("arrayName", JsonPrimitive(chain.arrayName))
                        put("arraySize", JsonPrimitive(chain.arraySize))
                        put("decoderName", JsonPrimitive(chain.decoderName))
                        put("offsetsPattern", JsonPrimitive(chain.offsetsPattern))
                        put("arrayPreview", JsonArray(chain.arrayPreview.take(30).map { JsonPrimitive(it) }))
                        put("decoderBody", JsonPrimitive(chain.decoderBody))
                        if (resolve) {
                            put("callSites", JsonArray(chain.decodeCallSites.take(60).map { cs ->
                                buildJsonObject {
                                    put("line", JsonPrimitive(cs.line))
                                    put("expression", JsonPrimitive(cs.expression))
                                    put("decodedGuess", JsonPrimitive(cs.decodedGuess))
                                }
                            }))
                        }
                    },
                )
            },

            f.tool(
                "static.sensitive_flow",
                "敏感数据流定位：cookie/token/localStorage/密码的读写点（含行号与上下文），配合 hook 动态验证",
                ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "source" to Schemas.strSchema("直接传入 JS 源码（可选）"),
                ),
                timeoutMs = 60_000,
            ) { args ->
                val (source, _) = sourceArg(args)
                    ?: return@tool McpToolResult.error("SOURCE_UNAVAILABLE", "无源码可分析")
                val report = StaticAnalyzer().analyze(source)
                McpToolResult.json(
                    buildJsonObject {
                        put("reads", JsonArray(report.sensitiveFlow.reads.map { r ->
                            buildJsonObject {
                                put("kind", JsonPrimitive(r.kind)); put("line", JsonPrimitive(r.line))
                                put("context", JsonPrimitive(r.context))
                            }
                        }))
                        put("writes", JsonArray(report.sensitiveFlow.writes.map { w ->
                            buildJsonObject {
                                put("kind", JsonPrimitive(w.kind)); put("line", JsonPrimitive(w.line))
                                put("context", JsonPrimitive(w.context))
                            }
                        }))
                    },
                )
            },

            // 解密链本地真实还原（离线模拟，纯 Kotlin）
            f.tool(
                "static.decrypt_resolve",
                "解密链真实还原（本地模拟）：识别解码器原型（索引偏移/base64/常量异或/位移）后逐一还原调用点明文——离线可用、零页面依赖；未命中原型时提示用 decrypt_execute 兜底",
                ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "source" to Schemas.strSchema("直接传入 JS 源码（推荐；解密链分析需要完整源码）"),
                    "maxSites" to Schemas.intSchema("最多还原调用点数（默认 100）"),
                ),
                timeoutMs = 60_000,
            ) { args ->
                val (source, kind) = sourceArg(args)
                    ?: return@tool McpToolResult.error("SOURCE_UNAVAILABLE", "无源码可分析（建议直接传 source）")
                val maxSites = ToolArgs.int(args, "maxSites", 100).coerceIn(1, 300)
                val result = DecryptSimulator().simulate(source, maxSites)
                if (!result.found) {
                    return@tool McpToolResult.json(
                        buildJsonObject {
                            put("found", JsonPrimitive(false))
                            put("notes", JsonArray(result.notes.map { JsonPrimitive(it) }))
                        },
                    )
                }
                McpToolResult.json(
                    buildJsonObject {
                        put("found", JsonPrimitive(true))
                        put("sourceKind", JsonPrimitive(kind))
                        put("arrayName", JsonPrimitive(result.arrayName))
                        put("decoderName", JsonPrimitive(result.decoderName))
                        put("decoderArchetype", JsonPrimitive(result.decoderArchetype))
                        put("totalSites", JsonPrimitive(result.totalSites))
                        put("resolvedCount", JsonPrimitive(result.resolved.size))
                        put("unresolvedCount", JsonPrimitive(result.unresolvedCount))
                        put("resolved", JsonArray(result.resolved.take(maxSites).map { r ->
                            buildJsonObject {
                                put("line", JsonPrimitive(r.line))
                                put("expression", JsonPrimitive(r.expression))
                                put("value", JsonPrimitive(r.value))
                                put("method", JsonPrimitive(r.method.display))
                                put("confidence", JsonPrimitive(r.confidence))
                            }
                        }))
                        put("notes", JsonArray(result.notes.map { JsonPrimitive(it) }))
                    },
                )
            },

            // 解密链页面沙箱重执行（任意解码器 100% 还原）
            f.tool(
                "static.decrypt_execute",
                "解密链页面沙箱重执行：把原始字符串数组 + 解码函数在页面 IIFE 沙箱内重放，逐调用点求值拿真实明文——本地原型不匹配时的终极兜底，可还原任意解码器（RC4/自定义）",
                ToolCategory.REVERSE,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                timeoutMs = 120_000,
                inputSchema = Schemas.objectSchema(
                    "source" to Schemas.strSchema("直接传入 JS 源码（推荐；需含数组与解码函数原文）"),
                ),
            ) { args ->
                val (source, kind) = sourceArg(args)
                    ?: return@tool McpToolResult.error("SOURCE_UNAVAILABLE", "无源码可分析（建议直接传 source）")
                val result = DecryptSimulator().simulate(source, 200)
                if (!result.found || result.sandboxScript.isBlank()) {
                    return@tool McpToolResult.error("NO_DECRYPT_CHAIN", "未识别到解密链三件套，无法生成沙箱脚本")
                }
                // 页面沙箱执行（IIFE 隔离作用域，不污染页面全局）
                val session = deps.activeSession()
                val raw = session.engine.evaluateJavascript(result.sandboxScript)
                    ?: return@tool McpToolResult.error("EVALUATE_FAILED", "沙箱脚本执行失败（页面可能已跳转）")
                // evaluateJavascript 返回外层带引号的 JSON
                val payload = raw.trim().removeSurrounding("\"").replace("\\\"", "\"").replace("\\\\", "\\")
                val parsed = runCatching { Json.parseToJsonElement(payload) as? JsonObject }.getOrNull()
                McpToolResult.json(
                    buildJsonObject {
                        put("sourceKind", JsonPrimitive(kind))
                        put("decoderName", JsonPrimitive(result.decoderName))
                        put("decoderArchetype", JsonPrimitive(result.decoderArchetype))
                        if (parsed != null) {
                            put("sandboxOk", parsed["ok"]?.jsonPrimBool() ?: JsonPrimitive(false))
                            val sandboxError = parsed["error"]?.jsonPrimStr()
                            if (!sandboxError.isNullOrBlank()) put("sandboxError", JsonPrimitive(sandboxError))
                            val resolved = parsed["resolved"] as? JsonArray
                            if (resolved != null) {
                                put("executedCount", JsonPrimitive(resolved.size))
                                put("results", JsonArray(resolved.take(200).map { el ->
                                    val o = el as? JsonObject
                                    buildJsonObject {
                                        put("expr", JsonPrimitive(o?.get("expr")?.jsonPrimStr() ?: ""))
                                        val value = o?.get("value")?.jsonPrimStr()
                                        val err = o?.get("error")?.jsonPrimStr()
                                        if (value != null) put("value", JsonPrimitive(value)) else
                                            put("error", JsonPrimitive(err ?: "?"))
                                    }
                                }))
                            }
                        } else {
                            put("sandboxOk", JsonPrimitive(false))
                            put("raw", JsonPrimitive(payload.take(400)))
                        }
                    },
                )
            },

            // v1.x.0：控制流图（基本块/边/支配/回边/圈复杂度）
            f.tool(
                "static.cfg",
                "控制流图分析：基于递归下降 AST 为每个函数构建基本块与有向边，计算支配关系、循环回边与圈复杂度——定位混淆控制流扁平化/switch 分发器",
                ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "source" to Schemas.strSchema("直接传入 JS 源码（可选）"),
                    "function" to Schemas.strSchema("只看该函数的 cfg（可选）"),
                    "detail" to Schemas.boolSchema("是否输出支配表与完整边（默认 true）"),
                ),
                timeoutMs = 60_000,
            ) { args ->
                val (source, kind) = sourceArg(args)
                    ?: return@tool McpToolResult.error("SOURCE_UNAVAILABLE", "无源码可分析")
                val report = JsCfgBuilder().build(source)
                val detail = ToolArgs.bool(args, "detail", true)
                val only = ToolArgs.str(args, "function")
                val funcs = if (only.isNotBlank()) report.functions.filter { it.name.contains(only, ignoreCase = true) } else report.functions
                McpToolResult.json(
                    buildJsonObject {
                        put("sourceKind", JsonPrimitive(kind))
                        put("totalFunctions", JsonPrimitive(report.totalFunctions))
                        put("totalBlocks", JsonPrimitive(report.totalBlocks))
                        put("totalEdges", JsonPrimitive(report.totalEdges))
                        put(
                            "functions",
                            JsonArray(funcs.take(50).map { c ->
                                buildJsonObject {
                                    put("name", JsonPrimitive(c.name))
                                    put("params", JsonPrimitive(c.params.joinToString(",")))
                                    put("nodes", JsonPrimitive(c.nodes))
                                    put("edges", JsonPrimitive(c.edgeCount))
                                    put("cyclomatic", JsonPrimitive(c.cyclomatic))
                                    put("backEdges", JsonPrimitive(c.backEdges.size))
                                    put(
                                        "blocks",
                                        JsonArray(c.blocks.take(300).map { b ->
                                            buildJsonObject {
                                                put("id", JsonPrimitive(b.id))
                                                put("line", JsonPrimitive(b.line))
                                                put("stmts", JsonArray(b.stmts.map { JsonPrimitive(it.take(120)) }))
                                            }
                                        }),
                                    )
                                    put(
                                        "edges",
                                        JsonArray(c.edges.take(500).map { e ->
                                            buildJsonObject {
                                                put("from", JsonPrimitive(e.from))
                                                put("to", JsonPrimitive(e.to))
                                                put("kind", JsonPrimitive(e.kind))
                                            }
                                        }),
                                    )
                                    if (detail) {
                                        put(
                                            "dominators",
                                            buildJsonObject {
                                                c.dominators.forEach { (id, doms) ->
                                                    val key = "b$id"
                                                    put(key, JsonPrimitive(doms.joinToString(",")))
                                                }
                                            },
                                        )
                                        put(
                                            "immediateDominator",
                                            JsonArray(c.blocks.sortedBy { it.id }.map { b ->
                                                JsonPrimitive("b${b.id}->${c.immediateDominators[b.id]?.let { "b$it" } ?: "entry"}")
                                            }),
                                        )
                                    }
                                }
                            }),
                        )
                    },
                )
            },

            // v1.x.0：数据流（def-use + 敏感污点传播）
            f.tool(
                "static.flow",
                "数据流分析：每个函数的 def-use 对 + 敏感数据污点传播（cookie/localStorage/token/password/atob → eval/fetch/XHR/innerHTML）",
                ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "source" to Schemas.strSchema("直接传入 JS 源码（可选）"),
                    "function" to Schemas.strSchema("只看该函数的 def-use（可选）"),
                    "maxFlows" to Schemas.intSchema("最多返回污点路径数（默认 100）"),
                ),
                timeoutMs = 60_000,
            ) { args ->
                val (source, kind) = sourceArg(args)
                    ?: return@tool McpToolResult.error("SOURCE_UNAVAILABLE", "无源码可分析")
                val report = JsDfgAnalyzer().analyze(source)
                val only = ToolArgs.str(args, "function")
                val maxFlows = ToolArgs.int(args, "maxFlows", 100)
                val funcs = if (only.isNotBlank()) report.functions.filter { it.name.contains(only, ignoreCase = true) } else report.functions
                McpToolResult.json(
                    buildJsonObject {
                        put("sourceKind", JsonPrimitive(kind))
                        put("functionCount", JsonPrimitive(funcs.size))
                        put("sensitiveFlowCount", JsonPrimitive(report.taintFlows.size))
                        put(
                            "taintFlows",
                            JsonArray(report.taintFlows.take(maxFlows).map { f ->
                                buildJsonObject {
                                    put("source", JsonPrimitive(f.source))
                                    put("line", JsonPrimitive(f.line))
                                    put("sink", JsonPrimitive(f.sink))
                                    put("path", JsonArray(f.path.map { JsonPrimitive(it) }))
                                }
                            }),
                        )
                        put(
                            "functions",
                            JsonArray(funcs.take(50).map { f ->
                                buildJsonObject {
                                    put("name", JsonPrimitive(f.name))
                                    put("params", JsonPrimitive(f.params.joinToString(",")))
                                    put(
                                        "defs",
                                        JsonArray(f.defs.take(200).map { d ->
                                            buildJsonObject {
                                                put("variable", JsonPrimitive(d.variable))
                                                put("line", JsonPrimitive(d.line))
                                                put("kind", JsonPrimitive(d.kind))
                                            }
                                        }),
                                    )
                                    put(
                                        "uses",
                                        JsonArray(f.uses.take(200).map { u ->
                                            buildJsonObject {
                                                put("variable", JsonPrimitive(u.variable))
                                                put("line", JsonPrimitive(u.line))
                                            }
                                        }),
                                    )
                                    put(
                                        "defUsePairs",
                                        JsonArray(f.defUsePairs.take(300).map { p ->
                                            buildJsonObject {
                                                put("variable", JsonPrimitive(p.variable))
                                                put("defLine", JsonPrimitive(p.defLine))
                                                put("useLine", JsonPrimitive(p.useLine))
                                            }
                                        }),
                                    )
                                }
                            }),
                        )
                    },
                )
            },
        )
    }

    // evaluateJavascript 原始值辅助（外层引号剥离后的元素仍可能带引号）
    private fun kotlinx.serialization.json.JsonElement?.jsonPrimStr(): String? =
        (this as? JsonPrimitive)?.contentOrNull

    private fun kotlinx.serialization.json.JsonElement?.jsonPrimBool(): JsonPrimitive? =
        (this as? JsonPrimitive)?.let { JsonPrimitive(it.contentOrNull == "true") }
}
