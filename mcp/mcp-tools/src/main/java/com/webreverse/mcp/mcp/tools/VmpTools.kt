package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import com.webreverse.mcp.javascript.analysis.JsCryptoScanner
import com.webreverse.mcp.javascript.analysis.JsvmpDeepAnalyzer
import com.webreverse.mcp.javascript.analysis.JsvmpSemanticRecovery
import com.webreverse.mcp.javascript.analysis.JsvmpSemanticValidator
import com.webreverse.mcp.javascript.analysis.TraceSymbolizer
import com.webreverse.mcp.javascript.analysis.VmpDecompiler
import com.webreverse.mcp.javascript.analysis.VmpTraceCfg
import com.webreverse.mcp.javascript.analysis.VmIrTranslator
import com.webreverse.mcp.javascript.analysis.VmpDetector
import com.webreverse.mcp.javascript.analysis.VmpVariantDiff
import com.webreverse.mcp.javascript.analysis.VpcResolver
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * JSVMP 深度分析工具链 v1（ 新增）。
 *
 * 与 debugger.detect_vmp / trace_vmp（定位 + 采样）互补的结构化分析层：
 * - jsvmp.analyze：完整 VM 画像——handler 语义分类（重建 ISA）+ VM 状态变量
 *   + 指令流载体提取 + 入口提示，一次调用拿到逆向 VM 所需的全套静态情报。
 * - jsvmp.handlers：只取 opcode -> 语义映射表（轻量，LLM 友好）。
 * - jsvmp.classify_handler：对指定 opcode 的 case 体单独分类。
 * - jsvmp.snapshot：运行时 VM 状态快照（pc/sp/ctx 表达式求值）。
 * - jsvmp.ir：通用反虚拟机 IR 翻译——opcode 按 handler 语义归一为平台无关
 *   助记符（LD、ST、ADD/SUB/XOR/MOV/JMP/CJMP/CALL/RET/PUSH/POP/STR2CHAR 等），
 *   输出归一指令流 + opcode->IR 等价表 + 派发矩阵（跨混淆器对比 VM 逻辑差异）。
 */
object VmpTools {

    private suspend fun ensureAttached(deps: ToolDependencies) {
        if (deps.debuggerManager.backend != "cdp") {
            val session = deps.activeSession()
            deps.debuggerManager.attach(session.engine)
        }
    }

    /** 取待分析脚本源码：优先 scriptId，否则取最大脚本 */
    private suspend fun resolveSource(
        deps: ToolDependencies,
        scriptId: String,
    ): Triple<String, String, String>? { // (source, scriptId, url)
        if (deps.debuggerManager.backend != "cdp") return null
        val session = deps.activeSession()
        val scripts = deps.debuggerManager.listScripts(session.engine)
            .filter { it.url.isNotBlank() && it.length > 1000 }
        val target = if (scriptId.isNotBlank()) {
            scripts.firstOrNull { it.scriptId == scriptId }
        } else {
            scripts.maxByOrNull { it.length }
        } ?: return null
        val source = deps.debuggerManager.getScriptSource(session.engine, target.scriptId, 4_000_000).getOrNull()
            ?: return null
        return Triple(source, target.scriptId, target.url)
    }

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)

        return listOf(
            f.tool(
                "jsvmp.analyze",
                "JSVMP 深度分析：handler 语义分类（重建 VM ISA 映射表）+ VM 状态变量识别（pc/sp/ctx/字节码数组）+ 指令流载体提取 + 入口提示；一次调用拿到逆向 JSVMP 的全套静态情报",
                ToolCategory.REVERSE,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "scriptId" to Schemas.strSchema("脚本 ID（来自 debugger.list_scripts；留空则分析最大脚本）"),
                    "source" to Schemas.strSchema("直接传入 JS 源码（与 scriptId 二选一且优先，适合配合 file.read 离线分析）"),
                    "candidateIndex" to Schemas.intSchema("候选序号（detect_vmp 返回多个候选时选择，默认 0=最高分）"),
                ),
            ) { args ->
                val inlineSource = ToolArgs.str(args, "source")
                val scriptId = ToolArgs.str(args, "scriptId")
                val candIdx = ToolArgs.int(args, "candidateIndex", 0)

                val (source, resolvedId, url) = when {
                    inlineSource.isNotBlank() -> Triple(inlineSource, "inline", "inline")
                    else -> {
                        ensureAttached(deps)
                        resolveSource(deps, scriptId)
                            ?: return@tool McpToolResult.error(
                                "SOURCE_UNAVAILABLE",
                                "无 CDP 会话或脚本源码获取失败（可先 debugger.attach，或直接传 source 参数）",
                            )
                    }
                }

                val candidates = VmpDetector().detect(source)
                if (candidates.isEmpty()) {
                    return@tool McpToolResult.error("NO_VMP_FOUND", "未检测到 JSVMP 特征（无 while+switch dispatch 结构）")
                }
                val candidate = candidates.getOrNull(candIdx) ?: candidates.first()
                val analyzer = JsvmpDeepAnalyzer()
                val profile = analyzer.analyze(source, candidate)

                McpToolResult.json(
                    buildJsonObject {
                        put("scriptUrl", JsonPrimitive(url))
                        put("scriptId", JsonPrimitive(resolvedId))
                        put("dispatchLoop", buildJsonObject {
                            put("line", JsonPrimitive(candidate.line))
                            put("column", JsonPrimitive(candidate.column))
                            put("score", JsonPrimitive(candidate.score))
                            put("reasons", JsonArray(candidate.reasons.map { JsonPrimitive(it) }))
                        })
                        put("vmVariables", buildJsonObject {
                            put("pc", JsonArray(profile.variables.pcCandidates.map { JsonPrimitive(it) }))
                            put("sp", JsonArray(profile.variables.spCandidates.map { JsonPrimitive(it) }))
                            put("ctx", JsonArray(profile.variables.ctxCandidates.map { JsonPrimitive(it) }))
                            put("bytecodeArray", JsonArray(profile.variables.bytecodeCandidates.map { JsonPrimitive(it) }))
                            put("dispatchExpr", JsonPrimitive(profile.variables.dispatchExpr))
                        })
                        put("kindHistogram", buildJsonObject {
                            profile.kindHistogram.forEach { (k, v) -> put(k, JsonPrimitive(v)) }
                        })
                        put("handlers", JsonArray(
                            profile.handlers.take(150).map { h ->
                                buildJsonObject {
                                    put("opcode", JsonPrimitive(h.key))
                                    put("kind", JsonPrimitive(h.kind.name))
                                    put("semantics", JsonPrimitive(h.kind.display))
                                    put("confidence", JsonPrimitive(h.confidence))
                                    put("line", JsonPrimitive(h.line))
                                    put("column", JsonPrimitive(h.column))
                                    put("snippet", JsonPrimitive(h.snippet.take(180)))
                                }
                            },
                        ))
                        put("instructions", buildJsonObject {
                            put("carrierType", JsonPrimitive(profile.instructions.carrierType))
                            put("carrierName", JsonPrimitive(profile.instructions.carrierName))
                            put("count", JsonPrimitive(profile.instructions.instructionCount))
                            put("distinctOpcodes", JsonPrimitive(profile.instructions.distinctOpcodes))
                            put("preview", JsonArray(profile.instructions.opcodePreview.take(80).map { JsonPrimitive(it) }))
                        })
                        put("isaSummary", JsonPrimitive(profile.isaSummary))
                        put("entryHints", JsonArray(profile.entryHints.map { JsonPrimitive(it) }))
                    },
                )
            },

            f.tool(
                "vmp.verify",
                "JSVMP 判定可信度校验：输出正/负双向证据 + reliability 分级（high-BENIGN/high/medium/low），" +
                    "供 AI 判断本次家族判定能否直接采信、是否需人工复核（验证度量，防深水还原误投入）",
                ToolCategory.REVERSE,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "scriptId" to Schemas.strSchema("脚本 ID（留空则分析最大脚本）"),
                    "source" to Schemas.strSchema("直接传入 JS 源码（优先，离线即可）"),
                ),
            ) { args ->
                val inlineSource = ToolArgs.str(args, "source")
                val scriptId = ToolArgs.str(args, "scriptId")
                val source = if (inlineSource.isNotBlank()) {
                    inlineSource
                } else {
                    ensureAttached(deps)
                    resolveSource(deps, scriptId)?.first
                        ?: return@tool McpToolResult.error("SOURCE_UNAVAILABLE", "无源码可校验（可先 debugger.attach 或直接传 source）")
                }
                val verdict = VmpDetector().verify(source)
                McpToolResult.json(
                    buildJsonObject {
                        put("family", JsonPrimitive(verdict.family))
                        put("confidence", JsonPrimitive(verdict.confidence))
                        put("reliability", JsonPrimitive(verdict.reliability))
                        put("dispatchStyle", JsonPrimitive(verdict.dispatchStyle))
                        put("supporting", JsonArray(verdict.supporting.map { JsonPrimitive(it) }))
                        put("contradicting", JsonArray(verdict.contradicting.map { JsonPrimitive(it) }))
                        put(
                            "hint",
                            JsonPrimitive(
                                when (verdict.reliability) {
                                    "high-BENIGN" -> "判定为轻/未混淆，无需投入深水还原"
                                    "high" -> "正证据充分且无矛盾，可直接采信家族并开始恢复"
                                    "medium" -> "存在一条反误报证据，建议先人工复核候选再深挖"
                                    else -> "存在强反误报证据，很可能并非真实 JSVMP，警惕误报"
                                },
                            ),
                        )
                    },
                )
            },

            f.tool(
                "jsvmp.handlers",
                "轻量获取 JSVMP opcode -> 语义映射表（LOAD/STORE/ARITH/BRANCH/CALL/RETURN 等分类），LLM 友好格式",
                ToolCategory.REVERSE,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "scriptId" to Schemas.strSchema("脚本 ID（留空则分析最大脚本）"),
                    "source" to Schemas.strSchema("直接传入 JS 源码（优先）"),
                ),
            ) { args ->
                val inlineSource = ToolArgs.str(args, "source")
                val scriptId = ToolArgs.str(args, "scriptId")
                val source = if (inlineSource.isNotBlank()) {
                    inlineSource
                } else {
                    ensureAttached(deps)
                    resolveSource(deps, scriptId)?.first
                        ?: return@tool McpToolResult.error("SOURCE_UNAVAILABLE", "无源码可分析")
                }
                val candidates = VmpDetector().detect(source)
                val candidate = candidates.firstOrNull()
                    ?: return@tool McpToolResult.error("NO_VMP_FOUND", "未检测到 JSVMP 特征")
                val handlers = JsvmpDeepAnalyzer().analyze(source, candidate).handlers
                val text = buildString {
                    appendLine("VM ISA（${handlers.size} opcodes）@ dispatch L${candidate.line}:C${candidate.column}")
                    appendLine("opcode | 语义 | 置信 | case 体")
                    appendLine("-------|------|------|--------")
                    handlers.take(150).forEach { h ->
                        appendLine("${h.key} | ${h.kind.display} | ${h.confidence}% | ${h.snippet.take(100)}")
                    }
                }
                McpToolResult.text(text)
            },

            f.tool(
                "jsvmp.variant_diff",
                "JSVMP 变体指纹与白盒 diff：对比两份 JSVMP 脚本（同站点升级前后 / 换混淆器）的 handler 语义指纹，输出 相同/新增/删除 的语义签名 + HandlerKind 分布位移 + decode 公式变化 + 签名区段（STORE/ARITH/CALL/COMPARE）是否漂移——秒级判断「围绕 key 的还原 patch 是否仍有效、签名主循环搬哪了」。输入用 sourceA/sourceB（配 file.read 离线对比）",
                ToolCategory.REVERSE,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "sourceA" to Schemas.strSchema("A 版 JSVMP 源码（升级前/已还原版本）"),
                    "sourceB" to Schemas.strSchema("B 版 JSVMP 源码（升级后/新版本）"),
                ),
            ) { args ->
                val srcA = ToolArgs.str(args, "sourceA")
                val srcB = ToolArgs.str(args, "sourceB")
                if (srcA.isBlank() || srcB.isBlank()) {
                    return@tool McpToolResult.error("INVALID_INPUT", "需同时提供 sourceA 与 sourceB 两份源码")
                }
                val eng = VmpVariantDiff()
                val pa = eng.profile(srcA, "A")
                val pb = eng.profile(srcB, "B")
                val d = eng.diff(pa, pb)
                if (!d.ok) return@tool McpToolResult.error("NO_VMP_FOUND", d.error)
                McpToolResult.json(
                    buildJsonObject {
                        put("digest", JsonPrimitive(d.digest))
                        put("similarity", JsonPrimitive(d.similarity))
                        put("profileA", buildJsonObject {
                            put("handlerCount", JsonPrimitive(pa.handlerCount))
                            put("decodeFormula", JsonPrimitive(pa.decodeFormulaHint.ifBlank { "未知" }))
                            put("envAccess", JsonArray(pa.envAccess.map { JsonPrimitive(it) }))
                            put("kindHistogram", buildJsonObject { pa.kindHistogram.forEach { (k, v) -> put(k, JsonPrimitive(v)) } })
                        })
                        put("profileB", buildJsonObject {
                            put("handlerCount", JsonPrimitive(pb.handlerCount))
                            put("decodeFormula", JsonPrimitive(pb.decodeFormulaHint.ifBlank { "未知" }))
                            put("envAccess", JsonArray(pb.envAccess.map { JsonPrimitive(it) }))
                            put("kindHistogram", buildJsonObject { pb.kindHistogram.forEach { (k, v) -> put(k, JsonPrimitive(v)) } })
                        })
                        put("diff", buildJsonObject {
                            put("sharedSigs", JsonPrimitive(d.sharedCount))
                            put("addedSigs", JsonPrimitive(d.addedCount))
                            put("removedSigs", JsonPrimitive(d.removedCount))
                            put("signSectionPreserved", JsonPrimitive(d.signSectionPreserved))
                            put("signSectionChanges", JsonArray(d.signSectionChanges.map { JsonPrimitive(it) }))
                            put("decodeFormulaShift", JsonPrimitive((d.decodeFormulaA.ifBlank { "未知" }) + " -> " + d.decodeFormulaB.ifBlank { "未知" }))
                            put("kindShift", buildJsonObject { d.kindShift.forEach { (k, v) -> put(k, JsonPrimitive(v)) } })
                        })
                        put("addedSemanticSigs", JsonArray(d.addedSigs.map { JsonPrimitive(it) }))
                        put("removedSemanticSigs", JsonArray(d.removedSigs.map { JsonPrimitive(it) }))
                        put("sharedSemanticSigs", JsonArray(d.sameSigs.map { JsonPrimitive(it) }))
                    },
                )
            },

            f.tool(
                "jsvmp.snapshot",
                "运行时 VM 状态快照：对指定表达式（如 pc 变量、ctx 数组切片）求值，配合断点暂停态或独立观察；表达式数组形式采集多个寄存器",
                ToolCategory.DEBUGGER,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "expressions" to Schemas.strSchema("表达式数组 JSON（如 [\"pc\",\"sp\",\"ctx.slice(0,16)\"]；留空自动尝试检测到的 pc/sp 候选）"),
                    "scriptId" to Schemas.strSchema("用于自动识别 VM 变量的脚本 ID（留空则最大脚本）"),
                ),
            ) { args ->
                val session = deps.activeSession()
                val exprsJson = ToolArgs.str(args, "expressions")
                val exprs: List<String> = if (exprsJson.isNotBlank()) {
                    runCatching {
                        val arr = kotlinx.serialization.json.Json.parseToJsonElement(exprsJson)
                        (arr as? kotlinx.serialization.json.JsonArray)?.map { (it as JsonPrimitive).content } ?: emptyList()
                    }.getOrDefault(emptyList())
                } else {
                    // 自动：检测 VM 变量候选
                    val scriptId = ToolArgs.str(args, "scriptId")
                    val src = runCatching {
                        ensureAttached(deps)
                        resolveSource(deps, scriptId)?.first
                    }.getOrNull()
                    val candidates = src?.let { VmpDetector().detect(it) } ?: emptyList()
                    val cand = candidates.firstOrNull()
                    if (cand != null && src != null) {
                        val vars = JsvmpDeepAnalyzer().analyze(src, cand).variables
                        (vars.pcCandidates.take(2) + vars.spCandidates.take(1) +
                            vars.ctxCandidates.take(2).map { "$it.slice(0,16)" }).distinct()
                    } else emptyList()
                }
                if (exprs.isEmpty()) {
                    return@tool McpToolResult.error("NO_EXPRESSIONS", "无表达式可求值（未指定且自动检测失败）")
                }
                val script = """
                    (function(){
                      var out = [];
                      ${exprs.joinToString("\n") { e ->
                    "try { var v = eval(${com.webreverse.mcp.browser.engine.util.JsScripts.quote(e)}); out.push({expr: ${com.webreverse.mcp.browser.engine.util.JsScripts.quote(e)}, value: (typeof v === 'object' && v !== null) ? JSON.stringify(v).substring(0, 400) : String(v)}); } catch(err){ out.push({expr: ${com.webreverse.mcp.browser.engine.util.JsScripts.quote(e)}, error: String(err && err.message || err)}); }"
                }}
                      return JSON.stringify({ts: Date.now(), results: out});
                    })()
                """.trimIndent()
                val raw = session.engine.evaluateJavascript(script)
                    ?: return@tool McpToolResult.error("EVALUATE_FAILED", "求值失败")
                McpToolResult.text(raw)
            },

            // JSVMP 反编译器（opcode 序列 -> 伪代码）
            f.tool(
                "jsvmp.decompile",
                "JSVMP 反编译：基于 ISA 语义映射把字节码载体（数组/hex/base64）翻译为伪代码——基本块标签 + 循环回边 + CALL 热点定位；操作数字长可经 arityOverride 迭代精修，是重建 VM 逻辑的临门一脚",
                ToolCategory.REVERSE,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                timeoutMs = 60_000,
                inputSchema = Schemas.objectSchema(
                    "scriptId" to Schemas.strSchema("脚本 ID（留空则分析最大脚本）"),
                    "source" to Schemas.strSchema("直接传入 JS 源码（优先）"),
                    "candidateIndex" to Schemas.intSchema("候选序号（默认 0=最高分）"),
                    "arityOverride" to Schemas.strSchema(
                        "opcode->操作数字长映射 JSON（如 {\"0x1a\":1,\"0x05\":2}；首次可不传看默认效果，根据对齐情况精修后重跑）",
                    ),
                    "maxInstructions" to Schemas.intSchema("最多反汇编指令数（默认 500）"),
                ),
            ) { args ->
                val inlineSource = ToolArgs.str(args, "source")
                val scriptId = ToolArgs.str(args, "scriptId")
                val candIdx = ToolArgs.int(args, "candidateIndex", 0)
                val arityJson = ToolArgs.str(args, "arityOverride")
                val maxIns = ToolArgs.int(args, "maxInstructions", 500).coerceIn(20, 3000)

                val (source, resolvedId, url) = when {
                    inlineSource.isNotBlank() -> Triple(inlineSource, "inline", "inline")
                    else -> {
                        ensureAttached(deps)
                        resolveSource(deps, scriptId)
                            ?: return@tool McpToolResult.error(
                                "SOURCE_UNAVAILABLE",
                                "无 CDP 会话或脚本源码获取失败（可先 debugger.attach，或直接传 source 参数）",
                            )
                    }
                }

                val candidates = VmpDetector().detect(source)
                val candidate = candidates.getOrNull(candIdx) ?: candidates.firstOrNull()
                    ?: return@tool McpToolResult.error("NO_VMP_FOUND", "未检测到 JSVMP 特征（无 while+switch dispatch 结构）")

                val arityOverride: Map<String, Int> = if (arityJson.isNotBlank()) {
                    runCatching {
                        val obj = kotlinx.serialization.json.Json.parseToJsonElement(arityJson) as? kotlinx.serialization.json.JsonObject
                        obj?.mapValues { (_, v) -> (v as? JsonPrimitive)?.content?.toIntOrNull() ?: 1 } ?: emptyMap()
                    }.getOrDefault(emptyMap())
                } else emptyMap()

                val result = VmpDecompiler().decompile(source, candidate, arityOverride, maxIns)
                McpToolResult.json(
                    buildJsonObject {
                        put("scriptUrl", JsonPrimitive(url))
                        put("scriptId", JsonPrimitive(resolvedId))
                        put("ok", JsonPrimitive(result.ok))
                        if (!result.ok) {
                            put("error", JsonPrimitive(result.error))
                            put("runtimeNeeded", JsonPrimitive(result.runtimeNeeded))
                        } else {
                            put("carrierType", JsonPrimitive(result.carrierType))
                            put("carrierName", JsonPrimitive(result.carrierName))
                            put("totalInstructions", JsonPrimitive(result.totalInstructions))
                            put("decodedInstructions", JsonPrimitive(result.decodedInstructions))
                            put("blocks", JsonPrimitive(result.blocks))
                            put("loopBacks", JsonPrimitive(result.loopBacks))
                            // P1-6：decode 公式（判别式非直通时的 byte->opcode 映射）
                            put("decodeFormula", JsonPrimitive(result.decodeFormula))
                            put("decodeTableUsed", JsonPrimitive(result.decodeTableUsed))
                            // P0-3：arity 来源分布（inferred=pc 推进量推断）
                            put("aritySource", buildJsonObject {
                                result.aritySource.entries.groupBy({ it.value }, { it.key }).forEach { (src, keys) ->
                                    put(src, JsonPrimitive(keys.size))
                                }
                            })
                            put("arityUsed", buildJsonObject {
                                result.arityUsed.forEach { (k, v) -> put(k, JsonPrimitive(v)) }
                            })
                            put("unresolvedOpcodes", JsonArray(result.unresolvedOpcodes.map { JsonPrimitive(it) }))
                            put("listing", JsonPrimitive(result.listing.take(90_000)))
                        }
                        // P2-11：LLM 命名提示包（UNKNOWN handler -> 助记名闭环）
                        if (result.namingHints.isNotBlank()) {
                            put("namingHints", JsonPrimitive(result.namingHints.take(4000)))
                        }
                    },
                )
            },

            // 通用反虚拟机 IR 翻译（opcode -> 平台无关 IR 助记符）
            f.tool(
                "jsvmp.ir",
                "通用反虚拟机 IR 翻译：把 JSVMP 的 opcode 按 handler 语义归一为平台无关 IR 助记符（LD_*/ST_*/ADD/SUB/XOR/MOV/JMP/CJMP/CALL/RET/PUSH/POP/STR2CHAR 等），输出归一指令流 + opcode->IR 等价表 + 派发矩阵——跨混淆器对比 VM 逻辑差异的标准接口",
                ToolCategory.REVERSE,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                timeoutMs = 60_000,
                inputSchema = Schemas.objectSchema(
                    "scriptId" to Schemas.strSchema("脚本 ID（留空则分析最大脚本）"),
                    "source" to Schemas.strSchema("直接传入 JS 源码（优先）"),
                    "candidateIndex" to Schemas.intSchema("候选序号（默认 0=最高分）"),
                ),
            ) { args ->
                val inlineSource = ToolArgs.str(args, "source")
                val scriptId = ToolArgs.str(args, "scriptId")
                val candIdx = ToolArgs.int(args, "candidateIndex", 0)

                val (source, resolvedId, url) = when {
                    inlineSource.isNotBlank() -> Triple(inlineSource, "inline", "inline")
                    else -> {
                        ensureAttached(deps)
                        resolveSource(deps, scriptId)
                            ?: return@tool McpToolResult.error(
                                "SOURCE_UNAVAILABLE",
                                "无 CDP 会话或脚本源码获取失败（可先 debugger.attach，或直接传 source 参数）",
                            )
                    }
                }

                val candidates = VmpDetector().detect(source)
                val candidate = candidates.getOrNull(candIdx) ?: candidates.firstOrNull()
                    ?: return@tool McpToolResult.error("NO_VMP_FOUND", "未检测到 JSVMP 特征（无 while+switch dispatch 结构）")

                val profile = JsvmpDeepAnalyzer().analyze(source, candidate)
                val result = VmIrTranslator().translate(source, candidate, profile)

                McpToolResult.json(
                    buildJsonObject {
                        put("scriptUrl", JsonPrimitive(url))
                        put("scriptId", JsonPrimitive(resolvedId))
                        put("ok", JsonPrimitive(result.ok))
                        if (!result.ok) {
                            put("error", JsonPrimitive("静态字节码载体未命中，仅输出等价表；可 trace_vmp 采样运行时 opcode 再归一"))
                        }
                        put("vmName", JsonPrimitive(result.vmName))
                        put("equivalenceMap", buildJsonObject {
                            result.equivalenceMap.entries
                                .sortedBy { it.key.toIntOrNull() ?: 0 }
                                .forEach { (k, v) -> put(k, JsonPrimitive(v)) }
                        })
                        put("dispatchedMatrix", JsonArray(
                            result.dispatchedMatrix.map { e ->
                                buildJsonObject {
                                    put("opcode", JsonPrimitive(e.opcode))
                                    put("key", JsonPrimitive(e.normalizedKey))
                                    put("kind", JsonPrimitive(e.kind))
                                    put("semantics", JsonPrimitive(e.kindDisplay))
                                    put("ir", JsonPrimitive(e.irMnemonic))
                                    put("confidence", JsonPrimitive(e.confidence))
                                    put("matched", JsonPrimitive(e.matched))
                                }
                            },
                        ))
                        put("irOpcodes", JsonArray(
                            result.irOpcodes.map { ins ->
                                buildJsonObject {
                                    put("pc", JsonPrimitive(ins.pc))
                                    put("op", JsonPrimitive(ins.originalOp))
                                    put("mnemonic", JsonPrimitive(ins.mnemonic))
                                    put("operands", JsonArray(ins.operands.map { JsonPrimitive(it) }))
                                }
                            },
                        ))
                        put("irListing", JsonPrimitive(result.irListing.take(60_000)))
                        put("notes", JsonArray(result.notes.map { JsonPrimitive(it) }))
                    },
                )
            },

            // P0-4：VPC 槽位评分识别（trace_vmp 采样后处理）
            f.tool(
                "jsvmp.resolve_vpc",
                "VPC 槽位评分识别：对 trace_vmp 的多变量对象采样（如 {op:x,pc:y,sp:z}）做槽位评分，自动找出虚拟 pc 变量并重建控制流转移图（跳转目标/热点 pc/转移边）——静态变量识别失败时的运行时兜底",
                ToolCategory.REVERSE,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "samples" to Schemas.strSchema(
                        "离线样本 JSON 数组（如 [{\"op\":1,\"pc\":2},...]；留空则自动从 debugger.get_vmp_trace 的原始缓冲取回）",
                    ),
                    "maxSamples" to Schemas.intSchema("最多取回样本数（默认 4000）"),
                ),
            ) { args ->
                val samplesJson = ToolArgs.str(args, "samples")
                val maxSamples = ToolArgs.int(args, "maxSamples", 4000).coerceIn(50, 50_000)

                // 样本来源：内联 JSON > 运行时缓冲
                val rawSamples: List<String> = if (samplesJson.isNotBlank()) {
                    runCatching {
                        val arr = kotlinx.serialization.json.Json.parseToJsonElement(samplesJson)
                        (arr as? JsonArray)?.map { el ->
                            when (el) {
                                is JsonPrimitive -> el.content
                                else -> el.toString()
                            }
                        } ?: emptyList()
                    }.getOrDefault(emptyList())
                } else {
                    val session = deps.activeSession()
                    deps.debuggerManager.collectVmpTraceRaw(session.engine, maxSamples).getOrNull() ?: emptyList()
                }

                // 解析对象样本 -> Map<变量名, 值串>
                val snapshots = rawSamples.mapNotNull { s ->
                    val t = s.trim()
                    if (!t.startsWith("{")) return@mapNotNull null
                    runCatching {
                        val obj = kotlinx.serialization.json.Json.parseToJsonElement(t) as? kotlinx.serialization.json.JsonObject
                        obj?.mapValues { (_, v) ->
                            (v as? JsonPrimitive)?.content ?: v.toString()
                        }
                    }.getOrNull()
                }

                if (snapshots.size < 8) {
                    return@tool McpToolResult.error(
                        "INSUFFICIENT_OBJECT_SAMPLES",
                        "对象采样不足（${snapshots.size} < 8）。trace_vmp 需用对象表达式采样多变量，" +
                            "如 expression={op:_0xop,pc:_0xpc,sp:_0xsp}",
                    )
                }

                val resolved = VpcResolver().resolve(snapshots)
                McpToolResult.json(
                    buildJsonObject {
                        put("ok", JsonPrimitive(resolved.ok))
                        if (!resolved.ok) {
                            put("error", JsonPrimitive(resolved.error))
                        }
                        put("samples", JsonPrimitive(resolved.samples))
                        if (resolved.ok) {
                            put("vpcSlot", JsonPrimitive(resolved.vpcSlot))
                            put("pcRange", buildJsonObject {
                                put("min", JsonPrimitive(resolved.pcRange.first))
                                put("max", JsonPrimitive(resolved.pcRange.second))
                            })
                            put("distinctPcs", JsonPrimitive(resolved.distinctPcs))
                            put("hottestPc", JsonPrimitive(resolved.hottestPc))
                        }
                        put("slotRanking", JsonArray(
                            resolved.slots.take(6).map { sc ->
                                buildJsonObject {
                                    put("slot", JsonPrimitive(sc.name))
                                    put("distinct", JsonPrimitive(sc.distinct))
                                    put("smallStepRatio", JsonPrimitive("%.2f".format(sc.smallStepRatio)))
                                    put("jumps", JsonPrimitive(sc.jumps))
                                    put("rank", JsonPrimitive("%.1f".format(sc.rank)))
                                }
                            },
                        ))
                        if (resolved.ok) {
                            put("jumpTargets", JsonArray(
                                resolved.jumpTargets.entries.sortedByDescending { it.value }.take(12).map { (pc, cnt) ->
                                    buildJsonObject {
                                        put("pc", JsonPrimitive(pc))
                                        put("hits", JsonPrimitive(cnt))
                                    }
                                },
                            ))
                            put("transitions", JsonArray(
                                resolved.transitions.entries.sortedByDescending { (_, succs) -> succs.sumOf { it.second } }
                                    .take(10).map { (from, succs) ->
                                        buildJsonObject {
                                            put("from", JsonPrimitive(from))
                                            put("to", JsonArray(succs.sortedByDescending { it.second }.take(5).map { (to, c) ->
                                                buildJsonObject {
                                                    put("pc", JsonPrimitive(to))
                                                    put("count", JsonPrimitive(c))
                                                }
                                            }))
                                        }
                                    },
                            ))
                            put("hint", JsonPrimitive(
                                "vpcSlot 即虚拟 pc；jumpTargets 高频 pc = 循环头/分支汇合点；" +
                                    "配合 jsvmp.decompile 的 L<n> 标签对齐即得执行热点区段",
                            ))
                        }
                    },
                )
            },

            // P1-7：轨迹驱动符号执行（trace -> 符号伪代码）
            f.tool(
                "jsvmp.trace_decompile",
                "轨迹符号化：把运行时 trace 的 opcode 序列翻译为符号伪代码（arity 感知切分 + 循环折叠 + 块级 repeat 识别）——字节码运行时解密、静态载体不可得时的反编译替代路径；与 jsvmp.decompile 静态结果互为印证",
                ToolCategory.REVERSE,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                timeoutMs = 60_000,
                inputSchema = Schemas.objectSchema(
                    "samples" to Schemas.strSchema("离线样本 JSON 数组（留空自动取回 trace 缓冲）"),
                    "scriptId" to Schemas.strSchema("用于构建 ISA 的脚本 ID（留空则最大脚本）"),
                    "source" to Schemas.strSchema("直接传入 JS 源码构建 ISA（优先）"),
                    "maxLines" to Schemas.intSchema("输出伪代码最大行数（默认 800）"),
                ),
            ) { args ->
                val samplesJson = ToolArgs.str(args, "samples")
                val inlineSource = ToolArgs.str(args, "source")
                val scriptId = ToolArgs.str(args, "scriptId")
                val maxLines = ToolArgs.int(args, "maxLines", 800).coerceIn(50, 5000)

                // ISA 构建：静态分析得出 opcode -> 语义
                val source = if (inlineSource.isNotBlank()) {
                    inlineSource
                } else {
                    runCatching {
                        ensureAttached(deps)
                        resolveSource(deps, scriptId)?.first
                    }.getOrNull()
                }
                if (source == null) {
                    return@tool McpToolResult.error("SOURCE_UNAVAILABLE", "无法获取源码构建 ISA（传 source 或先 debugger.attach）")
                }
                val candidates = VmpDetector().detect(source)
                val candidate = candidates.firstOrNull()
                    ?: return@tool McpToolResult.error("NO_VMP_FOUND", "未检测到 JSVMP 特征，无法构建 ISA")
                val profile = JsvmpDeepAnalyzer().analyze(source, candidate)

                // ISA：normalize 键 -> 助记名（语义 display 简化）
                val isa = profile.handlers.mapNotNull { h ->
                    normalizeOpKey(h.key)?.let { it to h.kind.name }
                }.toMap()
                val arity = VmpDecompiler().run {
                    val inferred = inferAritiesFromPcDelta(profile.handlers, profile.variables.pcCandidates)
                    profile.handlers.mapNotNull { h ->
                        normalizeOpKey(h.key)?.let { k -> inferred[k]?.let { k to it } }
                    }.toMap()
                }

                // 样本来源：内联 > 运行时缓冲
                val rawSamples: List<String> = if (samplesJson.isNotBlank()) {
                    runCatching {
                        val arr = kotlinx.serialization.json.Json.parseToJsonElement(samplesJson)
                        (arr as? JsonArray)?.map { el ->
                            when (el) {
                                is JsonPrimitive -> el.content
                                else -> el.toString()
                            }
                        } ?: emptyList()
                    }.getOrDefault(emptyList())
                } else {
                    val session = deps.activeSession()
                    runCatching {
                        deps.debuggerManager.collectVmpTraceRaw(session.engine, 4000).getOrNull()
                    }.getOrNull() ?: emptyList()
                }

                val result = TraceSymbolizer().symbolize(rawSamples, isa, arity, maxLines)
                if (!result.ok) {
                    return@tool McpToolResult.error("SYMBOLIZE_FAILED", result.error)
                }
                McpToolResult.json(
                    buildJsonObject {
                        put("samples", JsonPrimitive(result.samples))
                        put("opCodesUsed", JsonPrimitive(result.opCodesUsed))
                        put("instructions", JsonPrimitive(result.instructions))
                        put("loopsFolded", JsonPrimitive(result.loopsFolded))
                        put("blocksFolded", JsonPrimitive(result.blocksFolded))
                        put("coverage", buildJsonObject {
                            result.coverage.forEach { (k, v) -> put(k, JsonPrimitive(v)) }
                        })
                        put("hotOpcodes", JsonArray(
                            result.hotOpcodes.map { (n, c) ->
                                buildJsonObject {
                                    put("op", JsonPrimitive(n))
                                    put("count", JsonPrimitive(c))
                                }
                            },
                        ))
                        put("listing", JsonPrimitive(result.listing.take(60_000)))
                    },
                )
            },

            // P0-1：语义恢复引擎（程序切片 + 栈效果模拟 + arity 推断）
            f.tool(
                "jsvmp.semantics",
                "JSVMP 语义恢复引擎：对每个 handler case 体做程序切片级微观分析——模拟 VM 栈效果（push/pop/栈顶读写）+ 寄存器读写（ctx[i]）+ pc 推进量三源合一推断 arity + 表达式运算符直读生成语义签名（如 XOR(stack[-2], stack[-1]) -> stack[-1]），比 jsvmp.analyze 的 HandlerKind 粗分类细一个量级",
                ToolCategory.REVERSE,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "scriptId" to Schemas.strSchema("脚本 ID（留空则最大脚本）"),
                    "source" to Schemas.strSchema("直接传入 JS 源码（优先，适合离线分析）"),
                    "candidateIndex" to Schemas.intSchema("候选序号（默认 0=最高分）"),
                    "opcode" to Schemas.strSchema("只输出指定 opcode 的语义（可选，如 '23' 或 '0x17'）"),
                ),
            ) { args ->
                val inlineSource = ToolArgs.str(args, "source")
                val scriptId = ToolArgs.str(args, "scriptId")
                val candIdx = ToolArgs.int(args, "candidateIndex", 0)
                val opcodeFilter = ToolArgs.str(args, "opcode")

                val (source, resolvedId, url) = when {
                    inlineSource.isNotBlank() -> Triple(inlineSource, "inline", "inline")
                    else -> {
                        ensureAttached(deps)
                        resolveSource(deps, scriptId)
                            ?: return@tool McpToolResult.error(
                                "SOURCE_UNAVAILABLE",
                                "无 CDP 会话或脚本源码获取失败（可先 debugger.attach，或直接传 source 参数）",
                            )
                    }
                }
                val candidates = VmpDetector().detect(source)
                if (candidates.isEmpty()) {
                    return@tool McpToolResult.error("NO_VMP_FOUND", "未检测到 JSVMP 特征")
                }
                val candidate = candidates.getOrNull(candIdx) ?: candidates.first()
                val profile = JsvmpDeepAnalyzer().analyze(source, candidate)
                val report = JsvmpSemanticRecovery().recover(profile.handlers, profile.variables)

                val filtered = if (opcodeFilter.isNotBlank()) {
                    val norm = normalizeOpKey(opcodeFilter)
                    report.handlers.filter { normalizeOpKey(it.key) == norm || it.key == opcodeFilter }
                } else {
                    report.handlers
                }
                McpToolResult.json(
                    buildJsonObject {
                        put("scriptUrl", JsonPrimitive(url))
                        put("scriptId", JsonPrimitive(resolvedId))
                        put("handlerCount", JsonPrimitive(report.handlers.size))
                        put("recoveredCount", JsonPrimitive(report.improvedOverRegex))
                        put(
                            "mnemonicHistogram",
                            buildJsonObject {
                                report.mnemonicHistogram.forEach { (k, v) -> put(k, JsonPrimitive(v)) }
                            },
                        )
                        put(
                            "handlers",
                            JsonArray(
                                filtered.take(150).map { h ->
                                    buildJsonObject {
                                        put("opcode", JsonPrimitive(h.key))
                                        put("mnemonic", JsonPrimitive(h.mnemonic))
                                        put("signature", JsonPrimitive(h.signature))
                                        put("arity", JsonPrimitive(h.arity))
                                        put("stackIn", JsonPrimitive(h.stackIn))
                                        put("stackOut", JsonPrimitive(h.stackOut))
                                        if (h.regReads.isNotEmpty()) {
                                            put("regReads", JsonArray(h.regReads.map { JsonPrimitive(it) }))
                                        }
                                        if (h.regWrites.isNotEmpty()) {
                                            put("regWrites", JsonArray(h.regWrites.map { JsonPrimitive(it) }))
                                        }
                                        put("readsBytecode", JsonPrimitive(h.readsBytecode))
                                        put("branchTarget", JsonPrimitive(h.branchTarget))
                                        put("callsHost", JsonPrimitive(h.callsHost))
                                        put("confidence", JsonPrimitive(h.confidence))
                                        val oi = h.operandInfo
                                        if (oi != null) {
                                            put(
                                                "operandInfo",
                                                buildJsonObject {
                                                    put("operandCount", JsonPrimitive(oi.operandCount))
                                                    put("operandWidth", JsonPrimitive(oi.operandWidth))
                                                    put("operandEncoding", JsonPrimitive(oi.operandEncoding))
                                                    put("pcDelta", JsonPrimitive(oi.pcDelta))
                                                },
                                            )
                                        }
                                        if (h.symbolicStack.isNotEmpty()) {
                                            put("symbolicStack", JsonArray(h.symbolicStack.take(12).map { JsonPrimitive(it) }))
                                        }
                                        if (h.ops.isNotEmpty()) {
                                            put(
                                                "microOps",
                                                JsonArray(
                                                    h.ops.take(12).map { op ->
                                                        buildJsonObject {
                                                            put("op", JsonPrimitive(op.op))
                                                            put("detail", JsonPrimitive(op.detail))
                                                        }
                                                    },
                                                ),
                                            )
                                        }
                                    }
                                },
                            ),
                        )
                        put("isaTable", JsonPrimitive(report.isaTable.take(30_000)))
                        if (report.notes.isNotEmpty()) {
                            put("notes", JsonArray(report.notes.map { JsonPrimitive(it) }))
                        }
                    },
                )
            },

            // P0-3：静态/动态假设验证（Semantic Hypothesis → Runtime Validation）
            f.tool(
                "jsvmp.validate",
                "JSVMP opcode 语义假设验证：静态分析产出多候选（ADD? XOR? SUB?）时，喂运行时 (输入a, 输入b, 输出out) 样本自动裁决——逐候选求值比对淘汰，输出唯一胜者 + 置信度 + 逐条证据；配合 debugger.trace_vmp 采样的栈读写值使用，形成静态假设动态验证闭环",
                ToolCategory.REVERSE,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "opcode" to Schemas.strSchema("待验证的 opcode（如 '23' 或 '0x17'）"),
                    "samples" to Schemas.strSchema("样本 JSON 数组，每条形如 [{\"a\":123,\"b\":456,\"out\":579}, ...]（前两个数值字段为输入，最后数值字段为输出）"),
                    "candidates" to Schemas.strSchema("候选语义列表，逗号分隔（默认 ADD,SUB,XOR,OR,AND,MUL,SHL,SHR,ROTL,MOD）"),
                ),
            ) { args ->
                val opcode = ToolArgs.str(args, "opcode")
                if (opcode.isBlank()) {
                    return@tool McpToolResult.error("INVALID_ARGS", "opcode 必填")
                }
                val samplesJson = ToolArgs.str(args, "samples")
                if (samplesJson.isBlank()) {
                    return@tool McpToolResult.error("INVALID_ARGS", "samples 必填（JSON 数组，每条含输入a/输入b/输出out）")
                }
                val candidates = ToolArgs.str(args, "candidates")
                    .split(',')
                    .map { it.trim().uppercase() }
                    .filter { it.isNotEmpty() }
                    .ifEmpty { listOf("ADD", "SUB", "XOR", "OR", "AND", "MUL", "SHL", "SHR", "ROTL", "MOD") }

                val samples = runCatching {
                    val arr = kotlinx.serialization.json.Json.parseToJsonElement(samplesJson)
                    (arr as? JsonArray)?.mapNotNull { el ->
                        (el as? kotlinx.serialization.json.JsonObject)?.let { obj ->
                            obj.entries.associate { (k, v) -> k to ((v as? JsonPrimitive)?.content ?: v.toString()) }
                        }
                    } ?: emptyList()
                }.getOrElse {
                    return@tool McpToolResult.error("PARSE_ERROR", "samples JSON 解析失败：${it.message?.take(100)}")
                }

                val verdict = JsvmpSemanticRecovery().validateHypothesis(opcode, samples, candidates)
                McpToolResult.json(
                    buildJsonObject {
                        put("opcode", JsonPrimitive(verdict.opcode))
                        put("winner", JsonPrimitive(verdict.winner))
                        put("confirmed", JsonPrimitive(verdict.confirmed))
                        put("confidence", JsonPrimitive(verdict.confidence))
                        put("samplesUsed", JsonPrimitive(verdict.samplesUsed))
                        put("candidates", JsonArray(verdict.candidates.map { JsonPrimitive(it) }))
                        put("evidence", JsonArray(verdict.evidence.map { JsonPrimitive(it) }))
                        put(
                            "conclusion",
                            JsonPrimitive(
                                if (verdict.confirmed) {
                                    "opcode ${verdict.opcode} = ${verdict.winner}（置信 ${"%.0f".format(verdict.confidence * 100)}%，${verdict.samplesUsed} 个样本全部一致）"
                                } else {
                                    "无法唯一裁决：建议补充更多大数值/边界样本（当前存活候选见 evidence）"
                                },
                            ),
                        )
                    },
                )
            },

            // JSVMP handler 语义质量门
            f.tool(
                "jsvmp.quality_gate",
                "JSVMP 语义质量门：自动检查 handler key/kind/evidence/confidence/snippet 一致性，量化静态恢复质量并给出动态差分建议。",
                ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                timeoutMs = 20_000,
                capabilities = "jsvmp,semantic-validation,quality-gate,differential",
                cost = 3, reliability = 95,
                inputSchema = Schemas.objectSchema(
                    "source" to Schemas.strSchema("JS/JSVMP 源码"),
                    "candidateIndex" to Schemas.intSchema("候选派发索引，默认 0"),
                ),
            ) { args ->
                val source = ToolArgs.str(args, "source")
                if (source.isBlank()) return@tool McpToolResult.error("MISSING_SOURCE", "source 必填")
                val candidates = VmpDetector().detect(source)
                if (candidates.isEmpty()) return@tool McpToolResult.error("NO_VMP_CANDIDATE", "未发现可分析的 VM dispatcher")
                val idx = ToolArgs.int(args, "candidateIndex", 0).coerceIn(0, candidates.lastIndex)
                val profile = JsvmpDeepAnalyzer().analyze(source, candidates[idx])
                val report = JsvmpSemanticValidator().validate(profile.handlers)
                McpToolResult.json(buildJsonObject {
                    put("candidateIndex", idx)
                    put("handlerCount", report.handlers)
                    put("validated", report.validated)
                    put("confidence", report.confidence)
                    put("issues", JsonArray(report.issues.map { i -> buildJsonObject { put("severity", i.severity); put("message", i.message); put("handler", i.handler) } }))
                    put("recommendations", JsonArray(report.recommendations.map(::JsonPrimitive)))
                    put("hint", JsonPrimitive("confidence<0.90 的 handler 优先执行 jsvmp.validate / jsvmp.symbolic，并用真实 runtime trace 做差分验证。"))
                })
            },

            // 符号栈数据流（AST 语义切片，产出 S0=[A,B]; C=A XOR B; S1=[C]）
            f.tool(
                "jsvmp.symbolic",
                "JSVMP 符号栈数据流图：对每个 handler case 体做 AST 化语义切片 + 符号栈求值——输入输出用符号表达式而非计数器表达（如 S0=[A,B]; C = A XOR B; S1=[C]），并给出操作数字段四元组（operandCount/operandWidth/operandEncoding/pcDelta），是 jsvmp.semantics 的 AST 语义升级版",
                ToolCategory.REVERSE,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "scriptId" to Schemas.strSchema("脚本 ID（留空则最大脚本）"),
                    "source" to Schemas.strSchema("直接传入 JS 源码（优先，适合离线分析）"),
                    "candidateIndex" to Schemas.intSchema("候选序号（默认 0=最高分）"),
                ),
            ) { args ->
                val inlineSource = ToolArgs.str(args, "source")
                val scriptId = ToolArgs.str(args, "scriptId")
                val candIdx = ToolArgs.int(args, "candidateIndex", 0)

                val (source, resolvedId, url) = when {
                    inlineSource.isNotBlank() -> Triple(inlineSource, "inline", "inline")
                    else -> {
                        ensureAttached(deps)
                        resolveSource(deps, scriptId)
                            ?: return@tool McpToolResult.error(
                                "SOURCE_UNAVAILABLE",
                                "无 CDP 会话或脚本源码获取失败（可先 debugger.attach，或直接传 source 参数）",
                            )
                    }
                }
                val candidates = VmpDetector().detect(source)
                if (candidates.isEmpty()) {
                    return@tool McpToolResult.error("NO_VMP_FOUND", "未检测到 JSVMP 特征")
                }
                val candidate = candidates.getOrNull(candIdx) ?: candidates.first()
                val profile = JsvmpDeepAnalyzer().analyze(source, candidate)
                val flow = JsvmpSemanticRecovery().produceSymbolicReport(profile.handlers, profile.variables)
                McpToolResult.json(
                    buildJsonObject {
                        put("scriptUrl", JsonPrimitive(url))
                        put("scriptId", JsonPrimitive(resolvedId))
                        put("handlerCount", JsonPrimitive(flow.size))
                        put("symbolicFlow", JsonArray(flow.map { JsonPrimitive(it) }))
                    },
                )
            },

            // ---------- ：JS 层加密算法识别 ----------
            f.tool(
                "jsvmp.crypto_scan",
                "JS 层加密算法识别（ 新增，对标 wasm.recognize_crypto）：对 JSVMP/混淆 JS 源码做三层联合识别——①常量指纹（AES/DES S-box、SHA-256 K 表、MD5 轮常量、SM3/SM4 国密、CRC32 多项式、TEA delta、Murmur/xxHash 素数，十进制与 0x 十六进制内嵌均可命中）②API 调用（crypto.subtle.*、CryptoJS/jsencrypt/jsrsasign/elliptic、RSA BigInt 模幂）③结构模式（查表索引 t[i&255] + 位运算密度 + 轮循环）。输出算法/类别/证据/置信度/行号定位，运行时解密常量的场景结合 jsvmp.snapshot 使用",
                ToolCategory.REVERSE,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "scriptId" to Schemas.strSchema("脚本 ID（来自 debugger.list_scripts；留空则取最大脚本）"),
                    "source" to Schemas.strSchema("直接传入 JS 源码（与 scriptId 二选一且优先，适合离线分析）"),
                    "minConfidence" to Schemas.intSchema("置信度阈值（0-100，默认 0 全部返回）"),
                ),
            ) { args ->
                val inlineSource = ToolArgs.str(args, "source")
                val scriptId = ToolArgs.str(args, "scriptId")
                val minConf = ToolArgs.int(args, "minConfidence", 0).coerceIn(0, 100)

                val (source, resolvedId, url) = when {
                    inlineSource.isNotBlank() -> Triple(inlineSource, "inline", "inline")
                    else -> {
                        ensureAttached(deps)
                        resolveSource(deps, scriptId)
                            ?: return@tool McpToolResult.error(
                                "SOURCE_UNAVAILABLE",
                                "无 CDP 会话或脚本源码获取失败（可先 debugger.attach，或直接传 source 参数）",
                            )
                    }
                }

                val report = JsCryptoScanner().scan(source)
                val filtered = report.identifications.filter { it.confidence >= minConf }
                McpToolResult.json(
                    buildJsonObject {
                        put("scriptUrl", JsonPrimitive(url))
                        put("scriptId", JsonPrimitive(resolvedId))
                        put("linesScanned", JsonPrimitive(report.linesScanned))
                        put("charsScanned", JsonPrimitive(report.charsScanned))
                        put("bitOpDensity", JsonPrimitive(report.bitOpDensity))
                        put("identificationCount", JsonPrimitive(filtered.size))
                        put(
                            "identifications",
                            JsonArray(
                                filtered.map { id ->
                                    buildJsonObject {
                                        put("algorithm", JsonPrimitive(id.algorithm))
                                        put("category", JsonPrimitive(id.category.name))
                                        put("confidence", JsonPrimitive(id.confidence))
                                        put("basis", JsonArray(id.basis.map { JsonPrimitive(it.name) }))
                                        put("evidence", JsonArray(id.evidence.map { JsonPrimitive(it) }))
                                        put("lines", JsonArray(id.lines.map { JsonPrimitive(it) }))
                                        put("snippets", JsonArray(id.snippets.map { JsonPrimitive(it) }))
                                    }
                                },
                            ),
                        )
                        put("summary", JsonPrimitive(report.summary))
                    },
                )
            },

            // 轨迹驱动 CFG 恢复
            f.tool(
                "jsvmp.trace_cfg",
                "JSVMP 轨迹驱动 CFG 恢复：输入运行时虚拟 pc 执行序列，构建动态控制流图——节点频率/出入度 + 转移边 + Tarjan 强连通循环体 + 回边 + 热点/枢纽 pc。当静态字节码不足以恢复跳转（运行时解密 / 变长 opcode）时，用 trace 补齐控制流；输出的 loopPcs/回边可对齐 jsvmp.decompile 的 L<n> 标签锁定签名主循环（白盒 diff 定位目标动作区段的前置步骤）",
                ToolCategory.REVERSE,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                timeoutMs = 60_000,
                inputSchema = Schemas.objectSchema(
                    "samples" to Schemas.strSchema("离线样本 JSON 数组（元素为 {@\"pc\":N} 对象或裸数值；留空自动从 debugger.get_vmp_trace / collectVmpTraceRaw 缓冲取回）"),
                    "pcSlot" to Schemas.strSchema("显式指定 pc 槽名（如 \"op\" / \"vpc\"；默认按 pc/vpc/op/_vpc 自动探测）"),
                    "maxSamples" to Schemas.intSchema("最多取回样本数（默认 20000）"),
                ),
            ) { args ->
                val samplesJson = ToolArgs.str(args, "samples")
                val pcSlot = ToolArgs.str(args, "pcSlot")
                val maxSamples = ToolArgs.int(args, "maxSamples", 20_000).coerceIn(50, 100_000)

                val rawSamples: List<String> = if (samplesJson.isNotBlank()) {
                    runCatching {
                        val arr = kotlinx.serialization.json.Json.parseToJsonElement(samplesJson)
                        (arr as? JsonArray)?.map { el ->
                            when (el) {
                                is JsonPrimitive -> el.content
                                else -> el.toString()
                            }
                        } ?: emptyList()
                    }.getOrDefault(emptyList())
                } else {
                    val session = deps.activeSession()
                    runCatching {
                        deps.debuggerManager.collectVmpTraceRaw(session.engine, maxSamples).getOrNull()
                    }.getOrNull() ?: emptyList()
                }

                val cfg = VmpTraceCfg()
                val seq = cfg.extractPcSequence(rawSamples, pcSlot)
                if (seq.isEmpty()) {
                    return@tool McpToolResult.error(
                        "NO_PC_SAMPLES",
                        "pc 序列提取为空：样本需含 pc/vpc/op 数值槽（如 {\"pc\":N}）或裸数值；" +
                            "用 debugger.trace_vmp 以对象表达式采样多变量即可自动探测",
                    )
                }
                val r = cfg.build(seq)
                if (!r.ok) return@tool McpToolResult.error("CFG_FAILED", r.error)
                McpToolResult.json(
                    buildJsonObject {
                        put("ok", JsonPrimitive(true))
                        put("samples", JsonPrimitive(r.sampleCount))
                        put("distinctPcs", JsonPrimitive(r.distinctPcs))
                        put("entryPc", JsonPrimitive(r.entryPc))
                        put("exitPc", JsonPrimitive(r.exitPc))
                        put("loopCount", JsonPrimitive(r.loops.size))
                        put("loopPcs", JsonArray(r.loopPcs.map { JsonPrimitive(it) }))
                        put(
                            "loops",
                            JsonArray(
                                r.loops.map { comp ->
                                    JsonArray(comp.sorted().map { JsonPrimitive(it) })
                                },
                            ),
                        )
                        put(
                            "backEdges",
                            JsonArray(
                                r.backEdges.take(200).map { e ->
                                    buildJsonObject {
                                        put("from", JsonPrimitive(e.from))
                                        put("to", JsonPrimitive(e.to))
                                        put("count", JsonPrimitive(e.count))
                                    }
                                },
                            ),
                        )
                        put(
                            "hotPcs",
                            JsonArray(
                                r.hotPcs.take(20).map { (pc, c) ->
                                    buildJsonObject {
                                        put("pc", JsonPrimitive(pc))
                                        put("freq", JsonPrimitive(c))
                                    }
                                },
                            ),
                        )
                        put("hubs", JsonArray(r.hubs.take(20).map { JsonPrimitive(it) }))
                        put(
                            "nodes",
                            JsonArray(
                                r.nodes.take(400).map { n ->
                                    buildJsonObject {
                                        put("pc", JsonPrimitive(n.pc))
                                        put("freq", JsonPrimitive(n.freq))
                                        put("inDeg", JsonPrimitive(n.inDegree))
                                        put("outDeg", JsonPrimitive(n.outDegree))
                                        put("inLoop", JsonPrimitive(n.inLoop))
                                    }
                                },
                            ),
                        )
                        put(
                            "hint",
                            JsonPrimitive(
                                "loopPcs（非平凡 SCC）= VM 签名主循环候选；回边高频 to 节点 = 循环头。" +
                                    "对齐 jsvmp.decompile 的 L<n> 标签定位目标动作区段；若与 baseline trace 对比见 jsvmp 配套 diff_vmp_trace",
                            ),
                        )
                    },
                )
            },
        )
    }

    /** "0x1a" -> "26"；数字串原样；其他 null */
    private fun normalizeOpKey(key: String): String? {
        val k = key.trim()
        return when {
            k.startsWith("0x") || k.startsWith("0X") -> k.substring(2).toIntOrNull(16)?.toString()
            k.toIntOrNull() != null -> k.toIntOrNull().toString()
            k.length >= 3 && k.startsWith("'") && k.endsWith("'") -> k[1].code.toString()
            else -> null
        }
    }
}
