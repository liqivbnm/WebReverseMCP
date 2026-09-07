package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import com.webreverse.mcp.javascript.analysis.ConstraintSolver
import com.webreverse.mcp.javascript.analysis.JsCallGraphBuilder
import com.webreverse.mcp.javascript.analysis.JsSsaBuilder
import com.webreverse.mcp.javascript.analysis.RuntimeTaintBridge
import com.webreverse.mcp.javascript.analysis.StructuredWasmDecompiler
import com.webreverse.mcp.javascript.analysis.TaintEngine
import com.webreverse.mcp.javascript.analysis.ValidationEngine
import com.webreverse.mcp.javascript.parser.JsParser
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * 增强能力工具层 v2（本次逆向增强阶段新增）。
 *
 * 把五个新增验证/解析/污点/约束能力接到 MCP 工具入口：
 * - reverse.validate_batch：动态验证循环批量版（validateDynamicBatch，多候选×多样本统一执行 + 失败细分）
 * - wasm.structured_decompile：WASM 结构化反编译（控制流树 + 表达式树折叠）
 * - parse.imports_exports：ES import/export 结构化解析（默认/具名/命名空间/副作用）
 * - static.taint_bridged：静态污点 × 运行时污点标签联合视图（analyzeBridged）
 * - constraint.solve：线性约束求解 + 路径可达性（区间传播 / 替换 / witness）
 */
object EnhancedAnalysisTools {

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)

        return listOf(
            // ---------------- 动态验证循环：批量版 ----------------
            f.tool(
                "reverse.validate_batch",
                "动态验证循环批量版（本次增强）：一次提交多个候选公式 × 多条浏览器真实样本，统一执行并各自返回 通过/失败与" +
                    "失败细分（占位符未绑定/语法错误/运行时异常/超时/空值/类型不匹配/值不匹配），每个候选给出命中率汇总，" +
                    "并输出全局 winner、置信度、强收敛判定与环境就绪可重试方向。与 reverse.validate 互为补充：本工具面向" +
                    "『多个候选一起赛马』和『失败原因批量分类』，杜绝样本恰好命中的伪收敛",
                ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.MEDIUM,
                timeoutMs = 60_000,
                capabilities = "validation,dynamic-validation,batch,tracing",
                cost = 4, reliability = 82,
                inputSchema = Schemas.objectSchema(
                    "candidates" to Schemas.strSchema("候选公式 JSON 数组，每条 {\"name\":\"XOR\",\"formula\":\"({a} ^ {b}) >>> 0\"}；占位符用 {输入键名}"),
                    "samples" to Schemas.strSchema("浏览器观测样本 JSON 数组，每条 {\"inputs\":{\"a\":12,\"b\":4},\"realOutput\":8,\"note\":\"可选\"}"),
                    "tolerateFloatEpsilon" to Schemas.strSchema("浮点容差（默认 1e-9，可传 0 严格相等）"),
                ),
            ) { args ->
                val candidatesJson = ToolArgs.str(args, "candidates")
                val samplesJson = ToolArgs.str(args, "samples")
                if (candidatesJson.isBlank() || samplesJson.isBlank()) {
                    return@tool McpToolResult.error("INVALID_ARGS", "validate_batch 需 candidates + samples（JSON）")
                }
                val candidates = parseCandidates(candidatesJson)
                val samples = parseSamples(samplesJson)
                if (candidates.isEmpty()) return@tool McpToolResult.error("PARSE_ERROR", "candidates 解析失败（需 [{\"name\":..,\"formula\":..}]）")
                if (samples.isEmpty()) return@tool McpToolResult.error("PARSE_ERROR", "samples 解析失败（需 [{\"inputs\":{..},\"realOutput\":..}]）")
                val tol = (ToolArgs.str(args, "tolerateFloatEpsilon").toDoubleOrNull() ?: 1e-9).coerceAtLeast(0.0)

                val prepared = prebuildExecutor(deps)
                val executor = ValidationEngine.JsExecutor { code, inputs -> prepared(code, inputs) }
                val report = ValidationEngine().validateDynamicBatch(executor, samples, candidates, tolerateFloatEpsilon = tol)
                if (!report.ok) return@tool McpToolResult.error("VALIDATION_FAILED", report.error)

                McpToolResult.json(
                    buildJsonObject {
                        put("ok", true)
                        put("sampleCount", JsonPrimitive(report.sampleCount))
                        put("candidateCount", JsonPrimitive(report.candidateCount))
                        put("runCount", JsonPrimitive(report.runCount))
                        put("passedCount", JsonPrimitive(report.passedCount))
                        put("winner", JsonPrimitive(report.winner))
                        put("winnerConfidence", JsonPrimitive("%.0f".format(report.winnerConfidence * 100)))
                        put("confirmed", JsonPrimitive(report.confirmed))
                        put("needsMoreSamples", JsonPrimitive(report.needsMoreSamples))
                        put("summaryPerReason", JsonObject(
                            report.summaryPerReason.map { (k, v) -> k.name to JsonPrimitive(v) }.toMap(),
                        ))
                        put("rollups", JsonArray(
                            report.rollups.map { c ->
                                buildJsonObject {
                                    put("name", c.name)
                                    put("passed", c.passed)
                                    put("totalRuns", c.totalRuns)
                                    put("passedRuns", c.passedRuns)
                                    put("hitRate", JsonPrimitive("%.0f".format(c.confidence * 100)))
                                    put("primaryState", c.primaryState.name)
                                }
                            },
                        ))
                        put("results", JsonArray(
                            report.results.take(400).map { r ->
                                buildJsonObject {
                                    put("candidate", r.displayName)
                                    put("formula", r.formula)
                                    put("passed", r.passed)
                                    put("state", r.state.name)
                                    put("actual", r.actualValue ?: "null")
                                    put("expected", r.expectedValue ?: "null")
                                    put("browserExecutable", r.browserExecutable)
                                    put("elapsedMs", r.elapsedMs)
                                    put("conclusion", r.browserConclusion)
                                    put("hint", r.hint)
                                }
                            },
                        ))
                        put("retrySuggestions", JsonArray(report.retrySuggestions.map(::JsonPrimitive)))
                        put("summary", JsonPrimitive(report.summary))
                    },
                )
            },

            // ---------------- WASM 结构化反编译 ----------------
            f.tool(
                "wasm.structured_decompile",
                "WASM 结构化反编译（本次增强）：把线性 opcode 流还原为结构化高级伪代码——控制流树（if/else、block/loop、br/br_if/br_table 跳转）" +
                    "+ 表达式树折叠（const/local.get/二元/一元/比较/load/call 逐层折叠为嵌套表达式），输出 local 声明、mem[addr] 读写、字符串常量注解与" +
                    "符号化函数名。与 wasm.disassemble（逐条 wat 直译）互补，更利于读懂加密/解密主逻辑",
                ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                timeoutMs = 30_000,
                capabilities = "wasm,wasm-decompile,structured-pseudocode,control-flow",
                cost = 4, reliability = 78,
                inputSchema = Schemas.objectSchema(
                    "wasm" to Schemas.strSchema("WASM 二进制内容（base64 优先；其次 hex）"),
                    "funcIndex" to Schemas.intSchema("按函数索引反编译（可选，与 exportName 二选一）"),
                    "exportName" to Schemas.strSchema("按导出名反编译（可选，与 funcIndex 二选一）"),
                ),
            ) { args ->
                val wasmStr = ToolArgs.str(args, "wasm")
                if (wasmStr.isBlank()) return@tool McpToolResult.error("INVALID_ARGS", "wasm 参数必填（base64/hex）")
                val bytes = decodeBytes(wasmStr) ?: return@tool McpToolResult.error("DECODE_FAILED", "wasm 内容解码失败")
                val d = StructuredWasmDecompiler()
                val exportName = ToolArgs.str(args, "exportName")
                val funcIndex = ToolArgs.int(args, "funcIndex", -1)
                val r = when {
                    exportName.isNotBlank() -> d.decompileExport(bytes, exportName)
                    funcIndex >= 0 -> d.decompile(bytes, funcIndex)
                    else -> McpToolResult.error(
                        "VALIDATION_FAILED",
                        "需 funcIndex 或 exportName 之一",
                    ).let { return@tool McpToolResult.error("VALIDATION_FAILED", "需 funcIndex 或 exportName 之一") }
                }
                if (!r.ok) return@tool McpToolResult.error("DECOMPILE_FAILED", r.error)
                McpToolResult.json(
                    buildJsonObject {
                        put("ok", true)
                        put("funcName", r.funcName)
                        put("funcIndex", r.funcIndex)
                        put("signature", r.signature)
                        put("locals", r.locals)
                        put("instructionCount", r.instructionCount)
                        put("pseudocode", r.toReadableText())
                    },
                )
            },

            // ---------------- ES import/export 结构化解析 ----------------
            f.tool(
                "parse.imports_exports",
                "ES import/export 结构化解析（本次增强）：从 JS 源码精确提取 import 语句（default 名/namespace/具名导入/纯副作用导入）与" +
                    "export 语句（named/default/all/all_as/declaration），按模块分组。适合逆向 ESModule 打包产物时梳理依赖与对外接口",
                ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                timeoutMs = 15_000,
                capabilities = "parser,es-module,import-export,dependency",
                cost = 2, reliability = 88,
                inputSchema = Schemas.objectSchema("source" to Schemas.strSchema("JS 源码（ESModule 语法）")),
            ) { args ->
                val source = ToolArgs.str(args, "source")
                if (source.isBlank()) return@tool McpToolResult.error("MISSING_SOURCE", "source 必填")
                val p = JsParser()
                val imports = p.extractImports(source)
                val exports = p.extractExports(source)
                McpToolResult.json(
                    buildJsonObject {
                        put("ok", true)
                        put("sourceChars", source.length)
                        put("importCount", imports.size)
                        put("exportCount", exports.size)
                        put("imports", JsonArray(imports.map { imp ->
                            buildJsonObject {
                                put("module", imp.module)
                                imp.defaultName?.let { put("default", it) }
                                imp.namespace?.let { put("namespace", it) }
                                if (imp.sideEffectOnly) put("sideEffectOnly", true)
                                if (imp.namedImports.isNotEmpty()) put(
                                    "named", JsonArray(imp.namedImports.map { n ->
                                        buildJsonObject {
                                            put("imported", n.imported)
                                            if (n.local != n.imported) put("local", n.local)
                                        }
                                    }),
                                )
                            }
                        }))
                        put("exports", JsonArray(exports.map { e ->
                            buildJsonObject {
                                put("kind", e.kind)
                                val bound = StringBuilder()
                                if (e.names.isNotEmpty()) bound.append(
                                    e.names.joinToString(", ") { if (it.local == it.imported) it.imported else "${it.imported} as ${it.local}" },
                                )
                                if (e.expression.isNotBlank()) bound.append(if (bound.isEmpty()) e.expression else " = ${e.expression}")
                                put("summary", bound.toString())
                                if (e.module.isNotBlank()) put("module", e.module)
                                put("isDefault", e.isDefault)
                            }
                        }))
                    },
                )
            },

            // ---------------- 静态污点 × 运行时污点联合视图 ----------------
            f.tool(
                "static.taint_bridged",
                "静态污点 × 运行时污点标签联合视图（本次增强）：先跑既有静态传播（SSA def-use + 0-CFA 调用图 + ~cookie/token/参数~→eval/fetch/send~ 规则库），" +
                    "再把运行时上报的污点标签（runtime 采集的 source→中间→sink 路径）并入同一报告，按来源|汇|路径去重（静态优先）。" +
                    "输出合并后的污点流（含跨函数跳变与转换链），适合把 Hook 到的运行时观测补进静态分析闭环",
                ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.MEDIUM,
                timeoutMs = 60_000,
                capabilities = "taint,dataflow,runtime-taint,ssa,callgraph",
                cost = 5, reliability = 86,
                inputSchema = Schemas.objectSchema(
                    "source" to Schemas.strSchema("JS 源码（必填）"),
                    "runtimeTaint" to Schemas.strSchema("运行时污点标签 JSON 数组，每条 {\"tagId\":\"t1\",\"sourceLabel\":\"..\",\"sinkLabel\":\"..\",\"path\":[{\"kind\":\"hop\",\"label\":\"fnX\",\"seq\":0}]}（可选）"),
                    "runtimeSeverity" to Schemas.enumSchema("运行时污点严重级别", "CRITICAL", "HIGH", "MEDIUM", "LOW"),
                ),
            ) { args ->
                val source = ToolArgs.str(args, "source")
                if (source.isBlank()) return@tool McpToolResult.error("MISSING_SOURCE", "source 必填")
                val sev = parseSeverity(ToolArgs.str(args, "runtimeSeverity").ifBlank { "HIGH" })
                val runtimeRaw = runCatching {
                    val el = kotlinx.serialization.json.Json.parseToJsonElement(ToolArgs.str(args, "runtimeTaint"))
                    (el as? JsonArray)?.map { node ->
                        (node as? JsonObject)?.mapValues { (_, v) -> v }.orEmpty()
                    }.orEmpty()
                }.getOrDefault(emptyList())
                val runtimeInput = RuntimeTaintBridge().fromRaw(runtimeRaw)

                val engine = TaintEngine()
                val ssa = JsSsaBuilder().build(source)
                val cg = JsCallGraphBuilder().build(ssa)
                val report = engine.analyzeBridged(ssa, cg, runtimeInput, sev)
                McpToolResult.json(
                    buildJsonObject {
                        put("ok", true)
                        put("flowCount", report.flows.size)
                        put("runtimeFlows", runtimeRaw.size)
                        put("sourceCount", report.sourceCount)
                        put("sinkCount", report.sinkCount)
                        put("taintedVarCount", report.taintedVarCount)
                        put("iterations", report.iterations)
                        put("flows", JsonArray(report.flows.take(200).map { f ->
                            buildJsonObject {
                                put("source", f.sourceLabel)
                                put("sourceFunc", f.sourceFunc)
                                put("sink", f.sinkLabel)
                                put("sinkFunc", f.sinkFunc)
                                put("severity", f.severity.name)
                                put("crossFunction", f.crossFunction)
                                put("transforms", JsonArray(f.transforms.map(::JsonPrimitive)))
                                put("path", JsonArray(f.path.take(64).map { s ->
                                    buildJsonObject {
                                        put("func", s.funcName)
                                        put("line", s.line)
                                        put("var", s.varName)
                                        put("desc", s.desc)
                                        if (s.hop.isNotBlank()) put("hop", s.hop)
                                    }
                                }))
                            }
                        }))
                    },
                )
            },

            // ---------------- 线性约束求解 + 路径可达性 ----------------
            f.tool(
                "constraint.solve",
                "线性约束求解 + 符号可达性（本次增强 约束求解/符号执行）：声明符号变量与约束（EQ/NE/LT/LE/GT/GE，线性算术 a+b、a-b、a*const、-a，" +
                    "逻辑 And/Or/Not），引擎做区间传播 + 定义替换，返回每个变量的精确值/区间/符号哈希；并对约束集做路径可达性判定" +
                    "（FEASIBLE/INFEASIBLE/UNKNOWN，含 sound witness 构造）。适合把逆向中的关键等式（如签名校验、长度边界、寻址公式）建模来验证可行性",
                ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                timeoutMs = 20_000,
                capabilities = "constraint-solving,symbolic,interval,reachability",
                cost = 3, reliability = 84,
                inputSchema = Schemas.objectSchema(
                    "constraints" to Schemas.strSchema("约束声明 JSON：{\"vars\":[\"x\",\"a\",\"b\"],\"defines\":{\"x\":\"a + b\"},\"assert\":[{\"op\":\"EQ\",\"lhs\":\"x\",\"rhs\":\"10\"}]}"),
                    "paths" to Schemas.strSchema("可选：额外路径条件 JSON 数组 [{op,lhs,rhs}]，用于判定该分支可行性（不并入变量域，仅判可达）"),
                ),
            ) { args ->
                val spec = parseSpec(ToolArgs.str(args, "constraints"))
                    ?: return@tool McpToolResult.error("PARSE_ERROR", "constraints 解析失败：需 {\"vars\":[..],\"defines\":{..},\"assert\":[{op,lhs,rhs}]}")
                val system = buildSystem(spec)
                val solved = system.solve()
                val reachAll = system.isSatisfiable()

                // 路径可达性：若提供 paths，作为独立条件判定
                var pathReach: String? = null
                val paths = parseConstraints(ToolArgs.str(args, "paths"))
                if (paths.isNotEmpty()) {
                    val conds = paths.map { toConstraint(it) }
                    pathReach = system.reachability(conds).name
                }

                McpToolResult.json(
                    buildJsonObject {
                        put("ok", true)
                        put("variables", JsonArray(spec.vars.map(::JsonPrimitive)))
                        put("constraintCount", spec.asserts.size)
                        put("solutions", JsonObject(
                            solved.map { (name, v) ->
                                name to when (v) {
                                    is ConstraintSolver.SolverValue.Exact -> JsonPrimitive(v.v.toString())
                                    is ConstraintSolver.SolverValue.Interval -> JsonPrimitive("[${v.lo}, ${v.hi}]")
                                    is ConstraintSolver.SolverValue.Symbolic -> JsonPrimitive("(${v.hash}) ${v.expr}")
                                }
                            }.toMap(),
                        ))
                        put("reachability", JsonPrimitive(reachAll.name))
                        pathReach?.let { put("pathReachability", JsonPrimitive(it)) }
                        put("hint", JsonPrimitive(
                            "解出为区间或符号哈希时说明约束不唯一/非线性；补 assert 或换用浏览器真实值可缩小解空间",
                        ))
                    },
                )
            },
        )
    }

    // ---------------- helpers ----------------

    /** 在 suspend 上下文预构建浏览器 JS 执行器（普通函数，供引擎同步调用） */
    private suspend fun prebuildExecutor(deps: ToolDependencies): (String, Map<String, Any>) -> String? {
        val session = runCatching { deps.activeSession() }.getOrNull() ?: return { _, _ -> null }
        val engine = session.engine ?: return { _, _ -> null }
        return { code, inputs ->
            val bindings = inputs.entries.joinToString(", ") { (k, v) ->
                val js = when (v) {
                    is Number -> v.toLong().toString()
                    is String -> "\"$v\""
                    else -> v.toString()
                }
                "var $k = $js"
            }
            runCatching {
                kotlinx.coroutines.runBlocking {
                    engine.evaluateJavascript("(function(){ $bindings; return String($code); })()")
                }
            }.getOrNull()
        }
    }

    private fun parseSeverity(s: String): TaintEngine.Severity = try {
        TaintEngine.Severity.valueOf(s.uppercase())
    } catch (e: Exception) {
        TaintEngine.Severity.HIGH
    }

    private fun parseCandidates(json: String): List<Pair<String, String>> {
        return runCatching {
            val arr = kotlinx.serialization.json.Json.parseToJsonElement(json) as? JsonArray ?: return@runCatching emptyList()
            arr.mapNotNull { el ->
                val obj = (el as? JsonObject) ?: return@mapNotNull null
                val name = (obj["name"] as? JsonPrimitive)?.content ?: return@mapNotNull null
                val formula = (obj["formula"] as? JsonPrimitive)?.content ?: return@mapNotNull null
                name to formula
            }
        }.getOrDefault(emptyList())
    }

    private fun parseSamples(json: String): List<ValidationEngine.Sample> {
        return runCatching {
            val arr = kotlinx.serialization.json.Json.parseToJsonElement(json) as? JsonArray ?: return@runCatching emptyList()
            arr.mapNotNull { el ->
                val obj = (el as? JsonObject) ?: return@mapNotNull null
                val inputsObj = (obj["inputs"] as? JsonObject)
                    ?.mapValues { (_, v) ->
                        (v as? JsonPrimitive)?.let { prim ->
                            prim.content.toLongOrNull() ?: prim.content.toDoubleOrNull() ?: prim.content
                        } ?: v
                    }
                    ?: emptyMap()
                val real = (obj["realOutput"] as? JsonPrimitive)?.let { prim ->
                    prim.content.toLongOrNull() ?: prim.content.toDoubleOrNull() ?: prim.content
                } ?: return@mapNotNull null
                val note = (obj["note"] as? JsonPrimitive)?.content ?: ""
                ValidationEngine.Sample(inputsObj, real, note)
            }
        }.getOrDefault(emptyList())
    }

    private fun decodeBytes(s: String): ByteArray? {
        val t = s.trim()
        runCatching {
            if (t.length % 4 == 0 && t.length >= 8 && Regex("""^[A-Za-z0-9+/=]+$""").matches(t)) {
                return java.util.Base64.getDecoder().decode(t)
            }
        }
        runCatching {
            if (t.length % 2 == 0 && Regex("""^[0-9a-fA-F]+$""").matches(t)) {
                return ByteArray(t.length / 2) { i -> t.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
            }
        }
        return t.toByteArray(Charsets.UTF_8).takeIf { it.isNotEmpty() }
    }

    // ---------------- 约束求解：DSL/JSON 解析 ----------------

    private data class Spec(
        val vars: List<String>,
        val defines: Map<String, String>,
        val asserts: List<ConstraintSpec>,
    )

    private data class ConstraintSpec(val op: ConstraintSolver.RelOp, val lhs: String, val rhs: String)

    private fun parseSpec(json: String): Spec? {
        return runCatching {
            val root = kotlinx.serialization.json.Json.parseToJsonElement(json) as? JsonObject ?: return null
            val vars = (root["vars"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.content } ?: emptyList()
            val defines = (root["defines"] as? JsonObject)
                ?.mapValues { (_, v) -> (v as? JsonPrimitive)?.content ?: "" }
                ?.filterValues { it.isNotBlank() } ?: emptyMap()
            val asserts = (root["assert"] as? JsonArray)?.mapNotNull { el ->
                val obj = (el as? JsonObject) ?: return@mapNotNull null
                toConstraintSpec(obj)
            } ?: emptyList()
            Spec(vars, defines, asserts)
        }.getOrNull()
    }

    private fun parseConstraints(json: String): List<ConstraintSpec> {
        if (json.isBlank()) return emptyList()
        return runCatching {
            val arr = kotlinx.serialization.json.Json.parseToJsonElement(json) as? JsonArray ?: return@runCatching emptyList()
            arr.mapNotNull { el -> toConstraintSpec((el as? JsonObject) ?: return@mapNotNull null) }
        }.getOrDefault(emptyList())
    }

    private fun toConstraintSpec(obj: JsonObject): ConstraintSpec? {
        val op = obj["op"] as? JsonPrimitive ?: return null
        val lhs = (obj["lhs"] as? JsonPrimitive)?.content ?: return null
        val rhs = (obj["rhs"] as? JsonPrimitive)?.content ?: return null
        val relOp = when (op.content.uppercase()) {
            "EQ" -> ConstraintSolver.RelOp.EQ
            "NE", "NEQ" -> ConstraintSolver.RelOp.NE
            "LT" -> ConstraintSolver.RelOp.LT
            "LE", "LTE", "<=" -> ConstraintSolver.RelOp.LE
            "GT" -> ConstraintSolver.RelOp.GT
            "GE", "GTE", ">=" -> ConstraintSolver.RelOp.GE
            else -> return null
        }
        return ConstraintSpec(relOp, lhs, rhs)
    }

    /** 内置四则运算（加减乘与常量）表达式解析：数字/变量 + - * ( ) */
    private fun buildSystem(spec: Spec): ConstraintSolver.ConstraintSystem {
        val cs = ConstraintSolver.ConstraintSystem()
        spec.vars.forEach { cs.declare(it) }
        spec.defines.forEach { (name, expr) ->
            val e = try { parseExpr(expr) } catch (e: Exception) { ConstraintSolver.v(name) }
            cs.define(name, e)
        }
        spec.asserts.forEach { a ->
            val lhs = parseExpr(a.lhs)
            val rhs = parseExpr(a.rhs)
            cs.addRel(a.op, lhs, rhs)
        }
        return cs
    }

    private fun toConstraint(a: ConstraintSpec): ConstraintSolver.Constraint =
        ConstraintSolver.Constraint.Rel(a.op, parseExpr(a.lhs), parseExpr(a.rhs))

    /** 非常小的递归下降表达式解析：支持 数字/变量/+-/乘法常量/括号/一元负号 */
    private fun parseExpr(s: String): ConstraintSolver.SymExpr {
        val p = ExprParser(s.trim())
        val e = p.parseExpr()
        if (p.pos < p.src.length) throw IllegalArgumentException("unexpected '${p.src[p.pos]}'")
        return e
    }

    private class ExprParser(val src: String) {
        var pos = 0
        fun peek(): Char? = if (pos < src.length) src[pos] else null

        fun parseExpr(): ConstraintSolver.SymExpr {
            var lhs = parseTerm()
            while (peek() == '+' || peek() == '-') {
                val op = peek()
                pos++
                val rhs = parseTerm()
                lhs = if (op == '+') ConstraintSolver.add(lhs, rhs) else ConstraintSolver.sub(lhs, rhs)
            }
            return lhs
        }

        private fun parseTerm(): ConstraintSolver.SymExpr {
            var neg = false
            if (peek() == '-') { neg = true; pos++ }
            var base = parseFactor()
            // 乘常量展开，支持 a*2 与 2*a 及括号
            while (peek() == '*') {
                pos++
                val right = parseFactor()
                val const = evalConstOrSwap(base, right)
                base = const
            }
            return if (neg) ConstraintSolver.neg(base) else base
        }

        /** 返回 a*b 中常数为 b 的结果；若 b 非常量则尝试视 a*b 为 b*aOpt（仅单变量 × 常量合法） */
        private fun evalConstOrSwap(a: ConstraintSolver.SymExpr, b: ConstraintSolver.SymExpr): ConstraintSolver.SymExpr {
            val ca = constOf(a)
            if (ca != null) return ConstraintSolver.mul(b, ca)
            val cb = constOf(b)
            if (cb != null) return ConstraintSolver.mul(a, cb)
            throw IllegalArgumentException("仅支持变量(表达式) × 常量")
        }

        private fun constOf(e: ConstraintSolver.SymExpr): Long? = (e as? ConstraintSolver.SymExpr.Const)?.v

        private fun parseFactor(): ConstraintSolver.SymExpr {
            return when (peek()) {
                '(' -> {
                    pos++
                    val e = parseExpr()
                    if (peek() != ')') throw IllegalArgumentException("missing )")
                    pos++
                    e
                }
                else -> parseAtom()
            }
        }

        private fun parseAtom(): ConstraintSolver.SymExpr {
            skipWs()
            val start = pos
            while (pos < src.length) {
                val ch = src[pos]
                if (ch.isLetterOrDigit() || ch == '_') pos++ else break
            }
            if (pos == start) throw IllegalArgumentException("expected number or var")
            val tok = src.substring(start, pos)
            // 数字常量（可带负号由外层 neg 处理；此处支持普通整数）
            val num = tok.toLongOrNull()
            return if (num != null) ConstraintSolver.c(num) else ConstraintSolver.v(tok)
        }

        fun skipWs() { while (pos < src.length && src[pos].isWhitespace()) pos++ }
    }
}