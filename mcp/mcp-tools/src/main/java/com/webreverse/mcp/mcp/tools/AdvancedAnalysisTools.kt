package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import com.webreverse.mcp.javascript.analysis.JsvmpMicroIr
import com.webreverse.mcp.javascript.analysis.ValidationEngine
import com.webreverse.mcp.javascript.analysis.WasmMemoryProvenance
import com.webreverse.mcp.javascript.analysis.VmpDetector
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * 高级分析工具层 v1（ 新增，对应评审报告「统一数据流 + 验证闭环」落地）。
 *
 * 注册三个新能力入口：
 * - wasm.provenance：WASM 内存溯源 + JS↔WASM 统一数据流（返回内存写者/读者与边界画像）
 * - jsvmp.micro_ir：JSVMP Micro-IR + Handler 签名库 + 动态差分语义推断
 * - reverse.validate：验证闭环引擎（本地复现公式 × 浏览器真实值，反验证 EncDec/Sign 等）
 */
object AdvancedAnalysisTools {

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)

        return listOf(
            // ---------------- WASM 内存溯源 + JS↔WASM 统一数据流 ----------------
            f.tool(
                "wasm.provenance",
                "WASM 内存溯源 + JS↔WASM 统一数据流分析：逐函数扫描内存 load/store 并静态求值基址，" +
                    "得到「函数→读/写地址区间」访问谱、按写字节数排序的热点写者、以及 JS↔WASM 边界画像" +
                    "（memory 导出 / 吃内存指针的导出 / wbg 宿主导入语义）。支持对指定地址做正反向溯源" +
                    "（谁写了这段内存、谁在读），定位密钥缓冲/结果缓冲/常量区的产生与消费方；" +
                    "与 wasm.call_graph 的调用图互为补充。输入 wasm 二进制字节(base64/hex/utf8)，addr 可选做单地址溯源",
                ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                timeoutMs = 30_000,
                capabilities = "wasm,wasm-memory-provenance,static-analysis,data-flow",
                cost = 4, reliability = 75,
                inputSchema = Schemas.objectSchema(
                    "wasm" to Schemas.strSchema("WASM 二进制内容（base64 优先；其次 hex）"),
                    "addr" to Schemas.longSchema("可选：对指定内存地址做单点溯源（十进制）"),
                    "length" to Schemas.intSchema("溯源长度（默认 4 字节；addr 给定时生效）"),
                ),
            ) { args ->
                val wasmStr = ToolArgs.str(args, "wasm")
                if (wasmStr.isBlank()) return@tool McpToolResult.error("INVALID_ARGS", "wasm 参数必填（base64/hex）")
                val bytes = decodeBytes(wasmStr) ?: return@tool McpToolResult.error("DECODE_FAILED", "wasm 内容解码失败")
                val engine = WasmMemoryProvenance()

                val addr = ToolArgs.long(args, "addr", -1L)
                if (addr >= 0) {
                    val len = ToolArgs.int(args, "length", 4).coerceIn(1, 128)
                    val p = engine.provenance(bytes, addr, len.toLong())
                    return@tool McpToolResult.json(
                        buildJsonObject {
                            put("ok", JsonPrimitive(true))
                            put("mode", JsonPrimitive("single-address"))
                            put("addr", JsonPrimitive("0x${addr.toString(16)}"))
                            put("length", JsonPrimitive(len))
                            put("inDataSegment", JsonPrimitive(p.dataSegment))
                            put("dataRef", JsonPrimitive(p.dataRef))
                            put("likelyDynamic", JsonPrimitive(p.likelyDynamic))
                            put("writers", JsonArray(p.writers.take(10).map { JsonPrimitive(it.funcName) }))
                            put("readers", JsonArray(p.readers.take(10).map { JsonPrimitive(it.funcName) }))
                            put("summary", JsonPrimitive(p.summary))
                        },
                    )
                }

                val r = engine.analyze(bytes)
                if (!r.ok) return@tool McpToolResult.error("ANALYZE_FAILED", r.error)
                McpToolResult.json(
                    buildJsonObject {
                        put("ok", JsonPrimitive(true))
                        put("funcCount", JsonPrimitive(r.funcs.size))
                        put("totalWrites", JsonPrimitive(r.totalWrites))
                        put("totalReads", JsonPrimitive(r.totalReads))
                        put("topWriters", JsonArray(
                            r.topWriters.take(12).map { fw ->
                                buildJsonObject {
                                    put("func", JsonPrimitive(fw.funcName))
                                    put("writeCount", JsonPrimitive(fw.writeCount))
                                    put("writeRanges", JsonArray(fw.writes.take(15).map { JsonPrimitive(it.toString()) }))
                                    put("readRanges", JsonArray(fw.reads.take(10).map { JsonPrimitive(it.toString()) }))
                                }
                            },
                        ))
                        put("boundary", buildJsonObject {
                            put("memoryExports", JsonArray(r.boundary.memoryExports.map { JsonPrimitive(it) }))
                            put("memoryPages", JsonPrimitive(r.boundary.memorySize))
                            put("pointerExports", JsonArray(
                                r.boundary.pointerExports.take(40).map { bf ->
                                    buildJsonObject {
                                        put("export", JsonPrimitive(bf.export))
                                        put("index", JsonPrimitive(bf.funcIndex))
                                        put("signature", JsonPrimitive(bf.signature))
                                        put("ptrParam", JsonPrimitive(bf.memoryPointerParam))
                                        put("category", JsonPrimitive(bf.category))
                                        put("hint", JsonPrimitive(bf.hint))
                                    }
                                },
                            ))
                            put("hostImports", JsonArray(
                                r.boundary.hostImports.take(60).map { (n, sem) ->
                                    buildJsonObject {
                                        put("name", JsonPrimitive(n))
                                        put("semantic", JsonPrimitive(sem))
                                    }
                                },
                            ))
                        })
                        put("funcs", JsonArray(
                            r.funcs.take(60).map { fa ->
                                buildJsonObject {
                                    put("index", JsonPrimitive(fa.funcIndex))
                                    put("name", JsonPrimitive(fa.funcName))
                                    put("writes", JsonPrimitive(fa.writeCount))
                                    put("reads", JsonPrimitive(fa.readCount))
                                    put("writeRanges", JsonArray(fa.writes.take(8).map { JsonPrimitive(it.toString()) }))
                                }
                            },
                        ))
                        put("hint", JsonPrimitive(
                            "wasm.provenance addr=0x.. 对任意内存地址返回写者/读者链；pointerExports 命中 'method/ptr-passing' 的导出即 JS 传指针的人口，hostImports 的 [MEM]/[CRYPTO] 即宿主依赖",
                        ))
                    },
                )
            },

            // ---------------- JSVMP Micro-IR + Handler 签名库 + 动态差分语义推断 ----------------
            f.tool(
                "jsvmp.micro_ir",
                "JSVMP Micro-IR + Handler 签名库 + 动态差分语义推断：先把 dispatch case 体归一为微观指令序列" +
                    "（LOAD_CONST/READ_CTX/ARITH(op)/WRITE_CTX/BRANCH/CALL...，含 arity 推断），再把每条折叠成稳定语义签名并写入" +
                    "跨脚本共享签名库；支持 diff_signature 模式对比两份脚本的签名库（升级前后判定围绕 key 的 patch 是否仍有效）。" +
                    "infer 模式则用运行时 (输入→输出) 样本做差分语义推断（XOR/ADD/SUB/... 逐个喂样本,唯一全命中者胜出）——把静态微观语义从猜测升级为可验证事实",
                ToolCategory.REVERSE,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                timeoutMs = 30_000,
                capabilities = "jsvmp,jsvmp-micro-ir,jsvmp-signature,dynamic-tracing",
                cost = 3, reliability = 70,
                inputSchema = Schemas.objectSchema(
                    "source" to Schemas.strSchema("JSVMP 脚本源码（scriptId 与 source 二选一）"),
                    "mode" to Schemas.enumSchema("执行模式", "translate", "diff_signature", "infer"),
                    "sourceB" to Schemas.strSchema("diff_signature 模式的第二份源码"),
                    "opcode" to Schemas.strSchema("infer 模式下待推断语义的 opcode"),
                    "samples" to Schemas.strSchema("infer 模式样本 JSON 数组，每条 {\"a\":N,\"b\":N,\"out\":N}"),
                ),
            ) { args ->
                val mode = ToolArgs.str(args, "mode").ifBlank { "translate" }
                val engine = JsvmpMicroIr()
                when (mode) {
                    "diff_signature" -> {
                        val sa = ToolArgs.str(args, "source")
                        val sb = ToolArgs.str(args, "sourceB")
                        if (sa.isBlank() || sb.isBlank()) {
                            return@tool McpToolResult.error("INVALID_ARGS", "diff_signature 需 source + sourceB")
                        }
                        val sigA = collectSignatures(sa)
                        val sigB = collectSignatures(sb)
                        val common = (sigA.keys intersect sigB.keys)
                        val onlyA = sigA.keys - sigB.keys
                        val onlyB = sigB.keys - sigA.keys
                        McpToolResult.json(
                            buildJsonObject {
                                put("ok", JsonPrimitive(true))
                                put("mode", JsonPrimitive("diff_signature"))
                                put("signatureCountA", JsonPrimitive(sigA.size))
                                put("signatureCountB", JsonPrimitive(sigB.size))
                                put("shared", JsonPrimitive(common.size))
                                put("onlyA", JsonPrimitive(onlyA.size))
                                put("onlyB", JsonPrimitive(onlyB.size))
                                put("sharedSigs", JsonArray(common.take(30).map { JsonPrimitive(it) }))
                                put("onlyBSigs", JsonArray(onlyB.take(30).map { JsonPrimitive(it) }))
                                put("conclusion", JsonPrimitive(
                                    if (onlyB.isEmpty()) "B 是 A 的纯扩展/同构（签名区段无漂移，既有 patch 大概率有效）"
                                    else "B 引入 ${onlyB.size} 个新签名区段，需检查与目标动作相关的 signature 是否漂移",
                                ))
                            },
                        )
                    }
                    "infer" -> {
                        val opcode = ToolArgs.str(args, "opcode")
                        if (opcode.isBlank()) return@tool McpToolResult.error("INVALID_ARGS", "infer 需 opcode")
                        val samplesJson = ToolArgs.str(args, "samples")
                        if (samplesJson.isBlank()) return@tool McpToolResult.error("INVALID_ARGS", "infer 需 samples JSON")
                        val samples = parseSamples(samplesJson)
                        if (samples.size < 2) return@tool McpToolResult.error("INSUFFICIENT", "样本不足（至少 2 条，含边界值更佳）")
                        val candidates = listOf("XOR", "AND", "OR", "ADD", "SUB", "MUL", "SHL", "SHR", "ROTL", "ROTR", "MOD")
                        val r = engine.inferSemantics(opcode, samples, candidates)
                        McpToolResult.json(
                            buildJsonObject {
                                put("ok", JsonPrimitive(r.ok))
                                put("mode", JsonPrimitive("infer"))
                                put("opcode", JsonPrimitive(opcode))
                                if (r.ok) {
                                    put("winner", JsonPrimitive(r.winner))
                                    put("confirmed", JsonPrimitive(r.confirmed))
                                    put("confidence", JsonPrimitive("%.0f".format(r.confidence * 100)))
                                    put("samplesUsed", JsonPrimitive(r.samplesUsed))
                                    put("candidates", JsonArray(r.candidates.map { JsonPrimitive(it) }))
                                }
                                put("evidence", JsonArray(r.evidence.map { JsonPrimitive(it) }))
                                put("hint", JsonPrimitive(
                                    if (r.ok) "opcode $opcode 的语义已由差分样本验证为 $r.winner"
                                    else "先用 jsvmp.snapshot 采集该 opcode 的栈顶两输入与栈顶输出，作为样本；候选含 XOR/ADD/SUB/AND/OR/MUL/SHL/SHR/ROTL/ROTR/MOD",
                                ))
                            },
                        )
                    }
                    else -> { // translate
                        val source = ToolArgs.str(args, "source")
                        if (source.isBlank()) return@tool McpToolResult.error("INVALID_ARGS", "translate 需 source")
                        val candidates = VmpDetector().detect(source)
                        val cand = candidates.firstOrNull()
                            ?: return@tool McpToolResult.error("NO_VMP_FOUND", "未检测到 JSVMP dispatch 结构")
                        val units = engine.translate(cand.handlers)
                        McpToolResult.json(
                            buildJsonObject {
                                put("ok", JsonPrimitive(true))
                                put("mode", JsonPrimitive("translate"))
                                put("dispatchLine", JsonPrimitive(cand.line))
                                put("unitCount", JsonPrimitive(units.size))
                                put("signatureLibrarySize", JsonPrimitive(JsvmpMicroIr.SignatureLibrary.size()))
                                put("units", JsonArray(
                                    units.take(80).map { u ->
                                        buildJsonObject {
                                            put("opcode", JsonPrimitive(u.key))
                                            put("normalized", JsonPrimitive(u.normalizedKey))
                                            put("signature", JsonPrimitive(u.signature))
                                            put("arity", JsonPrimitive(u.arity))
                                            put("summary", JsonPrimitive(u.summary))
                                            put("microOps", JsonArray(u.ops.map { JsonPrimitive("${it.op.display}:${it.detail}") }))
                                        }
                                    },
                                ))
                                put("hint", JsonPrimitive("signatureLibrarySize 即跨脚本累计签名数；diff_signature 模式可判定升级前后 patch 是否漂移"))
                            },
                        )
                    }
                }
            },

            // ---------------- 验证闭环引擎 ----------------
            f.tool(
                "reverse.validate",
                "验证闭环引擎：把「本地复现公式 × 浏览器真实值」做闭环比对——对每个候选公式，用当前页面执行器" +
                    "（浏览器 evaluateJavascript）按样本输入求值，与观测到的真实输出比对；唯一全命中者胜出并给置信度。还支持" +
                    "diff_two 对两个候选公式差分定位分歧样本。核心用途：EncDec/Sign/签名算法从样本猜出的公式，喂浏览器真实值闭环验证，杜绝'恰好对'",
                ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.MEDIUM,
                timeoutMs = 60_000,
                capabilities = "validation,dynamic-tracing,decrypt",
                cost = 4, reliability = 80,
                inputSchema = Schemas.objectSchema(
                    "candidates" to Schemas.strSchema("候选公式 JSON 数组，每条 {\"name\":\"XOR\",\"formula\":\"({a} ^ {b}) >>> 0\"}；占位符用 {输入键名}"),
                    "samples" to Schemas.strSchema("浏览器观测样本 JSON 数组，每条 {\"inputs\":{\"a\":12,\"b\":4},\"realOutput\":8}；differential 模式用 {\"inputs\":{..},\"observed\":\"..\"}（observed 可省）"),
                    "mode" to Schemas.enumSchema("执行模式", "validate", "diff_two", "differential"),
                    "formulaB" to Schemas.strSchema("diff_two 模式的第二公式"),
                    "hypotheses" to Schemas.strSchema("differential 模式：假设族 JSON 数组，每条 {\"name\":\"h1\",\"formulas\":[{\"name\":\"f1\",\"formula\":\"...\"}]}"),
                ),
            ) { args ->
                val mode = ToolArgs.str(args, "mode").ifBlank { "validate" }
                // 当前页面执行器（浏览器真实复现）。在 suspend 上下文先取好 session，
                // executor 是普通函数，需把它放到 suspend 上下文中求值。这里用外部 suspend 函数 preparedExecutor。
                val prepared = prebuildExecutor(deps)
                val executor = ValidationEngine.JsExecutor { code, inputs ->
                    prepared(code, inputs)
                }

                if (mode == "diff_two") {
                    val formulaA = ToolArgs.str(args, "candidates")
                    val formulaB = ToolArgs.str(args, "formulaB")
                    val samples = parseValSamples(ToolArgs.str(args, "samples"))
                    if (formulaA.isBlank() || formulaB.isBlank() || samples.isEmpty()) {
                        return@tool McpToolResult.error("INVALID_ARGS", "diff_two 需 candidates(公式A) + formulaB + samples")
                    }
                    val trace = ValidationEngine().diffTwo(executor, samples, formulaA, formulaB)
                    return@tool McpToolResult.text(trace)
                }

                if (mode == "differential") {
                    // 多样本差分执行：多假设族 × 多样本，既比对金标准又互相差分
                    val samplesJson = ToolArgs.str(args, "samples")
                    val hypothesesJson = ToolArgs.str(args, "hypotheses")
                    if (samplesJson.isBlank() || hypothesesJson.isBlank()) {
                        return@tool McpToolResult.error("INVALID_ARGS", "differential 需 samples（inputs+可选 observed）+ hypotheses（多组公式）")
                    }
                    val diffSamples = parseDifferentialSamples(samplesJson)
                    val groups = parseHypothesisGroups(hypothesesJson)
                    if (diffSamples.isEmpty()) return@tool McpToolResult.error("PARSE_ERROR", "samples 解析失败（需 [{\"inputs\":{..},\"observed\":\"..\"}]）")
                    if (groups.isEmpty()) return@tool McpToolResult.error("PARSE_ERROR", "hypotheses 解析失败（需 [{\"name\":..,\"formulas\":[{\"name\":..,\"formula\":..}]}]）")
                    val rep = ValidationEngine().differentialRun(executor, diffSamples, groups)
                    if (!rep.ok) return@tool McpToolResult.error("DIFFERENTIAL_FAILED", rep.error)
                    McpToolResult.json(buildJsonObject {
                        put("ok", true)
                        put("mode", JsonPrimitive("differential"))
                        put("sampleCount", JsonPrimitive(rep.sampleCount))
                        put("groupCount", JsonPrimitive(rep.groupCount))
                        put("hasObserved", JsonPrimitive(rep.hasObserved))
                        put("winner", JsonPrimitive(rep.winner))
                        put("winnerConfidence", JsonPrimitive("%.0f".format(rep.winnerConfidence * 100)))
                        put("observedAccuracy", JsonObject(rep.observedAccuracy.map { (k, v) -> k to JsonPrimitive("%.0f".format(v * 100)) }.toMap()))
                        put("internalConsistency", JsonObject(rep.internalConsistency.map { (k, v) -> k to JsonPrimitive("%.0f".format(v * 100)) }.toMap()))
                        put("agreement", JsonObject(rep.agreement.map { (a, m) ->
                            a to JsonObject(m.map { (b, v) -> b to JsonPrimitive("%.0f".format(v * 100)) }.toMap())
                        }.toMap()))
                        put("divergenceSamples", JsonArray(rep.divergenceSamples.map(::JsonPrimitive)))
                        put("needsMoreSamples", JsonPrimitive(rep.needsMoreSamples))
                        put("matrix", JsonArray(rep.matrix.take(400).map { c ->
                            buildJsonObject {
                                put("sample", c.sampleIndex); put("group", c.groupName); put("matched", c.matched); put("consistent", c.consistent)
                                put("outputs", JsonArray(c.outputs.take(8).map { (n, v) -> JsonPrimitive("$n=$v") }))
                            }
                        }))
                        put("summary", JsonPrimitive(rep.summary))
                    })
                }

                val candidatesJson = ToolArgs.str(args, "candidates")
                val samplesJson = ToolArgs.str(args, "samples")
                if (candidatesJson.isBlank() || samplesJson.isBlank()) {
                    return@tool McpToolResult.error("INVALID_ARGS", "validate 需 candidates + samples（JSON）")
                }
                val candidates = parseCandidates(candidatesJson)
                val samples = parseValSamples(samplesJson)
                if (candidates.isEmpty()) return@tool McpToolResult.error("PARSE_ERROR", "candidates 解析失败（需 [{\"name\":..,\"formula\":..}]）")
                if (samples.isEmpty()) return@tool McpToolResult.error("PARSE_ERROR", "samples 解析失败（需 [{\"inputs\":{..},\"realOutput\":..}]）")

                val report = ValidationEngine().validate(executor, samples, candidates)
                val theBest = report.best
                McpToolResult.json(
                    buildJsonObject {
                        put("ok", JsonPrimitive(report.ok))
                        put("sampleCount", JsonPrimitive(report.sampleCount))
                        put("candidateCount", JsonPrimitive(report.candidateCount))
                        if (theBest != null) {
                            put("best", JsonPrimitive(theBest.formula))
                            put("hitRate", JsonPrimitive("%.0f".format(theBest.hitRate * 100)))
                            put("match", JsonPrimitive("${theBest.matchCount}/${theBest.total}"))
                        }
                        put("winner", JsonPrimitive(report.winnerNamed))
                        put("confirmed", JsonPrimitive(report.confirmed))
                        put("confidence", JsonPrimitive("%.0f".format(report.confidence * 100)))
                        put("verdicts", JsonArray(
                            report.verdicts.map { v ->
                                buildJsonObject {
                                    put("formula", JsonPrimitive(v.formula))
                                    put("hitRate", JsonPrimitive("%.0f".format(v.hitRate * 100)))
                                    put("match", JsonPrimitive("${v.matchCount}/${v.total}"))
                                    put("failedSamples", JsonArray(
                                        v.failedSamples.take(10).map { (idx, msg) ->
                                            JsonPrimitive("样本$idx: $msg")
                                        },
                                    ))
                                }
                            },
                        ))
                        put("diffTrace", JsonPrimitive(report.diffTrace))
                        put("hint", JsonPrimitive(
                            if (report.confirmed) "验证闭环通过：${report.winnerNamed} 在 ${report.sampleCount} 条浏览器真实样本上全部一致，可放心用于 Hook 覆写/本地复现"
                            else "未唯一收敛：补边界样本（0/负数/大数）再跑；或检查占位符名与 inputs 键是否一致",
                        ))
                    },
                )
            },
        )
    }

    // ---------------- helpers ----------------

    /** 在 suspend 上下文预构建浏览器 JS 执行器（普通函数，供 ValidationEngine 同步调用） */
    private suspend fun prebuildExecutor(deps: ToolDependencies): (String, Map<String, Any>) -> String? {
        val session = runCatching { deps.activeSession() }.getOrNull()
        val engine = session?.engine ?: return { _, _ -> null }
        return { code, inputs ->
            val a = (inputs["a"] ?: 0L).asJs()
            val b = (inputs["b"] ?: 0L).asJs()
            runCatching {
                kotlinx.coroutines.runBlocking {
                    engine.evaluateJavascript("(function(){ var a=$a, b=$b; return String($code); })()")
                }
            }.getOrNull()
        }
    }

    private fun collectSignatures(source: String): Map<String, String> {
        val detect = VmpDetector().detect(source)
        return detect.firstOrNull()?.let { cand ->
            JsvmpMicroIr().translate(cand.handlers).associate { it.signature to it.normalizedKey }
        } ?: emptyMap()
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

    private fun parseValSamples(json: String): List<ValidationEngine.Sample> {
        return runCatching {
            val arr = kotlinx.serialization.json.Json.parseToJsonElement(json) as? JsonArray ?: return@runCatching emptyList()
            arr.mapNotNull { el ->
                val obj = (el as? JsonObject) ?: return@mapNotNull null
                val inputsObj = (obj["inputs"] as? JsonObject)
                    ?.mapValues { (_, v) -> (v as? JsonPrimitive)?.let { prim -> prim.content.toLongOrNull() ?: prim.content } ?: v }
                    ?: emptyMap()
                val real = (obj["realOutput"] as? JsonPrimitive)?.let { prim ->
                    prim.content.toLongOrNull() ?: prim.content
                } ?: return@mapNotNull null
                ValidationEngine.Sample(inputsObj, real)
            }
        }.getOrDefault(emptyList())
    }

    private fun parseDifferentialSamples(json: String): List<ValidationEngine.DifferentialSample> {
        return runCatching {
            val arr = kotlinx.serialization.json.Json.parseToJsonElement(json) as? JsonArray ?: return@runCatching emptyList()
            arr.mapNotNull { el ->
                val obj = (el as? JsonObject) ?: return@mapNotNull null
                val inputsObj = (obj["inputs"] as? JsonObject)
                    ?.mapValues { (_, v) -> (v as? JsonPrimitive)?.let { prim -> prim.content.toLongOrNull() ?: prim.content } ?: v }
                    ?: emptyMap()
                if (inputsObj.isEmpty()) return@mapNotNull null
                val observed = (obj["observed"] as? JsonPrimitive)?.content
                ValidationEngine.DifferentialSample(inputsObj, observed)
            }
        }.getOrDefault(emptyList())
    }

    private fun parseHypothesisGroups(json: String): List<ValidationEngine.HypothesisGroup> {
        return runCatching {
            val arr = kotlinx.serialization.json.Json.parseToJsonElement(json) as? JsonArray ?: return@runCatching emptyList()
            arr.mapNotNull { el ->
                val obj = (el as? JsonObject) ?: return@mapNotNull null
                val name = (obj["name"] as? JsonPrimitive)?.content ?: return@mapNotNull null
                val formulasArr = (obj["formulas"] as? JsonArray) ?: return@mapNotNull null
                val formulas = formulasArr.mapNotNull { fe ->
                    val fo = (fe as? JsonObject) ?: return@mapNotNull null
                    val fn = (fo["name"] as? JsonPrimitive)?.content ?: return@mapNotNull null
                    val ff = (fo["formula"] as? JsonPrimitive)?.content ?: return@mapNotNull null
                    fn to ff
                }
                if (formulas.isEmpty()) return@mapNotNull null
                ValidationEngine.HypothesisGroup(name, formulas)
            }
        }.getOrDefault(emptyList())
    }

    private fun parseSamples(json: String): List<Map<String, Any>> {
        return runCatching {
            val arr = kotlinx.serialization.json.Json.parseToJsonElement(json) as? JsonArray ?: return@runCatching emptyList()
            arr.mapNotNull { el ->
                (el as? JsonObject)?.mapValues { (_, v) ->
                    (v as? JsonPrimitive)?.let { it.content.toLongOrNull() ?: it.content } ?: v
                }
            }
        }.getOrDefault(emptyList())
    }

    private fun Any.asJs(): String = when (this) {
        is Long -> toString()
        is Int -> toString()
        is Double -> if (this == toLong().toDouble()) toLong().toString() else toString()
        is String -> "\"$this\""
        else -> toString()
    }

    /** wasm 参数解码：base64 优先；其次 hex；其次视为 UTF-8 */
    private fun decodeBytes(s: String): ByteArray? {
        val t = s.trim()
        // base64
        runCatching {
            if (t.length % 4 == 0 && t.length >= 8 && Regex("""^[A-Za-z0-9+/=]+$""").matches(t)) {
                return java.util.Base64.getDecoder().decode(t)
            }
        }
        // hex
        runCatching {
            if (t.length % 2 == 0 && Regex("""^[0-9a-fA-F]+$""").matches(t)) {
                return ByteArray(t.length / 2) { i -> t.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
            }
        }
        return if (t.startsWith("(\u0006asm") || t.contains("\\0asm")) null else t.toByteArray(Charsets.UTF_8).takeIf { it.isNotEmpty() }
    }
}