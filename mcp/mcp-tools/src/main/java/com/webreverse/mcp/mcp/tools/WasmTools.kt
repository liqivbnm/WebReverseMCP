package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.browser.engine.wasm.WabtEngine
import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.common.util.WorkDir
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import com.webreverse.mcp.javascript.analysis.WasmAnalyzer
import com.webreverse.mcp.javascript.analysis.WasmCfgAnalyzer
import com.webreverse.mcp.javascript.analysis.WasmDisassembler
import com.webreverse.mcp.javascript.analysis.WasmImportTracer
import com.webreverse.mcp.javascript.analysis.WasmParser
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.io.File

/**
 * WASM 逆向工具链。
 *
 * 工作流：
 * 1. 页面加载时 hookWebAssembly（document_start 已默认安装）采集模块字节码引用 + 导出函数调用观测
 * 2. wasm.dump_module 结构级解析（纯 Kotlin 解析器：imports/exports/签名/加密热点/data 段）
 * 3. wasm.disassemble 指令级反汇编（离屏 wabt 引擎：完整 WAT、按函数分页、落盘可检索）
 * 4. wasm.wat2wasm 补丁重编译（改完的 WAT 编译回 WASM 并注入页面，供对照/重放实验）
 * 5. wasm.inspect_memory / wasm.write_memory 线性内存读写（明文/密文定位 + 篡改重放）
 *
 * 传输通道：所有字节拉取均分块（256KB/块）经 evaluateJavascript 往返，
 * Kotlin 侧拼接，规避 Chromium executeJavascript 大字符串 IPC 限制。
 */
object WasmTools {

    private val parser = WasmParser()
    private val json = Json { ignoreUnknownKeys = true }
    private const val PULL_CHUNK = 256 * 1024

    /**
     * 解析 evaluateJavascript 的返回值为 JsonObject。
     *
     * WebView evaluateJavascript 回调返回的是「JSON 编码后」的结果：
     * JS 表达式返回字符串 "{...}" 时，Kotlin 侧实际收到 "\"{\\\"chunk\\\":...}\""（外层再包一层引号）。
     * 直接 as JsonObject 必然 ClassCastException —— 这是 中
     * dump_module/disassemble 误报 MODULE_NOT_FOUND、inspect/write_memory 误报 PARSE_ERROR 的根因。
     */
    private fun parseJsObject(raw: String?): JsonObject? {
        if (raw.isNullOrBlank() || raw.trim() == "null") return null
        return try {
            when (val el = json.parseToJsonElement(raw.trim())) {
                is JsonObject -> el
                // 外层被引号包裹：剥一层再解析
                is JsonPrimitive -> json.parseToJsonElement(el.content) as? JsonObject
                else -> null
            }
        } catch (e: Exception) {
            null
        }
    }

    /** 分块拉取结果 */
    private data class PullResult(
        val bytes: ByteArray,
        val totalSize: Int,
        val truncated: Boolean,
    )

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)
        return listOf(
            f.tool(
                "wasm.list_modules", "列出页面采集到的 WASM 模块（体积/来源URL/imports/exports；由 document_start 早期 Hook 自动捕获，含导出函数调用观测）", ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val script = """
                    (function(){
                      var W = globalThis.__WRMCP_WASM__ || [];
                      try { globalThis.__WRMCP_HOOK__ && globalThis.__WRMCP_HOOK__.hookWasm && globalThis.__WRMCP_HOOK__.hookWasm(function(){}); } catch(e){}
                      var calls = globalThis.__WRMCP_WASM_CALLS__ || [];
                      return JSON.stringify({ modules: W.map(function(m, i){
                        return { index: i, size: m.size, url: m.url || '',
                                 importKeys: (m.importKeys||[]).slice(0,50),
                                 exportNames: (m.exportNames||[]).slice(0,100) };
                      }), callCount: calls.length, recentCalls: calls.slice(-5).map(function(c){ return {fn:c.fn, args:(c.args||[]).slice(0,6), ret: c.ret}; }) });
                    })()
                """.trimIndent()
                val raw = session.engine.evaluateJavascript(script)
                    ?: return@tool McpToolResult.error("EVALUATE_FAILED", "JS 执行失败")
                McpToolResult.text(raw)
            },

            f.tool(
                "wasm.dump_module",
                "解析 WASM 模块为结构级 WAT（imports/exports/函数签名/name section 函数名/加密热点函数/data 段；纯 Kotlin 解析器）",
                ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "index" to Schemas.intSchema("模块序号（来自 wasm.list_modules，默认 0）"),
                    "path" to Schemas.strSchema("本地 .wasm 文件相对路径（文件模式：模块被 GC/页面跳转后仍可分析；browser.download 下载的文件直接可用，与 index 二选一且优先）"),
                    "maxBytes" to Schemas.intSchema("最多拉取的字节数（默认 4194304=4MB；分块拉取）"),
                    "wat" to Schemas.boolSchema("是否同时输出结构级 WAT 文本（默认 true）"),
                ),
            ) { args ->
                val index = ToolArgs.int(args, "index", 0)
                val path = ToolArgs.str(args, "path")
                val maxBytes = ToolArgs.int(args, "maxBytes", 4_194_304)
                val wantWat = ToolArgs.bool(args, "wat", true)
                val (pulled, source) = when (val fileBytes = loadFromPath(deps, path)) {
                    null -> {
                        val session = deps.activeSession()
                        val p = pullModuleBytes(session, index, maxBytes)
                            ?: return@tool McpToolResult.error("MODULE_NOT_FOUND", pullError ?: "模块序号无效或无字节码")
                        p to "page[$index]"
                    }
                    else -> PullResult(fileBytes, fileBytes.size, false) to "file[$path]"
                }
                val parsed = parser.parse(pulled.bytes)
                McpToolResult.json(
                    buildJsonObject {
                        put("source", JsonPrimitive(source))
                        put("moduleSize", JsonPrimitive(pulled.totalSize))
                        put("truncated", JsonPrimitive(pulled.truncated))
                        put("parseOk", JsonPrimitive(parsed.ok))
                        if (!parsed.ok) {
                            put("error", JsonPrimitive(parsed.error))
                            return@buildJsonObject
                        }
                        put("version", JsonPrimitive(parsed.version))
                        put("imports", JsonPrimitive(parsed.imports.size))
                        put("exports", JsonPrimitive(parsed.exports.size))
                        put("localFunctions", JsonPrimitive(parsed.localFunctions.size))
                        put("memories", JsonPrimitive((parsed.memories + parsed.importedMemories).size))
                        put("dataSegments", JsonPrimitive(parsed.dataSegments.size))
                        put("customSections", JsonPrimitive(parsed.customSections.joinToString(",")))
                        put(
                            "importList",
                            JsonArray(
                                parsed.imports.take(60).map {
                                    buildJsonObject {
                                        put("module", JsonPrimitive(it.module))
                                        put("name", JsonPrimitive(it.name))
                                        put("kind", JsonPrimitive(it.kind))
                                        if (it.typeIndex >= 0) put("typeIndex", JsonPrimitive(it.typeIndex))
                                    }
                                },
                            ),
                        )
                        put(
                            "exportList",
                            JsonArray(
                                parsed.exports.take(80).map {
                                    buildJsonObject {
                                        put("name", JsonPrimitive(it.name))
                                        put("kind", JsonPrimitive(it.kind))
                                        put("index", JsonPrimitive(it.index))
                                    }
                                },
                            ),
                        )
                        // 加密热点：xor/rot/mul 加权 top 函数（无指令级反汇编时的实用近似）
                        val hot = parsed.funcBodies.sortedByDescending { it.cryptoScore }.take(8)
                            .filter { it.cryptoScore > 0 }
                        if (hot.isNotEmpty()) {
                            put(
                                "cryptoHotspots",
                                JsonArray(
                                    hot.map {
                                        buildJsonObject {
                                            put("func", JsonPrimitive(it.name ?: "func_${it.index}"))
                                            put("index", JsonPrimitive(it.index))
                                            put("bodyBytes", JsonPrimitive(it.bodySize))
                                            put("cryptoScore", JsonPrimitive(it.cryptoScore))
                                            put(
                                                "topOpcodes",
                                                JsonPrimitive(it.topOpcodes.take(6).joinToString(",") { (n, c) -> "$n:$c" }),
                                            )
                                        }
                                    },
                                ),
                            )
                        }
                        // data 段预览（密钥表/常量表所在地）
                        if (parsed.dataSegments.isNotEmpty()) {
                            put(
                                "dataPreview",
                                JsonArray(
                                    parsed.dataSegments.take(8).map {
                                        buildJsonObject {
                                            put("mode", JsonPrimitive(it.mode))
                                            put("memory", JsonPrimitive(it.memoryIndex))
                                            put("offset", JsonPrimitive(it.offsetExpr))
                                            put("length", JsonPrimitive(it.length))
                                            put("utf8", JsonPrimitive(it.previewUtf8))
                                        }
                                    },
                                ),
                            )
                        }
                        if (wantWat) put("wat", JsonPrimitive(parser.toWat(parsed)))
                    },
                )
            },

            f.tool(
                "wasm.disassemble",
                "指令级反汇编：用离屏 wabt 引擎把 WASM 转完整 WAT（带 name section 函数名），按函数分页返回；可落盘到工作目录供 file.search 检索",
                ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.MEDIUM,
                timeoutMs = 150_000, // 覆盖 WabtEngine 内部 120s 任务超时，避免 30s 默认工具超时被误杀
                inputSchema = Schemas.objectSchema(
                    "index" to Schemas.intSchema("模块序号（来自 wasm.list_modules，默认 0）"),
                    "path" to Schemas.strSchema("本地 .wasm 文件相对路径（文件模式：模块被 GC/页面跳转后仍可分析；与 index 二选一且优先）"),
                    "startFunc" to Schemas.intSchema("起始函数序号（默认 0）"),
                    "endFunc" to Schemas.intSchema("结束函数序号（不含；默认 startFunc+20）"),
                    "maxBytes" to Schemas.intSchema("最多拉取字节数（默认 8388608=8MB）"),
                    "fold" to Schemas.boolSchema("是否折叠表达式（默认 false，展开更适合分析）"),
                    "save" to Schemas.boolSchema("是否把完整 WAT 落盘到工作目录（默认 true）"),
                ),
            ) { args ->
                val index = ToolArgs.int(args, "index", 0)
                val path = ToolArgs.str(args, "path")
                val startFunc = ToolArgs.int(args, "startFunc", 0).coerceAtLeast(0)
                val endFuncArg = ToolArgs.int(args, "endFunc", startFunc + 20)
                val maxBytes = ToolArgs.int(args, "maxBytes", 8_388_608)
                val fold = ToolArgs.bool(args, "fold", false)
                val save = ToolArgs.bool(args, "save", true)
                val ctx = deps.browserService.appContext()
                val (wasmBytes, totalSize, source) = when (val fileBytes = loadFromPath(deps, path)) {
                    null -> {
                        val session = deps.activeSession()
                        val p = pullModuleBytes(session, index, maxBytes)
                            ?: return@tool McpToolResult.error("MODULE_NOT_FOUND", pullError ?: "模块序号无效或无字节码")
                        Triple(p.bytes, p.totalSize, "page[$index]")
                    }
                    else -> Triple(fileBytes, fileBytes.size, "file[$path]")
                }
                val wat = when (val r = WabtEngine.wasmToWat(ctx, wasmBytes, fold)) {
                    is WabtEngine.WabtResult.Wat -> r.wat
                    is WabtEngine.WabtResult.Failure ->
                        return@tool McpToolResult.error("WASM2WAT_FAILED", r.reason)
                    is WabtEngine.WabtResult.Wasm ->
                        return@tool McpToolResult.error("WASM2WAT_FAILED", "意外结果类型")
                }
                // 按顶层 "(func" 行切函数边界
                val lines = wat.lines()
                val funcStarts = ArrayList<Int>()
                lines.forEachIndexed { i, l -> if (l.startsWith("(func")) funcStarts.add(i) }
                val totalFuncs = funcStarts.size
                val endFunc = if (endFuncArg <= startFunc) startFunc + 20 else endFuncArg
                val headerOverview = funcStarts.take(400).map { lines[it].take(160) }
                val pageText = if (funcStarts.isEmpty()) {
                    wat.take(64_000)
                } else {
                    val from = funcStarts[startFunc.coerceAtMost(totalFuncs - 1)]
                    val to = if (endFunc >= totalFuncs) lines.size else funcStarts[endFunc]
                    lines.subList(from, to).joinToString("\n").take(96_000)
                }
                var savedPath: String? = null
                if (save) {
                    runCatching {
                        val file: File = WorkDir.resolve(ctx, "wasm_dis_$index.wat")
                        file.parentFile?.mkdirs()
                        file.writeText(wat)
                        savedPath = file.absolutePath
                    }
                }
                McpToolResult.json(
                    buildJsonObject {
                        put("source", JsonPrimitive(source))
                        put("moduleSize", JsonPrimitive(totalSize))
                        put("watChars", JsonPrimitive(wat.length))
                        put("totalFuncs", JsonPrimitive(totalFuncs))
                        put("pageRange", JsonPrimitive("$startFunc..$endFunc"))
                        put("funcHeaders", JsonArray(headerOverview.take(200).map { JsonPrimitive(it) }))
                        put("watPage", JsonPrimitive(pageText))
                        savedPath?.let {
                            put("savedTo", JsonPrimitive(it))
                            put("hint", JsonPrimitive("完整 WAT 已落盘，可用 file.search / file.read 分段离线检索"))
                        }
                    },
                )
            },

            f.tool(
                "wasm.wat2wasm",
                "把（修改后的）WAT 编译回 WASM 二进制，注入页面全局 __WRMCP_WASM_COMPILED__ 供实例化对照；用于篡改常量表/插入 trace 后重放",
                ToolCategory.REVERSE,
                PermissionScope.MODIFY_PAGE, RiskLevel.HIGH,
                timeoutMs = 150_000, // 覆盖 WabtEngine 内部 120s 任务超时
                inputSchema = Schemas.objectSchema(
                    "wat" to Schemas.strSchema("WAT 文本（与 path 二选一）"),
                    "path" to Schemas.strSchema("WAT 文件路径（wat 为空时从工作目录读，如 wasm_dis_0.wat 修改后的文件）"),
                ),
            ) { args ->
                var wat = ToolArgs.str(args, "wat")
                val path = ToolArgs.str(args, "path")
                if (wat.isBlank() && path.isNotBlank()) {
                    val file: File = WorkDir.resolve(deps.browserService.appContext(), path)
                    if (!file.exists()) return@tool McpToolResult.error("FILE_NOT_FOUND", "WAT 文件不存在: $path")
                    wat = runCatching { file.readText() }.getOrNull()
                        ?: return@tool McpToolResult.error("READ_FAILED", "WAT 文件读取失败")
                }
                if (wat.isBlank()) return@tool McpToolResult.error("INVALID_ARGS", "wat 或 path 必填")
                val ctx = deps.browserService.appContext()
                val bytes = when (val r = WabtEngine.watToWasm(ctx, wat)) {
                    is WabtEngine.WabtResult.Wasm -> r.bytes
                    is WabtEngine.WabtResult.Failure ->
                        return@tool McpToolResult.error("WAT2WASM_FAILED", r.reason)
                    is WabtEngine.WabtResult.Wat ->
                        return@tool McpToolResult.error("WAT2WASM_FAILED", "意外结果类型")
                }
                // 注入页面：分块推送 base64 -> new WebAssembly.Module(bytes)
                val session = deps.activeSession()
                val b64 = android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)
                val engine = session.engine
                engine.evaluateJavascript("globalThis.__WR_WAT2WASM_IN__ = ''")
                var off = 0
                while (off < b64.length) {
                    val part = b64.substring(off, minOf(off + PULL_CHUNK, b64.length))
                    engine.evaluateJavascript("globalThis.__WR_WAT2WASM_IN__ += ${org.json.JSONObject.quote(part)}")
                    off += PULL_CHUNK
                }
                val injectScript = """
                    (function(){
                      try {
                        var b = atob(globalThis.__WR_WAT2WASM_IN__);
                        var u = Uint8Array.from(b, function(c){ return c.charCodeAt(0); });
                        var mod = new WebAssembly.Module(u);
                        globalThis.__WRMCP_WASM_COMPILED__ = globalThis.__WRMCP_WASM_COMPILED__ || [];
                        globalThis.__WRMCP_WASM_COMPILED__.push(mod);
                        globalThis.__WR_WAT2WASM_IN__ = '';
                        return JSON.stringify({ ok: true, index: globalThis.__WRMCP_WASM_COMPILED__.length - 1, size: u.length });
                      } catch(e) {
                        return JSON.stringify({ ok: false, error: String(e && e.message || e) });
                      }
                    })()
                """.trimIndent()
                val raw = engine.evaluateJavascript(injectScript)
                    ?: return@tool McpToolResult.error("EVALUATE_FAILED", "注入页面失败")
                val obj = parseJsObject(raw)
                    ?: return@tool McpToolResult.error("PARSE_ERROR", raw.take(200))
                if (obj["ok"]?.jsonPrimitive?.contentOrNull != "true") {
                    return@tool McpToolResult.error(
                        "INJECT_FAILED",
                        obj["error"]?.jsonPrimitive?.contentOrNull ?: raw.take(200),
                    )
                }
                McpToolResult.json(
                    buildJsonObject {
                        put("compiledSize", JsonPrimitive(bytes.size))
                        put("pageCompiledIndex", JsonPrimitive(obj["index"]?.jsonPrimitive?.intOrNull ?: -1))
                        put(
                            "hint",
                            JsonPrimitive("已注入页面 __WRMCP_WASM_COMPILED__[n]；可用 js.evaluate 实例化并替换调用点做对照实验"),
                        )
                    },
                )
            },

            // 纯 Kotlin 单函数反汇编（wabt 不可用时的兜底 + 热点函数精准打击）
            f.tool(
                "wasm.disassemble_func",
                "单函数指令级反汇编（纯 Kotlin，无 wabt 依赖）：按导出名或函数索引输出 wat 风格伪代码——符号化 call 目标 + 结构缩进 + memarg 偏移；配合 dump_module 的 cryptoHotspots 精准打击加密函数",
                ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "exportName" to Schemas.strSchema("导出函数名（与 funcIndex 二选一且优先）"),
                    "funcIndex" to Schemas.intSchema("函数索引（含导入函数计数偏移，如 cryptoHotspots 返回的 index）"),
                    "index" to Schemas.intSchema("模块序号（来自 wasm.list_modules，默认 0）"),
                    "path" to Schemas.strSchema("本地 .wasm 文件相对路径（与 index 二选一且优先）"),
                    "maxBytes" to Schemas.intSchema("最多拉取字节数（默认 8388608=8MB）"),
                    "maxInstructions" to Schemas.intSchema("最多反汇编指令数（默认 800）"),
                ),
            ) { args ->
                val exportName = ToolArgs.str(args, "exportName")
                val funcIndex = ToolArgs.int(args, "funcIndex", -1)
                val index = ToolArgs.int(args, "index", 0)
                val path = ToolArgs.str(args, "path")
                val maxBytes = ToolArgs.int(args, "maxBytes", 8_388_608)
                val maxIns = ToolArgs.int(args, "maxInstructions", 800).coerceIn(20, 5000)
                if (exportName.isBlank() && funcIndex < 0) {
                    return@tool McpToolResult.error("INVALID_ARGS", "exportName 或 funcIndex(>=0) 必填")
                }
                val (wasmBytes, totalSize, source) = when (val fileBytes = loadFromPath(deps, path)) {
                    null -> {
                        val session = deps.activeSession()
                        val p = pullModuleBytes(session, index, maxBytes)
                            ?: return@tool McpToolResult.error("MODULE_NOT_FOUND", pullError ?: "模块序号无效或无字节码")
                        Triple(p.bytes, p.totalSize, "page[$index]")
                    }
                    else -> Triple(fileBytes, fileBytes.size, "file[$path]")
                }
                val disasm = WasmDisassembler()
                val result = if (exportName.isNotBlank()) {
                    disasm.disassembleExport(wasmBytes, exportName, maxIns)
                } else {
                    disasm.disassemble(wasmBytes, funcIndex, maxIns)
                }
                if (!result.ok) {
                    return@tool McpToolResult.error("DISASM_FAILED", result.error)
                }
                McpToolResult.json(
                    buildJsonObject {
                        put("source", JsonPrimitive(source))
                        put("moduleSize", JsonPrimitive(totalSize))
                        put("funcName", JsonPrimitive(result.funcName))
                        put("funcIndex", JsonPrimitive(result.funcIndex))
                        put("signature", JsonPrimitive(result.signature))
                        put("locals", JsonPrimitive(result.localsCount))
                        put("instructionCount", JsonPrimitive(result.instructionCount))
                        put("truncated", JsonPrimitive(result.truncated))
                        put("listing", JsonPrimitive(result.listing.take(90_000)))
                    },
                )
            },

            // 按虚拟内存地址读取 data 段字节（hex + utf8 双视图）
            f.tool(
                "wasm.data_at",
                "按虚拟内存地址读取 WASM data 段内容（hex + utf8 双视图）。逆向时遇到 i32.const 指向的字符串/常量/选择器，直接用此工具读取，无需手动解析 data 段",
                ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "vaddr" to Schemas.intSchema("虚拟内存地址（如反汇编中的 i32.const 值）"),
                    "length" to Schemas.intSchema("读取字节数（默认 64）"),
                    "index" to Schemas.intSchema("模块序号（来自 wasm.list_modules，默认 0）"),
                    "path" to Schemas.strSchema("本地 .wasm 文件相对路径（与 index 二选一且优先）"),
                    "maxBytes" to Schemas.intSchema("最多拉取字节数（默认 8388608=8MB）"),
                ),
            ) { args ->
                val vaddr = ToolArgs.int(args, "vaddr", -1)
                val length = ToolArgs.int(args, "length", 64).coerceIn(1, 4096)
                val index = ToolArgs.int(args, "index", 0)
                val path = ToolArgs.str(args, "path")
                val maxBytes = ToolArgs.int(args, "maxBytes", 8_388_608)
                if (vaddr < 0) {
                    return@tool McpToolResult.error("INVALID_ARGS", "vaddr 必填且 >= 0")
                }
                val (wasmBytes, totalSize, source) = when (val fileBytes = loadFromPath(deps, path)) {
                    null -> {
                        val session = deps.activeSession()
                        val p = pullModuleBytes(session, index, maxBytes)
                            ?: return@tool McpToolResult.error("MODULE_NOT_FOUND", pullError ?: "模块序号无效或无字节码")
                        Triple(p.bytes, p.totalSize, "page[$index]")
                    }
                    else -> Triple(fileBytes, fileBytes.size, "file[$path]")
                }
                val parser = WasmParser()
                val parsed = parser.parse(wasmBytes)
                if (!parsed.ok) return@tool McpToolResult.error("PARSE_ERROR", parsed.error)
                val result = parser.readDataAtVaddr(wasmBytes, parsed, vaddr.toLong(), length)
                if (!result.ok) {
                    return@tool McpToolResult.error("READ_FAILED", result.error)
                }
                // 尝试提取可打印字符串
                val strValue = parser.readStringAtVaddr(wasmBytes, parsed, vaddr.toLong(), length)
                McpToolResult.json(
                    buildJsonObject {
                        put("source", JsonPrimitive(source))
                        put("moduleSize", JsonPrimitive(totalSize))
                        put("vaddr", JsonPrimitive(vaddr))
                        put("vaddrHex", JsonPrimitive("0x${vaddr.toString(16)}"))
                        put("segmentIndex", JsonPrimitive(result.segmentIndex))
                        put("segmentOffset", JsonPrimitive(result.segmentOffset))
                        put("relativeOffset", JsonPrimitive(result.relativeOffset))
                        put("length", JsonPrimitive(result.length))
                        put("hex", JsonPrimitive(result.hex))
                        put("utf8", JsonPrimitive(result.utf8))
                        if (strValue != null) put("string", JsonPrimitive(strValue))
                    },
                )
            },

            // wasm-bindgen 调用骨架自动生成
            f.tool(
                "wasm.bindgen_skeleton",
                "自动生成 wasm-bindgen 模块的 Node.js 调用骨架：识别 wasm-bindgen 模块，列出导出函数分类（构造函数/方法/自由函数/内存/胶水），生成包含 malloc/free、字符串读写、imports 占位的完整 JS 模板，逆向时省去手写胶水代码",
                ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "index" to Schemas.intSchema("模块序号（来自 wasm.list_modules，默认 0）"),
                    "path" to Schemas.strSchema("本地 .wasm 文件相对路径（与 index 二选一且优先）"),
                    "maxBytes" to Schemas.intSchema("最多拉取字节数（默认 8388608=8MB）"),
                ),
            ) { args ->
                val index = ToolArgs.int(args, "index", 0)
                val path = ToolArgs.str(args, "path")
                val maxBytes = ToolArgs.int(args, "maxBytes", 8_388_608)
                val (wasmBytes, totalSize, source) = when (val fileBytes = loadFromPath(deps, path)) {
                    null -> {
                        val session = deps.activeSession()
                        val p = pullModuleBytes(session, index, maxBytes)
                            ?: return@tool McpToolResult.error("MODULE_NOT_FOUND", pullError ?: "模块序号无效或无字节码")
                        Triple(p.bytes, p.totalSize, "page[$index]")
                    }
                    else -> Triple(fileBytes, fileBytes.size, "file[$path]")
                }
                val analyzer = WasmAnalyzer()
                val result = analyzer.bindgenSkeleton(wasmBytes)
                if (!result.ok) {
                    return@tool McpToolResult.error("SKELETON_FAILED", result.error)
                }
                McpToolResult.json(
                    buildJsonObject {
                        put("source", JsonPrimitive(source))
                        put("moduleSize", JsonPrimitive(totalSize))
                        put("isBindgen", JsonPrimitive(result.isBindgen))
                        put("exportCount", JsonPrimitive(result.exports.size))
                        put("importCount", JsonPrimitive(result.imports.size))
                        // 导出函数分类列表
                        put("exports", kotlinx.serialization.json.buildJsonArray {
                            result.exports.forEach { e ->
                                add(kotlinx.serialization.json.buildJsonObject {
                                    put("name", JsonPrimitive(e.name))
                                    put("funcIndex", JsonPrimitive(e.funcIndex))
                                    put("params", JsonPrimitive(e.params))
                                    put("results", JsonPrimitive(e.results))
                                    put("category", JsonPrimitive(e.category))
                                    put("hint", JsonPrimitive(e.hint))
                                })
                            }
                        })
                        // 骨架代码
                        put("skeleton", JsonPrimitive(result.skeleton.take(30_000)))
                    },
                )
            },

            // 函数级 CFG + SSA + 污点分析（纯 Kotlin，无 wabt 依赖）
            f.tool(
                "wasm.cfg_ssa",
                "CFG+SSA+污点分析（纯Kotlin，无wabt依赖）：按函数构造控制流图（基本块+分支边 br/br_if/br_table/if/loop/end），输出局部变量SSA版本，并给出 源(内存load/导入函数调用返回值) -> 汇(store/memory.grow/return) 的污点传播路径；用于定位解密/校验函数中的敏感数据流",
                ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "exportName" to Schemas.strSchema("导出函数名（与 funcIndex 二选一且优先）"),
                    "funcIndex" to Schemas.intSchema("函数索引（含导入函数计数偏移，与 exportName 二选一）"),
                    "all" to Schemas.boolSchema("分析全部本地函数（默认 false；true 时忽略 exportName/funcIndex）"),
                    "index" to Schemas.intSchema("模块序号（来自 wasm.list_modules，默认 0）"),
                    "path" to Schemas.strSchema("本地 .wasm 文件相对路径（与 index 二选一且优先）"),
                    "maxBytes" to Schemas.intSchema("最多拉取字节数（默认 8388608=8MB）"),
                ),
            ) { args ->
                val exportName = ToolArgs.str(args, "exportName")
                val funcIndex = ToolArgs.int(args, "funcIndex", -1)
                val all = ToolArgs.bool(args, "all", false)
                val index = ToolArgs.int(args, "index", 0)
                val path = ToolArgs.str(args, "path")
                val maxBytes = ToolArgs.int(args, "maxBytes", 8_388_608)
                val (wasmBytes, totalSize, source) = when (val fileBytes = loadFromPath(deps, path)) {
                    null -> {
                        val session = deps.activeSession()
                        val p = pullModuleBytes(session, index, maxBytes)
                            ?: return@tool McpToolResult.error("MODULE_NOT_FOUND", pullError ?: "模块序号无效或无字节码")
                        Triple(p.bytes, p.totalSize, "page[$index]")
                    }
                    else -> Triple(fileBytes, fileBytes.size, "file[$path]")
                }
                if (exportName.isBlank() && funcIndex < 0 && !all) {
                    return@tool McpToolResult.error("INVALID_ARGS", "exportName / funcIndex(>=0) / all 至少指定一项")
                }
                val analyzer = WasmCfgAnalyzer()
                val results = when {
                    all -> analyzer.analyzeAll(wasmBytes)
                    exportName.isNotBlank() -> listOf(analyzer.analyzeExport(wasmBytes, exportName))
                    else -> listOf(analyzer.analyze(wasmBytes, funcIndex))
                }
                if (results.size == 1 && !results[0].ok) {
                    return@tool McpToolResult.error("CFG_ANALYSIS_FAILED", results[0].error)
                }
                val valid = results.filter { it.ok }
                McpToolResult.json(
                    buildJsonObject {
                        put("source", JsonPrimitive(source))
                        put("moduleSize", JsonPrimitive(totalSize))
                        put("functions", JsonPrimitive(results.size))
                        put("analyses", JsonArray(results.map { it.toCfgJson() }))
                        put(
                            "taintSources",
                            JsonArray(valid.flatMap { it.taintPath }.map { it.source }.distinct().sorted().map { JsonPrimitive(it) }),
                        )
                        put(
                            "taintSinks",
                            JsonArray(valid.flatMap { it.taintPath }.map { it.sink }.distinct().sorted().map { JsonPrimitive(it) }),
                        )
                    },
                )
            },

            // 真 CFG-based SSA（BasicBlock + 边 + 不动点 phi + 指针追踪）
            f.tool(
                "wasm.cfgssa",
                "WASM 真 CFG-SSA：把函数切分为基本块 + 建立 CFG 边（br/br_if/br_table/if/loop/end/back-edge）+ 抽象解释不动点收敛（有限轮）——在 if/else/loop/br 合并点生成 phi 节点（含循环 local 自引用 phi），并做类型栈细分（UNKNOWN_POINTER 指针算术追踪 + 内存 load/store 地址线索），解决旧 Stack-SSA 在循环 back-edge/br 汇合点丢语义的问题",
                ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "exportName" to Schemas.strSchema("导出函数名（与 funcIndex 二选一且优先）"),
                    "funcIndex" to Schemas.intSchema("函数索引（含导入函数计数偏移，与 exportName 二选一）"),
                    "index" to Schemas.intSchema("模块序号（来自 wasm.list_modules，默认 0）"),
                    "path" to Schemas.strSchema("本地 .wasm 文件相对路径（文件模式优先）"),
                    "maxBytes" to Schemas.intSchema("最多拉取字节数（默认 8388608=8MB）"),
                    "maxInstr" to Schemas.intSchema("单函数最多解码指令数（默认 2000）"),
                ),
            ) { args ->
                val exportName = ToolArgs.str(args, "exportName")
                val funcIndex = ToolArgs.int(args, "funcIndex", -1)
                val index = ToolArgs.int(args, "index", 0)
                val path = ToolArgs.str(args, "path")
                val maxBytes = ToolArgs.int(args, "maxBytes", 8_388_608)
                val maxInstr = ToolArgs.int(args, "maxInstr", 2000)
                val (wasmBytes, totalSize, source) = when (val fileBytes = loadFromPath(deps, path)) {
                    null -> {
                        val session = deps.activeSession()
                        val p = pullModuleBytes(session, index, maxBytes)
                            ?: return@tool McpToolResult.error("MODULE_NOT_FOUND", pullError ?: "模块序号无效或无字节码")
                        Triple(p.bytes, p.totalSize, "page[$index]")
                    }
                    else -> Triple(fileBytes, fileBytes.size, "file[$path]")
                }
                if (exportName.isBlank() && funcIndex < 0) {
                    return@tool McpToolResult.error("INVALID_ARGS", "exportName / funcIndex(>=0) 至少指定一项")
                }
                val builder = com.webreverse.mcp.javascript.analysis.WasmCfgSsaBuilder()
                val res = if (exportName.isNotBlank()) builder.analyzeExport(wasmBytes, exportName, maxInstr)
                    else builder.analyze(wasmBytes, funcIndex, maxInstr)
                if (!res.ok) return@tool McpToolResult.error("CFGSSA_FAILED", res.error)
                McpToolResult.json(
                    buildJsonObject {
                        put("source", JsonPrimitive(source))
                        put("moduleSize", JsonPrimitive(totalSize))
                        put("funcName", JsonPrimitive(res.funcName))
                        put("funcIndex", JsonPrimitive(res.funcIndex))
                        put("signature", JsonPrimitive(res.signature))
                        put("instructionCount", JsonPrimitive(res.instructions.size))
                        put("phiCount", JsonPrimitive(res.phis.size))
                        put("blockCount", JsonPrimitive(res.blocks.size))
                        put("cfgEdgeCount", JsonPrimitive(res.cfgEdges.size))
                        put("cfgConverged", JsonPrimitive(res.cfgConverged))
                        put(
                            "cfgEdges",
                            JsonArray(res.cfgEdges.take(200).map { e ->
                                buildJsonObject {
                                    put("from", JsonPrimitive("B${e.from}"))
                                    put("to", JsonPrimitive(if (e.to < 0) "EXIT" else "B${e.to}"))
                                    put("kind", JsonPrimitive(e.kind))
                                    put("atAddr", JsonPrimitive(e.atAddr))
                                }
                            }),
                        )
                        put(
                            "phis",
                            JsonArray(res.phis.take(100).map { p ->
                                buildJsonObject {
                                    put("target", JsonPrimitive(p.target))
                                    put("sources", JsonArray(p.sources.map { JsonPrimitive(it) }))
                                    put("type", JsonPrimitive(p.type.display))
                                    put("addr", JsonPrimitive(p.addr))
                                }
                            }),
                        )
                        put("listing", JsonPrimitive(res.listing.take(60_000)))
                    },
                )
            },

            f.tool(
                "wasm.inspect_memory",
                "读取 WASM 线性内存切片（返回 hex+utf8 双视图；用于定位明文输入/密文输出在内存中的偏移）",
                ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "memoryExpression" to Schemas.strSchema("WebAssembly.Memory 表达式（如 __WRMCP_WASM__[0].exports.memory 或模块实例引用）"),
                    "offset" to Schemas.intSchema("起始偏移（默认 0）"),
                    "length" to Schemas.intSchema("读取长度（默认 512，上限 4096）"),
                ),
            ) { args ->
                val memExpr = ToolArgs.str(args, "memoryExpression")
                val offset = ToolArgs.int(args, "offset", 0)
                val length = ToolArgs.int(args, "length", 512).coerceAtMost(4096)
                if (memExpr.isBlank()) return@tool McpToolResult.error("INVALID_ARGS", "memoryExpression 必填")
                val session = deps.activeSession()
                val script = """
                    (function(){
                      try {
                        var m = eval(${com.webreverse.mcp.browser.engine.util.JsScripts.quote(memExpr)});
                        if (!m) return JSON.stringify({error:'NULL'});
                        if (m.buffer && m.exports) m = m.exports.memory || m;
                        if (!m.buffer) return JSON.stringify({error:'NOT_MEMORY'});
                        var u = new Uint8Array(m.buffer);
                        var o = Math.max(0, Math.min($offset, u.length));
                        var n = Math.min($length, u.length - o);
                        var slice = u.subarray(o, o + n);
                        var s = '';
                        for (var i = 0; i < n; i += 0x8000) {
                          s += String.fromCharCode.apply(null, slice.subarray(i, Math.min(i + 0x8000, n)));
                        }
                        return JSON.stringify({ byteLength: u.length, offset: o, b64: btoa(s) });
                      } catch(e){ return JSON.stringify({error: String(e && e.message || e)}); }
                    })()
                """.trimIndent()
                val raw = session.engine.evaluateJavascript(script)
                    ?: return@tool McpToolResult.error("EVALUATE_FAILED", "JS 执行失败")
                val obj = parseJsObject(raw)
                    ?: return@tool McpToolResult.error("PARSE_ERROR", raw.take(200))
                if (obj.containsKey("error")) {
                    val err = (obj["error"] as JsonPrimitive).content
                    return@tool McpToolResult.error(
                        "MEMORY_READ_FAILED",
                        when (err) {
                            "NULL" -> "表达式求值为 null"
                            "NOT_MEMORY" -> "表达式不是 WebAssembly.Memory（应传 memory 对象，而非 instance）"
                            else -> err
                        },
                    )
                }
                val b64 = (obj["b64"] as JsonPrimitive).content
                val byteLength = (obj["byteLength"] as JsonPrimitive).content.toIntOrNull() ?: 0
                val realOffset = (obj["offset"] as JsonPrimitive).content.toIntOrNull() ?: 0
                val bytes = android.util.Base64.decode(b64, android.util.Base64.DEFAULT)
                val hex = bytes.take(2048).joinToString(" ") { "%02x".format(it) }
                val utf8 = String(bytes, Charsets.UTF_8)
                    .replace(Regex("[^\\x20-\\x7e]"), ".")
                    .take(2048)
                McpToolResult.json(
                    buildJsonObject {
                        put("memoryByteLength", JsonPrimitive(byteLength))
                        put("offset", JsonPrimitive(realOffset))
                        put("readLength", JsonPrimitive(bytes.size))
                        put("hex", JsonPrimitive(hex))
                        put("utf8", JsonPrimitive(utf8))
                    },
                )
            },

            f.tool(
                "wasm.write_memory",
                "写入 WASM 线性内存（inspect_memory 的镜像）：patch 密钥/开关/常量后重放观测，返回写入区 hex/utf8 校验视图",
                ToolCategory.REVERSE,
                PermissionScope.MODIFY_PAGE, RiskLevel.HIGH,
                inputSchema = Schemas.objectSchema(
                    "memoryExpression" to Schemas.strSchema("WebAssembly.Memory 表达式（如 __WRMCP_WASM__[0].exports.memory）"),
                    "offset" to Schemas.intSchema("写入起始偏移（必填 >= 0）"),
                    "hex" to Schemas.strSchema("十六进制字节（空格分隔，如 'de ad be ef'；与 utf8/base64 三选一）"),
                    "utf8" to Schemas.strSchema("按 UTF-8 文本写入（如替换明文密钥）"),
                    "base64" to Schemas.strSchema("base64 编码字节（长补丁用）"),
                ),
            ) { args ->
                val memExpr = ToolArgs.str(args, "memoryExpression")
                val offset = ToolArgs.int(args, "offset", -1)
                if (memExpr.isBlank() || offset < 0) {
                    return@tool McpToolResult.error("INVALID_ARGS", "memoryExpression 与 offset(>=0) 必填")
                }
                val hex = ToolArgs.str(args, "hex")
                val utf8 = ToolArgs.str(args, "utf8")
                val b64 = ToolArgs.str(args, "base64")
                val bytes: ByteArray = when {
                    hex.isNotBlank() -> runCatching {
                        hex.split(Regex("[\\s,]+")).filter { it.isNotEmpty() }
                            .map { it.toInt(16).toByte() }.toByteArray()
                    }.getOrNull() ?: return@tool McpToolResult.error("INVALID_HEX", "hex 解析失败")

                    utf8.isNotEmpty() -> utf8.toByteArray(Charsets.UTF_8)
                    b64.isNotBlank() -> runCatching {
                        android.util.Base64.decode(b64, android.util.Base64.DEFAULT)
                    }.getOrNull() ?: return@tool McpToolResult.error("INVALID_BASE64", "base64 解析失败")
                    else -> return@tool McpToolResult.error("INVALID_ARGS", "hex / utf8 / base64 至少一个")
                }
                if (bytes.isEmpty()) return@tool McpToolResult.error("INVALID_ARGS", "写入内容为空")
                if (bytes.size > 64 * 1024) return@tool McpToolResult.error("TOO_LARGE", "单次写入上限 64KB")
                val payload = android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)
                val session = deps.activeSession()
                val script = """
                    (function(){
                      try {
                        var m = eval(${com.webreverse.mcp.browser.engine.util.JsScripts.quote(memExpr)});
                        if (!m) return JSON.stringify({error:'NULL'});
                        if (m.buffer && m.exports) m = m.exports.memory || m;
                        if (!m.buffer) return JSON.stringify({error:'NOT_MEMORY'});
                        var u = new Uint8Array(m.buffer);
                        var o = $offset, n = ${bytes.size};
                        if (o + n > u.length) return JSON.stringify({error:'OUT_OF_RANGE', byteLength: u.length});
                        var b = atob(${com.webreverse.mcp.browser.engine.util.JsScripts.quote(payload)});
                        for (var i = 0; i < n; i++) u[o + i] = b.charCodeAt(i);
                        var s = '';
                        for (var i = 0; i < n; i++) s += String.fromCharCode(u[o + i]);
                        return JSON.stringify({ byteLength: u.length, offset: o, written: n, b64: btoa(s) });
                      } catch(e){ return JSON.stringify({error: String(e && e.message || e)}); }
                    })()
                """.trimIndent()
                val raw = session.engine.evaluateJavascript(script)
                    ?: return@tool McpToolResult.error("EVALUATE_FAILED", "JS 执行失败")
                val obj = parseJsObject(raw)
                    ?: return@tool McpToolResult.error("PARSE_ERROR", raw.take(200))
                if (obj.containsKey("error")) {
                    val err = (obj["error"] as JsonPrimitive).content
                    return@tool McpToolResult.error(
                        "MEMORY_WRITE_FAILED",
                        when (err) {
                            "NULL" -> "表达式求值为 null"
                            "NOT_MEMORY" -> "表达式不是 WebAssembly.Memory"
                            "OUT_OF_RANGE" -> "越界：offset+len 超出内存（byteLength=${(obj["byteLength"] as? JsonPrimitive)?.content}）"
                            else -> err
                        },
                    )
                }
                val verify = android.util.Base64.decode((obj["b64"] as JsonPrimitive).content, android.util.Base64.DEFAULT)
                McpToolResult.json(
                    buildJsonObject {
                        put("offset", JsonPrimitive((obj["offset"] as JsonPrimitive).content.toIntOrNull() ?: offset))
                        put("written", JsonPrimitive(verify.size))
                        put("verifyHex", JsonPrimitive(verify.take(512).joinToString(" ") { "%02x".format(it) }))
                        put(
                            "verifyUtf8",
                            JsonPrimitive(String(verify, Charsets.UTF_8).replace(Regex("[^\\x20-\\x7e]"), ".").take(512)),
                        )
                    },
                )
            },

            // 加密算法识别（常量指纹 + 指令模式双通道）
            f.tool(
                "wasm.recognize_crypto",
                "WASM 加密算法识别：常量指纹（AES S-box / SHA K 表 / ChaCha sigma / CRC32 多项式 / Base64 字母表）+ 指令模式（ARX 轮函数 / 字节混合 / 压缩函数 / 查表驱动）双通道扫描，输出算法名 + 置信度 + 关联函数 + 证据链——比 cryptoScore 排序直接定位到具体算法",
                ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "index" to Schemas.intSchema("模块序号（来自 wasm.list_modules，默认 0）"),
                    "path" to Schemas.strSchema("本地 .wasm 文件相对路径（文件模式优先）"),
                    "maxBytes" to Schemas.intSchema("最多拉取的字节数（默认 4194304=4MB）"),
                    "maxFunctions" to Schemas.intSchema("指令模式最多扫描的函数数（默认 400）"),
                ),
            ) { args ->
                val index = ToolArgs.int(args, "index", 0)
                val path = ToolArgs.str(args, "path")
                val maxBytes = ToolArgs.int(args, "maxBytes", 4_194_304)
                val maxFunctions = ToolArgs.int(args, "maxFunctions", 400)
                val (pulled, source) = when (val fileBytes = loadFromPath(deps, path)) {
                    null -> {
                        val session = deps.activeSession()
                        val p = pullModuleBytes(session, index, maxBytes)
                            ?: return@tool McpToolResult.error("MODULE_NOT_FOUND", pullError ?: "模块序号无效或无字节码")
                        p to "page[$index]"
                    }
                    else -> PullResult(fileBytes, fileBytes.size, false) to "file[$path]"
                }
                if (pulled.bytes.size < 8) {
                    return@tool McpToolResult.error("MODULE_TOO_SMALL", "模块字节过少（${pulled.bytes.size}B）")
                }
                val report = com.webreverse.mcp.javascript.analysis.WasmCryptoRecognizer()
                    .recognize(pulled.bytes, maxFunctions)
                if (!report.ok) return@tool McpToolResult.error("RECOGNIZE_FAILED", report.error)
                val recog = com.webreverse.mcp.javascript.analysis.WasmCryptoRecognizer()
                val identifications = recog.getIdentifications(pulled.bytes, maxFunctions)
                val indCall = recog.resolveCallIndirectTargets(pulled.bytes, maxFunctions)
                McpToolResult.json(
                    buildJsonObject {
                        put("source", JsonPrimitive(source))
                        put("moduleSize", JsonPrimitive(pulled.totalSize))
                        put("dataScanBytes", JsonPrimitive(report.dataScanBytes))
                        put("functionsScanned", JsonPrimitive(report.functionsScanned))
                        put("findingCount", JsonPrimitive(report.findings.size))
                        put(
                            "findings",
                            JsonArray(
                                report.findings.take(30).map { finding ->
                                    buildJsonObject {
                                        put("algorithm", JsonPrimitive(finding.algorithm))
                                        put("confidence", JsonPrimitive(finding.confidence))
                                        put("kind", JsonPrimitive(finding.kind))
                                        put("funcIndex", JsonPrimitive(finding.funcIndex))
                                        finding.funcName?.let { put("funcName", JsonPrimitive(it)) }
                                        put("evidence", JsonArray(finding.evidence.take(6).map { JsonPrimitive(it) }))
                                    }
                                },
                            ),
                        )
                        put(
                            "identifications",
                            JsonArray(
                                identifications.take(20).map { id ->
                                    buildJsonObject {
                                        put("algorithm", JsonPrimitive(id.algorithm))
                                        put("category", JsonPrimitive(id.category.name))
                                        put("confidence", JsonPrimitive(id.confidence))
                                        put("basis", JsonArray(id.basis.map { JsonPrimitive(it.name) }))
                                        put("funcIndexes", JsonArray(id.funcIndexes.take(8).map { JsonPrimitive(it) }))
                                        put("exportNames", JsonArray(id.exportNames.take(8).map { JsonPrimitive(it) }))
                                        put("evidence", JsonArray(id.evidence.take(8).map { JsonPrimitive(it) }))
                                    }
                                },
                            ),
                        )
                        put(
                            "callIndirectTargets",
                            JsonArray(
                                indCall.take(40).map { t ->
                                    buildJsonObject {
                                        put("callerFuncIndex", JsonPrimitive(t.callerFuncIndex))
                                        t.callerFuncName?.let { put("callerFuncName", JsonPrimitive(it)) }
                                        put("tableIndex", JsonPrimitive(t.tableIndex))
                                        put("typeIndex", JsonPrimitive(t.typeIndex))
                                        put("prescribedIndex", JsonPrimitive(t.prescribedIndex))
                                        put("candidateTargets", JsonArray(t.candidateTargets.take(10).map { JsonPrimitive(it) }))
                                        put("candidateNames", JsonArray(t.candidateNames.take(10).map { JsonPrimitive(it) }))
                                        put("evidence", JsonArray(t.evidence.take(6).map { JsonPrimitive(it) }))
                                    }
                                },
                            ),
                        )
                        put("summary", JsonPrimitive(report.summary))
                    },
                )
            },

            // Stack-SSA + 类型栈分析（if/else/loop 合并点 phi 恢复）
            f.tool(
                "wasm.ssa",
                "WASM Stack-SSA + 类型栈分析：栈机寄存器化（栈槽→v{n} 虚拟寄存器）+ local 版本号 + if/else/loop 合并点 phi 节点 + 逐指令类型校验（i32/i64/f32/f64/v128），输出类型化 SSA 伪代码 + 栈失步告警——解决线性版本号在控制流合并点丢语义的问题",
                ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "index" to Schemas.intSchema("模块序号（来自 wasm.list_modules，默认 0）"),
                    "path" to Schemas.strSchema("本地 .wasm 文件相对路径（文件模式优先）"),
                    "funcIndex" to Schemas.intSchema("函数索引（含导入函数偏移；与 exportName 二选一）"),
                    "exportName" to Schemas.strSchema("导出函数名（与 funcIndex 二选一且优先）"),
                    "maxInstr" to Schemas.intSchema("最多分析的指令数（默认 2000）"),
                ),
            ) { args ->
                val index = ToolArgs.int(args, "index", 0)
                val path = ToolArgs.str(args, "path")
                val funcIndex = ToolArgs.int(args, "funcIndex", -1)
                val exportName = ToolArgs.str(args, "exportName")
                val maxInstr = ToolArgs.int(args, "maxInstr", 2000)
                val (pulled, source) = when (val fileBytes = loadFromPath(deps, path)) {
                    null -> {
                        val session = deps.activeSession()
                        val p = pullModuleBytes(session, index, 4_194_304)
                            ?: return@tool McpToolResult.error("MODULE_NOT_FOUND", pullError ?: "模块序号无效或无字节码")
                        p to "page[$index]"
                    }
                    else -> PullResult(fileBytes, fileBytes.size, false) to "file[$path]"
                }
                if (pulled.bytes.size < 8) {
                    return@tool McpToolResult.error("MODULE_TOO_SMALL", "模块字节过少（${pulled.bytes.size}B）")
                }
                val ssa = com.webreverse.mcp.javascript.analysis.WasmSsaBuilder()
                val result = when {
                    exportName.isNotBlank() -> ssa.analyzeExport(pulled.bytes, exportName, maxInstr)
                    funcIndex >= 0 -> ssa.analyze(pulled.bytes, funcIndex, maxInstr)
                    else -> return@tool McpToolResult.error("INVALID_ARGS", "funcIndex 或 exportName 必填其一")
                }
                if (!result.ok) return@tool McpToolResult.error("SSA_FAILED", result.error)
                McpToolResult.json(
                    buildJsonObject {
                        put("source", JsonPrimitive(source))
                        put("funcName", JsonPrimitive(result.funcName))
                        put("funcIndex", JsonPrimitive(result.funcIndex))
                        put("signature", JsonPrimitive(result.signature))
                        put("instructionCount", JsonPrimitive(result.instructions.size))
                        put("phiCount", JsonPrimitive(result.phis.size))
                        put("vregCount", JsonPrimitive(result.vregCount))
                        put(
                            "stackIssues",
                            JsonArray(
                                result.issues.take(20).map { iss ->
                                    buildJsonObject {
                                        put("addr", JsonPrimitive(iss.addr))
                                        put("op", JsonPrimitive(iss.op))
                                        put("message", JsonPrimitive(iss.message))
                                    }
                                },
                            ),
                        )
                        put(
                            "phis",
                            JsonArray(
                                result.phis.take(50).map { phi ->
                                    buildJsonObject {
                                        put("target", JsonPrimitive(phi.target))
                                        put("sources", JsonArray(phi.sources.map { JsonPrimitive(it) }))
                                        put("type", JsonPrimitive(phi.type.display))
                                        put("addr", JsonPrimitive(phi.addr))
                                    }
                                },
                            ),
                        )
                        put(
                            "localVersions",
                            buildJsonObject {
                                result.localVersions.entries.sortedBy { it.key }.take(60).forEach { (k, v) ->
                                    put("l$k", JsonPrimitive(v))
                                }
                            },
                        )
                        put(
                            "ssaListing",
                            JsonPrimitive(result.listing.take(20_000)),
                        )
                    },
                )
            },

            // ---------- ：Import 边界观测 ----------
            f.tool(
                "wasm.trace_imports",
                "WASM import 边界观测（ 新增）：静态扫描全部函数体的 call 指令，建立 import -> 调用方 -> 调用次数 的反向索引；输出热点 import 排行、从未被调用的死 import、import 分类画像（Emscripten 运行时/WASI/JS 胶水/crypto/random）与宿主形态推断（Emscripten/WASI/Rust wasm-bindgen/Go/手写）。宿主注入函数（console/log 类）是 JS 侧拦截的理想位置",
                ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "index" to Schemas.intSchema("模块序号（来自 wasm.list_modules，默认 0）"),
                    "path" to Schemas.strSchema("本地 .wasm 文件相对路径（文件模式优先）"),
                    "maxFunctions" to Schemas.intSchema("最多扫描的函数数（默认 500）"),
                ),
            ) { args ->
                val index = ToolArgs.int(args, "index", 0)
                val path = ToolArgs.str(args, "path")
                val maxFunctions = ToolArgs.int(args, "maxFunctions", 500).coerceIn(10, 5000)
                val (pulled, source) = when (val fileBytes = loadFromPath(deps, path)) {
                    null -> {
                        val session = deps.activeSession()
                        val p = pullModuleBytes(session, index, 4_194_304)
                            ?: return@tool McpToolResult.error("MODULE_NOT_FOUND", pullError ?: "模块序号无效或无字节码")
                        p to "page[$index]"
                    }
                    else -> PullResult(fileBytes, fileBytes.size, false) to "file[$path]"
                }
                val tracer = WasmImportTracer()
                val report = tracer.traceImports(pulled.bytes, maxFunctions)
                if (!report.ok) return@tool McpToolResult.error("TRACE_FAILED", report.error)
                val profile = report.profile
                    ?: return@tool McpToolResult.error("TRACE_FAILED", "导入分析失败：profile 缺失")
                McpToolResult.json(
                    buildJsonObject {
                        put("source", JsonPrimitive(source))
                        put("moduleSize", JsonPrimitive(pulled.totalSize))
                        put("functionsScanned", JsonPrimitive(report.functionsScanned))
                        put("runtimeGuess", JsonPrimitive(profile.runtimeGuess))
                        put(
                            "importStats",
                            buildJsonObject {
                                put("total", JsonPrimitive(profile.totalImports))
                                put("func", JsonPrimitive(profile.funcImports))
                                put("memory", JsonPrimitive(profile.memoryImports))
                                put("table", JsonPrimitive(profile.tableImports))
                                put("global", JsonPrimitive(profile.globalImports))
                                put(
                                    "byCategory",
                                    buildJsonObject {
                                        profile.byCategory.forEach { (k, v) -> put(k, JsonPrimitive(v)) }
                                    },
                                )
                            },
                        )
                        put(
                            "hotImports",
                            JsonArray(
                                profile.usedImports.take(30).map { u ->
                                    buildJsonObject {
                                        put("index", JsonPrimitive(u.funcIndex))
                                        put("import", JsonPrimitive("${u.module}.${u.name}"))
                                        put("category", JsonPrimitive(u.category))
                                        put("callCount", JsonPrimitive(u.callCount))
                                        put(
                                            "callers",
                                            JsonArray(
                                                u.callers.take(6).map { c ->
                                                    buildJsonObject {
                                                        put("funcIndex", JsonPrimitive(c.funcIndex))
                                                        put("funcName", JsonPrimitive(c.funcName ?: ""))
                                                        put(
                                                            "exportNames",
                                                            JsonArray(c.exportNames.map { JsonPrimitive(it) }),
                                                        )
                                                        put("calls", JsonPrimitive(c.calls))
                                                    }
                                                },
                                            ),
                                        )
                                    }
                                },
                            ),
                        )
                        put(
                            "unusedImports",
                            JsonArray(profile.unusedImports.take(60).map { JsonPrimitive("${it.module}.${it.name}") }),
                        )
                        put("summary", JsonPrimitive(report.summary))
                    },
                )
            },

            // ---------- ：Data 段字符串提取 ----------
            f.tool(
                "wasm.strings",
                "WASM data 段字符串提取（ 新增）：从全部 data 段提取可打印字符串并分类（url=请求端点 / hex=密钥候选 / base64=密文候选 / identifier=符号名残留 / message=算法自检错误），带段号与线性内存地址定位，为 crypto 识别与魔数定位提供入口",
                ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "index" to Schemas.intSchema("模块序号（来自 wasm.list_modules，默认 0）"),
                    "path" to Schemas.strSchema("本地 .wasm 文件相对路径（文件模式优先）"),
                    "minLen" to Schemas.intSchema("最小字符串长度（默认 4）"),
                    "maxStrings" to Schemas.intSchema("最多返回条数（默认 400）"),
                    "kind" to Schemas.strSchema("按类型过滤（url/hex/base64/identifier/message，留空全部）"),
                ),
            ) { args ->
                val index = ToolArgs.int(args, "index", 0)
                val path = ToolArgs.str(args, "path")
                val minLen = ToolArgs.int(args, "minLen", 4).coerceIn(2, 64)
                val maxStrings = ToolArgs.int(args, "maxStrings", 400).coerceIn(10, 2000)
                val kindFilter = ToolArgs.str(args, "kind").trim().lowercase()
                val (pulled, source) = when (val fileBytes = loadFromPath(deps, path)) {
                    null -> {
                        val session = deps.activeSession()
                        val p = pullModuleBytes(session, index, 4_194_304)
                            ?: return@tool McpToolResult.error("MODULE_NOT_FOUND", pullError ?: "模块序号无效或无字节码")
                        p to "page[$index]"
                    }
                    else -> PullResult(fileBytes, fileBytes.size, false) to "file[$path]"
                }
                val tracer = WasmImportTracer()
                val report = tracer.extractStrings(pulled.bytes, minLen, maxStrings)
                if (!report.ok) return@tool McpToolResult.error("STRINGS_FAILED", report.error)
                val filtered = if (kindFilter.isEmpty()) {
                    report.strings
                } else {
                    report.strings.filter { it.kind == kindFilter }
                }
                val byKind = filtered.groupBy { it.kind }
                McpToolResult.json(
                    buildJsonObject {
                        put("source", JsonPrimitive(source))
                        put("moduleSize", JsonPrimitive(pulled.totalSize))
                        put("segmentsScanned", JsonPrimitive(report.segmentsScanned))
                        put("bytesScanned", JsonPrimitive(report.bytesScanned))
                        put("count", JsonPrimitive(filtered.size))
                        put(
                            "byKind",
                            buildJsonObject {
                                byKind.forEach { (k, v) -> put(k, JsonPrimitive(v.size)) }
                            },
                        )
                        put(
                            "strings",
                            JsonArray(
                                filtered.take(200).map { s ->
                                    buildJsonObject {
                                        put("value", JsonPrimitive(s.value))
                                        put("kind", JsonPrimitive(s.kind))
                                        put("segmentIndex", JsonPrimitive(s.segmentIndex))
                                        put("memoryOffset", JsonPrimitive(s.memoryOffset))
                                        put("length", JsonPrimitive(s.length))
                                    }
                                },
                            ),
                        )
                        put("summary", JsonPrimitive(report.summary))
                    },
                )
            },

            // 导入边界分析（静态实现）
            f.tool(
                "wasm.import_boundary",
                "WASM 导入边界分析：沿调用图求每个导出函数（及每个本地函数）传递可达的宿主 imports（env.* / wbg.* / __wbindgen_*），并标注 wbg 导入的 DOM/env 语义——揭示某个 export 在运行时实际依赖哪些浏览器 API（querySelector / navigator.webdriver / crypto / fetch…），是 Node 复刻补环境的直接依据。逆向 wasm-bindgen 签名/加密模块的边界探测首选",
                ToolCategory.REVERSE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "index" to Schemas.intSchema("模块序号（来自 wasm.list_modules，默认 0）"),
                    "path" to Schemas.strSchema("本地 .wasm 文件相对路径（文件模式优先）"),
                    "maxBytes" to Schemas.intSchema("最多拉取字节数（默认 8388608=8MB）"),
                    "minImports" to Schemas.intSchema("仅返回传递可达 import 数 >= 此值的 export（默认 0 全部）"),
                ),
            ) { args ->
                val index = ToolArgs.int(args, "index", 0)
                val path = ToolArgs.str(args, "path")
                val maxBytes = ToolArgs.int(args, "maxBytes", 8_388_608)
                val minImports = ToolArgs.int(args, "minImports", 0).coerceAtLeast(0)
                val (wasmBytes, totalSize, source) = when (val fileBytes = loadFromPath(deps, path)) {
                    null -> {
                        val session = deps.activeSession()
                        val p = pullModuleBytes(session, index, maxBytes)
                            ?: return@tool McpToolResult.error("MODULE_NOT_FOUND", pullError ?: "模块序号无效或无字节码")
                        Triple(p.bytes, p.totalSize, "page[$index]")
                    }
                    else -> Triple(fileBytes, fileBytes.size, "file[$path]")
                }
                val analyzer = WasmAnalyzer()
                val b = analyzer.importReachability(wasmBytes)
                if (!b.ok) return@tool McpToolResult.error("BOUNDARY_FAILED", b.error)
                val importName = { i: Int ->
                    b.imports.getOrNull(i)?.let { "${it.module}.${it.name}" } ?: "import#$i"
                }
                val exportBoundary = b.exportBoundary.filter { it.importCount >= minImports }
                McpToolResult.json(
                    buildJsonObject {
                        put("source", JsonPrimitive(source))
                        put("moduleSize", JsonPrimitive(totalSize))
                        put("importCount", JsonPrimitive(b.imports.size))
                        put(
                            "imports",
                            JsonArray(
                                b.imports.take(200).map { r ->
                                    buildJsonObject {
                                        put("index", JsonPrimitive(r.index))
                                        put("module", JsonPrimitive(r.module))
                                        put("name", JsonPrimitive(r.name))
                                        if (r.signature.isNotBlank()) put("signature", JsonPrimitive(r.signature))
                                        b.wbgSemantics[r.index]?.takeIf { it.isNotBlank() }?.let {
                                            put("semantic", JsonPrimitive(it))
                                        }
                                    }
                                },
                            ),
                        )
                        put(
                            "exportBoundary",
                            JsonArray(
                                exportBoundary.take(200).map { e ->
                                    buildJsonObject {
                                        put("export", JsonPrimitive(e.export))
                                        put("funcIndex", JsonPrimitive(e.funcIndex))
                                        put("importCount", JsonPrimitive(e.importCount))
                                        put(
                                            "imports",
                                            JsonArray(
                                                e.reachedImports.take(80).map {
                                                    buildJsonObject {
                                                        put("index", JsonPrimitive(it))
                                                        put("name", JsonPrimitive(importName(it)))
                                                        b.wbgSemantics[it]?.takeIf { it.isNotBlank() }?.let {
                                                            put("semantic", JsonPrimitive(it))
                                                        }
                                                    }
                                                },
                                            ),
                                        )
                                    }
                                },
                            ),
                        )
                        // 全模块边界汇总
                        val allImportsUsed = exportBoundary.flatMap { it.reachedImports }.distinct()
                        put("moduleImportsUsed", JsonPrimitive(allImportsUsed.size))
                        put(
                            "moduleImportSemantics",
                            JsonArray(
                                allImportsUsed.take(100).mapNotNull { i ->
                                    b.wbgSemantics[i]?.takeIf { it.isNotBlank() }?.let { s ->
                                        buildJsonObject {
                                            put("index", JsonPrimitive(i))
                                            put("name", JsonPrimitive(importName(i)))
                                            put("semantic", JsonPrimitive(s))
                                        }
                                    }
                                },
                            ),
                        )
                        put(
                            "hint",
                            JsonPrimitive(
                                "importCount 越小的 export，Node 复刻时需补的环境依赖越少（优先复刻）；" +
                                    "semantic 标注的 wbg 导入即该 export 在浏览器/DOM 环境读取的 API——复刻骨架时据此补 imports 占位",
                            ),
                        )
                    },
                )
            },
        )
    }

    // ---------------- 分块拉取（256KB/块，Kotlin 侧拼接） ----------------

    /**
     * 分块拉取页面内 WASM 模块字节码。
     * 每次 evaluateJavascript 只回传一个 256KB 块的 base64（~350KB 字符串），
     * 规避单次大字符串传输的 IPC 限制（评审缺陷 4 的修复）。
     */
    /**
     * 拉取失败原因（供调用方给出精确错误信息，避免一律误报 MODULE_NOT_FOUND）
     */
    @Volatile
    private var pullError: String? = null

    private suspend fun pullModuleBytes(
        session: com.webreverse.mcp.browser.engine.BrowserSession,
        index: Int,
        maxBytes: Int,
    ): PullResult? {
        val engine = session.engine
        var offset = 0
        val out = java.io.ByteArrayOutputStream()
        var totalSize = -1
        var truncated = false
        while (true) {
            val script = """
                (function(){
                  var W = globalThis.__WRMCP_WASM__ || [];
                  var m = W[$index];
                  if (!m || !m.bytes) return JSON.stringify({error:'MODULE_NOT_FOUND', count: W.length});
                  var u = m.bytes;
                  if (!(u instanceof Uint8Array) && u.buffer) u = new Uint8Array(u.buffer);
                  var o = $offset;
                  if (o >= u.length) return JSON.stringify({done: true, size: u.length});
                  var n = Math.min($PULL_CHUNK, u.length - o${if (maxBytes > 0) ", $maxBytes - o" else ""});
                  if (n <= 0) return JSON.stringify({done: true, size: u.length, truncated: true});
                  var s = '';
                  for (var i = o; i < o + n; i += 0x8000) {
                    s += String.fromCharCode.apply(null, u.subarray(i, Math.min(i + 0x8000, o + n)));
                  }
                  return JSON.stringify({ chunk: btoa(s), next: o + n, size: u.length,
                                          done: o + n >= u.length || ($maxBytes > 0 && o + n >= $maxBytes),
                                          truncated: $maxBytes > 0 && o + n < u.length && o + n >= $maxBytes });
                })()
            """.trimIndent()
            val raw = engine.evaluateJavascript(script)
            val obj = parseJsObject(raw)
            if (obj == null) {
                pullError = when {
                    raw.isNullOrBlank() || raw.trim() == "null" ->
                        "页面求值超时/失败（页面可能已跳转；可改用 path 文件模式直接分析已下载的 .wasm）"
                    raw.contains("MODULE_NOT_FOUND") ->
                        "模块不存在或字节码引用已释放（页面跳转/GC）；可改用 path 文件模式，或 browser.reload 后立即调用"
                    else -> "页面求值返回异常：${raw.take(120)}"
                }
                return null
            }
            if (obj.containsKey("error")) {
                pullError = "模块不存在或字节码引用已释放（页面跳转/GC）；可改用 path 文件模式，或 browser.reload 后立即调用"
                return null
            }
            pullError = null
            totalSize = (obj["size"] as? JsonPrimitive)?.content?.toIntOrNull() ?: totalSize
            val chunkB64 = (obj["chunk"] as? JsonPrimitive)?.content ?: break
            val chunk = runCatching { android.util.Base64.decode(chunkB64, android.util.Base64.DEFAULT) }.getOrNull() ?: return null
            out.write(chunk)
            offset = (obj["next"] as? JsonPrimitive)?.content?.toIntOrNull() ?: (offset + chunk.size)
            truncated = (obj["truncated"] as? JsonPrimitive)?.content == "true" || truncated
            if (obj["done"]?.jsonPrimitive?.content == "true") break
        }
        if (out.size() == 0) {
            pullError = "拉取到 0 字节"
            return null
        }
        return PullResult(out.toByteArray(), totalSize, truncated)
    }

    /** 读取字节来源：path 文件模式（模块被 GC 后的救援路径）优先 */
    private fun loadFromPath(deps: ToolDependencies, path: String): ByteArray? {
        if (path.isBlank()) return null
        return runCatching {
            val file: File = WorkDir.resolve(deps.browserService.appContext(), path)
            if (!file.exists()) return null
            file.readBytes()
        }.getOrNull()
    }

    /** WasmFuncAnalysis -> JSON（wasm.cfg_ssa 的输出载体） */
    private fun WasmCfgAnalyzer.WasmFuncAnalysis.toCfgJson(): JsonObject = buildJsonObject {
        put("ok", JsonPrimitive(ok))
        if (!ok && error.isNotBlank()) put("error", JsonPrimitive(error))
        put("funcIndex", JsonPrimitive(funcIndex))
        put("funcName", JsonPrimitive(funcName))
        if (signature.isNotBlank()) put("signature", JsonPrimitive(signature))
        if (ok) {
            put("summary", JsonPrimitive(summary))
            put(
                "blocks",
                JsonArray(blocks.map {
                    buildJsonObject {
                        put("id", JsonPrimitive(it.id))
                        put("start", JsonPrimitive(it.start))
                        put("end", JsonPrimitive(it.end))
                        put("kind", JsonPrimitive(it.kind))
                        put("instrCount", JsonPrimitive(it.instrCount))
                        put("addrRange", JsonPrimitive(it.addrRange))
                    }
                }),
            )
            put(
                "edges",
                JsonArray(cfgEdges.map {
                    buildJsonObject {
                        put("from", JsonPrimitive(it.from))
                        put("to", JsonPrimitive(it.to))
                        put("kind", JsonPrimitive(it.kind))
                        if (it.label >= 0) put("label", JsonPrimitive(it.label))
                    }
                }),
            )
            put(
                "ssa",
                JsonArray(ssaVersions.map {
                    buildJsonObject {
                        put("local", JsonPrimitive(it.local))
                        put(
                            "versions",
                            JsonArray(it.versions.map {
                                buildJsonObject {
                                    put("version", JsonPrimitive(it.version))
                                    put("addr", JsonPrimitive(it.addr))
                                    put("op", JsonPrimitive(it.op))
                                }
                            }),
                        )
                    }
                }),
            )
            put(
                "taint",
                JsonArray(taintPath.map {
                    buildJsonObject {
                        put("source", JsonPrimitive(it.source))
                        put("sink", JsonPrimitive(it.sink))
                        put("sourceAddr", JsonPrimitive(it.sourceAddr))
                        put("sinkAddr", JsonPrimitive(it.sinkAddr))
                        put("via", JsonArray(it.via.map { JsonPrimitive(it) }))
                        put("locals", JsonArray(it.locals.map { JsonPrimitive(it) }))
                    }
                }),
            )
        }
    }
}
