package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/**
 * WASM 运行时执行追踪（静态 ←→ 运行时打通 第 2 块）。
 *
 * 背景：document_start 的 hookWasm 已经把「模块字节码 + 导出函数轻量观测」
 * 存进页面 __WRMCP_WASM__ / __WRMCP_WASM_CALLS__（args/ret/指纹/256B 内存快照/diff），
 * 但一直没有 MCP 出口，AI 拿不到这些数据；且轻量观测参数序列化浅、内存快照固定 256B，
 * 不足以验证 WasmStructuredDecompiler 的伪代码还原是否准确。
 *
 * 本工具集补三块：
 * - wasm.trace_calls：读取 hookWasm 自动采集的导出函数调用记录（fn 过滤/分页/drain），
 *   并给出与静态反编译的对照建议；
 * - wasm.trace_export：对已实例化模块的指定导出函数安装「定向深度追踪」
 *   （完整参数深度序列化 / 调用栈 / 指定地址区间内存快照前后对照 / 耗时 / 异常），
 *   记录写入 __WRMCP_WASM_TRACE__；
 * - wasm.trace_read：分页读取 / drain 定向追踪记录。
 */
object WasmTraceTools {

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)

        return listOf(
            f.tool(
                "wasm.trace_calls",
                "读取 hookWasm 自动采集的 WASM 导出函数调用记录（__WRMCP_WASM_CALLS__）：每次调用的参数/返回值/值指纹/" +
                    "ptr-len 提示/调用栈/调用前后 256B 内存快照与 diff 区间——验证 wasm.disassemble/structured 反编译还原的入口。" +
                    "drain=true 时读取后清空（持续观测工作流：清空 → 触发页面动作 → 再读增量）",
                ToolCategory.REVERSE,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.LOW, timeoutMs = 60_000,
                inputSchema = Schemas.objectSchema(
                    "fn" to Schemas.strSchema("只看指定导出函数名（如 sign / encrypt；空=全部）"),
                    "start" to Schemas.intSchema("起始下标（分页，默认 0）", min = 0),
                    "count" to Schemas.intSchema("本页条数（默认 50，最多 500）", min = 1, max = 500),
                    "includeMem" to Schemas.boolSchema("是否包含内存快照 b64（默认 false，只给 diff 区间；true 时体积大）"),
                    "drain" to Schemas.boolSchema("读取后删除已返回记录（默认 false）"),
                ),
            ) { args ->
                val fnFilter = ToolArgs.str(args, "fn")
                val start = ToolArgs.int(args, "start", 0).coerceAtLeast(0)
                val count = ToolArgs.int(args, "count", 50).coerceIn(1, 500)
                val includeMem = ToolArgs.bool(args, "includeMem", false)
                val drain = ToolArgs.bool(args, "drain", false)
                val session = deps.activeSession()

                // 读取总数（分页拉取，COUNT 上限 500 但 total 单独拿）
                val totalObj = RuntimeCaptureBridge.parseJsObject(
                    session.engine.evaluateJavascript(
                        "(function(){ var L = globalThis.__WRMCP_WASM_CALLS__ || []; " +
                            "return JSON.stringify({total: L.length}); })()",
                    ),
                )
                val total = (totalObj?.get("total") as? JsonPrimitive)?.content?.toIntOrNull() ?: 0
                if (total == 0) {
                    return@tool McpToolResult.json(
                        buildJsonObject {
                            put("total", JsonPrimitive(0))
                            put(
                                "hint",
                                JsonPrimitive(
                                    "页面尚无 WASM 调用记录。检查：1) wasm.list_modules 确认模块已采集；" +
                                        "2) hookWasm 在 document_start 注入，页面加载前打开的 tab 才生效（可 browser.reload）；" +
                                        "3) 若导出函数未被页面调用，用 wasm.trace_export 主动触发",
                                ),
                            )
                        },
                    )
                }

                val page = RuntimeCaptureBridge.pullRecordsPage(
                    session.engine,
                    "globalThis.__WRMCP_WASM_CALLS__",
                    null,
                    start,
                    count,
                    drain,
                ) ?: return@tool McpToolResult.error("READ_FAILED", RuntimeCaptureBridge.lastPullError ?: "读取失败")

                val records = page["records"]?.jsonArray ?: JsonArray(emptyList())
                val filtered = if (fnFilter.isBlank()) {
                    records
                } else {
                    records.filter { (it as? kotlinx.serialization.json.JsonObject)?.get("fn")?.toString()?.trim('"') == fnFilter }
                }
                McpToolResult.json(
                    buildJsonObject {
                        put("total", JsonPrimitive(total))
                        put("start", JsonPrimitive(start))
                        put("returned", JsonPrimitive(filtered.size))
                        put("drained", JsonPrimitive(drain))
                        if (!includeMem) {
                            put(
                                "memoryNote",
                                JsonPrimitive("已剥除 memBefore/memAfter b64（includeMem=true 获取）；memoryDiffs 保留"),
                            )
                        }
                        put("records", JsonArray(filtered.map { rec ->
                            val obj = rec as? kotlinx.serialization.json.JsonObject
                            if (!includeMem && obj != null) {
                                buildJsonObject {
                                    obj.forEach { (k, v) ->
                                        if (k != "memBefore" && k != "memAfter") put(k, v)
                                    }
                                }
                            } else {
                                rec
                            }
                        }))
                        put(
                            "nextSteps",
                            JsonArray(
                                listOf(
                                    "对热点函数跑 wasm.disassemble / wasm.structured_decompile，把 args/ret 与伪代码输入输出对齐",
                                    "ptrLenHints 给出 (ptr,len) 相邻参数对 → 用 wasm.inspect_memory 读调用前后该区间内容（如待签名字符串）",
                                    "需要更深的参数/内存捕获时用 wasm.trace_export 安装定向追踪",
                                ).map { JsonPrimitive(it) },
                            ),
                        )
                    },
                )
            },

            f.tool(
                "wasm.trace_export",
                "对已实例化的 WASM 模块导出函数安装「定向深度追踪」：包装 exports[name] 捕获完整参数" +
                    "（bigint/TypedArray/ArrayBuffer 深度序列化）/ 返回值 / 调用栈 / 耗时 / 异常，" +
                    "并支持指定内存地址区间在调用前后做快照对照（验证伪代码还原 / 定位写入内容）。" +
                    "记录写入页面 __WRMCP_WASM_TRACE__，用 wasm.trace_read 读取",
                ToolCategory.REVERSE,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "index" to Schemas.intSchema("模块序号（来自 wasm.list_modules，默认 0）", min = 0),
                    "fn" to Schemas.strSchema("导出函数名（如 sign；也可用 wasm.list_modules 的 exportNames）"),
                    "deep" to Schemas.intSchema("参数对象序列化深度（默认 2，最多 4）", min = 0, max = 4),
                    "maxLen" to Schemas.intSchema("单值字符串截断长度（默认 2048）", min = 32, max = 65536),
                    "captureStack" to Schemas.boolSchema("捕获调用栈（默认 true）"),
                    "memAddr" to Schemas.intSchema("内存快照起始地址（与 memLen 配合；不填则不做区间快照）", min = 0),
                    "memLen" to Schemas.intSchema("内存快照长度（默认 256，最大 65536）", min = 1, max = 65536),
                    "cap" to Schemas.intSchema("记录条数上限（默认 200）", min = 1, max = 5000),
                ),
            ) { args ->
                val index = ToolArgs.int(args, "index", 0)
                val fn = ToolArgs.str(args, "fn")
                if (fn.isBlank()) return@tool McpToolResult.error("INVALID_ARGS", "fn 参数必填（导出函数名）")
                val deep = ToolArgs.int(args, "deep", 2).coerceIn(0, 4)
                val maxLen = ToolArgs.int(args, "maxLen", 2048).coerceIn(32, 65536)
                val captureStack = ToolArgs.bool(args, "captureStack", true)
                val memAddr = ToolArgs.int(args, "memAddr", -1)
                val memLen = ToolArgs.int(args, "memLen", 256).coerceIn(1, 65536)
                val cap = ToolArgs.int(args, "cap", 200).coerceIn(1, 5000)
                val session = deps.activeSession()

                val js = """
                    (function(){
                      try {
                        var fn = ${kotlinx.serialization.json.JsonPrimitive(fn)};
                        var W = globalThis.__WRMCP_WASM__ || [];
                        var m = W[$index];
                        if (!m || !m.instance) return JSON.stringify({ok:false, error:'NO_INSTANCE',
                          modules: W.length, hint: '模块未实例化（仅 compile 不算）；browser.reload 后重试，或确认 wasm.list_modules 显示的模块有实例'});
                        var ex = m.instance.exports || {};
                        if (!(fn in ex)) return JSON.stringify({ok:false, error:'EXPORT_NOT_FOUND', exports: Object.keys(ex)});
                        if (typeof ex[fn] !== 'function') return JSON.stringify({ok:false, error:'NOT_FUNCTION'});
                        m.__tracePatched = m.__tracePatched || {};
                        if (m.__tracePatched[fn]) return JSON.stringify({ok:true, already:true, fn: fn});
                        var target = ex[fn];
                        m.__tracePatched[fn] = target;
                        globalThis.__WRMCP_WASM_TRACE__ = globalThis.__WRMCP_WASM_TRACE__ || [];
                        var TRACE = globalThis.__WRMCP_WASM_TRACE__;
                        var DEEP = $deep, MAXLEN = $maxLen, CAP = $cap;
                        var MEM_ON = $memAddr >= 0, MEM_ADDR = Math.max(0, $memAddr), MEM_LEN = $memLen;
                        function hexPreview(u, n){
                          var s = '', end = Math.min(u.length, n);
                          for (var i = 0; i < end; i++) s += ('0' + u[i].toString(16)).slice(-2);
                          return s + (u.length > end ? '…(' + u.length + 'B)' : '');
                        }
                        function ser(v, d, seen){
                          d = d || 0; seen = seen || [];
                          try {
                            if (v === null) return null;
                            var t = typeof v;
                            if (t === 'undefined') return 'undefined';
                            if (t === 'number' || t === 'boolean') return v;
                            if (t === 'bigint') return String(v) + 'n';
                            if (t === 'string') return v.length > MAXLEN ? v.slice(0, MAXLEN) + '…(' + v.length + ')' : v;
                            if (t === 'function') return '[fn ' + (v.name || 'anonymous') + ']';
                            if (t === 'symbol') return v.toString();
                            if (v instanceof ArrayBuffer) return {type:'ArrayBuffer', byteLength:v.byteLength, hex:hexPreview(new Uint8Array(v), 128)};
                            if (ArrayBuffer.isView(v)) {
                              var u = new Uint8Array(v.buffer, v.byteOffset, Math.min(v.byteLength, 128));
                              return {type: v.constructor.name, length: v.length, hex: hexPreview(u, 128)};
                            }
                            if (typeof Element !== 'undefined' && v instanceof Element) return '<' + v.tagName.toLowerCase() + (v.id ? '#'+v.id : '') + '>';
                            if (d >= DEEP) return '[maxdepth]';
                            if (seen.indexOf(v) >= 0) return '[circular]';
                            seen = seen.concat([v]);
                            if (Array.isArray(v)) return v.slice(0, 48).map(function(x){ return ser(x, d+1, seen); });
                            var out = {}, keys = Object.keys(v).slice(0, 48);
                            for (var i = 0; i < keys.length; i++) { try { out[keys[i]] = ser(v[keys[i]], d+1, seen); } catch(e){} }
                            return out;
                          } catch(e){ return '[sererr]'; }
                        }
                        function memSnap(inst){
                          try {
                            var mem = inst.exports && (inst.exports.memory || inst.exports.mem);
                            if (!mem || !mem.buffer) return null;
                            var u = new Uint8Array(mem.buffer);
                            var start = Math.min(MEM_ADDR, u.length);
                            var end = Math.min(start + MEM_LEN, u.length);
                            if (end <= start) return null;
                            var s = '';
                            for (var i = start; i < end; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, Math.min(i + 0x8000, end)));
                            return {addr: start, len: end - start, b64: btoa(s)};
                          } catch(e){ return null; }
                        }
                        ex[fn] = function(){
                          var t0 = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
                          var entry = { ts: Date.now(), module: $index, fn: fn,
                                        args: Array.prototype.map.call(arguments, function(a){ return ser(a, 0, []); }) };
                          if ($captureStack) entry.stack = ((new Error()).stack || '').split('\\n').slice(1, 8).join('\\n');
                          var before = MEM_ON ? memSnap(m.instance) : null;
                          var ret;
                          try { ret = target.apply(this, arguments); entry.ok = true; }
                          catch(e) { entry.ok = false; entry.error = String(e); throw e; }
                          finally {
                            var t1 = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
                            entry.durMs = Math.max(0, t1 - t0);
                            entry.ret = ser(ret, 0, []);
                            if (MEM_ON) {
                              entry.memBefore = before;
                              entry.memAfter = memSnap(m.instance);
                            }
                            if (TRACE.length < CAP) TRACE.push(entry); else { TRACE.shift(); TRACE.push(entry); }
                          }
                          return ret;
                        };
                        return JSON.stringify({ok:true, fn: fn, module: $index, memSnap: MEM_ON ? {addr: MEM_ADDR, len: MEM_LEN} : null,
                          store: '__WRMCP_WASM_TRACE__', note: '调用入口已替换为追踪包装；原函数保存在模块 __tracePatched.' + fn});
                      } catch(e) { return JSON.stringify({ok:false, error:'throw:' + String(e).slice(0,160)}); }
                    })()
                """.trimIndent()
                val raw = session.engine.evaluateJavascript(js)
                val obj = RuntimeCaptureBridge.parseJsObject(raw)
                    ?: return@tool McpToolResult.error("INJECT_FAILED", "注入求值失败（页面已跳转？）: ${raw?.take(120)}")
                if (obj["ok"]?.jsonPrimitive?.content != "true") {
                    val err = (obj["error"] as? JsonPrimitive)?.content ?: "unknown"
                    return@tool McpToolResult.error(
                        "TRACE_INSTALL_FAILED",
                        when {
                            err.startsWith("throw:") -> err.removePrefix("throw:")
                            err == "NO_INSTANCE" -> "模块未实例化（只有 compile 没有 instance）；等待页面实例化后重试"
                            err == "EXPORT_NOT_FOUND" ->
                                "导出函数不存在。可用 exports 列表选择: ${(obj["exports"] as? JsonArray)?.joinToString(", ") { it.toString().trim('"') }?.take(400)}"
                            else -> err
                        },
                    )
                }
                McpToolResult.json(buildJsonObject {
                    put("installed", JsonPrimitive(true))
                    put("fn", JsonPrimitive(fn))
                    put("moduleIndex", JsonPrimitive(index))
                    put("deep", JsonPrimitive(deep))
                    put("captureStack", JsonPrimitive(captureStack))
                    if (memAddr >= 0) {
                        put("memorySnapshot", buildJsonObject {
                            put("addr", JsonPrimitive(memAddr))
                            put("len", JsonPrimitive(memLen))
                        })
                    }
                    put("cap", JsonPrimitive(cap))
                    put("store", JsonPrimitive("__WRMCP_WASM_TRACE__"))
                    put(
                        "nextSteps",
                        JsonArray(
                            listOf(
                                "触发页面动作（点击/请求）后用 wasm.trace_read 读取捕获记录",
                                "追踪会替换页面 export 引用——结束分析后建议 browser.reload 恢复现场",
                            ).map { JsonPrimitive(it) }
                        ),
                    )
                })
            },

            f.tool(
                "wasm.trace_read",
                "分页读取 wasm.trace_export 安装的定向追踪记录（__WRMCP_WASM_TRACE__），支持 drain 清空；" +
                    "与 wasm.trace_calls（hookWasm 自动采集）互补",
                ToolCategory.REVERSE,
                PermissionScope.DEBUG_SCRIPT, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "start" to Schemas.intSchema("起始下标（默认 0）", min = 0),
                    "count" to Schemas.intSchema("本页条数（默认 50，最多 500）", min = 1, max = 500),
                    "drain" to Schemas.boolSchema("读取后删除已返回记录（默认 false）"),
                ),
            ) { args ->
                val start = ToolArgs.int(args, "start", 0).coerceAtLeast(0)
                val count = ToolArgs.int(args, "count", 50).coerceIn(1, 500)
                val drain = ToolArgs.bool(args, "drain", false)
                val session = deps.activeSession()
                val page = RuntimeCaptureBridge.pullRecordsPage(
                    session.engine,
                    "globalThis.__WRMCP_WASM_TRACE__",
                    null,
                    start,
                    count,
                    drain,
                ) ?: return@tool McpToolResult.json(
                    buildJsonObject {
                        put("total", JsonPrimitive(0))
                        put("hint", JsonPrimitive("尚无定向追踪记录：先 wasm.trace_export 安装并触发页面动作；或记录已被 drain"))
                    },
                )
                McpToolResult.json(buildJsonObject {
                    put("ok", JsonPrimitive(page["ok"]?.jsonPrimitive?.content == "true"))
                    put("total", JsonPrimitive((page["total"] as? JsonPrimitive)?.content?.toIntOrNull() ?: 0))
                    put("returned", JsonPrimitive((page["returned"] as? JsonPrimitive)?.content?.toIntOrNull() ?: 0))
                    put("drained", JsonPrimitive(drain))
                    page["records"]?.let { put("records", it) }
                })
            },
        )
    }
}
