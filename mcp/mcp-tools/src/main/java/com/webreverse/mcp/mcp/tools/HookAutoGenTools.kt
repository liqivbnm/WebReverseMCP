package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/**
 * Hook 脚本自动生成（Agent 少写胶水 第 2 块）。
 *
 * 背景：hook.function/method/property 覆盖了固定形态，但真实站点经常要 hook
 * 「任意表达式目标」（webpack chunk 导出函数、深嵌套单例方法、原型方法、
 * 只有 getter 的属性、反检测环境下仍要工作的伪装 hook）——此前 Agent 必须
 * 手写整段注入 JS（深度序列化、循环引用、原生伪装、异常透传、上报通道……）。
 *
 * hook.generate / hook.generate_install / hook.gen_read 三件套：
 * - generate：按 target + capture 配置生成自包含 IIFE 脚本（不执行，可 file.write 落盘复用）；
 * - generate_install：生成并直接注入页面（幂等：同名重置）；
 * - gen_read：分页读取捕获记录（args/ret/stack/this/err/timing）+ drain。
 *
 * 生成的脚本特性：
 * 1. 不依赖页面 eval（target 解析用 new Function 全局求值 + 逐段下钻）；
 * 2. 深度序列化带循环引用保护、bigint/TypedArray/ArrayBuffer/DOM 感知、按长度截断；
 * 3. fn.toString 伪装 native code（fakeNative，规避 Function.toString 反调试检测）；
 * 4. 异常透传（不改变页面行为）；记录上限环形截断；
 * 5. 双通道上报：window.__WRMCP_HOOK_GEN__[name].records + window.__MCP__.log。
 */
object HookAutoGenTools {

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)

        val schema = Schemas.objectSchema(
            "target" to Schemas.strSchema("任意目标 JS 表达式（如 window.sign.generate / JSON.parse / document.cookie / api.client.encrypt）"),
            "name" to Schemas.strSchema("hook 名称（捕获记录的 key；空则自动从 target 生成）"),
            "mode" to Schemas.enumSchema(
                "hook 形态：auto=函数目标→函数包装，其它→属性(getter/setter)包装；function/property 强制指定",
                "auto", "function", "property",
            ),
            "capture" to Schemas.strSchema("捕获项逗号列表（args,ret,stack,this,err,timing；默认 args,ret,stack,err,timing）"),
            "deep" to Schemas.intSchema("参数/返回值对象序列化深度（默认 2，最多 4）", min = 0, max = 4),
            "maxLen" to Schemas.intSchema("单值字符串截断长度（默认 2048）", min = 64, max = 65536),
            "maxLog" to Schemas.intSchema("记录条数上限（环形，默认 200）", min = 1, max = 5000),
            "fakeNative" to Schemas.boolSchema("wrapper.toString 伪装 native code（默认 true；对抗 Function.toString 检测）"),
        )

        return listOf(
            f.tool(
                "hook.generate",
                "针对任意目标函数/属性自动生成完整 hook 脚本：参数/返回值/调用栈/异常/耗时捕获 + " +
                    "循环引用安全深度序列化 + native 伪装 + 双通道上报。只生成不安装（返回脚本源码），" +
                    "可直接 hook.generate_install 注入或 file.write 落盘复用——省去手写注入 JS 胶水",
                ToolCategory.HOOK,
                PermissionScope.INSTALL_HOOK, RiskLevel.MEDIUM,
                inputSchema = schema,
            ) { args ->
                val script = buildHookScript(args)
                    ?: return@tool McpToolResult.error("INVALID_ARGS", "target 参数必填")
                McpToolResult.json(
                    buildJsonObject {
                        put("generated", JsonPrimitive(true))
                        put("script", JsonPrimitive(script))
                        put("store", JsonPrimitive("__WRMCP_HOOK_GEN__[name].records"))
                        put(
                            "usage",
                            JsonArray(
                                listOf(
                                    "hook.generate_install 用同样参数一键注入",
                                    "或 js.evaluate 执行本脚本（返回 JSON 安装结果）",
                                    "file.write 落盘后可经 user_script / 手动粘进 Console 复用",
                                ).map { JsonPrimitive(it) },
                            ),
                        )
                    },
                )
            },

            f.tool(
                "hook.generate_install",
                "生成针对任意目标的 hook 脚本并立即注入页面（幂等：同名自动重置）。" +
                    "捕获记录写入 window.__WRMCP_HOOK_GEN__[name].records，用 hook.gen_read 读取",
                ToolCategory.HOOK,
                PermissionScope.INSTALL_HOOK, RiskLevel.HIGH,
                inputSchema = schema,
            ) { args ->
                val script = buildHookScript(args)
                    ?: return@tool McpToolResult.error("INVALID_ARGS", "target 参数必填")
                val session = deps.activeSession()
                val raw = session.engine.evaluateJavascript(script)
                val obj = RuntimeCaptureBridge.parseJsObject(raw)
                    ?: return@tool McpToolResult.error(
                        "INSTALL_FAILED",
                        "注入求值失败（页面已跳转 / CSP 拦截？）: ${raw?.take(120)}",
                    )
                if (obj["ok"]?.jsonPrimitive?.content != "true") {
                    val err = (obj["error"] as? JsonPrimitive)?.content ?: "unknown"
                    return@tool McpToolResult.error(
                        "HOOK_INSTALL_FAILED",
                        when (err) {
                            "TARGET_NOT_FOUND" -> "目标不存在或不可达：${(obj["path"] as? JsonPrimitive)?.content}（检查表达式拼写；iframe 内目标需先 frame.switch）"
                            "WRITE_PROTECTED" -> "目标属性不可写（configurable=false），无法包装：${obj["detail"]?.toString()}"
                            else -> err
                        },
                    )
                }
                val name = (obj["name"] as? JsonPrimitive)?.content ?: ""
                McpToolResult.json(
                    buildJsonObject {
                        obj.forEach { (k, v) -> put(k, v) }
                        put("readHint", JsonPrimitive("hook.gen_read {name: \"$name\", drain: true} 读取捕获"))
                    },
                )
            },

            f.tool(
                "hook.gen_read",
                "读取 hook.generate_install 生成 hook 的捕获记录（__WRMCP_HOOK_GEN__[name].records）：分页 + drain 清空；" +
                    "不带 name 时列出所有已安装的生成 hook",
                ToolCategory.HOOK,
                PermissionScope.INSTALL_HOOK, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "name" to Schemas.strSchema("hook 名称（空=列出已安装清单）"),
                    "start" to Schemas.intSchema("起始下标（默认 0）", min = 0),
                    "count" to Schemas.intSchema("本页条数（默认 50，最多 500）", min = 1, max = 500),
                    "drain" to Schemas.boolSchema("读取后删除已返回记录（默认 false）"),
                ),
            ) { args ->
                val name = ToolArgs.str(args, "name")
                val start = ToolArgs.int(args, "start", 0).coerceAtLeast(0)
                val count = ToolArgs.int(args, "count", 50).coerceIn(1, 500)
                val drain = ToolArgs.bool(args, "drain", false)
                val session = deps.activeSession()
                if (name.isBlank()) {
                    val raw = session.engine.evaluateJavascript(
                        "(function(){ var s = window.__WRMCP_HOOK_GEN__ || {}; " +
                            "return JSON.stringify({installed: Object.keys(s).map(function(k){ " +
                            "return {name:k, target:s[k].target, mode:s[k].mode, records:(s[k].records||[]).length, ts:s[k].ts}; })}); })()",
                    )
                    val obj = RuntimeCaptureBridge.parseJsObject(raw)
                    return@tool McpToolResult.json(
                        buildJsonObject {
                            put("installedCount", JsonPrimitive(
                                (obj?.get("installed") as? kotlinx.serialization.json.JsonArray)?.size ?: 0,
                            ))
                            obj?.get("installed")?.let { put("installed", it) }
                            put("hint", JsonPrimitive("传 name 参数读取对应捕获记录；drain=true 清空"))
                        },
                    )
                }
                val page = RuntimeCaptureBridge.pullRecordsPage(
                    session.engine,
                    "window.__WRMCP_HOOK_GEN__",
                    JsonPrimitive(name).toString(),
                    start,
                    count,
                    drain,
                ) ?: return@tool McpToolResult.json(
                    buildJsonObject {
                        put("ok", JsonPrimitive(false))
                        put("hint", JsonPrimitive("hook 未安装或已被页面刷新清除：先 hook.generate_install"))
                    },
                )
                McpToolResult.json(buildJsonObject {
                    put("ok", JsonPrimitive(page["ok"]?.jsonPrimitive?.content == "true"))
                    put("name", JsonPrimitive(name))
                    put("total", JsonPrimitive((page["total"] as? JsonPrimitive)?.content?.toIntOrNull() ?: 0))
                    put("returned", JsonPrimitive((page["returned"] as? JsonPrimitive)?.content?.toIntOrNull() ?: 0))
                    put("drained", JsonPrimitive(drain))
                    page["records"]?.let { put("records", it) }
                })
            },
        )
    }

    // ---------------- 脚本生成 ----------------

    private fun jstr(s: String): String = JsonPrimitive(s).toString()

    private fun buildHookScript(args: kotlinx.serialization.json.JsonObject): String? {
        val target = ToolArgs.str(args, "target").trim()
        if (target.isBlank()) return null
        val name = ToolArgs.str(args, "name").ifBlank {
            target.substringAfterLast('.').replace(Regex("[^A-Za-z0-9_]"), "_").ifBlank { "hook" } + "_${System.currentTimeMillis() % 100000}"
        }
        val mode = ToolArgs.str(args, "mode", "auto").lowercase()
        val capture = ToolArgs.str(args, "capture", "args,ret,stack,err,timing")
            .split(',').map { it.trim() }.filter { it.isNotBlank() }.toSet()
        val deep = ToolArgs.int(args, "deep", 2).coerceIn(0, 4)
        val maxLen = ToolArgs.int(args, "maxLen", 2048).coerceIn(64, 65536)
        val maxLog = ToolArgs.int(args, "maxLog", 200).coerceIn(1, 5000)
        val fakeNative = ToolArgs.bool(args, "fakeNative", true)

        val cfgJson = buildJsonObject {
            put("args", JsonPrimitive("args" in capture))
            put("ret", JsonPrimitive("ret" in capture))
            put("stack", JsonPrimitive("stack" in capture))
            put("thisVal", JsonPrimitive("this" in capture))
            put("err", JsonPrimitive("err" in capture))
            put("timing", JsonPrimitive("timing" in capture))
            put("deep", JsonPrimitive(deep))
            put("maxLen", JsonPrimitive(maxLen))
            put("maxLog", JsonPrimitive(maxLog))
        }

        return """
            (function(){
              'use strict';
              var NAME = ${jstr(name)};
              var TARGET_PATH = ${jstr(target)};
              var MODE = ${jstr(mode)};
              var CFG = $cfgJson;
              try {
                window.__WRMCP_HOOK_GEN__ = window.__WRMCP_HOOK_GEN__ || {};
                if (window.__WRMCP_HOOK_GEN__[NAME] && window.__WRMCP_HOOK_GEN__[NAME].installed) {
                  window.__WRMCP_HOOK_GEN__[NAME].records = [];
                  return JSON.stringify({ok:true, already:true, name:NAME, target:TARGET_PATH,
                    note:'同名 hook 已安装，本次调用已重置记录'});
                }
                function resolvePath(p){
                  var segs = p.split('.').filter(Boolean);
                  if (!segs.length) return null;
                  var cur;
                  try { cur = (new Function('return (' + segs[0] + ')'))(); } catch(e) { return null; }
                  if (cur == null && segs.length === 1) return null;
                  var owner = cur, key = segs[0];
                  for (var i = 1; i < segs.length; i++){
                    if (cur == null) return null;
                    owner = cur; key = segs[i];
                    try { cur = cur[segs[i]]; } catch(e) { return null; }
                  }
                  if (cur === undefined && owner !== undefined) cur = owner[key];
                  return {owner: owner, key: key, value: cur};
                }
                var resolved = resolvePath(TARGET_PATH);
                if (!resolved || resolved.value === undefined || resolved.value === null) {
                  return JSON.stringify({ok:false, error:'TARGET_NOT_FOUND', path:TARGET_PATH});
                }
                var STORE = window.__WRMCP_HOOK_GEN__;
                var seq = 0;
                function nowMs(){ return (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now(); }
                function hexPreview(u, n){
                  var s = '', end = Math.min(u.length, n || 96);
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
                    if (t === 'string') return v.length > CFG.maxLen ? v.slice(0, CFG.maxLen) + '…(' + v.length + ')' : v;
                    if (t === 'function') return '[fn ' + (v.name || 'anonymous') + ']';
                    if (t === 'symbol') return v.toString();
                    if (v instanceof ArrayBuffer) return {type:'ArrayBuffer', byteLength:v.byteLength, hex:hexPreview(new Uint8Array(v))};
                    if (ArrayBuffer.isView(v)) {
                      var u = new Uint8Array(v.buffer, v.byteOffset || 0, Math.min(v.byteLength || 0, 96));
                      return {type: v.constructor.name, length: v.length, hex: hexPreview(u)};
                    }
                    if (typeof Element !== 'undefined' && v instanceof Element) return '<' + v.tagName.toLowerCase() + (v.id ? '#' + v.id : '') + '>';
                    if (d >= CFG.deep) return '[maxdepth:' + (v.constructor && v.constructor.name) + ']';
                    if (seen.indexOf(v) >= 0) return '[circular]';
                    seen = seen.concat([v]);
                    if (Array.isArray(v)) return v.slice(0, 48).map(function(x){ return ser(x, d + 1, seen); });
                    if (t === 'object') {
                      var out = {}, keys;
                      try { keys = Object.keys(v).slice(0, 48); } catch(e) { return String(v).slice(0, 128); }
                      for (var i = 0; i < keys.length; i++) {
                        try { out[keys[i]] = ser(v[keys[i]], d + 1, seen); } catch(e) {}
                      }
                      return out;
                    }
                    return String(v);
                  } catch(e) { return '[sererr]'; }
                }
                function report(entry){
                  var rec = STORE[NAME].records;
                  if (rec.length < CFG.maxLog) rec.push(entry); else { rec.shift(); rec.push(entry); }
                  try {
                    if (window.__MCP__ && window.__MCP__.log) {
                      window.__MCP__.log('[hookgen:' + NAME + '#' + entry.seq + '] ' + JSON.stringify(entry).slice(0, 1200));
                    }
                  } catch(e) {}
                }
                var isFn = typeof resolved.value === 'function';
                var useFn = (MODE === 'function') || (MODE !== 'property' && isFn);
                if (useFn && !isFn) return JSON.stringify({ok:false, error:'NOT_A_FUNCTION', type: typeof resolved.value});
                if (useFn) {
                  var original = resolved.value;
                  var wrapper = function(){
                    seq++;
                    var entry = {ts: Date.now(), seq: seq, op: 'call'};
                    if (CFG.args) entry.args = Array.prototype.map.call(arguments, function(a){ return ser(a, 0, []); });
                    if (CFG.thisVal) entry.thisVal = ser(this, 1, []);
                    if (CFG.stack) entry.stack = ((new Error()).stack || '').split('\n').slice(1, 8).join('\n');
                    var t0 = CFG.timing ? nowMs() : 0;
                    var ret;
                    try { ret = original.apply(this, arguments); }
                    catch(e) {
                      if (CFG.timing) entry.durMs = Math.max(0, +(nowMs() - t0).toFixed(3));
                      if (CFG.err) entry.threw = ser(e, 1, []);
                      report(entry);
                      throw e;
                    }
                    if (CFG.timing) entry.durMs = Math.max(0, +(nowMs() - t0).toFixed(3));
                    if (CFG.ret) entry.ret = ser(ret, 0, []);
                    report(entry);
                    return ret;
                  };
                  try { Object.defineProperty(wrapper, 'name', {value: original.name || resolved.key}); } catch(e) {}
                  if (${JsonPrimitive(fakeNative)}) {
                    var nativeStr = 'function ' + (original.name || '') + '() { [native code] }';
                    try {
                      Object.defineProperty(wrapper, 'toString', {value: function(){ return nativeStr; }, writable: true, configurable: true});
                      Object.defineProperty(wrapper, 'length', {value: original.length || 0, writable: true, configurable: true});
                    } catch(e) {}
                  }
                  var owner = resolved.owner, key = resolved.key;
                  var desc = null, protoOwner = owner;
                  try { desc = Object.getOwnPropertyDescriptor(owner, key); } catch(e) {}
                  while (desc === undefined && protoOwner) {
                    protoOwner = Object.getPrototypeOf(protoOwner);
                    if (!protoOwner) break;
                    try { desc = Object.getOwnPropertyDescriptor(protoOwner, key); } catch(e) { desc = null; }
                    if (desc) owner = protoOwner;
                  }
                  try {
                    if (desc) Object.defineProperty(owner, key, {value: wrapper, writable: desc.writable !== false, configurable: desc.configurable !== false, enumerable: desc.enumerable});
                    else owner[key] = wrapper;
                  } catch(e) {
                    try { Object.defineProperty(owner, key, {value: wrapper, writable: true, configurable: true}); }
                    catch(e2) { return JSON.stringify({ok:false, error:'WRITE_PROTECTED', detail:String(e2).slice(0,120)}); }
                  }
                  STORE[NAME] = {installed:true, target:TARGET_PATH, mode:'function', ts:Date.now(), records:[]};
                  return JSON.stringify({ok:true, name:NAME, target:TARGET_PATH, mode:'function', fakeNative:${JsonPrimitive(fakeNative)}});
                }
                // 属性 hook：getter/setter 包装（数据属性自动转访问器）
                var owner = resolved.owner, key = resolved.key;
                var desc = null, protoOwner = owner;
                try { desc = Object.getOwnPropertyDescriptor(owner, key); } catch(e) {}
                while (desc === undefined && protoOwner) {
                  protoOwner = Object.getPrototypeOf(protoOwner);
                  if (!protoOwner) break;
                  try { desc = Object.getOwnPropertyDescriptor(protoOwner, key); } catch(e) { desc = null; }
                  if (desc) owner = protoOwner;
                }
                if (!desc) return JSON.stringify({ok:false, error:'NO_DESCRIPTOR'});
                var enumerable = desc.enumerable !== false;
                var configurable = desc.configurable !== false;
                if (!configurable) return JSON.stringify({ok:false, error:'WRITE_PROTECTED', detail:'configurable=false'});
                if (desc.get || desc.set) {
                  var g = desc.get, st = desc.set;
                  Object.defineProperty(owner, key, {
                    configurable: true, enumerable: enumerable,
                    get: g ? function(){ var v = g.call(this); seq++; report({ts:Date.now(), seq:seq, op:'get', value: ser(v, 0, [])}); return v; } : undefined,
                    set: st ? function(nv){ seq++; report({ts:Date.now(), seq:seq, op:'set', to: ser(nv, 0, [])}); return st.call(this, nv); } : undefined
                  });
                } else {
                  var val = desc.value;
                  Object.defineProperty(owner, key, {
                    configurable: true, enumerable: enumerable,
                    get: function(){ seq++; report({ts:Date.now(), seq:seq, op:'get', value: ser(val, 0, [])}); return val; },
                    set: function(nv){ seq++; report({ts:Date.now(), seq:seq, op:'set', from: ser(val, 0, []), to: ser(nv, 0, [])}); val = nv; }
                  });
                }
                STORE[NAME] = {installed:true, target:TARGET_PATH, mode:'property', ts:Date.now(), records:[]};
                return JSON.stringify({ok:true, name:NAME, target:TARGET_PATH, mode:'property'});
              } catch(e) {
                return JSON.stringify({ok:false, error:'throw:' + String(e).slice(0, 160)});
              }
            })()
        """.trimIndent()
    }
}
