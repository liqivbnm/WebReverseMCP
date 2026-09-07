package com.webreverse.mcp.javascript.runtime

import com.webreverse.mcp.browser.engine.BrowserEngine
import com.webreverse.mcp.browser.engine.util.JsScripts

/**
 * 运行时污点打标 / 追踪 / 上报模型（v1）。
 *
 * 与 [DynamicTracer] 的“值指纹(FNV-1a)+事件缓冲区”互补，但独立抽象：
 * 1. **污点源 / 标签**：网络响应、cookie / localStorage / sessionStorage 读取、
 *    postMessage 数据、被包装函数的处理参数等来源产生的值，被打上来源标签
 *    （[RuntimeTaintTag]）。标签以“值指纹”为键存储（JS 与宿主侧同一指纹算法，
 *    与 [DynamicTracer] 的 fp 口径一致），不改变页面业务行为。
 * 2. **传播**：沿函数调用（实参→返回）、属性读写、赋值等路径把标签从来源值
 *    复制到承接值，并记录 [TaintPropagationEvent]。
 * 3. **路径记录**：每个标签维护 source → … → sink 的节点链 [RuntimeTaintPathNode]，
 *    汇入 [RuntimeTaintFlow]，最终可汇聚成 [RuntimeTaintReport]。
 *
 * 注入的 JS（`globalThis.__WRMCP_TAINT__`）幂等；公开 API 全部新增，不影响
 * [DynamicTracer] / [JsRuntimeHook] 既有方法。宿主侧结果是纯 Kotlin 类型，可与
 * 静态 [com.webreverse.mcp.javascript.analysis.TaintEngine] 通过
 * “运行时污点标签桥接”合并（见 js-analysis 的 RuntimeTaintBridge）。
 */
class TaintTracker {

    /** 污点来源类型 */
    enum class TaintSourceType {
        /** 网络响应（fetch / XHR 返回体、响应头） */
        NETWORK_RESPONSE,
        /** document.cookie 读取 */
        COOKIE,
        /** localStorage.getItem 读取 */
        LOCAL_STORAGE,
        /** sessionStorage.getItem 读取 */
        SESSION_STORAGE,
        /** 被包装函数的处理参数 */
        FUNCTION_PARAM,
        /** 对象属性读取（Proxy get） */
        PROPERTY_READ,
        /** postMessage / MessagePort.message 收到的数据 */
        POST_MESSAGE,
        /** 显式手工打标 */
        EXPLICIT;

        /** JS 侧使用的来源名 */
        fun jsName(): String = when (this) {
            NETWORK_RESPONSE -> "network.response"
            COOKIE -> "cookie"
            LOCAL_STORAGE -> "localStorage"
            SESSION_STORAGE -> "sessionStorage"
            FUNCTION_PARAM -> "function.param"
            PROPERTY_READ -> "property.read"
            POST_MESSAGE -> "message.data"
            EXPLICIT -> "explicit"
        }
    }

    /** 单个污点标签（打标后的来源描述） */
    data class RuntimeTaintTag(
        val id: String,
        val source: TaintSourceType,
        val expr: String,
    )

    /** 沿调用/返回/属性访问的标签传播事件 */
    data class TaintPropagationEvent(
        val tagId: String,
        val kind: String,
        val fromFp: String,
        val toFp: String,
        val label: String,
    )

    /** 路径节点（source → intermediate(prop.get/call/return…) → sink） */
    data class RuntimeTaintPathNode(
        val kind: String,
        val label: String,
        val seq: Long,
    )

    /** 单条运行时污点流 */
    data class RuntimeTaintFlow(
        val tagId: String,
        val sourceLabel: String,
        val sinkLabel: String,
        val path: List<RuntimeTaintPathNode>,
    )

    /** 运行时污点上报表（对外入口） */
    data class RuntimeTaintReport(
        val flows: List<RuntimeTaintFlow>,
        val totalTags: Int,
        val propagations: Int,
        val events: Int,
    )

    companion object {
        /**
         * 污点载体 JS（幂等）：标签存储（按值指纹）、传播、路径链、汇、上报。
         * API：
         *  - T.tagWithFp(value, source, expr) -> tagId（为值打来源标签）
         *  - T.propagate(fromValue, toValue, kind, label) -> 复制的标签数
         *  - T.sink(value, sinkLabel) -> 触达汇的标签数
         *  - T.fp / T.resp 内部指纹与规整
         *  - T.report() -> JSON
         */
        private const val TAG_BOOTSTRAP = """
            (function(){
              if (globalThis.__WRMCP_TAINT__) return;
              var T = {
                n: 0, tags: {}, defs: {}, props: [], flows: [], paths: {}, evs: 0,
                fp: function(s){
                  try {
                    var v = String(s);
                    if (v.length < 3 || v.length > 4096) return '';
                    var h = 0x811c9dc5;
                    for (var i = 0; i < v.length; i++) { h ^= v.charCodeAt(i); h = (h * 0x01000193) >>> 0; }
                    return ('00000000' + h.toString(16)).slice(-8) + ':' + v.length;
                  } catch(e){ return ''; }
                },
                resp: function(v){
                  try { return (v && typeof v === 'object') ? JSON.stringify(v) : String(v); }
                  catch(e){ return String(v); }
                },
                addTag: function(fp, source, expr){
                  var id = 't' + (++T.n);
                  T.defs[id] = { id: id, source: String(source), expr: String(expr), ts: Date.now() };
                  if (!T.tags[fp]) T.tags[fp] = [];
                  T.tags[fp].push(id);
                  if (!T.paths[id]) T.paths[id] = [{ k: 'source', l: String(expr), s: T.n }];
                  return id;
                },
                tagWithFp: function(v, source, expr){
                  var fp = T.fp(T.resp(v));
                  if (!fp) return '';
                  return T.addTag(fp, source, expr);
                },
                propagate: function(fromV, toV, kind, label){
                  var ff = T.fp(T.resp(fromV)), tf = T.fp(T.resp(toV));
                  if (!ff || !tf || !T.tags[ff]) return 0;
                  if (!T.tags[tf]) T.tags[tf] = [];
                  var added = 0;
                  T.tags[ff].forEach(function(id){
                    if (T.tags[tf].indexOf(id) < 0) {
                      T.tags[tf].push(id);
                      T.paths[id].push({ k: String(kind), l: String(label), s: ++T.n });
                      T.props.push({ tagId: id, kind: String(kind), from: ff, to: tf, label: String(label) });
                      T.evs++;
                      added++;
                    }
                  });
                  return added;
                },
                sink: function(v, sinkLabel){
                  var fp = T.fp(T.resp(v));
                  if (!fp || !T.tags[fp]) return 0;
                  var c = 0;
                  T.tags[fp].forEach(function(id){
                    T.paths[id].push({ k: 'sink', l: String(sinkLabel), s: ++T.n });
                    T.flows.push({ tagId: id, source: T.defs[id].expr, sink: String(sinkLabel), path: T.paths[id].slice() });
                    T.evs++;
                    c++;
                  });
                  return c;
                },
                report: function(){
                  return JSON.stringify({ tags: Object.keys(T.defs).length, props: T.props.length, events: T.evs, flows: T.flows });
                },
                hookFunction: function(pathExpr, name){
                  try {
                    var parts = String(pathExpr).split('.');
                    var obj = globalThis;
                    for (var i = 0; i < parts.length - 1; i++) { obj = obj[parts[i]]; if (!obj) return false; }
                    var prop = parts[parts.length - 1];
                    var orig = obj[prop];
                    if (typeof orig !== 'function') return false;
                    if (orig.__wrmcp_taint__) return true;
                    var self = this;
                    var wrapped = function(){
                      var args = Array.prototype.slice.call(arguments);
                      for (var a = 0; a < args.length && a < 8; a++) self.tagWithFp(args[a], 'function.param', String(name || prop) + '.arg' + a);
                      var ret = orig.apply(this, arguments);
                      for (var b = 0; b < args.length && b < 8; b++) self.propagate(args[b], ret, 'call', String(name || prop) + '.call');
                      return ret;
                    };
                    wrapped.__wrmcp_taint__ = true;
                    obj[prop] = wrapped;
                    return true;
                  } catch(e){ return false; }
                }
              };
              globalThis.__WRMCP_TAINT__ = T;
              globalThis.__WRMCP_TAINT_EVAL__ = function(expr){ try { return eval(expr); } catch(e){ return undefined; } };
              // 自动打标：cookie / storage 读取 与 跨上下文 postMessage
              (function(){
                try {
                  var d = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
                  if (d) Object.defineProperty(document, 'cookie', {
                    get: function(){ var v = d.get.call(document); T.tagWithFp(v, 'cookie', 'document.cookie'); return v; },
                    set: function(x){ return d.set.call(document, x); },
                    configurable: true
                  });
                } catch(e){}
              })();
              (function(){
                ['localStorage', 'sessionStorage'].forEach(function(ns){
                  try {
                    var store = globalThis[ns]; if (!store) return;
                    var orig = store.getItem;
                    store.getItem = function(k){
                      var v = orig.apply(this, arguments);
                      T.tagWithFp(v === null ? '' : v, ns, ns + '.getItem(' + String(k) + ')');
                      return v;
                    };
                  } catch(e){}
                });
              })();
            })()
        """

        /**
         * 求值表达式 → 指纹并打标；返回 tagId。
         * @param jsExpr 页面内的任意 JS 表达式（如 "window.token"）。
         */
        internal fun tagValueScript(expr: String, source: String, label: String): String = """
            (function(){
              var T = globalThis.__WRMCP_TAINT__;
              if (!T) return '';
              try {
                var v = globalThis.__WRMCP_TAINT_EVAL__(${JsScripts.quote(expr)});
                var src = ${JsScripts.quote(source)};
                var lbl = ${JsScripts.quote(label)};
                var id = T.tagWithFp(v, src, lbl);
                return id === undefined || id === null ? '' : String(id);
              } catch(e){ return ''; }
            })()
        """.trimIndent()

        /** 把来源表达式值传播到目标表达式（fingerprint 桥接）。 */
        internal fun propagateScript(fromExpr: String, toExpr: String, kind: String, label: String): String = """
            (function(){
              var T = globalThis.__WRMCP_TAINT__;
              if (!T) return '0';
              try {
                var f = globalThis.__WRMCP_TAINT_EVAL__(${JsScripts.quote(fromExpr)});
                var t = globalThis.__WRMCP_TAINT_EVAL__(${JsScripts.quote(toExpr)});
                return String(T.propagate(f, t, ${JsScripts.quote(kind)}, ${JsScripts.quote(label)}));
              } catch(e){ return '0'; }
            })()
        """.trimIndent()

        /** 声明表达式值为 sink。 */
        internal fun sinkScript(expr: String, sinkLabel: String): String = """
            (function(){
              var T = globalThis.__WRMCP_TAINT__;
              if (!T) return '0';
              try {
                var v = globalThis.__WRMCP_TAINT_EVAL__(${JsScripts.quote(expr)});
                return String(T.sink(v, ${JsScripts.quote(sinkLabel)}));
              } catch(e){ return '0'; }
            })()
        """.trimIndent()

        internal const val REPORT_SCRIPT =
            "(function(){ var T = globalThis.__WRMCP_TAINT__; if (!T) return '{}'; return T.report(); })()"

        internal const val CLEAR_SCRIPT =
            "(function(){ var T = globalThis.__WRMCP_TAINT__; if (T) { T.tags = {}; T.defs = {}; T.props = []; T.flows = []; T.paths = {}; T.n = 0; T.evs = 0; } })()"
    }

    /** 注入污点载体（幂等） */
    suspend fun install(engine: BrowserEngine) {
        engine.evaluateJavascript(TAG_BOOTSTRAP)
    }

    /**
     * 为页面内表达式 [jsExpr] 的当前值打上污点来源标签，返回 tagId。
     * @return 生成的标签 id；失败返回 null。
     */
    suspend fun tagValue(engine: BrowserEngine, jsExpr: String, source: TaintSourceType, label: String = jsExpr): String? {
        install(engine)
        val r = engine.evaluateJavascript(tagValueScript(jsExpr, source.jsName(), label))
        return r?.trim('"')?.takeIf { it.startsWith("t") && it.isNotBlank() }
    }

    /** 把 [fromExpr] 上的标签传播到 [toExpr]（沿调用/返回/属性访问，kind 由调用方语义指定）。 */
    suspend fun propagate(engine: BrowserEngine, fromExpr: String, toExpr: String, kind: String, label: String): Int {
        install(engine)
        val r = engine.evaluateJavascript(propagateScript(fromExpr, toExpr, kind, label))
        return r?.trim('"')?.toIntOrNull() ?: 0
    }

    /** 声明 [jsExpr] 的值为污点 sink（触达记录并收敛为流）。 */
    suspend fun recordSink(engine: BrowserEngine, jsExpr: String, sinkLabel: String): Int {
        install(engine)
        val r = engine.evaluateJavascript(sinkScript(jsExpr, sinkLabel))
        return r?.trim('"')?.toIntOrNull() ?: 0
    }

    /**
     * 包装页面内全局路径函数（如 "window.myHandler"），使其：
     *  - 参数自动打 FUNCTION_PARAM 标签；
     *  - 返回时把参数标签传播到返回值的指纹（function.call 传播，含返回值承接）。
     * 与 [DynamicTracer.traceFunction] 可并存（互不依赖）。
     */
    suspend fun traceFunction(engine: BrowserEngine, target: String, displayName: String = target): Boolean {
        install(engine)
        val script = """
            (function(){
              var T = globalThis.__WRMCP_TAINT__;
              if (!T) return false;
              try { return T.hookFunction(${JsScripts.quote(target)}, ${JsScripts.quote(displayName)}) ? 'true' : 'false'; }
              catch(e){ return 'false'; }
            })()
        """.trimIndent()
        return engine.evaluateJavascript(script) == "true"
    }

    /** 取回运行时污点上报表（含路径记录）。 */
    suspend fun collectReport(engine: BrowserEngine): RuntimeTaintReport? {
        install(engine)
        val raw = engine.evaluateJavascript(REPORT_SCRIPT) ?: return null
        return parseReport(raw)
    }

    /** 清空运行时污点状态。 */
    suspend fun clear(engine: BrowserEngine) {
        install(engine)
        engine.evaluateJavascript(CLEAR_SCRIPT)
    }

    // ---------------- 轻量 JSON 解析（无第三方依赖） ----------------

    private sealed class JVal {
        data class JStr(val v: String) : JVal()
        data class JNum(val v: Long) : JVal()
        data class JBool(val v: Boolean) : JVal()
        object JNull : JVal()
        data class JArr(val items: List<JVal>) : JVal()
        data class JObj(val fields: Map<String, JVal>) : JVal()
    }

    private fun parseReport(raw: String): RuntimeTaintReport? {
        val root = try { parseJson(raw) } catch (e: Exception) { return null }
        if (root !is JVal.JObj) return null
        val tags = (root.fields["tags"] as? JVal.JNum)?.v?.toInt() ?: 0
        val props = (root.fields["props"] as? JVal.JNum)?.v?.toInt() ?: 0
        val events = (root.fields["events"] as? JVal.JNum)?.v?.toInt() ?: 0
        val flows = (root.fields["flows"] as? JVal.JArr)?.items.orEmpty().mapNotNull { it as? JVal.JObj }.map { f ->
            val path = (f.fields["path"] as? JVal.JArr)?.items.orEmpty().mapNotNull { it as? JVal.JObj }.map { n ->
                RuntimeTaintPathNode(
                    kind = (n.fields["k"] as? JVal.JStr)?.v ?: "",
                    label = (n.fields["l"] as? JVal.JStr)?.v ?: "",
                    seq = (n.fields["s"] as? JVal.JNum)?.v ?: 0L,
                )
            }
            RuntimeTaintFlow(
                tagId = (f.fields["tagId"] as? JVal.JStr)?.v ?: "",
                sourceLabel = (f.fields["source"] as? JVal.JStr)?.v ?: "",
                sinkLabel = (f.fields["sink"] as? JVal.JStr)?.v ?: "",
                path = path,
            )
        }
        return RuntimeTaintReport(flows, tags, props, events)
    }

    private fun parseJson(s: String): JVal {
        var i = 0
        fun skipWs() { while (i < s.length && s[i].isWhitespace()) i++ }
        fun parseString(): String {
            skipWs()
            if (i >= s.length || s[i] != '"') return ""
            i++
            val sb = StringBuilder()
            while (i < s.length) {
                val c = s[i]
                if (c == '\\' && i + 1 < s.length) {
                    val n = s[i + 1]
                    when (n) {
                        'n' -> sb.append('\n'); 't' -> sb.append('\t'); 'r' -> sb.append('\r')
                        '"' -> sb.append('"'); '\\' -> sb.append('\\'); '/', 'u' -> sb.append(n)
                        else -> sb.append(n)
                    }
                    i += 2
                } else if (c == '"') { i++; break } else { sb.append(c); i++ }
            }
            return sb.toString()
        }
        fun parseValue(): JVal {
            skipWs()
            val c = s[i]
            return when {
                c == '{' -> {
                    i++
                    val fields = LinkedHashMap<String, JVal>()
                    while (true) {
                        skipWs()
                        if (i < s.length && s[i] == '}') { i++; break }
                        val key = parseString()
                        skipWs(); if (s[i] == ':') i++
                        fields[key] = parseValue()
                        skipWs()
                        if (i < s.length && s[i] == ',') i++ else if (i < s.length && s[i] == '}') { i++; break }
                    }
                    JVal.JObj(fields)
                }
                c == '[' -> {
                    i++
                    val items = mutableListOf<JVal>()
                    while (true) {
                        skipWs()
                        if (i < s.length && s[i] == ']') { i++; break }
                        items.add(parseValue())
                        skipWs()
                        if (i < s.length && s[i] == ',') i++ else if (i < s.length && s[i] == ']') { i++; break }
                    }
                    JVal.JArr(items)
                }
                c == '"' -> JVal.JStr(parseString())
                c == 't' -> { i += 4; JVal.JBool(true) }
                c == 'f' -> { i += 5; JVal.JBool(false) }
                c == 'n' -> { i += 4; JVal.JNull }
                else -> {
                    val sb = StringBuilder()
                    while (i < s.length && (s[i].isDigit() || s[i] == '-' || s[i] == '.' || s[i] == 'e' || s[i] == 'E' || s[i] == '+')) { sb.append(s[i]); i++ }
                    JVal.JNum(sb.toString().toLongOrNull() ?: 0L)
                }
            }
        }
        return parseValue()
    }
}