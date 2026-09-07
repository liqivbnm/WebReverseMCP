package com.webreverse.mcp.javascript.runtime

import com.webreverse.mcp.browser.engine.BrowserEngine
import com.webreverse.mcp.browser.engine.util.JsScripts

/**
 * 动态调试追踪器 v2（ 统一数据流观测层）。
 *
 * v1 只有「函数包装 + JSON 记录」；v2 面向 ChatGPT 报告提出的统一数据流引擎：
 *
 * 1. **值指纹（ValueFingerprint）**：每个捕获的参数/返回值/属性值在 JS 侧
 *    直接计算指纹（32 位 FNV-1a + 长度，与宿主 Kotlin 侧 `ValueFingerprint`
 *    完全一致），事件以 `fp0/fp1/.../fpRet` 字段携带。指纹让「hook 输出」与
 *    「请求头里的值」无需原始文本即可做等值判定。
 * 2. **异步谱系（Async Lineage）**：
 *    - 包装 `Promise.prototype.then/catch/finally`、`setTimeout/setInterval`，
 *      回调执行期间所有事件挂到同一 `chainId`；
 *    - 回调被调度时记录 `parentSeq`（调度者的最后事件号），回答
 *      「这个请求是谁触发的」「这个 then 链从哪个 fetch 开始」。
 * 3. **原始事件缓冲**：客户端环形缓冲 + `sinceSeq` 游标增量取回，宿主侧
 *    `TraceEventBuffer` 全量留存可回放；事件结构对齐宿主统一模型
 *    （seq/ts/source/kind/name/argN/ret/fpN/chainId/parentSeq/stack）。
 * 4. **值角色**：arg0..argN = INPUT、ret = OUTPUT、prop get/set = INTERMEDIATE，
 *    供污点引擎与关联器直接消费。
 *
 * 兼容性：v1 的 traceFunction/monitorObject/profileObject/collectTrace API 全保留。
 */
class DynamicTracer {

    companion object {
        private const val CAP = 2000
        private const val MAX_VAL = 256

        /** 注入的 JS 载体（幂等）：指纹 + 环形缓冲 + 异步链 + 值捕获 */
        private const val BOOTSTRAP = """
            (function(){
              if (globalThis.__WRMCP_TRACE__) return;
              var T = {
                cap: 2000,
                entries: [],
                n: 0,
                chainSeq: 0,
                chainStack: [],
                // 32 位 FNV-1a + 长度，与宿主 ValueFingerprint 一致
                fp: function(s){
                  try {
                    var v = String(s).trim();
                    if (v.length < 3 || v.length > 4096) return '';
                    var h = 0x811c9dc5;
                    for (var i = 0; i < v.length; i++) {
                      h ^= v.charCodeAt(i);
                      h = (h * 0x01000193) >>> 0;
                    }
                    return ('00000000' + h.toString(16)).slice(-8) + ':' + v.length;
                  } catch(e){ return ''; }
                },
                capv: function(v){
                  try {
                    var s = (typeof v === 'object' && v !== null) ? JSON.stringify(v) : String(v);
                    if (s === undefined) s = String(v);
                    if (s.length > 256) s = s.substring(0, 256) + '…';
                    return s;
                  } catch(e){ return String(v); }
                },
                redact: function(s){
                  try {
                    var v = String(s);
                    if (v.length > 400) v = v.substring(0, 400) + '…';
                    return v.replace(/("(?:authorization|cookie|token|secret|password|passwd|pwd)"\s*[:=]\s*)"[^"]*"/gi, '$1"[REDACTED]"');
                  } catch(e){ return String(s); }
                },
                push: function(e){
                  e.seq = ++T.n;
                  e.chainId = T.chainStack.length ? T.chainStack[T.chainStack.length - 1] : '';
                  if (T.entries.length >= T.cap) T.entries.shift();
                  T.entries.push(e);
                },
                stack: function(){
                  try {
                    return (new Error().stack || '').split('\n').slice(2, 8).map(function(l){ return l.trim(); }).join('\n');
                  } catch(e){ return ''; }
                },
                stackTop: function(){
                  try {
                    var l = (new Error().stack || '').split('\n');
                    return (l[2] || '').trim().substring(0, 160);
                  } catch(e){ return ''; }
                },
                // 异步作用域：回调执行期间事件挂同一链
                scope: function(chainId, fn){
                  return function(){
                    T.chainStack.push(chainId);
                    try { return fn.apply(this, arguments); }
                    finally { T.chainStack.pop(); }
                  };
                }
              };
              globalThis.__WRMCP_TRACE__ = T;
              globalThis.__WRMCP_FP__ = T.fp;
            })()
        """

        /**
         * 网络语义 Trace：fetch + XHR，只采集请求元数据，不读取 response body，避免改变业务行为。
         *
         * 实现说明：本项目原创编写。装配采用「方法描述符表 + 包装工厂 + WeakMap 元数据」
         * 的统一管线（open/setRequestHeader/send 共用同一条装配路径），XHR 各实例的
         * 请求元数据存放在 WeakMap 而非页面对象属性上；fetch 分支以 Request/选项
         * 两路归一化函数提取参数。不读取响应体、异常全部静默透传。
         */
        private const val NETWORK_PATCH = """
            (function(){
              if (globalThis.__WRMCP_NETWORK_TRACE__) return;
              globalThis.__WRMCP_NETWORK_TRACE__ = true;
              var T = globalThis.__WRMCP_TRACE__;
              if (!T) return;
              function cap(v){ try { return T.capv(v); } catch(e){ return ''; } }
              function fp(v){ try { var x = (v && typeof v === 'object') ? JSON.stringify(v) : v; return T.fp(x); } catch(e){ return ''; } }
              function emit(name, method, url, body, headers){
                try {
                  var e = { type:'network.request', source:'network', name:String(url || name), method:String(method || 'GET'), ts:Date.now() };
                  if (url) e.url = String(url);
                  if (body !== undefined && body !== null) { e.body = cap(body); var f = fp(body); if (f) e.fpBody = f; }
                  if (headers) {
                    e.headers = cap(headers); var fh = fp(headers); if (fh) e.fpHeaders = fh;
                    try {
                      if (headers instanceof Headers) headers.forEach(function(v,k){ var hv=fp(v); if(hv) e['fpHeader_' + String(k).replace(/[^a-zA-Z0-9_]/g,'_')] = hv; });
                      else if (typeof headers === 'object') Object.keys(headers).slice(0,64).forEach(function(k){ var hv=fp(headers[k]); if(hv) e['fpHeader_' + String(k).replace(/[^a-zA-Z0-9_]/g,'_')] = hv; });
                    } catch(eh){}
                  }
                  T.push(e);
                } catch(e){}
              }
              // fetch 分支：把 Request 对象与 (url, init) 两种调用形态归一化成同一份元数据
              function describeFetchCall(input, init){
                var d = { url: '', method: 'GET', body: undefined, headers: null };
                try {
                  var asRequest = (input && typeof input === 'object' && typeof input.url === 'string');
                  if (asRequest) {
                    d.url = input.url;
                    d.headers = (init && init.headers) ? init.headers : input.headers;
                    d.body = (init && init.body !== undefined) ? init.body : undefined;
                    d.method = (init && init.method) ? init.method : (input.method || 'GET');
                  } else {
                    d.url = String(input);
                    d.method = (init && init.method) ? init.method : 'GET';
                    d.body = (init && init.body !== undefined) ? init.body : undefined;
                    d.headers = (init && init.headers) ? init.headers : null;
                  }
                } catch(pe){}
                return d;
              }
              try {
                var netApi = globalThis.fetch;
                if (typeof netApi === 'function' && !netApi.__wrmcp_network__) {
                  var tracedFetch = function(){
                    try {
                      var d = describeFetchCall(arguments[0], arguments[1]);
                      emit('fetch', d.method, d.url, d.body, d.headers);
                    } catch(ex){}
                    return netApi.apply(this, arguments);
                  };
                  tracedFetch.__wrmcp_network__ = true;
                  globalThis.fetch = tracedFetch;
                }
              } catch(e){}
              try {
                var xhrProto = globalThis.XMLHttpRequest && globalThis.XMLHttpRequest.prototype;
                if (xhrProto) {
                  // 每个实例的请求元数据放在 WeakMap：不污染页面对象、实例回收自动释放
                  var metaPool = new WeakMap();
                  function metaFor(x){
                    if (!metaPool.has(x)) metaPool.set(x, { method: '', url: '', headers: {} });
                    return metaPool.get(x);
                  }
                  // 统一装配管线：name -> 包装工厂(nativeImpl, metaFor)
                  var pipeSpec = [
                    ['open', function(nativeImpl){
                      return function(method, url){
                        try { var mt = metaFor(this); mt.method = method; mt.url = url; } catch(ex){}
                        return nativeImpl.apply(this, arguments);
                      };
                    }],
                    ['setRequestHeader', function(nativeImpl){
                      return function(k, v){
                        try { metaFor(this).headers[String(k)] = String(v); } catch(ex){}
                        return nativeImpl.apply(this, arguments);
                      };
                    }],
                    ['send', function(nativeImpl){
                      return function(body){
                        try {
                          var mt = metaFor(this);
                          emit('xhr', mt.method || 'GET', mt.url || '', body, mt.headers || {});
                        } catch(ex){}
                        return nativeImpl.apply(this, arguments);
                      };
                    }],
                  ];
                  pipeSpec.forEach(function(spec){
                    try {
                      var propName = spec[0];
                      if (typeof xhrProto[propName] !== 'function') return;
                      var nativeImpl = xhrProto[propName];
                      if (nativeImpl.__wrmcp_network__) return;
                      var wrapped = spec[1](nativeImpl);
                      wrapped.__wrmcp_network__ = true;
                      xhrProto[propName] = wrapped;
                    } catch(ex){}
                  });
                }
              } catch(e){}
            })()
        """

        /** WASM 导出 + linear-memory 边界追踪：记录 export 参数、ptr/len、memory range 与返回值 fingerprint。 */
        private const val WASM_PATCH = """
            (function(){
              if (globalThis.__WRMCP_WASM_TRACE__) return;
              globalThis.__WRMCP_WASM_TRACE__ = true;
              var T = globalThis.__WRMCP_TRACE__;
              if (!T || !globalThis.WebAssembly) return;
              function cap(v){ try { return T.capv(v); } catch(e){ return ''; } }
              function fp(v){ try { return T.fp((v && typeof v === 'object') ? JSON.stringify(v) : v) || ''; } catch(e){ return ''; } }
              function bytesFp(memory, start, len){
                try {
                  if (!memory || !memory.buffer || !Number.isFinite(start) || !Number.isFinite(len) || start < 0 || len <= 0) return '';
                  var n = Math.min(len, 4096), u = new Uint8Array(memory.buffer, start, n), s = '';
                  for (var i=0;i<u.length;i++) s += String.fromCharCode(u[i]);
                  return T.fp(s);
                } catch(e){ return ''; }
              }
              function wrapInstance(inst){
                try {
                  if (!inst || !inst.exports) return inst;
                  if (inst.exports.__wrmcp_wasm_wrapped__) return inst;
                  var ex = inst.exports, wrapped = {};
                  Object.keys(ex).forEach(function(k){
                    var v = ex[k];
                    if (typeof v !== 'function') { wrapped[k] = v; return; }
                    if (v.__wrmcp_wasm_export__) { wrapped[k] = v; return; }
                    var wf = function(){
                      var args = Array.prototype.slice.call(arguments), e = { type:'wasm.export', source:'wasm', kind:'wasm_export', name:k, wasmExport:k, wasmFn:k, ts:Date.now(), parentSeq:T.n };
                      for (var i=0;i<Math.min(args.length,6);i++) { e['arg'+i]=cap(args[i]); var afp=fp(args[i]); if(afp)e['fp'+i]=afp; }
                      try {
                        var mem = ex.memory && ex.memory.buffer ? ex.memory : null;
                        for (var j=0;j<3;j++) {
                          var arg = args[j];
                          if (arg && typeof arg === 'object' && typeof arg.byteOffset === 'number' && typeof arg.byteLength === 'number') {
                            e['typedArrayByteOffset'+j]=arg.byteOffset; e['typedArrayByteLength'+j]=arg.byteLength;
                          }
                          var ptr = Number(args[j]), len = Number(args[j+1]);
                          if (Number.isFinite(ptr) && ptr >= 0 && Number.isFinite(len) && len > 0 && len <= 16*1024*1024 && mem) {
                            e['ptr'+j]=ptr; e['len'+j]=len; e.memoryStart=ptr; e.memoryEnd=ptr+len-1;
                            var before=bytesFp(mem,ptr,len); if(before)e.memoryFingerprintBefore=before;
                            break;
                          }
                        }
                      } catch(e0){}
                      var ret, err=null;
                      try { ret = v.apply(this,args); }
                      catch(x){ err=String(x && x.message || x); throw x; }
                      finally {
                        try {
                          e.ret=cap(ret); var rfp=fp(ret); if(rfp)e.fpRet=rfp;
                          var mem2 = ex.memory && ex.memory.buffer ? ex.memory : null;
                          if (e.memoryStart !== undefined && e.memoryEnd !== undefined && mem2) {
                            var after=bytesFp(mem2, e.memoryStart, e.memoryEnd-e.memoryStart+1); if(after)e.memoryFingerprintAfter=after;
                          }
                        } catch(e1){}
                        e.error=err; T.push(e);
                      }
                      return ret;
                    };
                    try { Object.defineProperty(wf,'name',{value:k}); } catch(e){}
                    wf.__wrmcp_wasm_export__=true; wrapped[k]=wf;
                  });
                  try { wrapped.__wrmcp_wasm_wrapped__ = true; } catch(e){}
                  return { instance: inst, exports: wrapped };
                } catch(e){ return inst; }
              }
              try {
                var oi = WebAssembly.instantiate;
                if (typeof oi === 'function') {
                  WebAssembly.instantiate = function(bytes, imports){
                    var r = oi.apply(this, arguments);
                    return (r && typeof r.then === 'function') ? r.then(function(x){ return wrapInstance(x); }) : wrapInstance(r);
                  };
                }
              } catch(e){}
              try {
                var os = WebAssembly.instantiateStreaming;
                if (typeof os === 'function') {
                  WebAssembly.instantiateStreaming = function(source, imports){
                    var r = os.apply(this, arguments);
                    return r && typeof r.then === 'function' ? r.then(function(x){ return wrapInstance(x); }) : r;
                  };
                }
              } catch(e){}
            })()
        """

        /** Worker/iframe 跨上下文边界追踪：postMessage / MessagePort / ServiceWorker / BroadcastChannel。 */
        private const val CONTEXT_PATCH = """
            (function(){
              if (globalThis.__WRMCP_CONTEXT_TRACE__) return;
              globalThis.__WRMCP_CONTEXT_TRACE__ = true;
              var T = globalThis.__WRMCP_TRACE__;
              if (!T) return;
              function fp(v){ try { return T.fp((v && typeof v === 'object') ? JSON.stringify(v) : v) || ''; } catch(e){ return ''; } }
              function cap(v){ try { return T.capv(v); } catch(e){ return ''; } }
              function emit(type, name, value, direction, target){
                try {
                  var f = fp(value), e = { type:type, source:'tracer', name:name || type, direction:direction || '', targetContext:String(target || ''), ts:Date.now(), parentSeq:T.n };
                  if (value !== undefined) { e.value = cap(value); if (f) e.fp = f; }
                  T.push(e);
                } catch(e){}
              }
              try {
                if (globalThis.postMessage) {
                  var opm = globalThis.postMessage;
                  globalThis.postMessage = function(message, targetOrigin, transfer){
                    emit('context.postMessage','window.postMessage',message,'send',targetOrigin || '*');
                    return opm.apply(this, arguments);
                  };
                }
              } catch(e){}
              try {
                if (globalThis.MessagePort && MessagePort.prototype.postMessage) {
                  var ppm = MessagePort.prototype.postMessage;
                  MessagePort.prototype.postMessage = function(message, transfer){
                    emit('context.messagePort','MessagePort.postMessage',message,'send','MessagePort');
                    return ppm.apply(this, arguments);
                  };
                  var ostart = MessagePort.prototype.start;
                  if (ostart) MessagePort.prototype.start = function(){ return ostart.apply(this, arguments); };
                  var oadd = MessagePort.prototype.addEventListener;
                  if (oadd) MessagePort.prototype.addEventListener = function(type, fn, opts){
                    if (type === 'message' && typeof fn === 'function') {
                      var chain = 'ctx' + (++T.chainSeq), origFn = fn;
                      fn = T.scope(chain, function(ev){ emit('context.messagePort','MessagePort.message',ev && ev.data,'recv','MessagePort'); return origFn.apply(this, arguments); });
                      try { fn.__wrmcp_chain__ = true; } catch(e){}
                    }
                    return oadd.call(this, type, fn, opts);
                  };
                }
              } catch(e){}
              try {
                if (globalThis.BroadcastChannel) {
                  var bpc = BroadcastChannel.prototype.postMessage;
                  BroadcastChannel.prototype.postMessage = function(message){ emit('context.broadcast','BroadcastChannel.postMessage',message,'send',this.name || 'BroadcastChannel'); return bpc.apply(this, arguments); };
                  var bae = BroadcastChannel.prototype.addEventListener;
                  if (bae) BroadcastChannel.prototype.addEventListener = function(type, fn, opts){
                    if (type === 'message' && typeof fn === 'function') { var origFn = fn; fn = T.scope('bc'+(++T.chainSeq), function(ev){ emit('context.broadcast','BroadcastChannel.message',ev && ev.data,'recv',this && this.name || 'BroadcastChannel'); return origFn.apply(this, arguments); }); }
                    return bae.call(this, type, fn, opts);
                  };
                }
              } catch(e){}
              try {
                if (globalThis.ServiceWorkerContainer && ServiceWorkerContainer.prototype.postMessage) {
                  var spm = ServiceWorkerContainer.prototype.postMessage;
                  ServiceWorkerContainer.prototype.postMessage = function(message, transfer){ emit('context.serviceWorker','ServiceWorkerContainer.postMessage',message,'send','service-worker'); return spm.apply(this, arguments); };
                }
              } catch(e){}
              try {
                if (globalThis.Worker && Worker.prototype.postMessage) {
                  var wpm = Worker.prototype.postMessage;
                  Worker.prototype.postMessage = function(message, transfer){ emit('context.worker','Worker.postMessage',message,'send','dedicated-worker'); return wpm.apply(this, arguments); };
                }
              } catch(e){}
              try {
                if (globalThis.SharedWorker && SharedWorker.prototype.port && MessagePort.prototype.postMessage) { /* MessagePort hook above covers it */ }
              } catch(e){}
            })()
        """

        /** 异步链包装：Promise.then/catch/finally + setTimeout/setInterval（幂等） */
        private const val ASYNC_PATCH = """
            (function(){
              if (globalThis.__WRMCP_ASYNC__) return;
              globalThis.__WRMCP_ASYNC__ = true;
              var T = globalThis.__WRMCP_TRACE__;
              if (!T) return;
              function mkChain(){ return 'c' + (++T.chainSeq); }
              // Promise.prototype.then/catch/finally
              try {
                var origThen = Promise.prototype.then;
                Promise.prototype.then = function(onF, onR){
                  var chain = mkChain();
                  var seqAtSchedule = T.n;
                  var wrappedF = onF ? T.scope(chain, function(){
                    T.push({ type: 'async.resume', source: 'tracer', name: 'Promise.then',
                             parentSeq: seqAtSchedule, trigger: 'promise', ts: Date.now() });
                    try { return onF.apply(this, arguments); }
                    finally { T.push({ type: 'async.end', source: 'tracer', name: 'Promise.then', ts: Date.now() }); }
                  }) : onF;
                  var wrappedR = onR ? T.scope(chain, function(){
                    T.push({ type: 'async.resume', source: 'tracer', name: 'Promise.catch',
                             parentSeq: seqAtSchedule, trigger: 'promise', ts: Date.now() });
                    try { return onR.apply(this, arguments); }
                    finally { T.push({ type: 'async.end', source: 'tracer', name: 'Promise.catch', ts: Date.now() }); }
                  }) : onR;
                  return origThen.call(this, wrappedF, wrappedR);
                };
              } catch(e){}
              // setTimeout / setInterval
              try {
                var origSt = globalThis.setTimeout, origSi = globalThis.setInterval;
                if (origSt) globalThis.setTimeout = function(fn, ms){
                  if (typeof fn === 'function') {
                    var chain = mkChain();
                    var seqAtSchedule = T.n;
                    arguments[0] = T.scope(chain, function(){
                      T.push({ type: 'timer.fire', source: 'timer', name: 'setTimeout',
                               parentSeq: seqAtSchedule, trigger: 'timer',
                               ms: +ms || 0, ts: Date.now() });
                      try { return fn.apply(this, arguments); }
                      finally { T.push({ type: 'async.end', source: 'timer', name: 'setTimeout', ts: Date.now() }); }
                    });
                  }
                  return origSt.apply(this, arguments);
                };
                if (origSi) globalThis.setInterval = function(fn, ms){
                  if (typeof fn === 'function') {
                    var chain = mkChain();
                    var seqAtSchedule = T.n;
                    arguments[0] = T.scope(chain, function(){
                      T.push({ type: 'timer.fire', source: 'timer', name: 'setInterval',
                               parentSeq: seqAtSchedule, trigger: 'timer',
                               ms: +ms || 0, ts: Date.now() });
                      try { return fn.apply(this, arguments); }
                      finally { T.push({ type: 'async.end', source: 'timer', name: 'setInterval', ts: Date.now() }); }
                    });
                  }
                  return origSi.apply(this, arguments);
                };
              } catch(e){}
              // addEventListener（DOM 事件链）
              try {
                if (globalThis.EventTarget && EventTarget.prototype.addEventListener) {
                  var origAel = EventTarget.prototype.addEventListener;
                  EventTarget.prototype.addEventListener = function(type, fn, opts){
                    if (typeof fn === 'function' && !fn.__wrmcp_chain__) {
                      var chain = mkChain();
                      var seqAtSchedule = T.n;
                      var wrapped = T.scope(chain, function(){
                        T.push({ type: 'event.fire', source: 'tracer',
                                 name: (this && this.tagName ? this.tagName + '.' : '') + String(type),
                                 parentSeq: seqAtSchedule, trigger: 'event', ts: Date.now() });
                        try { return fn.apply(this, arguments); }
                        finally { T.push({ type: 'async.end', source: 'tracer', name: String(type), ts: Date.now() }); }
                      });
                      wrapped.__wrmcp_chain__ = true;
                      return origAel.call(this, type, wrapped, opts);
                    }
                    return origAel.call(this, type, fn, opts);
                  };
                }
              } catch(e){}
            })()
        """
    }

    /** 初始化 trace 载体（幂等）；[withAsync] 同时安装异步谱系包装 */
    suspend fun install(
        engine: BrowserEngine,
        withAsync: Boolean = true,
        withNetwork: Boolean = true,
    ) {
        engine.evaluateJavascript(BOOTSTRAP)
        if (withAsync) engine.evaluateJavascript(ASYNC_PATCH)
        engine.evaluateJavascript(CONTEXT_PATCH)
        engine.evaluateJavascript(WASM_PATCH)
        if (withNetwork) engine.evaluateJavascript(NETWORK_PATCH)
    }

    // ---------------- 1. 函数级 Trace（v2：值指纹 + 角色 + 异步链） ----------------

    /**
     * 追踪目标函数（支持点路径，如 "window.sign" / "JSON.stringify"）。
     * v2 事件结构：{type:'call', target, arg0..argN, ret, fp0..fpN, fpRet,
     *              error, ms, ts, chainId, parentSeq, stack?}
     */
    suspend fun traceFunction(
        engine: BrowserEngine,
        target: String,
        captureArgs: Boolean = true,
        captureReturn: Boolean = true,
        captureStack: Boolean = false,
    ): Boolean {
        install(engine)
        val script = """
            (function(){
              try {
                var T = globalThis.__WRMCP_TRACE__;
                var path = ${JsScripts.quote(target)}.split('.');
                var obj = globalThis;
                for (var i = 0; i < path.length - 1; i++) {
                  if (obj[path[i]] === undefined || obj[path[i]] === null) return false;
                  obj = obj[path[i]];
                }
                var name = path[path.length - 1];
                var orig = obj[name];
                if (typeof orig !== 'function') return false;
                if (orig.__wrmcp_traced__) return true;
                var wrapped = function(){
                  var t0 = performance.now();
                  var parentSeq = T.n;
                  var e = { type: 'call', source: 'tracer', target: ${JsScripts.quote(target)}, ts: Date.now(), parentSeq: parentSeq };
                  if (${if (captureArgs) "true" else "false"}) {
                    for (var i = 0; i < arguments.length && i < 8; i++) {
                      var a = arguments[i];
                      var s = T.capv(a);
                      e['arg' + i] = s;
                      var fp = T.fp(typeof a === 'object' && a !== null ? JSON.stringify(a) : a);
                      if (fp) e['fp' + i] = fp;
                    }
                  }
                  var ret, err = null;
                  try { ret = orig.apply(this, arguments); }
                  catch(e2){ err = String(e2 && e2.message || e2); throw e2; }
                  finally {
                    ${if (captureReturn) """
                    try {
                      var rs = (typeof ret === 'object' && ret !== null) ? T.capv(ret) : T.capv(ret);
                      e.ret = rs;
                      var rfp = T.fp(typeof ret === 'object' && ret !== null ? JSON.stringify(ret) : ret);
                      if (rfp) e.fpRet = rfp;
                    } catch(e3){}
                    """ else ""}
                    e.error = err;
                    e.ms = +(performance.now() - t0).toFixed(3);
                    if (${if (captureStack) "true" else "false"}) { e.stack = T.stack(); e.stackTop = T.stackTop(); }
                    T.push(e);
                  }
                  return ret;
                };
                wrapped.__wrmcp_traced__ = true;
                wrapped.__wrmcp_orig__ = orig;
                try { Object.defineProperty(wrapped, 'length', { value: orig.length }); } catch(e){}
                obj[name] = wrapped;
                return true;
              } catch(e){ return false; }
            })()
        """.trimIndent()
        return engine.evaluateJavascript(script) == "true"
    }

    /** 取消追踪（恢复原函数） */
    suspend fun untraceFunction(engine: BrowserEngine, target: String): Boolean {
        val script = """
            (function(){
              try {
                var path = ${JsScripts.quote(target)}.split('.');
                var obj = globalThis;
                for (var i = 0; i < path.length - 1; i++) {
                  if (obj[path[i]] === undefined) return false;
                  obj = obj[path[i]];
                }
                var name = path[path.length - 1];
                var cur = obj[name];
                if (cur && cur.__wrmcp_traced__) { obj[name] = cur.__wrmcp_orig__; return true; }
                return false;
              } catch(e){ return false; }
            })()
        """.trimIndent()
        return engine.evaluateJavascript(script) == "true"
    }

    // ---------------- 2. 对象属性监控（v2：值指纹） ----------------

    /** 用 Proxy 监控对象属性读写，值携带指纹（fp 字段）。 */
    suspend fun monitorObject(engine: BrowserEngine, target: String): Boolean {
        install(engine)
        val script = """
            (function(){
              try {
                var T = globalThis.__WRMCP_TRACE__;
                var path = ${JsScripts.quote(target)}.split('.');
                var holder = globalThis;
                for (var i = 0; i < path.length - 1; i++) {
                  if (holder[path[i]] === undefined || holder[path[i]] === null) return false;
                  holder = holder[path[i]];
                }
                var name = path[path.length - 1];
                var orig = holder[name];
                if (orig === null || typeof orig !== 'object') return false;
                if (orig.__wrmcp_monitored__) return true;
                var proxy = new Proxy(orig, {
                  get: function(o, prop){
                    var v = o[prop];
                    if (typeof prop === 'string' && prop !== '__wrmcp_monitored__' && prop !== 'then') {
                      var s = (typeof v === 'object' && v !== null) ? '[object]' : T.capv(v);
                      var fp = T.fp(v);
                      T.push({ type: 'prop.get', source: 'tracer', target: ${JsScripts.quote(target)}, prop: String(prop),
                               value: s, fp: fp, stackTop: T.stackTop(), ts: Date.now() });
                    }
                    return v;
                  },
                  set: function(o, prop, val){
                    if (typeof prop === 'string') {
                      var s = (typeof val === 'object' && val !== null) ? '[object]' : T.capv(val);
                      var fp = T.fp(val);
                      T.push({ type: 'prop.set', source: 'tracer', target: ${JsScripts.quote(target)}, prop: String(prop),
                               value: s, fp: fp, stackTop: T.stackTop(), ts: Date.now() });
                    }
                    o[prop] = val;
                    return true;
                  }
                });
                try { Object.defineProperty(proxy, '__wrmcp_monitored__', { value: true }); } catch(e){}
                holder[name] = proxy;
                return true;
              } catch(e){ return false; }
            })()
        """.trimIndent()
        return engine.evaluateJavascript(script) == "true"
    }

    /** 取消对象监控（Proxy 会被整体替换回原对象，尽力恢复） */
    suspend fun unmonitorObject(engine: BrowserEngine, target: String): Boolean {
        return untraceFunction(engine, target)
    }

    // ---------------- 3. 方法耗时剖析 ----------------

    /** 批量剖析对象的所有方法（统计调用数/总耗时/平均耗时）。 */
    suspend fun profileObject(engine: BrowserEngine, target: String, maxMethods: Int = 30): Int {
        install(engine)
        val script = """
            (function(){
              try {
                var T = globalThis.__WRMCP_TRACE__;
                var path = ${JsScripts.quote(target)}.split('.');
                var obj = globalThis;
                for (var i = 0; i < path.length - 1; i++) {
                  if (obj[path[i]] === undefined || obj[path[i]] === null) return 0;
                  obj = obj[path[i]];
                }
                var name = path[path.length - 1];
                var target2 = obj[name];
                if (!target2 || typeof target2 !== 'object') return 0;
                var count = 0;
                Object.getOwnPropertyNames(target2).slice(0, $maxMethods).forEach(function(k){
                  var fn = target2[k];
                  if (typeof fn !== 'function' || fn.__wrmcp_profiled__) return;
                  var stats = { calls: 0, totalMs: 0 };
                  var wrapped = function(){
                    var t0 = performance.now();
                    try { return fn.apply(this, arguments); }
                    finally {
                      stats.calls++;
                      stats.totalMs += performance.now() - t0;
                    }
                  };
                  wrapped.__wrmcp_profiled__ = true;
                  wrapped.__wrmcp_stats__ = stats;
                  wrapped.__wrmcp_orig__ = fn;
                  try { target2[k] = wrapped; count++; } catch(e){}
                });
                return count;
              } catch(e){ return 0; }
            })()
        """.trimIndent()
        return engine.evaluateJavascript(script)?.toDoubleOrNull()?.toInt() ?: 0
    }

    /** 取回剖析统计 */
    suspend fun collectProfile(engine: BrowserEngine): String? =
        engine.evaluateJavascript(
            """
            (function(){
              var out = [];
              function walk(obj, prefix, depth) {
                if (!obj || typeof obj !== 'object' || depth > 2 || out.length > 200) return;
                Object.getOwnPropertyNames(obj).forEach(function(k){
                  var fn = obj[k];
                  if (typeof fn === 'function' && fn.__wrmcp_stats__) {
                    out.push({ method: prefix + k, calls: fn.__wrmcp_stats__.calls,
                               totalMs: +fn.__wrmcp_stats__.totalMs.toFixed(2),
                               avgMs: +(fn.__wrmcp_stats__.totalMs / Math.max(1, fn.__wrmcp_stats__.calls)).toFixed(3) });
                  }
                });
              }
              walk(globalThis, '', 0);
              ['crypto','JSON','Math','Object','Array'].forEach(function(ns){
                try { walk(globalThis[ns], ns + '.', 1); } catch(e){}
              });
              return JSON.stringify(out.sort(function(a,b){ return b.totalMs - a.totalMs; }));
            })()
            """.trimIndent(),
        )

    // ---------------- 4. trace 收集 ----------------

    /** v1 兼容取回（过滤 target 包含关键字） */
    suspend fun collectTrace(engine: BrowserEngine, filter: String = "", limit: Int = 200): String? {
        val script = """
            (function(){
              var T = globalThis.__WRMCP_TRACE__;
              if (!T) return '[]';
              var arr = T.entries;
              ${if (filter.isNotBlank()) "arr = arr.filter(function(e){ return String(e.target||'').indexOf(${JsScripts.quote(filter)}) >= 0; });" else ""}
              return JSON.stringify({ total: T.n, buffered: T.entries.length, entries: arr.slice(-$limit) });
            })()
        """.trimIndent()
        return engine.evaluateJavascript(script)
    }

    /**
     * v2 增量取回：seq 严格大于 [sinceSeq] 的原始事件（游标续传）。
     * 返回 {total, buffered, lastSeq, entries}，宿主侧 TraceEventBuffer 消费。
     */
    suspend fun collectTraceEvents(engine: BrowserEngine, sinceSeq: Long = -1, limit: Int = 500): String? {
        val script = """
            (function(){
              var T = globalThis.__WRMCP_TRACE__;
              if (!T) return JSON.stringify({ total: 0, buffered: 0, lastSeq: -1, entries: [] });
              var out = [];
              for (var i = T.entries.length - 1; i >= 0 && out.length < $limit; i--) {
                if (T.entries[i].seq > $sinceSeq) out.unshift(T.entries[i]);
                else break;
              }
              return JSON.stringify({ total: T.n, buffered: T.entries.length, lastSeq: T.n, entries: out });
            })()
        """.trimIndent()
        return engine.evaluateJavascript(script)
    }

    /** 按指纹查询：哪些事件流过该值（客户端侧反查，宿主缓冲缺数据时兜底） */
    suspend fun findByFingerprint(engine: BrowserEngine, fp: String): String? {
        val script = """
            (function(){
              var T = globalThis.__WRMCP_TRACE__;
              if (!T) return '[]';
              var out = T.entries.filter(function(e){
                for (var k in e) {
                  if (k.indexOf('fp') === 0 && e[k] === ${JsScripts.quote(fp)}) return true;
                }
                return false;
              });
              return JSON.stringify(out);
            })()
        """.trimIndent()
        return engine.evaluateJavascript(script)
    }

    /** 当前异步链统计（活跃链/累计链数） */
    suspend fun chainStats(engine: BrowserEngine): String? {
        val script = """
            (function(){
              var T = globalThis.__WRMCP_TRACE__;
              if (!T) return '{}';
              var chains = {};
              T.entries.forEach(function(e){
                if (e.chainId) chains[e.chainId] = (chains[e.chainId] || 0) + 1;
              });
              var top = Object.keys(chains).map(function(k){ return { chainId: k, events: chains[k] }; })
                .sort(function(a,b){ return b.events - a.events; }).slice(0, 20);
              return JSON.stringify({ totalChains: Object.keys(chains).length, chainSeq: T.chainSeq, top: top });
            })()
        """.trimIndent()
        return engine.evaluateJavascript(script)
    }

    /** 清空 trace */
    suspend fun clearTrace(engine: BrowserEngine) {
        engine.evaluateJavascript(
            "(function(){ var T = globalThis.__WRMCP_TRACE__; if (T) { T.entries = []; T.n = 0; } })()",
        )
    }
}
