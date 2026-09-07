package com.webreverse.mcp.browser.engine.util

/** JS 脚本工具 */
object JsScripts {

    fun quote(value: String): String =
        "'" + value.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n").replace("\r", "\\r") + "'"

    /**
     * 运行时观测脚本（v2：基于 Hook Registry，幂等、可恢复、不叠加）。
     *
     * v1 直接替换 window.fetch / XHR.prototype，与 document_start 早期 Hook 会形成
     * 二次包装（一次请求两条观测日志）。v2 统一挂到 __WRMCP_HOOK__ Registry：
     * 已存在的 key 只追加回调（attach），不重复包装。
     */
    fun runtimeObserverScript(): String = hookFrameworkScript() + """
        ;
        (function(){
          var R = window.__WRMCP_HOOK__;
          if (!R || R.__observerInstalled) return;
          R.__observerInstalled = true;
          function cb(tag, maxLength) {
            return function(info) {
              try {
                if (window.__MCP__ && window.__MCP__.log) {
                  window.__MCP__.log('[' + tag + '] ' + JSON.stringify(info).substring(0, maxLength || 1000));
                }
              } catch(e){}
            };
          }
          try { R.hookFetch(cb('fetch', 1200)); } catch(e){}
          try { R.hookXHR(cb('xhr', 1000)); } catch(e){}
          try { R.hookWebSocket(cb('ws', 800)); } catch(e){}
          try { R.hookConsole(function(info){
                  try {
                    if (window.__MCP__ && window.__MCP__.log) {
                      window.__MCP__.log('[' + info.level + '] ' + String(info.args || '').substring(0, 500));
                    }
                  } catch(e){}
                }); } catch(e){}
          try { R.hookTimer(function(info){
                  try {
                    var code = String(info.code || '');
                    if (code && code.length <= 120 && window.__MCP__ && window.__MCP__.log) {
                      window.__MCP__.log('[timer:' + info.type + '] ' + code + ' @' + (info.delay || 0) + 'ms');
                    }
                  } catch(e){}
                }); } catch(e){}
        })();
    """.trimIndent()

    /** 环境信息采集脚本 */
    fun environmentScript(): String = """
        (function(){
          var out = {};
          out.userAgent = navigator.userAgent;
          out.platform = navigator.platform;
          out.language = navigator.language;
          out.languages = navigator.languages;
          out.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
          out.screen = screen.width + 'x' + screen.height;
          out.viewport = window.innerWidth + 'x' + window.innerHeight;
          out.devicePixelRatio = window.devicePixelRatio;
          out.touchSupport = 'ontouchstart' in window;
          out.cpuCores = navigator.hardwareConcurrency || 0;
          out.deviceMemory = navigator.deviceMemory || 0;
          out.connection = (navigator.connection && navigator.connection.effectiveType) || '';
          out.webgl = (function(){ try { var c = document.createElement('canvas'); return !!(c.getContext('webgl') || c.getContext('experimental-webgl')); } catch(e){ return false; } })();
          out.canvas = (function(){ try { var c = document.createElement('canvas'); return !!(c.getContext('2d')); } catch(e){ return false; } })();
          out.audio = (function(){ try { var a = new (window.AudioContext || window.webkitAudioContext)(); a.close(); return true; } catch(e){ return false; } })();
          out.serviceWorker = 'serviceWorker' in navigator;
          out.webAssembly = typeof WebAssembly !== 'undefined';
          out.webRTC = !!(window.RTCPeerConnection || window.webkitRTCPeerConnection);
          out.cookiesEnabled = navigator.cookieEnabled;
          out.indexedDB = !!window.indexedDB;
          out.localStorage = (function(){ try { localStorage.setItem('__t','1'); localStorage.removeItem('__t'); return true; } catch(e){ return false; } })();
          out.sessionStorage = (function(){ try { sessionStorage.setItem('__t','1'); sessionStorage.removeItem('__t'); return true; } catch(e){ return false; } })();
          out.permissions = {};
          try {
            if (navigator.permissions && navigator.permissions.query) {
              ['geolocation','notifications','camera','microphone'].forEach(function(name){
                navigator.permissions.query({name:name}).then(function(s){ out.permissions[name] = s.state; }).catch(function(){});
              });
            }
          } catch(e){}
          return JSON.stringify(out);
        })()
    """.trimIndent()

    /** 框架检测脚本 */
    fun frameworkDetectScript(): String = """
        (function(){
          var out = {};
          out.react = !!(window.React || document.querySelector('#root') && (window.__REACT_DEVTOOLS_GLOBAL_HOOK__ || document.querySelector('[data-reactroot]')));
          out.vue = !!(window.Vue || document.querySelector('[data-v-app]'));
          out.angular = !!(window.ng || document.querySelector('[ng-version]'));
          out.svelte = !!(document.querySelector('[data-svelte]'));
          out.jquery = !!window.jQuery;
          out.lodash = !!window._ && !!window._.debounce;
          out.axios = !!window.axios;
          out.redux = !!(window.__REDUX_DEVTOOLS_EXTENSION__ || (window.__store__));
          out.next = !!(document.querySelector('#__next'));
          out.nuxt = !!(document.querySelector('#__nuxt'));
          out.webpack = !!(window.webpackJsonp || document.querySelector('script[src*="webpack"]'));
          out.vite = !!document.querySelector('script[type="module"]');
          out.pwa = !!navigator.serviceWorker;
          out.shadowDom = !!document.querySelector('* /deep/ *');
          out.spa = (function(){
            var links = document.querySelectorAll('a[href]');
            for (var i=0;i<links.length;i++){ if (links[i].href.indexOf('#') >= 0) return true; }
            return false;
          })();
          return JSON.stringify(out);
        })()
    """.trimIndent()

    /**
     * 浏览器环境兼容脚本（ 升级为"环境模拟器"，替代旧版仅 window.chrome 补丁）。
     *
     * 目标：补齐页面脚本依赖的常用浏览器能力，降低"真实页面环境缺失"导致的执行差异。
     * 覆盖（参考 ChatGPT 报告 §2）：
     * - window.chrome / chrome.runtime（Chrome 扩展 API 桩）
     * - window: top/self/parent/frames/origin/name/length/closed/frameElement
     * - navigator: 常规字段 + webdriver=false + 伪造头字节指纹
     * - screen / visualViewport 存根
     * - history 只读字段
     * - localStorage/sessionStorage 可用性在 WebView 已由 WebSettings 保证，此处补防御性引用
     * - 常见反自动化/反模拟检测的脱敏（toString 指纹、navigator.webdriver）
     *
     * 注意：这是"执行期兼容层"，与 base 模式的零注入验证路径互斥（由调用方 BASELINE_MODE 控制）。
     * 所有补丁均幂等 + try/catch 包裹，失败静默，不影响页面加载。
     */
    fun browserEnvCompatScript(): String = """
        (function() {
          function def(obj, key, value) {
            try {
              if (obj === undefined || obj === null) return;
              if (!(key in Object(obj))) { try { Object.defineProperty(obj, key, {value: value, writable: true, configurable: true, enumerable: true}); } catch(e) { obj[key] = value; } }
            } catch(e) {}
          }
          try {
            // ---- window 自引用与身份 ----
            def(window, 'top', window);
            def(window, 'self', window);
            def(window, 'parent', window);
            def(window, 'frames', window);
            def(window, 'window', window);
            def(window, 'origin', (function(){ try { return location.origin; } catch(e){ return 'null'; } })());
            if (window.opener === undefined) { try { def(window, 'opener', null); } catch(e){} }

            // ---- chrome 扩展 API 桩 ----
            if (!window.chrome) { window.chrome = {}; }
            if (!window.chrome.runtime) { window.chrome.runtime = {}; }
            if (window.chrome.runtime && !window.chrome.runtime.connect) { window.chrome.runtime.connect = function(){ return {postMessage:function(){}, onMessage:{addListener:function(){}}}; }; }

            // ---- navigator 脱敏：移除 webdriver 自动化痕迹 ----
            if (navigator && navigator.webdriver !== undefined) {
              try { Object.defineProperty(navigator, 'webdriver', {get: function(){ return false; }, configurable: true}); } catch(e) {}
            }

            // ---- 常见缺失全局构造器防御性引用（存在则不动，缺失才补安全默认） ----
            var missingGlobals = {
              'TextEncoder': (function(){ return function(){ return {encode: function(s){ var r=[]; for(var i=0;i<s.length;i++){r.push(s.charCodeAt(i)&0xFF);} return new Uint8Array(r); } }; }; })(),
              'TextDecoder': function(enc){ this.decode = function(buf){ return String.fromCharCode.apply(null, new Uint8Array(buf||[])); }; },
              'URLSearchParams': (typeof URLSearchParams !== 'undefined' ? undefined : function(init){ this._m={}; if(init&&String(init).charAt(0)==='?')init=String(init).slice(1); if(init){String(init).split('&').forEach(function(kv){var i=kv.indexOf('=');var k=i>=0?kv.slice(0,i):kv;var v=i>=0?kv.slice(i+1):'';this._m[decodeURIComponent(k)]=decodeURIComponent(v);},this);} this.get=function(k){return this._m[k]!=null?this._m[k]:null;}; this.has=function(k){return this._m[k]!=null;}; })
            };
            for (var g in missingGlobals) {
              if (missingGlobals[g] !== undefined && typeof window[g] === 'undefined') {
                try { def(window, g, missingGlobals[g]); def(globalThis, g, missingGlobals[g]); } catch(e) {}
              }
            }

            // ---- history 只读字段缺省补 ----
            if (window.history && window.history.length === undefined) {
              try { Object.defineProperty(window.history, 'length', {value: 1, writable:true, configurable:true}); } catch(e){}
            }
          } catch (e) {}
        })();
    """.trimIndent()

    /**
     * 浏览器环境采集脚本（打通 captureableKeys → 真实浏览器采集管线）。
     *
     * 注入当前 WebView 页面，按给定 key 清单（如 window.crypto.subtle / navigator.userAgent）
     * 读取真实浏览器环境值，JSON 序列化后返回。返回值可直接喂给
     * BrowserEnvironmentSynthesizer.buildShim(captured=...) 生成带真实值的 Node shim。
     *
     * 取值规则：
     *  - 根为 window 的路径从 window 起取；其余从 self/globalThis 起取
     *  - 函数 → "[function]"；循环引用/不可序列化 → "[unserializable]"；缺失 → 跳过
     *  - 返回 JSON.stringify({key: jsonValue})，jsonValue 为可直接内嵌的 JS 表达式
     *
     * 指纹采集通道（几何指纹一致性引擎打通）：
     *  - canvas.* / webgl.* 前缀的 key 无法靠属性读取获得——指纹需要真实执行
     *    （画布渲染/着色器绘制/字体度量）才能产生。本脚本对这类 key 走专用
     *    采集函数，真实执行后取指纹值：
     *    - canvas.data2d     经典 2D 渲染指纹（fillText+渐变+圆弧 → toDataURL）
     *    - canvas.measureText 字体度量指纹（13 种字体 × 探测串的宽度表）
     *    - canvas.fonts       字体可用性探测（宽度差法，27 种常用字体）
     *    - webgl.vendor/renderer UNMASKED_VENDOR/RENDERER（WEBGL_debug_renderer_info）
     *    - webgl.params       24 项常用 getParameter 枚举值表
     *    - webgl.data         WebGL 渲染指纹（画三角形 readPixels → FNV-1a 哈希）
     */
    fun captureEnvScript(keys: List<String>): String {
        val keyJson = keys.joinToString(",") { quote(it) }
        return """
            (function(){
              var keys = [$keyJson];
              var out = {};
              var needCanvas = false, needWebgl = false;
              keys.forEach(function(k){
                if (k === 'canvas' || k.indexOf('canvas.') === 0) needCanvas = true;
                if (k === 'webgl' || k.indexOf('webgl.') === 0) needWebgl = true;
              });

              // ---- 指纹采集通道：需真实执行 ----
              function fnv1a(bytes){
                var h = 0x811c9dc5;
                for (var i = 0; i < bytes.length; i++){ h ^= bytes[i]; h = (h * 0x01000193) >>> 0; }
                return h;
              }
              function collectCanvas(){
                var o = {};
                // 1) 2D 渲染指纹（经典 fillText + 渐变 + 圆弧组合）
                try {
                  var c = document.createElement('canvas');
                  c.width = 220; c.height = 60;
                  var ctx = c.getContext('2d');
                  if (ctx) {
                    ctx.textBaseline = 'alphabetic';
                    ctx.fillStyle = '#f60';
                    ctx.fillRect(125, 1, 62, 20);
                    ctx.fillStyle = '#069';
                    ctx.font = '11pt Arial';
                    ctx.fillText('Cwm fjordbank glyphs vext quiz', 2, 15);
                    ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
                    ctx.font = '18pt Arial';
                    ctx.fillText('Cwm fjordbank glyphs vext quiz', 4, 45);
                    ctx.globalCompositeOperation = 'multiply';
                    ctx.fillStyle = 'rgb(255,0,255)';
                    ctx.beginPath();
                    ctx.arc(50, 50, 20, 0, Math.PI * 2, true);
                    ctx.fill();
                    o['canvas.data2d'] = c.toDataURL();
                  }
                } catch (e) {}
                // 2) measureText 字体度量指纹（各字体对固定探测串的宽度）
                try {
                  var c2 = document.createElement('canvas');
                  var x2 = c2.getContext('2d');
                  if (x2) {
                    var widths = {};
                    var FONTS = ['13px Arial','17px Times New Roman','13px monospace','17px Courier New','13px Georgia','15px Verdana','13px Tahoma','13px Comic Sans MS','13px Impact','13px Trebuchet MS','15px Lucida Console','13px Palatino Linotype','13px Segoe UI'];
                    FONTS.forEach(function(f){
                      try { x2.font = f; widths[f] = x2.measureText('mmmmmmmmmmlliWWWW@#1234567890').width; } catch (e2) {}
                    });
                    o['canvas.measureText'] = widths;
                  }
                } catch (e) {}
                // 3) 字体可用性探测（宽度差法：与三种通用字体的基线宽度比较）
                try {
                  var c3 = document.createElement('canvas');
                  var x3 = c3.getContext('2d');
                  if (x3) {
                    var PROBE = 'mmmmmmmmmmlli';
                    function widthOf(f){
                      try { x3.font = '72px ' + f; return x3.measureText(PROBE).width; } catch (e2) { return -1; }
                    }
                    var base = widthOf('monospace'), baseS = widthOf('serif'), baseSans = widthOf('sans-serif');
                    var TEST = ['Arial','Times New Roman','Courier New','Georgia','Verdana','Tahoma','Comic Sans MS','Impact','Trebuchet MS','Lucida Console','Palatino Linotype','Segoe UI','Calibri','Cambria','Consolas','Helvetica','Century Gothic','Franklin Gothic Medium','Garamond','MS Sans Serif','MS Serif','Segoe UI Emoji','Segoe UI Symbol','Wingdings','Cordia New','Droid Sans','Roboto'];
                    var avail = [];
                    TEST.forEach(function(f){
                      var w = widthOf('"' + f + '", monospace');
                      if (w >= 0 && base >= 0 && w !== base) {
                        var wS = widthOf('"' + f + '", serif');
                        var wN = widthOf('"' + f + '", sans-serif');
                        if ((wS >= 0 && wS !== baseS) || (wN >= 0 && wN !== baseSans)) avail.push(f);
                      }
                    });
                    o['canvas.fonts'] = avail;
                  }
                } catch (e) {}
                return o;
              }
              function collectWebGL(){
                var o = {};
                try {
                  var c = document.createElement('canvas');
                  var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
                  if (!gl) return o;
                  var dbg = gl.getExtension('WEBGL_debug_renderer_info');
                  if (dbg) {
                    try { o['webgl.vendor'] = String(gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL)); } catch (e) {}
                    try { o['webgl.renderer'] = String(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL)); } catch (e) {}
                  }
                  try {
                    var params = {};
                    var NAMES = ['VERSION','SHADING_LANGUAGE_VERSION','VENDOR','RENDERER','MAX_TEXTURE_SIZE','MAX_CUBE_MAP_TEXTURE_SIZE','MAX_RENDERBUFFER_SIZE','MAX_VIEWPORT_DIMS','MAX_VERTEX_ATTRIBS','MAX_VARYING_VECTORS','MAX_VERTEX_UNIFORM_VECTORS','MAX_FRAGMENT_UNIFORM_VECTORS','MAX_COMBINED_TEXTURE_IMAGE_UNITS','MAX_TEXTURE_IMAGE_UNITS','MAX_VERTEX_TEXTURE_IMAGE_UNITS','RED_BITS','GREEN_BITS','BLUE_BITS','ALPHA_BITS','DEPTH_BITS','STENCIL_BITS','SUBPIXEL_BITS','ALIASED_LINE_WIDTH_RANGE','ALIASED_POINT_SIZE_RANGE'];
                    NAMES.forEach(function(n){
                      try { var e = gl[n]; if (e !== undefined) params[n] = gl.getParameter(e); } catch (e2) {}
                    });
                    o['webgl.params'] = params;
                  } catch (e) {}
                  try {
                    var vsrc = 'attribute vec2 p; void main(){ gl_Position = vec4(p, 0.0, 1.0); }';
                    var fsrc = 'precision mediump float; void main(){ gl_FragColor = vec4(1.0, 0.5, 0.25, 1.0); }';
                    function sh(t, s){ var o2 = gl.createShader(t); gl.shaderSource(o2, s); gl.compileShader(o2); return o2; }
                    var pr = gl.createProgram();
                    gl.attachShader(pr, sh(gl.VERTEX_SHADER, vsrc));
                    gl.attachShader(pr, sh(gl.FRAGMENT_SHADER, fsrc));
                    gl.linkProgram(pr); gl.useProgram(pr);
                    var buf = gl.createBuffer();
                    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
                    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, 0, 1]), gl.STATIC_DRAW);
                    var loc = gl.getAttribLocation(pr, 'p');
                    gl.enableVertexAttribArray(loc);
                    gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
                    gl.drawArrays(gl.TRIANGLES, 0, 3);
                    var W = Math.min(64, gl.drawingBufferWidth || 64), H = Math.min(64, gl.drawingBufferHeight || 64);
                    var px = new Uint8Array(W * H * 4);
                    gl.readPixels(0, 0, W, H, gl.RGBA, gl.UNSIGNED_BYTE, px);
                    o['webgl.data'] = 'fnv1a32:' + fnv1a(px).toString(16) + ':' + px.length;
                  } catch (e) {}
                } catch (e) {}
                return o;
              }
              if (needCanvas) { var cc = collectCanvas(); for (var k1 in cc) out[k1] = cc[k1]; }
              if (needWebgl) { var cw = collectWebGL(); for (var k2 in cw) out[k2] = cw[k2]; }

              // ---- 常规属性路径通道 ----
              function get(path){
                var parts = String(path).split('.');
                var cur = (parts[0] === 'window') ? window : (typeof self !== 'undefined' ? self : globalThis);
                for (var i = 1; i < parts.length; i++){
                  if (cur === null || cur === undefined) return undefined;
                  cur = cur[parts[i]];
                }
                return cur;
              }
              function safe(v){
                if (v === undefined) return undefined;
                if (v === null) return null;
                var t = typeof v;
                if (t === 'string' || t === 'number' || t === 'boolean') return v;
                if (t === 'function') return '[function]';
                // 对象/数组：先验证可序列化（循环引用会抛错），再存引用，由外层 JSON.stringify 单层编码
                try { JSON.stringify(v); return v; } catch (e) { return '[unserializable]'; }
              }
              for (var i = 0; i < keys.length; i++){
                var k = keys[i];
                if (k === 'canvas' || k.indexOf('canvas.') === 0 || k === 'webgl' || k.indexOf('webgl.') === 0) continue;
                try {
                  var v = get(k);
                  if (v !== undefined) out[k] = safe(v);
                } catch (e) {}
              }
              return JSON.stringify(out);
            })()
        """.trimIndent()
    }

    /**
     * 缩放解锁脚本：像正常浏览器一样强制允许双指缩放。
     *
     * 背景：很多站点在 viewport meta 中声明 user-scalable=no / maximum-scale=1，
     * WebView 会尊重该声明导致无法缩放（Chrome 可在无障碍设置中强制开启）。
     * 本脚本在页面加载完成后移除这些限制，并持续监控 meta 变化防止站点动态改回。
     *
     * 修复：原实现存在无限循环——maximum-scale=10.0 替换后仍匹配数字正则，
     * setAttribute 相同值再次触发 MutationObserver，observer 又调 apply() 写回相同值。
     * 页面主线程被高频空转占满，表现为"图片已显示但后续动态内容（文字）全部停止渲染"。
     * 修复：1) 写回前比对替换前后内容，相同则跳过（幂等）；2) apply 期间先 disconnect observer。
     */
    fun zoomUnlockScript(): String = """
        (function() {
          // 防重复注入：同一页面上下文已初始化过则只重新解锁一次，不重复创建 observer
          if (window.__WRMCP_ZOOM_UNLOCK__) { window.__WRMCP_ZOOM_UNLOCK__.apply(); return; }
          function unlock() {
            try {
              var metas = document.querySelectorAll('meta[name="viewport"]');
              for (var i = 0; i < metas.length; i++) {
                var m = metas[i];
                var c = m.getAttribute('content') || '';
                if (!c) continue;
                var orig = c;
                c = c.replace(/user-scalable\s*=\s*no/gi, 'user-scalable=yes');
                c = c.replace(/maximum-scale\s*=\s*[\d.]+/gi, 'maximum-scale=10.0');
                // 幂等写回：只有内容真的变化才 setAttribute，避免触发 observer 死循环
                if (c !== orig) m.setAttribute('content', c);
              }
              // 没有声明 viewport 的页面：补一个允许缩放的（保留 overview 行为）
              if (metas.length === 0 && document.head) {
                var meta = document.createElement('meta');
                meta.name = 'viewport';
                meta.content = 'width=device-width, initial-scale=1.0, maximum-scale=10.0, user-scalable=yes';
                document.head.appendChild(meta);
              }
            } catch (e) {}
          }
          window.__WRMCP_ZOOM_UNLOCK__ = { apply: unlock };

          var obs = null;
          function startObserve() {
            try {
              var target = document.head || document.documentElement;
              if (!target || !window.MutationObserver) return;
              obs = new MutationObserver(function() {
                // apply 期间先断开，防止自身写回触发连锁
                try { obs && obs.disconnect(); } catch (e) {}
                unlock();
                try { obs && obs.observe(target, { childList: true, subtree: true, attributes: true, attributeFilter: ['content'] }); } catch (e) {}
              });
              obs.observe(target, { childList: true, subtree: true, attributes: true, attributeFilter: ['content'] });
            } catch (e) {}
          }

          unlock();
          startObserve();
        })();
    """.trimIndent()

    /** 获取所有脚本源码 */
    fun scriptsScript(): String = """
        (function(){
          var out = [];
          document.querySelectorAll('script').forEach(function(s, i){
            var src = s.src || '(inline)';
            out.push({index:i, src:src, type:s.type||'text/javascript', text:(s.textContent||'').substring(0, 200000)});
          });
          return JSON.stringify(out);
        })()
    """.trimIndent()

    /**
     * Hook Registry Framework（唯一权威实现，JsRuntimeHook / document_start 注入共用）。
     *
     * 语义：
     * 1. 幂等安装：Hook 以 type(+target) 为 key 登记，同 key 重复安装只追加回调
     *    （attach），绝不重复包装目标——杜绝 hook 链叠加与"一次请求 N 条日志"。
     * 2. 多回调：每个 Hook 持有 cbs 数组。document_start 早期安装的观测回调与
     *    后续 MCP 工具注册的用户回调共存，互不覆盖。
     * 3. 完整恢复：所有类型（含 xhr/storage/cookie/timer/console/crypto/history/
     *    location/event/eval）在注册表保存 original，removeHook 精确还原。
     * 4. Event Hook 用 document 级捕获委托 + closest 匹配：SPA 重建 DOM 后依然生效。
     * 5. Timer Hook 覆盖 setTimeout/setInterval/requestAnimationFrame/queueMicrotask，
     *    记录函数体片段（不仅 string 形式）。
     * 6. eval/Function Hook 追踪动态代码执行。
     * 7. WebSocket Hook 保留原型链（instanceof 与静态属性不破坏）。
     * 挂载于 window.__WRMCP_HOOK__，并别名到 __MCP__（兼容旧调用）。
     */
    fun hookFrameworkScript(): String = """
        (function(){
          if (window.__WRMCP_HOOK__ && window.__WRMCP_HOOK__.v2) return;
          var R = {
            v2: true,
            hooks: {},
            byKey: {},
            _id: 0,
            register: function(key, entry) {
              var id = key + '_' + (++this._id);
              entry.cbs = [];
              this.hooks[id] = entry;
              this.byKey[key] = id;
              return id;
            },
            /** 同 key 已存在时只追加回调，返回既有 id；否则 null */
            attach: function(key, callback) {
              var id = this.byKey[key];
              if (id && this.hooks[id] && typeof callback === 'function') {
                this.hooks[id].cbs.push(callback);
                return id;
              }
              return null;
            },
            /** 触发指定 Hook 的全部回调（单回调异常不影响其余） */
            fire: function(id, info) {
              var h = this.hooks[id];
              if (!h) return;
              for (var i = 0; i < h.cbs.length; i++) {
                try { h.cbs[i](info); } catch(e){}
              }
            },
            restore: function(id) {
              var h = this.hooks[id];
              if (!h) return false;
              try {
                switch (h.type) {
                  case 'function': case 'method': h.obj[h.prop] = h.original; break;
                  case 'property': Object.defineProperty(h.obj, h.prop, h.descriptor); break;
                  case 'fetch': window.fetch = h.original; break;
                  case 'xhr':
                    XMLHttpRequest.prototype.open = h.open; XMLHttpRequest.prototype.send = h.send; break;
                  case 'websocket': window.WebSocket = h.original; break;
                  case 'storage':
                    Storage.prototype.setItem = h.setItem; Storage.prototype.removeItem = h.removeItem; break;
                  case 'cookie': Object.defineProperty(Document.prototype, 'cookie', h.descriptor); break;
                  case 'timer':
                    window.setTimeout = h.setTimeout; window.setInterval = h.setInterval;
                    if (h.raf) window.requestAnimationFrame = h.raf;
                    if (h.qmt) window.queueMicrotask = h.qmt;
                    break;
                  case 'console':
                    Object.keys(h.levels).forEach(function(l){ console[l] = h.levels[l]; }); break;
                  case 'crypto':
                    if (h.digest) crypto.subtle.digest = h.digest;
                    if (h.grv) crypto.getRandomValues = h.grv;
                    break;
                  case 'cryptoLib':
                    // 按登记路径逐一恢复（含 btoa/atob/TextEncoder 原型）
                    if (h.orig) {
                      Object.keys(h.orig).forEach(function(path){
                        try {
                          var fn = h.orig[path];
                          if (path === 'btoa' || path === 'atob') { window[path] = fn; return; }
                          if (path === 'encode' && window.TextEncoder) { TextEncoder.prototype.encode = fn; return; }
                          if (path === 'decode' && window.TextDecoder) { TextDecoder.prototype.decode = fn; return; }
                          // CryptoJS/JSEncrypt 方法路径：AES.encrypt 等
                          var owner = null;
                          if (window.CryptoJS) {
                            var seg = path.split('.');
                            if (seg[0] === 'Base64' && window.CryptoJS.enc) owner = {o: window.CryptoJS.enc.Base64, p: seg[1]};
                            else owner = {o: window.CryptoJS[seg[0]], p: seg[1]};
                          }
                          if (!owner && window.JSEncrypt && (path === 'encrypt' || path === 'decrypt' || path === 'setPublicKey')) {
                            owner = {o: window.JSEncrypt.prototype, p: path};
                          }
                          if (owner && owner.o) owner.o[owner.p] = fn;
                        } catch(e){}
                      });
                    }
                    break;
                  case 'history':
                    history.pushState = h.pushState; history.replaceState = h.replaceState; break;
                  case 'location': Object.defineProperty(Location.prototype, 'href', h.descriptor); break;
                  case 'event': document.removeEventListener(h.eventType, h.handler, true); break;
                  case 'eval': window.eval = h.evalFn; window.Function = h.Function; break;
                }
              } catch(e){}
              delete this.byKey[h.key];
              delete this.hooks[id];
              return true;
            }
          };
          window.__WRMCP_HOOK__ = R;

          // 网络事件上报通道——fetch/XHR hook 把请求/响应/响应体回传给
          // NetworkBridge（__MCP__.netEvent），补全 shouldInterceptRequest 看不到的信息。
          // URL 统一绝对化 + 去 fragment，保证与原生侧条目可按 path 匹配。
          // （报告 §12 Request Identity）：每条请求携带唯一 rid，
          // request/response/body 三阶段同 rid 归并——同 URL 并发请求不再互相错配
          // （旧 pathKey 归并把响应体挂到"最近一条同路径请求"上，轮询/并发场景必错）。
          R.__ridN = 0;
          R.rid = function() {
            return 'r' + (++R.__ridN).toString(36) + '-' + Math.random().toString(36).slice(2, 8);
          };
          R.reportNet = function(info) {
            try {
              if (window.__MCP__ && window.__MCP__.netEvent) {
                window.__MCP__.netEvent(JSON.stringify(info));
              }
            } catch(e){}
          };
          R.absUrl = function(u) {
            try {
              return new URL(String(u), location.href).href.split('#')[0];
            } catch(e) { return String(u).split('#')[0]; }
          };

          // toString 伪装内建进框架（不再依赖 stealthScript 的注入顺序）
          // 三层防御：显式注册表 > __original 约定兜底 > 原样返回
          // 解决 缺口：stealthScript 事后扫描 hooks 存的是 h.prop（字符串），
          // 包装函数实际从未注册成功——fetch.toString() 会暴露 hook 源码
          var __tsPatched = false;
          try {
            var _ts = Function.prototype.toString;
            var __nativeReg = new WeakMap();
            Function.prototype.toString = function() {
              try {
                if (__nativeReg.has(this)) return __nativeReg.get(this);
                var orig = R.origOf(this);
                if (typeof orig === 'function') {
                  var s = _ts.call(orig);
                  __nativeReg.set(this, s);
                  return s;
                }
              } catch(e){}
              return _ts.call(this);
            };
            __nativeReg.set(Function.prototype.toString, 'function toString() { [native code] }');
            R._native = function(fn, name) {
              try {
                if (typeof fn === 'function') {
                  __nativeReg.set(fn, 'function ' + (name || fn.name || '') + '() { [native code] }');
                  return true;
                }
              } catch(e){}
              return false;
            };
            __tsPatched = true;
          } catch(e){}

          var stackOf = function() {
            try { return new Error().stack; } catch(e){ return ''; }
          };
          var fnSrc = function(fn, n) {
            try { return typeof fn === 'string' ? fn.substring(0, n) : (fn && fn.toString ? fn.toString().substring(0, n) : typeof fn); }
            catch(e){ return typeof fn; }
          };
          var resolve = function(pathExpr) {
            var path = pathExpr.split('.');
            var obj = window;
            for (var i=0;i<path.length-1;i++){ if (obj[path[i]] === undefined) return null; obj = obj[path[i]]; }
            return {obj: obj, prop: path[path.length-1]};
          };
          // （Hook 隐匿性）：原引用不再以可枚举属性外露。主存储用 WeakMap（
          // 页面 for..in / Object.keys / getOwnPropertyNames 完全不可见），另留一个
          // 不可枚举 __original 兜底供 toString 伪装与兼容读取。registry 仍持 original，
          // removeHook 恢复路径不变。
          R.__origMap = R.__origMap || new WeakMap();
          R.saveOriginal = function(fn, orig) {
            try {
              R.__origMap.set(fn, orig);
              Object.defineProperty(fn, '__original', {
                value: orig, writable: true, configurable: true, enumerable: false
              });
            } catch(e){ try { fn.__original = orig; } catch(e2){} }
          };
          R.origOf = function(fn) {
            try { if (fn && R.__origMap.has(fn)) return R.__origMap.get(fn); } catch(e){}
            return fn && fn.__original;
          };
          /** 安装模板：已存在则 attach；否则包装目标并登记 original */
          var install = function(key, callback, wrapFactory) {
            var ex = R.attach(key, callback);
            if (ex) return ex;
            var id = wrapFactory();
            if (id === null || id === undefined) return null;
            if (typeof callback === 'function') R.hooks[id].cbs.push(callback);
            return id;
          };

          R.hookFunction = function(name, callback) {
            var key = 'function:' + name;
            return install(key, callback, function(){
              var loc = resolve(name); if (!loc) return null;
              var original = loc.obj[loc.prop];
              if (typeof original !== 'function') return null;
              var id = R.register(key, {type:'function', key:key, obj:loc.obj, prop:loc.prop, original:original});
              var wrapped = function() {
                var stack = stackOf();
                var result;
                try { result = original.apply(this, arguments); }
                finally { R.fire(id, {name:name, args:Array.prototype.slice.call(arguments), result:result, stack:stack}); }
                return result;
              };
              R.saveOriginal(wrapped, original);
              loc.obj[loc.prop] = wrapped;
              return id;
            });
          };

          R.hookMethod = function(objExpr, methodName, callback) {
            var key = 'method:' + objExpr + '.' + methodName;
            return install(key, callback, function(){
              // 不再用 eval(objExpr)，改用 resolve 从 window 安全迭代取宿主对象。
              // 页面若污染 window.eval / Function.prototype.apply（如 stealth、Hook_CryptoJS），
              // eval 路径会解析失败或返回非对象，导致“对象或方法不存在”误报。
              var loc = resolve(objExpr + '.' + methodName);
              if (!loc) return null;
              var obj = loc.obj;
              var original = loc.obj[loc.prop];
              if (typeof original !== 'function') return null;
              var id = R.register(key, {type:'method', key:key, obj:obj, prop:loc.prop, original:original});
              var wrapped = function() {
                var result;
                try { result = original.apply(this, arguments); }
                finally { R.fire(id, {target:objExpr+'.'+methodName, args:Array.prototype.slice.call(arguments), result:result}); }
                return result;
              };
              R.saveOriginal(wrapped, original);
              loc.obj[loc.prop] = wrapped;
              return id;
            });
          };

          R.hookProperty = function(objExpr, propName, getter, setter) {
            var key = 'property:' + objExpr + '.' + propName;
            var ex = R.attach(key, typeof getter === 'function' && setter === undefined ? getter : null);
            if (ex) return ex;
            try {
              // 与 hookMethod 一致，resolve 替代 eval，规避 eval/apply 污染
              var loc = resolve(objExpr + '.' + propName);
              if (!loc) return null;
              var obj = loc.obj;
              var descriptor = Object.getOwnPropertyDescriptor(obj, loc.prop) || {configurable:true, enumerable:true, writable:true, value: obj[loc.prop]};
              var originalGet = descriptor.get || function(){ return obj[loc.prop]; };
              var originalSet = descriptor.set || function(v){ obj[loc.prop] = v; };
              var id = R.register(key, {type:'property', key:key, descriptor:descriptor, obj:obj, prop:loc.prop});
              if (typeof getter === 'function' && setter === undefined) R.hooks[id].cbs.push(getter);
              Object.defineProperty(obj, loc.prop, {
                configurable: true,
                enumerable: descriptor.enumerable !== false,
                get: function() {
                  var v = originalGet.call(this);
                  R.fire(id, {kind:'get', target:objExpr+'.'+propName, value:v});
                  return v;
                },
                set: function(v) {
                  R.fire(id, {kind:'set', target:objExpr+'.'+propName, value:v});
                  return originalSet.call(this, v);
                }
              });
              return id;
            } catch(e){ return null; }
          };

          // Event Hook：document 捕获委托 + closest 匹配（SPA 动态 DOM 生效）
          R.hookEvent = function(selector, eventType, callback) {
            var key = 'event:' + selector + ':' + eventType;
            var ex = R.attach(key, callback); if (ex) return ex;
            try {
              var handler = function(e) {
                try {
                  var t = e.target && e.target.closest ? e.target.closest(selector) : null;
                  if (t) R.fire(id, {selector:selector, type:eventType, target: t.tagName, id: t.id || '', text: (t.textContent||'').trim().substring(0,80)});
                } catch(err){}
              };
              document.addEventListener(eventType, handler, true);
              var id = R.register(key, {type:'event', key:key, selector:selector, eventType:eventType, handler:handler});
              if (typeof callback === 'function') R.hooks[id].cbs.push(callback);
              return id;
            } catch(e){ return null; }
          };

          R.hookFetch = function(callback) {
            var key = 'fetch';
            return install(key, callback, function(){
              var original = window.fetch;
              if (typeof original !== 'function') return null;
              var id = R.register(key, {type:'fetch', key:key, original:original});
              window.fetch = function() {
                var url = arguments[0];
                var opts = arguments[1] || {};
                var urlStr = (typeof url === 'string') ? url : (url && url.url) || String(url);
                var method = ((url && url.method) || opts.method || 'GET').toUpperCase();
                var absUrl = R.absUrl(urlStr);
                var rid = R.rid();
                var t0 = Date.now();
                var bodyStr = null;
                try {
                  var b = (url && url.body) || opts.body;
                  if (typeof b === 'string') bodyStr = b.substring(0, 4096);
                  else if (typeof URLSearchParams !== 'undefined' && b instanceof URLSearchParams) bodyStr = b.toString().substring(0, 4096);
                } catch(e){}
                R.reportNet({phase:'request', rid:rid, src:'fetch', url:absUrl, method:method, body:bodyStr});
                R.fire(id, {type:'request', url:urlStr, method:method, bodyType: typeof opts.body, stack: stackOf()});
                return original.apply(this, arguments).then(function(resp){
                  var dur = Date.now() - t0;
                  var ct = '';
                  try { ct = (resp.headers && resp.headers.get && resp.headers.get('content-type')) || ''; } catch(e){}
                  R.reportNet({phase:'response', rid:rid, src:'fetch', url:absUrl, method:method, status:resp.status, durationMs:dur, contentType:ct});
                  // 文本类响应体捕获（clone 异步读取，尽力而为，失败不影响页面）
                  try {
                    var cl = -1;
                    try { cl = parseInt(resp.headers.get('content-length') || '-1', 10); } catch(e2){}
                    if (cl <= 0 || cl <= 2097152) {
                      if (/text|json|javascript|ecmascript|xml|html/i.test(ct)) {
                        resp.clone().text().then(function(txt){
                          if (txt) R.reportNet({phase:'body', rid:rid, src:'fetch', url:absUrl, method:method, status:resp.status, body:txt.substring(0, 131072)});
                        }).catch(function(){});
                      }
                    }
                  } catch(e){}
                  R.fire(id, {type:'response', url:urlStr, method:method, status:resp.status});
                  return resp;
                }, function(err){
                  R.reportNet({phase:'response', rid:rid, src:'fetch', url:absUrl, method:method, status:0, durationMs:Date.now()-t0, error:String(err && err.message || err)});
                  throw err;
                });
              };
              R.saveOriginal(window.fetch, original);
              return id;
            });
          };

          R.hookXHR = function(callback) {
            var key = 'xhr';
            return install(key, callback, function(){
              var _open = XMLHttpRequest.prototype.open;
              var _send = XMLHttpRequest.prototype.send;
              var id = R.register(key, {type:'xhr', key:key, open:_open, send:_send});
              XMLHttpRequest.prototype.open = function(method, url) {
                this.__wrmcpUrl = url; this.__wrmcpMethod = method;
                R.fire(id, {type:'open', url:String(url), method:method});
                return _open.apply(this, arguments);
              };
              R.saveOriginal(XMLHttpRequest.prototype.open, _open);
              XMLHttpRequest.prototype.send = function(body) {
                var self = this;
                var t0 = Date.now();
                var rid = R.rid();
                self.__wrmcpRid = rid;
                var bodyStr = null;
                try {
                  if (typeof body === 'string') bodyStr = body.substring(0, 4096);
                  else if (typeof URLSearchParams !== 'undefined' && body instanceof URLSearchParams) bodyStr = body.toString().substring(0, 4096);
                } catch(e){}
                R.reportNet({phase:'request', rid:rid, src:'xhr', url:R.absUrl(self.__wrmcpUrl || ''), method:String(self.__wrmcpMethod || 'GET'), body:bodyStr});
                this.addEventListener('loadend', function(){
                  var dur = Date.now() - t0;
                  var finalUrl = R.absUrl(self.responseURL || self.__wrmcpUrl || '');
                  var method = String(self.__wrmcpMethod || 'GET');
                  var ct = '';
                  try { ct = (self.getResponseHeader && self.getResponseHeader('content-type')) || ''; } catch(e){}
                  R.reportNet({phase:'response', rid:rid, src:'xhr', url:finalUrl, method:method, status:self.status, durationMs:dur, contentType:ct});
                  // 文本响应体捕获（responseType 为空/text 时才可读，否则抛异常）
                  try {
                    if (self.responseType === '' || self.responseType === 'text') {
                      var txt = self.responseText;
                      if (txt) R.reportNet({phase:'body', rid:rid, src:'xhr', url:finalUrl, method:method, status:self.status, body:txt.substring(0, 131072)});
                    }
                  } catch(e){}
                  R.fire(id, {type:'response', url:self.__wrmcpUrl, method:self.__wrmcpMethod, status:self.status});
                });
                return _send.apply(this, arguments);
              };
              R.saveOriginal(XMLHttpRequest.prototype.send, _send);
              return id;
            });
          };

          R.hookWebSocket = function(callback) {
            var key = 'websocket';
            return install(key, callback, function(){
              var OrigWS = window.WebSocket;
              if (typeof OrigWS !== 'function') return null;
              var id = R.register(key, {type:'websocket', key:key, original:OrigWS});
              var WSHook = function(url, protocols) {
                R.fire(id, {type:'open', url:String(url)});
                var ws = protocols !== undefined ? new OrigWS(url, protocols) : new OrigWS(url);
                var _send = ws.send;
                ws.send = function(data) {
                  R.fire(id, {type:'send', url:String(url), data:String(data).substring(0,500)});
                  return _send.apply(ws, arguments);
                };
                ws.addEventListener('message', function(ev){
                  R.fire(id, {type:'message', url:String(url), data:String(ev.data).substring(0,500)});
                });
                return ws;
              };
              WSHook.prototype = OrigWS.prototype;
              Object.setPrototypeOf(WSHook, OrigWS);
              window.WebSocket = WSHook;
              return id;
            });
          };

          R.hookStorage = function(callback) {
            var key = 'storage';
            return install(key, callback, function(){
              var _setItem = Storage.prototype.setItem;
              var _removeItem = Storage.prototype.removeItem;
              var id = R.register(key, {type:'storage', key:key, setItem:_setItem, removeItem:_removeItem});
              Storage.prototype.setItem = function(k, value) {
                var sensitive = /(password|token|secret|api[_-]?key|authorization|cookie)/i.test(k);
                R.fire(id, {type:'setItem', key:k, value: sensitive ? '[REDACTED]' : String(value).substring(0,500)});
                return _setItem.apply(this, arguments);
              };
              Storage.prototype.removeItem = function(k) {
                R.fire(id, {type:'removeItem', key:k});
                return _removeItem.apply(this, arguments);
              };
              return id;
            });
          };

          R.hookCookie = function(callback) {
            var key = 'cookie';
            return install(key, callback, function(){
              var desc = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
              if (!desc || !desc.get || !desc.set) return null;
              var _get = desc.get, _set = desc.set;
              var id = R.register(key, {type:'cookie', key:key, descriptor:desc});
              Object.defineProperty(Document.prototype, 'cookie', {
                configurable: true, enumerable: desc.enumerable,
                get: function() {
                  var v = _get.call(this);
                  R.fire(id, {type:'read', value: v ? '[REDACTED_COOKIE]' : ''});
                  return v;
                },
                set: function(v) {
                  R.fire(id, {type:'write', value: '[REDACTED_COOKIE]'});
                  return _set.call(this, v);
                }
              });
              return id;
            });
          };

          R.hookTimer = function(callback) {
            var key = 'timer';
            return install(key, callback, function(){
              var _st = window.setTimeout, _si = window.setInterval;
              var _raf = window.requestAnimationFrame, _qmt = window.queueMicrotask;
              var id = R.register(key, {type:'timer', key:key, setTimeout:_st, setInterval:_si, raf:_raf, qmt:_qmt});
              window.setTimeout = function(fn, delay) {
                if (fn) R.fire(id, {type:'setTimeout', code:fnSrc(fn,200), delay:delay||0});
                return _st.apply(window, arguments);
              };
              window.setInterval = function(fn, delay) {
                if (fn) R.fire(id, {type:'setInterval', code:fnSrc(fn,200), delay:delay||0});
                return _si.apply(window, arguments);
              };
              if (_raf) window.requestAnimationFrame = function(fn) {
                R.fire(id, {type:'rAF', code:fnSrc(fn,200)});
                return _raf.apply(window, arguments);
              };
              if (_qmt) window.queueMicrotask = function(fn) {
                R.fire(id, {type:'microtask', code:fnSrc(fn,200)});
                return _qmt.apply(window, arguments);
              };
              return id;
            });
          };

          R.hookConsole = function(callback) {
            var key = 'console';
            return install(key, callback, function(){
              var levels = {};
              ['log','warn','error','info','debug'].forEach(function(level){ levels[level] = console[level]; });
              var id = R.register(key, {type:'console', key:key, levels:levels});
              Object.keys(levels).forEach(function(level){
                var orig = levels[level];
                console[level] = function() {
                  R.fire(id, {type:'console', level:level, args:Array.prototype.slice.call(arguments).map(String).join(' ').substring(0,500)});
                  return orig.apply(console, arguments);
                };
              });
              return id;
            });
          };

          R.hookCrypto = function(callback) {
            var key = 'crypto';
            return install(key, callback, function(){
              try {
                var _digest = crypto.subtle.digest;
                var _grv = crypto.getRandomValues;
                var id = R.register(key, {type:'crypto', key:key, digest:_digest, grv:_grv});
                crypto.subtle.digest = function(algorithm, data) {
                  R.fire(id, {type:'digest', algorithm: typeof algorithm === 'string' ? algorithm : (algorithm && algorithm.name) || ''});
                  return _digest.apply(this, arguments);
                };
                R.saveOriginal(crypto.subtle.digest, _digest);
                crypto.getRandomValues = function(arr) {
                  R.fire(id, {type:'getRandomValues', length: arr && arr.length});
                  return _grv.apply(this, arguments);
                };
                R.saveOriginal(crypto.getRandomValues, _grv);
                return id;
              } catch(e){ return null; }
            });
          };

          R.hookHistory = function(callback) {
            var key = 'history';
            return install(key, callback, function(){
              var _push = history.pushState, _replace = history.replaceState;
              var id = R.register(key, {type:'history', key:key, pushState:_push, replaceState:_replace});
              history.pushState = function(state, title, url) {
                R.fire(id, {type:'pushState', url:String(url)});
                return _push.apply(this, arguments);
              };
              history.replaceState = function(state, title, url) {
                R.fire(id, {type:'replaceState', url:String(url)});
                return _replace.apply(this, arguments);
              };
              return id;
            });
          };

          R.hookLocation = function(callback) {
            var key = 'location';
            return install(key, callback, function(){
              try {
                var desc = Object.getOwnPropertyDescriptor(Location.prototype, 'href');
                if (!desc || !desc.get || !desc.set) return null;
                var _get = desc.get, _set = desc.set;
                var id = R.register(key, {type:'location', key:key, descriptor:desc});
                Object.defineProperty(Location.prototype, 'href', {
                  configurable: true, enumerable: desc.enumerable,
                  get: function(){ return _get.call(this); },
                  set: function(v){ R.fire(id, {type:'href', url:String(v)}); return _set.call(this, v); }
                });
                return id;
              } catch(e){ return null; }
            });
          };

          // 动态代码执行追踪：eval / new Function
          R.hookEval = function(callback) {
            var key = 'eval';
            return install(key, callback, function(){
              var _eval = window.eval, _Function = window.Function;
              if (typeof _eval !== 'function') return null;
              var id = R.register(key, {type:'eval', key:key, evalFn:_eval, Function:_Function});
              window.eval = function(code) {
                R.fire(id, {type:'eval', code: String(code).substring(0,500)});
                return _eval.apply(window, arguments);
              };
              if (typeof _Function === 'function') {
                window.Function = function() {
                  var args = Array.prototype.slice.call(arguments);
                  R.fire(id, {type:'Function', body: String(args[args.length-1]).substring(0,500)});
                  return _Function.apply(this, arguments);
                };
                window.Function.prototype = _Function.prototype;
              }
              return id;
            });
          };

          // WASM 模块采集 v2：拦截 instantiate / instantiateStreaming / Module / compile，
          // 保留字节码引用与 import/export 清单（逆向 WASM 签名算法的入口）。
          //
          // v2 修复/增强（评审缺陷 3.4 + P1 建议）：
          // - instantiateStreaming 竞态修复：fillExports 改挂进 clone().arrayBuffer()
          //   的 Promise 链内部，不再同步读 idx（旧实现恒 -1，exportNames 永远为空）
          // - WebAssembly.compile 补 hook
          // - 导出函数观测：instantiate 成功后自动包装 exports 中的函数，
          //   记录每次调用的参数/返回值/调用前后内存快照（签名算法逆向最直接手段）
          R.hookWasm = function(callback) {
            if (!window.WebAssembly) return null;
            if (R.__wasmHooked) { return 'wasm'; }
            R.__wasmHooked = true;
            window.__WRMCP_WASM__ = window.__WRMCP_WASM__ || [];
            window.__WRMCP_WASM_CALLS__ = window.__WRMCP_WASM_CALLS__ || [];
            var CALL_CAP = 500;
            var MEM_SNAP = 256;
            function record(bytes, importKeys, url) {
              try {
                var u = (bytes instanceof ArrayBuffer) ? new Uint8Array(bytes) : bytes;
                if (!u || !u.length) return -1;
                var rec = { ts: Date.now(), size: u.length, bytes: u, url: url || '',
                            importKeys: importKeys || [], exportNames: [] };
                window.__WRMCP_WASM__.push(rec);
                if (callback) try { callback({size: rec.size, importKeys: rec.importKeys}); } catch(e){}
                return window.__WRMCP_WASM__.length - 1;
              } catch(e){ return -1; }
            }
            function memSnapshot(instance) {
              try {
                var m = instance && instance.exports && (instance.exports.memory || instance.exports.mem);
                if (!m || !m.buffer) return {b64:'', size:0};
                var u = new Uint8Array(m.buffer, 0, Math.min(MEM_SNAP, m.buffer.byteLength));
                var s = '';
                for (var i = 0; i < u.length; i += 0x800) {
                  s += String.fromCharCode.apply(null, u.subarray(i, Math.min(i + 0x800, u.length)));
                }
                return {b64:btoa(s), size:u.length, bytes:Array.prototype.slice.call(u)};
              } catch(e){ return {b64:'', size:0, bytes:[]}; }
            }
            function diffRanges(a, b) {
              try {
                var aa = (a && a.bytes) || [], bb = (b && b.bytes) || [];
                var n = Math.min(aa.length, bb.length), out = [], start = -1;
                for (var i = 0; i < n; i++) {
                  if (aa[i] !== bb[i]) { if (start < 0) start = i; }
                  else if (start >= 0) { out.push({start:start, end:i-1, len:i-start}); start = -1; if (out.length >= 16) break; }
                }
                if (start >= 0 && out.length < 16) out.push({start:start, end:n-1, len:n-start});
                return out;
              } catch(e){ return []; }
            }
            function valueFp(v) {
              try {
                var str = (typeof v === 'string') ? v : JSON.stringify(v);
                if (!str || str.length < 3 || str.length > 4096) return '';
                var h = 0x811c9dc5;
                for (var i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 0x01000193); }
                return ('00000000' + (h >>> 0).toString(16)).slice(-8) + ':' + str.length;
              } catch(e){ return ''; }
            }
            function ptrLenHints(args) {
              var out = [];
              for (var i = 0; i + 1 < args.length; i++) {
                var a = args[i], b = args[i+1];
                if (typeof a === 'number' && typeof b === 'number' && a >= 0 && b > 0 && b <= 0x1000000) {
                  out.push({ptr:a >>> 0, len:b >>> 0, argIndex:i});
                }
              }
              return out.slice(0, 4);
            }
            function fillExports(idx, result) {
              try {
                var rec = window.__WRMCP_WASM__[idx];
                var instance = result && (result.instance || result);
                if (!rec || !instance) return;
                var exports = instance.exports || {};
                rec.exportNames = Object.keys(exports);
                rec.instance = instance;
                // 导出函数观测：包装每个导出函数，记录参数/返回值/内存前后快照
                Object.keys(exports).forEach(function(name) {
                  var fn = exports[name];
                  if (typeof fn !== 'function') return;
                  try {
                    Object.defineProperty(exports, name, {
                      configurable: true, writable: true,
                      value: function() {
                        var args = Array.prototype.slice.call(arguments).map(function(a){
                          try { return (typeof a === 'bigint') ? String(a) : (typeof a === 'number') ? a : String(a); } catch(e){ return '?'; }
                        });
                        var before = memSnapshot(instance);
                        var ret = fn.apply(this, arguments);
                        var after = memSnapshot(instance);
                        var entry = { ts: Date.now(), fn: name, args: args,
                                      argFingerprints: args.map(valueFp),
                                      ptrLenHints: ptrLenHints(arguments),
                                      ret: (typeof ret === 'bigint') ? String(ret) : ret,
                                      retFingerprint: valueFp(ret),
                                      stack: (new Error()).stack || '',
                                      memBefore: before.b64, memAfter: after.b64,
                                      memoryDiffs: diffRanges(before, after) };
                        if (window.__WRMCP_WASM_CALLS__.length < CALL_CAP) {
                          window.__WRMCP_WASM_CALLS__.push(entry);
                        }
                        return ret;
                      }
                    });
                  } catch(e){}
                });
              } catch(e){}
            }
            function hookPromise(p, idx) {
              if (p && p.then) p.then(function(r){ fillExports(idx, r); }).catch(function(){});
              return p;
            }
            var _inst = WebAssembly.instantiate;
            WebAssembly.instantiate = function(bytes, imports) {
              var idx = record(bytes, imports ? Object.keys(imports) : []);
              return hookPromise(_inst.apply(this, arguments), idx);
            };
            var _instS = WebAssembly.instantiateStreaming;
            if (_instS) {
              WebAssembly.instantiateStreaming = function(resp, imports) {
                // 原调用只执行一次；字节采集（异步 clone）完成后，
                // 再把 fillExports 挂到这个（可能已 settle 的）promise 上
                var p = _instS.apply(this, arguments);
                try {
                  var srcUrl = (resp && resp.url) || '';
                  resp.clone().arrayBuffer().then(function(b) {
                    var idx = record(b, imports ? Object.keys(imports) : [], srcUrl);
                    if (idx >= 0) p.then(function(r){ fillExports(idx, r); }).catch(function(){});
                  }).catch(function(){});
                } catch(e){}
                return p;
              };
            }
            var _compile = WebAssembly.compile;
            if (_compile) {
              WebAssembly.compile = function(bytes) {
                record(bytes, []);
                return _compile.apply(this, arguments);
              };
            }
            var _Mod = WebAssembly.Module;
            WebAssembly.Module = function(bytes) {
              record(bytes, []);
              return new _Mod(bytes);
            };
            WebAssembly.Module.prototype = _Mod.prototype;
            return 'wasm';
          };

          // ===== 新增 Hook（Worker / WebCrypto subtle / 设备指纹 / 通知） =====

          // Worker / SharedWorker / ServiceWorker 拦截：逆向打包进 Worker 的签名逻辑
          R.hookWorker = function(callback) {
            var key = 'worker';
            return install(key, callback, function(){
              var _W = window.Worker;
              var _SW = window.SharedWorker;
              if (!_W) return null;
              var id = R.register(key, {type:'worker', key:key, Worker:_W, SharedWorker:_SW});
              function wrapWorker(Orig, kind) {
                return function(url, opts) {
                  var info = {type: kind, url: String(url), opts: (opts && opts.type) || 'classic'};
                  try {
                    if (opts && opts.name) info.name = String(opts.name);
                  } catch(e){}
                  R.fire(id, info);
                  return new Orig(url, opts);
                };
              }
              window.Worker = wrapWorker(_W, 'Worker');
              window.Worker.prototype = _W.prototype;
              if (_SW) {
                window.SharedWorker = wrapWorker(_SW, 'SharedWorker');
                window.SharedWorker.prototype = _SW.prototype;
              }
              if (navigator.serviceWorker && navigator.serviceWorker.register) {
                var _reg = navigator.serviceWorker.register.bind(navigator.serviceWorker);
                navigator.serviceWorker.register = function(url, opts) {
                  R.fire(id, {type:'ServiceWorker', url: String(url)});
                  return _reg(url, opts);
                };
              }
              return id;
            });
          };

          // WebCrypto subtle 全量 Hook：encrypt/decrypt/sign/verify/digest/deriveKey/exportKey
          // —— 签名算法逆向最直接的观测点（算法名 + 参数长度，不采集密钥明文）
          R.hookSubtleCrypto = function(callback) {
            var key = 'subtleCrypto';
            return install(key, callback, function(){
              if (!window.crypto || !window.crypto.subtle) return null;
              var S = window.crypto.subtle;
              var orig = {};
              var methods = ['encrypt','decrypt','sign','verify','digest','deriveKey','deriveBits','generateKey','importKey','exportKey','wrapKey','unwrapKey'];
              methods.forEach(function(m){ orig[m] = S[m]; });
              var id = R.register(key, {type:'subtleCrypto', key:key, orig: orig});
              methods.forEach(function(m){
                if (typeof orig[m] !== 'function') return;
                S[m] = function() {
                  var args = Array.prototype.slice.call(arguments);
                  var algo = args[0];
                  var algoName = (typeof algo === 'string') ? algo : (algo && (algo.name || String(algo))) || '';
                  var info = {type: m, algorithm: algoName};
                  // 参数长度摘要（不采集 KeyMaterial 明文）
                  try {
                    info.argShapes = args.map(function(a){
                      if (a instanceof ArrayBuffer || ArrayBuffer.isView(a)) return 'bytes(' + a.byteLength + ')';
                      if (a && a.type === 'secret' || a && a.extractable !== undefined) return 'CryptoKey(' + (a.algorithm && a.algorithm.name || '?') + ')';
                      if (typeof a === 'object' && a !== null) return 'obj(' + Object.keys(a).slice(0,5).join(',') + ')';
                      return typeof a === 'string' ? a.substring(0, 50) : String(a);
                    });
                  } catch(e){}
                  var p = orig[m].apply(S, arguments);
                  if (p && p.then) p.then(function(r){
                    if (r instanceof ArrayBuffer) info.result = 'bytes(' + r.byteLength + ')';
                    else if (r && r.constructor) info.result = (r.constructor.name || 'object');
                    R.fire(id, info);
                  }, function(){});
                  return p;
                };
              });
              return id;
            });
          };

          // JS 层加密库细粒度 Hook（加密参数第一入口）
          // 覆盖：CryptoJS（AES/DES/MD5/SHA/HMAC/PBKDF2/Base64）、JSEncrypt（RSA）、
          //       btoa/atob、TextEncoder/TextDecoder——国内站点 sign 生成的绝对主力
          R.hookCryptoLib = function(callback) {
            var key = 'cryptoLib';
            return install(key, callback, function(){
              var id = R.register(key, {type:'cryptoLib', key:key, orig:{}});
              var entry = R.hooks[id];
              var hitCount = 0;
              function fire(info) { try { hitCount++; R.fire(id, info); } catch(e){} }
              function safeStr(v, n) {
                try {
                  if (v === null || v === undefined) return String(v);
                  if (typeof v === 'string') return v.substring(0, n);
                  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
                  if (v && v.toString) return v.toString().substring(0, n);
                  return typeof v;
                } catch(e){ return '?'; }
              }
              function wrapMethod(obj, path, label, argIdx) {
                try {
                  var seg = path.split('.');
                  var o = obj;
                  for (var i = 0; i < seg.length - 1; i++) { o = o[seg[i]]; if (!o) return; }
                  var prop = seg[seg.length - 1];
                  var orig = o[prop];
                  if (typeof orig !== 'function') return;
                  entry.orig[path] = orig;
                  o[prop] = function() {
                    var info = {type: label, args: []};
                    for (var i = 0; i < Math.min(arguments.length, 4); i++) info.args.push(safeStr(arguments[i], 80));
                    var r;
                    try { r = orig.apply(this, arguments); }
                    catch(e){ fire(info); throw e; }
                    info.result = safeStr(r, 120);
                    fire(info);
                    return r;
                  };
                  R.saveOriginal(o[prop], orig);
                } catch(e){}
              }
              // CryptoJS：等待库加载（常见全局名都试）
              function tryCryptoJS() {
                var CJ = window.CryptoJS || (window.Crypto && window.Crypto.CryptoJS) || null;
                if (!CJ) return false;
                ['AES','DES','TripleDES','RC4','Rabbit'].forEach(function(c){
                  if (CJ[c]) { wrapMethod(CJ, c + '.encrypt', 'CryptoJS.' + c + '.encrypt'); wrapMethod(CJ, c + '.decrypt', 'CryptoJS.' + c + '.decrypt'); }
                });
                ['MD5','SHA1','SHA256','SHA512','SHA3','RIPEMD160'].forEach(function(h){
                  wrapMethod(CJ, h, 'CryptoJS.' + h);
                });
                if (CJ.HmacSHA256) wrapMethod(CJ, 'HmacSHA256', 'CryptoJS.HmacSHA256');
                if (CJ.HmacMD5) wrapMethod(CJ, 'HmacMD5', 'CryptoJS.HmacMD5');
                if (CJ.PBKDF2) wrapMethod(CJ, 'PBKDF2', 'CryptoJS.PBKDF2');
                if (CJ.enc && CJ.enc.Base64) { wrapMethod(CJ.enc, 'Base64.stringify', 'CryptoJS.enc.Base64.stringify'); wrapMethod(CJ.enc, 'Base64.parse', 'CryptoJS.enc.Base64.parse'); }
                if (CJ.AES) fire({type:'cryptojs.detected', version: safeStr(CJ.version, 20)});
                return true;
              }
              var cjDone = tryCryptoJS();
              if (!cjDone) {
                // 轮询等待异步加载的库（最多 20 次 × 500ms）
                var tries = 0;
                var timer = setInterval(function(){
                  if (tryCryptoJS() || ++tries > 20) clearInterval(timer);
                }, 500);
              }
              // JSEncrypt（RSA）
              function tryJSEncrypt() {
                var JE = window.JSEncrypt;
                if (!JE || !JE.prototype) return false;
                wrapMethod(JE.prototype, 'encrypt', 'JSEncrypt.encrypt');
                wrapMethod(JE.prototype, 'decrypt', 'JSEncrypt.decrypt');
                wrapMethod(JE.prototype, 'setPublicKey', 'JSEncrypt.setPublicKey');
                return true;
              }
              var jeDone = tryJSEncrypt();
              if (!jeDone) {
                var tries2 = 0;
                var timer2 = setInterval(function(){
                  if (tryJSEncrypt() || ++tries2 > 20) clearInterval(timer2);
                }, 500);
              }
              // btoa/atob（Base64 编解码）
              try {
                entry.orig.btoa = window.btoa;
                window.btoa = function(s) {
                  var r = entry.orig.btoa.apply(this, arguments);
                  fire({type:'btoa', input: safeStr(s, 80), result: safeStr(r, 120)});
                  return r;
                };
                window.btoa.__original = entry.orig.btoa;
                entry.orig.atob = window.atob;
                window.atob = function(s) {
                  var r = entry.orig.atob.apply(this, arguments);
                  fire({type:'atob', input: safeStr(s, 80), result: safeStr(r, 120)});
                  return r;
                };
                window.atob.__original = entry.orig.atob;
              } catch(e){}
              // TextEncoder/TextDecoder
              try {
                if (window.TextEncoder) {
                  entry.orig.encode = TextEncoder.prototype.encode;
                  TextEncoder.prototype.encode = function(s) {
                    var r = entry.orig.encode.apply(this, arguments);
                    fire({type:'TextEncoder.encode', input: safeStr(s, 80), bytes: r.length});
                    return r;
                  };
                  TextEncoder.prototype.encode.__original = entry.orig.encode;
                }
                if (window.TextDecoder) {
                  entry.orig.decode = TextDecoder.prototype.decode;
                  TextDecoder.prototype.decode = function(buf) {
                    var r = entry.orig.decode.apply(this, arguments);
                    fire({type:'TextDecoder.decode', result: safeStr(r, 120), bytes: (buf && buf.byteLength) || 0});
                    return r;
                  };
                  TextDecoder.prototype.decode.__original = entry.orig.decode;
                }
              } catch(e){}
              return id;
            });
          };

          // 设备指纹 API Hook：canvas/webgl/audio 指纹采集观测
          R.hookFingerprint = function(callback) {
            var key = 'fingerprint';
            return install(key, callback, function(){
              var id = R.register(key, {type:'fingerprint', key:key, orig:{}});
              var entry = R.hooks[id];
              // Canvas toDataURL/toBlob（指纹最常见来源）
              try {
                entry.orig.tDU = HTMLCanvasElement.prototype.toDataURL;
                HTMLCanvasElement.prototype.toDataURL = function() {
                  var data = entry.orig.tDU.apply(this, arguments);
                  R.fire(id, {type:'canvas.toDataURL', length: data.length, prefix: data.substring(0, 32)});
                  return data;
                };
              } catch(e){}
              // WebGL getParameter / getExtension（WebGL 指纹）
              try {
                var _gp = WebGLRenderingContext.prototype.getParameter;
                entry.orig.getParm = _gp;
                WebGLRenderingContext.prototype.getParameter = function(p) {
                  var v = _gp.apply(this, arguments);
                  if (p === 37445 || p === 37446) R.fire(id, {type:'webgl.getParameter', param: p, value: String(v)});
                  return v;
                };
              } catch(e){}
              // AudioContext（音频指纹）
              try {
                var _gcd = AudioContext.prototype.getChannelData || (window.OfflineAudioContext && window.OfflineAudioContext.prototype.getChannelData);
                if (_gcd) {
                  entry.orig.gcd = _gcd;
                  var proto = AudioContext.prototype.getChannelData ? AudioContext.prototype : window.OfflineAudioContext.prototype;
                  proto.getChannelData = function(ch) {
                    R.fire(id, {type:'audio.getChannelData', channel: ch});
                    return _gcd.apply(this, arguments);
                  };
                }
              } catch(e){}
              return id;
            });
          };

          // Notification API（某些风控借 Notification.permission 做检测）
          R.hookNotification = function(callback) {
            var key = 'notification';
            return install(key, callback, function(){
              if (!window.Notification) return null;
              var _req = Notification.requestPermission;
              var id = R.register(key, {type:'notification', key:key, requestPermission:_req});
              Notification.requestPermission = function() {
                R.fire(id, {type:'requestPermission', permission: Notification.permission});
                return _req.apply(this, arguments);
              };
              return id;
            });
          };

          R.removeHook = function(id) { return R.restore(id); };
          R.listHooks = function() {
            return Object.keys(R.hooks).map(function(id){
              var h = R.hooks[id];
              return {id:id, type:h.type, key:h.key, callbacks:h.cbs.length, target:(h.prop || h.selector || '')};
            });
          };
          R.resetHooks = function() {
            Object.keys(R.hooks).slice().forEach(function(id){ R.restore(id); });
            return true;
          };

          // 别名挂载到 __MCP__（兼容既有调用方式；bridge 未就绪时仅用 __WRMCP_HOOK__）
          if (window.__MCP__) {
            ['hookFunction','hookMethod','hookProperty','hookEvent','hookFetch','hookXHR',
             'hookWebSocket','hookStorage','hookCookie','hookTimer','hookConsole','hookCrypto',
             'hookHistory','hookLocation','hookEval','removeHook','listHooks','resetHooks'
            ].forEach(function(m){ try { window.__MCP__[m] = R[m]; } catch(e){} });
          }
        })();
    """.trimIndent()

    /**
     * 反调试对抗（Anti-Anti-Debug）脚本 v2（报告 §6/§8：真实几何指纹一致性 + VirtualClock）。
     *
     * v2 相对 v1 初版重构两处系统性缺陷：
     *
     * A. VirtualClock 统一虚拟时间源（v1 缺陷：Date.now 与 performance.now 各自独立
     *    量化，基准不一致——跨 API 一致性检测（Date.now() - timeOrigin - performance.now()
     *    的漂移）可识别伪造时间）：
     *    - 单一虚拟时间线：真实时间映射为 100ms 桶粒度，时间仍流逝；
     *    - Date.now() / new Date() / performance.now() / performance.timeOrigin
     *      全部从同一时间线取值，跨 API 差值恒 <= 1 个量子；
     *    - 时间夹层检测（t1~debugger~t2 差值 < 100ms）失效，但长任务计时不受影响。
     *
     * B. 真实几何指纹一致性引擎（v1 缺陷：inner 1366x790 / outer 1400x820 直接定义，
     *    与真实 screen（手机竖屏 1080x2400 等）交叉对比时 screen.width < window.outerWidth
     *    是几何不可能——尺寸自洞性检测一查一个准）：
     *    - 桌面形态几何表（1920x1080 屏幕 / avail 1920x1040 / outer 1552x840 /
     *      inner 1366x738 / dpr 1 / 24 位色深 / 窗口位置 12,12）全部自洽：
     *      screen >= avail >= outer >= inner，窗口位置 + outer 尺寸不越出 avail 区域；
     *    - screen / window / devicePixelRatio / colorDepth 七组取值联动，任一 API
     *      读取均返回同一套几何。
     *
     * （报告 §20/§21，P0-6）重大修正——从"硬编码桌面几何"升级为"真实派生一致性引擎"：
     *   v1/v2 硬塞桌面值（screen 1920x1080 / inner 1366x738 / dpr 1）在 Android WebView 里
     *   与真实 UA(mobile)/touch=true/WebGL(mobile GPU) 交叉时形成"桌面几何 + 移动信号"的
     *   撕裂指纹，跨信号一致性检测一键识别。现改为以 WebView 上报的【真实】物理尺寸与 DPR
     *   为唯一基座，派生 CSS 口径 screen/avail/outer/inner/dpr/orientation 全部取值并保持
     *   相互可推导、与 UA/touch/GPU 同一现实——几何自洞性与跨信号检测均不可识别。
     *
     * v1 基础能力（本项目自研实现）：
     *   0. eval / Function / Function.prototype.constructor 字符串中的 debugger
     *      关键字全局剥离；
     *   1. console 对象引用冻结；
     *   2. Function.prototype.toString 检测 Hook 包装 -> toString 伪装层；
     *   3. setInterval(()=>{debugger}, N) 死循环卡断点 -> 定时器回调含 debugger 替换为 noop。
     */
    fun stealthScript(): String = """
        (function(){
          if (window.__WRMCP_STEALTH__) return;
          var S = { nativeCount: 0, debuggerFiltered: 0, version: 2 };
          // （报告 P0-6）：幂等标记改为不可枚举属性——页面 `for..in window` /
          // Object.getOwnPropertyNames 探测不出 WRMCP 集合，但仍可作幂等守卫。
          try {
            Object.defineProperty(window, '__WRMCP_STEALTH__', { value: S, writable: true, configurable: true, enumerable: false });
          } catch(e0){ window.__WRMCP_STEALTH__ = S; }

          // 0.toString 伪装注册器（必须先就位，后续包装函数才能登记为 native 形态）
          try {
            var _ts = Function.prototype.toString;
            var registry = new WeakMap();
            Function.prototype.toString = function() {
              if (registry.has(this)) return registry.get(this);
              return _ts.call(this);
            };
            registry.set(Function.prototype.toString, 'function toString() { [native code] }');
            S.registerNative = function(fn, name) {
              registry.set(fn, 'function ' + (name || fn.name || '') + '() { [native code] }');
              S.nativeCount++;
            };
          } catch(e){}

          // ---- 0. debugger 关键字剥离：eval / Function / constructor 三通道统一收敛 ----
          try {
            var _sanitizeCode = function(s) { return String(s).replace(/\bdebugger\b/g, ''); };
            var _sanitizeArgs = function(args) {
              var touched = false;
              for (var i = 0; i < args.length; i++) {
                if (typeof args[i] === 'string' && args[i].indexOf('debugger') !== -1) {
                  args[i] = _sanitizeCode(args[i]);
                  touched = true;
                }
              }
              return touched;
            };
            // eval 通道
            var _rawEval = window.eval;
            window.eval = function() {
              if (arguments.length > 0 && _sanitizeArgs(arguments)) S.debuggerFiltered++;
              return _rawEval.apply(this, arguments);
            };
            if (S.registerNative) S.registerNative(window.eval, 'eval');
            // Function 构造器通道（window.Function 与 Function.prototype.constructor 同源收敛）
            var _rawFunction = window.Function;
            var _FunctionGuard = function() {
              if (_sanitizeArgs(arguments)) S.debuggerFiltered++;
              return _rawFunction.apply(this, arguments);
            };
            _FunctionGuard.prototype = _rawFunction.prototype;
            window.Function = _FunctionGuard;
            try {
              Object.defineProperty(_rawFunction.prototype, 'constructor', {
                value: _FunctionGuard, writable: true, configurable: true
              });
            } catch(e2){}
            if (S.registerNative) S.registerNative(window.Function, 'Function');
          } catch(e){}

          // ---- 1. [真实几何指纹一致性引擎（P0-6）] ----
          // v1/v2 硬编码"桌面几何"（screen 1920x1080 / inner 1366x738 / dpr 1）在 Android
          // WebView 里与真实 UA(mobile)/touch=true/WebGL(mobile GPU) 交叉时形成"桌面几何 +
          // 移动信号"的撕裂指纹，一键即露（ChatGPT 报告 §20）。 改为真·一致性引擎
          // （§21）：以 WebView 上报的【真实】物理尺寸与 DPR 为唯一基座，派生 CSS 口径的
          // screen/avail/outer/inner/dpr/orientation 全部取值，相互可推导、与设备信号同一
          // 现实——几何自洞性与跨信号一致性检测皆不可识别。
          try {
            // ONE（修复"页面显示不全"）的几何基座必须用【真实 viewport】。
            // 旧实现读 window.screen.width/dpr 倒推 CSS 宽——但 Android WebView 的
            // screen.width 已是 CSS 像素，再 ÷dpr 会把 innerWidth 钉成 ~320 的错误窄值
            //（再配 Math.max 夹逼），innerHeight 则被钉成整屏高。响应式页面按错误的
            // 视口做布局，内容被裁剪/重叠 = 表现为"有些页面显示不全"。
            // 修复：以真实 innerWidth/innerHeight 为唯一基座派生 ALL 几何，且【不再覆盖】
            // window.innerWidth/innerHeight/outerWidth/outerHeight——布局必须读真实视口，
            // 只对 screen.* / devicePixelRatio / orientation 做自洽性固定。
            var _realIW = window.innerWidth;
            var _realIH = window.innerHeight;
            var _dpr = window.devicePixelRatio || 1;
            var _physW = (window.screen && window.screen.width) || 0;
            var _physH = (window.screen && window.screen.height) || 0;
            var _baseW = _realIW || Math.max(320, Math.round(_physW / _dpr));
            var _baseH = _realIH || Math.max(480, Math.round(_physH / _dpr));
            var _cssW = Math.max(320, _baseW);
            var _cssH = Math.max(480, _baseH);
            var _availH = Math.max(1, _cssH); // 布局可见高即真实 innerHeight，不再扣系统栏差异
            var GEO = {
              screenW: _cssW, screenH: _cssH,
              availW: _cssW, availH: _availH, availL: 0, availT: 0,
              outerW: _cssW, outerH: _cssH,
              dpr: _dpr, depth: 24,
              winX: 0, winY: 0
            };
            var _fix = function(obj, name, val) {
              try {
                var d = Object.getOwnPropertyDescriptor(obj, name);
                if (!d || d.configurable) {
                  Object.defineProperty(obj, name, {
                    configurable: true,
                    enumerable: d ? d.enumerable : true,
                    get: function(){ return val; },
                    set: function(){ /* 静默吸收写操作 */ }
                  });
                }
              } catch(e){}
            };
            // screen 几何（自洽派生自真实 viewport）
            if (window.screen) {
              _fix(window.screen, 'width', GEO.screenW);
              _fix(window.screen, 'height', GEO.screenH);
              _fix(window.screen, 'availWidth', GEO.availW);
              _fix(window.screen, 'availHeight', GEO.availH);
              _fix(window.screen, 'availLeft', GEO.availL);
              _fix(window.screen, 'availTop', GEO.availT);
              _fix(window.screen, 'colorDepth', GEO.depth);
              _fix(window.screen, 'pixelDepth', GEO.depth);
              // orientation 与真实形态一致（竖屏）
              try {
                if (window.screen.orientation && window.screen.orientation.type !== undefined) {
                  _fix(window.screen.orientation, 'type', 'portrait-primary');
                  _fix(window.screen.orientation, 'angle', 0);
                }
              } catch(e2){}
            }
            // 仅对 screenX/screenY/devicePixelRatio 做固定；inner/outer 保持真实视口，
            // 否则响应式/弹性布局页面会按错误的 innerWidth 渲染导致内容显示不全。
            _fix(window, 'screenX', GEO.winX);
            _fix(window, 'screenY', GEO.winY);
            _fix(window, 'devicePixelRatio', GEO.dpr);
            // GEO 仅存于本 IIFE 作用域，不落全局，避免页面枚举出剩余指纹面。
          } catch(e){}

          // ---- 2. [v2: VirtualClock 统一虚拟时间源] ----
          // 单一时间线：真实时间 → 100ms 桶量化虚拟时间。Date.now / new Date /
          // performance.now / performance.timeOrigin 全部由它派生：
          //   Date.now() ≈ performance.timeOrigin + performance.now()（差 <= 1 量子）
          // v1 的两套独立基准不再存在，跨 API 一致性检测无法识别伪造。
          // 真实定时器由事件循环驱动，不受该 shim 影响；长任务计时粒度粗化，
          // 子 100ms 的时间夹层检测（debugger 断点计时差）失效。
          try {
            var _DateOrig = window.Date;
            var _realNow = _DateOrig.now.bind(_DateOrig);
            var _VBASE = _realNow();
            var _Q = 100; // 量子（ms）
            function _vnow() {
              return _VBASE + Math.floor((_realNow() - _VBASE) / _Q) * _Q;
            }
            // performance 基准（与 Date 基准在同一时刻采样，保持同源）
            var _pnowOrig = (window.performance && typeof window.performance.now === 'function')
              ? window.performance.now.bind(window.performance) : null;
            var _PBASE = _pnowOrig ? _pnowOrig() : 0;
            function _vperf() {
              if (!_pnowOrig) return 0;
              // （报告 P0-6）：由 Date 虚拟线精确派生，而非二次独立量化。
              // 旧实现里 Date 走 _VBASE 量化、performance 走自身 _PBASE 量化，两条基线不共享
              // 时间原点的对齐——Date.now()-timeOrigin-performance.now() 恒不为 0 而是 O(_PBASE)
              // 的恒定偏移，被跨 API 一致性检测一查一个准。现在二者同源：
              //   Date.now() - performance.timeOrigin - performance.now() === 0（精确，非"≤1量子"）
              return _vnow() - (_VBASE - _PBASE);
            }
            // Date.now / Date 构造器
            _DateOrig.now = function(){ return _vnow(); };
            try {
              var _DW = function Date(){
                if (!(this instanceof _DW)) return new _DW().toString();
                var d;
                if (arguments.length === 0) {
                  d = new _DateOrig(_vnow());
                } else if (arguments.length === 1) {
                  d = new _DateOrig(arguments[0]);
                } else {
                  d = new (Function.prototype.bind.apply(_DateOrig, [null].concat(Array.prototype.slice.call(arguments))))();
                }
                return d; // 构造器返回对象：new Date() 实际返回真实 Date 实例
              };
              _DW.prototype = _DateOrig.prototype;
              _DW.parse = _DateOrig.parse;
              _DW.UTC = _DateOrig.UTC;
              _DW.now = function(){ return _vnow(); };
              window.Date = _DW;
              if (S.registerNative) S.registerNative(_DW, 'Date');
            } catch(e2){}
            // performance.now / timeOrigin
            if (_pnowOrig) {
              try {
                Object.defineProperty(window.performance, 'now', {
                  value: _vperf, writable: true, configurable: true
                });
                if (window.performance.timeOrigin !== undefined) {
                  Object.defineProperty(window.performance, 'timeOrigin', {
                    get: function(){ return _VBASE - _PBASE; },
                    configurable: true
                  });
                }
              } catch(e3){}
            }
            // （报告 P0-6）：不再暴露 window.__WRMCP_VCLOCK__——和时间轴同步的
            // 跨 API 一致性已通过单一虚拟线保证，不再需要全局暴露供调试或外部读取。
            // 幂等守卫 __WRMCP_STEALTH__ 已不可枚举，__WRMCP_VCLOCK__ 同样不应暴露。
          } catch(e){}

          // ---- 3. [console 引用加固] 冻结 console 原引用，防止页面整体替换 ----
          try {
            var _consoleRef = window.console;
            if (_consoleRef && !_consoleRef.__WRMCP_FROZEN) {
              Object.defineProperty(_consoleRef, '__WRMCP_FROZEN', { value: true });
              S.registerNative && S.registerNative(_consoleRef.log, 'log');
            }
          } catch(e){}

          // 2.debugger 定时器过滤：回调源码含 debugger 语句则替换为 noop
          try {
            var _st = window.setTimeout, _si = window.setInterval;
            function patched(orig) {
              return function(fn) {
                if (typeof fn === 'function') {
                  try {
                    var src = Function.prototype.toString.call(fn);
                    if (/\bdebugger\b/.test(src)) {
                      S.debuggerFiltered++;
                      return orig.call(window, function(){}, arguments[1]);
                    }
                  } catch(e){}
                } else if (typeof fn === 'string' && /\bdebugger\b/.test(fn)) {
                  S.debuggerFiltered++;
                  return orig.call(window, '', arguments[1]);
                }
                return orig.apply(window, arguments);
              };
            }
            window.setTimeout = patched(_st);
            window.setInterval = patched(_si);
            if (S.registerNative) { S.registerNative(window.setTimeout, 'setTimeout'); S.registerNative(window.setInterval, 'setInterval'); }
          } catch(e){}

          // 3.现存 Hook 包装函数注册为 native（对已替换的 fetch/XHR 等生效）
          try {
            var R = window.__WRMCP_HOOK__;
            if (R && S.registerNative) {
              Object.keys(R.hooks || {}).forEach(function(id){
                var h = R.hooks[id];
                [h.prop, h.wrapped].forEach(function(f){
                  if (typeof f === 'function') S.registerNative(f);
                });
              });
            }
          } catch(e){}
        })();
    """.trimIndent()

    /**
     * document_start 早期反调试对抗脚本。
     *
     * 在页面自身任何脚本（含内联 <script>）运行之前注入完整 stealth 对抗层，
     * 使 parse 期/非常早期的 `debugger` 语句、eval('debugger')、无限 debugger
     * 死循环在触发前即被中和。stealthScript 幂等（由 __WRMCP_STEALTH__ 守卫），
     * 与后续 browser.set_stealth 不冲突。
     */
    fun antiDebugDocumentStartScript(): String = stealthScript()

    /**
     * 动态代码统一捕获与拦截脚本（报告 §10：eval/Function/Blob/Worker）。
     *
     * JSVMP / 动态打包站点的核心逻辑几乎全部经动态通道执行：
     *   eval(code) / new Function(body) / Blob→URL→Worker / importScripts /
     *   setTimeout('code') / constructor('debugger')
     * 静态抓包 + scriptParsed 只能看到入口壳，本脚本把全部动态通道统一收口到
     * globalThis.__WRMCP_DYN__，供 MCP 工具（script_intercept.* / dynamic.*）查询与拦截。
     *
     * 捕获语义：
     * - 每条记录 {kind, ts, size, code, url, stack, linked}，环形缓冲（默认 300 条）；
     * - Blob 与 URL.createObjectURL 关联：Worker(blobURL) 时把 blob 内容链接给 worker 记录
     *   （否则只有 blob:xxx 伪 URL，拿不到 worker 源码）；
     * - 堆栈捕获（new Error().stack 截断 1200 字符）：定位动态代码的发起位置。
     *
     * 拦截语义（规则注册，JS 侧同步执行，无需往返宿主）：
     * - __WRMCP_DYN__.addRule({kind, match, action, replacement})：
     *   kind ∈ eval|Function|Blob|Worker|timer|all；match 为子串或 /regex/；
     *   action ∈ log（默认，仅记录）| block（丢弃执行，返回 undefined）| replace（替换代码）；
     * - 规则在代码执行前同步求值（eval 是同步调用，无法等待宿主决策——报告 §10）。
     */
    fun dynamicCodeScript(capacity: Int = 300, codeCap: Int = 100_000): String = """
        (function(){
          if (globalThis.__WRMCP_DYN__) return;
          var D = {
            records: [], n: 0, cap: $capacity, codeCap: $codeCap,
            rules: [], blocked: 0, replaced: 0,
            blobMap: new Map(),
          };
          globalThis.__WRMCP_DYN__ = D;

          function stackOf() {
            try { return String(new Error().stack || '').split('\n').slice(2, 8).join('\n').substring(0, 1200); }
            catch(e){ return ''; }
          }
          function push(kind, code, url, linked) {
            D.n++;
            var rec = {
              i: D.n, kind: kind, ts: Date.now(),
              size: code ? String(code).length : 0,
              code: code ? String(code).substring(0, D.codeCap) : '',
              url: url || '', stack: stackOf(), linked: linked || ''
            };
            D.records.push(rec);
            if (D.records.length > D.cap) D.records.shift();
            return rec;
          }
          // 规则求值：返回 undefined（放行）/ null（block）/ string（replace）
          function applyRules(kind, code) {
            var s = String(code);
            for (var i = 0; i < D.rules.length; i++) {
              var r = D.rules[i];
              if (r.kind !== 'all' && r.kind !== kind) continue;
              try {
                var hit = r.regex ? r.regex.test(s) : s.indexOf(r.match) !== -1;
                if (!hit) continue;
                if (r.action === 'block') { D.blocked++; return null; }
                if (r.action === 'replace' && typeof r.replacement === 'string') { D.replaced++; return r.replacement; }
              } catch(e){}
            }
            return undefined;
          }
          D.addRule = function(rule) {
            var r = {
              kind: rule.kind || 'all',
              match: rule.match || '',
              action: rule.action || 'log',
              replacement: rule.replacement,
              regex: null
            };
            if (typeof rule.match === 'string' && rule.match.length > 1 && rule.match[0] === '/') {
              try {
                var last = rule.match.lastIndexOf('/');
                r.regex = new RegExp(rule.match.substring(1, last), rule.match.substring(last + 1));
              } catch(e){}
            }
            D.rules.push(r);
            return D.rules.length;
          };
          D.clearRules = function(){ D.rules = []; };
          D.clear = function(){ D.records = []; };

          // ---- eval / Function / constructor ----
          try {
            var _eval = window.eval;
            window.eval = function(code) {
              var verdict = applyRules('eval', code);
              if (verdict === null) { push('eval', code, '', '(blocked)'); return undefined; }
              var finalCode = (verdict !== undefined) ? verdict : code;
              if (finalCode !== code) push('eval', code, '', '(replaced)');
              else push('eval', finalCode);
              return _eval.call(window, finalCode);
            };
          } catch(e){}
          try {
            var _Function = window.Function;
            var _FW = function() {
              var args = Array.prototype.slice.call(arguments);
              var body = args.length ? String(args[args.length - 1]) : '';
              var verdict = applyRules('Function', body);
              if (verdict === null) { push('Function', body, '', '(blocked)'); return function(){}; }
              if (verdict !== undefined) args[args.length - 1] = verdict;
              push('Function', args.join(',').substring(0, 400) + ' -> ' + body);
              return _Function.apply(this, args);
            };
            _FW.prototype = _Function.prototype;
            window.Function = _FW;
            try {
              Object.defineProperty(_Function.prototype, 'constructor', { value: _FW, writable: true, configurable: true });
            } catch(e2){}
          } catch(e){}

          // ---- Blob（text/javascript worker 源码最常见载体） ----
          try {
            var _Blob = window.Blob;
            if (_Blob) {
              window.Blob = function(parts, opts) {
                try {
                  var type = (opts && opts.type) || '';
                  var text = '';
                  if (parts && parts.length && /text|javascript|application/.test(type)) {
                    for (var i = 0; i < parts.length; i++) {
                      var p = parts[i];
                      if (typeof p === 'string') text += p;
                      else if (p instanceof ArrayBuffer || ArrayBuffer.isView(p)) {
                        try { text += String.fromCharCode.apply(null, new Uint8Array(p.buffer || p)); } catch(e){}
                      }
                    }
                    var verdict = applyRules('Blob', text);
                    if (verdict === null) { push('Blob', text, type, '(blocked)'); return new _Blob([''], opts); }
                    if (verdict !== undefined) { parts = [verdict]; text = verdict; push('Blob', text, type, '(replaced)'); }
                    else push('Blob', text, type);
                  }
                  var blob = new _Blob(parts, opts);
                  if (text) D.blobMap.set(blob, text.substring(0, D.codeCap));
                  return blob;
                } catch(e){ return new _Blob(parts, opts); }
              };
              window.Blob.prototype = _Blob.prototype;
            }
          } catch(e){}

          // ---- URL.createObjectURL：blob → url 映射 ----
          try {
            var _cURL = window.URL && window.URL.createObjectURL;
            if (_cURL) {
              window.URL.createObjectURL = function(blob) {
                var u = _cURL.call(window.URL, blob);
                try { if (blob && D.blobMap.has(blob)) D.blobMap.set(u, D.blobMap.get(blob)); } catch(e){}
                return u;
              };
            }
          } catch(e){}

          // ---- Worker / SharedWorker ----
          try {
            var _W = window.Worker;
            if (_W) {
              var _WW = function(url, opts) {
                var u = String(url);
                var linked = '';
                try { if (D.blobMap.has(u)) linked = D.blobMap.get(u).substring(0, D.codeCap); } catch(e){}
                var verdict = applyRules('Worker', linked || u);
                if (verdict === null) {
                  push('Worker', linked, u, '(blocked)');
                  throw new Error('Worker blocked by WRMCP rule');
                }
                push('Worker', linked, u, linked ? 'blob-source' : '');
                return new _W(url, opts);
              };
              _WW.prototype = _W.prototype;
              window.Worker = _WW;
            }
          } catch(e){}

          // ---- 定时器字符串代码（setTimeout('code') 老 JS 常用） ----
          try {
            var _st = window.setTimeout, _si = window.setInterval;
            window.setTimeout = function(fn) {
              if (typeof fn === 'string') {
                var verdict = applyRules('timer', fn);
                if (verdict === null) { push('timer', fn, 'setTimeout', '(blocked)'); return _st.call(window, function(){}, arguments[1]); }
                push('timer', fn, 'setTimeout');
                if (verdict !== undefined) fn = verdict;
              }
              return _st.apply(window, arguments.length ? [fn].concat(Array.prototype.slice.call(arguments, 1)) : arguments);
            };
            window.setInterval = function(fn) {
              if (typeof fn === 'string') {
                var verdict = applyRules('timer', fn);
                if (verdict === null) { push('timer', fn, 'setInterval', '(blocked)'); return _si.call(window, function(){}, arguments[1]); }
                push('timer', fn, 'setInterval');
                if (verdict !== undefined) fn = verdict;
              }
              return _si.apply(window, arguments.length ? [fn].concat(Array.prototype.slice.call(arguments, 1)) : arguments);
            };
          } catch(e){}

          // ---- importScripts（本脚本注入 Worker 全局时生效） ----
          try {
            if (typeof importScripts === 'function' && typeof self !== 'undefined' && self !== window) {
              var _imp = importScripts;
              self.importScripts = function() {
                for (var i = 0; i < arguments.length; i++) push('importScripts', '', String(arguments[i]));
                return _imp.apply(self, arguments);
              };
            }
          } catch(e){}

          // ---- 供宿主取回统计 ----
          D.stats = function() {
            return { total: D.n, captured: D.records.length, blocked: D.blocked,
                     replaced: D.replaced, rules: D.rules.length };
          };
        })();
    """.trimIndent()

    /**
     * document-start 单次合并注入脚本（报告 §30：合并注入）。
     *
     * 把 earlyHook（网络/框架 Hook）+ 动态代码捕获 + stealth 反调试对抗层
     * 合并为单个脚本、单次 addDocumentStartJavaScript 调用注入：
     * - 减少 WebView 侧注入通道数量（两次注入存在时序窗口：第一条执行完到第二条
     *   注入前，页面早期脚本可能已运行）；
     * - 执行顺序保证：Hook 框架先就位（网络零漏抓）→ 动态代码捕获叠加
     *   （eval/Function 原始引用未被页面保存）→ stealth 对抗层最后（几何/时间
     *   伪装在 Hook 之后不影响 Hook 的 toString 注册）。
     * - 各段均幂等（__WRMCP_HOOK__ / __WRMCP_DYN__ / __WRMCP_STEALTH__ 守卫）。
     */
    fun documentStartScript(): String =
        earlyHookScript() + "\n;" + dynamicCodeScript() + "\n;" + stealthScript()

    /**
     * VMP 采样断点载体 v2：globalThis.__WRMCP_VMP_TRACE__
     *
     * v2 修复（评审缺陷 2/3）：
     * - 环形缓冲：超过 CAP 后 shift() 丢最旧样本，不再无界增长（防 OOM/拖死页面）
     * - 采样率 RATE：每 N 次执行才记录 1 次，配合高频 dispatch 降开销
     * - 独立计数器 N__：记录真实触发总数（含被采样率跳过的），统计不失真
     */
    fun vmpTraceInitScript(capacity: Int = 50_000): String = """
        (function(){
          globalThis.__WRMCP_VMP_TRACE__ = [];
          globalThis.__WRMCP_VMP_N__ = 0;
          globalThis.__WRMCP_VMP_CAP__ = $capacity;
          globalThis.__WRMCP_VMP_RATE__ = 1;
          globalThis.__WRMCP_VMP_CLEAR__ = function(){
            globalThis.__WRMCP_VMP_TRACE__ = [];
            globalThis.__WRMCP_VMP_N__ = 0;
          };
        })();
    """.trimIndent()

    /**
     * document_start 早期注入脚本：Hook 框架 + 立即安装网络/动态代码观测。
     *
     * 时机关键：页面自身脚本（如 `const old = window.fetch` 的保存引用、
     * webpack 模块初始化）运行之前完成替换，才能保证零漏抓。
     * 通过 WebViewCompat.addDocumentStartJavaScript 注入（WebView 105+，
     * 低版本由 androidx 自动降级到 onPageStarted）。
     */
    fun earlyHookScript(): String = hookFrameworkScript() + """
        ;
        (function(){
          var R = window.__WRMCP_HOOK__;
          if (!R || R.__earlyInstalled) return;
          R.__earlyInstalled = true;
          function log(tag, info) {
            try {
              if (window.__MCP__ && window.__MCP__.log) {
                window.__MCP__.log('[early:' + tag + '] ' + JSON.stringify(info).substring(0, 800));
              }
            } catch(e){}
          }
          try { R.hookFetch(function(i){ log('fetch', i); }); } catch(e){}
          try { R.hookXHR(function(i){ log('xhr', i); }); } catch(e){}
          try { R.hookWebSocket(function(i){ log('ws', i); }); } catch(e){}
          try { R.hookEval(function(i){ log('eval', i); }); } catch(e){}
          try { R.hookWasm(function(i){ log('wasm', i); }); } catch(e){}
        })();
    """.trimIndent()

    // ==================== 断点增强脚本 ====================

    /**
     * DOM 断点脚本（ 新增）。
     *
     * 对齐 Chrome DevTools 的三种 DOM breakpoint：
     * - subtree-modified：子树结构变化（增删节点）
     * - attribute-modified：属性被修改
     * - node-removed：节点被移除
     *
     * 实现基于 MutationObserver（无需 CDP），命中时：
     * 1. 记录变更详情到 __WRMCP_DOM_BP_HITS__
     * 2. 若 [pause] = true 则执行 debugger;（CDP attach 时形成真实暂停，
     *    未 attach 时静默跳过——debugger 语句在无调试器时是 no-op）
     */
    fun domBreakpointScript(selector: String, kind: String, pause: Boolean): String = """
        (function(){
          globalThis.__WRMCP_DOM_BP_HITS__ = globalThis.__WRMCP_DOM_BP_HITS__ || [];
          var target = document.querySelector(${quote(selector)});
          if (!target) return JSON.stringify({ok: false, error: 'SELECTOR_NOT_FOUND'});
          var opts = {subtree: true, childList: ${kind != "attribute"}, attributes: ${kind == "attribute" || kind == "all"}, attributeOldValue: true};
          var bpId = 'dombp_' + Date.now();
          var mo = new MutationObserver(function(muts){
            muts.forEach(function(m){
              var hitKind = null;
              if ((m.type === 'childList') && (m.addedNodes.length || m.removedNodes.length) &&
                  (${quote(kind)} === 'all' || ${quote(kind)} === 'subtree' ||
                   (${quote(kind)} === 'removed' && m.removedNodes.length > 0))) {
                hitKind = 'childList';
              } else if (m.type === 'attributes' && (${quote(kind)} === 'all' || ${quote(kind)} === 'attribute')) {
                hitKind = 'attribute';
              }
              if (!hitKind) return;
              var hit = {
                id: bpId, kind: hitKind,
                target: (function(){ try { return m.target.tagName + (m.target.id ? '#' + m.target.id : '') + (m.target.className && typeof m.target.className === 'string' ? '.' + m.target.className.split(' ')[0] : ''); } catch(e){ return '?'; } })(),
                attr: m.attributeName || '',
                oldValue: (m.oldValue || '').substring(0, 100),
                added: m.addedNodes.length, removed: m.removedNodes.length,
                ts: Date.now()
              };
              try { hit.stack = (new Error().stack || '').split('\n').slice(1, 6).join(' <- '); } catch(e){}
              if (globalThis.__WRMCP_DOM_BP_HITS__.length < 500) globalThis.__WRMCP_DOM_BP_HITS__.push(hit);
              if (${if (pause) "true" else "false"}) { debugger; }
            });
          });
          mo.observe(target, opts);
          globalThis.__WRMCP_DOM_BPS__ = globalThis.__WRMCP_DOM_BPS__ || {};
          globalThis.__WRMCP_DOM_BPS__[bpId] = {observer: mo, selector: ${quote(selector)}, kind: ${quote(kind)}};
          return JSON.stringify({ok: true, id: bpId, tagName: target.tagName});
        })()
    """.trimIndent()

    /** 移除 DOM 断点（id 为空则全部移除） */
    fun domBreakpointRemoveScript(id: String): String = """
        (function(){
          var B = globalThis.__WRMCP_DOM_BPS__;
          if (!B) return JSON.stringify({removed: 0});
          var n = 0;
          Object.keys(B).forEach(function(k){
            if (${if (id.isBlank()) "true" else "k === " + quote(id)}) {
              try { B[k].observer.disconnect(); } catch(e){}
              delete B[k]; n++;
            }
          });
          return JSON.stringify({removed: n});
        })()
    """.trimIndent()

    /**
     * 事件监听断点脚本（ 新增）。
     *
     * 对齐 Chrome DevTools Event Listener Breakpoints：指定事件类型（如
     * click/keydown/submit/mousemove）在监听器执行前暂停。
     * 实现：document 捕获阶段提前触发 + debugger（CDP attach 时真实暂停）。
     * 特殊类别：control(按钮类)/all(常见交互事件全集)。
     */
    fun eventBreakpointScript(eventType: String, pause: Boolean, captureStack: Boolean): String {
        val evList = when (eventType) {
            "control" -> "['click','submit','change','input','focus','blur','reset']"
            "all" -> "['click','dblclick','mousedown','mouseup','mousemove','keydown','keyup','keypress','submit','change','input','focus','blur','scroll','resize','touchstart','touchend','load','error']"
            else -> "[" + quote(eventType) + "]"
        }
        return """
        (function(){
          globalThis.__WRMCP_EVT_BP_HITS__ = globalThis.__WRMCP_EVT_BP_HITS__ || [];
          var evts = $evList;
          var bpId = 'evtbp_' + Date.now();
          evts.forEach(function(ev){
            document.addEventListener(ev, function(e){
              var hit = {
                id: bpId, event: ev,
                target: (function(){ try { var t = e.target; return t.tagName + (t.id ? '#' + t.id : '') + (t.className && typeof t.className === 'string' && t.className ? '.' + t.className.split(' ')[0] : ''); } catch(err){ return '?'; } })(),
                detail: ev === 'keydown' ? ('key=' + (e.key || '')) : '',
                ts: Date.now()
              };
              ${if (captureStack) "try { hit.stack = (new Error().stack || '').split('\\n').slice(1, 6).join(' <- '); } catch(err){}" else ""}
              if (globalThis.__WRMCP_EVT_BP_HITS__.length < 500) globalThis.__WRMCP_EVT_BP_HITS__.push(hit);
              if (${if (pause) "true" else "false"}) { debugger; }
            }, true); // 捕获阶段：先于页面监听器
          });
          globalThis.__WRMCP_EVT_BPS__ = globalThis.__WRMCP_EVT_BPS__ || {};
          globalThis.__WRMCP_EVT_BPS__[bpId] = {events: evts};
          return JSON.stringify({ok: true, id: bpId, events: evts});
        })()
        """.trimIndent()
    }

    /** Promise/异步断点脚本：捕获 rejection + 长任务（>50ms 的微任务链） */
    fun promiseBreakpointScript(pause: Boolean): String = """
        (function(){
          globalThis.__WRMCP_PROM_BP_HITS__ = globalThis.__WRMCP_PROM_BP_HITS__ || [];
          window.addEventListener('unhandledrejection', function(e){
            var hit = {
              kind: 'unhandledrejection',
              reason: (function(){ try { return typeof e.reason === 'object' ? JSON.stringify(e.reason).substring(0, 200) : String(e.reason); } catch(err){ return String(e.reason); } })(),
              ts: Date.now()
            };
            try { hit.stack = (e.reason && e.reason.stack) ? String(e.reason.stack).split('\n').slice(0, 6).join(' <- ') : (new Error().stack || '').split('\n').slice(1, 6).join(' <- '); } catch(err){}
            if (globalThis.__WRMCP_PROM_BP_HITS__.length < 300) globalThis.__WRMCP_PROM_BP_HITS__.push(hit);
            if (${if (pause) "true" else "false"}) { debugger; }
          });
          // Promise 构造器包装：then 链异常不丢失
          try {
            var _P = window.Promise;
            var OrigPromise = _P;
            function WPromise(executor) {
              return new OrigPromise(executor);
            }
            WPromise.prototype = OrigPromise.prototype;
            Object.setPrototypeOf(WPromise, OrigPromise);
            ['resolve','reject','all','allSettled','race','any'].forEach(function(m){
              if (typeof OrigPromise[m] === 'function') WPromise[m] = OrigPromise[m].bind(OrigPromise);
            });
            // 仅记录，不替换全局（替换 Promise 有兼容风险）
          } catch(e){}
          return JSON.stringify({ok: true});
        })()
    """.trimIndent()
}
