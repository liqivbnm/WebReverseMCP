package com.webreverse.mcp.javascript.analysis

import kotlinx.serialization.Serializable

/**
 * 浏览器环境能力项（报告 §21/§23）。
 */
@Serializable
data class EnvironmentCapability(
    val path: String = "",
    val present: Boolean = false,
    val capturedValue: String? = null,
)

/**
 * 浏览器环境依赖扫描结果（报告 §21）。
 *
 * 对一段要在 Node 中复现的脚本做静态预扫描，找出其依赖的浏览器全局/能力，
 * 供 BrowserEnvironmentSynthesizer 生成 shim。
 */
@Serializable
data class EnvironmentInferenceResult(
    val requiredGlobals: List<String> = emptyList(),
    val requiredPaths: List<String> = emptyList(),   // 如 window.crypto.subtle
    val capabilities: Map<String, Boolean> = emptyMap(),
    val networkUsage: NetworkUsageKind = NetworkUsageKind.CAPTURED_ONLY,
    val timeline: HashMap<String, Int> = HashMap(),
) {
    companion object {
        val empty = EnvironmentInferenceResult()
    }
}

/** 脚本网络能力使用范围（报告 §43） */
@Serializable
enum class NetworkUsageKind {
    NONE,          // 无网络使用
    CAPTURED_ONLY, // 仅回放已捕获的请求/响应（检测到敏感认证信息时强制，最安全）
    TARGET_ONLY,   // 仅允许访问目标站点（有网络依赖但无敏感认证信息）
    FULL,          // 完全放开网络（不推荐默认启用，需人工确认）
}

/* * shim 语法校验结果（定界符配平 + 结构检查） */
@Serializable
data class ShimValidation(
    val valid: Boolean = true,
    val issues: List<String> = emptyList(),
)

/**
 * shim 执行模式（报 §20/§21：错误驱动补环境的"缺啥补啥"策略参数）。
 *
 * - [PERMISSIVE]：默认。缺失能力返回默认值/空对象，脚本尽量跑通（适合快跑复现）。
 * - [STRICT]：访问缺失能力时抛错，把"到底缺什么"显式暴露给错误驱动回填循环，
 *   避免被空对象静默掩盖导致签名输出错误。
 * - [LEARN]：访问缺失能力时记录日志（挂到 global.__WRMCP_SHIM_LOG__），其余正常，
 *   用于采集"本次运行实际触达但没补全的能力"。
 */
@Serializable
enum class ShimMode {
    PERMISSIVE, STRICT, LEARN,
}

/**
 * 浏览器环境合成器（BrowserEnvironmentSynthesizer，报告 ④ / §17~§24）。
 *
 * 目标：把"从网页提取的 JS"自动放到一个最接近目标浏览器的 Node 运行环境中复现，
 * 替代手工逐项补 window/document/navigator ...。
 *
 * 当前实现提供两个核心能力：
 * 1. [infer]：静态预扫描脚本，列出其依赖的浏览器全局与嵌套路径（错误驱动+静态双通道中的"静态通道"）。
 * 2. [buildShim]：基于推断结果 + 真实浏览器捕获值，生成可注入 Node 的 shim JS 代码骨架。
 *
 * 设计要点（对齐报告 §18/§20/§22）：
 *  - 不把浏览器全局盲目塞进 Node global（报告 §18 明确反对 Object.assign(global, dom.window)）。
 *  - 生成独立的隔离上下文引导代码，让脚本运行在被 shim 补全的 window 代理上。
 *  - 路径用法（如 window.crypto.subtle）递归补全，dotted path 拆成嵌套对象。
 *  - 网络默认 [NetworkUsageKind.CAPTURED_ONLY]。
 *
 * 改进：
 *  - 静态扫描升级为 AST 通道（[BrowserEnvAstScanner]）：识别 `.prop` 与 `['str']` 两种
 *    成员访问、连续链式访问，且不命中注释/字符串伪代码；解析失败时回退正则通道。
 *  - 修复 atob/btoa 分支缺少闭合大括号导致的 shim 语法错误。
 *  - 网络推断去冗余：无网络→NONE；有网络且含敏感认证信息→CAPTURED_ONLY；
 *    有网络且无敏感信息→TARGET_ONLY（FULL 永不自动推断）。
 *  - 新增 [validateShim]：对生成的 shim 做定界符配平校验，提前暴露语法问题。
 */
class BrowserEnvironmentSynthesizer {

    /** 常用浏览器全局（报告 §2/§21），扫描命中即标记需要补齐 */
    private val knownGlobals = listOf(
        "window", "document", "navigator", "location", "history", "screen",
        "performance", "crypto", "localStorage", "sessionStorage", "indexedDB",
        "fetch", "XMLHttpRequest", "WebSocket", "Worker", "Blob", "File",
        "FormData", "URL", "URLSearchParams", "DOMParser", "MutationObserver",
        "IntersectionObserver", "ResizeObserver", "TextEncoder", "TextDecoder",
        "atob", "btoa", "AudioContext", "CanvasRenderingContext2D", "Notification",
        "Permissions", "customElements", "matchMedia",
    )

    /** window 子路径（嵌套能力，如 crypto.subtle） */
    private val knownSubpaths = listOf(
        "window.crypto.subtle",
        "window.chrome",
        "window.chrome.runtime",
        "navigator.userAgent",
        "navigator.platform",
        "navigator.language",
        "navigator.languages",
        "navigator.hardwareConcurrency",
        "navigator.deviceMemory",
        "navigator.maxTouchPoints",
        "navigator.webdriver",
        "navigator.plugins",
        "navigator.mimeTypes",
        "location.href",
        "location.origin",
        "location.protocol",
        "location.host",
        "location.search",
        "document.cookie",
        "screen.width",
        "screen.height",
        "screen.colorDepth",
        "screen.pixelDepth",
        "window.outerWidth",
        "window.outerHeight",
        "window.innerWidth",
        "window.innerHeight",
        "window.devicePixelRatio",
        "performance.now",
        "window.__ABC__",
        // 几何指纹一致性（报告 §指纹）：这些 key 的值需要真实浏览器执行
        // （画布渲染/着色器/字体度量）才能产生，captureEnvScript 走指纹采集通道
        "canvas.data2d",
        "canvas.measureText",
        "canvas.fonts",
        "webgl.vendor",
        "webgl.renderer",
        "webgl.params",
        "webgl.data",
    )

    /**
     * 指纹依赖启发：源码出现这些 API 调用时，自动补对应指纹能力项。
     *
     * 指纹脚本（风控/签名）几乎必然走 canvas/WebGL API；纯静态路径扫描
     * 无法发现"运行时才 createElement('canvas')"的依赖。启发式命中即补——
     * 多补的代价只是多装桩（无网络、无副作用），漏补则 Node 复现直接失败。
     */
    private val fingerprintIndicators = linkedMapOf(
        "canvas.data2d" to listOf("toDataURL", "toBlob", "getImageData"),
        "canvas.measureText" to listOf("measureText"),
        "canvas.fonts" to listOf("document.fonts", "fonts.check", "FontFace"),
        "webgl.params" to listOf("getParameter", "getShaderPrecisionFormat", "getExtension"),
        "webgl.data" to listOf("readPixels"),
    )

    /** 网络调用根标识符（AST 通道） */
    private val networkCallRoots = setOf("fetch", "XMLHttpRequest", "WebSocket")

    private val networkIndicator = Regex(
        """\b(?:fetch|XMLHttpRequest|WebSocket|navigator\.sendBeacon)\s*\(""",
    )
    private val fullNetworkBlockers = listOf(
        "cookie", "authorization", "x-token", "sign", "apikey", "api_key",
    )

    private val astScanner = BrowserEnvAstScanner()

    /**
     * 静态预扫描：找出脚本依赖的浏览器全局与路径。
     * 同时按脚本使用网络的方式推断默认网络策略。
     *
     * 优先 AST 通道（精确、无注释/字符串误报、支持括号访问）；
     * AST 无信号（解析失败或确无浏览器依赖）时回退正则通道。
     */
    fun infer(source: String): EnvironmentInferenceResult {
        val scan = astScanner.scan(source)

        val globals: List<String>
        val paths: List<String>
        val usesNetwork: Boolean
        if (scan.parsed) {
            // AST 通道：精确识别，不命中注释/字符串伪代码，支持括号访问。
            // 全局判定：根标识符命中；或成员链根为已知全局且链中含该全局（如 window.crypto.subtle → crypto）。
            globals = knownGlobals.filter { g ->
                g in scan.rootIdentifiers || scan.memberPaths.any { p ->
                    val segs = p.split('.')
                    segs.first() == g || (segs.first() in knownGlobals && g in segs)
                }
            }
            paths = knownSubpaths.filter { sp ->
                scan.memberPaths.any { it == sp || it.startsWith("$sp.") }
            }
            usesNetwork = scan.callRoots.any { it in networkCallRoots } ||
                scan.memberPaths.any { it == "navigator.sendBeacon" } ||
                networkIndicator.containsMatchIn(source)
        } else {
            // 回退：token/正则通道（仅当 AST 整体解析失败时）
            globals = knownGlobals.filter { tokenUsed(source, it) }
            paths = knownSubpaths.filter { source.contains(it) || pathUsedVariants(source, it) }
            usesNetwork = networkIndicator.containsMatchIn(source)
        }

        val capabilities = LinkedHashMap<String, Boolean>()
        globals.forEach { capabilities[it] = true }
        paths.forEach { capabilities[it] = true }

        // 指纹依赖启发：命中 canvas/WebGL/字体 API 用法时补指纹能力项，
        // Node 复现时由 __installFingerprint 桩 + 真实捕获指纹值回填（见 buildShim 尾部）。
        fingerprintIndicators.forEach { (cap, hints) ->
            if (capabilities[cap] != true && hints.any { source.contains(it) }) {
                capabilities[cap] = true
            }
        }

        // 网络推断（ 去冗余）：
        //  - 无网络调用 → NONE
        //  - 有网络调用且含敏感认证信息（cookie/token/sign 等）→ CAPTURED_ONLY（防泄漏，最安全）
        //  - 有网络调用且无敏感信息 → TARGET_ONLY（受限目标域放行）
        //  - FULL 永不自动推断，需人工确认
        val network = when {
            !usesNetwork -> NetworkUsageKind.NONE
            fullNetworkBlockers.any { source.lowercase().contains(it) } -> NetworkUsageKind.CAPTURED_ONLY
            else -> NetworkUsageKind.TARGET_ONLY
        }

        return EnvironmentInferenceResult(
            requiredGlobals = globals,
            requiredPaths = paths,
            capabilities = capabilities,
            networkUsage = network,
        )
    }

    /** 浏览器能力表（导航场景直接返回可捕获项清单，供 MCP 工具生成采集指令） */
    fun captureableKeys(): List<String> = knownGlobals + knownSubpaths

    /**
     * 生成可注入 Node 隔离上下文的 shim 引导 JS（报告 §24/§34 的统一格式）。
     *
     * @param captured 真实浏览器捕获到的值（key -> JSON 字符串或原始值）
     * @param includeWindow 是否创建 window 根对象
     */
    fun buildShim(capabilities: Map<String, Boolean>, captured: Map<String, String> = emptyMap(), includeWindow: Boolean = true, mode: ShimMode = ShimMode.PERMISSIVE): String {
        val sb = StringBuilder()
        sb.append("(function(global){\n")
        sb.append("// BrowserEnvironmentSynthesizer 生成的浏览器环境 shim (mode=").append(mode.name).append(")\n")
        sb.append("global.__WRMCP_SHIM_MODE__ = ").append(quote(mode.name)).append(";\n")
        sb.append("global.__WRMCP_BROWSER_ENV__ = {};\n")
        if (includeWindow) {
            sb.append("var __win = global.__WRMCP_BROWSER_ENV__.window = {};\n")
        } else {
            sb.append("var __win = global;\n")
        }
        sb.append("var __captured = ${quoteMap(captured)};\n")
        sb.append("var __set = function(obj,path,val){ var parts=String(path).split('.'); var cur=obj; for(var i=0;i<parts.length-1;i++){ var p=parts[i]; if(cur[p]===undefined||cur[p]===null||typeof cur[p]!=='object'){ try{cur[p]={};}catch(e){return;} } cur=cur[p]; } try{cur[parts[parts.length-1]]=val;}catch(e){} };\n")
        sb.append("var __val = function(k){ return Object.prototype.hasOwnProperty.call(__captured,k) ? __captured[k] : undefined; };\n")
        // 增强：通用方法桩/一致性字段安装器（对齐真实浏览器行为）
        // 报20/21：桩按执行模式区分行为——STRICT 缺啥抛错、LEARN 缺啥记日志、PERMISSIVE 静默返回
        sb.append("var __mode=global.__WRMCP_SHIM_MODE__||'PERMISSIVE';\n")
        sb.append("var __missing=function(n){ if(__mode==='STRICT'){ throw new Error('[shim:'+n+'] 缺少的浏览器能力（STRICT 模式）'); } if(__mode==='LEARN'&&typeof global.__WRMCP_SHIM_LOG__==='function'){ try{global.__WRMCP_SHIM_LOG__('[shim:missing] '+n);}catch(e){} } return undefined; };\n")
        sb.append("var __stubFn=function(n){ return function(){ return __missing(n||arguments.callee&&arguments.callee.name||'method'); }; };\n")
        sb.append("var __nodeStub=function(){ return {children:[],childNodes:[],nodeType:9,nodeName:'#document',ownerDocument:null,textContent:'',innerHTML:'',style:{},classList:{add:__stubFn('classList.add'),remove:__stubFn('classList.remove'),toggle:__stubFn('classList.toggle'),contains:function(){return false;}},appendChild:function(){return this;},removeChild:function(){return this;},addEventListener:__stubFn('node.addEventListener'),removeEventListener:__stubFn('node.removeEventListener'),dispatchEvent:__stubFn('node.dispatchEvent'),getAttribute:function(){return null;},setAttribute:__stubFn('node.setAttribute'),removeAttribute:__stubFn('node.removeAttribute'),querySelector:function(){return null;},querySelectorAll:function(){return[];},getElementById:function(){return null;},getElementsByClassName:function(){return[];},getElementsByTagName:function(){return[];},cloneNode:function(){return this;},contains:function(){return false;},insertBefore:function(){return this;},replaceChild:function(){return this;},insertAdjacentHTML:__stubFn('insertAdjacentHTML'),getBoundingClientRect:function(){return{top:0,left:0,width:0,height:0,right:0,bottom:0};}}; };\n")
        sb.append("var __initNavigator=function(n){ if(!n) return; if(n.webdriver===undefined){ try{Object.defineProperty(n,'webdriver',{value:false,configurable:true});}catch(e){n.webdriver=false;} } if(n.plugins===undefined){ n.plugins=[]; } if(n.mimeTypes===undefined){ n.mimeTypes=[]; } if(n.maxTouchPoints===undefined){ n.maxTouchPoints=1; } if(typeof n.javaEnabled!=='function'){ n.javaEnabled=function(){return false;}; } return n; };\n")
        sb.append("var __installDocument=function(d){ if(!d||typeof d!=='object') return; __installCommon(d); ['querySelector','querySelectorAll','getElementById','getElementsByClassName','getElementsByTagName','getElementsByName','createElement','createElementNS','createTextNode','createDocumentFragment','importNode','getElementByXpath','adoptNode'].forEach(function(m){ if(typeof d[m]!=='function'){ d[m]=(m==='querySelector'||m==='getElementById')?(function(){return null;}):(m==='querySelectorAll'||m==='getElementsByClassName'||m==='getElementsByTagName'||m==='getElementsByName')?(function(){return[];}):(function(){return __nodeStub();}); } }); if(typeof d.addEventListener!=='function'){ d.addEventListener=__stubFn(); } if(d.head===undefined){ d.head=__nodeStub(); } if(d.body===undefined){ d.body=__nodeStub(); } if(d.documentElement===undefined){ d.documentElement=d; } if(d.readyState===undefined){ d.readyState='complete'; } if(typeof d.createEvent!=='function'){ d.createEvent=function(){return __nodeStub();}; } if(typeof d.write!=='function'){ d.write=__stubFn(); } return d; };\n")
        sb.append("var __installWindow=function(w){ __installCommon(w); if(typeof w.matchMedia!=='function'){ w.matchMedia=function(q){ return {matches:false,media:String(q),addListener:__stubFn(),removeListener:__stubFn(),addEventListener:__stubFn(),removeEventListener:__stubFn(),dispatchEvent:__stubFn(),onchange:null}; }; } if(typeof w.scrollTo!=='function'){ w.scrollTo=__stubFn(); w.scrollBy=__stubFn(); } if(typeof w.requestAnimationFrame!=='function'){ w.requestAnimationFrame=global.requestAnimationFrame||function(cb){ return setTimeout(function(){ cb(Date.now()); },0); }; } if(typeof w.cancelAnimationFrame!=='function'){ w.cancelAnimationFrame=global.cancelAnimationFrame||clearTimeout; } if(w.outerWidth===undefined && w.screen && w.screen.width){ try{Object.defineProperty(w,'outerWidth',{value:Number(w.screen.width),configurable:true});}catch(e){} } return w; };\n")

        val allKeys = LinkedHashSet<String>()
        allKeys.addAll(capabilities.keys)

        for (key in allKeys) {
            val capturedVal = "__val(" + quote(key) + ")"
            when {
                key.equals("window", true) -> sb.append("__set(__win, 'window', __win);\n")
                key.equals("crypto", true) -> sb.append("(function(){var c=(typeof globalThis.crypto==='object'&&globalThis.crypto.getRandomValues)?globalThis.crypto:(typeof require==='function'?(function(){try{return require('crypto').webcrypto;}catch(e){return null;}})():null);if(c){__win.crypto=c;}else{(function(){var ncc=(typeof require==='function');var rb=null;if(ncc){try{rb=require('crypto').randomBytes;}catch(e){rb=null;}}/* 报22：绝不降级为 Math.random 弱随机。无强随机源时 getRandomValues 走 STRICT 显式报错，避免产出错误签名 */\n__win.crypto={getRandomValues:function(a){if(typeof rb==='function'&&rb){var b=rb(Math.max(a.length*2,32));for(var i=0;i<a.length;i++){a[i]=b[i&(b.length-1)];}return a;}if(__mode==='STRICT'){throw new Error('crypto.getRandomValues：无可用的强随机源');}return (function(){var t=typeof performance!=='undefined'&&performance.now?performance.now():Date.now();for(var j=0;j<a.length;j++){a[j]=(t>>>0)^((t=Math.imul(t^t>>>16,0x85ebca6b))>>>0);(a[j]>>>=0);}return a;})();},subtle:{digest:function(){return Promise.resolve(null);}}};})();} globalThis.crypto=__win.crypto;})();\n")
                key.startsWith("window.") -> {
                    // 数值型路径的兜底值必须类型正确（devicePixelRatio 兜 1，而非空对象）
                    val leaf = key.substring("window.".length)
                    val default = when (leaf) {
                        "devicePixelRatio" -> "1"
                        "outerWidth", "innerWidth" -> "390"
                        "outerHeight", "innerHeight" -> "844"
                        else -> "{}"
                    }
                    sb.append("__set(__win, ").append(quote(leaf)).append(", (__val(").append(quote(key)).append(")!==undefined?__val(").append(quote(key)).append("):").append(default).append("));\n")
                }
                key.startsWith("navigator.") -> sb.append("if(typeof __win.navigator==='undefined'){__win.navigator={};}\n").append("__set(__win.navigator, ").append(quote(key.substring("navigator.".length))).append(", __val(").append(quote(key)).append("));\n").append("__initNavigator(__win.navigator);\n")
                key.startsWith("location.") -> sb.append("if(typeof __win.location==='undefined'){__win.location={};}\n").append("__set(__win.location, ").append(quote(key.substring("location.".length))).append(", __val(").append(quote(key)).append("));\n").append("if(typeof __win.location.assign!=='function'){__win.location.assign=__stubFn();__win.location.replace=__stubFn();__win.location.reload=__stubFn();__win.location.toString=function(){return String(__win.location.href||'');};}\n")
                key.startsWith("document.") -> sb.append("if(typeof __win.document==='undefined'){__win.document={};}\n").append("__set(__win.document, ").append(quote(key.substring("document.".length))).append(", __val(").append(quote(key)).append("));\n").append("__installDocument(__win.document);\n")
                key.startsWith("screen.") -> {
                    // colorDepth/pixelDepth 兜 24（真实主流值），其余为对象
                    val leaf = key.substring("screen.".length)
                    val default = if (leaf == "colorDepth" || leaf == "pixelDepth") "24" else "{}"
                    sb.append("if(typeof __win.screen==='undefined'){__win.screen={};}\n")
                        .append("__set(__win.screen, ").append(quote(leaf)).append(", (__val(").append(quote(key)).append(")!==undefined?__val(").append(quote(key)).append("):").append(default).append("));\n")
                }
                // 几何指纹：canvas.*/webgl.* 由尾部 __installFingerprint 统一安装
                //（真实捕获指纹值回填），此处不单独输出，避免脏路径 __win.canvas.data2d
                key.startsWith("canvas.") || key.startsWith("webgl.") ||
                    key.equals("canvas", true) || key.equals("webgl", true) -> Unit
                key.startsWith("performance.") -> sb.append("if(typeof __win.performance==='undefined'){__win.performance={};}\n").append("if(!__win.performance.now){__win.performance.now=function(){return Date.now();};}\n")
                key.equals("navigator", true) -> {
                    sb.append("if(typeof __win.navigator==='undefined'){__win.navigator={};}\n")
                    sb.append("if(__val('navigator.userAgent')!==undefined)__set(__win,'navigator.userAgent',__val('navigator.userAgent'));\n")
                    sb.append("__initNavigator(__win.navigator);\n")
                }
                key.equals("location", true) ||
                    key.equals("history", true) ||
                    key.equals("screen", true) ||
                    key.equals("performance", true) ||
                    key.equals("document", true) -> {
                    sb.append("if(typeof __win.").append(key).append("==='undefined'){__win.").append(key).append("={};}\n")
                    if (key=="document") sb.append("__installDocument(__win.document);\n")
                }
                key.equals("localStorage", true) || key.equals("sessionStorage", true) ->
                    sb.append("if(typeof __win.").append(key).append("==='undefined'){(function(){var m={};__win.").append(key).append("={getItem:function(k){return m[k]!==undefined?m[k]:null;},setItem:function(k,v){m[k]=String(v);},removeItem:function(k){delete m[k];},clear:function(){m={};},key:function(i){return Object.keys(m)[i]||null;},get length(){return Object.keys(m).length;}};})();}\n")
                key.equals("fetch", true) ->
                    sb.append("if(typeof __win.fetch==='undefined'){__win.fetch=function(){return Promise.reject(new Error('网络策略 CAPTURED_ONLY：fetch 由捕获请求回放提供'));};}\n")
                key.equals("XMLHttpRequest", true) ->
                    sb.append("if(typeof __win.XMLHttpRequest==='undefined'){__win.XMLHttpRequest=function(){};__win.XMLHttpRequest.prototype.open=function(){};__win.XMLHttpRequest.prototype.send=function(){};}\n")
                key.equals("atob", true) -> sb.append("if(typeof __win.atob==='undefined'){__win.atob=function(s){return Buffer.from(s,'base64').toString('binary');}}\n")
                key.equals("btoa", true) -> sb.append("if(typeof __win.btoa==='undefined'){__win.btoa=function(s){return Buffer.from(s,'binary').toString('base64');}}\n")
                key.equals("TextEncoder", true) -> sb.append("if(typeof __win.TextEncoder==='undefined'){__win.TextEncoder=global.TextEncoder;}\n")
                key.equals("TextDecoder", true) -> sb.append("if(typeof __win.TextDecoder==='undefined'){__win.TextDecoder=global.TextDecoder;}\n")
                key.equals("URL", true) -> sb.append("if(typeof __win.URL==='undefined'){__win.URL=global.URL;}\n")
                key.equals("URLSearchParams", true) -> sb.append("if(typeof __win.URLSearchParams==='undefined'){__win.URLSearchParams=global.URLSearchParams;}\n")
                else -> {
                    // 通用兜底：任意未知全局/路径也能补成空对象或回填捕获值，
                    // 这是错误驱动回填（reverse.backfill_environment）能处理任意缺失全局的基础。
                    if (key.matches(Regex("[A-Za-z_$][A-Za-z0-9_$]*"))) {
                        sb.append("if(typeof __win.").append(key).append("==='undefined'){__win.").append(key).append("={};}\n")
                    } else {
                        sb.append("__set(__win, ").append(quote(key)).append(", (__val(").append(quote(key)).append(")!==undefined?__val(").append(quote(key)).append("):{}));\n")
                    }
                }
            }
        }

        // 增强：统一安装 window/document/navigator 常用方法与一致性字段
        sb.append("__installWindow(__win);\n")
        sb.append("if(__win.document)__installDocument(__win.document);\n")
        sb.append("if(__win.navigator)__initNavigator(__win.navigator);\n")
        // 几何指纹一致性引擎：canvas/WebGL/字体桩 + 真实捕获指纹回填
        sb.append(FINGERPRINT_INSTALLER)
        sb.append("__installFingerprint(__win);\n")
        sb.append("// 脚本依赖的 window 解析已完成，见 __WRMCP_BROWSER_ENV__\n")
        sb.append("return global.__WRMCP_BROWSER_ENV__;\n").append("})(typeof globalThis!=='undefined'?globalThis:this);")
        return sb.toString()
    }

    /**
     * 几何指纹一致性桩安装器（生成 JS，随 shim 内嵌）。
     *
     * 桩行为与真实浏览器的差异面（诚实边界）：
     *  - toDataURL 回传采集到的真实 dataURL（签名脚本对其哈希/子串时结果与真机一致）
     *  - measureText 按捕获的宽度表查值（同 font 精确命中；同 family 按字号比例缩放；兜底 0.6*size*len）
     *  - document.fonts.check 按捕获的可用字体清单判定
     *  - WebGL getParameter 按捕获的枚举值表回值；UNMASKED_VENDOR/RENDERER 回传真实值
     *  - readPixels 返回全 0（像素级渲染结果无法离线还原）；webgl.data 捕获值供比对
     * 未采集指纹（captured 无 canvas / webgl 项）时桩仍可用但值是默认值——
     * 签名输出会与真机不同，需 reverse.capture_environment 采集后重跑。
     */
    private val FINGERPRINT_INSTALLER: String = """
var __installFingerprint=function(w){
  if(w.__WRMCP_FP__) return; w.__WRMCP_FP__=1;
  var V=function(k){ return Object.prototype.hasOwnProperty.call(__captured,k)?__captured[k]:undefined; };
  var MT=V('canvas.measureText'); if(!MT||typeof MT!=='object') MT=null;

  // ---- measureText 宽度解析：捕获表精确命中 → 同 family 按字号比例 → 等宽近似 ----
  var __mtW=function(font,text){
    var f=String(font||'10px sans-serif'), t=String(text==null?'':text);
    if(MT){
      if(Object.prototype.hasOwnProperty.call(MT,f)) return Number(MT[f])||0;
      var fam=f.replace(/^[^ ]+\s+/,'');
      var mS=/(\d+(?:\.\d+)?)(px|pt)\b/.exec(f), sz=mS?parseFloat(mS[1]):10;
      for(var k in MT){
        if(Object.prototype.hasOwnProperty.call(MT,k)&&k.indexOf(fam)>=0){
          var m2=/(\d+(?:\.\d+)?)(px|pt)\b/.exec(k); var sz2=m2?parseFloat(m2[1]):10;
          if(sz2>0) return Math.round((Number(MT[k])*sz/sz2)*100)/100;
        }
      }
    }
    var m=/(\d+(?:\.\d+)?)(px|pt)\b/.exec(f); var size=m?parseFloat(m[1]):10;
    return Math.round(t.length*size*0.6*100)/100;
  };

  // ---- Canvas 2D 上下文桩 ----
  function C2D(canvas){
    this.canvas=canvas; this.fillStyle='#000000'; this.strokeStyle='#000000';
    this.font='10px sans-serif'; this.textBaseline='alphabetic'; this.textAlign='start';
    this.direction='ltr'; this.globalAlpha=1; this.globalCompositeOperation='source-over';
    this.lineWidth=1; this.lineCap='butt'; this.lineJoin='miter'; this.miterLimit=10;
    this.shadowBlur=0; this.shadowColor='rgba(0, 0, 0, 0)'; this.shadowOffsetX=0; this.shadowOffsetY=0;
    this.imageSmoothingEnabled=true; this.filter='none'; this.lineDashOffset=0;
    this.letterSpacing='0px'; this.wordSpacing='0px'; this.fontKerning='auto';
    this.fontStretch='normal'; this.fontVariantCaps='normal'; this.textRendering='auto';
  }
  var c2p=C2D.prototype;
  ['fillText','strokeText','beginPath','closePath','moveTo','lineTo','arc','arcTo','ellipse','rect','fill','stroke','clip','fillRect','strokeRect','clearRect','setLineDash','drawImage','putImageData','save','restore','translate','rotate','scale','transform','setTransform','resetTransform','createPattern','scrollPathIntoView'].forEach(function(m){ c2p[m]=function(){ return undefined; }; });
  c2p.getLineDash=function(){ return []; };
  c2p.measureText=function(t){ var wd=__mtW(this.font,t); return {width:wd,actualBoundingBoxLeft:0,actualBoundingBoxRight:wd,actualBoundingBoxAscent:Math.round(wd*0.1),actualBoundingBoxDescent:2,fontBoundingBoxAscent:10,fontBoundingBoxDescent:3,alphabeticBaseline:0,ideographicBaseline:0,hangingBaseline:0}; };
  c2p.getImageData=function(x,y,W,H){ var n=(W|0)*(H|0)*4; return {width:W|0,height:H|0,colorSpace:'srgb',data:new Uint8ClampedArray(Math.max(n,0))}; };
  c2p.createImageData=function(W,H){ var n=(W|0)*(H|0)*4; return {width:W|0,height:H|0,data:new Uint8ClampedArray(Math.max(n,0))}; };
  c2p.createLinearGradient=c2p.createRadialGradient=c2p.createConicGradient=function(){ return {addColorStop:__stubFn()}; };
  c2p.isPointInPath=c2p.isPointInStroke=function(){ return false; };

  // ---- WebGL 上下文桩（枚举常量 + 捕获值表回传） ----
  var __glEnums={VERSION:7936,SHADING_LANGUAGE_VERSION:35724,VENDOR:7934,RENDERER:7937,MAX_TEXTURE_SIZE:3379,MAX_CUBE_MAP_TEXTURE_SIZE:34076,MAX_RENDERBUFFER_SIZE:34024,MAX_VIEWPORT_DIMS:3386,MAX_VERTEX_ATTRIBS:34921,MAX_VARYING_VECTORS:36348,MAX_VERTEX_UNIFORM_VECTORS:36347,MAX_FRAGMENT_UNIFORM_VECTORS:36349,MAX_COMBINED_TEXTURE_IMAGE_UNITS:35661,MAX_TEXTURE_IMAGE_UNITS:34930,MAX_VERTEX_TEXTURE_IMAGE_UNITS:35660,RED_BITS:3410,GREEN_BITS:3411,BLUE_BITS:3412,ALPHA_BITS:3413,DEPTH_BITS:3414,STENCIL_BITS:3415,SUBPIXEL_BITS:3408,ALIASED_LINE_WIDTH_RANGE:33901,ALIASED_POINT_SIZE_RANGE:33902};
  var __glShader={VERTEX_SHADER:35633,FRAGMENT_SHADER:35632,COMPILE_STATUS:35713,LINK_STATUS:35714,ARRAY_BUFFER:34962,STATIC_DRAW:35044,FLOAT:5126,TRIANGLES:4,RGBA:6408,UNSIGNED_BYTE:5121};
  var __glParams=(V('webgl.params')&&typeof V('webgl.params')==='object')?V('webgl.params'):{};
  var __glVendor=(typeof V('webgl.vendor')==='string')?V('webgl.vendor'):'';
  var __glRenderer=(typeof V('webgl.renderer')==='string')?V('webgl.renderer'):'';
  var __enumName={}; var __n; for(__n in __glEnums){ __enumName[String(__glEnums[__n])]=__n; }
  function GL(canvas){
    this.canvas=canvas; this.drawingBufferWidth=(canvas&&canvas.width)||300; this.drawingBufferHeight=(canvas&&canvas.height)||150;
    var k; for(k in __glEnums){ this[k]=__glEnums[k]; } for(k in __glShader){ this[k]=__glShader[k]; }
    this.CONTEXT_LOST_WEBGL=37475; this.UNMASKED_VENDOR_WEBGL=37445; this.UNMASKED_RENDERER_WEBGL=37446;
    this.drawingBufferColorSpace='srgb'; this.packAlignment=4;
  }
  var gp=GL.prototype;
  for(var __n2 in __glEnums){ gp[__n2]=__glEnums[__n2]; }
  for(var __n3 in __glShader){ gp[__n3]=__glShader[__n3]; }
  gp.CONTEXT_LOST_WEBGL=37475; gp.UNMASKED_VENDOR_WEBGL=37445; gp.UNMASKED_RENDERER_WEBGL=37446;
  gp.getParameter=function(p){
    if(p===37445) return __glVendor;
    if(p===37446) return __glRenderer;
    var nm=__enumName[String(p)];
    if(nm&&Object.prototype.hasOwnProperty.call(__glParams,nm)) return __glParams[nm];
    return null;
  };
  gp.getExtension=function(x){
    x=String(x||'');
    if(x==='WEBGL_debug_renderer_info') return {UNMASKED_VENDOR_WEBGL:37445,UNMASKED_RENDERER_WEBGL:37446};
    if(x==='EXT_texture_filter_anisotropic') return {MAX_TEXTURE_MAX_ANISOTROPY_EXT:34046};
    return null;
  };
  gp.getSupportedExtensions=function(){ return ['ANGLE_instanced_arrays','EXT_blend_minmax','EXT_color_buffer_half_float','EXT_texture_filter_anisotropic','OES_element_index_uint','OES_standard_derivatives','OES_texture_float','OES_texture_half_float','WEBGL_debug_renderer_info']; };
  gp.getContextAttributes=function(){ return {alpha:true,antialias:true,depth:true,desynchronized:false,failIfMajorPerformanceCaveat:false,powerPreference:'default',premultipliedAlpha:true,preserveDrawingBuffer:false,stencil:false}; };
  gp.getShaderPrecisionFormat=function(){ return {rangeMin:127,rangeMax:127,precision:23}; };
  gp.readPixels=function(x,y,W,H,f,t,px){ try{ for(var i=0;i<px.length;i++) px[i]=0; }catch(e){} };
  gp.getShaderParameter=function(sh,p){ return p===35713?true:null; };
  gp.getProgramParameter=function(pr,p){ return p===35714?true:null; };
  gp.getError=function(){ return 0; };
  gp.createShader=function(){ return {__st:1}; };
  gp.createProgram=function(){ return {__pr:1}; };
  gp.createBuffer=function(){ return {__buf:1}; };
  ['shaderSource','compileShader','attachShader','bindAttribLocation','linkProgram','useProgram','bindBuffer','bufferData','getAttribLocation','getUniformLocation','enableVertexAttribArray','vertexAttribPointer','drawArrays','drawElements','viewport','clear','enable','disable','blendFunc','depthFunc','cullFace','clearColor','clearDepth','finish','flush','deleteShader','deleteProgram','deleteBuffer','generateMipmap','activeTexture','bindTexture','texImage2D','texParameteri','pixelStorei','uniform1f','uniform2f','uniform3f','uniform4f','uniform1i','uniformMatrix4fv','vertexAttrib1f','isEnabled','isBuffer','isProgram','isShader','checkFramebufferStatus','frontFace','hint','lineWidth','polygonOffset','sampleCoverage','scissor','stencilFunc','stencilMask','stencilOp','getShaderInfoLog','getProgramInfoLog'].forEach(function(m){ gp[m]=function(){ return undefined; }; });

  // ---- HTMLCanvasElement 桩 ----
  function CanvasEl(){
    this.width=300; this.height=150; this.nodeType=1; this.nodeName='CANVAS';
    this.clientWidth=300; this.clientHeight=150;
  }
  var cep=CanvasEl.prototype;
  ['addEventListener','removeEventListener','dispatchEvent'].forEach(function(m){ cep[m]=__stubFn(); });
  cep.getContext=function(t){
    t=String(t||'').toLowerCase();
    if(t==='2d') return new C2D(this);
    if(t.indexOf('webgl')===0||t==='experimental-webgl') return new GL(this);
    return null;
  };
  cep.toDataURL=function(){ var d=V('canvas.data2d'); return (typeof d==='string')?d:'data:,'; };
  cep.toBlob=function(cb){ try{ if(typeof cb==='function') cb(null,{}); }catch(e){} };
  cep.getBoundingClientRect=function(){ return {top:0,left:0,width:this.width,height:this.height,right:this.width,bottom:this.height,x:0,y:0}; };
  cep.setAttribute=cep.removeAttribute=__stubFn();
  cep.getAttribute=function(){ return null; };
  cep.addEventListener=__stubFn();

  w.HTMLCanvasElement=CanvasEl;
  w.CanvasRenderingContext2D=C2D;
  w.WebGLRenderingContext=GL;
  w.WebGL2RenderingContext=GL;

  // ---- document.createElement('canvas') 返回桩实例 ----
  try{
    var d=w.document;
    if(d&&typeof d.createElement==='function'){
      var __ce=d.createElement;
      d.createElement=function(tag,ns){
        if(String(tag||'').toLowerCase()==='canvas') return new CanvasEl();
        try{ return __ce.call(d,tag,ns); }catch(e){ return __nodeStub(); }
      };
    }
  }catch(e){}

  // ---- document.fonts 桩（按捕获的可用字体清单判定） ----
  // 注：正则刻意不含引号字符——validateShim 的配平扫描会把正则里的引号
  // 误判为字符串边界导致括号计数错位，故用字符判断替代首尾引号剥离。
  try{
    var F=V('canvas.fonts');
    if(F&&typeof F==='object'&&typeof F.indexOf==='function'){
      var d2=w.document;
      if(d2){
        function __stripQ(s){
          s=String(s);
          while(s.length>0&&(s.charAt(0)==='"'||s.charAt(0)==="'")) s=s.substring(1);
          while(s.length>0&&(s.charAt(s.length-1)==='"'||s.charAt(s.length-1)==="'")) s=s.substring(0,s.length-1);
          return s;
        }
        d2.fonts={
          check:function(fam){
            try{
              var fams=String(fam).replace(/\d+(?:\.\d+)?px\s*/,'').split(',').map(function(s){ return __stripQ(s.trim()); }).filter(function(s){ return s.length>0; });
              for(var i=0;i<fams.length;i++){ if(F.indexOf(fams[i])>=0) return true; }
              return false;
            }catch(e2){ return false; }
          },
          ready:Promise.resolve(), status:'loaded',
          add:__stubFn(), forEach:__stubFn(),
          load:function(){ return Promise.resolve([]); },
          values:function(){ return [][Symbol.iterator](); }
        };
      }
    }
  }catch(e){}
};
"""

    /**
     * 错误驱动补环境的静态模拟：输入"缺啥补啥"路径集合，产出合并后的 shim（报告 §22）
     * ——实际 Node 环境下由执行错误驱动，这里给出可读的合并结果供 MCP 返回。
     */
    fun mergeShim(existing: Map<String, Boolean>, newlyRequired: List<String>): Map<String, Boolean> {
        val merged = LinkedHashMap(existing)
        newlyRequired.forEach { merged[it] = true }
        return merged
    }

    /**
     * 对生成的 shim 做定界符配平校验。
     *
     * 跳过字符串/注释/模板串，检查 () [] {} 是否成对闭合。
     * 用于在交付给 Node 前提前暴露语法问题（如历史上 atob/btoa 分支缺闭合大括号）。
     */
    fun validateShim(shim: String): ShimValidation {
        val stack = ArrayDeque<Char>()
        val issues = mutableListOf<String>()
        val pairs = mapOf(')' to '(', ']' to '[', '}' to '{')
        var i = 0
        val n = shim.length
        var line = 1
        while (i < n) {
            val c = shim[i]
            when {
                c == '\n' -> line++
                c == '/' && i + 1 < n && shim[i + 1] == '/' -> {
                    while (i < n && shim[i] != '\n') i++
                    continue
                }
                c == '/' && i + 1 < n && shim[i + 1] == '*' -> {
                    i += 2
                    while (i + 1 < n && !(shim[i] == '*' && shim[i + 1] == '/')) {
                        if (shim[i] == '\n') line++
                        i++
                    }
                    i += 2
                    continue
                }
                c == '"' || c == '\'' || c == '`' -> {
                    val q = c
                    i++
                    while (i < n && shim[i] != q) {
                        if (shim[i] == '\\') i++
                        if (shim[i] == '\n') line++
                        i++
                    }
                    i++ // 跳过闭合引号
                    continue
                }
                c == '(' || c == '[' || c == '{' -> stack.addLast(c)
                c == ')' || c == ']' || c == '}' -> {
                    val expect = pairs[c]
                    if (stack.isEmpty() || stack.removeLast() != expect) {
                        issues.add("第 $line 行：多余的 '$c'")
                    }
                }
            }
            i++
        }
        if (stack.isNotEmpty()) {
            issues.add("存在未闭合的定界符：${stack.joinToString("") { it.toString() }}")
        }
        return ShimValidation(valid = issues.isEmpty(), issues = issues)
    }

    // ---- 私有辅助 ----

    private fun tokenUsed(source: String, token: String): Boolean {
        return Regex("""\b${Regex.escape(token)}\b""").containsMatchIn(source)
    }

    /** 匹配变体（如 _0x123['window']['crypto'] 动态访问的静态近似） */
    private fun pathUsedVariants(source: String, path: String): Boolean {
        val leaf = path.substringAfterLast('.')
        return source.contains(path) || Regex("""\b${Regex.escape(leaf)}\b""").containsMatchIn(source)
    }

    private fun quote(s: String): String = "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

    private fun quoteMap(map: Map<String, String>): String {
        if (map.isEmpty()) return "{}"
        return map.entries.joinToString(",", "{", "}") { (k, v) -> quote(k) + ":" + v }
    }
}
