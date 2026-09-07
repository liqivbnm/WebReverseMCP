package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** Page Analysis Tools：页面环境、框架、脚本、Worker、权限、安全分析 */
object PageTools {

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)
        return listOf(
            f.tool(
                "page.environment", "分析页面运行环境", ToolCategory.PAGE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val result = session.engine.evaluateJavascript(
                    """
                    (function(){
                      return JSON.stringify({
                        userAgent: navigator.userAgent,
                        platform: navigator.platform,
                        language: navigator.language,
                        languages: navigator.languages,
                        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                        screen: {width: screen.width, height: screen.height, availWidth: screen.availWidth, availHeight: screen.availHeight, colorDepth: screen.colorDepth},
                        viewport: {width: window.innerWidth, height: window.innerHeight},
                        devicePixelRatio: window.devicePixelRatio,
                        touch: 'ontouchstart' in window,
                        cpuCores: navigator.hardwareConcurrency,
                        memory: navigator.deviceMemory,
                        connection: navigator.connection ? {type: navigator.connection.type, effectiveType: navigator.connection.effectiveType} : null,
                        webgl: (function(){ try { var c = document.createElement('canvas'); return !!(c.getContext('webgl') || c.getContext('experimental-webgl')); } catch(e){ return false; } })(),
                        canvas: (function(){ try { var c = document.createElement('canvas'); return !!(c.getContext('2d')); } catch(e){ return false; } })(),
                        webRTC: !!window.RTCPeerConnection,
                        webAssembly: typeof WebAssembly !== 'undefined',
                        serviceWorker: 'serviceWorker' in navigator,
                        indexedDB: !!window.indexedDB,
                        cookiesEnabled: navigator.cookieEnabled,
                        doNotTrack: navigator.doNotTrack,
                        online: navigator.onLine,
                        pdfViewer: navigator.pdfViewerEnabled
                      });
                    })()
                    """.trimIndent()
                ) ?: "{}"
                McpToolResult.text(result)
            },
            f.tool(
                "page.framework_detect", "检测页面使用的框架/构建工具/混淆器", ToolCategory.PAGE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val source = session.engine.getPageSource() ?: ""
                val jsResult = session.engine.evaluateJavascript(
                    "(function(){var out={};out.react=!!window.__REACT_DEVTOOLS_GLOBAL_HOOK__;out.vue=!!(window.Vue||document.querySelector('#app')&&document.querySelector('#app').__vue__);out.angular=!!window.ng;out.jquery=!!window.jQuery;out.next=!!window.__NEXT_DATA__;out.nuxt=!!window.__NUXT__;out.webpack=!!window.webpackJsonp;out.vite=!!document.querySelector('script[src*=\"/@vite/\"]');out.pwa=!!navigator.serviceWorker;out.spa=!!(window.history.pushState&&document.querySelector('#root,#app'));out.shadowDom=!!document.querySelector('*').shadowRoot;return JSON.stringify(out)})()"
                ) ?: "{}"
                val fromJs = deps.frameworkDetector.detectFromJs(source)
                val fromRuntime = deps.frameworkDetector.detectFromRuntime(jsResult)
                McpToolResult.json(
                    buildJsonObject {
                        put("frameworks", JsonArray((fromJs.frameworks + fromRuntime.frameworks).distinct().map { JsonPrimitive(it) }))
                        put("bundlers", JsonArray(fromJs.bundlers.map { JsonPrimitive(it) }))
                        put("obfuscators", JsonArray(fromJs.obfuscators.map { JsonPrimitive(it) }))
                        put("architecture", JsonArray((fromJs.architecture + fromRuntime.architecture).distinct().map { JsonPrimitive(it) }))
                        put("confidence", JsonPrimitive(fromJs.confidence.toString()))
                    },
                )
            },
            f.tool(
                "page.api_list", "列出页面 API 清单", ToolCategory.PAGE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val source = session.engine.getPageSource() ?: ""
                val scripts = session.engine.evaluateJavascript(
                    "(function(){var out=[];document.querySelectorAll('script[src]').forEach(function(s){out.push(s.src)});return JSON.stringify(out)})()"
                ) ?: "[]"
                val fromHtml = deps.apiDiscoveryEngine.discoverFromHtml(source)
                val fromJs = deps.apiDiscoveryEngine.discoverFromJs(source, "html")
                val fromNetwork = deps.apiDiscoveryEngine.discoverFromNetwork(session.engine.getNetworkEntries())
                val merged = deps.apiDiscoveryEngine.merge(fromHtml, fromJs, fromNetwork)
                McpToolResult.json(
                    buildJsonObject {
                        put(
                            "endpoints",
                            JsonArray(
                                merged.endpoints.map { e ->
                                    buildJsonObject {
                                        put("method", JsonPrimitive(e.method))
                                        put("url", JsonPrimitive(e.url))
                                        put("source", JsonPrimitive(e.source))
                                        put("caller", JsonPrimitive(e.caller))
                                        put("line", JsonPrimitive(e.line))
                                        put("confidence", JsonPrimitive(e.confidence))
                                    }
                                },
                            ),
                        )
                        put("scriptSources", JsonPrimitive(scripts))
                    },
                )
            },
            f.tool(
                "page.script_list", "列出页面脚本", ToolCategory.PAGE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val result = session.engine.evaluateJavascript(
                    "(function(){var out=[];document.querySelectorAll('script').forEach(function(s,i){out.push({index:i,src:s.src||'(inline)',type:s.type||'text/javascript',async:s.async,defer:s.defer,length:(s.textContent||'').length})});return JSON.stringify(out)})()"
                ) ?: "[]"
                McpToolResult.text(result)
            },
            f.tool(
                "page.source_list", "列出页面所有资源（link/script/img）", ToolCategory.PAGE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val result = session.engine.evaluateJavascript(
                    "(function(){var out=[];document.querySelectorAll('script[src],link[href],img[src]').forEach(function(el){out.push({tag:el.tagName,src:el.src||el.href||''})});return JSON.stringify(out.slice(0,500))})()"
                ) ?: "[]"
                McpToolResult.text(result)
            },
            f.tool(
                "page.worker_list", "列出页面 Worker", ToolCategory.PAGE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val result = session.engine.evaluateJavascript(
                    "(function(){var out={};out.serviceWorkers='serviceWorker' in navigator;out.workers=[];return JSON.stringify(out)})()"
                ) ?: "{}"
                McpToolResult.text(result)
            },
            f.tool(
                "page.service_worker_list", "列出 Service Workers", ToolCategory.PAGE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val result = deps.storageInspector.getServiceWorkers(session.engine)
                result.fold(
                    onSuccess = { McpToolResult.json(buildJsonObject { put("serviceWorkers", JsonPrimitive(it.toString())) }) },
                    onFailure = { McpToolResult.error("STORAGE_READ_FAILED", it.message) },
                )
            },
            f.tool(
                "page.permissions", "查询页面权限状态", ToolCategory.PAGE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val result = session.engine.evaluateJavascript(
                    """
                    (function(){
                      var perms = ['geolocation','notifications','camera','microphone','clipboard-read','clipboard-write','persistent-storage','background-sync','midi','payment-handler'];
                      var out = {};
                      var pending = perms.length;
                      return new Promise(function(resolve){
                        if (!navigator.permissions) { resolve(JSON.stringify({unsupported:true})); return; }
                        perms.forEach(function(p){
                          navigator.permissions.query({name:p}).then(function(status){
                            out[p] = status.state;
                            pending--;
                            if (pending === 0) resolve(JSON.stringify(out));
                          }).catch(function(){ out[p] = 'unknown'; pending--; if (pending === 0) resolve(JSON.stringify(out)); });
                        });
                      });
                    })()
                    """.trimIndent()
                ) ?: "{}"
                McpToolResult.text(result)
            },
            f.tool(
                "page.security", "分析页面安全属性", ToolCategory.PAGE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val result = session.engine.evaluateJavascript(
                    """
                    (function(){
                      var out = {};
                      out.protocol = location.protocol;
                      out.isHttps = location.protocol === 'https:';
                      out.host = location.host;
                      out.pathname = location.pathname;
                      out.cookiesEnabled = navigator.cookieEnabled;
                      out.hasCSP = (function(){ for (var i=0;i<document.querySelectorAll('meta[http-equiv="Content-Security-Policy"]').length;i++) return true; return false; })();
                      out.iframeCount = document.querySelectorAll('iframe').length;
                      out.hasMixedContent = (function(){ var mixed=false; document.querySelectorAll('img,script,link,iframe').forEach(function(el){ var src=el.src||el.href||''; if(src.indexOf('http://')===0) mixed=true; }); return mixed; })();
                      out.webRTC = !!window.RTCPeerConnection;
                      out.localStorage = (function(){ try { localStorage.setItem('__t','1'); localStorage.removeItem('__t'); return true; } catch(e){ return false; } })();
                      out.sessionStorage = (function(){ try { sessionStorage.setItem('__t','1'); sessionStorage.removeItem('__t'); return true; } catch(e){ return false; } })();
                      return JSON.stringify(out);
                    })()
                    """.trimIndent()
                ) ?: "{}"
                McpToolResult.text(result)
            },
            f.tool(
                "page.performance", "获取页面性能数据", ToolCategory.PAGE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val timing = deps.performanceAnalyzer.getNavigationTiming(session.engine)
                val resources = deps.performanceAnalyzer.getResourceTiming(session.engine)
                val memory = deps.performanceAnalyzer.getMemory(session.engine)
                McpToolResult.json(
                    buildJsonObject {
                        timing.getOrNull()?.let { t ->
                            put("navigation", buildJsonObject {
                                put("domContentLoaded", JsonPrimitive(t.domContentLoaded))
                                put("loadEvent", JsonPrimitive(t.loadEvent))
                                put("firstPaint", JsonPrimitive(t.firstPaint))
                                put("firstContentfulPaint", JsonPrimitive(t.firstContentfulPaint))
                            })
                        }
                        resources.getOrNull()?.let { r ->
                            put("resourceCount", JsonPrimitive(r.size))
                        }
                        memory.getOrNull()?.let { m ->
                            put("usedJSHeapSize", JsonPrimitive(m.usedJSHeapSize))
                            put("totalJSHeapSize", JsonPrimitive(m.totalJSHeapSize))
                        }
                    },
                )
            },
            f.tool(
                "page.memory", "获取页面内存信息", ToolCategory.PAGE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val result = deps.performanceAnalyzer.getMemory(session.engine)
                result.fold(
                    onSuccess = { m ->
                        McpToolResult.json(
                            buildJsonObject {
                                put("usedJSHeapSize", JsonPrimitive(m.usedJSHeapSize))
                                put("totalJSHeapSize", JsonPrimitive(m.totalJSHeapSize))
                                put("jsHeapSizeLimit", JsonPrimitive(m.jsHeapSizeLimit))
                            },
                        )
                    },
                    onFailure = { McpToolResult.error("PERF_UNAVAILABLE", it.message) },
                )
            },
            f.tool(
                "page.inspect", "综合检查当前页面", ToolCategory.PAGE,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val url = session.engine.currentUrl() ?: ""
                val title = session.engine.currentTitle() ?: ""
                val source = session.engine.getPageSource() ?: ""
                val scripts = deps.jsParser.extractFunctions(source)
                McpToolResult.json(
                    buildJsonObject {
                        put("url", JsonPrimitive(url))
                        put("title", JsonPrimitive(title))
                        put("htmlLength", JsonPrimitive(source.length))
                        put("scriptCount", JsonPrimitive(scripts.size))
                        put("networkEntryCount", JsonPrimitive(session.engine.getNetworkEntries().size))
                    },
                )
            },
            f.tool(
                "page.cookies", "读取当前页面 Cookie", ToolCategory.PAGE,
                PermissionScope.READ_COOKIES, RiskLevel.HIGH,
            ) { _ ->
                val session = deps.activeSession()
                val result = deps.storageInspector.getCookies(session.engine)
                result.fold(
                    onSuccess = { cookies ->
                        McpToolResult.json(
                            buildJsonObject {
                                put(
                                    "cookies",
                                    JsonArray(
                                        cookies.map { c ->
                                            buildJsonObject {
                                                put("name", JsonPrimitive(c["name"] ?: ""))
                                                put("value", JsonPrimitive(com.webreverse.mcp.core.common.util.Redactor.redactValue(c["name"] ?: "", c["value"] ?: "")))
                                            }
                                        },
                                    ),
                                )
                            },
                        )
                    },
                    onFailure = { McpToolResult.error("STORAGE_READ_FAILED", it.message) },
                )
            },
        )
    }
}
