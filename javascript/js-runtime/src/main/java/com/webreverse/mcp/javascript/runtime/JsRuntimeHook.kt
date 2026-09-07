package com.webreverse.mcp.javascript.runtime

import com.webreverse.mcp.browser.engine.BrowserEngine
import com.webreverse.mcp.browser.engine.util.JsScripts

/**
 * JavaScript Runtime Hook Framework（Registry 语义）。
 *
 * 重构要点：
 * 1. 幂等安装：每个 Hook 以 type(+target) 为 key 登记，重复 install 对同 key 只
 *    追加回调（attach），返回同一 id——杜绝 hook 链叠加（此前连续 hookFetch 两次
 *    会导致一次请求两次回调）。
 * 2. 完整恢复：所有类型（含 xhr/storage/cookie/timer/console/crypto/history/
 *    location/event/eval）在注册表保存 original，removeHook 恢复页面原始状态。
 * 3. Event Hook 改为 document 级捕获委托 + closest 匹配：SPA 重建 DOM 后依然生效。
 * 4. Timer Hook 覆盖 setTimeout/setInterval/requestAnimationFrame/queueMicrotask，
 *    并记录函数体片段（不仅 string 形式）。
 * 5. 新增 eval/Function Hook：追踪动态代码执行。
 * 6. WebSocket Hook 保留原型链（instanceof 与静态属性不破坏）。
 * 默认禁止采集敏感认证数据（Cookie / Authorization / Token / 密码等）。
 */
class JsRuntimeHook {

    /** 安装 Hook 基础框架（幂等，可安全重复调用） */
    suspend fun installFramework(engine: BrowserEngine) {
        engine.evaluateJavascript(frameworkScript())
    }

    /**
     * Hook 基础框架脚本。
     * 唯一权威实现在 [JsScripts.hookFrameworkScript]（browser-engine 层），
     * 此处委托以保证 document_start 早期注入与运行时安装使用同一份 Registry。
     */
    fun frameworkScript(): String = JsScripts.hookFrameworkScript()

    /** 安装 Hook 并返回 hook id（幂等：重复安装同 key 返回同一 id） */
    suspend fun installHook(engine: BrowserEngine, hookType: String, target: String, callbackJs: String): String? {
        installFramework(engine)
        val call = "function(info){ $callbackJs }"
        val script = when (hookType) {
            "function" -> "window.__WRMCP_HOOK__.hookFunction(${JsScripts.quote(target)}, $call)"
            // target 形如 "JSON.stringify"：拆成对象表达式 + 方法名
            "method" -> {
                val objExpr = target.substringBeforeLast('.', "").ifBlank { "window" }
                val method = target.substringAfterLast('.', target)
                "window.__WRMCP_HOOK__.hookMethod(${JsScripts.quote(objExpr)}, ${JsScripts.quote(method)}, $call)"
            }
            // target 形如 "document.title"：拆成对象表达式 + 属性名
            "property" -> {
                val objExpr = target.substringBeforeLast('.', "").ifBlank { "window" }
                val prop = target.substringAfterLast('.', target)
                "window.__WRMCP_HOOK__.hookProperty(${JsScripts.quote(objExpr)}, ${JsScripts.quote(prop)}, $call)"
            }
            "fetch" -> "window.__WRMCP_HOOK__.hookFetch($call)"
            "xhr" -> "window.__WRMCP_HOOK__.hookXHR($call)"
            "websocket" -> "window.__WRMCP_HOOK__.hookWebSocket($call)"
            "storage" -> "window.__WRMCP_HOOK__.hookStorage($call)"
            "cookie" -> "window.__WRMCP_HOOK__.hookCookie($call)"
            "timer" -> "window.__WRMCP_HOOK__.hookTimer($call)"
            "console" -> "window.__WRMCP_HOOK__.hookConsole($call)"
            "crypto" -> "window.__WRMCP_HOOK__.hookCrypto($call)"
            "history" -> "window.__WRMCP_HOOK__.hookHistory($call)"
            "location" -> "window.__WRMCP_HOOK__.hookLocation($call)"
            "eval" -> "window.__WRMCP_HOOK__.hookEval($call)"
            // 新增
            "worker" -> "window.__WRMCP_HOOK__.hookWorker($call)"
            "subtleCrypto" -> "window.__WRMCP_HOOK__.hookSubtleCrypto($call)"
            // JS 层加密库细粒度（CryptoJS/JSEncrypt/btoa/TextEncoder）
            "cryptoLib" -> "window.__WRMCP_HOOK__.hookCryptoLib($call)"
            "fingerprint" -> "window.__WRMCP_HOOK__.hookFingerprint($call)"
            "notification" -> "window.__WRMCP_HOOK__.hookNotification($call)"
            else -> null
        } ?: return null
        return evalHookInstall(engine, script)
    }

    /** 安装 DOM 事件 Hook（document 捕获委托，SPA 动态 DOM 生效） */
    suspend fun installEventHook(engine: BrowserEngine, selector: String, eventType: String, callbackJs: String): String? {
        installFramework(engine)
        val call = "function(info){ $callbackJs }"
        val script = "window.__WRMCP_HOOK__.hookEvent(${JsScripts.quote(selector)}, ${JsScripts.quote(eventType)}, $call)"
        return evalHookInstall(engine, script)
    }

    /**
     * 执行安装表达式并规整返回值（null/undefined → null，其余 → 字符串 id）。
     *
     * 不再经页面 `eval(string)` 间接执行。此前用
     * `eval("window.__WRMCP_HOOK__.hookMethod(...)")`，一旦页面污染了 `window.eval`
     * 或 `Function.prototype.apply`（stealth 脚本、Hook_CryptoJS 均如此，且会互相叠加），
     * 这条 eval 链路就整体失效——表现为 hook.method/crypto/console 一律报
     * “对象或方法不存在 / 安装失败”，而同走的 js.evaluate/script_install（不经页面
     * eval 的 WebView 主通道）却正常。
     *
     * 现改为把安装表达式直接内联进 IIFE，由 WebView evaluateJavascript 在主世界执行，
     * 与 js.evaluate 走同一稳妥通道，彻底规避页面 eval/apply 污染。
     */
    private suspend fun evalHookInstall(engine: BrowserEngine, script: String): String? {
        val wrapped = "(function(){ try { var v = ($script); " +
            "return (v === null || v === undefined) ? null : String(v); } catch(e){ return null } })()"
        val result = engine.evaluateJavascript(wrapped)
        return result?.trim('"')?.takeIf { it != "null" && it.isNotBlank() }
    }

    suspend fun removeHook(engine: BrowserEngine, hookId: String): Boolean {
        val result = engine.evaluateJavascript(
            "(function(){ try { return window.__WRMCP_HOOK__ && window.__WRMCP_HOOK__.removeHook(${JsScripts.quote(hookId)}) } catch(e){ return false } })()",
        )
        return result == "true"
    }

    suspend fun listHooks(engine: BrowserEngine): String? =
        engine.evaluateJavascript(
            "(function(){ try { return JSON.stringify(window.__WRMCP_HOOK__ ? window.__WRMCP_HOOK__.listHooks() : []) } catch(e){ return '[]' } })()",
        )

    suspend fun resetHooks(engine: BrowserEngine): Boolean {
        val result = engine.evaluateJavascript(
            "(function(){ try { return window.__WRMCP_HOOK__ ? window.__WRMCP_HOOK__.resetHooks() : true } catch(e){ return false } })()",
        )
        return result == "true"
    }
}
