package com.webreverse.mcp.devtools.console

import com.webreverse.mcp.browser.engine.BrowserEngine
import com.webreverse.mcp.browser.engine.util.JsScripts
import com.webreverse.mcp.core.common.util.AppError
import com.webreverse.mcp.core.common.util.AppResult
import kotlinx.serialization.json.Json

/** JavaScript 控制台管理器 */
class ConsoleManager {

    suspend fun evaluate(engine: BrowserEngine, expression: String): AppResult<String> {
        if (expression.isBlank()) return AppResult.failure(AppError.INVALID_ARGUMENTS)
        val result = engine.evaluateJavascript(expression)
            ?: return AppResult.failure(AppError.JS_EXECUTION_FAILED)
        return AppResult.success(result)
    }

    /**
     * 异步执行 JavaScript（支持 await），等待 Promise 结算后返回结果。
     *
     * 修复：原实现把表达式包成 async IIFE 直接交给引擎，但
     * Android WebView 的 evaluateJavascript 回调不等待 Promise——结果为
     * Promise 时只拿到 `{}`，js.evaluate_async 永远返回空对象。
     * Promise 等待逻辑已下沉到 WebViewBrowserEngine.evaluateJavascriptAsync
     * （「落盘 + 轮询」），此处仅负责把表达式包进 async IIFE 以支持顶层 await。
     *
     * 修复：补全值丢失——原包裹 `(async function{ $expr })` 对
     * 多语句体（如 `setTimeout(...); 'ok'` 或 `promise.then(...)` 结尾不接
     * return）永远返回 undefined（IIFE 无 return 语句），AI 拿不到尾表达式
     * 的值。改用 eval 补全值语义（与 DevTools Console 一致）：eval 返回最后
     * 一个表达式语句的完成值，再由 await 展开 Promise。
     */
    suspend fun evaluateAsync(engine: BrowserEngine, expression: String): AppResult<String> {
        if (expression.isBlank()) return AppResult.failure(AppError.INVALID_ARGUMENTS)
        val wrapped = "(async function(){\n" +
            "return await eval(${JsScripts.quote(expression)})\n" +
            "})()"
        val result = engine.evaluateJavascriptAsync(wrapped)
            ?: return AppResult.failure(
                AppError(
                    "JS_EXECUTION_FAILED",
                    "异步执行失败（Promise rejected、页面导航或超过引擎 30s 等待上限）",
                ),
            )
        return AppResult.success(result)
    }

    suspend fun callFunction(engine: BrowserEngine, functionName: String, vararg args: String): AppResult<String> {
        val argsJson = args.joinToString(",") { JsScripts.quote(it) }
        val result = engine.evaluateJavascript("($functionName)($argsJson)")
            ?: return AppResult.failure(AppError.JS_EXECUTION_FAILED)
        return AppResult.success(result)
    }

    suspend fun inspect(engine: BrowserEngine, expression: String): AppResult<String> {
        val script = """
            (function(){
              try {
                var value = eval(${JsScripts.quote(expression)});
                return JSON.stringify({
                  type: typeof value,
                  value: (typeof value === 'object' && value !== null) ? JSON.stringify(value).substring(0, 10000) : String(value),
                  keys: (typeof value === 'object' && value !== null) ? Object.keys(value).slice(0, 100) : [],
                  isArray: Array.isArray(value),
                  isFunction: typeof value === 'function',
                  isNull: value === null,
                  isUndefined: value === undefined,
                  isNumber: typeof value === 'number',
                  isString: typeof value === 'string',
                  isBoolean: typeof value === 'boolean'
                });
              } catch(e) {
                return JSON.stringify({error: e.message});
              }
            })()
        """.trimIndent()
        val result = engine.evaluateJavascript(script)
            ?: return AppResult.failure(AppError.JS_EXECUTION_FAILED)
        return AppResult.success(result)
    }

    suspend fun watch(engine: BrowserEngine, expression: String): AppResult<String> {
        return evaluate(engine, expression)
    }

    suspend fun getGlobal(engine: BrowserEngine, name: String): AppResult<String> {
        val result = engine.evaluateJavascript("JSON.stringify(window[$name])")
            ?: return AppResult.failure(AppError.JS_EXECUTION_FAILED)
        return AppResult.success(result)
    }

    suspend fun getProperty(engine: BrowserEngine, objectExpression: String, property: String): AppResult<String> {
        val result = engine.evaluateJavascript("JSON.stringify(($objectExpression)[${JsScripts.quote(property)}])")
            ?: return AppResult.failure(AppError.JS_EXECUTION_FAILED)
        return AppResult.success(result)
    }

    suspend fun setProperty(engine: BrowserEngine, objectExpression: String, property: String, value: String): AppResult<Boolean> {
        engine.evaluateJavascript("($objectExpression)[${JsScripts.quote(property)}] = $value")
        return AppResult.success(true)
    }

    suspend fun deleteProperty(engine: BrowserEngine, objectExpression: String, property: String): AppResult<Boolean> {
        engine.evaluateJavascript("delete ($objectExpression)[${JsScripts.quote(property)}]")
        return AppResult.success(true)
    }

    suspend fun clearConsole(engine: BrowserEngine) {
        engine.evaluateJavascript("console.clear()")
    }
}
