package com.webreverse.mcp.browser.engine.wasm

import android.annotation.SuppressLint
import android.content.Context
import android.webkit.WebView
import android.webkit.WebViewClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.Json
import java.util.concurrent.atomic.AtomicReference
import kotlin.coroutines.resume

/**
 * wabt 离屏引擎：在隐藏 WebView 中运行官方 libwabt 的 WASM 构建（assets/wabt/wabt.js），
 * 提供 wasm -> wat（指令级反汇编）与 wat -> wasm（补丁重编译）能力。
 *
 * 选型说明（评审报告路线 A）：相比 NDK+CMake 交叉编译 libwabt（需维护 4 个 ABI、
 * 每 ABI +2.5MB 包体、构建链复杂），wabt.js 官方维护、零 NDK、跨 ABI 无矩阵；
 * 本应用本身就是 WebView 容器，JS 执行环境零成本。超大模块（>20MB）再考虑原生路线。
 *
 * 数据通道：输入/输出均分块（256KB/块）经 evaluateJavascript 往返，
 * 规避 Chromium executeJavascript 大字符串 IPC 限制。
 */
object WabtEngine {

    private const val INPUT_CHUNK = 256 * 1024
    private const val OUTPUT_CHUNK = 256 * 1024

    private val json = Json { ignoreUnknownKeys = true }

    @Volatile
    private var webViewRef: AtomicReference<WebView?> = AtomicReference(null)

    @Volatile
    private var initFailed = false

    sealed class WabtResult {
        data class Wat(val wat: String) : WabtResult()
        data class Wasm(val bytes: ByteArray) : WabtResult()
        data class Failure(val reason: String) : WabtResult()
    }

    /** 确保离屏 WebView 已创建且 wabt wasm 实例就绪（幂等；Mutex 串行化并发首调） */
    private val initMutex = Mutex()

    suspend fun ensureReady(context: Context): Boolean = initMutex.withLock {
        webViewRef.get()?.let { return@withLock isApiReady(it) }
        if (initFailed) return@withLock false
        return@withLock try {
            val wv = createOffscreen(context.applicationContext)
            webViewRef.set(wv)
            waitForApi(wv, timeoutMs = 20_000)
        } catch (e: Exception) {
            initFailed = true
            false
        }
    }

    /** WASM 二进制 -> 指令级 WAT 文本 */
    suspend fun wasmToWat(context: Context, wasm: ByteArray, foldExprs: Boolean = false): WabtResult {
        val wv = readyOr(context) ?: return WabtResult.Failure("wabt 引擎初始化失败（WebView 不可用）")
        pushInput(wv, android.util.Base64.encodeToString(wasm, android.util.Base64.NO_WRAP))
        eval(wv, "globalThis.__wrWasm2WatStart(${if (foldExprs) "true" else "false"})")
        return when (val state = waitJob(wv, job = 1, timeoutMs = 120_000)) {
            "done" -> WabtResult.Wat(readResultText(wv, job = 1))
            "error" -> WabtResult.Failure(eval(wv, "globalThis.__wrError(1)")?.trim('"') ?: "wasm2wat failed")
            else -> WabtResult.Failure("wasm2wat 超时/异常 state=$state")
        }
    }

    /** WAT 文本 -> WASM 二进制（补丁重编译，round-trip 校验） */
    suspend fun watToWasm(context: Context, wat: String): WabtResult {
        val wv = readyOr(context) ?: return WabtResult.Failure("wabt 引擎初始化失败（WebView 不可用）")
        pushInput(wv, wat)
        eval(wv, "globalThis.__wrWat2WasmStart()")
        return when (val state = waitJob(wv, job = 2, timeoutMs = 120_000)) {
            "done" -> {
                val b64 = readResultText(wv, job = 2)
                val bytes = runCatching {
                    android.util.Base64.decode(b64, android.util.Base64.DEFAULT)
                }.getOrNull() ?: return WabtResult.Failure("wat2wasm 结果解码失败")
                WabtResult.Wasm(bytes)
            }
            "error" -> WabtResult.Failure(eval(wv, "globalThis.__wrError(2)")?.trim('"') ?: "wat2wasm failed")
            else -> WabtResult.Failure("wat2wasm 超时/异常 state=$state")
        }
    }

    // ---------------- 内部实现 ----------------

    @SuppressLint("SetJavaScriptEnabled")
    private suspend fun createOffscreen(context: Context): WebView =
        withContext(Dispatchers.Main) {
            val wv = WebView(context)
            wv.settings.javaScriptEnabled = true
            wv.settings.allowFileAccess = true
            wv.settings.domStorageEnabled = false
            suspendCancellableCoroutine { cont ->
                wv.webViewClient = object : WebViewClient() {
                    override fun onPageFinished(view: WebView?, url: String?) {
                        if (cont.isActive) cont.resume(wv)
                    }
                }
                wv.loadUrl("file:///android_asset/wabt/wabt.html")
            }
        }

    private suspend fun isApiReady(wv: WebView): Boolean {
        val state = eval(wv, "globalThis.__WRMCP_WABT_STATE__ || 'none'")?.trim('"') ?: "none"
        return state == "ready"
    }

    private suspend fun waitForApi(wv: WebView, timeoutMs: Long): Boolean {
        val ok = withTimeoutOrNull(timeoutMs) {
            while (true) {
                if (isApiReady(wv)) return@withTimeoutOrNull true
                kotlinx.coroutines.delay(150)
            }
            @Suppress("UNREACHABLE_CODE")
            false
        }
        return ok == true
    }

    private suspend fun readyOr(context: Context): WebView? {
        if (!ensureReady(context)) return null
        return webViewRef.get()
    }

    /** 分块推送输入（base64 或 WAT 文本），规避单次 evaluateJavascript 大脚本 */
    private suspend fun pushInput(wv: WebView, input: String) {
        eval(wv, "globalThis.__wrInReset()")
        var off = 0
        while (off < input.length) {
            val part = input.substring(off, minOf(off + INPUT_CHUNK, input.length))
            val escaped = org.json.JSONObject.quote(part)
            eval(wv, "globalThis.__wrInAppend($escaped)")
            off += INPUT_CHUNK
        }
    }

    /** 轮询任务状态直到 done/error */
    private suspend fun waitJob(wv: WebView, job: Int, timeoutMs: Long): String {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            when (val s = eval(wv, "globalThis.__wrState($job)")?.trim('"')) {
                "done", "error" -> return s ?: "unknown"
            }
            kotlinx.coroutines.delay(120)
        }
        return "timeout"
    }

    /** 分块读取结果字符串 */
    private suspend fun readResultText(wv: WebView, job: Int): String {
        // 注意 evaluateJavascript 返回 JSON 编码值：数字 64979 实际收到 "\"64979\""，必须去引号
        val len = eval(wv, "globalThis.__wrResultLen($job)")?.trim('"')?.toIntOrNull() ?: 0
        val sb = StringBuilder(minOf(len, 64 * 1024 * 1024))
        var off = 0
        while (off < len) {
            val n = minOf(OUTPUT_CHUNK, len - off)
            val chunkExpr = "JSON.stringify(globalThis.__wrResultChunk($job, $off, $n))"
            val raw = eval(wv, chunkExpr) ?: break
            val piece = runCatching { json.parseToJsonElement(raw).let { (it as kotlinx.serialization.json.JsonPrimitive).content } }.getOrNull() ?: break
            sb.append(piece)
            off += n
        }
        return sb.toString()
    }

    private suspend fun eval(wv: WebView, script: String): String? =
        withContext(Dispatchers.Main) {
            suspendCancellableCoroutine { cont ->
                try {
                    wv.evaluateJavascript(script) { result -> if (cont.isActive) cont.resume(result) }
                } catch (e: Exception) {
                    if (cont.isActive) cont.resume(null)
                }
            }
        }
}
