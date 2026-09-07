package com.webreverse.mcp.devtools.protocol.cdp

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * CDP 会话：JSON-RPC 请求/响应配对 + 事件流。
 *
 * 与 [com.webreverse.mcp.devtools.protocol.DevToolsProtocol] 中的静态数据模型不同，
 * 本类提供真正的 Transport/Session 能力：消息 id 管理、pending 响应分发、
 * domain 事件 Flow（Debugger.paused / scriptParsed / Runtime.* 等）。
 *
 * （报告 §16/§17 Target domain 支持）：
 * - 支持 flatten 模式子会话路由：send/call/callDetailed 可携带 sessionId，
 *   命令以 `{"id":N,"method":...,"params":...,"sessionId":"<sid>"}` 形式发给
 *   同一 target 连接，由 Target.setAutoAttach(flatten=true) 派生的 Worker/
 *   ServiceWorker/iframe 子会话共用一条 WebSocket。
 * - 事件携带来源 sessionId：子会话事件（Runtime.consoleAPICalled 等）以
 *   根级 "sessionId" 字段标识来源，[CdpEvent.sessionId] 透传给消费者，
 *   上层（CdpTargetManager）据此区分 Page / Worker / ServiceWorker 上下文。
 * - 会话生命周期状态机（报告 §17）：
 *   DISCONNECTED → CONNECTING → CONNECTED → (READY 由调用方标记) → CLOSED；
 *   断线/崩溃进入 CLOSED 前保留 lastError 供重连诊断。
 */
class CdpSession(
    private val ws: RawWebSocket,
    private val scope: CoroutineScope,
) {
    private val json = Json { ignoreUnknownKeys = true }

    private val pending = ConcurrentHashMap<Int, CompletableDeferred<JsonObject>>()
    private val idCounter = AtomicInteger(0)
    private val active = AtomicBoolean(false)

    // （P0 修复）：连续超时计数器——页面主线程阻塞时，CDP 后端不响应，
    // 所有命令都会等满各自的超时。过去每个命令仅抛一次错，会话仍保持"半死"
    // 连接，后续 attach/network/内存工具反复失败。改为连续超时达到阈值即判定
    // 会话不可用并关闭（fail-closed），让上层得到明确断连状态并触发重连。
    private val consecutiveTimeouts = AtomicInteger(0)

    private val _events = MutableSharedFlow<CdpEvent>(
        extraBufferCapacity = 1024,
        onBufferOverflow = kotlinx.coroutines.channels.BufferOverflow.DROP_OLDEST,
    )
    val events: SharedFlow<CdpEvent> = _events.asSharedFlow()

    // ================= 会话状态机 =================

    /** CDP 会话生命周期状态（报告 §17：DISCONNECTED/CONNECTING/CONNECTED/READY/RECONNECTING/FAILED/CLOSED） */
    enum class State { DISCONNECTED, CONNECTING, CONNECTED, READY, RECONNECTING, FAILED, CLOSED }

    private val _state = MutableStateFlow(State.DISCONNECTED)
    /** 当前会话状态（供 UI / MCP 工具 / 重连 watcher 观察） */
    val state: StateFlow<State> = _state.asStateFlow()

    /** 最近一次异常/断线原因（重连诊断用） */
    @Volatile
    var lastError: String? = null
        private set

    val isConnected: Boolean get() = active.get() && !ws.isClosed()

    /** 标记会话进入 READY（域启用完成，由调用方在 Runtime/Debugger/Network.enable 成功后调用） */
    fun markReady() {
        if (_state.value == State.CONNECTED) _state.value = State.READY
    }

    /** 启动接收循环（阻塞读 socket，跑在 IO 协程） */
    fun start() {
        if (!active.compareAndSet(false, true)) return
        _state.value = State.CONNECTING
        scope.launch(Dispatchers.IO) {
            // （P1-1 修复）：配合 TcpWebSocket 的读超时做死连接检测。
            // 空闲会话（无事件无命令）触发读超时 ≠ 断线：先发探活命令验证活性，
            // 连续 2 次探活无响应才判定半开/死连接并退出（触发 watcher 重连）。
            // 原实现读阻塞无超时——半开连接下 isConnected 恒 true，
            // 每条命令都要等满 20s 超时，接收协程永久挂起。
            var idleTimeouts = 0
            while (active.get() && !ws.isClosed()) {
                val message = try {
                    ws.readTextMessage()
                } catch (e: java.net.SocketTimeoutException) {
                    idleTimeouts++
                    if (idleTimeouts >= 2 || !probeAlive()) break
                    continue
                } catch (e: Exception) {
                    break
                }
                if (message == null) break
                idleTimeouts = 0
                if (message.isNotEmpty()) {
                    if (_state.value == State.CONNECTING) _state.value = State.CONNECTED
                    dispatch(message)
                }
            }
            close()
        }
    }

    /**
     * （P1-1 修复）：连接活性探活。
     * 发送一条 no-op 求值命令（负数 id 避免与 pending 表冲突，响应无人
     * 等待，dispatch 时静默丢弃）。socket 已死则发送返回 false。
     */
    private fun probeAlive(): Boolean {
        val payload = buildJsonObject {
            put("id", -1_000_000 - idCounter.incrementAndGet())
            put("method", "Runtime.evaluate")
            put("params", buildJsonObject { put("expression", "1") })
        }
        return runCatching { ws.sendText(payload.toString()) }.getOrDefault(false)
    }

    private fun dispatch(message: String) {
        val obj = runCatching { json.parseToJsonElement(message).jsonObject }.getOrNull() ?: return
        val id = obj["id"]?.jsonPrimitive?.intOrNull
        if (id != null) {
            pending.remove(id)?.complete(obj)
        } else {
            val method = obj["method"]?.jsonPrimitive?.contentOrNull ?: return
            val params = obj["params"] as? JsonObject ?: JsonObject(emptyMap())
            // flatten 模式：子会话事件在根级携带 sessionId（无 sessionId = 根会话事件）
            val sessionId = obj["sessionId"]?.jsonPrimitive?.contentOrNull
            _events.tryEmit(CdpEvent(method, params, sessionId))
        }
    }

    /** 发送 CDP 命令并等待完整响应（含 error 字段时由调用方判断） */
    suspend fun send(method: String, params: JsonObject = JsonObject(emptyMap())): JsonObject =
        send(method, params, null)

    /**
     * 发送 CDP 命令（可路由到 flatten 子会话）。
     * @param sessionId Target.setAutoAttach(flatten=true) 返回的子会话 id；null = 根会话（当前 target 本体）
     * @param retries 幂等命令（enable/setCacheDisabled 等）可传 >0 做瞬时超时重试；普通命令保持 0
     */
    suspend fun send(
        method: String,
        params: JsonObject,
        sessionId: String?,
        retries: Int = 0,
    ): JsonObject {
        if (!isConnected) throw CdpException("CDP 会话未连接")
        var attempt = 0
        while (true) {
            val id = idCounter.incrementAndGet()
            val deferred = CompletableDeferred<JsonObject>()
            pending[id] = deferred
            try {
                val payload = buildJsonObject {
                    put("id", id)
                    put("method", method)
                    put("params", params)
                    if (!sessionId.isNullOrBlank()) put("sessionId", sessionId)
                }
                if (!ws.sendText(payload.toString())) {
                    lastError = "CDP 发送失败: $method"
                    throw CdpException(lastError!!)
                }
                // （P1-2 修复）：外层协程被取消（MCP 工具超时/结构化并发取消）时
                // withTimeoutOrNull 抛 CancellationException 直接穿透，原实现的
                // pending.remove(id) 永不执行——CompletableDeferred 连同引用永久滞留
                // pending 表（高频调用下持续累积）。finally 兜底保证表项清理。
                val response = withTimeoutOrNull(REQUEST_TIMEOUT_MS) { deferred.await() }
                if (response != null) {
                    consecutiveTimeouts.set(0)
                    return response
                }
                // 响应超时：先按调用方配置重试幂等命令；随后判定会话健康度。
                val consecutive = consecutiveTimeouts.incrementAndGet()
                if (attempt < retries && isConnected) {
                    attempt++
                    delay(RETRY_DELAY_MS)
                    if (!isConnected) throw CdpException("CDP 响应超时且会话已断开: $method")
                    continue
                }
                if (consecutive >= MAX_CONSECUTIVE_TIMEOUTS) {
                    lastError = "CDP 响应连续超时($consecutive 次)，会话判定不可用: $method"
                    // fail-closed：关闭会话并让所有等待中的 pending 立刻失败，
                    // 避免后续工具持续复用"半死"连接。上层看到 CLOSED 后走重连。
                    close()
                } else {
                    lastError = "CDP 响应超时: $method"
                }
                throw CdpException(lastError!!)
            } finally {
                pending.remove(id)
            }
        }
    }

    /** 便捷调用：成功返回 result 对象，失败（协议 error / 连接异常）返回 null */
    suspend fun call(method: String, params: JsonObject = JsonObject(emptyMap())): JsonObject? =
        call(method, params, null)

    /** 便捷调用（flatten 子会话路由） */
    suspend fun call(method: String, params: JsonObject, sessionId: String?): JsonObject? {
        val response = runCatching { send(method, params, sessionId) }.getOrNull() ?: return null
        return if (response.containsKey("error")) null else response["result"]?.jsonObject
    }

    /** 便捷调用（flatten 子会话路由，可对幂等命令传 retries 做瞬时超时重试） */
    suspend fun call(method: String, params: JsonObject, sessionId: String?, retries: Int): JsonObject? {
        val response = runCatching { send(method, params, sessionId, retries) }.getOrNull() ?: return null
        return if (response.containsKey("error")) null else response["result"]?.jsonObject
    }

    /** 同 [call]，但把协议 error message 带回（供诊断） */
    suspend fun callDetailed(method: String, params: JsonObject = JsonObject(emptyMap())): Result<JsonObject> =
        callDetailed(method, params, null)

    /** 同 [callDetailed]（flatten 子会话路由） */
    suspend fun callDetailed(method: String, params: JsonObject, sessionId: String?): Result<JsonObject> =
        callDetailed(method, params, sessionId, 0)

    /** 同 [callDetailed]，可对幂等命令传 retries 做瞬时超时重试 */
    suspend fun callDetailed(
        method: String,
        params: JsonObject,
        sessionId: String?,
        retries: Int,
    ): Result<JsonObject> {
        val response = runCatching { send(method, params, sessionId, retries) }.getOrElse {
            return Result.failure(it)
        }
        val error = response["error"] as? JsonObject
        if (error != null) {
            val message = error["message"]?.jsonPrimitive?.contentOrNull ?: "unknown CDP error"
            return Result.failure(CdpException("$method: $message"))
        }
        return Result.success(response["result"]?.jsonObject ?: JsonObject(emptyMap()))
    }

    fun close() {
        active.set(false)
        ws.close()
        pending.values.forEach { it.completeExceptionally(CdpException("CDP 会话已关闭")) }
        pending.clear()
        _state.value = State.CLOSED
    }

    companion object {
        private const val REQUEST_TIMEOUT_MS = 20_000L

        // 瞬时超时重试间隔（幂等命令 setCacheDisabled/enable 系列）
        private const val RETRY_DELAY_MS = 150L

        // 连续超时达到该阈值判定会话不可用并 fail-closed，避免僵尸会话
        const val MAX_CONSECUTIVE_TIMEOUTS = 3
    }
}
