package com.webreverse.mcp.devtools.debugger

import com.webreverse.mcp.browser.engine.BrowserEngine
import com.webreverse.mcp.core.common.event.ConsoleEvent
import com.webreverse.mcp.core.common.event.DebuggerEvent
import com.webreverse.mcp.core.common.event.EventBus
import com.webreverse.mcp.core.common.model.CallFrame
import com.webreverse.mcp.core.common.model.Scope
import com.webreverse.mcp.core.common.model.ScopeType
import com.webreverse.mcp.devtools.protocol.cdp.CdpEvent
import com.webreverse.mcp.devtools.protocol.cdp.CdpScript
import com.webreverse.mcp.devtools.protocol.cdp.CdpSession
import com.webreverse.mcp.devtools.protocol.cdp.CdpHub
import com.webreverse.mcp.devtools.protocol.cdp.CdpTargetInfo
import com.webreverse.mcp.devtools.protocol.cdp.CdpTargetManager
import com.webreverse.mcp.devtools.protocol.cdp.CdpTransport
import com.webreverse.mcp.devtools.protocol.cdp.RawWebSocket
import com.webreverse.mcp.javascript.analysis.PauseLoopDetector
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/**
 * 真实 CDP 调试会话（基于 V8 Debugger domain）。
 *
 * 能力（均为 Chromium/V8 原生语义，非 evaluateJavascript 模拟）：
 * - Debugger.enable 后 scriptParsed 流（scriptId/url/sourceMapUrl 收集）
 * - setBreakpointByUrl 真源码断点（V8 执行 condition）
 * - Debugger.paused 真暂停态 callFrames（含 scopeChain objectId）
 * - stepInto/stepOver/stepOut/restartFrame/resume
 * - evaluateOnCallFrame（暂停态读取局部变量）
 * - Runtime.getProperties（解析 scope 变量）
 * - getScriptSource（取脚本源码，配合 SourceMap 工具链）
 *
 * 附注：CDP attach 后，页面内注入的 `debugger;` 语句同样触发 Debugger.paused，
 * 因此注入式断点（XHR/DOM/函数 Hook 中注入的 debugger 语句）自动升级为真断点。
 */
class CdpDebuggerSession private constructor(
    val tabId: String,
    private val session: CdpSession,
    private val scope: CoroutineScope,
    private val eventBus: EventBus,
    private val onStateChange: (String) -> Unit,
) {
    private val json = Json { ignoreUnknownKeys = true }

    private val _scripts = MutableStateFlow<List<CdpScript>>(emptyList())
    val scripts: StateFlow<List<CdpScript>> = _scripts.asStateFlow()

    /** 其他客户端（外部调试器等，经 CDP 复用枢纽接入）设置的断点（breakpointResolved 同步，MCP 侧可见） */
    class RemoteBreakpoint(
        val breakpointId: String,
        val scriptId: String,
        val line: Int,
        val url: String,
    )

    private val remoteBreakpoints = LinkedHashMap<String, RemoteBreakpoint>()

    /** 列出后端已解析的全部断点（含其他客户端设置、经本会话设置的） */
    fun listRemoteBreakpoints(): List<RemoteBreakpoint> = synchronized(remoteBreakpoints) { remoteBreakpoints.values.toList() }

    private fun scriptUrl(scriptId: String): String =
        _scripts.value.firstOrNull { it.scriptId == scriptId }?.url ?: scriptId

    /** CPU Profile 结果缓存（stopCpuProfile 后可取） */
    @Volatile
    var lastCpuProfile: JsonObject? = null
        private set

    /** 最近一次暂停的原始 callFrames（CDP 结构，含 objectId） */
    @Volatile
    var rawPauseParams: JsonObject? = null
        private set

    @Volatile
    var pauseReason: String = ""
        private set

    // ---------------- Heap Snapshot 收集 ----------------
    // 流式收集 HeapProfiler.addHeapSnapshotChunk 事件到文件（DevTools Memory 面板的
    // Heap Snapshot 底层同样基于 takeHeapSnapshot + chunk 事件流））。
    @Volatile
    private var heapOut: java.io.OutputStream? = null

    @Volatile
    private var heapFinish: kotlinx.coroutines.CompletableDeferred<Boolean>? = null

    /** 记录再采集中的快照路径，供并发防护与错误诊断 */
    @Volatile
    private var heapSnapshotActiveFile: String? = null

    /** Heap 采集互斥锁（锁对象稳定，不随 heapOut 引用变化） */
    private val heapLock = Any()

    val isConnected: Boolean get() = session.isConnected

    /**
     * Target domain 管理器（ 报告 §三/§四）：
     * Worker/ServiceWorker/iframe 统一发现与调试。
     * Target domain 不可用（旧 WebView）时为 null，工具侧降级。
     */
    val targets: CdpTargetManager by lazy { CdpTargetManager(session, scope) }

    /* * 反调试暂停循环检测 + 自动恢复执行器（报告 P0-5）。
     *
     * 过去只"感知"不"处理"：Debugger.paused 仅发事件，无限 debugger 循环会让 getter
     * 反复被暂停却无人恢复。现在把检测结果真正落地：
     *   - 同一脚本窗口内连续 pause 且非用户断点 → AUTO_RESUME：自动 Debugger.resume；
     *   - 更高/更久（MARK_ADVISE_INTERCEPT / SOURCE_PATCH）→ Debugger.setSkipAllPauses(true)
     *     从源头断掉暂停风暴，再 resume，并把该脚本标记为可执行前拦截改写。
     */
    private val pauseLoopDetector = PauseLoopDetector()

    /** 是否启用自动恢复（默认开启；关闭后仅记录、不自动 resume/skip） */
    @Volatile
    var autoRecoveryEnabled: Boolean = true

    /**
     * （P0-3 修复）：setSkipAllPauses(true) 生效标记。
     * 反调试暂停风暴触发 skip 后若不复位，本会话上所有后续断点（含用户
     * 显式设置的）将永久静默失效。新断点设置 / 主动 pause 前自动复位。
     */
    @Volatile
    private var skipAllPausesActive: Boolean = false

    /* *（P1-3 修复）：事件收集协程句柄，close 时取消，防每次连接泄漏一个协程 */
    private var eventJob: Job? = null

    /** 每次触发自动恢复时的观察回调（供 Evidence Graph / 工具层提示） */
    var onAutoRecovered: ((url: String, level: PauseLoopDetector.RecoveryLevel) -> Unit)? = null

    /**
     * Response 阶段脚本改写闭环（ 报告 §7）：
     * Fetch.getResponseBody → ScriptInterceptor.transform → Fetch.fulfillRequest。
     */
    val scriptRewrite: ScriptRewriteInterceptor by lazy { ScriptRewriteInterceptor(session, scope) }

    /** Target domain 是否已启用（targets.start 成功后置 true） */
    @Volatile
    var targetsEnabled: Boolean = false
        private set

    /** 启用 Target domain 自动发现 + auto-attach（失败返回 false：旧 WebView 不支持） */
    suspend fun enableTargets(): Boolean {
        if (targetsEnabled) return true
        val ok = targets.start()
        if (ok) targetsEnabled = true
        return ok
    }

    /** CDP 会话状态（重连 watcher 观察） */
    val sessionState get() = session.state

    /** 最近一次会话错误（重连诊断） */
    val sessionError get() = session.lastError

    fun close() {
        // （P1-3 修复）：取消事件收集协程——SharedFlow.collect 永不返回，
        // 原实现每次 connect 泄漏一个协程并强持有整个 session/脚本表引用
        eventJob?.cancel()
        eventJob = null
        // 若快照采集中断，关闭输出流并释放完成信号
        runCatching { heapOut?.flush(); heapOut?.close() }
        heapOut = null
        heapFinish?.complete(false)
        heapFinish = null
        // （P0-3 修复）：会话生命周期结束，复位 skip 标记
        skipAllPausesActive = false
        runCatching { targets.stop() }
        // Fetch.disable 尽力而为（非阻塞：会话关闭本身就是断线，disable 失败无害）
        runCatching { scope.launch { if (scriptRewrite.enabled) scriptRewrite.disable() } }
        session.close()
    }

    // ---------------- 连接 ----------------

    companion object {
        // 幂等 enable 命令的瞬时超时重试次数（配合 CdpSession 连续超时 fail-closed）
        private const val RETRY_IDEMPOTENT = 2

        /**
         * 尝试与目标 WebView 页面建立 CDP 会话。
         * 失败（无 DevTools socket / 页面不匹配 / 握手失败）返回 null，调用方降级注入式。
         */
        suspend fun connect(
            engine: BrowserEngine,
            eventBus: EventBus,
            scope: CoroutineScope,
            onStateChange: (String) -> Unit,
        ): CdpDebuggerSession? {
            val pages = CdpTransport.listPages()
            if (pages == null) {
                if (CdpTransport.lastError == null) CdpTransport.lastError = "无法获取 DevTools 页面列表"
                return null
            }
            val targetUrl = engine.currentUrl()
            val pageCandidates = pages.filter { it.type == "page" }
            if (pageCandidates.isEmpty()) {
                CdpTransport.lastError = "DevTools 已连接但无可调试页面目标（页面可能尚未加载完成，稍后重试）"
                return null
            }
            val page = pageCandidates.firstOrNull { p ->
                !targetUrl.isNullOrBlank() && p.url.isNotBlank() &&
                    (p.url == targetUrl || normalizeUrl(p.url) == normalizeUrl(targetUrl))
            } ?: pageCandidates.firstOrNull { p ->
                !targetUrl.isNullOrBlank() && p.url.contains(hostOf(targetUrl)) && hostOf(targetUrl).length > 3
            } ?: pageCandidates.first() ?: return null

            // 优先经 CDP 复用枢纽（TcpWebSocket 回环接入）：
            // 与 CdpNetworkMonitor 等进程内 MCP 会话共享同一条后端 CDP 会话，
            // 事件流互通不互踢。枢纽不可用时回退直连 unix socket
            // （独立会话，语义不变）。
            val wsPath = CdpTransport.wsPathOf(page)
            val ws: RawWebSocket? = CdpHub.connectViaHub(wsPath)
                ?: CdpTransport.connectWebSocket(wsPath = wsPath)
            if (ws == null) {
                if (CdpTransport.lastError == null) CdpTransport.lastError = "WebSocket 升级失败"
                return null
            }
            val session = CdpSession(ws, scope)
            val cdp = CdpDebuggerSession(engine.tabId, session, scope, eventBus, onStateChange)
            session.start()
            // （P0-4 修复）：必须先订阅事件流，再启用域。
            // Debugger.enable 响应返回前，V8 会立即补发所有已解析脚本的
            // scriptParsed 事件；SharedFlow(replay=0) 若晚于 enable 订阅，
            // 这批事件将被永久丢弃，导致 attach 后脚本表系统性缺失、
            // resolveScriptId 找不到脚本、断点 URL 解析失败。
            // 先订阅后 enable 是 CDP 客户端的标准顺序。
            cdp.collectEvents()
            // 域启用：失败即视为不可用。Runtime.evaluate/Debugger.enable
            // 为幂等命令，页面主线程瞬时阻塞时常发首条超时，这里做 2 次重试，
            // 配合 CdpSession 端连续超时 fail-closed，显著降低 attach 假失败。
            var runtimeResult = session.callDetailed("Runtime.enable", JsonObject(emptyMap()), null, RETRY_IDEMPOTENT)
            if (runtimeResult.isFailure) {
                // 短暂退避后重试一轮（不能直接把 retries 全交给 send，避免一个调用
                // 独占 60s；此处给一次全流程重试机会）
                runtimeResult = session.callDetailed("Runtime.enable", JsonObject(emptyMap()), null, RETRY_IDEMPOTENT)
            }
            if (runtimeResult.isFailure) {
                CdpTransport.lastError = "Runtime.enable 失败: ${runtimeResult.exceptionOrNull()?.message}"
                cdp.close()
                return null
            }
            var debuggerResult = session.callDetailed("Debugger.enable", JsonObject(emptyMap()), null, RETRY_IDEMPOTENT)
            if (debuggerResult.isFailure) {
                debuggerResult = session.callDetailed("Debugger.enable", JsonObject(emptyMap()), null, RETRY_IDEMPOTENT)
            }
            if (debuggerResult.isFailure) {
                CdpTransport.lastError = "Debugger.enable 失败: ${debuggerResult.exceptionOrNull()?.message}"
                cdp.close()
                return null
            }
            // 修复（call_stack.asyncCauses）：显式开启异步调用栈采集。
            // 裸 CDP 会话下 Chromium 不保证采集异步栈，不开此命令则 Debugger.paused
            // 只带同步 callFrames，asyncCauses 永远为空。maxDepth=32 足够覆盖常见
            // async/await / Promise.then 链（DevTools 默认 200，取 32 兼顾采集开销）。
            runCatching {
                session.call(
                    "Debugger.setAsyncCallStackDepth",
                    buildJsonObject { put("maxDepth", 32) },
                )
            }
            CdpTransport.lastError = null
            return cdp
        }

        private fun normalizeUrl(url: String): String =
            url.substringBefore('#').trimEnd('/').lowercase()

        private fun hostOf(url: String): String =
            url.substringAfter("//").substringBefore('/')
    }

    private fun collectEvents() {
        // （P1-3 修复）：持有事件收集协程，close 时取消
        eventJob?.cancel()
        eventJob = scope.launch {
            session.events.collect { event -> onEvent(event) }
        }
    }

    private fun onEvent(event: CdpEvent) {
        when (event.method) {
            "Debugger.scriptParsed" -> handleScriptParsed(event.params)
            "Debugger.breakpointResolved" -> {
                // 断点解析回调：其他客户端设置的断点在此同步
                val bpId = event.params["breakpointId"]?.jsonPrimitive?.contentOrNull ?: return
                val loc = event.params["location"]?.jsonObject
                synchronized(remoteBreakpoints) {
                    val scriptId = loc?.get("scriptId")?.jsonPrimitive?.contentOrNull ?: ""
                    val line = ((loc?.get("lineNumber")?.jsonPrimitive?.intOrNull ?: 0) + 1)
                    remoteBreakpoints[bpId] = RemoteBreakpoint(bpId, scriptId, line, scriptUrl(scriptId))
                }
            }
            "Profiler.consoleProfileFinished" -> Unit // CPU profile 完成事件（stop 时同步取）
            // 未捕获异常（含 Promise rejection）：带完整调用栈发出，
            // AI 用 event.wait console.error 即可捕获——WebView onConsoleMessage 不带栈
            "Runtime.exceptionThrown" -> handleExceptionThrown(event.params)
            // consoleAPICalled 不转发：WebView onConsoleMessage 已覆盖同源消息，转发会双份
            "Debugger.paused" -> {
                rawPauseParams = event.params
                pauseReason = event.params["reason"]?.jsonPrimitive?.contentOrNull ?: ""
                onStateChange("PAUSED")
                val frames = parseCallFrames(event.params)
                eventBus.tryEmit(
                    DebuggerEvent.Paused(tabId, pauseReason, encodeFrames(frames)),
                )
                // 命中真断点时发出 BreakpointHit（hitBreakpoints 携带 CDP breakpointId）
                val hits = event.params["hitBreakpoints"]?.jsonArray
                val firstHit = hits?.firstOrNull()?.jsonPrimitive?.contentOrNull
                if (firstHit != null && frames.isNotEmpty()) {
                    eventBus.tryEmit(
                        DebuggerEvent.BreakpointHit(tabId, firstHit, frames[0].url, frames[0].lineNumber),
                    )
                }
                // （报告 P0-5）：无限 debugger 自动恢复——把检测结果真正落地执行
                runLoopAutoRecovery(event.params, frames)
            }
            "Debugger.resumed" -> {
                onStateChange("RESUMED")
                rawPauseParams = null
                pauseReason = ""
                eventBus.tryEmit(DebuggerEvent.Resumed(tabId))
            }
            // HeapProfiler：takeHeapSnapshot 的 chunk 事件流
            "HeapProfiler.addHeapSnapshotChunk" -> {
                val chunk = event.params["chunk"]?.jsonPrimitive?.contentOrNull
                val out = heapOut ?: return
                if (chunk != null) {
                    runCatching { out.write(chunk.toByteArray(Charsets.UTF_8)) }
                }
            }
            "HeapProfiler.reportHeapSnapshotProgress" -> {
                if (event.params["finished"]?.jsonPrimitive?.contentOrNull == "true") {
                    heapFinish?.complete(true)
                }
            }
        }
    }

    /* *（报告 P0-5）：无限 debugger 循环自动恢复执行器。 */
    private fun runLoopAutoRecovery(params: JsonObject, frames: List<CallFrame>) {
        if (!autoRecoveryEnabled) return
        val url = frames.firstOrNull()?.url.orEmpty()
        if (url.isBlank()) return
        // 真断点（用户/工具显式设置）由 hitBreakpoints 标记，不视为反调试循环
        val hits = params["hitBreakpoints"]?.jsonArray
        val isUserBreakpoint = hits != null && hits.isNotEmpty()
        val level = pauseLoopDetector.onPause(url, isUserBreakpoint)
        if (isUserBreakpoint || level.severity < PauseLoopDetector.RecoveryLevel.AUTO_RESUME.severity) return

        onAutoRecovered?.invoke(url, level)
        scope.launch {
            // 三级及以上（连续暂停过密/反调试锁定）：setSkipAllPauses 从源头断掉暂停风暴
            if (level.severity >= PauseLoopDetector.RecoveryLevel.MARK_ADVISE_INTERCEPT.severity) {
                runCatching {
                    session.call("Debugger.setSkipAllPauses", buildJsonObject { put("skip", true) })
                    // （P0-3 修复）：记录 skip 已生效，后续设断点/主动暂停前自动复位，
                    // 否则当前会话所有断点永久静默失效且无任何提示
                    skipAllPausesActive = true
                }
            }
            // 打破暂停循环（AUTO_RESUME 及以上都 resume；skip-all 后 resume 立即生效）
            runCatching { session.call("Debugger.resume") }
        }
    }

    /**
     * （P0-3 修复）：确保暂停可用。
     * 若反调试自动恢复曾触发 setSkipAllPauses(true)，在设置新断点或
     * 主动暂停前先复位为 false，保证断点语义有效。
     */
    private suspend fun ensurePausesNotSkipped() {
        if (!skipAllPausesActive) return
        runCatching {
            session.call("Debugger.setSkipAllPauses", buildJsonObject { put("skip", false) })
        }
        skipAllPausesActive = false
    }

    private fun handleScriptParsed(params: JsonObject) {
        val scriptId = params["scriptId"]?.jsonPrimitive?.contentOrNull ?: return
        val url = params["url"]?.jsonPrimitive?.contentOrNull ?: ""
        val script = CdpScript(
            scriptId = scriptId,
            url = url,
            startLine = params["startLine"]?.jsonPrimitive?.intOrNull ?: 0,
            endLine = params["endLine"]?.jsonPrimitive?.intOrNull ?: 0,
            sourceMapUrl = params["sourceMapURL"]?.jsonPrimitive?.contentOrNull?.takeIf { it.isNotBlank() },
            hasSourceURL = params["hasSourceURL"]?.jsonPrimitive?.contentOrNull == "true",
            length = params["length"]?.jsonPrimitive?.contentOrNull?.toLongOrNull() ?: 0,
        )
        _scripts.value = (_scripts.value.filterNot { it.scriptId == scriptId }) + script
        eventBus.tryEmit(DebuggerEvent.ScriptParsed(tabId, scriptId, url))
    }

    /** Runtime.exceptionThrown：解析 exceptionDetails（text/exception.description/stackTrace） */
    private fun handleExceptionThrown(params: JsonObject) {
        val details = params["exceptionDetails"]?.jsonObject ?: return
        val text = details["text"]?.jsonPrimitive?.contentOrNull ?: ""
        val exception = details["exception"]?.jsonObject
        val description = exception?.get("description")?.jsonPrimitive?.contentOrNull
            ?: exception?.get("value")?.jsonPrimitive?.contentOrNull
        // description 通常已含 JS .stack（message + at frames），优先取
        val url = details["url"]?.jsonPrimitive?.contentOrNull
            ?: scriptUrl(details["scriptId"]?.jsonPrimitive?.contentOrNull ?: "")
        val line = (details["lineNumber"]?.jsonPrimitive?.intOrNull ?: -1) + 1
        val cdpStack = details["stackTrace"]?.jsonObject?.get("callFrames")?.jsonArray
            ?.joinToString("\n") { f ->
                val fo = f as? JsonObject ?: return@joinToString "    at <unknown>"
                val fn = fo["functionName"]?.jsonPrimitive?.contentOrNull?.ifBlank { "<anonymous>" } ?: "<anonymous>"
                val fUrl = fo["url"]?.jsonPrimitive?.contentOrNull?.ifBlank {
                    scriptUrl(fo["scriptId"]?.jsonPrimitive?.contentOrNull ?: "")
                }
                val fLine = (fo["lineNumber"]?.jsonPrimitive?.intOrNull ?: 0) + 1
                "    at $fn ($fUrl:$fLine)"
            }.orEmpty()
        val message = buildString {
            append(description ?: text)
            if (url.isNotBlank()) append(" @ $url:$line")
        }.take(3000)
        val stack = cdpStack.ifBlank { description?.substringAfter('\n')?.take(4000) ?: "" }
        eventBus.tryEmit(ConsoleEvent.Exception(tabId, message, stack))
    }

    // ---------------- Debugger domain ----------------

    suspend fun pause(): Boolean {
        ensurePausesNotSkipped()
        return session.call("Debugger.pause") != null
    }

    suspend fun resume(): Boolean = session.call("Debugger.resume") != null

    suspend fun stepInto(): Boolean = session.call("Debugger.stepInto") != null

    suspend fun stepOver(): Boolean = session.call("Debugger.stepOver") != null

    suspend fun stepOut(): Boolean = session.call("Debugger.stepOut") != null

    suspend fun restartFrame(): Boolean {
        val frameId = currentCallFrameIds().firstOrNull() ?: return false
        return session.call(
            "Debugger.restartFrame",
            buildJsonObject { put("callFrameId", frameId) },
        ) != null
    }

    suspend fun setPauseOnExceptions(state: String): Boolean =
        session.call(
            "Debugger.setPauseOnExceptions",
            buildJsonObject { put("state", state) },
        ) != null

    /**
     * 真源码行断点：V8 在指定位置暂停并执行 condition。
     * lineNumber/columnNumber 均为 1-based（DevTools 习惯），CDP 需要 0-based。
     *
     * columnNumber 对 minified 单行 JSVMP 是必需的：整文件几十万列时，
     * 纯行断点只会命中该行第一个可断点位（模块头部），打不进 dispatch 循环。
     *
     * @return CDP breakpointId（存入 Breakpoint.scriptId 供移除），失败返回 null
     */
    suspend fun setBreakpointByUrl(
        url: String,
        lineNumber: Int,
        columnNumber: Int? = null,
        condition: String? = null,
    ): String? {
        // （P1-6 修复）：空 URL 不再回退 urlRegex=".*"——
        // ".*" 会命中浏览器内部脚本在内的所有脚本，断点落在不可控位置，
        // 等于在随机位置下断。调用方必须提供明确的 url。
        if (url.isBlank()) return null
        ensurePausesNotSkipped()
        val params = buildJsonObject {
            put("lineNumber", (lineNumber - 1).coerceAtLeast(0))
            columnNumber?.takeIf { it > 0 }?.let { put("columnNumber", it - 1) }
            put("url", url)
            condition?.takeIf { it.isNotBlank() }?.let { put("condition", it) }
        }
        val result = session.call("Debugger.setBreakpointByUrl", params) ?: return null
        val bpId = result["breakpointId"]?.jsonPrimitive?.contentOrNull
        // （P1-6 修复）：CDP 允许"先注册后解析"，URL 不匹配时仍返回成功
        // 但 locations 为空——登记保留（V8 后续解析同名脚本时仍会命中），
        // 调用方可通过 listRemoteBreakpoints 观察是否已解析。
        val firstLoc = result["locations"]?.jsonArray?.firstOrNull()?.jsonObject
        if (bpId != null) {
            synchronized(remoteBreakpoints) {
                remoteBreakpoints[bpId] = RemoteBreakpoint(
                    bpId,
                    firstLoc?.get("scriptId")?.jsonPrimitive?.contentOrNull ?: "",
                    (firstLoc?.get("lineNumber")?.jsonPrimitive?.intOrNull ?: lineNumber - 1) + 1,
                    url,
                )
            }
        }
        return bpId
    }

    suspend fun removeBreakpoint(cdpBreakpointId: String): Boolean {
        val ok = session.call(
            "Debugger.removeBreakpoint",
            buildJsonObject { put("breakpointId", cdpBreakpointId) },
        ) != null
        if (ok) synchronized(remoteBreakpoints) { remoteBreakpoints.remove(cdpBreakpointId) }
        return ok
    }

    // ---------------- CDP 增强 ----------------

    /** Debugger.searchInContent：脚本内容搜索（不拉全量源码，返回行号+命中行） */
    suspend fun searchInContent(scriptId: String, query: String, caseSensitive: Boolean = false, limit: Int = 50): JsonArray {
        val result = session.call(
            "Debugger.searchInContent",
            buildJsonObject {
                put("scriptId", scriptId)
                put("query", query)
                put("caseSensitive", caseSensitive)
            },
        ) ?: return JsonArray(emptyList())
        val matches = result["result"]?.jsonArray ?: return JsonArray(emptyList())
        val out = mutableListOf<JsonObject>()
        for (m in matches.take(limit)) {
            val mo = m as? JsonObject ?: continue
            // 修复（响应体积失控根因）：minified/打包脚本整文件只有 1 行，
            // CDP 返回的 lineContent 即整份源码（可达数 MB）。原先原样透传，
            // search_script / re.analyze_page 单次响应被撑到 MB 级直接撑爆 AI 上下文。
            // 现在只保留命中位置附近的窗口（前后各 LINE_CONTEXT_CHARS），并标注截断。
            val line = mo["lineContent"]?.jsonPrimitive?.contentOrNull ?: ""
            val (snippet, truncated, column) = snippetAround(line, query, caseSensitive)
            out.add(
                buildJsonObject {
                    put("lineNumber", (mo["lineNumber"]?.jsonPrimitive?.intOrNull ?: 0) + 1)
                    put("lineContent", snippet)
                    if (line.length > snippet.length) {
                        put("lineContentLength", line.length)
                        put("truncated", truncated)
                        put("column", column)
                    }
                },
            )
        }
        return JsonArray(out)
    }

    /** searchInContent 命中行保留的上下文窗口（单侧字符数） */
    private val lineContextChars = 160

    /**
     * 从（可能极长的）单行源码中截取 [query] 命中位置附近的片段。
     * 返回 (片段, 是否命中了 query 定位, 命中列号 1-based)；找不到命中位置时回退行首窗口。
     */
    private fun snippetAround(line: String, query: String, caseSensitive: Boolean): Triple<String, Boolean, Int> {
        if (line.length <= lineContextChars * 2 + 8) return Triple(line, false, 1)
        val idx = if (caseSensitive) line.indexOf(query) else line.indexOf(query, ignoreCase = true)
        val anchor = if (idx >= 0) idx else 0
        val start = (anchor - lineContextChars).coerceAtLeast(0)
        // 尽量不把多字节字符/标识符切一半：向前回退到空白或边界
        var s = start
        while (s > 0 && start - s < 24 && !line[s].isWhitespace()) s--
        val end = (anchor + query.length + lineContextChars).coerceAtMost(line.length)
        val prefix = if (s > 0) "…" else ""
        val suffix = if (end < line.length) " …(line ${line.length} chars)" else ""
        return Triple(prefix + line.substring(s, end).trim() + suffix, idx >= 0, anchor + 1)
    }

    /**
     * Debugger.getPossibleBreakpoints：查询可断点位置。
     * AI 打断点前先查（行号会被 V8 自动对齐到最近的 statement 起点），
     * 返回 actualLocation 供 set_breakpoint 精确命中。
     *
     * 修复（报告 P1-1）：页面脚本被重新解析后旧 scriptId 在 V8 失效
     * （同 URL 出现 29 -> 5184 两个 ID），原实现 firstOrNull 取旧 ID，
     * CDP 调用失败被 call() 吞掉、静默返回空数组。现改为：
     *   1. 按 URL 匹配全部候选 scriptId（最新解析者优先）；
     *   2. 逐个用 callDetailed 探测，失败自动换下一个候选；
     *   3. minified 单行脚本（startLine==endLine==0）未给 column 时不带
     *      column，让 V8 返回整行全部可断点列。
     */
    suspend fun getPossibleBreakpoints(
        url: String,
        line: Int,
        column: Int? = null,
        restrictToFunction: Boolean = false,
        limit: Int = 20,
    ): JsonObject {
        val candidates = resolveScriptIds(url)
        if (candidates.isEmpty()) {
            return buildJsonObject {
                put("locations", JsonArray(emptyList()))
                put("hint", "未找到匹配脚本：${url.ifBlank { "(blank)" }}，请先 debugger.list_scripts 核对 URL")
            }
        }
        val lineNumber = (line - 1).coerceAtLeast(0)
        val columnNumber = column?.takeIf { it > 0 }?.let { it - 1 }

        var lastError: String? = null
        for (scriptId in candidates) {
            val start = buildJsonObject {
                put("lineNumber", lineNumber)
                columnNumber?.let { put("columnNumber", it) }
                put("scriptId", scriptId)
            }
            val params = buildJsonObject {
                put("start", start)
                put("restrictToFunction", restrictToFunction)
            }
            val call = session.callDetailed("Debugger.getPossibleBreakpoints", params)
            if (call.isFailure) {
                lastError = call.exceptionOrNull()?.message ?: "CDP error"
                continue
            }
            val result = call.getOrThrow()
            val locations = result["locations"]?.jsonArray ?: JsonArray(emptyList())
            val out = mutableListOf<JsonObject>()
            for (loc in locations.take(limit)) {
                val lo = loc as? JsonObject ?: continue
                val sid = lo["scriptId"]?.jsonPrimitive?.contentOrNull ?: ""
                out.add(
                    buildJsonObject {
                        put("scriptId", sid)
                        put("url", scriptUrl(sid))
                        put("lineNumber", (lo["lineNumber"]?.jsonPrimitive?.intOrNull ?: 0) + 1)
                        put("columnNumber", (lo["columnNumber"]?.jsonPrimitive?.intOrNull ?: 0) + 1)
                    },
                )
            }
            return buildJsonObject {
                put("scriptId", JsonPrimitive(scriptId))
                put("total", JsonPrimitive(locations.size))
                put("locations", JsonArray(out))
                if (out.isEmpty() && columnNumber == null) {
                    put(
                        "hint",
                        "该行未返回可断点位置：minified 单行脚本请提供精确 column（1-based，可用 debugger.search_script 定位语句后再查），" +
                            "或先用 debugger.get_script_source 拿到源码核对目标位置",
                    )
                }
            }
        }
        return buildJsonObject {
            put("locations", JsonArray(emptyList()))
            put(
                "hint",
                "候选 scriptId 均不可用（旧脚本已失效）：${lastError ?: "未知 CDP 错误"}，" +
                    "请重新 debugger.list_scripts 获取有效 scriptId",
            )
        }
    }

    /**
     * url -> 匹配的全部 scriptId（最新解析者优先）。
     * 页面脚本重新解析后 _scripts 会同时保留新旧 ID；V8 中仅最新 ID 有效，
     * 因此让调用方按"最新优先"逐个探测。
     */
    private fun resolveScriptIds(url: String): List<String> {
        if (url.isBlank()) return emptyList()
        val scripts = _scripts.value
        val exact = scripts.filter { it.url == url }
        val suffix = if (exact.isEmpty()) scripts.filter { it.url.endsWith(url) } else emptyList()
        val byName = if (exact.isEmpty() && suffix.isEmpty()) {
            scripts.filter { it.url.contains(url.substringAfterLast('/')) }
        } else emptyList()
        // 合并并去重（LinkedHashSet 保序），反转使最新解析者优先
        return LinkedHashSet((exact + suffix + byName).map { it.scriptId }).toList().asReversed()
    }

    /** Debugger.setVariableValue：暂停态修改局部变量（改完单步即可观察影响） */
    suspend fun setVariableValue(
        frameIndex: Int,
        scopeNumber: Int,
        variableName: String,
        newValue: String,
    ): Result<JsonObject> {
        val frameId = currentCallFrameIds().getOrNull(frameIndex)
            ?: return Result.failure(IllegalStateException("未处于暂停态或帧不存在"))
        // newValue 按 JS 表达式求值（数字/字符串/对象均可）
        return session.callDetailed(
            "Debugger.setVariableValue",
            buildJsonObject {
                put("callFrameId", frameId)
                put("scopeNumber", scopeNumber)
                put("variableName", variableName)
                put("newValue", buildJsonObject { put("expression", newValue) })
            },
        )
    }

    /**
     * Runtime.queryObjects：查询某构造器/原型现有的全部实例。
     * 逆向利器：找加密器实例（如 queryObjects("window.JSEncrypt") 后逐一 dump）。
     */
    suspend fun queryObjects(prototypeExpression: String, limit: Int = 20): JsonObject {
        // 先求值拿到 prototype 的 objectId
        val eval = session.call(
            "Runtime.evaluate",
            buildJsonObject {
                put("expression", "(${prototypeExpression}).prototype")
                put("returnByValue", false)
            },
        ) ?: return buildJsonObject { put("ok", false); put("error", "原型求值失败") }
        val objectId = eval["result"]?.jsonObject?.get("objectId")?.jsonPrimitive?.contentOrNull
            ?: return buildJsonObject {
                put("ok", false)
                put("error", "表达式无 prototype（非构造器或不存在）")
            }
        val query = session.call(
            "Runtime.queryObjects",
            buildJsonObject { put("prototypeObjectId", objectId) },
        ) ?: return buildJsonObject { put("ok", false); put("error", "queryObjects 调用失败") }
        val objectsId = query["objects"]?.jsonObject?.get("objectId")?.jsonPrimitive?.contentOrNull
            ?: return buildJsonObject { put("ok", false); put("error", "无实例") }
        // 展开实例数组（每个元素再展开一层给 className/description）
        val props = getObjectProperties(objectsId, limit)
        // （P1-10 修复）：临时对象用完即释放，防止远程对象表
        // 随 queryObjects 循环调用无限累积（页面内存上涨、CDP 通道变慢）
        releaseObjectQuietly(objectId)
        releaseObjectQuietly(objectsId)
        return buildJsonObject {
            put("ok", true)
            put("prototype", prototypeExpression)
            put("instances", props)
        }
    }

    /* *（P1-10 修复）：释放远程对象句柄（静默尽力而为） */
    private suspend fun releaseObjectQuietly(objectId: String?) {
        if (objectId.isNullOrBlank()) return
        runCatching {
            session.call("Runtime.releaseObject", buildJsonObject { put("objectId", objectId) })
        }
    }

    /** Runtime.callFunctionOn：在指定对象上执行函数（配合 get_object_properties 的 objectId） */
    suspend fun callFunctionOn(
        objectId: String,
        functionDeclaration: String,
        arguments: List<String> = emptyList(),
        awaitPromise: Boolean = true,
    ): JsonObject {
        val args = JsonArray(
            arguments.map { arg ->
                buildJsonObject { put("expression", arg) }
            },
        )
        val result = session.call(
            "Runtime.callFunctionOn",
            buildJsonObject {
                put("objectId", objectId)
                put("functionDeclaration", functionDeclaration)
                put("arguments", args)
                put("returnByValue", true)
                put("awaitPromise", awaitPromise)
            },
        ) ?: return buildJsonObject { put("ok", false); put("error", "callFunctionOn 调用失败") }
        val remote = result["result"]?.jsonObject ?: JsonObject(emptyMap())
        val exception = result["exceptionDetails"]?.jsonObject
        return buildJsonObject {
            put("ok", exception == null)
            put("type", remote["type"]?.jsonPrimitive?.contentOrNull ?: "")
            put("value", describeRemoteValue(remote) ?: "")
            remote["objectId"]?.jsonPrimitive?.contentOrNull?.let { put("objectId", it) }
            exception?.let {
                put(
                    "exception",
                    buildJsonObject {
                        put("text", it["text"]?.jsonPrimitive?.contentOrNull ?: "")
                        it["exception"]?.jsonObject?.get("description")?.jsonPrimitive?.contentOrNull
                            ?.let { d -> put("description", d.take(2000)) }
                    },
                )
            }
        }
    }

    /** DOMDebugger.setEventListenerBreakpoint：CDP 原生事件断点（与 DevTools Event Listener Breakpoints 同语义） */
    suspend fun setEventListenerBreakpoint(eventName: String): Boolean =
        session.call(
            "DOMDebugger.setEventListenerBreakpoint",
            buildJsonObject { put("eventName", eventName) },
        ) != null

    suspend fun removeEventListenerBreakpoint(eventName: String): Boolean =
        session.call(
            "DOMDebugger.removeEventListenerBreakpoint",
            buildJsonObject { put("eventName", eventName) },
        ) != null

    /** DOMDebugger.setXHRBreakpoint：CDP 原生 XHR/fetch 断点（请求发起前暂停，DevTools 同款） */
    suspend fun setXHRBreakpoint(urlPattern: String): Boolean =
        session.call(
            "DOMDebugger.setXHRBreakpoint",
            buildJsonObject { put("url", urlPattern) },
        ) != null

    suspend fun removeXHRBreakpoint(urlPattern: String): Boolean =
        session.call(
            "DOMDebugger.removeXHRBreakpoint",
            buildJsonObject { put("url", urlPattern) },
        ) != null

    /**
     * Debugger.setInstrumentationBreakpoint：脚本级断点。
     * beforeScriptExecution = 任何新脚本执行前暂停（拦截加密初始化/JSVMP 加载）。
     */
    suspend fun setInstrumentationBreakpoint(instrumentation: String = "beforeScriptExecution"): Boolean =
        session.call(
            "Debugger.setInstrumentationBreakpoint",
            buildJsonObject { put("instrumentation", instrumentation) },
        ) != null

    suspend fun removeInstrumentationBreakpoint(instrumentation: String = "beforeScriptExecution"): Boolean =
        session.call(
            "Debugger.removeInstrumentationBreakpoint",
            buildJsonObject { put("instrumentation", instrumentation) },
        ) != null

    // ---------------- CPU Profiler（热点函数定位） ----------------

    private var cpuProfiling = false

    /** Profiler.enable + Profiler.start：录制 CPU profile（逆向时让页面跑加密流程，热点即加密函数） */
    suspend fun startCpuProfile(): Boolean {
        if (cpuProfiling) return true
        val enabled = session.call("Profiler.enable") != null
        if (!enabled) return false
        val ok = session.call("Profiler.setSamplingInterval", buildJsonObject { put("interval", 1000) }) != null
            && session.call("Profiler.start") != null
        cpuProfiling = ok
        return ok
    }

    /**
     * Profiler.stop：结束录制并解析 profile。
     * 返回按 selfTime 排序的热点函数（含 url:line，可直接 set_breakpoint 定位）。
     */
    suspend fun stopCpuProfile(topN: Int = 25): JsonObject {
        if (!cpuProfiling) {
            return buildJsonObject { put("ok", false); put("error", "未在录制（先 start）") }
        }
        val result = session.call("Profiler.stop")
        cpuProfiling = false
        session.call("Profiler.disable")
        if (result == null) return buildJsonObject { put("ok", false); put("error", "Profiler.stop 失败") }
        val profile = result["profile"]?.jsonObject
            ?: return buildJsonObject { put("ok", false); put("error", "无 profile 数据") }
        lastCpuProfile = profile
        return analyzeCpuProfile(profile, topN)
    }

    private fun analyzeCpuProfile(profile: JsonObject, topN: Int): JsonObject {
        val nodes = profile["nodes"]?.jsonArray ?: return buildJsonObject { put("ok", false); put("error", "无 nodes") }
        val samples = profile["samples"]?.jsonArray ?: JsonArray(emptyList())
        val timeDeltas = profile["timeDeltas"]?.jsonArray ?: JsonArray(emptyList())
        // 节点表
        data class Node(val id: Int, val fn: String, val url: String, val line: Int, val parent: Int?)
        val nodeById = HashMap<Int, Node>()
        val parentOf = HashMap<Int, Int>()
        for (n in nodes) {
            val no = n as? JsonObject ?: continue
            val id = no["id"]?.jsonPrimitive?.intOrNull ?: continue
            val cf = no["callFrame"]?.jsonObject ?: JsonObject(emptyMap())
            val url = cf["url"]?.jsonPrimitive?.contentOrNull ?: ""
            nodeById[id] = Node(
                id = id,
                fn = cf["functionName"]?.jsonPrimitive?.contentOrNull?.takeIf { it.isNotBlank() } ?: "(anonymous)",
                url = url,
                line = ((cf["lineNumber"]?.jsonPrimitive?.intOrNull ?: -1) + 1),
                parent = null,
            )
            (no["children"]?.jsonArray ?: emptyList()).forEach { c ->
                (c as? JsonObject)?.get("id")?.jsonPrimitive?.intOrNull?.let { cid -> parentOf[cid] = id }
            }
        }
        // selfTime 累计
        val selfMicros = HashMap<Int, Long>()
        var prevSample: Int? = null
        for (i in samples.indices) {
            val s = samples[i].jsonPrimitive.intOrNull ?: continue
            val delta = timeDeltas.getOrNull(i)?.jsonPrimitive?.intOrNull ?: 0
            if (delta <= 0) continue
            val target = prevSample ?: s // delta 属于上一采样点（Chrome 语义）
            selfMicros[target] = (selfMicros[target] ?: 0L) + delta
            prevSample = s
        }
        val total = selfMicros.values.sum().coerceAtLeast(1L)
        val hot = selfMicros.entries
            .filter { (id, us) -> id != 0 && us > 0 && nodeById.containsKey(id) }
            .sortedByDescending { it.value }
            .take(topN)
            .mapNotNull { (id, us) ->
                val node = nodeById[id] ?: return@mapNotNull null
                buildJsonObject {
                    put("selfTimeMs", kotlin.math.round(us / 1000.0 * 10) / 10)
                    put("selfTimePct", kotlin.math.round(us * 1000.0 / total) / 10)
                    put("function", node.fn)
                    put("url", node.url)
                    put("line", node.line)
                }
            }
        return buildJsonObject {
            put("ok", true)
            put("totalSamples", samples.size)
            put("totalTimeMs", kotlin.math.round(total / 1000.0 * 10) / 10)
            put("hotFunctions", JsonArray(hot))
            put("hint", "selfTime 最高的函数即热点（加密/签名计算通常霸榜），url:line 可直接 debugger.set_breakpoint")
        }
    }

    /** 暂停态在调用帧上求值（可读局部变量/闭包变量）；非暂停态走 Runtime.evaluate */
    suspend fun evaluateOnCallFrame(expression: String, frameIndex: Int = 0): String? {
        val frameId = currentCallFrameIds().getOrNull(frameIndex)
            ?: return evaluateGlobal(expression)
        val result = session.call(
            "Debugger.evaluateOnCallFrame",
            buildJsonObject {
                put("callFrameId", frameId)
                put("expression", expression)
                put("returnByValue", true)
                put("silent", true)
            },
        ) ?: return null
        return describeRemoteValue(result["result"]?.jsonObject)
    }

    suspend fun evaluateGlobal(expression: String): String? {
        val result = session.call(
            "Runtime.evaluate",
            buildJsonObject {
                put("expression", expression)
                put("returnByValue", true)
            },
        ) ?: return null
        return describeRemoteValue(result["result"]?.jsonObject)
    }

    /**
     * Runtime.evaluate 增强版（DevTools Console 语义）：
     * - awaitPromise：支持 await fetch(...) / Promise 表达式
     * - exceptionDetails：异常文本 + 堆栈（而非静默 undefined）
     * - objectId：复杂对象返回引用，供 [getObjectProperties] 继续展开
     *
     * 失败诊断：原实现把"响应超时"与"会话断开"混报为同一句
     * "CDP 调用失败（会话未连接或超时）"，AI 客户端误判为掉线而去重新
     * attach（重建会话、丢断点）。实际多数场景是页面处于断点暂停态 /
     * 主线程阻塞导致 awaitPromise 的 Promise 永不 settle，20s 请求超时
     * 而会话仍连接。现区分：会话断开 / 暂停态超时 / 非暂停态超时（重试一次）。
     */
    suspend fun evaluateDetailed(expression: String, awaitPromise: Boolean = true): JsonObject {
        val first = runRuntimeEvaluate(expression, awaitPromise)
        if (first != null) return buildDetailedResult(first, expression, awaitPromise)
        if (!session.isConnected) {
            return buildJsonObject {
                put("ok", false)
                put("error", "CDP 会话已断开（页面跳转/WebView 重建）；自动重连进行中，可稍后重试或 debugger.attach")
            }
        }
        // 会话仍连接：说明是响应超时（页面暂停态 / 主线程阻塞 / Promise 未 settle）
        if (rawPauseParams != null) {
            return buildJsonObject {
                put("ok", false)
                put("error", "CDP 响应超时：页面处于断点暂停态，Runtime.evaluate 的 Promise 无法推进。先 debugger.resume 再求值；会话仍连接，无需重新 attach")
            }
        }
        // 非暂停态超时：瞬时繁忙大概率可重试成功；重试一次（2×20s 需工具超时 ≥45s）
        val retried = runRuntimeEvaluate(expression, awaitPromise)
        if (retried != null) return buildDetailedResult(retried, expression, awaitPromise)
        return buildJsonObject {
            put("ok", false)
            put("error", "CDP 响应超时（20s×2）：页面主线程可能阻塞或 Promise 未 settle；会话仍连接，可降 awaitPromise=false 或稍后重试")
        }
    }

    /** 执行一次 Runtime.evaluate，返回原始结果；失败（断开/超时）返回 null */
    private suspend fun runRuntimeEvaluate(expression: String, awaitPromise: Boolean): JsonObject? =
        session.call(
            "Runtime.evaluate",
            buildJsonObject {
                put("expression", expression)
                put("returnByValue", true)
                put("awaitPromise", awaitPromise)
                put("userGesture", true)
            },
        )

    /** 由原始 Runtime.evaluate 结果构建增强结果（异常详情 + objectId 展开引用） */
    private suspend fun buildDetailedResult(
        result: JsonObject,
        expression: String,
        awaitPromise: Boolean,
    ): JsonObject {
        val remote = result["result"]?.jsonObject ?: JsonObject(emptyMap())
        val exception = result["exceptionDetails"]?.jsonObject
        // （P1-8 修复）：returnByValue=true 时 CDP 不返回 objectId，
        // 注释承诺的"getObjectProperties 继续展开"链路从未生效。
        // 对象/数组结果补发一次 returnByValue=false 的求值获取 objectId。
        var objectId: String? = remote["objectId"]?.jsonPrimitive?.contentOrNull
        if (objectId == null && exception == null) {
            val t = remote["type"]?.jsonPrimitive?.contentOrNull ?: ""
            if (t == "object" || t == "array") {
                runCatching {
                    val r2 = session.call(
                        "Runtime.evaluate",
                        buildJsonObject {
                            put("expression", expression)
                            put("returnByValue", false)
                            put("awaitPromise", awaitPromise)
                            put("userGesture", true)
                            put("objectGroup", "wrmcp-eval")
                        },
                    )
                    objectId = r2?.get("result")?.jsonObject?.get("objectId")
                        ?.jsonPrimitive?.contentOrNull
                }
            }
        }
        return buildJsonObject {
            val failed = exception != null
            put("ok", !failed)
            put("type", remote["type"]?.jsonPrimitive?.contentOrNull ?: "")
            remote["subtype"]?.jsonPrimitive?.contentOrNull?.let { put("subtype", it) }
            remote["className"]?.jsonPrimitive?.contentOrNull?.let { put("className", it) }
            put("value", describeRemoteValue(remote) ?: "")
            objectId?.let { put("objectId", it) }
            if (failed) {
                put(
                    "exception",
                    buildJsonObject {
                        put("text", exception["text"]?.jsonPrimitive?.contentOrNull ?: "")
                        exception["exception"]?.jsonObject?.get("description")?.jsonPrimitive?.contentOrNull
                            ?.let { put("description", it.take(4000)) }
                        exception["exception"]?.jsonObject?.get("value")?.jsonPrimitive?.contentOrNull
                            ?.let { put("value", it) }
                    },
                )
            }
        }
    }

    /** Runtime.getProperties：按 objectId 展开远程对象（Console 里点开对象的能力） */
    suspend fun getObjectProperties(objectId: String, maxEntries: Int = 100): JsonArray {
        val result = session.call(
            "Runtime.getProperties",
            buildJsonObject {
                put("objectId", objectId)
                put("ownProperties", true)
            },
        ) ?: return JsonArray(emptyList())
        val props = result["result"]?.jsonArray ?: return JsonArray(emptyList())
        val out = mutableListOf<JsonObject>()
        for (p in props.take(maxEntries)) {
            val po = p as? JsonObject ?: continue
            val valueObj = po["value"]?.jsonObject
            out.add(
                buildJsonObject {
                    put("name", po["name"]?.jsonPrimitive?.contentOrNull ?: "")
                    put("type", valueObj?.get("type")?.jsonPrimitive?.contentOrNull ?: "")
                    valueObj?.get("subtype")?.jsonPrimitive?.contentOrNull?.let { put("subtype", it) }
                    put("value", describeRemoteValue(valueObj) ?: "")
                    valueObj?.get("objectId")?.jsonPrimitive?.contentOrNull?.let { put("objectId", it) }
                },
            )
        }
        return JsonArray(out)
    }

    suspend fun getScriptSource(scriptId: String): String? {
        val result = session.call(
            "Debugger.getScriptSource",
            buildJsonObject { put("scriptId", scriptId) },
        ) ?: return null
        return result["scriptSource"]?.jsonPrimitive?.contentOrNull
    }

    // ---------------- DevTools 能力补齐 ----------------

    /**
     * 异步调用栈：遍历 Debugger.paused 的 asyncStackTrace 链（逐级向上跟随 parent）。
     * DevTools 默认开启 async stack traces；CDP 的 asyncStackTrace 形如
     *   { callFrames:[...], description:"Promise.then", parent:{ callFrames:[...] } }。
     * 每条 Cause 记录其来源（如 await / Promise.then / setInterval）与该异步段的调用帧。
     * 纯同步帧栈（无 asyncStackTrace）时返回空数组。
     *
     * 修复：paused 事件可能只带 asyncStackTraceId（跨上下文/截断的异步栈），
     * 此时经 Debugger.getStackTrace 解析出完整异步栈后再跟随 parent/parentId 链；
     * 之前只解析内联 asyncStackTrace，遇到 asyncStackTraceId 直接返回空数组。
     */
    suspend fun asyncStackTraceJson(maxCauses: Int = 8, limitPerCause: Int = 40): JsonArray {
        val params = rawPauseParams ?: return JsonArray(emptyList())
        var chain: JsonObject? = params["asyncStackTrace"]?.jsonObject
        // 无内联 asyncStackTrace 时尝试 asyncStackTraceId（Debugger.getStackTrace 取回完整栈）
        if (chain == null) {
            chain = params["asyncStackTraceId"]?.jsonObject?.let { resolveStackTraceById(it) }
        }
        if (chain == null) return JsonArray(emptyList())
        val scriptUrlById = _scripts.value.associate { it.scriptId to it.url }
        val out = mutableListOf<JsonObject>()
        var causes = 0
        while (chain != null && causes < maxCauses) {
            val causeDesc = chain["description"]?.jsonPrimitive?.contentOrNull
                ?.ifBlank { "async" } ?: "async"
            val frames = chain["callFrames"]?.jsonArray ?: JsonArray(emptyList())
            val frameObjs = frames.take(limitPerCause).mapNotNull { f ->
                val fo = f as? JsonObject ?: return@mapNotNull null
                val scriptId = fo["scriptId"]?.jsonPrimitive?.contentOrNull ?: ""
                buildJsonObject {
                    put(
                        "functionName",
                        fo["functionName"]?.jsonPrimitive?.contentOrNull?.ifBlank { "(anonymous)" } ?: "(anonymous)",
                    )
                    put("url", scriptUrlById[scriptId] ?: fo["url"]?.jsonPrimitive?.contentOrNull ?: scriptId)
                    put("lineNumber", (fo["lineNumber"]?.jsonPrimitive?.intOrNull ?: 0) + 1)
                    put("columnNumber", (fo["columnNumber"]?.jsonPrimitive?.intOrNull ?: 0) + 1)
                }
            }
            if (frameObjs.isNotEmpty()) {
                out.add(
                    buildJsonObject {
                        put("cause", causeDesc)
                        put("callFrames", JsonArray(frameObjs))
                    },
                )
            }
            // parent 可能是内联 StackTrace，也可能是跨上下文截断的 parentId（StackTraceId）
            val parent = chain["parent"]?.jsonObject
            chain = parent ?: chain["parentId"]?.jsonObject?.let { resolveStackTraceById(it) }
            causes++
        }
        return JsonArray(out)
    }

    /**
     * 修复：按 StackTraceId（{id, debuggerId}）经 Debugger.getStackTrace 解析异步栈。
     * paused 事件在跨上下文（如 Worker）或异步栈被截断时只给 asyncStackTraceId，
     * 需一次额外 CDP 调用取回完整栈；解析失败返回 null（由调用方降级为空，不抛异常）。
     */
    private suspend fun resolveStackTraceById(idObj: JsonObject): JsonObject? {
        val id = idObj["id"]?.jsonPrimitive?.contentOrNull ?: return null
        return runCatching {
            session.call(
                "Debugger.getStackTrace",
                buildJsonObject {
                    put(
                        "stackTraceId",
                        buildJsonObject {
                            put("id", id)
                            idObj["debuggerId"]?.let { put("debuggerId", it) }
                        },
                    )
                },
            )?.get("stackTrace")?.jsonObject
        }.getOrNull()
    }

    /**
     * 按精确位置（scriptId + 行 + 列）下断点：Debugger.setBreakpoint（按 ID 定位，非 byUrl）。
     * 供 pretty_print 的格式化行映射回原始坐标后落断点。
     */
    suspend fun setBreakpointByLocation(
        scriptId: String,
        lineNumber: Int,
        columnNumber: Int = 1,
        condition: String? = null,
    ): String? {
        if (scriptId.isBlank()) return null
        ensurePausesNotSkipped()
        val params = buildJsonObject {
            put(
                "location",
                buildJsonObject {
                    put("scriptId", scriptId)
                    put("lineNumber", (lineNumber - 1).coerceAtLeast(0))
                    if (columnNumber > 0) put("columnNumber", columnNumber - 1)
                },
            )
            condition?.takeIf { it.isNotBlank() }?.let { put("condition", it) }
        }
        val result = session.call("Debugger.setBreakpoint", params) ?: return null
        val bpId = result["breakpointId"]?.jsonPrimitive?.contentOrNull
        val loc = result["actualLocation"]?.jsonObject
        if (bpId != null) {
            synchronized(remoteBreakpoints) {
                remoteBreakpoints[bpId] = RemoteBreakpoint(
                    bpId,
                    loc?.get("scriptId")?.jsonPrimitive?.contentOrNull ?: scriptId,
                    (loc?.get("lineNumber")?.jsonPrimitive?.intOrNull ?: lineNumber - 1) + 1,
                    scriptUrl(scriptId),
                )
            }
        }
        // 便于调用方展示实际落点与命中 URL
        actualBreakpointLocation = Triple(bpId, loc, scriptUrl(scriptId))
        return bpId
    }

    /** 最近一次 setBreakpointByLocation 的实际落点（URL/原始坐标） */
    @Volatile
    var actualBreakpointLocation: Triple<String?, JsonObject?, String?>? = null
        private set

    /**
     * Debugger.setBlackboxPatterns：把匹配 URL 的脚本标记为黑盒（DevTools "Blackbox Script"）。
     * 空列表 = 清空黑盒配置（恢复所有脚本可单步）。
     */
    suspend fun setBlackboxPatterns(patterns: List<String>): Boolean {
        val p = patterns.filter { it.isNotBlank() }
        val call = session.call(
            "Debugger.setBlackboxPatterns",
            buildJsonObject { put("patterns", JsonArray(p.map { JsonPrimitive(it) })) },
        )
        // 空数组需显式调用清除；调用返回非 null（含空 responses）即视为成功
        return call != null
    }

    /** 当前已设置的黑盒 URL 正则（工具层维护镜像） */
    @Volatile
    var blackboxPatterns: List<String> = emptyList()

    /**
     * 堆内存用量：Runtime.getHeapUsage（JS 堆）+ Memory.getDOMCounters（DOM 节点/事件）。
     * DevTools Memory 面板的实时数字即二者组合。
     */
    suspend fun heapUsage(): JsonObject {
        val heap = session.call("Runtime.getHeapUsage")
        val dom = session.call("Memory.getDOMCounters")
        var used = heap?.get("usedSize")?.jsonPrimitive?.contentOrNull?.toLongOrNull()
        var total = heap?.get("totalSize")?.jsonPrimitive?.contentOrNull?.toLongOrNull()
        // WebView 缺 Runtime.getHeapUsage 时降级读 performance.memory
        // （非标准但 WebView 常可用），避免裸 ok:false 无从下手。
        if (used == null) {
            val pm = session.call(
                "Runtime.evaluate",
                buildJsonObject {
                    put("expression", "(()=>{const m=(window.performance&&performance.memory)||null;if(!m)return '';return m.usedJSHeapSize+','+m.jsHeapSizeLimit})()")
                    put("returnByValue", true)
                },
            )
            pm?.get("result")?.jsonObject?.get("value")?.jsonPrimitive?.contentOrNull
                ?.takeIf { it.contains(',') }?.let { pair ->
                    val (u, t) = pair.split(',')
                    used = u.toLongOrNull()
                    total = t.toLongOrNull()
                }
        }
        val domUsed = dom?.get("documents")?.jsonPrimitive?.intOrNull != null
        return buildJsonObject {
            put("ok", used != null || domUsed)
            if (used != null) put("usedMB", kotlin.math.round(used / 1048576.0 * 10) / 10)
            if (total != null) put("totalMB", kotlin.math.round(total / 1048576.0 * 10) / 10)
            if (used != null && total != null && total > 0) put("usedPct", kotlin.math.round(used * 1000.0 / total) / 10)
            dom?.let { d ->
                put("documents", d["documents"]?.jsonPrimitive?.intOrNull ?: 0)
                put("nodes", d["nodes"]?.jsonPrimitive?.intOrNull ?: 0)
                put("jsEventListeners", d["jsEventListeners"]?.jsonPrimitive?.intOrNull ?: 0)
            }
            if (used == null && dom?.get("documents")?.jsonPrimitive?.intOrNull == null) {
                // Android WebView 通常缺少 Runtime.getHeapUsage / Memory.getDOMCounters
                // 这两个 domain（Chrome DevTools 而非 WebView 才完整暴露）。返回清晰受限提示，
                // 避免调用方拿到裸 ok:false 无从下手。
                put(
                    "error",
                    "WebView 未暴露 HeapProfiler/Memory domain（Runtime.getHeapUsage、performance.memory 与 Memory.getDOMCounters " +
                        "均不可用）。完整对象图需 Chrome 调试通道；JS 堆用量可尝试 js.evaluate 读取 performance.memory。",
                )
            }
            put(
                "hint",
                "usedMB 为 JS 堆实占；完整堆结构用 memory.heap_snapshot 落到文件（含对象图/引用链）",
            )
        }
    }

    /**
     * Heap Snapshot：HeapProfiler.takeHeapSnapshot 流式收集 chunk 事件，写入
     * [destPath]（推荐 .heapsnapshot）。等价于 DevTools 导出 .heapsnapshot，可离线解析
     * 对象图/保留引用链。返回文件字节数与路径；超大堆可能超过 30s，超时时已写部分返回。
     */
    suspend fun takeHeapSnapshot(destPath: String, timeoutMs: Long = 120_000L): JsonObject {
        // 启发式快速失败：已有快照采集中则无需 enable（避免在临界区做悬挂调用）
        val alreadyActive = synchronized(heapLock) { heapOut != null }
        if (alreadyActive) {
            return buildJsonObject {
                put("ok", false)
                put("error", "已有快照采集中（$heapSnapshotActiveFile），请先等待完成")
            }
        }
        val ready = session.call("HeapProfiler.enable") != null
        if (!ready) return buildJsonObject {
            put("ok", false)
            put("error", "HeapProfiler.enable 失败（Android WebView 通常不暴露 HeapProfiler domain，无法导出 .heapsnapshot；建议改用 memory.heap_usage 看堆用量，或用 js.evaluate 读取 performance.memory）")
        }
        // 临界区仅做字段初始化，绝不持有锁做挂起调用
        val canStart = synchronized(heapLock) {
            if (heapOut != null) {
                null
            } else {
                val file = java.io.File(destPath).apply { parentFile?.mkdirs() }
                val sink: java.io.OutputStream = java.io.FileOutputStream(file)
                heapOut = sink
                heapSnapshotActiveFile = destPath
                heapFinish = kotlinx.coroutines.CompletableDeferred<Boolean>()
                true
            }
        } == true
        if (!canStart) {
            return buildJsonObject {
                put("ok", false)
                put("error", "已有快照采集中（$heapSnapshotActiveFile），请先等待完成")
            }
        }
        // 修复：reportProgress 必须为 true——完成信号来自
        // HeapProfiler.reportHeapSnapshotProgress(finished=true)；为 false 时后端不发该事件，
        // 快照其实已写完却永远等不到完成信号，只能靠超时退出（实测 8.7MB 文件已写但报超时）。
        val started = session.call(
            "HeapProfiler.takeHeapSnapshot",
            buildJsonObject {
                put("reportProgress", true)
                put("captureNumericValue", true)
            },
        ) != null
        if (!started) {
            synchronized(heapLock) {
                runCatching { heapOut?.close() }
                heapOut = null
                heapFinish?.complete(false)
                heapFinish = null
            }
            return buildJsonObject { put("ok", false); put("error", "takeHeapSnapshot 调用失败") }
        }
        // 修复：超时由参数化 timeoutMs 控制（默认 120s），与 MCP 工具声明一致
        val finished = kotlinx.coroutines.withTimeoutOrNull(timeoutMs) {
            heapFinish?.await() ?: false
        } ?: false
        val sink = synchronized(heapLock) {
            heapOut.also { heapOut = null }
        }
        // 修复：去除重复 close（原实现 close 调了两次）
        runCatching { sink?.flush(); sink?.close() }
        heapFinish = null
        runCatching { session.call("HeapProfiler.disable") }
        val size = runCatching { java.io.File(destPath).length() }.getOrDefault(0L)
        if (!finished || size <= 0L) {
            return buildJsonObject {
                put("ok", false)
                put("error", "快照未完成（${timeoutMs / 1000}s 超时或文件为空），已写文件 $size 字节（堆可能过大，可用 memory.heap_usage 监控或放宽超时）")
                put("file", destPath)
                put("bytes", size)
            }
        }
        val meta = parseHeapSnapshotMeta(java.io.File(destPath))
        val valid = meta != null && meta.first >= 0L
        return buildJsonObject {
            put("ok", valid)
            put("file", destPath)
            put("bytes", size)
            meta?.let { put("nodeCount", it.first); put("edgeCount", it.second) }
            if (!valid) put("error", "快照文件已生成但文件头校验异常（node_count 缺失，可能写入中断，建议重试）")
            put("hint", "该文件即 DevTools 导出的 .heapsnapshot 格式；按 bytes 尽可能大、文件头含 snapshot JSON 则为有效快照")
        }
    }

    /** 解析 .heapsnapshot 文件头的 node/edge 计数（尽力而为，失败返回 null） */
    private fun parseHeapSnapshotMeta(file: java.io.File): Pair<Long, Long>? {
        return runCatching {
            val head = file.inputStream().use { ins ->
                val bytes = ByteArray(4096)
                var n = ins.read(bytes); if (n <= 0) "" else String(bytes, 0, n, Charsets.UTF_8)
            }
            // node_count/edge_count 出现在 "snapshot" 对象内，但 meta 里含嵌套花括号，
            // 不能用 [^}]* 跨过，直接按键名匹配（宽容起见搜全文头任意 offset）
            val nodeCount = Regex("\"node_count\"\\s*[:]\\s*(\\d+)").find(head)?.groupValues?.get(1)?.toLongOrNull()
            val edgeCount = Regex("\"edge_count\"\\s*[:]\\s*(\\d+)").find(head)?.groupValues?.get(1)?.toLongOrNull()
            Pair(nodeCount ?: -1L, edgeCount ?: -1L)
        }.getOrNull()
    }

    /** 暂停态调用帧的 scopeChain 解析（Runtime.getProperties 读取真实变量） */
    suspend fun scopesOfFrame(frameIndex: Int = 0): List<Scope> {
        val params = rawPauseParams ?: return emptyList()
        val frames = params["callFrames"]?.jsonArray ?: return emptyList()
        val frame = frames.getOrNull(frameIndex)?.jsonObject ?: return emptyList()
        val scopeChain = frame["scopeChain"]?.jsonArray ?: return emptyList()
        return scopeChain.mapNotNull { sc ->
            val scopeObj = sc as? JsonObject ?: return@mapNotNull null
            val type = scopeObj["type"]?.jsonPrimitive?.contentOrNull ?: "global"
            val name = scopeObj["name"]?.jsonPrimitive?.contentOrNull?.takeIf { it.isNotBlank() }
                ?: scopeObj["object"]?.jsonObject?.get("className")?.jsonPrimitive?.contentOrNull
                ?: type
            val objectId = scopeObj["object"]?.jsonObject?.get("objectId")?.jsonPrimitive?.contentOrNull
            val variables = objectId?.let { fetchProperties(it) } ?: emptyMap()
            Scope(
                type = runCatching { ScopeType.valueOf(type.uppercase()) }
                    .getOrDefault(ScopeType.GLOBAL),
                name = name,
                variables = variables,
            )
        }
    }

    /** 暂停态 frame[0] 的 LOCAL scope 变量（真实局部变量，非 window 采样） */
    suspend fun localsOfFrame(frameIndex: Int = 0): Map<String, String> {
        val scopes = scopesOfFrame(frameIndex)
        val local = scopes.filter { it.type == ScopeType.LOCAL || it.type == ScopeType.CLOSURE }
        if (local.isEmpty()) return emptyMap()
        // 多个 local/closure scope 依序合并（内层遮蔽外层）
        val merged = LinkedHashMap<String, String>()
        local.reversed().forEach { merged.putAll(it.variables) }
        return merged
    }

    // ---------------- 内部工具 ----------------

    private suspend fun fetchProperties(objectId: String): Map<String, String> {
        val result = session.call(
            "Runtime.getProperties",
            buildJsonObject {
                put("objectId", objectId)
                put("ownProperties", true)
            },
        ) ?: return emptyMap()
        val props = result["result"]?.jsonArray ?: return emptyMap()
        val out = LinkedHashMap<String, String>()
        for (p in props) {
            val po = p as? JsonObject ?: continue
            val name = po["name"]?.jsonPrimitive?.contentOrNull ?: continue
            val valueObj = po["value"]?.jsonObject
            val rendered = describeRemoteValue(valueObj) ?: ""
            out[name] = rendered.take(300)
            if (out.size >= 64) break // 变量数量上限，防大对象拖垮会话
        }
        return out
    }

    private fun describeRemoteValue(value: JsonObject?): String? {
        value ?: return null
        val type = value["type"]?.jsonPrimitive?.contentOrNull ?: return ""
        return when {
            value.containsKey("value") -> {
                // （P0-1 修复）：
                // 1) returnByValue=true 下对象/数组结果的 "value" 是 JsonObject/JsonArray，
                //    原实现用 jsonPrimitive 访问会抛 IllegalStateException（jsonPrimitive 对
                //    非原始类型直接报错），导致所有对象求值（evaluateWatch / runtimeEvaluate /
                //    callFunctionOn / getObjectProperties / fetchProperties）直接崩溃。
                //    改为按实际元素类型取值，对象/数组序列化为合法 JSON 文本。
                // 2) 字符串结果由单引号包装改为合法 JSON 双引号转义：原实现使
                //    collectVmpTrace 的 json.parseToJsonElement 必然失败（单引号开头
                //    不是合法 JSON），整条 VMP 采样追踪链路 100% 返回 TRACE_PARSE_ERROR。
                val rawEl = value["value"]
                val raw = when (rawEl) {
                    null -> null
                    is kotlinx.serialization.json.JsonPrimitive -> rawEl.contentOrNull
                    else -> rawEl.toString()
                }
                if (type == "string") {
                    val s = (raw ?: "")
                        .replace("\\", "\\\\")
                        .replace("\"", "\\\"")
                        .replace("\n", "\\n")
                        .replace("\r", "\\r")
                        .replace("\t", "\\t")
                    "\"$s\""
                } else {
                    raw ?: type
                }
            }
            value.containsKey("description") -> value["description"]?.jsonPrimitive?.contentOrNull ?: type
            else -> type
        }
    }

    private fun currentCallFrameIds(): List<String> {
        val frames = rawPauseParams?.get("callFrames")?.jsonArray ?: return emptyList()
        return frames.mapNotNull { f ->
            (f as? JsonObject)?.get("callFrameId")?.jsonPrimitive?.contentOrNull
        }
    }

    /** CDP callFrames -> 领域模型（lineNumber/columnNumber 转 1-based） */
    internal fun parseCallFrames(params: JsonObject): List<CallFrame> {
        val frames = params["callFrames"]?.jsonArray ?: return emptyList()
        val scriptUrlById = _scripts.value.associate { it.scriptId to it.url }
        return frames.mapNotNull { f ->
            val fo = f as? JsonObject ?: return@mapNotNull null
            val location = fo["location"]?.jsonObject ?: JsonObject(emptyMap())
            val scriptId = location["scriptId"]?.jsonPrimitive?.contentOrNull ?: ""
            CallFrame(
                callFrameId = fo["callFrameId"]?.jsonPrimitive?.contentOrNull ?: "",
                functionName = fo["functionName"]?.jsonPrimitive?.contentOrNull ?: "(anonymous)",
                url = scriptUrlById[scriptId] ?: scriptId,
                lineNumber = (location["lineNumber"]?.jsonPrimitive?.intOrNull ?: 0) + 1,
                columnNumber = (location["columnNumber"]?.jsonPrimitive?.intOrNull ?: 0) + 1,
                scopeChain = (fo["scopeChain"]?.jsonArray ?: emptyList()).mapNotNull { sc ->
                    val sco = sc as? JsonObject ?: return@mapNotNull null
                    val type = sco["type"]?.jsonPrimitive?.contentOrNull ?: "global"
                    Scope(
                        type = runCatching { ScopeType.valueOf(type.uppercase()) }
                            .getOrDefault(ScopeType.GLOBAL),
                        name = sco["name"]?.jsonPrimitive?.contentOrNull?.takeIf { it.isNotBlank() } ?: type,
                    )
                },
                thisObject = describeRemoteValue(fo["this"]?.jsonObject) ?: "",
            )
        }
    }

    private fun encodeFrames(frames: List<CallFrame>): String =
        runCatching { json.encodeToString(kotlinx.serialization.builtins.ListSerializer(CallFrame.serializer()), frames) }.getOrDefault("[]")
}
