package com.webreverse.mcp.devtools.debugger

import com.webreverse.mcp.browser.engine.BrowserEngine
import com.webreverse.mcp.browser.engine.util.JsScripts
import com.webreverse.mcp.core.common.event.DebuggerEvent
import com.webreverse.mcp.core.common.event.EventBus
import com.webreverse.mcp.core.common.util.AppError
import com.webreverse.mcp.core.common.model.Breakpoint
import com.webreverse.mcp.core.common.model.BreakpointType
import com.webreverse.mcp.core.common.model.CallFrame
import com.webreverse.mcp.core.common.model.DebuggerState
import com.webreverse.mcp.core.common.model.Scope
import com.webreverse.mcp.core.common.model.WatchExpression
import com.webreverse.mcp.core.common.util.AppResult
import com.webreverse.mcp.core.common.util.Ids
import com.webreverse.mcp.devtools.protocol.cdp.CdpScript
import com.webreverse.mcp.devtools.protocol.cdp.CdpSession
import com.webreverse.mcp.devtools.protocol.cdp.CdpTargetInfo
import com.webreverse.mcp.javascript.analysis.OriginalLocation
import com.webreverse.mcp.javascript.analysis.VmpTraceAnalyzer
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/**
 * JavaScript 调试器管理器。
 *
 * 重构：双后端架构。
 * - 首选后端：CDP（Chrome DevTools Protocol）——通过 WebView DevTools socket 建立
 *   真实 V8 Debugger 会话。断点/单步/调用栈/作用域/求值全部是 Chromium 原生语义。
 * - 降级后端：注入式（debugger 语句 + 函数 Hook）。CDP 不可用时保持工具可用；
 *   CDP attach 后，注入的 debugger; 语句同样触发 Debugger.paused（自动升级为真断点）。
 */
class DebuggerManager(
    private val eventBus: EventBus,
) {
    private val json = Json { ignoreUnknownKeys = true }
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val _state = MutableStateFlow(DebuggerState.DETACHED)
    val state: StateFlow<DebuggerState> = _state.asStateFlow()

    private val _breakpoints = MutableStateFlow<List<Breakpoint>>(emptyList())
    val breakpoints: StateFlow<List<Breakpoint>> = _breakpoints.asStateFlow()

    private val _watchExpressions = MutableStateFlow<List<WatchExpression>>(emptyList())
    val watchExpressions: StateFlow<List<WatchExpression>> = _watchExpressions.asStateFlow()

    private val _callFrames = MutableStateFlow<List<CallFrame>>(emptyList())
    val callFrames: StateFlow<List<CallFrame>> = _callFrames.asStateFlow()

    /** 当前使用的调试后端：cdp / injected / none */
    @Volatile
    var backend: String = "none"
        private set

    private val cdpSessions = java.util.concurrent.ConcurrentHashMap<String, CdpDebuggerSession>()

    /** attach 顺序记录（最近 attach 的 Tab 优先），供调试工具定位调试目标 */
    private val attachOrder = java.util.concurrent.CopyOnWriteArrayList<String>()

    private fun cdpOf(engine: BrowserEngine): CdpDebuggerSession? =
        cdpSessions[engine.tabId]?.takeIf { it.isConnected }

    // ---------------- pretty_print 缓存 ----------------
    // scriptId → 每个格式化行（1-based→下标-1）对应原始 (line, col)（1-based）。
    // 由 prettyPrint 填充；setPrettyBreakpoint 据此把格式化行映射回原始坐标下断点。
    private val prettyCache = java.util.concurrent.ConcurrentHashMap<String, kotlinx.serialization.json.JsonArray>()

    /**
     * 已建立 CDP 会话且仍连接的 tabId（最近 attach 优先）。
     * 调试工具据此锚定调试目标：不随"活跃 Tab"漂移——多 Tab 场景下用户切换
     * 活跃 Tab 后，调试工具仍应作用于 attach 的目标页，否则会打到非调试
     * 目标页面（断点互不可见的根因之一）。
     */
    fun connectedTabIds(): List<String> =
        attachOrder.asReversed().filter { cdpSessions[it]?.isConnected == true }

    // ---------------- 自动重连 + 断点恢复（报告 §17） ----------------

    /** tabId → attach 时使用的 engine（自动重连需要重连到同一页面） */
    private val enginesByTab = java.util.concurrent.ConcurrentHashMap<String, BrowserEngine>()

    /** tabId → 会话状态 watcher Job */
    private val watcherJobs = java.util.concurrent.ConcurrentHashMap<String, Job>()

    /** tabId → 重连尝试计数 */
    private val reconnectAttempts = java.util.concurrent.ConcurrentHashMap<String, Int>()

    /** 显式 detach 的 tab（不触发自动重连） */
    private val detachedTabs: MutableSet<String> =
        java.util.Collections.newSetFromMap(java.util.concurrent.ConcurrentHashMap())

    /** 自动重连开关（默认开；用户显式 detach 或工具关闭时置 false） */
    @Volatile
    var autoReconnectEnabled: Boolean = true

    /** 启动会话状态 watcher：意外断线（CLOSED）时自动重连并恢复断点 */
    private fun startWatcher(tabId: String) {
        watcherJobs.remove(tabId)?.cancel()
        val engine = enginesByTab[tabId] ?: return
        val cdp = cdpSessions[tabId] ?: return
        watcherJobs[tabId] = scope.launch {
            cdp.sessionState.collect { state ->
                if ((state == CdpSession.State.CLOSED || state == CdpSession.State.FAILED) &&
                    autoReconnectEnabled && tabId !in detachedTabs
                ) {
                    watcherJobs.remove(tabId)?.cancel()
                    scheduleReconnect(tabId, engine)
                }
            }
        }
    }

    /**
     * 自动重连：指数退避（1.5s/3s/4.5s/6s/7.5s），最多 5 次。
     * 重连成功后：
     * - 重建 Target domain（enableTargets）
     * - 等待脚本重新解析（scriptParsed 流）后恢复断点
     * - 发出 cdp-reconnected 事件（UI / MCP 工具可见）
     */
    private fun scheduleReconnect(tabId: String, engine: BrowserEngine) {
        val attempt = (reconnectAttempts[tabId] ?: 0) + 1
        reconnectAttempts[tabId] = attempt
        if (attempt > MAX_RECONNECT_ATTEMPTS) {
            _state.value = DebuggerState.DETACHED
            eventBus.tryEmit(DebuggerEvent.Resumed(tabId))
            return
        }
        scope.launch {
            delay(1500L * attempt)
            if (!autoReconnectEnabled || tabId in detachedTabs) return@launch
            val cdp = runCatching {
                CdpDebuggerSession.connect(engine, eventBus, scope) { stateName ->
                    runCatching { _state.value = DebuggerState.valueOf(stateName) }
                }
            }.getOrNull()
            if (cdp != null) {
                cdpSessions[tabId] = cdp
                reconnectAttempts.remove(tabId)
                cdp.enableTargets()
                eventBus.tryEmit(DebuggerEvent.ScriptParsed(tabId, "", "cdp-reconnected"))
                // 等待 scriptParsed 流（脚本重新解析后断点才能恢复）
                delay(2000)
                recoverBreakpoints(tabId, cdp)
                startWatcher(tabId)
            } else {
                scheduleReconnect(tabId, engine)
            }
        }
    }

    /**
     * 断点恢复：重连后对 LINE/LOGPOINT 断点重新 setBreakpointByUrl。
     * 恢复成功更新 scriptId（CDP breakpointId 每次会话不同），失败保留原记录等下次重连。
     */
    private suspend fun recoverBreakpoints(tabId: String, cdp: CdpDebuggerSession) {
        val recoverable = _breakpoints.value.filter {
            it.tabId == tabId && it.lineNumber > 0 &&
                (it.type == BreakpointType.LINE || it.type == BreakpointType.LOGPOINT)
        }
        if (recoverable.isEmpty()) return
        var ok = 0
        _breakpoints.value = _breakpoints.value.map { bp ->
            if (bp in recoverable) {
                val cond = if (bp.type == BreakpointType.LOGPOINT && !bp.logExpression.isNullOrBlank()) {
                    "(console.log(${bp.logExpression}), false)"
                } else {
                    bp.condition
                }
                val cdpId = cdp.setBreakpointByUrl(bp.url, bp.lineNumber, null, cond)
                if (cdpId != null) {
                    ok++
                    bp.copy(scriptId = cdpId)
                } else {
                    bp
                }
            } else {
                bp
            }
        }
        if (ok > 0) {
            eventBus.tryEmit(DebuggerEvent.ScriptParsed(tabId, "", "breakpoints-recovered:$ok"))
        }
    }

    // ---------------- Target domain 门面（Worker/SW/iframe 统一管理） ----------------

    /** 列出全部 target（自动启用 Target domain；旧 WebView 返回空表） */
    suspend fun listTargets(engine: BrowserEngine): List<CdpTargetInfo> {
        val cdp = cdpOf(engine) ?: return emptyList()
        if (!cdp.targetsEnabled) cdp.enableTargets()
        return if (cdp.targetsEnabled) cdp.targets.targetsSnapshot() else emptyList()
    }

    /** 在指定 target（Worker/SW 子会话）上执行表达式 */
    suspend fun evaluateOnTarget(engine: BrowserEngine, targetId: String, expression: String): AppResult<JsonObject> {
        val cdp = cdpOf(engine)
            ?: return AppResult.failure(AppError("CDP_NOT_ATTACHED", "需要 CDP 调试会话，请先 debugger.attach"))
        if (!cdp.targetsEnabled) {
            val enabled = cdp.enableTargets()
            if (!enabled) return AppResult.failure(AppError("TARGET_DOMAIN_UNAVAILABLE", "当前 WebView 不支持 Target domain"))
        }
        return AppResult.success(cdp.targets.evaluateOnTarget(targetId, expression))
    }

    /** 对 target 启用 Debugger domain（worker 内断点/脚本可见） */
    suspend fun enableDebuggerOnTarget(engine: BrowserEngine, targetId: String): AppResult<Boolean> {
        val cdp = cdpOf(engine)
            ?: return AppResult.failure(AppError("CDP_NOT_ATTACHED", "需要 CDP 调试会话"))
        val ok = cdp.targets.enableDebuggerOnTarget(targetId)
        return if (ok) AppResult.success(true)
        else AppResult.failure(AppError("TARGET_DEBUGGER_FAILED", "enableDebuggerOnTarget 失败（target 未 attach？）"))
    }

    /** 列出 target 内已解析脚本（需先 enableDebuggerOnTarget） */
    suspend fun listTargetScripts(engine: BrowserEngine, targetId: String): List<CdpScript> {
        val cdp = cdpOf(engine) ?: return emptyList()
        return cdp.targets.scriptsOnTarget(targetId)
    }

    /** 手动 attach 指定 target（返回 flatten sessionId） */
    suspend fun attachToTarget(engine: BrowserEngine, targetId: String): AppResult<String> {
        val cdp = cdpOf(engine)
            ?: return AppResult.failure(AppError("CDP_NOT_ATTACHED", "需要 CDP 调试会话"))
        val sid = cdp.targets.attachToTarget(targetId)
            ?: return AppResult.failure(AppError("TARGET_ATTACH_FAILED", "attachToTarget 失败"))
        return AppResult.success(sid)
    }

    /** CDP 会话诊断信息（连接状态/最近错误/重连计数） */
    fun sessionDiagnostics(engine: BrowserEngine): JsonObject {
        val cdp = cdpOf(engine)
        return buildJsonObject {
            put("backend", backend)
            put("connected", cdp != null)
            cdp?.let {
                put("state", it.sessionState.value.name)
                it.sessionError?.let { e -> put("lastError", e) }
                put("targetsEnabled", it.targetsEnabled)
                put("scriptRewriteEnabled", it.scriptRewrite.enabled)
                put("reconnectAttempt", reconnectAttempts[engine.tabId] ?: 0)
            }
        }
    }

    // ---------------- Response 阶段脚本改写门面（报告 §7 闭环） ----------------

    /**
     * 启用 Response 阶段脚本改写（Fetch domain）。
     * @return 成功 true；无 CDP 会话 / Fetch 不可用 false
     */
    suspend fun enableScriptRewrite(engine: BrowserEngine): AppResult<Boolean> {
        val cdp = cdpOf(engine)
            ?: return AppResult.failure(AppError("CDP_NOT_ATTACHED", "需要 CDP 调试会话，请先 debugger.attach"))
        val ok = cdp.scriptRewrite.enable()
        return if (ok) AppResult.success(true)
        else AppResult.failure(AppError("FETCH_UNAVAILABLE", "Fetch.enable 失败（Response 阶段拦截不可用）"))
    }

    suspend fun disableScriptRewrite(engine: BrowserEngine): AppResult<Boolean> {
        val cdp = cdpOf(engine)
            ?: return AppResult.failure(AppError("CDP_NOT_ATTACHED", "需要 CDP 调试会话"))
        cdp.scriptRewrite.disable()
        return AppResult.success(true)
    }

    /** 添加改写规则（urlPattern 空=全部脚本；neutralizeDebugger 中和 debugger；prepend/append 注入代码） */
    suspend fun addScriptRewriteRule(
        engine: BrowserEngine,
        urlPattern: String,
        neutralizeDebugger: Boolean,
        prepend: String?,
        append: String?,
    ): AppResult<JsonObject> {
        val cdp = cdpOf(engine)
            ?: return AppResult.failure(AppError("CDP_NOT_ATTACHED", "需要 CDP 调试会话，请先 debugger.attach"))
        val ruleId = cdp.scriptRewrite.addRule(urlPattern, neutralizeDebugger, prepend, append)
        return AppResult.success(
            buildJsonObject {
                put("ruleId", ruleId)
                put("urlPattern", urlPattern)
                put("enabled", cdp.scriptRewrite.enabled)
            },
        )
    }

    suspend fun removeScriptRewriteRule(engine: BrowserEngine, ruleId: String): AppResult<Boolean> {
        val cdp = cdpOf(engine)
            ?: return AppResult.failure(AppError("CDP_NOT_ATTACHED", "需要 CDP 调试会话"))
        return AppResult.success(cdp.scriptRewrite.removeRule(ruleId))
    }

    /** 改写规则列表 */
    suspend fun listScriptRewriteRules(engine: BrowserEngine): List<ScriptRewriteInterceptor.RewriteRule> {
        val cdp = cdpOf(engine) ?: return emptyList()
        return cdp.scriptRewrite.listRules()
    }

    /** 改写记录（最近在前；URL/原哈希/改后哈希/中和数/SRI 警告） */
    suspend fun listScriptRewriteRecords(engine: BrowserEngine, limit: Int = 50): List<ScriptRewriteInterceptor.RewriteRecord> {
        val cdp = cdpOf(engine) ?: return emptyList()
        return cdp.scriptRewrite.recordsSnapshot(limit)
    }

    // ---------------- attach / detach ----------------

    /**
     * 附加调试器：优先建立 CDP 会话（真实 V8 Debugger），
     * 失败则降级为注入式（evaluateJavascript + debugger 语句）。
     *
     * 幂等：同 Tab 已有活跃 CDP 会话直接复用。重复 attach 不重建——
     * 重建会经枢纽 removeClient 断开旧客户端（ 前 MCP 客户端
     * 断开会代撤其全部断点，AI 工作流中反复 attach 会静默丢断点）。
     */
    suspend fun attach(engine: BrowserEngine): AppResult<Boolean> {
        cdpOf(engine)?.let {
            _state.value = DebuggerState.ATTACHED
            backend = "cdp"
            return AppResult.success(true)
        }
        // （P0-2 修复）：先做"不标记显式断开"的内部清理，再登记 engine。
        // 原实现在登记 enginesByTab 之后调用 detachTab()——它把 enginesByTab、
        // cdpSessions 全部抹掉并标记 detachedTabs，导致 startWatcher 永远提前
        // return、重连条件 tabId !in detachedTabs 恒为 false，整套"自动重连 +
        // 断点恢复"（scheduleReconnect/recoverBreakpoints）成为不可达死代码。
        cleanupTabState(engine.tabId)
        detachedTabs.remove(engine.tabId)
        enginesByTab[engine.tabId] = engine
        val cdp = CdpDebuggerSession.connect(engine, eventBus, scope) { stateName ->
            runCatching { _state.value = DebuggerState.valueOf(stateName) }
        }
        if (cdp != null) {
            cdpSessions[engine.tabId] = cdp
            backend = "cdp"
            attachOrder.add(engine.tabId)
            reconnectAttempts.remove(engine.tabId)
            cdp.enableTargets()
            eventBus.tryEmit(DebuggerEvent.ScriptParsed(engine.tabId, "", "cdp-attached"))
            startWatcher(engine.tabId)
        } else {
            backend = "injected"
        }
        _state.value = DebuggerState.ATTACHED
        return AppResult.success(true)
    }

    /* *（P0-2 修复）：内部清理旧会话状态，不标记"显式 detach"（不阻断自动重连） */
    private fun cleanupTabState(tabId: String) {
        watcherJobs.remove(tabId)?.cancel()
        reconnectAttempts.remove(tabId)
        attachOrder.removeAll { it == tabId }
        cdpSessions.remove(tabId)?.close()
    }

    suspend fun detach(): AppResult<Boolean> {
        // 显式撤销 MCP 设置的 CDP 断点（对齐"关闭 DevTools 撤销断点"语义；
        // 枢纽对 MCP 客户端断开不代撤，断点生命周期在此收口）
        _breakpoints.value.forEach { bp ->
            bp.scriptId?.takeIf { it.isNotBlank() && !it.startsWith("-") }?.let { cdpId ->
                cdpSessions[bp.tabId]?.removeBreakpoint(cdpId)
            }
        }
        _breakpoints.value = emptyList()
        cdpSessions.values.forEach { it.close() }
        cdpSessions.clear()
        attachOrder.clear()
        // （P2-9 修复）：补全 watcher/引擎表/重连计数的清理。
        // 原实现不清理 watcherJobs——修复 P0-2 后 watcher 会真正启动，
        // 残留的 watcher 会在 CLOSED 状态触发"detach 后又自动重连"的异常行为。
        watcherJobs.values.forEach { it.cancel() }
        watcherJobs.clear()
        enginesByTab.clear()
        reconnectAttempts.clear()
        detachedTabs.clear()
        backend = "none"
        _state.value = DebuggerState.DETACHED
        _callFrames.value = emptyList()
        return AppResult.success(true)
    }

    /** 清理指定 Tab 的 CDP 会话（Tab 关闭时调用；标记显式断开，禁自动重连） */
    fun detachTab(tabId: String) {
        detachedTabs.add(tabId)
        watcherJobs.remove(tabId)?.cancel()
        reconnectAttempts.remove(tabId)
        attachOrder.removeAll { it == tabId }
        cdpSessions.remove(tabId)?.close()
        enginesByTab.remove(tabId)
    }

    // ---------------- 执行控制 ----------------

    suspend fun pause(engine: BrowserEngine): AppResult<Boolean> {
        val cdp = cdpOf(engine)
        if (cdp != null) {
            return if (cdp.pause()) {
                // 状态由 Debugger.paused 事件回调更新
                AppResult.success(true)
            } else {
                AppResult.failure(AppError("CDP_PAUSE_FAILED", "Debugger.pause 调用失败"))
            }
        }
        // 注入式：debugger; 语句只在 DevTools/CDP attach 时暂停；此处尽力执行
        engine.evaluateJavascript("debugger;")
        _state.value = DebuggerState.PAUSED
        eventBus.tryEmit(DebuggerEvent.Paused(engine.tabId, "injected", ""))
        return AppResult.success(true)
    }

    suspend fun resume(engine: BrowserEngine): AppResult<Boolean> {
        val cdp = cdpOf(engine)
        if (cdp != null) {
            val ok = cdp.resume()
            if (ok) _state.value = DebuggerState.RESUMED
            return if (ok) AppResult.success(true)
            else AppResult.failure(AppError("CDP_RESUME_FAILED", "未处于暂停态或会话已断开"))
        }
        // 无自有会话（未 attach）：经共享枢纽放行——覆盖"其他客户端设置的
        // 断点命中暂停、AI 未 attach 直接 resume"的场景
        if (com.webreverse.mcp.devtools.protocol.cdp.CdpHub.resumePausedSessions() > 0) {
            _state.value = DebuggerState.RESUMED
            return AppResult.success(true)
        }
        _state.value = DebuggerState.RESUMED
        eventBus.tryEmit(DebuggerEvent.Resumed(engine.tabId))
        return AppResult.success(true)
    }

    suspend fun stepInto(engine: BrowserEngine): AppResult<Boolean> =
        cdpStep(engine, "stepInto", "单步进入")

    suspend fun stepOver(engine: BrowserEngine): AppResult<Boolean> =
        cdpStep(engine, "stepOver", "单步跳过")

    suspend fun stepOut(engine: BrowserEngine): AppResult<Boolean> =
        cdpStep(engine, "stepOut", "单步跳出")

    private suspend fun cdpStep(engine: BrowserEngine, op: String, label: String): AppResult<Boolean> {
        val cdp = cdpOf(engine)
            ?: return AppResult.failure(AppError("CDP_NOT_ATTACHED", "步进需要 CDP 调试会话，请先调用 debugger.attach"))
        if (cdp.rawPauseParams == null) {
            return AppResult.failure(AppError("NOT_PAUSED", "当前未处于暂停态，无法$label"))
        }
        val ok = when (op) {
            "stepInto" -> cdp.stepInto()
            "stepOver" -> cdp.stepOver()
            else -> cdp.stepOut()
        }
        return if (ok) AppResult.success(true)
        else AppResult.failure(AppError("CDP_STEP_FAILED", "$label 调用失败"))
    }

    suspend fun restartFrame(engine: BrowserEngine): AppResult<Boolean> {
        val cdp = cdpOf(engine)
            ?: return AppResult.failure(AppError("CDP_NOT_ATTACHED", "重启帧需要 CDP 调试会话"))
        if (cdp.rawPauseParams == null) {
            return AppResult.failure(AppError("NOT_PAUSED", "当前未处于暂停态"))
        }
        return if (cdp.restartFrame()) AppResult.success(true)
        else AppResult.failure(AppError("CDP_RESTART_FRAME_FAILED", "restartFrame 调用失败"))
    }

    // ---------------- 断点 ----------------

    suspend fun setBreakpoint(
        engine: BrowserEngine,
        type: BreakpointType,
        url: String = "",
        lineNumber: Int = 0,
        condition: String? = null,
        logExpression: String? = null,
        target: String? = null,
    ): AppResult<Breakpoint> {
        val breakpoint = Breakpoint(
            id = Ids.uuid(),
            tabId = engine.tabId,
            type = type,
            url = url,
            lineNumber = lineNumber,
            condition = condition,
            logExpression = logExpression,
            target = target,
        )

        val cdp = cdpOf(engine)
        when (type) {
            BreakpointType.LINE, BreakpointType.LOGPOINT -> {
                if (cdp != null && lineNumber > 0) {
                    // Logpoint = V8 条件断点 + console.log（DevTools 同款实现）
                    val cond = if (type == BreakpointType.LOGPOINT && !logExpression.isNullOrBlank()) {
                        "(console.log(${logExpression}), false)"
                    } else {
                        condition?.takeIf { it.isNotBlank() }
                    }
                    val cdpId = cdp.setBreakpointByUrl(url, lineNumber, null, cond)
                    if (cdpId != null) {
                        _breakpoints.value = _breakpoints.value +
                            breakpoint.copy(scriptId = cdpId, condition = cond)
                        return AppResult.success(breakpoint)
                    }
                    return AppResult.failure(AppError("CDP_SET_BREAKPOINT_FAILED", "setBreakpointByUrl 未命中任何脚本"))
                }
                // 注入式降级 / 无行号
                installInjectedBreakpoint(engine, breakpoint)
            }
            BreakpointType.EXCEPTION -> {
                var viaCdp = false
                if (cdp != null) viaCdp = cdp.setPauseOnExceptions("all")
                if (!viaCdp) {
                    engine.evaluateJavascript(
                        "window.addEventListener('error', function(){ debugger; }); " +
                            "window.addEventListener('unhandledrejection', function(){ debugger; })",
                    )
                }
            }
            else -> {
                // FUNCTION / XHR / DOM / EVENT：注入 debugger; 语句（CDP attach 后即真暂停）
                installInjectedBreakpoint(engine, breakpoint)
            }
        }
        _breakpoints.value = _breakpoints.value + breakpoint
        return AppResult.success(breakpoint)
    }

    suspend fun setFunctionBreakpoint(engine: BrowserEngine, functionName: String, condition: String? = null): AppResult<Breakpoint> {
        val breakpoint = Breakpoint(
            id = Ids.uuid(),
            tabId = engine.tabId,
            type = BreakpointType.FUNCTION,
            target = functionName,
            condition = condition,
        )
        installFunctionBreakpoint(engine, functionName, condition)
        _breakpoints.value = _breakpoints.value + breakpoint
        return AppResult.success(breakpoint)
    }

    suspend fun setLogpoint(engine: BrowserEngine, url: String, lineNumber: Int, expression: String): AppResult<Breakpoint> =
        setBreakpoint(engine, BreakpointType.LOGPOINT, url, lineNumber, logExpression = expression)

    /** 异常断点开关：CDP 路径走 Debugger.setPauseOnExceptions，注入式降级挂 error 监听 */
    /**
     * 异常断点（ 粒度升级）：mode ∈ none / all / uncaught。
     * - CDP 后端：Debugger.setPauseOnExceptions(state)
     * - 注入式降级：仅 all/none 两个语义（error + unhandledrejection 注入 debugger）
     * 向后兼容：历史调用传布尔 enabled 仍有效（true→all，false→none）。
     */
    suspend fun setExceptionBreakpoints(engine: BrowserEngine, mode: String = "all"): AppResult<Boolean> {
        val cdp = cdpOf(engine)
        val state = when (mode.lowercase()) {
            "uncaught" -> "uncaught"
            "caught" -> "all" // CDP 无独立 caught-only，DevTools 的"暂停在已捕获异常"即 all；文档化提示
            else -> if (mode.equals("none", true)) "none" else "all"
        }
        if (cdp != null) {
            val ok = cdp.setPauseOnExceptions(state)
            return if (ok) AppResult.success(true)
            else AppResult.failure(AppError("CDP_EXCEPTION_BP_FAILED", "setPauseOnExceptions($state) 调用失败"))
        }
        if (state != "none") {
            engine.evaluateJavascript(
                "window.addEventListener('error', function(){ debugger; }); " +
                    "window.addEventListener('unhandledrejection', function(){ debugger; })",
            )
        }
        return AppResult.success(true)
    }

    // ---------------- DevTools 能力补齐 ----------------

    /**
     * 异步调用栈：CDP 后端返回 Debugger.paused 的 asyncStackTrace 链（await/Promise 来源）。
     * 注入式降级无异步语义，返回空数组 + 提示（不生成假数据）。
     */
    suspend fun getAsyncCallStack(engine: BrowserEngine): AppResult<JsonArray> {
        val cdp = cdpOf(engine)
            ?: return AppResult.success(JsonArray(emptyList()))
        if (cdp.rawPauseParams == null) {
            return AppResult.failure(AppError("NOT_PAUSED", "未处于暂停态（需先暂停才能有异步调用栈）"))
        }
        return AppResult.success(cdp.asyncStackTraceJson())
    }

    /**
     * pretty_print：取全量源码 → JsFormatter 词法格式化 → 缓存"格式化行→原始坐标"映射。
     * 返回格式化文本（超长截断）+ 行数/统计；随后可 debugger.set_pretty_breakpoint 在格式化行下断。
     */
    suspend fun prettyPrint(engine: BrowserEngine, scriptId: String, rename: Boolean = false, maxChars: Int = 120_000): AppResult<JsonObject> {
        val cdp = cdpOf(engine)
            ?: return AppResult.failure(AppError("CDP_NOT_ATTACHED", "pretty_print 需要 CDP 会话"))
        val src = cdp.getScriptSource(scriptId)
            ?: return AppResult.failure(AppError("SCRIPT_NOT_FOUND", "获取脚本源码失败（ScriptId 可能已失效，请 list_scripts 复核）"))
        val r = com.webreverse.mcp.javascript.parser.JsFormatter(
            renameObfuscated = rename,
            maxOutputChars = 2_000_000,
        ).format(src)
        val offsets = r.lineStartOffsets
        val positions = if (offsets.isEmpty()) {
            JsonArray(emptyList())
        } else {
            // 原始源码每行起点偏移（二分用）
            val origLineStarts = ArrayList<Int>()
            origLineStarts.add(0)
            src.forEachIndexed { i, c -> if (c == '\n') origLineStarts.add(i + 1) }
            fun origPos(off: Int): Pair<Int, Int> {
                var lo = 0; var hi = origLineStarts.size - 1; var line0 = 0
                while (lo <= hi) { val m = (lo + hi) ushr 1; if (origLineStarts[m] <= off) { line0 = m; lo = m + 1 } else hi = m - 1 }
                return Pair(line0 + 1, off - origLineStarts[line0] + 1)
            }
            JsonArray(offsets.map { off ->
                val (l, c) = origPos(off)
                buildJsonObject { put("line", l); put("column", c) }
            })
        }
        prettyCache[scriptId] = positions
        val shown = if (r.formatted.length > maxChars) r.formatted.take(maxChars) + "\n…(其余截断，共 ${r.formatted.length} 字符)" else r.formatted
        return AppResult.success(
            buildJsonObject {
                put("scriptId", scriptId)
                put("formatted", shown)
                put("length", r.formatted.length)
                put("totalLines", r.lineCount)
                put("originalChars", r.originalChars)
                put("formattedChars", r.formattedChars)
                put("renameCount", r.renameMap.size)
                put("degraded", r.degraded)
                put("truncated", r.formatted.length > maxChars)
                put(
                    "hint",
                    "格式化行↔原始坐标映射已缓存：用 debugger.set_pretty_breakpoint(scriptId=${scriptId}, formattedLine=N) 在格式化后的第 N 行下断点",
                )
            },
        )
    }

    /** 在格式化输出的第 [formattedLine] 行下断点（经 pretty_print 映射回原始坐标） */
    suspend fun setPrettyBreakpoint(
        engine: BrowserEngine,
        scriptId: String,
        formattedLine: Int,
        condition: String? = null,
    ): AppResult<JsonObject> {
        val cdp = cdpOf(engine)
            ?: return AppResult.failure(AppError("CDP_NOT_ATTACHED", "需要 CDP 会话"))
        val positions = prettyCache[scriptId]
            ?: return AppResult.failure(AppError("NO_PRETTY_CACHE", "未命中格式映射，请先 debugger.pretty_print(scriptId=$scriptId)"))
        val idx = formattedLine - 1
        if (idx < 0 || idx >= positions.size) {
            return AppResult.failure(AppError("LINE_OUT_OF_RANGE", "格式化行号越界：有效范围 1..${positions.size}"))
        }
        val pos = positions[idx].jsonObject
        val line = pos["line"]?.jsonPrimitive?.intOrNull ?: 0
        val col = pos["column"]?.jsonPrimitive?.intOrNull ?: 1
        val bpId = cdp.setBreakpointByLocation(scriptId, line, col, condition)
            ?: return AppResult.failure(AppError("BREAKPOINT_FAILED", "下断失败（脚本可能已重新解析，请重跑 pretty_print）"))
        val url = cdp.scripts.value.firstOrNull { it.scriptId == scriptId }?.url ?: ""
        return AppResult.success(
            buildJsonObject {
                put("breakpointId", bpId)
                put("scriptId", scriptId)
                put("url", url)
                put("originalLine", line)
                put("originalColumn", col)
                put("formattedLine", formattedLine)
                put("hint", "断点已下在原始源码 (${line}:${col})，对应格式化第 ${formattedLine} 行")
            },
        )
    }

    /** 设置黑盒脚本（DevTools "Blackbox Script"）；空列表清空。 */
    suspend fun setBlackbox(engine: BrowserEngine, patterns: List<String>): AppResult<Boolean> {
        val cdp = cdpOf(engine)
            ?: return AppResult.failure(AppError("CDP_NOT_ATTACHED", "黑盒设置需要 CDP 会话"))
        val ok = cdp.setBlackboxPatterns(patterns)
        if (ok) cdp.blackboxPatterns = patterns.filter { it.isNotBlank() }
        return if (ok) AppResult.success(true)
        else AppResult.failure(AppError("CDP_BLACKBOX_FAILED", "Debugger.setBlackboxPatterns 调用失败"))
    }

    /** 堆内存用量（Runtime.getHeapUsage + Memory.getDOMCounters） */
    suspend fun heapUsage(engine: BrowserEngine): AppResult<JsonObject> {
        val cdp = cdpOf(engine)
            ?: return AppResult.failure(AppError("CDP_NOT_ATTACHED", "堆用量查询需要 CDP 会话"))
        return AppResult.success(cdp.heapUsage())
    }

    /** Heap Snapshot：落到工作目录文件（.heapsnapshot） */
    suspend fun takeHeapSnapshot(engine: BrowserEngine, filePath: String, timeoutMs: Long = 120_000L): AppResult<JsonObject> {
        val cdp = cdpOf(engine)
            ?: return AppResult.failure(AppError("CDP_NOT_ATTACHED", "Heap Snapshot 需要 CDP 会话"))
        return AppResult.success(cdp.takeHeapSnapshot(filePath, timeoutMs))
    }

    suspend fun removeBreakpoint(engine: BrowserEngine, breakpointId: String): AppResult<Boolean> {
        val bp = _breakpoints.value.firstOrNull { it.id == breakpointId }
        val cdpId = bp?.scriptId
        if (cdpId != null && cdpId.isNotBlank() && !cdpId.startsWith("-")) {
            cdpOf(engine)?.removeBreakpoint(cdpId)
        }
        // 异常断点关闭时恢复
        if (bp?.type == BreakpointType.EXCEPTION) {
            cdpOf(engine)?.setPauseOnExceptions("none")
        }
        _breakpoints.value = _breakpoints.value.filterNot { it.id == breakpointId }
        return AppResult.success(true)
    }

    suspend fun listBreakpoints(engine: BrowserEngine): List<Breakpoint> =
        _breakpoints.value.filter { it.tabId == engine.tabId }

    // ---------------- Watch / 求值 ----------------

    suspend fun addWatch(engine: BrowserEngine, expression: String): AppResult<WatchExpression> {
        val watch = WatchExpression(id = Ids.uuid(), expression = expression)
        _watchExpressions.value = _watchExpressions.value + watch
        return AppResult.success(watch)
    }

    suspend fun removeWatch(watchId: String): AppResult<Boolean> {
        _watchExpressions.value = _watchExpressions.value.filterNot { it.id == watchId }
        return AppResult.success(true)
    }

    /**
     * Watch 求值：暂停态在调用帧上求值（可读局部变量），否则全局求值。
     * CDP 路径：Debugger.evaluateOnCallFrame / Runtime.evaluate。
     */
    suspend fun evaluateWatch(engine: BrowserEngine, expression: String): AppResult<String> {
        val cdp = cdpOf(engine)
        if (cdp != null) {
            val result = cdp.evaluateOnCallFrame(expression)
                ?: cdp.evaluateGlobal(expression)
            return if (result != null) AppResult.success(result)
            else AppResult.failure(AppError("EVALUATE_FAILED", "表达式求值失败"))
        }
        val result = engine.evaluateJavascript("JSON.stringify(eval(${JsScripts.quote(expression)}))")
            ?: return AppResult.failure(AppError.JS_EXECUTION_FAILED)
        return AppResult.success(result)
    }

    /** 暂停态指定调用帧求值（CDP 真实局部变量上下文） */
    suspend fun evaluateOnCallFrame(engine: BrowserEngine, expression: String, frameIndex: Int = 0): AppResult<String> {
        val cdp = cdpOf(engine)
            ?: return AppResult.failure(AppError("CDP_NOT_ATTACHED", "需要 CDP 调试会话"))
        if (cdp.rawPauseParams == null) {
            return AppResult.failure(AppError("NOT_PAUSED", "当前未处于暂停态"))
        }
        val result = cdp.evaluateOnCallFrame(expression, frameIndex)
            ?: return AppResult.failure(AppError("EVALUATE_FAILED", "调用帧求值失败"))
        return AppResult.success(result)
    }

    // ---------------- 调用栈 / 作用域 / 局部变量 ----------------

    /**
     * 调用栈：CDP 路径返回真实暂停态 CallFrame（V8 调用链）；
     * 注入式降级返回 Error().stack 解析。
     */
    suspend fun getCallStack(engine: BrowserEngine): AppResult<List<CallFrame>> {
        val cdp = cdpOf(engine)
        if (cdp != null) {
            val params = cdp.rawPauseParams
                ?: return AppResult.failure(AppError("NOT_PAUSED", "未处于暂停态（CDP 后端）"))
            val frames = parseCdpFrames(cdp, params)
            _callFrames.value = frames
            return AppResult.success(frames)
        }
        val script = """
            (function(){
              var err = new Error();
              var stack = (err.stack || '').split('\n').slice(1).map(function(line){
                var m = line.trim().match(/at\s+(.*?)\s*\(?(.*?):(\d+):(\d+)\)?$/);
                if (m) return {functionName: m[1], url: m[2], lineNumber: parseInt(m[3]), columnNumber: parseInt(m[4])};
                return {functionName: line.trim(), url: '', lineNumber: 0, columnNumber: 0};
              });
              return JSON.stringify(stack);
            })()
        """.trimIndent()
        val result = engine.evaluateJavascript(script)
            ?: return AppResult.failure(AppError.JS_EXECUTION_FAILED)
        return try {
            val frames = json.decodeFromString(
                kotlinx.serialization.builtins.ListSerializer(CallFrame.serializer()),
                unquoteJs(result),
            )
            _callFrames.value = frames
            AppResult.success(frames)
        } catch (e: Exception) {
            AppResult.failure(AppError("DEBUGGER_PARSE_ERROR", e.message.orEmpty()))
        }
    }

    /**
     * 作用域：CDP 路径解析暂停态 frame 的 scopeChain
     * （local/closure/script/global 均含真实变量，Runtime.getProperties 读取）。
     */
    suspend fun getScopes(engine: BrowserEngine): AppResult<List<Scope>> {
        val cdp = cdpOf(engine)
        if (cdp != null) {
            if (cdp.rawPauseParams == null) {
                return AppResult.failure(AppError("NOT_PAUSED", "未处于暂停态（CDP 后端）"))
            }
            return AppResult.success(cdp.scopesOfFrame(0))
        }
        // 注入式：global 采样（JS 无暂停态无法取 local，如实返回）
        val script = """
            (function(){
              var scopes = [];
              try { scopes.push({type: 'GLOBAL', name: 'Global', variables: {}}); } catch(e){}
              return JSON.stringify(scopes);
            })()
        """.trimIndent()
        val result = engine.evaluateJavascript(script)
            ?: return AppResult.failure(AppError.JS_EXECUTION_FAILED)
        return try {
            AppResult.success(
                json.decodeFromString(kotlinx.serialization.builtins.ListSerializer(Scope.serializer()), unquoteJs(result)),
            )
        } catch (e: Exception) {
            AppResult.failure(AppError("DEBUGGER_PARSE_ERROR", e.message.orEmpty()))
        }
    }

    /**
     * 剥掉 evaluateJavascript 的 JSON 编码外层：
     * JS 表达式返回字符串 "{...}" 时，回调实际给出 "\"{\\\"...\\\"}\""，
     * 直接 decodeFromString 必然失败（注入式降级路径曾因此恒报 PARSE_ERROR）。
     */
    private fun unquoteJs(raw: String): String {
        val trimmed = raw.trim()
        if (!trimmed.startsWith("\"")) return trimmed
        return try {
            (json.parseToJsonElement(trimmed) as? kotlinx.serialization.json.JsonPrimitive)?.content ?: trimmed
        } catch (e: Exception) {
            trimmed
        }
    }

    /**
     * 局部变量：CDP 路径读取暂停态 LOCAL/CLOSURE scope 真实变量；
     * 注入式降级明确返回提示（不再伪装成空对象）。
     */
    suspend fun getLocals(engine: BrowserEngine): AppResult<Map<String, String>> {
        val cdp = cdpOf(engine)
        if (cdp != null) {
            if (cdp.rawPauseParams == null) {
                return AppResult.failure(AppError("NOT_PAUSED", "未处于暂停态（CDP 后端）"))
            }
            return AppResult.success(cdp.localsOfFrame(0))
        }
        return AppResult.success(
            mapOf("_hint" to "注入式后端无法读取暂停态局部变量，请先 debugger.attach 建立 CDP 会话并触发断点"),
        )
    }

    // ---------------- 脚本（CDP 独有） ----------------

    suspend fun listScripts(engine: BrowserEngine): List<CdpScript> =
        cdpOf(engine)?.scripts?.value ?: emptyList()

    suspend fun getScriptSource(engine: BrowserEngine, scriptId: String, maxChars: Int = 200_000): AppResult<String> {
        val cdp = cdpOf(engine)
            ?: return AppResult.failure(AppError("CDP_NOT_ATTACHED", "需要 CDP 调试会话"))
        // （报告 P1）：脚本重新解析后旧 scriptId 在 V8 失效（getScriptSource 返回 null）。
        // 直接取失败时按 URL 反查最新解析者，逐个探测。
        var source = cdp.getScriptSource(scriptId)
        if (source == null) {
            val scripts = cdp.scripts.value
            val url = scripts.lastOrNull { it.scriptId == scriptId }?.url
            if (!url.isNullOrBlank()) {
                for (fresh in scripts.filter { it.url == url }.map { it.scriptId }.asReversed()) {
                    if (fresh == scriptId) continue
                    source = cdp.getScriptSource(fresh)
                    if (source != null) break
                }
            }
        }
        return source?.let { AppResult.success(it.take(maxChars)) }
            ?: AppResult.failure(
                AppError(
                    "SCRIPT_NOT_FOUND",
                    "scriptId 不存在或脚本尚未解析（页面已刷新/脚本已重新解析，请重新 debugger.list_scripts 获取最新 scriptId）",
                ),
            )
    }

    // ---------------- SourceMap 联动（CDP 独有） ----------------

    private val sourceMapService = SourceMapService()

    /**
     * 原始源码断点（DevTools Sources 面板语义）：
     * src/api/sign.ts:87 -> 下载 sourcemap -> 反查 bundle 位置 -> V8 setBreakpointByUrl。
     * 页面有多个带 sourcemap 的脚本时依序尝试，命中即设。
     */
    suspend fun setSourceBreakpoint(
        engine: BrowserEngine,
        sourceFile: String,
        lineNumber: Int,
        condition: String? = null,
    ): AppResult<Breakpoint> {
        val cdp = cdpOf(engine)
            ?: return AppResult.failure(AppError("CDP_NOT_ATTACHED", "需要 CDP 调试会话，请先 debugger.attach"))
        if (sourceFile.isBlank() || lineNumber <= 0) {
            return AppResult.failure(AppError("INVALID_ARGS", "sourceFile 与 lineNumber(>=1) 必填"))
        }
        val candidates = cdp.scripts.value.filter { !it.sourceMapUrl.isNullOrBlank() && it.url.isNotBlank() }
        if (candidates.isEmpty()) {
            return AppResult.failure(
                AppError("NO_SOURCE_MAP", "页面已解析脚本均未声明 sourceMappingURL（可能已关闭 sourcemap）"),
            )
        }
        // 优先使用已缓存 sourcemap 且包含目标源文件的脚本
        val ordered = candidates.sortedByDescending { s ->
            sourceMapService.cached().any { it.scriptUrl == s.url && it.info?.parsed == true }
        }
        for (script in ordered) {
            val entry = sourceMapService.load(script)
            val info = entry.info?.takeIf { it.parsed } ?: continue
            val gen = sourceMapService.reverseLocate(entry, sourceFile, lineNumber) ?: continue
            val cdpId = cdp.setBreakpointByUrl(script.url, gen.line, null, condition)
            if (cdpId != null) {
                val bp = Breakpoint(
                    id = Ids.uuid(),
                    tabId = engine.tabId,
                    type = BreakpointType.LINE,
                    url = script.url,
                    lineNumber = gen.line,
                    condition = condition,
                    scriptId = cdpId,
                    target = "$sourceFile:$lineNumber",
                )
                _breakpoints.value = _breakpoints.value + bp
                return AppResult.success(bp)
            }
        }
        return AppResult.failure(
            AppError("SOURCE_NOT_FOUND", "$sourceFile:$lineNumber 未映射到任何 bundle 位置（源文件名或行号可能有误）"),
        )
    }

    /** bundle 位置 -> 原始源码位置（暂停调用栈映射回源码） */
    suspend fun resolveOriginalPosition(
        engine: BrowserEngine,
        scriptUrl: String,
        line: Int,
        column: Int = 1,
    ): AppResult<OriginalLocation> {
        val cdp = cdpOf(engine)
            ?: return AppResult.failure(AppError("CDP_NOT_ATTACHED", "需要 CDP 调试会话"))
        val script = cdp.scripts.value.firstOrNull {
            it.url == scriptUrl || it.url.endsWith(scriptUrl.substringAfterLast('/'))
        } ?: return AppResult.failure(AppError("SCRIPT_NOT_FOUND", "未找到脚本: $scriptUrl"))
        val entry = sourceMapService.load(script)
        val info = entry.info?.takeIf { it.parsed }
            ?: return AppResult.failure(AppError("NO_SOURCE_MAP", entry.error ?: "该脚本无可用 sourcemap"))
        val original = sourceMapService.locateOriginal(entry, line, column)
            ?: return AppResult.failure(AppError("POSITION_NOT_MAPPED", "bundle 位置未映射到源码"))
        return AppResult.success(original)
    }

    /** 列出带 sourcemap 的脚本及源文件清单（触发下载，供 AI 选择断点目标） */
    suspend fun listSourceMappedScripts(engine: BrowserEngine): List<SourceMapService.SourceMapEntry> {
        val cdp = cdpOf(engine) ?: return emptyList()
        return cdp.scripts.value
            .filter { !it.sourceMapUrl.isNullOrBlank() && it.url.isNotBlank() }
            .map { sourceMapService.load(it) }
    }

    // ---------------- Runtime 域（CDP 独有） ----------------

    /** Runtime.evaluate：awaitPromise + 异常详情 + objectId（DevTools Console 语义） */
    suspend fun runtimeEvaluate(
        engine: BrowserEngine,
        expression: String,
        awaitPromise: Boolean = true,
    ): AppResult<JsonObject> {
        val cdp = cdpOf(engine)
            ?: return AppResult.failure(AppError("CDP_NOT_ATTACHED", "需要 CDP 调试会话"))
        return AppResult.success(cdp.evaluateDetailed(expression, awaitPromise))
    }

    /** 按 objectId 展开远程对象 */
    suspend fun getObjectProperties(engine: BrowserEngine, objectId: String): AppResult<JsonArray> {
        val cdp = cdpOf(engine)
            ?: return AppResult.failure(AppError("CDP_NOT_ATTACHED", "需要 CDP 调试会话"))
        return AppResult.success(cdp.getObjectProperties(objectId))
    }

    // ---------------- JSVMP 采样追踪（CDP 独有） ----------------

    /**
     * VMP 采样断点 v2：在 dispatch 循环位置设条件断点（line+column），
     * condition 求值恒为 falsy——V8 不暂停但每次执行该位置都会求值并记录。
     *
     * v2 改进：
     * - column 支持：minified 单行 JSVMP 必须列号才能命中 dispatch 循环
     * - 环形缓冲 + 采样率：高频 dispatch 不再无界增长（防 OOM/拖死页面）
     * - 真实触发计数：统计不被采样率/环形覆盖失真
     */
    suspend fun setTraceBreakpoint(
        engine: BrowserEngine,
        url: String,
        line: Int,
        expression: String,
        column: Int? = null,
        sampleRate: Int = 1,
    ): AppResult<Breakpoint> {
        val cdp = cdpOf(engine)
            ?: return AppResult.failure(AppError("CDP_NOT_ATTACHED", "需要 CDP 调试会话，请先 debugger.attach"))
        if (line <= 0 || expression.isBlank()) {
            return AppResult.failure(AppError("INVALID_ARGS", "line(>=1) 与 expression 必填"))
        }
        // 载体初始化（Trace 断点与普通断点共存：先尝试 CDP 注入，失败用 evaluate）
        cdp.evaluateGlobal(JsScripts.vmpTraceInitScript())
        engine.evaluateJavascript(JsScripts.vmpTraceInitScript())
        val rate = sampleRate.coerceAtLeast(1)
        if (rate > 1) {
            val setRate = "globalThis.__WRMCP_VMP_RATE__ = $rate"
            cdp.evaluateGlobal(setRate)
            engine.evaluateJavascript(setRate)
        }
        // 计数 -> 按采样率记录 -> 环形覆盖 -> 恒 false 不暂停
        val cond = "(" +
            "globalThis.__WRMCP_VMP_N__=(globalThis.__WRMCP_VMP_N__||0)+1," +
            "(globalThis.__WRMCP_VMP_N__%globalThis.__WRMCP_VMP_RATE__===0&&" +
            "(globalThis.__WRMCP_VMP_TRACE__.length<globalThis.__WRMCP_VMP_CAP__||" +
            "globalThis.__WRMCP_VMP_TRACE__.shift())&&" +
            "globalThis.__WRMCP_VMP_TRACE__.push(($expression)))," +
            "false)"
        val cdpId = cdp.setBreakpointByUrl(url, line, column, cond)
            ?: return AppResult.failure(
                AppError(
                    "CDP_SET_BREAKPOINT_FAILED",
                    "setBreakpointByUrl 未命中（url/line/column 有误？用 detect_vmp 重新定位，minified 必须带 column）",
                ),
            )
        val bp = Breakpoint(
            id = Ids.uuid(),
            tabId = engine.tabId,
            type = BreakpointType.LINE,
            url = url,
            lineNumber = line,
            condition = cond,
            scriptId = cdpId,
            target = "vmp-trace@$line:${column ?: 0} rate=$rate: ($expression)",
        )
        _breakpoints.value = _breakpoints.value + bp
        return AppResult.success(bp)
    }

    /** 取回采样数据并折叠分析（原始样本可数万条，直接返回会撑爆上下文） */
    suspend fun collectVmpTrace(
        engine: BrowserEngine,
        maxSamples: Int = 5000,
    ): AppResult<VmpTraceAnalyzer.TraceReport> {
        val cdp = cdpOf(engine)
            ?: return AppResult.failure(AppError("CDP_NOT_ATTACHED", "需要 CDP 调试会话"))
        val collectExpr = """
            (function(){
              var t = globalThis.__WRMCP_VMP_TRACE__ || [];
              return JSON.stringify({realTotal: globalThis.__WRMCP_VMP_N__ || t.length,
                                     tail: t.slice(-$maxSamples).map(function(x){
                try { return (typeof x === 'object' && x !== null) ? JSON.stringify(x) : String(x); } catch(e){ return '?'; }
              })});
            })()
        """.trimIndent()
        val raw = cdp.evaluateGlobal(collectExpr)
            ?: return AppResult.failure(AppError("EVALUATE_FAILED", "取回 trace 失败（页面可能已刷新）"))
        val obj = runCatching { json.parseToJsonElement(raw.trim()).jsonObject }.getOrNull()
            ?: return AppResult.failure(AppError("TRACE_PARSE_ERROR", raw.take(200)))
        // realTotal 来自页面计数器（含被采样率跳过/环形覆盖的部分），统计不失真
        val realTotal = obj["realTotal"]?.jsonPrimitive?.intOrNull ?: 0
        val tail = obj["tail"]?.jsonArray?.map { it.jsonPrimitive.contentOrNull ?: "?" } ?: emptyList()
        return AppResult.success(VmpTraceAnalyzer().analyze(tail, realTotal))
    }

    /** 取回原始样本（供对照组 diff 用，不折叠） */
    suspend fun collectVmpTraceRaw(
        engine: BrowserEngine,
        maxSamples: Int = 4000,
    ): AppResult<List<String>> {
        val cdp = cdpOf(engine)
            ?: return AppResult.failure(AppError("CDP_NOT_ATTACHED", "需要 CDP 调试会话"))
        val collectExpr = """
            (function(){
              var t = globalThis.__WRMCP_VMP_TRACE__ || [];
              return JSON.stringify(t.slice(-$maxSamples).map(function(x){
                try { return (typeof x === 'object' && x !== null) ? JSON.stringify(x) : String(x); } catch(e){ return '?'; }
              }));
            })()
        """.trimIndent()
        val raw = cdp.evaluateGlobal(collectExpr)
            ?: return AppResult.failure(AppError("EVALUATE_FAILED", "取回 trace 失败"))
        val arr = runCatching { json.parseToJsonElement(raw.trim()).jsonArray }.getOrNull()
            ?: return AppResult.failure(AppError("TRACE_PARSE_ERROR", raw.take(200)))
        return AppResult.success(arr.map { it.jsonPrimitive.contentOrNull ?: "?" })
    }

    /** 保留当前采样为对照组快照（diff_vmp_trace 用） */
    private var vmpBaseline: List<String> = emptyList()

    suspend fun snapshotVmpBaseline(engine: BrowserEngine): Int {
        val raw = collectVmpTraceRaw(engine).getOrNull() ?: emptyList()
        vmpBaseline = raw
        return raw.size
    }

    /** 与对照组差分：新增/缺失的 opcode 块即疑似签名路径 */
    suspend fun diffVmpTrace(engine: BrowserEngine): AppResult<VmpTraceAnalyzer.TraceDiff> {
        if (vmpBaseline.isEmpty()) {
            return AppResult.failure(AppError("NO_BASELINE", "先执行 baseline 快照（get_vmp_trace baseline=true），触发对照操作后再 diff"))
        }
        val test = collectVmpTraceRaw(engine).getOrNull()
            ?: return AppResult.failure(AppError("EVALUATE_FAILED", "取回 trace 失败"))
        return AppResult.success(VmpTraceAnalyzer().diff(vmpBaseline, test))
    }

    /** 清空采样缓冲（新一轮采样前调用） */
    suspend fun clearVmpTrace(engine: BrowserEngine) {
        cdpOf(engine)?.evaluateGlobal("globalThis.__WRMCP_VMP_CLEAR__ && globalThis.__WRMCP_VMP_CLEAR__()")
        engine.evaluateJavascript("globalThis.__WRMCP_VMP_CLEAR__ && globalThis.__WRMCP_VMP_CLEAR__()")
    }

    // ---------------- CDP 增强 ----------------

    /** 暂停现场一键快照：调用栈 + 每帧局部变量 + this + 命中断点 + reason（AI 一次看清现场） */
    suspend fun snapshotPausedState(engine: BrowserEngine): AppResult<JsonObject> {
        val cdp = cdpOf(engine)
            ?: return AppResult.failure(AppError("CDP_NOT_ATTACHED", "需要 CDP 调试会话，请先 debugger.attach"))
        val params = cdp.rawPauseParams
            ?: return AppResult.failure(AppError("NOT_PAUSED", "当前未暂停（快照需要断点命中后的暂停态）"))
        val frames = parseCdpFrames(cdp, params)
        _callFrames.value = frames
        val reason = params["reason"]?.jsonPrimitive?.contentOrNull ?: ""
        val data = params["data"]

        // 每帧解析局部变量（前 maxFrames 帧，防超长调用栈拖垮）
        val maxFrames = frames.size.coerceAtMost(8)
        val framesJson = (0 until maxFrames).map { i ->
            val locals = cdp.localsOfFrame(i)
            buildJsonObject {
                put("index", i)
                put("functionName", frames[i].functionName)
                put("url", frames[i].url)
                put("line", frames[i].lineNumber)
                put("column", frames[i].columnNumber)
                put("locals", JsonObject(locals.mapValues { (_, v) -> kotlinx.serialization.json.JsonPrimitive(v) }))
                if (i == 0) put("this", frames[i].thisObject)
            }
        }

        // 命中的断点 ID
        val hits = params["hitBreakpoints"]?.jsonArray
            ?.mapNotNull { it.jsonPrimitive?.contentOrNull } ?: emptyList()

        return AppResult.success(
            buildJsonObject {
                put("state", "PAUSED")
                put("reason", reason)
                if (data != null) put("data", data)
                put("hitBreakpoints", JsonArray(hits.map { kotlinx.serialization.json.JsonPrimitive(it) }))
                put("callFrames", JsonArray(framesJson))
                put("hint", "变量用 debugger.evaluate_on_call_frame 深挖；步进 step_into/step_over；改变量 set_variable")
            },
        )
    }

    /** Debugger.searchInContent：脚本内容搜索（不拉全量源码）；scriptIdOrUrl 为空或 "*" 时全局搜索全部已解析脚本 */
    suspend fun searchScriptContent(
        engine: BrowserEngine,
        scriptIdOrUrl: String,
        query: String,
        caseSensitive: Boolean = false,
        limit: Int = 50,
    ): AppResult<JsonArray> {
        val cdp = cdpOf(engine)
            ?: return AppResult.failure(AppError("CDP_NOT_ATTACHED", "需要 CDP 调试会话，请先 debugger.attach"))
        // 修复（实测问题：传 "main." 之类部分名直接失败，AI 只能盲猜完整 URL 重试）：
        // 匹配顺序改为 scriptId 精确 → URL 精确 → URL 后缀 → URL 子串（大脚本优先，与 js.format 一致）。
        // 仍未命中时不再只丢一句"未找到"，而是回传候选清单（按体积排序前 10 个带 URL 的脚本），
        // 让 AI 一轮自纠，不必再 list_scripts 全量拉一遍。
        // 全局搜索：scriptIdOrUrl 为空或 "*" 时遍历全部已解析脚本，命中项附带 scriptId/url 便于定位
         if (scriptIdOrUrl.isBlank() || scriptIdOrUrl == "*") {
             // 每脚本预算：总量均分，避免单个大脚本霸占全部预算；上限 20 条/脚本
             val perScript = (limit / 3).coerceIn(2, 20)
             val matches = cdp.scripts.value
                 .filter { it.url.isNotBlank() }
                 .flatMap { script ->
                     cdp.searchInContent(script.scriptId, query, caseSensitive, perScript)
                         .mapNotNull { match ->
                             val mo = match as? JsonObject ?: return@mapNotNull null
                             buildJsonObject {
                                 put("scriptId", JsonPrimitive(script.scriptId))
                                 put("url", JsonPrimitive(script.url))
                                 mo.forEach { (k, v) -> put(k, v) }
                             }
                         }
                 }
                 .take(limit)
             return AppResult.success(JsonArray(matches))
         }
        val scriptId = cdp.scripts.value.firstOrNull { it.scriptId == scriptIdOrUrl }?.scriptId
            ?: cdp.scripts.value.firstOrNull { it.url == scriptIdOrUrl }?.scriptId
            ?: cdp.scripts.value.firstOrNull { it.url.endsWith(scriptIdOrUrl) }?.scriptId
            ?: cdp.scripts.value
                .filter { it.url.isNotBlank() && it.url.contains(scriptIdOrUrl) }
                .maxByOrNull { it.length }?.scriptId
            ?: return AppResult.failure(
                AppError(
                    "SCRIPT_NOT_FOUND",
                    "未找到脚本：$scriptIdOrUrl。支持 scriptId / 完整 URL / URL 子串（如 main.）。候选脚本（按体积）：${
                        cdp.scripts.value
                            .filter { it.url.isNotBlank() }
                            .sortedByDescending { it.length }
                            .take(10)
                            .joinToString(" | ") { "${it.scriptId} ${it.url.take(80)}" }
                    }",
                ),
            )
        return AppResult.success(cdp.searchInContent(scriptId, query, caseSensitive, limit))
    }

    /** Debugger.getPossibleBreakpoints：可断点位置查询（打断点前校准行号；minified 脚本精确到列） */
    suspend fun getBreakableLocations(
        engine: BrowserEngine,
        url: String,
        line: Int,
        column: Int? = null,
        limit: Int = 20,
    ): AppResult<JsonObject> {
        val cdp = cdpOf(engine)
            ?: return AppResult.failure(AppError("CDP_NOT_ATTACHED", "需要 CDP 调试会话，请先 debugger.attach"))
        return AppResult.success(cdp.getPossibleBreakpoints(url, line, column, false, limit))
    }

    /** Debugger.setVariableValue：暂停态修改变量（scopeNumber 从 scopes 结果取） */
    suspend fun setVariableValue(
        engine: BrowserEngine,
        frameIndex: Int,
        scopeNumber: Int,
        variableName: String,
        newValue: String,
    ): AppResult<Boolean> {
        val cdp = cdpOf(engine)
            ?: return AppResult.failure(AppError("CDP_NOT_ATTACHED", "需要 CDP 调试会话"))
        val result = cdp.setVariableValue(frameIndex, scopeNumber, variableName, newValue)
        return result.fold(
            onSuccess = { AppResult.success(true) },
            onFailure = { AppResult.failure(AppError("SET_VARIABLE_FAILED", it.message ?: "setVariableValue 调用失败")) },
        )
    }

    /** Runtime.queryObjects：构造器实例查询（找加密器实例） */
    suspend fun queryObjects(engine: BrowserEngine, prototypeExpression: String, limit: Int = 20): AppResult<JsonObject> {
        val cdp = cdpOf(engine)
            ?: return AppResult.failure(AppError("CDP_NOT_ATTACHED", "需要 CDP 调试会话，请先 debugger.attach"))
        return AppResult.success(cdp.queryObjects(prototypeExpression, limit))
    }

    /** Runtime.callFunctionOn：在远程对象上调用函数 */
    suspend fun callFunctionOn(
        engine: BrowserEngine,
        objectId: String,
        functionDeclaration: String,
        arguments: List<String>,
    ): AppResult<JsonObject> {
        val cdp = cdpOf(engine)
            ?: return AppResult.failure(AppError("CDP_NOT_ATTACHED", "需要 CDP 调试会话，请先 debugger.attach"))
        return AppResult.success(cdp.callFunctionOn(objectId, functionDeclaration, arguments))
    }

    /** CDP 原生 XHR/fetch 断点（请求发起前暂停，url 子串匹配，空串=全部请求） */
    suspend fun setXhrBreakpoint(engine: BrowserEngine, urlPattern: String, enabled: Boolean): AppResult<Boolean> {
        val cdp = cdpOf(engine)
            ?: return AppResult.failure(AppError("CDP_NOT_ATTACHED", "需要 CDP 调试会话（原生 XHR 断点），请先 debugger.attach"))
        val ok = if (enabled) cdp.setXHRBreakpoint(urlPattern) else cdp.removeXHRBreakpoint(urlPattern)
        return if (ok) AppResult.success(true)
        else AppResult.failure(AppError("XHR_BP_FAILED", "DOMDebugger.setXHRBreakpoint 调用失败"))
    }

    /** CDP 原生事件断点（DevTools Event Listener Breakpoints 同语义） */
    suspend fun setEventListenerBreakpoint(engine: BrowserEngine, eventName: String, enabled: Boolean): AppResult<Boolean> {
        val cdp = cdpOf(engine)
            ?: return AppResult.failure(AppError("CDP_NOT_ATTACHED", "需要 CDP 调试会话（原生事件断点），请先 debugger.attach"))
        val ok = if (enabled) cdp.setEventListenerBreakpoint(eventName) else cdp.removeEventListenerBreakpoint(eventName)
        return if (ok) AppResult.success(true)
        else AppResult.failure(AppError("EVT_BP_FAILED", "DOMDebugger.setEventListenerBreakpoint 调用失败"))
    }

    /** 脚本执行前断点（beforeScriptExecution：新脚本执行前暂停，拦截加密初始化） */
    suspend fun setInstrumentationBreakpoint(engine: BrowserEngine, enabled: Boolean): AppResult<Boolean> {
        val cdp = cdpOf(engine)
            ?: return AppResult.failure(AppError("CDP_NOT_ATTACHED", "需要 CDP 调试会话，请先 debugger.attach"))
        val ok = if (enabled) cdp.setInstrumentationBreakpoint() else cdp.removeInstrumentationBreakpoint()
        return if (ok) AppResult.success(true)
        else AppResult.failure(AppError("INSTR_BP_FAILED", "setInstrumentationBreakpoint 调用失败"))
    }

    /** CPU profile 开始/停止与热点分析（start=true 开始录制，false 停止并返回热点函数） */
    suspend fun cpuProfile(engine: BrowserEngine, start: Boolean, topN: Int = 25): AppResult<JsonObject> {
        val cdp = cdpOf(engine)
            ?: return AppResult.failure(AppError("CDP_NOT_ATTACHED", "需要 CDP 调试会话，请先 debugger.attach"))
        return if (start) {
            if (cdp.startCpuProfile()) {
                AppResult.success(buildJsonObject { put("ok", true); put("recording", true); put("hint", "让页面执行加密/签名流程后，cpu_profile start=false 停止并取热点") })
            } else {
                AppResult.failure(AppError("PROFILER_FAILED", "Profiler.start 调用失败"))
            }
        } else {
            AppResult.success(cdp.stopCpuProfile(topN))
        }
    }

    /** 全部断点（本地记录 + CDP 后端已解析断点（含其他客户端设置），合并去重） */
    suspend fun listAllBreakpoints(engine: BrowserEngine): List<JsonObject> {
        val local = _breakpoints.value.filter { it.tabId == engine.tabId }
        val cdp = cdpOf(engine)
        val out = mutableListOf<JsonObject>()
        local.forEach { bp ->
            out.add(
                buildJsonObject {
                    put("id", bp.id)
                    put("source", "mcp")
                    put("type", bp.type.name)
                    put("url", bp.url)
                    put("line", bp.lineNumber)
                    put("condition", bp.condition ?: "")
                    put("cdpId", bp.scriptId ?: "")
                },
            )
        }
        cdp?.listRemoteBreakpoints()?.forEach { rb ->
            // 本地已通过 setBreakpointByUrl 记录的（scriptId == cdpId）跳过
            if (local.none { it.scriptId == rb.breakpointId }) {
                out.add(
                    buildJsonObject {
                        put("id", rb.breakpointId)
                        put("source", "devtools")
                        put("type", "LINE")
                        put("url", rb.url)
                        put("line", rb.line)
                    },
                )
            }
        }
        return out
    }

    // ---------------- 注入式辅助（降级路径） ----------------

    private suspend fun installInjectedBreakpoint(engine: BrowserEngine, breakpoint: Breakpoint) {
        when (breakpoint.type) {
            BreakpointType.FUNCTION -> breakpoint.target?.let {
                installFunctionBreakpoint(engine, it, breakpoint.condition)
            }
            BreakpointType.LOGPOINT -> engine.evaluateJavascript(
                "console.log('Logpoint: ' + (${breakpoint.logExpression ?: "''"}))",
            )
            BreakpointType.EXCEPTION -> engine.evaluateJavascript(
                "window.addEventListener('error', function(e){ debugger; })",
            )
            BreakpointType.XHR -> engine.evaluateJavascript(
                """
                (function(){
                  var _open = XMLHttpRequest.prototype.open;
                  XMLHttpRequest.prototype.open = function(m, u){
                    var pat = ${JsScripts.quote(breakpoint.target ?: "")};
                    if (pat.length === 0 || String(u).indexOf(pat) >= 0) debugger;
                    return _open.apply(this, arguments);
                  };
                })()
                """.trimIndent(),
            )
            else -> engine.evaluateJavascript(
                """
                (function(){
                  var cond = ${if (breakpoint.condition != null) "(" + breakpoint.condition + ")" else "true"};
                  if (cond) debugger;
                })()
                """.trimIndent(),
            )
        }
    }

    private suspend fun installFunctionBreakpoint(engine: BrowserEngine, functionName: String, condition: String?) {
        val script = """
            (function(){
              var path = ${JsScripts.quote(functionName)}.split('.');
              var obj = window;
              for (var i=0;i<path.length-1;i++){
                if (obj[path[i]] === undefined) return;
                obj = obj[path[i]];
              }
              var fnName = path[path.length-1];
              var original = obj[fnName];
              if (typeof original !== 'function') return;
              if (original.__wrmcp_bp__) return; // 防重复包装
              var wrapped = function(){
                var cond = ${if (condition != null) "(" + condition + ")" else "true"};
                if (cond) debugger;
                return original.apply(this, arguments);
              };
              wrapped.__wrmcp_bp__ = true;
              wrapped.__original = original;
              obj[fnName] = wrapped;
            })()
        """.trimIndent()
        engine.evaluateJavascript(script)
    }

    // ---------------- 断点增强：DOM / Event Listener / Promise ----------------

    /** 收集页面内所有断点命中记录（DOM/事件/Promise） */
    suspend fun collectBreakpointHits(engine: BrowserEngine, kind: String, limit: Int = 100): String? {
        val varName = when (kind) {
            "dom" -> "__WRMCP_DOM_BP_HITS__"
            "event" -> "__WRMCP_EVT_BP_HITS__"
            "promise" -> "__WRMCP_PROM_BP_HITS__"
            else -> return null
        }
        return engine.evaluateJavascript(
            "(function(){ var h = globalThis.$varName || []; return JSON.stringify(h.slice(-$limit)); })()",
        )
    }

    /** 清空命中记录 */
    suspend fun clearBreakpointHits(engine: BrowserEngine, kind: String) {
        val varName = when (kind) {
            "dom" -> "__WRMCP_DOM_BP_HITS__"
            "event" -> "__WRMCP_EVT_BP_HITS__"
            "promise" -> "__WRMCP_PROM_BP_HITS__"
            else -> return
        }
        engine.evaluateJavascript("globalThis.$varName = []")
    }

    private fun parseCdpFrames(cdp: CdpDebuggerSession, params: kotlinx.serialization.json.JsonObject): List<CallFrame> =
        cdp.parseCallFrames(params)

    companion object {
        /** 自动重连最大尝试次数（超过后置 DETACHED 等待显式 attach） */
        private const val MAX_RECONNECT_ATTEMPTS = 5
    }
}
