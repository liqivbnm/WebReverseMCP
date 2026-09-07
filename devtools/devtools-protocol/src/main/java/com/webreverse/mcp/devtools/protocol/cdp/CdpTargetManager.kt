package com.webreverse.mcp.devtools.protocol.cdp

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.util.concurrent.ConcurrentHashMap

/**
 * CDP Target domain 管理器（报告 §三/§四：Worker/ServiceWorker/iframe 统一管理）。
 *
 * 背景：逆向对象常把加密/签名/风控代码放进 Worker（Web Worker / Service Worker）
 * 或跨域 iframe（payment/webview 壳）执行，单纯对 Page target 调试看不见这些
 * 执行环境。CDP Target domain 提供：
 * - Target.setDiscoverTargets：枚举进程内全部 target（页面/iframe/worker）
 * - Target.setAutoAttach(flatten=true)：新 target 出现时自动 attach，
 *   并在同一 WebSocket 连接上派生子会话（消息根级 sessionId 路由），
 *   无需为每个 worker 再建 WS 连接。
 *
 * 本类挂接在一条已建立的根 CdpSession（Page target 会话）之上：
 * - 收集 Target.targetCreated/targetInfoChanged/targetDestroyed 维护目标表；
 * - attachedToTarget/detachedFromTarget 维护 targetId → sessionId 映射；
 * - 对 worker/service_worker 子会话可直接 Runtime.evaluate /
 *   Debugger.enable（canDebug=true）；iframe 经页面会话的 DOM 执行。
 *
 * 典型逆向链路：listTargets() 找到 worker → evaluateOnTarget 探测
 * self.importScripts / 加密入口 → 对 worker 子会话打断点抓栈。
 */
class CdpTargetManager(
    private val session: CdpSession,
    private val scope: CoroutineScope,
) {
    /** targetId → 最新 target 信息（含 flatten sessionId） */
    private val targets = ConcurrentHashMap<String, CdpTargetInfo>()

    /** flatten sessionId → targetId 反查（事件路由用） */
    private val targetIdBySession = ConcurrentHashMap<String, String>()

    /** sessionId → 已解析脚本（worker 子会话 Debugger.scriptParsed 累积） */
    private val scriptsBySession = ConcurrentHashMap<String, LinkedHashMap<String, CdpScript>>()

    private var watchJob: Job? = null

    /** 目标变更回调（供上层发 EventBus / 刷新 UI） */
    var onTargetsChanged: ((List<CdpTargetInfo>) -> Unit)? = null

    /** 脚本解析事件转发（worker 子会话的 Debugger.scriptParsed） */
    var onScriptParsed: ((CdpScript, String?) -> Unit)? = null

    /** worker/service worker 子会话的 console 转发（sessionId 标记来源） */
    var onConsoleApiCalled: ((JsonObject, String?) -> Unit)? = null

    /** worker 内未捕获异常转发 */
    var onExceptionThrown: ((JsonObject, String?) -> Unit)? = null

    val sessionState: StateFlow<CdpSession.State> get() = session.state

    /**
     * 启用 Target domain 自动发现 + 自动 attach。
     *
     * autoAttach 顺序：先 setDiscoverTargets（枚举已存在的 target），
     * 再 setAutoAttach（对已存在 + 未来出现的 target 触发 attachedToTarget）。
     *
     * @param waitForDebugger 暂停在 worker 启动处（拿到调用栈后再放行）。
     *        逆向加密 worker 时置 true 可在 importScripts 前断下。
     * @return 成功启动 true；Target domain 不可用（旧 WebView）false。
     */
    suspend fun start(waitForDebugger: Boolean = false): Boolean {
        // Discover：枚举 + 持续跟踪 target 增删
        val discover = session.callDetailed(
            "Target.setDiscoverTargets",
            buildJsonObject { put("discover", true) },
        )
        if (discover.isFailure) return false

        // AutoAttach：flatten=true 使子会话共用本 WebSocket（sessionId 路由）
        val autoAttach = session.callDetailed(
            "Target.setAutoAttach",
            buildJsonObject {
                put("autoAttach", true)
                put("waitForDebuggerOnStart", waitForDebugger)
                put("flatten", true)
            },
        )
        if (autoAttach.isFailure) return false

        watchJob?.cancel()
        watchJob = scope.launch {
            session.events.collect { event -> onEvent(event) }
        }
        return true
    }

    fun stop() {
        watchJob?.cancel()
        watchJob = null
        // 尽力关闭（不阻塞调用线程）
        scope.launch {
            runCatching {
                session.call("Target.setAutoAttach", buildJsonObject { put("autoAttach", false) })
                session.call("Target.setDiscoverTargets", buildJsonObject { put("discover", false) })
            }
        }
        targets.clear()
        targetIdBySession.clear()
        scriptsBySession.clear()
    }

    /**
     * 对单个子 target（worker/service_worker/iframe）统一初始化能力域（报告 P0-2）。
     *
     * 按 target 类型启用不同 capability profile：
     * - worker / shared_worker / service_worker：Runtime + Debugger + Network
     *   （Debugger 使 worker 内 scriptParsed/断点可见——旧实现漏掉的致命缺口；
     *     Network 使 worker 发起 fetch/XHR 进 evidence chain）
     * - page / iframe：Runtime + Debugger + Network + Page
     *   （iframe 独立执行上下文需 Page 域才能拿生命周期）
     * - browser：不初始化（会话级控制面，无 JS 执行语义）
     *
     * 每个域独立 try 容忍失败（如 worker 不支持 Page）——失败不影响其余域。
     */
    private suspend fun initializeChildTarget(sessionId: String, type: String) {
        val isWorker = type == "worker" || type == "shared_worker" || type == "service_worker"
        val isPage = type == "page" || type == "iframe"
        if (!isWorker && !isPage) return

        runCatching { session.call("Runtime.enable", JsonObject(emptyMap()), sessionId) }
        if (isWorker || isPage) {
            runCatching { session.call("Debugger.enable", JsonObject(emptyMap()), sessionId) }
            runCatching { session.call("Network.enable", JsonObject(emptyMap()), sessionId) }
        }
        if (isPage) {
            runCatching { session.call("Page.enable", JsonObject(emptyMap()), sessionId) }
        }
    }

    // ---------------- 事件处理 ----------------

    private fun onEvent(event: CdpEvent) {
        when (event.method) {
            "Target.targetCreated", "Target.targetInfoChanged" -> {
                val info = event.params["targetInfo"]?.jsonObject ?: return
                val target = parseTargetInfo(info)
                if (event.method == "Target.targetInfoChanged") {
                    // 保留旧 sessionId/attached 状态（infoChanged 不携带）
                    val old = targets[target.targetId]
                    targets[target.targetId] = target.copy(
                        attached = old?.attached ?: target.attached,
                        sessionId = old?.sessionId ?: target.sessionId,
                    )
                } else {
                    targets[target.targetId] = target
                }
                notifyChanged()
            }

            "Target.targetDestroyed" -> {
                val targetId = event.params["targetId"]?.jsonPrimitive?.contentOrNull ?: return
                targets.remove(targetId)?.sessionId?.let { targetIdBySession.remove(it) }
                notifyChanged()
            }

            "Target.attachedToTarget" -> {
                val info = event.params["targetInfo"]?.jsonObject ?: JsonObject(emptyMap())
                val targetId = info.get("targetId")?.jsonPrimitive?.contentOrNull
                    ?: event.params["targetId"]?.jsonPrimitive?.contentOrNull
                    ?: return
                val sessionId = event.params["sessionId"]?.jsonPrimitive?.contentOrNull ?: return
                val targetType = info.get("type")?.jsonPrimitive?.contentOrNull ?: ""
                targetIdBySession[sessionId] = targetId
                targets.compute(targetId) { _, old ->
                    old?.copy(attached = true, sessionId = sessionId)
                        ?: parseTargetInfo(info).copy(attached = true, sessionId = sessionId)
                }
                notifyChanged()
                // （报告 P0-2）：子 target 统一初始化能力域。
                // 旧实现只 Runtime.enable——worker/service_worker 的脚本（Web/Blob/Module）
                // 因未 Debugger.enable 而 "scriptParsed 收不到"，主页面能看到、worker 看不到，
                // 对现在大量把加密逻辑放 worker 的网站属致命缺陷。按 target 类型补全域。
                scope.launch { initializeChildTarget(sessionId, targetType) }
            }

            "Target.detachedFromTarget" -> {
                val sessionId = event.params["sessionId"]?.jsonPrimitive?.contentOrNull ?: return
                val targetId = event.params["targetId"]?.jsonPrimitive?.contentOrNull
                    ?: targetIdBySession.remove(sessionId)
                if (targetId != null) {
                    targets.computeIfPresent(targetId) { _, old -> old.copy(attached = false, sessionId = null) }
                    targetIdBySession.remove(sessionId)
                    notifyChanged()
                }
            }

            // ---- flatten 子会话事件（根级 sessionId 区分来源）----

            "Debugger.scriptParsed" -> {
                val scriptId = event.params["scriptId"]?.jsonPrimitive?.contentOrNull ?: return
                val script = CdpScript(
                    scriptId = scriptId,
                    url = event.params["url"]?.jsonPrimitive?.contentOrNull ?: "",
                    startLine = event.params["startLine"]?.jsonPrimitive?.intOrNull ?: 0,
                    endLine = event.params["endLine"]?.jsonPrimitive?.intOrNull ?: 0,
                    sourceMapUrl = event.params["sourceMapURL"]?.jsonPrimitive?.contentOrNull,
                    length = event.params["length"]?.jsonPrimitive?.contentOrNull?.toLongOrNull() ?: 0,
                )
                val sid = event.sessionId ?: return
                scriptsBySession.computeIfAbsent(sid) { LinkedHashMap() }[scriptId] = script
                onScriptParsed?.invoke(script, sid)
            }

            "Runtime.consoleAPICalled" ->
                if (event.sessionId != null) onConsoleApiCalled?.invoke(event.params, event.sessionId)

            "Runtime.exceptionThrown" ->
                if (event.sessionId != null) onExceptionThrown?.invoke(event.params, event.sessionId)
        }
    }

    private fun notifyChanged() {
        onTargetsChanged?.invoke(targetsSnapshot())
    }

    private fun parseTargetInfo(info: JsonObject): CdpTargetInfo {
        val type = info["type"]?.jsonPrimitive?.contentOrNull ?: "page"
        return CdpTargetInfo(
            targetId = info["targetId"]?.jsonPrimitive?.contentOrNull ?: "",
            type = type,
            title = info["title"]?.jsonPrimitive?.contentOrNull ?: "",
            url = info["url"]?.jsonPrimitive?.contentOrNull ?: "",
            attached = info["attached"]?.jsonPrimitive?.contentOrNull == "true",
            canDebug = type in DEBUGGABLE_TYPES,
            browserContextId = info["browserContextId"]?.jsonPrimitive?.contentOrNull,
            openerId = info["openerId"]?.jsonPrimitive?.contentOrNull,
            subtype = info["subtype"]?.jsonPrimitive?.contentOrNull,
        )
    }

    // ---------------- 查询 ----------------

    /** 当前全部 target（按类型分组排序：page 最前，worker 其次） */
    fun targetsSnapshot(): List<CdpTargetInfo> =
        targets.values.sortedWith(
            compareBy({ TYPE_ORDER.indexOf(it.type) }, { it.url }),
        )

    /** 可调试执行环境（Worker/ServiceWorker/iframe，canDebug=true 且已 attach） */
    fun debuggableTargets(): List<CdpTargetInfo> =
        targetsSnapshot().filter { it.canDebug && it.attached && it.sessionId != null }

    /** 按类型过滤 */
    fun targetsOfType(vararg types: String): List<CdpTargetInfo> =
        targetsSnapshot().filter { it.type in types }

    fun findByUrl(urlPart: String): CdpTargetInfo? =
        targetsSnapshot().firstOrNull { it.url.contains(urlPart) }

    fun findBySessionId(sessionId: String): CdpTargetInfo? =
        targetIdBySession[sessionId]?.let { targets[it] }

    fun targetLabel(target: CdpTargetInfo): String {
        val name = target.url.substringAfterLast('/').ifBlank { target.title.ifBlank { target.type } }
        return "${target.type}: $name (${target.targetId.take(8)})"
    }

    // ---------------- 对 target 执行 ----------------

    /**
     * 在指定 target 的子会话上执行 Runtime.evaluate。
     * Worker/ServiceWorker 可直接执行；iframe 返回错误提示走页面会话。
     */
    suspend fun evaluateOnTarget(
        targetId: String,
        expression: String,
        awaitPromise: Boolean = true,
        returnByValue: Boolean = true,
    ): JsonObject {
        val target = targets[targetId]
            ?: return err("target 不存在: $targetId（先 target.list 刷新）")
        val sessionId = target.sessionId
            ?: return err("target 未 attach（iframe 类 target 需经页面会话执行）")
        val result = session.call(
            "Runtime.evaluate",
            buildJsonObject {
                put("expression", expression)
                put("awaitPromise", awaitPromise)
                put("returnByValue", returnByValue)
                put("userGesture", true)
            },
            sessionId,
        ) ?: return err("CDP 调用失败（子会话超时/断开）")
        val remote = result["result"]?.jsonObject ?: JsonObject(emptyMap())
        val exception = result["exceptionDetails"]?.jsonObject
        return buildJsonObject {
            put("ok", exception == null)
            put("target", targetLabel(target))
            put("type", remote["type"]?.jsonPrimitive?.contentOrNull ?: "")
            put("value", remote["value"]?.jsonPrimitive?.contentOrNull
                ?: remote["description"]?.jsonPrimitive?.contentOrNull ?: "")
            exception?.let {
                put("error", it["text"]?.jsonPrimitive?.contentOrNull
                    ?: it["exception"]?.jsonObject?.get("description")?.jsonPrimitive?.contentOrNull ?: "eval 异常")
            }
        }
    }

    /** 对 worker 子会话启用 Debugger domain（断点/栈可见） */
    suspend fun enableDebuggerOnTarget(targetId: String): Boolean {
        val target = targets[targetId] ?: return false
        val sessionId = target.sessionId ?: return false
        return session.call("Debugger.enable", JsonObject(emptyMap()), sessionId) != null
    }

    /** 对 worker 子会话拉取已解析脚本列表（Debugger.scriptParsed 累积，需先 enableDebuggerOnTarget） */
    suspend fun scriptsOnTarget(targetId: String): List<CdpScript> {
        val sessionId = targets[targetId]?.sessionId ?: return emptyList()
        return scriptsBySession[sessionId]?.values?.toList() ?: emptyList()
    }

    /** 手动 attach（autoAttach 未覆盖或 detach 后重连） */
    suspend fun attachToTarget(targetId: String, flatten: Boolean = true): String? {
        val result = session.call(
            "Target.attachToTarget",
            buildJsonObject {
                put("targetId", targetId)
                put("flatten", flatten)
            },
        ) ?: return null
        val sessionId = result["sessionId"]?.jsonPrimitive?.contentOrNull ?: return null
        targetIdBySession[sessionId] = targetId
        targets.computeIfPresent(targetId) { _, old -> old.copy(attached = true, sessionId = sessionId) }
        notifyChanged()
        return sessionId
    }

    suspend fun detachFromTarget(sessionId: String): Boolean {
        val ok = session.call(
            "Target.detachFromTarget",
            buildJsonObject { put("sessionId", sessionId) },
        ) != null
        if (ok) {
            targetIdBySession.remove(sessionId)?.let { tid ->
                targets.computeIfPresent(tid) { _, old -> old.copy(attached = false, sessionId = null) }
            }
            notifyChanged()
        }
        return ok
    }

    /** Target.getTargetInfo：查单个 target 详情（补齐未走事件的字段） */
    suspend fun getTargetInfo(targetId: String): CdpTargetInfo? {
        val result = session.call(
            "Target.getTargetInfo",
            buildJsonObject { put("targetId", targetId) },
        ) ?: return targets[targetId]
        return result["targetInfo"]?.jsonObject?.let { parseTargetInfo(it) }
    }

    /** 重载 target（拿到干净执行环境） */
    suspend fun reloadTarget(targetId: String): Boolean {
        val sessionId = targets[targetId]?.sessionId ?: return false
        return session.call("Page.reload", JsonObject(emptyMap()), sessionId) != null
    }

    private fun err(message: String): JsonObject =
        buildJsonObject {
            put("ok", false)
            put("error", message)
        }

    companion object {
        /** 可直接 Runtime.evaluate 的 target 类型（iframe 的 JS 走所属页面会话） */
        private val DEBUGGABLE_TYPES = setOf(
            "page", "worker", "service_worker", "shared_worker", "dedicated_worker", "browser",
        )

        private val TYPE_ORDER = listOf(
            "page", "iframe", "worker", "dedicated_worker", "shared_worker", "service_worker", "browser", "other",
        )
    }
}
