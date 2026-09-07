package com.webreverse.mcp.mcp.server

import com.webreverse.mcp.core.logging.AppLogger
import com.webreverse.mcp.core.logging.LogCategory
import com.webreverse.mcp.devtools.protocol.cdp.CdpTransport
import com.webreverse.mcp.devtools.protocol.cdp.RawWebSocket
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * CDP 会话复用枢纽：同一 target 只保持一条后端 CDP 连接（LocalWebSocket 直连
 * WebView DevTools unix socket），进程内 MCP 工具（及可能的外部调试客户端）
 * 都作为客户端接入。
 *
 * 客户端来源（对枢纽同构，均为标准 WebSocket；用 [ClientKind] 区分语义）：
 * - MCP 工具：CdpDebuggerSession / CdpNetworkMonitor（TcpWebSocket → 127.0.0.1
 *   回环，ws path 携带 ?client=mcp）
 * - 外部客户端：无 client 参数的 WS 会话（如经 adb 端口转发接入的桌面调试器），
 *   按"UI 所有者"语义处理——断开即撤销其断点并自动恢复暂停（对齐桌面 Chrome
 *   关闭 DevTools 窗口的行为）
 *
 * 消息路由规则：
 * - 请求（客户端 → 后端）：JSON-RPC id 重写为全局唯一 hubId 再转发，记录映射
 * - 响应（后端 → 客户端）：按 hubId 查映射路由回发起方，id 还原为原值
 * - 事件（后端无 id 消息）：广播给所有客户端
 *
 * 联动语义：任一 MCP 会话设断点命中 → Debugger.paused 广播 → 其他 MCP 会话
 * 同步收到；单步/恢复/Console 求值 → 全部会话事件流同步。所有客户端共享同一条
 * V8 会话状态，互不踢线。
 *
 * 【断开语义（对齐桌面 Chrome：客户端断开即撤销其调试影响）】
 * - 断点归属：追踪每个客户端 setBreakpoint* 设置的断点 id（及 DOMDebugger 事件/
 *   XHR 断点请求原文），外部客户端断开时自动向后端发送对应 remove，断点不残留；
 * - 自动恢复：页面处于暂停态且"暂停归因于离开的客户端"（其断点命中 / 其发起的
 *   pause/step），或所有客户端均已离开时，自动 Debugger.resume——否则客户端
 *   尽数离开后页面将永久卡死（转圈）无人能恢复；
 * - 状态重放：后接入的客户端 Debugger.enable 后，重放缓存的 scriptParsed 事件与
 *   当前 paused 事件——晚接入的客户端能立即看到完整脚本列表与暂停现场。
 *
 * id 重写采用前缀快速路径（`{"id":123` / `{"method":...`），不做全量 JSON 解析——
 * CDP 响应体可达数十 MB（截图/响应体 base64），逐条 parse 重建的内存与 CPU
 * 开销不可接受；Chromium JSONWriter 保证 id/method 恒在消息首位。
 */
internal class CdpHubSession(
    private val logger: AppLogger,
    private val scope: CoroutineScope,
    private val label: String,
    private val onDead: (CdpHubSession) -> Unit,
) {

    /** 客户端类型：进程内 MCP 工具 / 外部调试客户端（UI 所有者语义，断开撤销其断点） */
    enum class ClientKind { MCP, EXTERNAL }

    /** 枢纽客户端（由 WS 中继实现：send 发帧给对端，backendClosed 通知对端后端已断） */
    interface Client {
        suspend fun send(text: String): Boolean
        fun onBackendClosed(reason: String)
    }

    companion object {
        /** hubId 起始值：与客户端侧 id（客户端均从 1 递增）错开，便于日志辨识 */
        private const val HUB_ID_BASE = 1_000_000

        /** 全部客户端离开后，后端连接的保留时长（客户端重连窗口，避免后端连接抖动） */
        private const val IDLE_CLOSE_DELAY_MS = 10_000L

        /** scriptParsed 重放缓存上限（页面脚本数量防御，超出丢最旧） */
        private const val SCRIPT_CACHE_MAX = 3000

        /** 状态重放延迟：让后端紧随 enable 响应的原始事件先送达 */
        private const val REPLAY_DELAY_MS = 250L

        /** 消息首部的 JSON-RPC id（Chromium 序列化保证 id/method 在首位） */
        private val ID_PREFIX = Regex("^\\{\"id\":(\\d+)")
        private val METHOD_PREFIX = Regex("^\\{\"method\":\"([^\"]+)\"")
        private val METHOD_ANYWHERE = Regex("\"method\":\"([^\"]+)\"")
        private val BP_ID_IN_RESPONSE = Regex("\"breakpointId\":\"([^\"]+)\"")
        private val BP_ID_IN_REQUEST = Regex("\"breakpointId\":\"([^\"]+)\"")
        private val HIT_BPS = Regex("\"hitBreakpoints\":\\[(.*?)]")
        private val QUOTED = Regex("\"([^\"]*)\"")

        /** 返回 breakpointId、需归属到发起客户端的 Debugger 域断点设置命令 */
        private val BP_SET_METHODS = setOf(
            "Debugger.setBreakpoint",
            "Debugger.setBreakpointByUrl",
            "Debugger.setBreakpointOnFunctionCall",
        )

        /** DOM/XHR/事件监听断点：无返回 id，断开时按缓存请求原文合成 remove 命令 */
        private val DOM_BP_SET_METHODS = setOf(
            "DOMDebugger.setEventListenerBreakpoint",
            "DOMDebugger.setInstrumentationBreakpoint",
            "DOMDebugger.setXHRBreakpoint",
        )

        /** 执行控制命令（用于"暂停归因"：最后发命令者拥有执行控制权） */
        private val CONTROL_METHODS = setOf(
            "Debugger.pause",
            "Debugger.resume",
            "Debugger.stepInto",
            "Debugger.stepOver",
            "Debugger.stepOut",
            "Debugger.restartFrame",
        )
    }

    /** hubId → 发起客户端与原始 id、method（method 供断点归属/状态重放判定） */
    private class PendingEntry(val clientKey: Long, val originalId: Int, val method: String?)

    private val pending = ConcurrentHashMap<Int, PendingEntry>()

    private val clients = ConcurrentHashMap<Long, Client>()
    private val clientKinds = ConcurrentHashMap<Long, ClientKind>()
    private val clientKeys = AtomicLong(0)
    private val hubIds = AtomicInteger(HUB_ID_BASE)

    /** clientKey → 其设置的 CDP breakpointId 集合（断开时逐个 remove） */
    private val clientBreakpointIds = ConcurrentHashMap<Long, MutableSet<String>>()

    /** clientKey → DOMDebugger 断点设置请求原文（断开时改写 set→remove 重发） */
    private val clientDomBpRequests = ConcurrentHashMap<Long, MutableList<String>>()

    /** 当前暂停态的 Debugger.paused 原始消息（重放给后接入客户端）；null = 运行中 */
    @Volatile
    private var pausedEvent: String? = null

    /** 当前暂停命中的 breakpointId 列表（暂停归因用） */
    @Volatile
    private var hitBreakpoints: List<String> = emptyList()

    /** 最后发送执行控制命令的客户端（step/pause/resume 的"控制权"持有者） */
    @Volatile
    private var controllerKey: Long = -1L

    /** scriptParsed 事件缓存（后接入客户端 enable 后重放，补齐 Sources 脚本列表） */
    private val scriptCache = ArrayDeque<String>()

    /**
     * breakpointResolved 事件缓存（breakpointId → 原始消息）。
     * 断点状态与 scriptParsed 同为"事件即状态"：后接入的客户端收不到历史
     * resolved 事件就看不到已存在的断点——MCP list_breakpoints 为空。故缓存
     * 并随状态重放；断点移除（removeBreakpoint 请求 / 客户端断开批量撤销）
     * 时同步清缓存。
     */
    private val breakpointCache = LinkedHashMap<String, String>()

    @Volatile
    var backend: RawWebSocket? = null
        private set

    @Volatile
    var backendPath: String = ""
        private set

    private var pumpJob: Job? = null
    private var idleCloseJob: Job? = null

    val clientCount: Int get() = clients.size
    val isConnected: Boolean get() = backend?.let { !it.isClosed() } == true

    /** 当前暂停中（后端 Debugger.paused 且未 resume） */
    val isPaused: Boolean get() = pausedEvent != null

    /**
     * 外部放行：页面处于暂停态时向后端发送 Debugger.resume。
     * 供 App UI 暂停提示条 / MCP debugger.resume 兜底调用——手机上没有放行
     * 入口时，断点命中后页面会一直卡死在暂停态。
     * @return 是否执行了恢复（false = 本就运行中）
     */
    fun resumeIfPaused(): Boolean {
        if (pausedEvent == null) return false
        sendToBackend("""{"id":${hubIds.incrementAndGet()},"method":"Debugger.resume"}""")
        logger.i(LogCategory.MCP, "CDP 枢纽[$label]: 外部请求放行，已发送 Debugger.resume")
        return true
    }

    /** 外部（非 MCP）客户端连接数（如经 adb 端口转发接入的桌面调试器） */
    val externalClientCount: Int get() = clientKinds.values.count { it == ClientKind.EXTERNAL }

    /** MCP 工具连接数 */
    val mcpClientCount: Int get() = clientKinds.values.count { it == ClientKind.MCP }

    // ---------------- 后端生命周期 ----------------

    /**
     * 建立后端 CDP 连接（target 路径变化时重连）。幂等：同路径且存活直接返回。
     * @return 是否成功
     */
    suspend fun startBackend(path: String): Boolean {
        if (isConnected && backendPath == path) return true
        closeBackendOnly("重建后端连接")
        val ws = withContext(Dispatchers.IO) { CdpTransport.connectWebSocket(wsPath = path) }
        if (ws == null) return false
        backend = ws
        backendPath = path
        idleCloseJob?.cancel()
        pumpJob = scope.launch(Dispatchers.IO) { pumpBackend(ws) }
        return true
    }

    /** 只关后端连接，不动客户端（重建场景）；自然断开走 [onBackendClosed] */
    fun closeBackendOnly(reason: String) {
        val be = backend
        backend = null
        pumpJob?.cancel()
        pumpJob = null
        // 后端会话级状态随连接失效：scriptId/breakpointId 均为会话作用域，
        // 旧数据重放给新会话客户端会造成幽灵脚本/断点
        synchronized(scriptCache) { scriptCache.clear() }
        synchronized(breakpointCache) { breakpointCache.clear() }
        pausedEvent = null
        hitBreakpoints = emptyList()
        controllerKey = -1L
        clientBreakpointIds.clear()
        clientDomBpRequests.clear()
        if (be != null) {
            runCatching { be.close() }
            logger.i(LogCategory.MCP, "CDP 枢纽[$label]: 后端主动关闭($reason) $backendPath")
        }
    }

    /** 后端读循环：响应路由 + 事件广播；结束即后端断开，通知所有客户端 */
    private suspend fun pumpBackend(ws: RawWebSocket) {
        var reason = "EOF"
        try {
            while (!ws.isClosed()) {
                val msg = ws.readTextMessage()
                if (msg == null) {
                    reason = ws.lastEndReason ?: "EOF"
                    break
                }
                if (msg.isEmpty()) continue
                dispatchBackendMessage(msg)
            }
        } catch (e: Exception) {
            reason = "${e.javaClass.simpleName}: ${e.message}"
        }
        // closeBackendOnly/startBackend 重建时 backend 已被替换/置空，此处不触发清理
        if (backend === ws) onBackendClosed(reason)
    }

    // ---------------- 消息路由 ----------------

    /** 客户端 → 后端：请求 id 重写为全局唯一 hubId（阻塞 socket 写跑在 IO） */
    suspend fun onClientMessage(clientKey: Long, text: String) {
        val be = backend ?: return
        val rewritten = rewriteRequestId(clientKey, text) ?: text
        withContext(Dispatchers.IO) { runCatching { be.sendText(rewritten) } }
    }

    private fun rewriteRequestId(clientKey: Long, text: String): String? {
        val m = ID_PREFIX.find(text) ?: return null // 非请求（无 id）：原样转发
        val originalId = m.groupValues[1].toIntOrNull() ?: return null
        val method = METHOD_ANYWHERE.find(text)?.groupValues?.get(1)
        val hubId = hubIds.incrementAndGet()
        pending[hubId] = PendingEntry(clientKey, originalId, method)
        trackClientRequest(clientKey, method, text)
        return text.replaceRange(m.groups[1]!!.range, hubId.toString())
    }

    /** 断点归属与控制权追踪（仅请求消息；事件不在本方法处理） */
    private fun trackClientRequest(clientKey: Long, method: String?, text: String) {
        if (method == null) return
        when {
            method in CONTROL_METHODS -> controllerKey = clientKey

            method == "Debugger.removeBreakpoint" ->
                BP_ID_IN_REQUEST.find(text)?.groupValues?.get(1)?.let { bpId ->
                    clientBreakpointIds[clientKey]?.remove(bpId)
                    // 断点已撤：同步清缓存，重放不再发给后接入客户端
                    synchronized(breakpointCache) { breakpointCache.remove(bpId) }
                }

            method in DOM_BP_SET_METHODS ->
                clientDomBpRequests.getOrPut(clientKey) { mutableListOf() }.add(text)

            method.startsWith("DOMDebugger.remove") -> {
                // 客户端撤销事件/XHR 断点：按 params 文本匹配移除缓存请求
                val params = paramsSnippet(text)
                clientDomBpRequests[clientKey]?.removeAll { cached ->
                    cached.contains("\"method\":\"${method.replaceFirst("remove", "set")}\"") &&
                        paramsSnippet(cached) == params
                }
            }
        }
    }

    private fun paramsSnippet(text: String): String =
        text.substringAfter("\"params\":", "").removeSuffix("}")

    /** 后端 → 客户端：响应按 hubId 路由回发起方（id 还原），事件广播 */
    private suspend fun dispatchBackendMessage(msg: String) {
        val m = ID_PREFIX.find(msg)
        if (m != null) {
            // 响应消息：按 hubId 路由回发起方，id 还原为客户端原值
            val hubId = m.groupValues[1].toIntOrNull()
            val entry = hubId?.let { pending.remove(it) }
            if (entry != null) {
                val rewritten = msg.replaceRange(m.groups[1]!!.range, entry.originalId.toString())
                if (entry.method in BP_SET_METHODS) {
                    BP_ID_IN_RESPONSE.find(msg)?.groupValues?.get(1)?.let { bpId ->
                        clientBreakpointIds.getOrPut(entry.clientKey) { ConcurrentHashMap.newKeySet() }.add(bpId)
                    }
                }
                val client = clients[entry.clientKey] ?: return
                runCatching { client.send(rewritten) }
                // Debugger.enable 响应后重放状态：脚本列表 + 暂停现场（后接入方补齐）
                if (entry.method == "Debugger.enable") replayStateTo(entry.clientKey)
            }
            // 无归属（发起方已离开）：丢弃。广播会让其他客户端收到不认识的 id，
            // 客户端可能报协议错误
            return
        }
        // 事件（无 id，{"method":... 开头）：先更新枢纽状态缓存，再广播给所有客户端
        cacheBackendEvent(msg)
        for ((key, client) in clients) {
            runCatching { client.send(msg) }
                .onFailure { clients.remove(key) } // 发送失败视为死客户端
        }
    }

    /** 缓存后端事件中的关键状态（scriptParsed / breakpointResolved / paused / resumed） */
    private fun cacheBackendEvent(msg: String) {
        val method = METHOD_PREFIX.find(msg)?.groupValues?.get(1) ?: return
        when (method) {
            "Debugger.scriptParsed" -> {
                synchronized(scriptCache) {
                    if (scriptCache.size >= SCRIPT_CACHE_MAX) scriptCache.removeFirst()
                    scriptCache.addLast(msg)
                }
            }

            "Debugger.breakpointResolved" -> {
                BP_ID_IN_REQUEST.find(msg)?.groupValues?.get(1)?.let { bpId ->
                    synchronized(breakpointCache) { breakpointCache[bpId] = msg }
                }
            }

            "Debugger.paused" -> {
                pausedEvent = msg
                hitBreakpoints = HIT_BPS.find(msg)?.groupValues?.get(1)
                    ?.let { QUOTED.findAll(it).map { q -> q.groupValues[1] }.toList() }
                    ?: emptyList()
            }

            "Debugger.resumed" -> {
                pausedEvent = null
                hitBreakpoints = emptyList()
                controllerKey = -1L
            }
        }
    }

    /**
     * 向指定客户端重放缓存状态，延迟让原始事件先过。
     * 顺序：scriptParsed → breakpointResolved → paused（脚本先到位，
     * 断点 location 的 scriptId 才能被客户端解析；暂停现场最后）。
     */
    private fun replayStateTo(clientKey: Long) {
        val client = clients[clientKey] ?: return
        val scripts: List<String> = synchronized(scriptCache) { scriptCache.toList() }
        val breakpoints: List<String> = synchronized(breakpointCache) { breakpointCache.values.toList() }
        val paused = pausedEvent
        if (scripts.isEmpty() && breakpoints.isEmpty() && paused == null) return
        scope.launch {
            delay(REPLAY_DELAY_MS)
            val c = clients[clientKey] ?: return@launch
            for (s in scripts) runCatching { c.send(s) }
            for (b in breakpoints) runCatching { c.send(b) }
            paused?.let { runCatching { c.send(it) } }
            logger.i(
                LogCategory.MCP,
                "CDP 枢纽[$label]: 已向客户端 #$clientKey 重放状态" +
                    "（scripts=${scripts.size} breakpoints=${breakpoints.size} paused=${paused != null}）",
            )
        }
    }

    // ---------------- 客户端管理 ----------------

    /** 客户端接入，返回分配的 clientKey */
    fun addClient(client: Client, kind: ClientKind = ClientKind.EXTERNAL): Long {
        val key = clientKeys.incrementAndGet()
        clients[key] = client
        clientKinds[key] = kind
        idleCloseJob?.cancel()
        logger.i(
            LogCategory.MCP,
            "CDP 枢纽[$label]: 客户端 #$key 接入($kind，共 ${clients.size} 个)" +
                (if (pausedEvent != null) " [页面处于暂停态]" else "") + " $backendPath",
        )
        return key
    }

    /**
     * 客户端离开；执行断开语义（对齐桌面 Chrome 关闭 DevTools 窗口）：
     * 1. 外部客户端离开：撤销其设置的全部断点（CDP breakpointId +
     *    DOMDebugger 事件/XHR 断点）；
     *    MCP 客户端离开【不】代撤——MCP 断点由 DebuggerManager 显式管理
     *    （remove_breakpoint / detach 时撤销），否则 AI 工作流中重复
     *    debugger.attach（attach 内部会重建会话）会静默撤销之前设的全部断点；
     * 2. 页面处于暂停态且暂停归因于该客户端（或所有客户端已离开）时自动恢复执行，
     *    否则客户端尽数离开后断点命中会把页面永久卡死在暂停态（转圈）无人能恢复。
     */
    fun removeClient(key: Long) {
        val isExternal = clientKinds[key] == ClientKind.EXTERNAL
        clients.remove(key)
        clientKinds.remove(key)
        val it = pending.entries.iterator()
        while (it.hasNext()) {
            if (it.next().value.clientKey == key) it.remove()
        }
        val ownedBps = clientBreakpointIds.remove(key) ?: emptySet()
        val domRequests = clientDomBpRequests.remove(key) ?: emptyList()
        val wasController = controllerKey == key
        if (wasController) controllerKey = -1L
        val noExternalLeft = clientKinds.values.none { it == ClientKind.EXTERNAL }
        logger.i(
            LogCategory.MCP,
            "CDP 枢纽[$label]: 客户端 #$key 离开（剩余 ${clients.size} 个，" +
                (if (isExternal) "撤销断点 ${ownedBps.size + domRequests.size} 个" else "MCP 客户端，断点保留 ${ownedBps.size} 个") +
                (if (pausedEvent != null) "，页面暂停中" else "") + "）",
        )

        if (isExternal) {
            // 1) 撤销该客户端设置的断点（响应无归属，hub 路由层自动丢弃）
            for (bpId in ownedBps) {
                synchronized(breakpointCache) { breakpointCache.remove(bpId) }
                sendToBackend("""{"id":${hubIds.incrementAndGet()},"method":"Debugger.removeBreakpoint","params":{"breakpointId":"$bpId"}}""")
            }
            for (raw in domRequests) {
                synthesizeDomRemoval(raw)?.let { sendToBackend(it) }
            }
        }

        // 2) 自动恢复判定
        if (pausedEvent != null) {
            val resume = clients.isEmpty() ||
                (noExternalLeft && pauseOwnedByLeaving(key, ownedBps, wasController))
            if (resume) {
                logger.i(
                    LogCategory.MCP,
                    "CDP 枢纽[$label]: 暂停态无调试 UI 接管，自动恢复执行" +
                        "（hitBreakpoints=${hitBreakpoints}）",
                )
                sendToBackend("""{"id":${hubIds.incrementAndGet()},"method":"Debugger.resume"}""")
            }
        }

        if (clients.isEmpty()) scheduleIdleClose()
    }

    /** 暂停是否归因于离开的客户端：其断点命中，或其发起的 pause/step（无断点命中时） */
    private fun pauseOwnedByLeaving(
        leavingKey: Long,
        leavingBps: Set<String>,
        wasController: Boolean,
    ): Boolean {
        if (hitBreakpoints.isNotEmpty()) return hitBreakpoints.all { it in leavingBps }
        // 无断点命中（手动 pause / step / 页内 debugger; 语句）：控制权归属者或无主暂停
        return wasController || controllerKey == -1L || controllerKey == leavingKey
    }

    /** DOMDebugger 断点设置请求原文 → 对应 remove 命令（method set→remove，id 换新） */
    private fun synthesizeDomRemoval(rawRequest: String): String? {
        val idMatch = ID_PREFIX.find(rawRequest) ?: return null
        val setMethod = METHOD_ANYWHERE.find(rawRequest)?.groupValues?.get(1) ?: return null
        if (!setMethod.startsWith("DOMDebugger.set")) return null
        val removeMethod = "DOMDebugger.remove" + setMethod.removePrefix("DOMDebugger.set")
        return rawRequest
            .replaceRange(idMatch.groups[1]!!.range, hubIds.incrementAndGet().toString())
            .replace("\"method\":\"$setMethod\"", "\"method\":\"$removeMethod\"")
    }

    /** 向后端发送枢纽自身发起的命令（不注册 pending，响应自动丢弃） */
    private fun sendToBackend(text: String) {
        val be = backend ?: return
        scope.launch(Dispatchers.IO) {
            val current = backend ?: return@launch
            if (current === be) runCatching { current.sendText(text) }
        }
    }

    private fun scheduleIdleClose() {
        idleCloseJob?.cancel()
        idleCloseJob = scope.launch {
            delay(IDLE_CLOSE_DELAY_MS)
            if (clients.isEmpty() && backend != null) {
                logger.i(LogCategory.MCP, "CDP 枢纽[$label]: 空闲超时，关闭后端 $backendPath")
                closeBackendOnly("idle")
                onDead(this@CdpHubSession)
            }
        }
    }

    /** 后端自然断开（页面导航/target 销毁）：断开全部客户端并清理 */
    private fun onBackendClosed(reason: String) {
        backend = null
        pumpJob = null
        pending.clear()
        synchronized(scriptCache) { scriptCache.clear() }
        pausedEvent = null
        hitBreakpoints = emptyList()
        controllerKey = -1L
        clientBreakpointIds.clear()
        clientDomBpRequests.clear()
        val snapshot = clients.values.toList()
        clients.clear()
        clientKinds.clear()
        for (c in snapshot) runCatching { c.onBackendClosed(reason) }
        onDead(this)
        logger.w(
            LogCategory.MCP,
            "CDP 枢纽[$label]: 后端断开($reason)，已断开 ${snapshot.size} 个客户端 $backendPath",
        )
    }
}
