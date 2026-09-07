package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.common.event.NetworkEvent
import com.webreverse.mcp.core.database.entity.NetworkEntryEntity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.filterIsInstance
import kotlinx.coroutines.launch
import java.util.concurrent.ConcurrentHashMap

/**
 * P0-6 网络持久化桥：把 EventBus 上的网络事件真正写入 Room。
 *
 * 动机（对应 ChatGPT 分析十四）： 已有 `NetworkEntryEntity / NetworkRepository /
 * NetworkEntryDao`，但 `networkRepository.upsert(...)` 在源码中没有任何调用点——Room 网络表
 * 只是「准备好了」，`CdpNetworkMonitor` 的数据从未落库。导致：
 * - `network.list` 看到的是内存（EvidenceStore/NetworkInspector）
 * - `workspace` 看到的是数据库
 * - 重启 App 后网络历史全部消失（内存世界崩塌）
 *
 * 本桥订阅 EventBus 的 NetworkEvent（RequestStarted/ResponseReceived/RequestCompleted/RequestFailed），
 * 组装成 NetworkEntryEntity 通过 NetworkRepository 落库，形成
 * `CdpNetworkMonitor → NetworkEvent → NetworkPersistenceBridge → NetworkRepository → Room`
 * 的完整链路，而不是让 Tool 层自己保存。
 *
 * 归并策略：以 entryId 为主键，RequestStarted 先写一条占位记录，RequestCompleted/RequestFailed
 * 时读取内存缓存合并写回状态/耗时，避免多事件覆盖丢字段。
 */
class NetworkPersistenceBridge(
    private val deps: ToolDependencies,
    private val scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.IO),
) {
    private var job: Job? = null

    /** entryId → 内存中的半成品记录（用于合并 RequestStarted → Completed 的状态） */
    private val pending = ConcurrentHashMap<String, NetworkEntryEntity>()

    /** 启动订阅 */
    fun start() {
        if (job != null) return
        job = scope.launch {
            // 报七：持久化走 EventBus 的 journal（replay 缓冲），慢落库时网络事件也不静默丢失
            deps.eventBus.journal
                .filterIsInstance<NetworkEvent>()
                .collect { e ->
                    try {
                        persist(e)
                    } catch (t: Throwable) {
                        deps.logger.e(com.webreverse.mcp.core.logging.LogCategory.NETWORK, "网络持久化失败: ${t.message}")
                    }
                }
        }
    }

    /** 停止订阅 */
    fun stop() {
        job?.cancel()
        job = null
        pending.clear()
    }

    private suspend fun persist(e: NetworkEvent) {
        when (e) {
            is NetworkEvent.RequestStarted -> {
                val entity = NetworkEntryEntity(
                    id = e.entryId,
                    tabId = e.tabId,
                    requestId = e.entryId,
                    url = e.url,
                    method = e.method,
                    startedAt = e.timestamp,
                )
                pending[e.entryId] = entity
                deps.networkRepository.upsert(entity)
            }
            is NetworkEvent.ResponseReceived -> {
                val base = pending[e.entryId] ?: NetworkEntryEntity(
                    id = e.entryId, tabId = e.tabId, requestId = e.entryId, url = e.url,
                    startedAt = e.timestamp,
                )
                val merged = base.copy(status = e.status)
                pending[e.entryId] = merged
                deps.networkRepository.upsert(merged)
            }
            is NetworkEvent.RequestCompleted -> {
                val base = pending.remove(e.entryId) ?: NetworkEntryEntity(
                    id = e.entryId, tabId = e.tabId, requestId = e.entryId, url = e.url,
                    startedAt = e.timestamp,
                )
                val merged = base.copy(
                    status = e.status,
                    endedAt = e.timestamp,
                )
                deps.networkRepository.upsert(merged)
            }
            is NetworkEvent.RequestFailed -> {
                val base = pending.remove(e.entryId) ?: NetworkEntryEntity(
                    id = e.entryId, tabId = e.tabId, requestId = e.entryId, url = e.url,
                    startedAt = e.timestamp,
                )
                val merged = base.copy(status = 0, endedAt = e.timestamp)
                deps.networkRepository.upsert(merged)
            }
            is NetworkEvent.WebSocketFrame -> {
                // WebSocket 帧消息不含 entryId，忽略（由 NetworkInspector 内存层单独维护）
            }
            is NetworkEvent.SseMessage -> {
                // SSE 推送消息不含 entryId，忽略（由 NetworkInspector 内存层单独维护）
            }
        }
    }
}