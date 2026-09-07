package com.webreverse.mcp.mcp.server

import android.content.Context
import com.webreverse.mcp.core.common.event.EventBus
import com.webreverse.mcp.core.common.model.McpClient
import com.webreverse.mcp.core.common.model.McpServerConfig
import com.webreverse.mcp.core.logging.AppLogger
import com.webreverse.mcp.core.logging.LogCategory
import com.webreverse.mcp.core.security.TokenManager
import com.webreverse.mcp.mcp.tools.ToolDependencies
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.net.Inet4Address
import java.net.NetworkInterface
import java.net.ServerSocket

/**
 * MCP Server 管理器：负责 Server 生命周期、配置持久化、连接管理。
 * 提供给 UI 层（MCP Server 管理页面）使用。
 */
class McpServerManager(
    private val context: Context,
    private val deps: ToolDependencies,
    private val tokenManager: TokenManager,
    private val eventBus: EventBus,
    private val logger: AppLogger,
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    // 端口持久化。保存在应用私有 SharedPreferences 中，下次启动时恢复，
    // 用户修改端口并保存后，重启 APP 仍使用该端口。
    private val portPrefs = context.applicationContext
        .getSharedPreferences("mcp_prefs", Context.MODE_PRIVATE)

    private val _config = MutableStateFlow(McpServerConfig().copy(port = loadSavedPort()))
    val config: StateFlow<McpServerConfig> = _config.asStateFlow()

    private val _serverState = MutableStateFlow(McpServerState.STOPPED)
    val serverState: StateFlow<McpServerState> = _serverState.asStateFlow()

    private val _clients = MutableStateFlow<List<McpClient>>(emptyList())
    val clients: StateFlow<List<McpClient>> = _clients.asStateFlow()

    private val _stats = MutableStateFlow(McpServerStats(McpServerState.STOPPED))
    val stats: StateFlow<McpServerStats> = _stats.asStateFlow()

    private var server: McpServer? = null

    /**
     * 生命周期互斥锁——序列化 start / stop / restart。
     * 修复：快速连续切换配置开关触发多次 restart 并发交错，stop 的 Netty 异步端口释放
     * 与下一次 start 的端口检测竞争，导致「端口已被占用」误报、服务进入 ERROR。
     */
    private val lifecycleMutex = Mutex()

    /**
     * 运行意图标志（独立于实际状态）。
     * restart 中途状态会短暂经过 STOPPED/server==null，仅凭状态无法判断"是否应保持运行"，
     * 用此标志保证防抖重启在 restart 进行中的配置变更也能最终生效。
     */
    @Volatile
    private var desiredRunning = false

    /* * ：防抖重启任务（合并短时间内的连续配置变更，只重启一次） */
    private var restartJob: Job? = null

    /** 统计轮询任务：运行期间每秒从 Server 同步统计与客户端列表到 StateFlow */
    private var statsJob: Job? = null

    /** 读取本 App 版本名（供 serverInfo.version 使用；失败回退 unknown） */
    private fun appVersionName(): String = try {
        @Suppress("DEPRECATION")
        context.packageManager.getPackageInfo(context.packageName, 0).versionName ?: "unknown"
    } catch (e: Exception) {
        "unknown"
    }

    /** 启动 Server（端口检测等阻塞操作切换到 IO 线程，避免 UI 主线程调用时卡顿） */
    suspend fun start(): Boolean = lifecycleMutex.withLock {
        desiredRunning = true
        startLocked()
    }

    private suspend fun startLocked(): Boolean {
        if (_serverState.value == McpServerState.RUNNING) return true
        return withContext(Dispatchers.IO) {
            // 端口占用检测
            if (isPortInUse(_config.value.port)) {
                // 端口占用先等待释放（上一次实例正在异步关闭），仍占用才判定失败。
                // 此前直接报「端口被占用」进入 ERROR，快速重启场景下极易误判
                logger.i(LogCategory.MCP, "端口 ${_config.value.port} 暂被占用，等待释放...")
                awaitPortReleased(_config.value.port, waitForMs = 5_000)
            }
            if (isPortInUse(_config.value.port)) {
                _serverState.value = McpServerState.ERROR
                logger.e(LogCategory.MCP, "端口 ${_config.value.port} 已被占用")
                return@withContext false
            }

            val cfg = _config.value.copy(enabled = true)
            _config.value = cfg

            val srv = McpServer(
                deps = deps,
                tokenManager = tokenManager,
                eventBus = eventBus,
                logger = logger,
                config = cfg,
                // serverInfo.version 用真实 App 版本号（原先硬编码会与实际版本漂移）
                serverVersion = appVersionName(),
            )
            val ok = srv.start()
            if (ok) {
                server = srv
                _serverState.value = McpServerState.RUNNING
                startStatsPolling()
                refreshStats()
                logger.i(LogCategory.MCP, "MCP Server 已启动")
            } else {
                _serverState.value = McpServerState.ERROR
            }
            ok
        }
    }

    /** 停止 Server（Netty 关闭为阻塞操作，切换到 IO 线程执行，避免 UI 主线程调用时卡顿） */
    suspend fun stop(): Boolean = lifecycleMutex.withLock {
        desiredRunning = false
        restartJob?.cancel()
        restartJob = null
        stopLocked()
    }

    private suspend fun stopLocked(): Boolean {
        val srv = server ?: return false
        return withContext(Dispatchers.IO) {
            val ok = srv.stop()
            if (ok) {
                server = null
                stopStatsPolling()
                _serverState.value = McpServerState.STOPPED
                _config.value = _config.value.copy(enabled = false)
                _stats.value = McpServerStats(McpServerState.STOPPED)
                _clients.value = emptyList()
                logger.i(LogCategory.MCP, "MCP Server 已停止")
                // Netty stop 为异步优雅关闭，确认端口真正释放后再返回，
                // 保证紧随其后的 start（restart 场景）不会撞上残留监听
                awaitPortReleased(srv.currentConfig().port, waitForMs = 5_000)
            }
            ok
        }
    }

    /** 重启 Server */
    suspend fun restart(): Boolean = lifecycleMutex.withLock {
        stopLocked()
        startLocked()
    }

    /**
     * 轮询等待端口释放（旧实例异步关闭 / TIME_WAIT 场景），超时后放弃。
     * 仅在生命周期锁内调用，保证检测-绑定不与其他启停交错。
     */
    private suspend fun awaitPortReleased(port: Int, waitForMs: Long) {
        val deadline = System.currentTimeMillis() + waitForMs
        while (System.currentTimeMillis() < deadline) {
            if (!isPortInUse(port)) return
            delay(150)
        }
    }

    /** 更新配置 */
    suspend fun updateConfig(config: McpServerConfig) {
        lifecycleMutex.withLock {
            val previousPort = _config.value.port
            _config.value = config
            // 端口持久化——端口变化时同步写入 SharedPreferences，重启后恢复
            if (config.port != previousPort) {
                savePort(config.port)
                logger.i(LogCategory.MCP, "MCP Server 端口已持久化为 ${config.port}")
            }
        }
        // 防抖重启。运行中网络/认证配置变更需重启生效；快速连续修改时，旧实现每次变更都立即 restart：
        // 多次 restart 并发交错，stop 的 Netty 异步端口释放与下一次 start 的端口检测竞争，
        // 造成「端口被占用」误报。现合并 500ms 内的连续变更只重启一次；
        // 重启期间若有新变更，会追加重启直至配置与运行实例一致。
        if (desiredRunning) {
            scheduleDebouncedRestart()
        }
    }

    /**
     * 调度防抖重启（取消旧任务，500ms 静默期后执行）。
     * 重启用 NonCancellable 保证 stop/start 流程不被中途打断产生悬挂状态；
     * 自愈循环：重启后配置若又变化（重启期间的变更），追加重启一轮。
     */
    private fun scheduleDebouncedRestart() {
        restartJob?.cancel()
        restartJob = scope.launch {
            delay(500)
            while (isActive) {
                if (!desiredRunning) break
                val configBefore = _config.value
                val ok = withContext(NonCancellable) {
                    runCatching { restart() }.getOrDefault(false)
                }
                // 重启失败（如端口被外部进程占用）或配置已收敛时结束循环
                if (!ok || _config.value == configBefore) break
            }
        }
    }

    /** 读取已持久化的端口；无记录或非法时回退默认 8787 */
    private fun loadSavedPort(): Int {
        val saved = portPrefs.getInt(KEY_PORT, -1)
        return if (saved in 1024..65535) saved else McpServerConfig.DEFAULT_PORT
    }

    /** 保存端口到 SharedPreferences */
    private fun savePort(port: Int) {
        portPrefs.edit().putInt(KEY_PORT, port).apply()
    }

    /** 获取当前运行状态 */
    fun isRunning(): Boolean = _serverState.value == McpServerState.RUNNING

    /** 检查端口是否被占用（阻塞 socket 操作，仅供 IO 线程内部使用） */
    fun isPortInUse(port: Int): Boolean {
        return try {
            ServerSocket(port).use { socket ->
                socket.reuseAddress = true
                // 如果能绑定说明端口可用，绑定失败说明被占用
                false
            }
        } catch (e: Exception) {
            true
        }
    }

    /** 检查端口是否被占用（挂起版本，自动切换到 IO 线程，供 UI 安全调用） */
    suspend fun checkPort(port: Int): Boolean = withContext(Dispatchers.IO) { isPortInUse(port) }

    /** 获取本机局域网 IP 地址列表 */
    fun getLanAddresses(): List<String> {
        val addresses = mutableListOf<String>()
        try {
            val interfaces = NetworkInterface.getNetworkInterfaces()
            for (intf in interfaces) {
                // 跳过回环和未启用的接口
                if (intf.isLoopback || !intf.isUp) continue
                for (addr in intf.inetAddresses) {
                    if (addr is Inet4Address && !addr.isLoopbackAddress) {
                        addresses.add(addr.hostAddress ?: "")
                    }
                }
            }
        } catch (e: Exception) {
            logger.e(LogCategory.MCP, "获取局域网地址失败: ${e.message}")
        }
        return addresses.filter { it.isNotEmpty() }
    }

    /** 获取完整的 MCP 端点地址（本地）。绑定 0.0.0.0 通配时展示可直连的回环地址 */
    fun mcpEndpoint(): String {
        val cfg = _config.value
        val displayHost = if (cfg.host == "0.0.0.0" || cfg.host == "::") "127.0.0.1" else cfg.host
        return "http://$displayHost:${cfg.port}/mcp"
    }

    /** 获取局域网 MCP 端点地址列表 */
    fun lanMcpEndpoints(): List<String> {
        val port = _config.value.port
        return getLanAddresses().map { "http://$it:$port/mcp" }
    }

    /** 获取服务器地址（供 UI 显示） */
    fun serverAddress(): String {
        val cfg = _config.value
        return "${cfg.host}:${cfg.port}"
    }

    /** 启动统计轮询 */
    private fun startStatsPolling() {
        statsJob?.cancel()
        statsJob = scope.launch {
            while (isActive) {
                try {
                    refreshStats()
                } catch (e: Exception) {
                    logger.e(LogCategory.MCP, "刷新统计失败: ${e.message}")
                }
                delay(1000)
            }
        }
    }

    /** 停止统计轮询 */
    private fun stopStatsPolling() {
        statsJob?.cancel()
        statsJob = null
    }

    /** 刷新统计 */
    private fun refreshStats() {
        val srv = server ?: return
        _stats.value = srv.stats()
        _clients.value = srv.connectedClients
    }

    companion object {
        private const val KEY_PORT = "mcp_server_port"
    }
}
