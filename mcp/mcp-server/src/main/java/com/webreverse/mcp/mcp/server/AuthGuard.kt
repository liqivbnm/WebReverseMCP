package com.webreverse.mcp.mcp.server

import com.webreverse.mcp.core.common.model.McpServerConfig
import com.webreverse.mcp.core.security.TokenManager
import io.ktor.http.HttpHeaders
import io.ktor.server.request.ApplicationRequest
import io.ktor.server.request.header
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * P0-1 安全守卫：在 HTTP 统一入口做 Token 认证 + 速率限制。
 *
 * 动机（对应 ChatGPT 分析二十五/二十六）：
 * - 里 `TokenManager.validateToken` 存在但从未被 McpServer 调用，Token 只是「保存」而非
 *   「认证中间件」；且 `install(CORS){ anyHost() }` 全放。一旦 UI 把 host 设成 0.0.0.0 或 192.x，
 *   局域网内任何主机都可直接调用 `file.write / debugger.evaluate / hook.add / network interception`，
 *   形成「局域网 -> MCP -> Browser -> Debugger -> Hook -> Filesystem」的危险权限链。
 * - 本守卫把认证提升到传输层统一入口，而不是在 Tool 层才做权限。
 *
 * 认证链：
 * ```
 * Request
 *   ├─ 提取 Token（Authorization: Bearer / X-MCP-Token；不再接受 ?token= 查询串）
 *   ├─ authRequired? 是 → validateToken 失败则拒绝
 *   ├─ rateLimit? 是 → 全局 + 按身份双层滑动窗口超限则拒绝
 *   └─ 通过 → 放行到 Tool 层
 * ```
 *
 * 设计取舍：MCP 官方客户端（Claude Desktop / Cursor）并不都支持 Custom Header。
 * 因此 authRequired 采用「自动」策略（见 McpServerConfig.requireAuth）：绑定回环地址时默认只校验
 * 携带的 Token（不强制）；绑定非回环地址（0.0.0.0 / LAN IP）时强制要求 Token，杜绝局域网裸奔。
 */
class AuthGuard(
    private val tokenManager: TokenManager,
    private val config: McpServerConfig,
) {
    /** 每客户端滑动窗口：key = "$transport|$remoteHost|$identity" */
    private val rateBuckets = ConcurrentHashMap<String, RateBucket>()

    /** 全局速率桶：所有请求共享，独立于 per-identity，防止伪造身份绕过限流（报三五） */
    private val globalBucket = RateBucket(System.currentTimeMillis())

    private class RateBucket(@Volatile var windowStart: Long, val counter: AtomicInteger = AtomicInteger(0))

    /** 是否强制要求认证（按配置 / host 自动决定） */
    fun isAuthRequired(): Boolean = config.requireAuth ?: (!isLoopbackHost(config.host) && config.host != "localhost")

    private fun isLoopbackHost(host: String): Boolean =
        host == "127.0.0.1" || host == "localhost" || host == "::1"

    /**
     * 私网/链路本地/回环地址判断（lanOnly 用）：
     * IPv4：10/8、172.16/12、192.168/16（site-local）、169.254/16（link-local）、127/8（loopback）
     * IPv6：fe80::/10（link-local）、fc00::/7（ULA，局域网常用 fd00::/8）、::1（loopback）
     */
    private fun isPrivateNetworkHost(remoteHost: String): Boolean = try {
        val addr = java.net.InetAddress.getByName(remoteHost)
        when {
            addr.isLoopbackAddress || addr.isLinkLocalAddress || addr.isSiteLocalAddress -> true
            addr is java.net.Inet6Address -> (addr.address[0].toInt() and 0xFE) == 0xFC
            else -> false
        }
    } catch (_: Exception) {
        true
    }

    /**
     * 认证校验结果。
     */
    sealed class AuthResult {
        /** 通过，允许继续处理请求 */
        object Allowed : AuthResult()
        /** 认证失败，须返回 401 */
        data class Unauthorized(val reason: String) : AuthResult()
        /** 触发速率限制，须返回 429 */
        data class RateLimited(val retryAfterMs: Long) : AuthResult()
        /** 超出最大连接数或被 IP 白名单挡住 */
        data class Rejected(val reason: String) : AuthResult()
    }

    /**
     * 统一入口认证。
     *
     * @param request 当前请求（用于提取远程地址、请求头、查询参数）
     * @param remoteHost 远程地址（IP）
     * @param identity 客户端身份（transport + 会话/连接标识），用于速率限制计数
     * @param providingToken 已由上层解析出的 Token；为 null 时由本方法自行从请求提取
     */
    suspend fun authenticate(
        request: ApplicationRequest,
        remoteHost: String,
        identity: String,
        providingToken: String? = null,
    ): AuthResult {
        val token = providingToken ?: extractToken(request)

        // 强制认证模式：必须有合法 Token
        if (isAuthRequired()) {
            if (token.isNullOrBlank()) return AuthResult.Unauthorized("Missing authentication token")
            if (!tokenManager.validateToken(token)) {
                return AuthResult.Unauthorized("Invalid authentication token")
            }
        } else {
            // 非强制模式：携带 Token 则校验（防错误 Token 误用），未携带则放行（兼容本地客户端）
            if (!token.isNullOrBlank() && !tokenManager.validateToken(token)) {
                return AuthResult.Unauthorized("Invalid authentication token from $remoteHost")
            }
        }

        // IP 白名单（可选）
        if (config.ipAllowlist.isNotEmpty() && !config.ipAllowlist.contains(remoteHost)) {
            return AuthResult.Rejected("Remote address $remoteHost not in allowlist")
        }

        // lanOnly 落地。服务器绑定 0.0.0.0 后监听全部接口，此处仅放行
        // 私网/链路本地/回环来源（WiFi、热点、本机），拒绝公网直连，
        // 兑现 UI「仅局域网·禁止公网访问」开关的承诺。解析异常时放行，
        // 由认证与速率限制继续把关（避免异常路径误伤正常连接）。
        if (config.lanOnly && !isPrivateNetworkHost(remoteHost)) {
            return AuthResult.Rejected("Remote address $remoteHost is outside local network")
        }

        // 速率限制（可选）：先全局、后按身份，双层桶
        if (config.rateLimitPerMinute > 0) {
            val limit = config.rateLimitPerMinute
            val now = System.currentTimeMillis()

            // 全局桶：所有来源共享，伪造身份/更换 session 无法绕过
            val globalAllowed = synchronized(globalBucket) {
                if (now - globalBucket.windowStart > 60_000L) {
                    globalBucket.windowStart = now
                    globalBucket.counter.set(0)
                }
                globalBucket.counter.incrementAndGet() <= limit
            }
            if (!globalAllowed) {
                val retryAfterMs = 60_000L - (now - globalBucket.windowStart).coerceAtLeast(0)
                return AuthResult.RateLimited(retryAfterMs)
            }

            // 每身份桶：限制单个客户端（identity 已包含 remoteHost）
            val key = "limit|$remoteHost|$identity"
            val bucket = rateBuckets.compute(key) { _, b ->
                if (b == null) RateBucket(now)
                else if (now - b.windowStart > 60_000L) RateBucket(now)
                else b
            } ?: RateBucket(now)
            val current = bucket.counter.incrementAndGet()
            if (current > limit) {
                val retryAfterMs = 60_000L - (now - bucket.windowStart)
                return AuthResult.RateLimited(retryAfterMs)
            }
        }

        return AuthResult.Allowed
    }

    /** 从请求提取 Token：Authorization Bearer 优先，其次 X-MCP-Token；不再接受 ?token= 查询串 */
    private fun extractToken(request: ApplicationRequest): String? {
        val auth = request.header(HttpHeaders.Authorization)
        if (!auth.isNullOrBlank()) {
            if (auth.startsWith("Bearer ", ignoreCase = true)) return auth.substring(7).trim().ifBlank { null }
            if (auth.startsWith("X-MCP-Token", ignoreCase = true) || auth.startsWith("Token", ignoreCase = true)) {
                val idx = auth.indexOf(' ')
                return if (idx > 0) auth.substring(idx + 1).trim().ifBlank { null } else null
            }
            // 裸 Token
            return auth.trim().ifBlank { null }
        }
        request.header("X-MCP-Token")?.trim()?.let { if (it.isNotBlank()) return it }
        // 报三四：不再接受 Query String Token（?token=）。Token 若经 URL 传递会进入代理日志、
        // 浏览器历史 / Access Log / Referrer，构成泄密面；仅支持 Authorization / X-MCP-Token 头。
        // （回环默认部署不强制认证，不受影响；非回环绑定时客户端须用请求头发送 Token。）
        return null
    }
}