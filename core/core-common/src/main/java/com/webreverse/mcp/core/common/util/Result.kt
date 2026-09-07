package com.webreverse.mcp.core.common.util

import kotlinx.serialization.Serializable

/** 统一结果包装 */
@Serializable
sealed class AppResult<out T> {
    data class Success<T>(val data: T) : AppResult<T>()
    data class Failure(val error: AppError) : AppResult<Nothing>()

    val isSuccess: Boolean get() = this is Success
    val isFailure: Boolean get() = this is Failure

    fun getOrNull(): T? = (this as? Success)?.data

    fun getOrThrow(): T = when (this) {
        is Success -> data
        is Failure -> throw error.toException()
    }

    inline fun <R> map(transform: (T) -> R): AppResult<R> = when (this) {
        is Success -> Success(transform(data))
        is Failure -> this
    }

    inline fun <R> mapCatching(transform: (T) -> R): AppResult<R> = try {
        map(transform)
    } catch (e: Throwable) {
        Failure(AppError.from(e))
    }

    /** Result 风格的 fold：成功走 onSuccess，失败走 onFailure */
    inline fun <R> fold(
        onSuccess: (T) -> R,
        onFailure: (AppError) -> R,
    ): R = when (this) {
        is Success -> onSuccess(data)
        is Failure -> onFailure(error)
    }

    fun onSuccess(action: (T) -> Unit): AppResult<T> {
        if (this is Success) action(data)
        return this
    }

    fun onFailure(action: (AppError) -> Unit): AppResult<T> {
        if (this is Failure) action(error)
        return this
    }

    companion object {
        fun <T> success(data: T): AppResult<T> = Success(data)
        fun <T> failure(error: AppError): AppResult<T> = Failure(error)
        inline fun <T> runCatching(block: () -> T): AppResult<T> = try {
            Success(block())
        } catch (e: Throwable) {
            Failure(AppError.from(e))
        }
    }
}

/** 结构化错误 */
@Serializable
data class AppError(
    val code: String,
    val message: String,
    val details: Map<String, String> = emptyMap(),
    val cause: String? = null,
) {
    fun toException(): AppException = AppException(this)

    companion object {
        val NO_ACTIVE_TAB = AppError("NO_ACTIVE_TAB", "没有活动标签页")
        val INVALID_TAB = AppError("INVALID_TAB", "无效的标签页")
        val FRAME_NOT_FOUND = AppError("FRAME_NOT_FOUND", "未找到指定 Frame")
        val PAGE_NOT_READY = AppError("PAGE_NOT_READY", "页面尚未就绪")
        val JS_EXECUTION_FAILED = AppError("JS_EXECUTION_FAILED", "JavaScript 执行失败")
        val DEBUGGER_UNAVAILABLE = AppError("DEBUGGER_UNAVAILABLE", "调试器不可用")
        val NETWORK_UNAVAILABLE = AppError("NETWORK_UNAVAILABLE", "网络不可用")
        val HOOK_FAILED = AppError("HOOK_FAILED", "Hook 安装失败")
        val PERMISSION_DENIED = AppError("PERMISSION_DENIED", "权限被拒绝")
        val MCP_AUTH_FAILED = AppError("MCP_AUTH_FAILED", "MCP 认证失败")
        val TIMEOUT = AppError("TIMEOUT", "操作超时")
        val INVALID_ARGUMENTS = AppError("INVALID_ARGUMENTS", "参数无效")
        val NOT_IMPLEMENTED = AppError("NOT_IMPLEMENTED", "功能尚未实现")
        val INTERNAL_ERROR = AppError("INTERNAL_ERROR", "内部错误")

        fun from(e: Throwable): AppError = when (e) {
            is AppException -> e.error
            is kotlinx.coroutines.TimeoutCancellationException -> TIMEOUT
            else -> AppError("INTERNAL_ERROR", e.message ?: "未知错误", cause = e.javaClass.simpleName)
        }
    }
}

class AppException(val error: AppError) : Exception(error.message) {
    override val message: String get() = error.message
}
