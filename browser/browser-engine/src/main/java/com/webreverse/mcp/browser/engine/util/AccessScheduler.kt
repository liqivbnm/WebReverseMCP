package com.webreverse.mcp.browser.engine.util

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.yield

/**
 * 读写分离调度器（ P2-9 新增）。
 *
 * 背景：MCP Agent 并发调用工具时（如同时 hook.trace + dom.snapshot +
 * storage.get），页面求值彼此交错——读操作读到的可能是另一个写操作
 * 装到一半的状态。调度器设计：
 *
 * - **读**（DOM 快照 / 表达式求值 / 状态读取）：彼此并发，零互斥开销；
 * - **写**（hook 安装 / 事件派发 / storage 写入 / 断点设置）：全局互斥，
 *   且写优先——写请求到达后，新读必须排队等待写完成（防写饥饿）。
 *
 * 死锁安全：read/write 块内不得嵌套再次进入同调度器（本项目的用法
 * 均为叶子求值，无嵌套）。
 */
class AccessScheduler {

    private val stateMutex = Mutex()
    private var activeReaders = 0
    private var pendingWriters = 0
    private var writerActive = false

    /** 统计（诊断用） */
    val stats = Stats()

    class Stats {
        var reads: Long = 0
            internal set
        var writes: Long = 0
            internal set
        var readContends: Long = 0
            internal set
        var writeWaits: Long = 0
            internal set
    }

    /** 读路径：多读并发；有活跃写或等待写时阻塞（写优先闸门） */
    suspend fun <T> read(block: suspend () -> T): T {
        var gated = false
        enterRead { gated = true }
        if (gated) stats.readContends++
        try {
            stats.reads++
            return block()
        } finally {
            stateMutex.withLock { activeReaders-- }
        }
    }

    /** 自旋进入读临界区；每次失败回调一次 onRetry */
    private suspend fun enterRead(onRetry: () -> Unit) {
        while (true) {
            val entered = stateMutex.withLock {
                if (!writerActive && pendingWriters == 0) {
                    activeReaders++
                    true
                } else {
                    false
                }
            }
            if (entered) return
            onRetry()
            yield()
        }
    }

    /** 写路径：全局互斥，写优先（新读在写等待期间不得插队） */
    suspend fun <T> write(block: suspend () -> T): T {
        stateMutex.withLock { pendingWriters++ }
        try {
            // 等待读者排空
            while (true) {
                val acquired = stateMutex.withLock {
                    if (!writerActive && activeReaders == 0) {
                        writerActive = true
                        true
                    } else {
                        false
                    }
                }
                if (acquired) break
                stats.writeWaits++
                yield()
            }
        } catch (e: Throwable) {
            // 获取阶段异常：只回收 pending 计数
            stateMutex.withLock { pendingWriters-- }
            throw e
        }
        try {
            stats.writes++
            return block()
        } finally {
            stateMutex.withLock {
                writerActive = false
                pendingWriters--
            }
        }
    }

    /**
     * 依据脚本形态判定访问类别（启发式，供未显式标注的调用点使用）。
     *
     * WRITE 判定特征（满足其一）：
     * - 状态变更 API（localStorage.setItem / dispatchEvent / .click() /
     *   removeHook / cookie 赋值 / history 跳转）；
     * - 页面全局赋值（window.X= / globalThis.X= / document.X=，排除 == 等比较）。
     * 其余（纯表达式求值、JSON 取值、DOM 查询）视为 READ。
     */
    fun classify(script: String): Access = if (WRITE_HINTS.any { it.containsMatchIn(script) }) {
        Access.WRITE
    } else if (ASSIGN_HINT.containsMatchIn(script)) {
        Access.WRITE
    } else {
        Access.READ
    }

    enum class Access { READ, WRITE }

    companion object {
        private val WRITE_HINTS = listOf(
            Regex("""\blocalStorage\s*\.\s*setItem"""),
            Regex("""\bsessionStorage\s*\.\s*setItem"""),
            Regex("""document\s*\.\s*cookie\s*="""),
            Regex("""\.dispatchEvent\s*\("""),
            Regex("""\.click\s*\(\s*\)"""),
            Regex("""removeHook|unhookAll|__WRMCP_HOOKS__\s*\["""),
            Regex("""\.outerHTML\s*="""),
            Regex("""history\s*\.\s*(push|replace)State"""),
            Regex("""location\s*\.\s*(href|assign|replace)\s*="""),
        )

        /** 页面全局赋值（排除 ==/===/=>/<=/>=/!= 比较形态） */
        private val ASSIGN_HINT = Regex(
            """(?<![=!<>])(?:window|globalThis|document)\s*\.\s*[\w$]+\s*=(?![=>])""",
        )
    }
}
