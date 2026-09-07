package com.webreverse.mcp.core.common.model

import java.util.ArrayDeque
import kotlinx.serialization.Serializable

/**
 * 统一追踪模型（ChatGPT 分析报告 P0：Unified TraceEvent / ValueRef / ValueFingerprint）。
 *
 * 逆向分析的核心痛点是「证据孤岛」：Hook 命中记一份 JSON、网络请求记一份、
 * WASM 内存读一份，彼此之间只有时间戳可以猜。本模型让所有观测共享同一套结构：
 *
 * - [TraceEvent]：任何运行时事件（hook 命中/函数调用/属性读写/网络请求/WASM 导入导出/
 *   定时器/控制台）统一为带序号、时间、来源、值引用的事件；
 * - [ValueRef]：事件中「流动的值」的引用——指向指纹而非原始字符串，跨事件可比对；
 * - [ValueFingerprint]：值的规范化指纹（归一化 + 哈希），用于把
 *   「加密函数返回值」与「300ms 后出现在请求头里的值」判定为同一个值。
 *
 * 关键能力：
 * 1. **值级关联**：event A.output.fingerprint == event B.input.fingerprint => 值同源；
 * 2. **异步谱系（async lineage）**：[TraceEvent.asyncChainId] + [TraceEvent.parentEventId]
 *    把 promise/定时器/XHR 回调链串起来，回答「这个请求是谁触发的」；
 * 3. **原始事件缓冲**：客户端只推增量（seq 递增），宿主侧全量留存可回放。
 */

// ---------------- 值指纹 ----------------

/**
 * 值的规范化指纹。
 *
 * **跨语言一致性**：指纹必须在 JS 注入层与 Kotlin 宿主层产出完全一致
 * （JS 侧 Number 无法安全做 64 位乘法），故统一为 **32 位 FNV-1a + 归一化长度**
 * 联合编码——同哈希且同长度才视为同值，实际碰撞空间 ≈ 2^40，对关联提示足够。
 *
 * 规范化规则（两侧一致）：仅 trim（大小写敏感；敏感值匹配时可选小写化）。
 * 原始值始终随行携带（截断），指纹是加速索引而非替代。
 */
object ValueFingerprint {

    /** 归一化并计算指纹；空/过短值返回 null（无法区分噪音） */
    fun of(raw: String?, caseInsensitive: Boolean = false): String? {
        if (raw == null) return null
        val s = raw.trim()
        if (s.length < 3 || s.length > 4096) return null
        val norm = if (caseInsensitive) s.lowercase() else s
        return encode(fnv1a32(norm), norm.length)
    }

    /** 指纹编码："<hex32>:<len>"，与 JS 侧 wrmcpFp() 输出一致 */
    fun encode(hash: Int, length: Int): String =
        (hash.toLong() and 0xffffffffL).toString(16).padStart(8, '0') + ":" + length

    /** 32 位 FNV-1a */
    fun fnv1a32(input: String): Int {
        var hash = -0x7ee362eb // 0x811c9dc5
        for (ch in input) {
            hash = hash xor ch.code
            hash *= 0x01000193
        }
        return hash
    }

    /** 指纹前缀（截断后的值仍可前缀匹配） */
    fun prefixOf(fp: String): String = fp.take(8)
}

// ---------------- 值引用 ----------------

/** 一个值在事件中的角色 */
@Serializable
enum class ValueRole {
    /** 输入（函数参数/请求参数） */
    INPUT,
    /** 输出（返回值/写出的头） */
    OUTPUT,
    /** 中间值（属性读写快照） */
    INTERMEDIATE,
    /** 环境输入（cookie/UA/storage 读出） */
    ENV,
}

/**
 * 事件中的值引用：原始文本 + 指纹 + 归一化提示。
 * 序列化保持轻量（原始值截断），指纹用于等值判定。
 */
@Serializable
data class ValueRef(
    /** 原始文本（截断到 256 字符，敏感字段已由采集端脱敏） */
    val raw: String,
    /** 规范化指纹（ValueFingerprint.of 产出） */
    val fingerprint: String = "",
    /** 角色 */
    val role: ValueRole = ValueRole.INTERMEDIATE,
    /** 值类型提示：string/number/object/array/unknown */
    val kind: String = "unknown",
    /** 来源标签：参数下标 / 属性名 / 头名，如 "arg0" / "ret" / "X-Sign" */
    val label: String = "",
    /** 是否疑似敏感值（token/密码等，只存指纹） */
    val sensitive: Boolean = false,
    /** 嵌套值指纹（对象前 N 个属性的浅层指纹，供部分匹配） */
    val childFingerprints: List<String> = emptyList(),
) {
    val hasFingerprint: Boolean get() = fingerprint.isNotBlank()

    /** 中段指纹（用于被拼接/截断的值做子串匹配） */
    fun matchesSubstringOf(other: ValueRef): Boolean {
        if (!hasFingerprint || !other.hasFingerprint) return false
        if (fingerprint == other.fingerprint) return true
        return raw.length >= 8 && other.raw.contains(raw)
    }
}

// ---------------- 统一事件 ----------------

/** 事件来源（观测层） */
@Serializable
enum class TraceSource {
    HOOK,           // HookEngine 规则命中
    TRACER,         // DynamicTracer 函数/属性包装
    NETWORK,        // 网络请求/响应
    WASM,           // WASM 导入调用/内存/导出
    TIMER,          // setTimeout/setInterval
    CONSOLE,        // console.*
    STORAGE,        // localStorage/sessionStorage/cookie
    DEBUGGER,       // 断点现场
    PLANNER,        // 调查规划器决策（自省）
}

/** 事件类型 */
@Serializable
enum class TraceKind {
    CALL,           // 函数调用（含返回）
    PROP_GET,       // 属性读
    PROP_SET,       // 属性写
    CONSTRUCT,      // new
    APPLY,          // apply/call/bind
    REQUEST,        // 请求发出
    RESPONSE,       // 响应接收
    WASM_IMPORT,    // JS -> WASM 导入函数调用
    WASM_EXPORT,    // WASM -> JS 导出调用
    WASM_MEMORY,    // WASM 内存写入（含范围）
    TIMER_FIRE,     // 定时器触发
    STORAGE_OP,     // 存储读写
    CONSOLE_OUT,    // 控制台输出
    ERROR,          // 异常
    CUSTOM,         // 自定义
}

/** 异步链触发方式 */
@Serializable
enum class AsyncTrigger {
    NONE,           // 同步
    PROMISE,        // promise then/catch/finally
    TIMER,          // setTimeout/setInterval
    XHR_CALLBACK,   // XHR onreadystatechange/onload
    EVENT,          // DOM 事件
    MICROTASK,      // 微任务队列
}

/**
 * 统一追踪事件。
 *
 * @param seq 全局递增序号（客户端产生，回放与断点续传的游标）
 * @param ts 毫秒时间戳
 * @param source 观测层
 * @param kind 事件类型
 * @param name 事件主体：函数名/URL/属性路径/WASM 函数
 * @param values 值引用集合（输入/输出/环境）
 * @param asyncChainId 异步链 id：同一 promise/timer 链上的事件共享；空=同步或未知
 * @param parentEventId 触发本事件的事件 seq（异步谱系：回调由哪个请求/调用发起）
 * @param stackTop 调用栈顶部函数名（轻量谱系，避免全栈体积）
 * @param stack 精简调用栈（可选，换行分隔）
 * @param tabId/frameId 现场隔离维度
 */
@Serializable
data class TraceEvent(
    val seq: Long,
    val ts: Long,
    val source: TraceSource,
    val kind: TraceKind,
    val name: String,
    val values: List<ValueRef> = emptyList(),
    val asyncChainId: String = "",
    val parentEventId: Long = -1L,
    val asyncTrigger: AsyncTrigger = AsyncTrigger.NONE,
    val stackTop: String = "",
    val stack: String = "",
    val tabId: String = "",
    val frameId: String = "",
    val executionContextId: String = "",
    val scriptUrl: String = "",
    val line: Int = 0,
    val error: String = "",
    val meta: Map<String, String> = emptyMap(),
) {
    val input: ValueRef? get() = values.firstOrNull { it.role == ValueRole.INPUT }
    val output: ValueRef? get() = values.firstOrNull { it.role == ValueRole.OUTPUT }
    val envValues: List<ValueRef> get() = values.filter { it.role == ValueRole.ENV }

    /** 指纹集合（供索引） */
    val fingerprints: Set<String> get() = values.mapNotNull { if (it.hasFingerprint) it.fingerprint else null }.toSet()
}

// ---------------- 事件缓冲（宿主侧） ----------------

/**
 * 宿主侧原始事件环形缓冲：
 * - 按 seq 递增接收客户端增量推送；
 * - 保留原始事件供回放/补捞（工具一次取不完时游标续传）；
 * - 值指纹倒排索引：fingerprint -> 事件 seq 列表（值级关联 O(1) 查询）；
 * - 异步链索引：chainId -> 事件序列（谱系回溯）。
 */
class TraceEventBuffer(private val capacity: Int = 20000) {

    private val events = ArrayDeque<TraceEvent>()
    private val bySeq = HashMap<Long, TraceEvent>()
    private val byFingerprint = HashMap<String, MutableList<Long>>()
    private val byChain = HashMap<String, MutableList<Long>>()
    private val byName = HashMap<String, MutableList<Long>>()
    var lastSeq: Long = -1
        private set
    var dropped: Long = 0
        private set

    @Synchronized
    fun append(event: TraceEvent) {
        // 客户端可能重传；相同 seq 已存在时直接忽略，避免 bySeq 被覆盖而
        // events 队列仍保留重复条目。乱序事件不推进游标，但仍可收录，前提是 seq 尚未存在。
        if (bySeq.containsKey(event.seq)) {
            dropped++
            return
        }
        if (event.seq > lastSeq) lastSeq = event.seq

        if (events.size >= capacity) {
            val old = events.removeFirst()
            bySeq.remove(old.seq)
            // 同步清理所有倒排索引，避免环形缓冲长期运行后产生“幽灵事件”和内存泄漏。
            for (fp in old.fingerprints) {
                byFingerprint[fp]?.let { list ->
                    list.remove(old.seq)
                    if (list.isEmpty()) byFingerprint.remove(fp)
                }
            }
            if (old.asyncChainId.isNotBlank()) {
                byChain[old.asyncChainId]?.let { list ->
                    list.remove(old.seq)
                    if (list.isEmpty()) byChain.remove(old.asyncChainId)
                }
            }
            if (old.name.isNotBlank()) {
                byName[old.name]?.let { list ->
                    list.remove(old.seq)
                    if (list.isEmpty()) byName.remove(old.name)
                }
            }
        }
        events.addLast(event)
        bySeq[event.seq] = event
        for (fp in event.fingerprints) {
            byFingerprint.getOrPut(fp) { mutableListOf() }.let {
                if (it.size < 4096) it.add(event.seq)
            }
        }
        if (event.asyncChainId.isNotBlank()) {
            byChain.getOrPut(event.asyncChainId) { mutableListOf() }.add(event.seq)
        }
        if (event.name.isNotBlank()) {
            byName.getOrPut(event.name) { mutableListOf() }.let {
                if (it.size < 2048) it.add(event.seq)
            }
        }
    }

    @Synchronized
    fun appendAll(list: List<TraceEvent>) = list.forEach { append(it) }

    /** 增量取回：seq 严格大于 after 的事件（游标续传） */
    @Synchronized
    fun since(after: Long, limit: Int = 500): List<TraceEvent> =
        events.filter { it.seq > after }.take(limit)

    /** 值指纹反查：哪些事件流过该值 */
    @Synchronized
    fun findByFingerprint(fp: String): List<TraceEvent> =
        byFingerprint[fp]?.mapNotNull { bySeq[it] } ?: emptyList()

    /** 异步谱系：同一链上的全部事件（按 seq 排序） */
    @Synchronized
    fun findChain(chainId: String): List<TraceEvent> =
        byChain[chainId]?.mapNotNull { bySeq[it] }?.sortedBy { it.seq } ?: emptyList()

    /** 名称查询（函数名/URL） */
    @Synchronized
    fun findByName(name: String): List<TraceEvent> =
        byName[name]?.mapNotNull { bySeq[it] } ?: emptyList()

    /**
     * 值传播路径：从最早出现到最晚出现的指纹流动轨迹
     * （fingerprint 的生命周期视图，回答「这个值从哪来、到哪去」）。
     */
    @Synchronized
    fun valuePropagation(fp: String): List<TraceEvent> =
        findByFingerprint(fp).sortedBy { it.seq }

    /**
     * 向上回溯异步谱系：parentEventId 逐级上溯到根（同步事件或链头）。
     * 返回从根到本事件的路径（含自身）。
     */
    fun lineageOf(event: TraceEvent, maxDepth: Int = 16): List<TraceEvent> {
        val path = mutableListOf(event)
        var cur = event
        var depth = 0
        while (cur.parentEventId >= 0 && depth < maxDepth) {
            val parent = bySeq[cur.parentEventId] ?: break
            path.add(0, parent)
            cur = parent
            depth++
        }
        // 同链上更早的事件也并入（弱谱系）
        if (event.asyncChainId.isNotBlank()) {
            val chain = findChain(event.asyncChainId).filter { it.seq < event.seq }
            for (c in chain) if (c.seq !in path.map { it.seq }) path.add(0, c)
        }
        return path.sortedBy { it.seq }
    }

    @Synchronized
    fun all(): List<TraceEvent> = events.toList()

    @Synchronized
    fun stats(): TraceBufferStats {
        val bySource = events.groupingBy { it.source }.eachCount()
        return TraceBufferStats(
            size = events.size,
            lastSeq = lastSeq,
            dropped = dropped,
            distinctFingerprints = byFingerprint.size,
            distinctChains = byChain.size,
            bySource = bySource.mapKeys { it.key.name },
        )
    }

    @Synchronized
    fun clear() {
        events.clear()
        bySeq.clear()
        byFingerprint.clear()
        byChain.clear()
        byName.clear()
        lastSeq = -1
        dropped = 0
    }
}

@Serializable
data class TraceBufferStats(
    val size: Int,
    val lastSeq: Long,
    val dropped: Long,
    val distinctFingerprints: Int,
    val distinctChains: Int,
    val bySource: Map<String, Int>,
)

// ---------------- JSON 解析辅助 ----------------

/**
 * 把客户端推来的 JSON 事件（DynamicTracer/HookEngine/WASM 层产出）解析为 [TraceEvent]。
 * 字段宽松映射：兼容 `target`/`name`、`type`/`kind`、`ret`/`output` 等历史命名。
 */
object TraceEventParser {

    fun parseList(json: String): List<TraceEvent> {
        // 极简 JSON 数组解析：委托给宿主 JSON 库不可用时使用
        val out = mutableListOf<TraceEvent>()
        val objs = splitJsonArray(json)
        for (o in objs) out.add(parseObject(o))
        return out
    }

    fun parseObject(json: String): TraceEvent {
        val m = flatJson(json)
        val values = mutableListOf<ValueRef>()
        m.forEach { (k, v) ->
            val role = when {
                k.equals("arg0", true) || k.startsWith("arg", true) && k.drop(3).all { it.isDigit() } -> ValueRole.INPUT
                k.equals("ret", true) || k.equals("return", true) || k.equals("output", true) -> ValueRole.OUTPUT
                k.equals("input", true) || k.equals("body", true) || k.equals("headers", true) -> ValueRole.INPUT
                k.equals("fpBody", true) || k.equals("fpHeaders", true) || k.startsWith("fpHeader_", true) -> ValueRole.OUTPUT
                k.equals("value", true) || k.equals("val", true) -> ValueRole.INTERMEDIATE
                else -> null
            }
            if (role != null && v.isNotBlank() && v != "null" && v != "undefined") {
                val sensitive = isSensitiveKey(k)
                val fp = ValueFingerprint.of(v, caseInsensitive = sensitive)
                values.add(
                    ValueRef(
                        raw = if (sensitive) "[SENSITIVE:${fp?.take(8)}]" else v.take(256),
                        fingerprint = fp ?: "",
                        role = role,
                        kind = valueKind(v),
                        label = k,
                        sensitive = sensitive,
                    )
                )
            }
        }
        val seq = m["seq"]?.toLongOrNull() ?: m["n"]?.toLongOrNull() ?: 0L
        val ts = m["ts"]?.toLongOrNull() ?: m["timestamp"]?.toLongOrNull() ?: 0L
        val source = parseSource(m["source"] ?: m["layer"])
        val kind = parseKind(m["kind"] ?: m["type"] ?: "")
        val name = m["name"] ?: m["target"] ?: m["func"] ?: m["fn"] ?: m["url"] ?: ""
        val asyncChain = m["asyncChainId"] ?: m["chainId"] ?: ""
        val parent = m["parentEventId"]?.toLongOrNull() ?: m["parentSeq"]?.toLongOrNull() ?: -1L
        val trigger = parseTrigger(m["asyncTrigger"] ?: m["trigger"])
        return TraceEvent(
            seq = seq,
            ts = ts,
            source = source,
            kind = kind,
            name = name,
            values = values,
            asyncChainId = asyncChain,
            parentEventId = parent,
            asyncTrigger = trigger,
            stackTop = (m["stackTop"] ?: m["stack"]?.split("\n")?.firstOrNull() ?: "").take(160),
            stack = m["stack"] ?: "",
            tabId = m["tabId"] ?: "",
            frameId = m["frameId"] ?: "",
            executionContextId = m["executionContextId"] ?: m["ctxId"] ?: "",
            scriptUrl = m["scriptUrl"] ?: m["url"] ?: "",
            line = m["line"]?.toIntOrNull() ?: 0,
            error = m["error"] ?: "",
            meta = m.filterKeys { it in META_KEYS },
        )
    }

    private val META_KEYS = setOf("method", "endpoint", "status", "ms", "prop", "op", "opcode", "pc", "wasmFn", "wasmExport", "ptr0", "ptr1", "ptr2", "len0", "len1", "len2", "memoryStart", "memoryEnd", "memoryFingerprint", "memoryFingerprintBefore", "memoryFingerprintAfter", "typedArrayByteOffset0", "typedArrayByteLength0", "typedArrayByteOffset1", "typedArrayByteLength1", "typedArrayByteOffset2", "typedArrayByteLength2", "direction", "targetContext", "workerId", "workerType", "channel", "messagePort", "origin", "scope", "url")

    private fun isSensitiveKey(k: String): Boolean {
        val t = k.lowercase()
        return t.contains("token") || t.contains("passw") || t.contains("secret") ||
            t.contains("authoriz") || t.contains("cookie") || t.contains("session") || t.contains("key")
    }

    private fun valueKind(v: String): String = when {
        v.startsWith("{") || v.startsWith("[") -> if (v.startsWith("{")) "object" else "array"
        v.toLongOrNull() != null || v.toDoubleOrNull() != null -> "number"
        v == "true" || v == "false" -> "boolean"
        else -> "string"
    }

    private fun parseSource(s: String?): TraceSource = when (s?.lowercase()) {
        "hook" -> TraceSource.HOOK
        "tracer", "trace", "debug" -> TraceSource.TRACER
        "network", "net", "request" -> TraceSource.NETWORK
        "wasm" -> TraceSource.WASM
        "timer" -> TraceSource.TIMER
        "console" -> TraceSource.CONSOLE
        "storage" -> TraceSource.STORAGE
        "debugger" -> TraceSource.DEBUGGER
        "planner" -> TraceSource.PLANNER
        else -> TraceSource.TRACER
    }

    private fun parseKind(k: String): TraceKind = when {
        k.contains("prop.get") || k == "get" -> TraceKind.PROP_GET
        k.contains("prop.set") || k == "set" -> TraceKind.PROP_SET
        k == "construct" || k.contains("new ") -> TraceKind.CONSTRUCT
        k == "request" -> TraceKind.REQUEST
        k == "response" -> TraceKind.RESPONSE
        k.contains("wasm_import") || k.contains("wasm.import") -> TraceKind.WASM_IMPORT
        k.contains("wasm_export") || k.contains("wasm.export") -> TraceKind.WASM_EXPORT
        k.contains("wasm_mem") || k.contains("memory") -> TraceKind.WASM_MEMORY
        k.contains("timer") -> TraceKind.TIMER_FIRE
        k.contains("storage") -> TraceKind.STORAGE_OP
        k.contains("console") || k.contains("log") -> TraceKind.CONSOLE_OUT
        k.contains("error") || k.contains("exception") -> TraceKind.ERROR
        k.contains("apply") -> TraceKind.APPLY
        k == "call" || k.contains("call") -> TraceKind.CALL
        else -> TraceKind.CUSTOM
    }

    private fun parseTrigger(t: String?): AsyncTrigger = when (t?.lowercase()) {
        "promise", "then" -> AsyncTrigger.PROMISE
        "timer", "settimeout", "setinterval" -> AsyncTrigger.TIMER
        "xhr", "xhr_callback" -> AsyncTrigger.XHR_CALLBACK
        "event", "dom" -> AsyncTrigger.EVENT
        "microtask" -> AsyncTrigger.MICROTASK
        else -> AsyncTrigger.NONE
    }

    /** 拆 JSON 数组为对象串（括号深度扫描，不依赖 JSON 库） */
    internal fun splitJsonArray(json: String): List<String> {
        val t = json.trim()
        if (!t.startsWith("[") || !t.endsWith("]")) return if (t.startsWith("{")) listOf(t) else emptyList()
        val inner = t.substring(1, t.length - 1).trim()
        if (inner.isEmpty()) return emptyList()
        val out = mutableListOf<String>()
        val sb = StringBuilder()
        var depth = 0
        var inStr = false
        var esc = false
        for (c in inner) {
            when {
                esc -> { sb.append(c); esc = false }
                c == '\\' && inStr -> { sb.append(c); esc = true }
                c == '"' -> { inStr = !inStr; sb.append(c) }
                !inStr && (c == '{' || c == '[') -> { depth++; sb.append(c) }
                !inStr && (c == '}' || c == ']') -> { depth--; sb.append(c) }
                c == ',' && depth == 0 -> { out.add(sb.toString()); sb.setLength(0) }
                else -> sb.append(c)
            }
        }
        if (sb.isNotBlank()) out.add(sb.toString())
        return out.filter { it.trim().startsWith("{") }
    }

    /** 浅层 JSON 扁平化为 Map（字符串值不反转义，够用） */
    internal fun flatJson(json: String): Map<String, String> {
        val t = json.trim()
        val out = mutableMapOf<String, String>()
        if (!t.startsWith("{")) return out
        val inner = t.substring(1, t.length - 1).trim().trimEnd(',')
        if (inner.isEmpty()) return out
        val parts = splitJsonArray("[$inner]").ifEmpty { return out }
        for (p in parts) {
            val idx = p.indexOf(':')
            if (idx <= 0) continue
            val k = p.substring(0, idx).trim().trim('"')
            var v = p.substring(idx + 1).trim()
            if (v.length >= 2 && v.first() == '"' && v.last() == '"') v = v.substring(1, v.length - 1)
            if (k.isNotBlank()) out[k] = v
        }
        return out
    }
}
