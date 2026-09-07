package com.webreverse.mcp.workspace.core

import com.webreverse.mcp.core.common.model.ValueFingerprint

/**
 * 多证据关联评分器（统一数据流关联升级）。
 *
 * 相比 ，本次升级：
 * 1. **补充 frameId / sessionId / queryParams**：修复「Hook 无 tabId 只能靠 ±3s」的已知精度漏洞，
 *    多一路「同 Frame / 同 会话」强证。
 * 2. **按 ChatGPT 建议的全信号加权**：
 *
 *    | 信号                               | 分值 | 说明 |
 *    |------------------------------------|------|------|
 *    | sameFrame                         | +20 | 同一 JS Frame（CDP 级） |
 *    | sameTab                           | +20 | 同一标签页现场 |
 *    | sameExecutionCtx                  | +30 | 同一 JS 执行上下文（最强） |
 *    | sameCallStack                     | +40 | 调用栈重叠（同源调用） |
 *    | inputMatches                      | +30 | 输入值命中请求参数/体 |
 *    | returnValueInHeader               | +50 | 返回值出现在请求头（值级强证） |
 *    | returnValueInBody                 | +40 | 返回值出现在请求体 |
 *    | returnValueInQueryOrUrl           | +40 | 返回值出现在 URL/Query |
 *    | timeDistance <=800ms / <=3000ms   | +20 / +8 | 时间相近 |
 *
 * 3. **分级而非一刀切**：分别判定为 `SIGNS`（置信度 ≥0.75）、`POSSIBLE_SIGNS`（≥0.45）。
 * 4. **Provenance**：每条关联记录各信号的贡献（method + contribution + confidence），
 *    让 Agent 不止看到「sign() SIGNS /api」，还能看到「为什么判定它是签名函数」。
 */
class EvidenceCorrelator {

    /** 一次加密/敏感函数命中现场 */
    data class CryptoHit(
        val function: String,
        val stackTrace: String,
        val timestamp: Long,
        val tabId: String = "",
        val executionContextId: String = "",
        val output: String = "",
        val input: String = "",
        val frameId: String = "",
        val sessionId: String = "",
        /* * 值指纹：hook 命中涉及的值（输入/输出），值哈希关联主体 */
        val valueFingerprints: List<String> = emptyList(),
        /* * 异步谱系：所在 promise/timer/xhr 链 id */
        val asyncChainId: String = "",
    )

    /** 一条网络请求候选 */
    data class RequestCandidate(
        val url: String,
        val endpointKey: String,
        val timestamp: Long,
        val tabId: String = "",
        val executionContextId: String = "",
        val stackTrace: String = "",
        val headers: Map<String, String> = emptyMap(),
        val body: String = "",
        val frameId: String = "",
        val sessionId: String = "",
        val queryParams: String = "",
        /* * 请求涉及的值指纹（头/体/URL 里的关键值） */
        val valueFingerprints: List<String> = emptyList(),
        /* * 异步谱系：发起该请求的链 id */
        val asyncChainId: String = "",
    )

    /** 一条关联依据 */
    data class Provenance(
        val method: String,
        val contribution: Int,
        val confidence: Double,
    )

    /** 一对关联的结果 */
    data class Correlation(
        val function: String,
        val endpointKey: String,
        val endpointUrl: String,
        val relation: String,        // SIGNS / POSSIBLE_SIGNS
        val confidence: Double,
        val score: Int,
        val matchedSignals: List<String>,
        val provenance: List<Provenance> = emptyList(),
    )

    fun correlate(hit: CryptoHit, req: RequestCandidate): Correlation {
        var score = 0
        val signals = mutableListOf<String>()
        val provenance = mutableListOf<Provenance>()
        val fpSignals = mutableListOf<String>()
        val timeDelta = kotlin.math.abs(req.timestamp - hit.timestamp)

        fun add(method: String, pts: Int) {
            score += pts
            signals += method
            provenance += Provenance(method, pts, pts.toDouble() / MAX_SCORE)
        }

        // 1. 同 Frame（CDP 级，WebView 同 frame 场景最强区分）
        if (hit.frameId.isNotBlank() && hit.frameId == req.frameId) add("same_frame", 20)
        // 2. 同 Tab
        if (hit.tabId.isNotBlank() && hit.tabId == req.tabId) add("same_tab", 20)
        // 3. 同 ExecutionContext
        if (hit.executionContextId.isNotBlank() && hit.executionContextId == req.executionContextId) add("same_execution_context", 30)
        // 4. 调用栈重叠
        val stackTokens = stackTokens(hit.stackTrace)
        val reqTokens = stackTokens(req.stackTrace)
        val overlap = stackTokens.intersect(reqTokens)
        if (overlap.isNotEmpty()) add("call_stack_match", 40)
        // 5. 时间距离
        when {
            timeDelta <= 800 -> add("time_close", 20)
            timeDelta <= 3000 -> add("time_within_window", 8)
        }
        // 6. 输入命中请求
        val input = hit.input.trim()
        if (input.length >= 4 && (req.body.contains(input) || req.url.contains(input))) add("input_value_match", 30)
        // 7. 返回值值级命中
        val out = hit.output.trim()
        if (out.length >= 4) {
            when {
                req.headers.values.any { it.contains(out) } -> add("header_value_match", 50)
                req.body.contains(out) -> add("body_value_match", 40)
                req.url.contains(out) || req.queryParams.contains(out) -> add("query_value_match", 40)
            }
        }
        // 8. 值指纹直接命中（最强证据：hook 输出与请求值哈希一致，DIRECT 级）
        val fpOverlap = hit.valueFingerprints.toSet() intersect req.valueFingerprints.toSet()
        if (fpOverlap.isNotEmpty()) {
            add("value_fingerprint_match", 120)
            fpSignals += fpOverlap.take(3)
        }
        // 9. 值哈希生命周期关联：hook 输出指纹与请求指纹前缀一致（被拆包/包装后残留）
        val hitPfx = hit.valueFingerprints.map { ValueFingerprint.prefixOf(it) }.toSet()
        val reqPfx = req.valueFingerprints.map { ValueFingerprint.prefixOf(it) }.toSet()
        if (hitPfx.isNotEmpty() && reqPfx.isNotEmpty() && (hitPfx intersect reqPfx).isNotEmpty()) {
            add("value_prefix_match", 60)
        }
        // 10. 异步谱系：同一 promise/timer/xhr 链（回答「这个请求是被谁触发的」链证据）
        if (hit.asyncChainId.isNotBlank() && req.asyncChainId == hit.asyncChainId) {
            add("async_lineage_match", 70)
        }

        val confidence = (score.toDouble() / MAX_SCORE).coerceIn(0.0, 1.0)
        val relation = classify(confidence)
        return Correlation(
            function = hit.function,
            endpointKey = req.endpointKey,
            endpointUrl = req.url,
            relation = relation,
            confidence = confidence,
            score = score,
            matchedSignals = signals + fpSignals,
            provenance = provenance,
        )
    }

    /** 分级：SIGNS / POSSIBLE_SIGNS / LOW */
    fun classify(confidence: Double): String = when {
        confidence >= SIGNS_THRESHOLD -> "SIGNS"
        confidence >= POSSIBLE_THRESHOLD -> "POSSIBLE_SIGNS"
        else -> "LOW"
    }

    /** 全量打分并排序；keepBestPerRequest=true 时每个端点仅保最高分 */
    fun relate(
        hits: List<CryptoHit>,
        requests: List<RequestCandidate>,
        keepBestPerRequest: Boolean = true,
        minScore: Int = 20,
    ): List<Correlation> {
        val results = mutableListOf<Correlation>()
        for (h in hits) {
            for (r in requests) {
                val c = correlate(h, r)
                if (c.score >= minScore) results.add(c)
            }
        }
        val sorted = results.sortedWith(compareByDescending<Correlation> { it.score }.thenByDescending { it.confidence })
        if (!keepBestPerRequest) return sorted
        val best = LinkedHashMap<String, Correlation>()
        sorted.forEach { if (!best.containsKey(it.endpointKey)) best[it.endpointKey] = it }
        return best.values.toList()
    }

    private fun stackTokens(stack: String): Set<String> =
        Regex("""([A-Za-z_$][\w$]{1,40})""").findAll(stack)
            .map { it.groupValues[1] }
            .filter { name ->
                name !in noiseTokens && !name.contains(".js") && name.length > 2
            }
            .toSet()

    private companion object {
        // 加入值指纹/前缀/谱系信号后归一化上限（保持 confidence 收缩在 [0,1]）
        const val MAX_SCORE = 600
        const val SIGNS_THRESHOLD = 0.55
        const val POSSIBLE_THRESHOLD = 0.3

        val noiseTokens = setOf(
            "function", "anonymous", "new", "at", "await", "async", "return", "exports",
            "require", "module", "apply", "call", "then", "catch", "finally", "click",
        )
    }
}