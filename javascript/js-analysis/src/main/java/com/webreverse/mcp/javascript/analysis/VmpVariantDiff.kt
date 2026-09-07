package com.webreverse.mcp.javascript.analysis

/**
 * JSVMP 变体指纹与白盒 diff（ 新增）。
 *
 * 站点升级 JSVMP 脚本后，opcode 键（0x1a/0x05...）与 decode 公式常整体更换，导致
 * 「更新前还原的 patch 直接失效」。本类脱离具体 opcode 键，改从 handler **case 体语义**提取
 * 结构无关指纹：
 *
 * 1. 语义签名（semanticSig）：对每个 case 体做正则归一化（去掉数值字面量/变量名/空白），
 *    得到「操作模式骨架」，如 `_x[ _y ]`（寄存器数组读）→ STORE/LOAD 的可比对指纹。
 * 2. 指纹画像：语义签名集合 + HandlerKind 直方图 + 变量（pc/sp/ctx）候选 + 关键环境访问
 *    （window/document/navigator/crypto）— 用于跨版本识别「同一 VM 变体」。
 * 3. 白盒 diff：diffA/B 两根脚本，输出 新增/删除/共享 的语义签名、kind 分布变化、
 *    decode 公式变化、以及「预签名区段」（STORE+ARITH+CALL 高密度语义签名）在变更后
 *    是否仍在（锁定签名主循环是否被改）。
 *
 * 使用场景：A=升级前已还原脚本，B=升级后新脚本 → 秒级判断「语义是否漂移、签名区段搬哪了」。
 */
class VmpVariantDiff {

    data class HandlerFingerprint(
        val opcode: String,          // 原始 opcode 键（仅作展示，不参与跨版本匹配）
        val kind: String,            // HandlerKind.name
        val semanticSig: String,     // 归一化操作骨架（跨版本稳定）
        val confidence: Int,
        val snippet: String,         // 原始 case 体（截断）
    )

    data class VariantProfile(
        val ok: Boolean,
        val error: String = "",
        val candidateCount: Int = 0,
        val dispatchExpr: String = "",
        val handlerCount: Int = 0,
        val semanticSigs: List<String> = emptyList(),   // 去重排序
        val kindHistogram: Map<String, Int> = emptyMap(),
        val fingerprints: List<HandlerFingerprint> = emptyList(),
        val envAccess: List<String> = emptyList(),       // window/document/... 等环境访问
        val decodeFormulaHint: String = "",              // decode 公式（来自判别式）
    )

    data class DiffResult(
        val ok: Boolean,
        val error: String = "",
        val sameSigs: List<String> = emptyList(),
        val addedSigs: List<String> = emptyList(),
        val removedSigs: List<String> = emptyList(),
        val sharedCount: Int = 0,
        val addedCount: Int = 0,
        val removedCount: Int = 0,
        // 签名区段漂移评估：高价值语义（STORE/ARITH/CALL/COMPARE）在变更后是否仍存在
        val signSectionPreserved: Boolean = true,
        val signSectionChanges: List<String> = emptyList(),
        val kindShift: Map<String, String> = emptyMap(), // kind -> "a->b 计数变化"
        val decodeFormulaA: String = "",
        val decodeFormulaB: String = "",
        val similarity: Int = 0,                          // 0-100 语义相似度
        val digest: String = "",                          // 短指纹串（快速人工对比）
    )

    fun profile(source: String, sourceLabel: String = ""): VariantProfile {
        val candidates = VmpDetector().detect(source)
        if (candidates.isEmpty()) {
            return VariantProfile(ok = false, error = "未检测到 JSVMP 特征")
        }
        val candidate = candidates.first()
        val profile = JsvmpDeepAnalyzer().analyze(source, candidate)
        val maps = profile.handlers.map { normalizeSigs(it) }
        val sigs = maps.map { it.semanticSig }.distinct().sorted()
        val env = scanEnvAccess(source)
        val formula = DecodeFormulaHint.extract(profile.variables.dispatchExpr)

        return VariantProfile(
            ok = true,
            candidateCount = candidates.size,
            dispatchExpr = profile.variables.dispatchExpr,
            handlerCount = profile.handlers.size,
            semanticSigs = sigs,
            kindHistogram = profile.handlers.groupingBy { it.kind.name }.eachCount(),
            fingerprints = profile.handlers.map { h ->
                HandlerFingerprint(
                    opcode = h.key,
                    kind = h.kind.name,
                    semanticSig = normalizeSigText(h.kind, h.key, h.snippet),
                    confidence = h.confidence,
                    snippet = h.snippet.take(120),
                )
            },
            envAccess = env,
            decodeFormulaHint = formula,
        )
    }

    fun diff(a: VariantProfile, b: VariantProfile): DiffResult {
        if (!a.ok || !b.ok) {
            return DiffResult(ok = false, error = listOfNotNull(
                a.error.takeIf { !a.ok },
                b.error.takeIf { !b.ok },
            ).joinToString("; "))
        }
        val sigA = a.semanticSigs.toSet()
        val sigB = b.semanticSigs.toSet()
        val same = (sigA intersect sigB).sorted()
        val added = (sigB - sigA).sorted()
        val removed = (sigA - sigB).sorted()

        // 签名区段是否保留：高价值操作语义签名在 B 中仍存在
        val signOps = setOf("STORE_LOCAL", "ARITH", "CALL", "COMPARE")
        val aSignOps = a.fingerprints.filter { it.kind in signOps }.map { it.semanticSig }.toSet()
        val bOps = b.fingerprints.filter { it.kind in signOps }.map { it.semanticSig }.toSet()
        val preservedOps = aSignOps intersect bOps
        val lostOps = aSignOps - bOps
        val signPreserved = aSignOps.isEmpty() || lostOps.size.toDouble() / aSignOps.size <= 0.3
        val signChanges = when {
            aSignOps.isEmpty() -> emptyList()
            lostOps.isEmpty() -> listOf("签名区段全部保留（STORE/ARITH/CALL/COMPARE 语义未漂移）")
            else -> listOf(
                "签名区段部分漂移：${lostOps.size}/${aSignOps.size} 个高价值语义签名在 B 中消失",
                "消失样本：${lostOps.take(8).joinToString("; ")}",
            )
        }

        // kind 直方图位移
        val allKinds = a.kindHistogram.keys + b.kindHistogram.keys
        val kindShift = allKinds.distinct().associate { k ->
            k to "${a.kindHistogram[k] ?: 0}->${b.kindHistogram[k] ?: 0}"
        }

        // 语义相似度（Jaccard）
        val uni = sigA.size + sigB.size
        val inter = same.size
        val sim = if (uni == 0) 100 else (200.0 * inter / uni).toInt().coerceIn(0, 100)

        // 短指纹
        val digest = buildString {
            append("sigs${a.handlerCount}/${b.handlerCount}")
            append(" sim${sim}")
            append(" +${added.size}/-${removed.size}")
            append(" envA${a.envAccess.size}/envB${b.envAccess.size}")
        }

        return DiffResult(
            ok = true,
            sameSigs = same.take(200),
            addedSigs = added.take(150),
            removedSigs = removed.take(150),
            sharedCount = same.size,
            addedCount = added.size,
            removedCount = removed.size,
            signSectionPreserved = signPreserved,
            signSectionChanges = signChanges,
            kindShift = kindShift,
            decodeFormulaA = a.decodeFormulaHint,
            decodeFormulaB = b.decodeFormulaHint,
            similarity = sim,
            digest = digest,
        )
    }

    // ---------------- 内部工具 ----------------

    private fun normalizeSigs(h: JsvmpDeepAnalyzer.HandlerInfo): HandlerFingerprint =
        HandlerFingerprint(h.key, h.kind.name, normalizeSigText(h.kind, h.key, h.snippet), h.confidence, h.snippet.take(120))

    /** 归一化 case 体为跨版本稳定的操作骨架 */
    private fun normalizeSigText(kind: JsvmpDeepAnalyzer.HandlerKind, key: String, snippet: String): String {
        var s = snippet
            .replace(Regex("0x[0-9a-fA-F]+|\\b\\d+\\b"), "N")          // 数值字面量
            .replace(Regex("'[^']*'|\"[^\"]*\""), "S")                // 字符串字面量
            .replace(Regex("[A-Za-z_$][A-Za-z0-9_$]*"), "v")           // 标识符
            .replace(Regex("\\s+"), "")
        if (s.length > 48) s = s.take(48)
        return "$kind:$s"
    }

    /** 扫描源码中的关键环境访问（补环境依据） */
    private fun scanEnvAccess(source: String): List<String> {
        val found = LinkedHashSet<String>()
        val patterns = listOf(
            "window", "document", "navigator", "location", "history", "screen",
            "crypto", "performance", "Date", "Math", "XMLHttpRequest", "fetch",
            "localStorage", "sessionStorage", "WebSocket", "canvas",
        )
        patterns.forEach { p ->
            if (Regex("\\b$p\\b").containsMatchIn(source)) found.add(p)
        }
        return found.sorted()
    }
}

/** 从 dispatch 判别式提取 decode 公式描述（复用 DecodeFormula 的识别思路，纯文本版） */
internal object DecodeFormulaHint {
    fun extract(dispatchExpr: String): String {
        val expr = dispatchExpr.trim()
        if (expr.isBlank()) return ""
        return when {
            Regex("\\*").containsMatchIn(expr) && Regex("%").containsMatchIn(expr) -> "乘法取模映射"
            Regex("\\^").containsMatchIn(expr) -> "异或映射"
            Regex("-\\s*0x|\\+\\s*0x").containsMatchIn(expr) -> "偏移映射"
            Regex("parseInt").containsMatchIn(expr) -> "进制解析映射"
            Regex("charCodeAt").containsMatchIn(expr) -> "字符码映射"
            else -> "疑似直通（元素即 opcode）"
        }
    }
}