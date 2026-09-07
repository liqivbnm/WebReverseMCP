package com.webreverse.mcp.javascript.analysis

/**
 * JSVMP Micro-IR + Handler 签名库 + 动态差分语义推断。
 *
 * 在 JsvmpDeepAnalyzer（粗分类 HandlerKind）与 JsvmpSemanticRecovery（AST 切片）之上，
 * 补两档更细、且可跨脚本复用/可被动态差分验证的层：
 *
 * 1. **Micro-IR**：把 handler 的 case 体归一为微型指令序列（与 jsvmp.ir 的平台无关
 *    助记符不同，这里聚焦「单条 JS 语句 → 微观原子操作」），粒度更细：
 *    `LOAD_CONST/CONST_STR -> PUSH/READ_CTX/WRITE_CTX -> ARITH(op) -> STORE/BRANCH/CALL/JUMP`。
 *    每个 micro-op 携带操作类型与目标，组成 MicroUnit（opcode -> [microOp]）。
 *
 * 2. **Handler 签名库**：把每个 opcode 的微观语义折叠成一条稳定指纹签名
 *    （如 `ARITH:XOR::WRITE_CTX`），并维护一个跨脚本共享的签名库（类级 ConcurrentHashMap）。
 *    用途：
 *    - **跨混淆器/跨版本识别**：同一语义道程序列在不同 JSVMP 里 opcode 编号不同，
 *      但 Micro-IR 签名一致 → 签名比对即可识别「这个新 opcode 等价于旧脚本的 xxx」。
 *    - **patch 稳定性判定**：升级前后两份脚本的签名库 diff，秒级判断围绕 key 的
 *      还原 patch 是否仍有效（若 ARM signature 区块漂移则需重做）。
 *
 * 3. **动态差分语义推断**：对单条 opcode，用运行时 (输入→输出) 样本做差分求值——
 *    把候选语义当作「纯函数」逐个喂样本，若某候选对所有样本都预测正确则胜出。
 *    这是把静态微观语义从「猜测」升级为「可验证事实」的闭环（与本报告 validation
 *    引擎联动）。
 */
class JsvmpMicroIr {

    // ---------------- Micro-IR 数据模型 ----------------

    /** 微观操作分类 */
    enum class MicroOp(val display: String) {
        LOAD_CONST("push const"), PUSH_STR("push string"),
        READ_CTX("read ctx/reg"), WRITE_CTX("write ctx/reg"),
        ARITH("arith"), COMPARE("compare"), BRANCH("branch"),
        CALL("call"), MEMBER("member access"), RETURN("return"),
        STACK("stack op"), ENV("env access"), NOOP("noop"), UNKNOWN("unknown"),
    }

    /** 单条微观操作 */
    data class MicroOpIns(
        val op: MicroOp,
        val detail: String = "",   // 如 "XOR"、"ctx[sp-1]"、"fn.apply"
        val addr: Int = 0,         // case 体内相对偏移（定位）
    )

    /** 单个 opcode 的微观单元 */
    data class MicroUnit(
        val key: String,           // 原始 opcode 键（0x1a / 26 / 'a'）
        val normalizedKey: String, // 归一化十进制（"26"）
        val ops: List<MicroOpIns>,
        val signature: String,     // 折叠指纹：如 "ARITH:XOR::WRITE_CTX"
        val arity: Int = 0,        // 栈/输入操作数
    ) {
        val summary: String get() = ops.joinToString(">") { it.op.display }
    }

    // ---------------- 签名库（跨脚本共享） ----------------

    /**
     * 全局 Handler 签名库：signature -> 已知 opcode 标注。
     * 线程安全（ConcurrentHashMap），同进程内跨脚本复用。
     */
    object SignatureLibrary {
        private val sigToOpcodes = java.util.concurrent.ConcurrentHashMap<String, java.util.concurrent.ConcurrentHashMap.KeySetView<String, Boolean>>()

        /** 登记一个 signature -> opcode 映射 */
        fun register(signature: String, opcode: String) {
            if (signature.isBlank()) return
            val set = sigToOpcodes.getOrPut(signature) { java.util.concurrent.ConcurrentHashMap.newKeySet() }
            set.add(opcode)
        }

        /** 查询签名对应的已知 opcode 集合 */
        fun lookup(signature: String): List<String> =
            sigToOpcodes[signature]?.toList() ?: emptyList()

        /** 全部签名 */
        fun all(): Map<String, List<String>> =
            sigToOpcodes.mapValues { it.value.toList().sorted() }

        /** signature -> 第一 opcode（快捷） */
        fun canonical(signature: String): String? = lookup(signature).firstOrNull()

        fun size(): Int = sigToOpcodes.size
    }

    // ---------------- 主入口 ----------------

    /**
     * 对一个 JSVMP 脚本的 handlers 做 Micro-IR 归一 + 签名入库。
     * @return opcode -> MicroUnit 列表，签名已写入 [SignatureLibrary]
     */
    fun translate(handlers: List<VmpDetector.OpHandler>): List<MicroUnit> {
        val units = handlers.mapNotNull { h ->
            val key = h.key.trim()
            val normalized = normalizeKey(key) ?: return@mapNotNull null
            val ops = microOps(h.snippet)
            val sig = foldSignature(ops)
            val arity = inferArity(ops)
            SignatureLibrary.register(sig, normalized)
            MicroUnit(key, normalized, ops, sig, arity)
        }
        return units
    }

    /** 归一化 opcode 键："0x1a" -> "26"；数字原样 */
    fun normalizeKey(key: String): String? {
        val k = key.trim()
        return when {
            k.startsWith("0x") || k.startsWith("0X") -> k.substring(2).toIntOrNull(16)?.toString()
            k.toIntOrNull() != null -> k.toIntOrNull().toString()
            k.length >= 3 && k.startsWith("'") && k.endsWith("'") -> k[1].code.toString()
            else -> null
        }
    }

    // ---------------- 微观操作提取（把 case 体切成 micro-op 序列） ----------------

    private fun microOps(snippet: String): List<MicroOpIns> {
        if (snippet.isBlank()) return listOf(MicroOpIns(MicroOp.NOOP))
        val out = mutableListOf<MicroOpIns>()
        // 按 ';' 与 ',' 分割为语句片段（粗粒度近似）
        val parts = snippet.split(Regex("""[;,]""")).map { it.trim() }.filter { it.isNotEmpty() }

        for (p in parts) {
            val sa = p.length
            out.add(classifyStatement(p, sa))
        }
        if (out.isEmpty()) out.add(MicroOpIns(MicroOp.UNKNOWN))
        return out.take(12)
    }

    private fun classifyStatement(s: String, addr: Int): MicroOpIns {
        // 分支：pc 赋值 / 跳转
        if (Regex("""(pc|ip|code)\s*(=|\+=)""").containsMatchIn(s) || Regex("""\b(branch)\b""").containsMatchIn(s)) {
            return MicroOpIns(MicroOp.BRANCH, s.take(40), addr)
        }
        // 算术
        val arith = detectArith(s)
        if (arith != null) return MicroOpIns(MicroOp.ARITH, arith, addr)
        // 比较
        if (Regex(""".*[=!<>]={1,3}.*""").containsMatchIn(s)) return MicroOpIns(MicroOp.COMPARE, s.take(30), addr)
        // 调用
        if (Regex("""(\.(call|apply|bind))\s*\(|\w+\s*\(\w*""").containsMatchIn(s)) return MicroOpIns(MicroOp.CALL, s.take(30), addr)
        // 成员访问
        if (s.contains("[")) return MicroOpIns(MicroOp.MEMBER, s.take(30), addr)
        // 字符串常量
        if (Regex("""fromCharCode|charCodeAt""").containsMatchIn(s)) return MicroOpIns(MicroOp.PUSH_STR, s.take(30), addr)
        // 常量
        if (Regex("""=[^\s]*(0x|'|")""").containsMatchIn(s) || Regex("""(push|unshift)\s*\(""").containsMatchIn(s)) {
            return MicroOpIns(MicroOp.LOAD_CONST, s.take(30), addr)
        }
        // 上下文读写
        if (Regex("""(ctx|reg|stack|temp)\s*\[""").containsMatchIn(s) || Regex("""\[\s*\w+\s*\]\s*=""").containsMatchIn(s)) {
            return MicroOpIns(if (s.contains("=")) MicroOp.WRITE_CTX else MicroOp.READ_CTX, s.take(30), addr)
        }
        // env 访问
        if (Regex("""(window|document|navigator|location|globalThis)""").containsMatchIn(s)) return MicroOpIns(MicroOp.ENV, s.take(30), addr)
        // 返回
        if (Regex("""\breturn\b""").containsMatchIn(s)) return MicroOpIns(MicroOp.RETURN, s.take(20), addr)
        // 栈操作
        if (Regex("""(push|pop|shift)|stack""").containsMatchIn(s)) return MicroOpIns(MicroOp.STACK, s.take(30), addr)
        return MicroOpIns(MicroOp.UNKNOWN, s.take(30), addr)
    }

    private fun detectArith(s: String): String? {
        val ops = mapOf(
            "xor" to "XOR", "^" to "XOR",
            "imul" to "MUL", "*" to "MUL",
            "+" to "ADD", "-" to "SUB",
            "&" to "AND", "|" to "OR",
            "<<" to "SHL", ">>" to "SHR",
            "rotl" to "ROTL", "rotr" to "ROTR",
            "%" to "MOD",
        )
        for ((k, v) in ops) if (s.contains(k)) return v
        return null
    }

    private fun foldSignature(ops: List<MicroOpIns>): String {
        if (ops.isEmpty()) return "UNKNOWN"
        // 签名 = 语义类别链 + 关键 ARITH/opcode 细节
        val chain = ops.joinToString(":") { it.op.display }
        val arithDetail = ops.firstOrNull { it.op == MicroOp.ARITH }?.detail
        return if (arithDetail != null) "$chain::$arithDetail" else chain
    }

    private fun inferArity(ops: List<MicroOpIns>): Int {
        var arity = 0
        for (op in ops) {
            when (op.op) {
                MicroOp.LOAD_CONST, MicroOp.PUSH_STR, MicroOp.READ_CTX -> arity++
                MicroOp.ARITH, MicroOp.COMPARE, MicroOp.CALL -> arity = maxOf(0, arity - 1) // 消费 2 产 1（近似）
                else -> {}
            }
        }
        return arity
    }

    // ---------------- 动态差分语义推断 ----------------

    data class DiffInference(
        val ok: Boolean,
        val opcode: String,
        val winner: String,        // 胜出语义名，如 "XOR" / "ADD"
        val confirmed: Boolean,    // 是否对全部样本可验证
        val confidence: Double,    // 0~1 （存活候选 / 初始候选）
        val samplesUsed: Int,
        val candidates: List<String>,
        val evidence: List<String>,
    )

    /**
     * 对 (val, 期望输出) 样本做差分求值。候选语义如 ["XOR","ADD","SUB","OR","AND","MUL","SHL","SHR","ROTL","MOD"]。
     * 以「val[0] op val[1] == expected」逐一验证；胜者须对全部样本一致。
     */
    fun inferSemantics(opcode: String, samples: List<Map<String, Any>>, candidates: List<String>): DiffInference {
        if (samples.size < 2) {
            return DiffInference(false, opcode, "", false, 0.0, samples.size, candidates, listOf("样本不足（<2）"))
        }
        val alive = mutableListOf<String>()
        val evidence = mutableListOf<String>()
        for (cand in candidates) {
            var allMatch = true
            var tested = 0
            for (s in samples) {
                val a = num(s, "a") ?: num(s, "in1") ?: continue
                val b = num(s, "b") ?: num(s, "in2") ?: continue
                val out = num(s, "out") ?: num(s, "result") ?: s.values.lastOrNull()?.let { numOf(it) } ?: continue
                val pred = tryEval(cand, a, b)
                if (pred == null) { allMatch = false; break }
                tested++
                if (pred != out) { allMatch = false; break }
            }
            if (allMatch && tested >= 2) {
                alive.add(cand)
                evidence.add("$cand 在 $tested 样本上全部预测正确")
            }
        }
        if (alive.isEmpty()) {
            return DiffInference(false, opcode, "", false, 0.0, samples.size, candidates, evidence + listOf("无候选语义匹配全部样本"))
        }
        return DiffInference(
            ok = true,
            opcode = opcode,
            winner = alive.first(),
            confirmed = alive.size == 1,
            confidence = 1.0 / alive.size,
            samplesUsed = samples.size,
            candidates = candidates,
            evidence = evidence,
        )
    }

    /** 尝试按候选语义计算 a op b；不支持/除零/溢出返回 null */
    private fun tryEval(op: String, a: Long, b: Long): Long? {
        // 截断到 32 位（JS 位运算语义）
        val aa = (a and 0xFFFFFFFFL).toInt()
        val bb = (b and 0xFFFFFFFFL).toInt()
        val ua = aa.toLong() and 0xFFFFFFFFL
        val ub = bb.toLong() and 0xFFFFFFFFL
        return when (op) {
            "XOR" -> (ua xor ub) and 0xFFFFFFFFL
            "AND" -> (ua and ub) and 0xFFFFFFFFL
            "OR" -> (ua or ub) and 0xFFFFFFFFL
            "ADD" -> (ua + ub) and 0xFFFFFFFFL
            "SUB" -> (ua - ub) and 0xFFFFFFFFL
            "MUL" -> (ua * ub) and 0xFFFFFFFFL
            "SHL" -> (ua shl (bb and 31)) and 0xFFFFFFFFL
            // SHR：JS 的 >>> 逻辑右移，Long 上 ushr 即可
            "SHR" -> (ua ushr (bb and 31)) and 0xFFFFFFFFL
            "ROTL" -> rotl(ua, (bb and 31))
            "ROTR" -> rotr(ua, (bb and 31))
            "MOD" -> if (b == 0L) null else (a % b) and 0xFFFFFFFFL
            else -> null
        }
    }

    /** 从样本 map 按键取长整数值 */
    private fun num(s: Map<String, Any>, key: String): Long? = s[key]?.let { numOf(it) }

    private fun numOf(v: Any): Long? = when (v) {
        is Long -> v
        is Int -> v.toLong()
        is Number -> v.toLong()
        is String -> v.toDoubleOrNull()?.toLong()
        else -> null
    }

    /** 对 32 位无符号值做循环左移 */
    private fun rotl(u: Long, n: Int): Long {
        val v = u and 0xFFFFFFFFL
        if (n == 0) return v
        return ((v shl n) or (v ushr (32 - n))) and 0xFFFFFFFFL
    }

    /** 对 32 位无符号值做循环右移 */
    private fun rotr(u: Long, n: Int): Long {
        val v = u and 0xFFFFFFFFL
        if (n == 0) return v
        return ((v ushr n) or (v shl (32 - n))) and 0xFFFFFFFFL
    }
}