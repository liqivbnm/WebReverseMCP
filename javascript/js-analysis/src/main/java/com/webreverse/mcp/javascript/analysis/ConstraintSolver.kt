package com.webreverse.mcp.javascript.analysis

/**
 * 轻量符号约束求解器（v1）——纯 Kotlin，无第三方依赖。
 *
 * 面向 [TraceSymbolizer] 及 js-analysis 内其它符号化/符号执行产物：
 * 提供“符号变量 → 约束表达式”的建模、线性算术 + 比较 + 布尔逻辑约束的求解
 * （区间传播 / 替换）、路径可达性判定，以及从符号化结果构造约束集的适配入口。
 *
 * 能力：
 *  1. 符号变量到约束表达式的映射（[ConstraintSystem.define] / [ConstraintSystem.declare]）；
 *  2. 约束语言：[SymExpr]（常量/变量/加减/乘常量/取负）+ [Constraint]
 *     （Rel 比较、And / Or / Not 布尔组合）；
 *  3. [ConstraintSystem.solve]：区间传播 + 替换，给不出精确值时返回 [SolverValue.Interval]
 *     或 [SolverValue.Symbolic]（表达式哈希）；
 *  4. [ConstraintSystem.reachability]：给定路径条件判定可行性
 *     [Reachability.FEASIBLE / INFEASIBLE / UNKNOWN]（不精确时返回 UNKNOWN）；
 *  5. [ConstraintSystem.fromTraceSymbolized]：从 [TraceSymbolizer.Symbolized] 输出构造约束集。
 */
class ConstraintSolver {

    // ---------------- 表达式 ----------------

    sealed class SymExpr {
        /** 整型常量 */
        data class Const(val v: Long) : SymExpr()
        /** 符号变量 */
        data class Var(val name: String) : SymExpr()
        /** 加法 */
        data class Add(val a: SymExpr, val b: SymExpr) : SymExpr()
        /** 减法 */
        data class Sub(val a: SymExpr, val b: SymExpr) : SymExpr()
        /** 乘常量 */
        data class Mul(val e: SymExpr, val c: Long) : SymExpr()
        /** 取负 */
        data class Neg(val e: SymExpr) : SymExpr()

        /** 规范字符串（同时也是“符号哈希”的输入源） */
        override fun toString(): String = when (this) {
            is Const -> v.toString()
            is Var -> name
            is Add -> "($a+$b)"
            is Sub -> "($a-$b)"
            is Mul -> "($e*$c)"
            is Neg -> "(-$e)"
        }
    }

    companion object {
        private const val LONG_MIN = Long.MIN_VALUE
        private const val LONG_MAX = Long.MAX_VALUE

        private data class Interval(val lo: Long, val hi: Long)

        private val FULL = Interval(LONG_MIN, LONG_MAX)

        /** 快捷构造常量 */
        fun c(v: Long): SymExpr.Const = SymExpr.Const(v)
        /** 快捷构造变量 */
        fun v(name: String): SymExpr.Var = SymExpr.Var(name)
        fun add(a: SymExpr, b: SymExpr): SymExpr = SymExpr.Add(a, b)
        fun sub(a: SymExpr, b: SymExpr): SymExpr = SymExpr.Sub(a, b)
        fun mul(e: SymExpr, c: Long): SymExpr = if (c == 1L) e else SymExpr.Mul(e, c)
        fun neg(e: SymExpr): SymExpr = SymExpr.Neg(e)

        /** 表达式规范哈希（十六进制，用于给不出精确值时作为符号指纹） */
        fun symbolHash(e: SymExpr): String {
            val h = e.toString().hashCode()
            return ("00000000" + Integer.toHexString(h)).takeLast(8)
        }

        // ---------------- 区间（Long，饱和防溢出） ----------------

        private fun satAdd(a: Long, b: Long): Long {
            if (a > 0 && b > LONG_MAX - a) return LONG_MAX
            if (a < 0 && b < LONG_MIN - a) return LONG_MIN
            return a + b
        }

        private fun satSub(a: Long, b: Long): Long {
            if (b == LONG_MIN) return if (a < 0) LONG_MAX else LONG_MIN + a  // 近似
            return satAdd(a, -b)
        }

        private fun satNeg(a: Long): Long = if (a == LONG_MIN) LONG_MAX else -a

        private fun satMul(a: Long, b: Long): Long {
            if (a == 0L || b == 0L) return 0L
            if (a == LONG_MIN || b == LONG_MIN) return if ((a < 0) xor (b < 0)) LONG_MIN else LONG_MAX
            val r = a * b
            if (r / a != b) return if ((a > 0) == (b > 0)) LONG_MAX else LONG_MIN
            return r
        }

        private fun intervalAdd(a: Interval, b: Interval) =
            Interval(satAdd(a.lo, b.lo), satAdd(a.hi, b.hi))

        private fun intervalSub(a: Interval, b: Interval) =
            Interval(satSub(a.lo, b.hi), satSub(a.hi, b.lo))

        private fun intervalNeg(a: Interval) = Interval(satNeg(a.hi), satNeg(a.lo))

        private fun intervalMulConst(a: Interval, c: Long): Interval = when {
            c >= 0 -> Interval(satMul(a.lo, c), satMul(a.hi, c))
            else -> Interval(satMul(a.hi, c), satMul(a.lo, c))
        }

        private fun floorDiv(a: Long, b: Long): Long = a / b

        private fun ceilDiv(a: Long, b: Long): Long {
            if (b < 0) return ceilDiv(-a, -b)
            val q = a / b
            val r = a % b
            return if (r > 0) q + 1 else q
        }

        // ---------------- 线性化与区间求值 ----------------

        /** 把表达式关于目标变量 v 化简为 a*v + rest，rest 为区间；非线性（v 出现在乘数）返回 null。 */
        private fun toAffine(e: SymExpr, target: String, dom: Map<String, Interval>): Pair<Long, Interval>? {
            return when (e) {
                is SymExpr.Const -> 0L to Interval(e.v, e.v)
                is SymExpr.Var -> if (e.name == target) 1L to Interval(0L, 0L)
                else 0L to (dom[e.name] ?: FULL)
                is SymExpr.Add -> {
                    val (la, lb) = toAffine(e.a, target, dom) ?: return null
                    val (ra, rb) = toAffine(e.b, target, dom) ?: return null
                    satAdd(la, ra) to intervalAdd(lb, rb)
                }
                is SymExpr.Sub -> {
                    val (la, lb) = toAffine(e.a, target, dom) ?: return null
                    val (ra, rb) = toAffine(e.b, target, dom) ?: return null
                    satSub(la, ra) to intervalSub(lb, rb)
                }
                is SymExpr.Mul -> {
                    val (a, b) = toAffine(e.e, target, dom) ?: return null
                    satMul(a, e.c) to intervalMulConst(b, e.c)
                }
                is SymExpr.Neg -> {
                    val (a, b) = toAffine(e.e, target, dom) ?: return null
                    (-a) to intervalNeg(b)
                }
            }
        }

        /** 符号替换：把 defs 中已定义变量替换为其表达式（深展开，含环保护）。 */
        private fun expand(e: SymExpr, defs: Map<String, SymExpr>): SymExpr = expand(e, defs, HashSet())

        private fun expand(e: SymExpr, defs: Map<String, SymExpr>, seen: HashSet<String>): SymExpr = when (e) {
            is SymExpr.Const -> e
            is SymExpr.Var -> {
                val d = defs[e.name]
                if (d != null && e.name !in seen) {
                    seen.add(e.name)
                    val r = expand(d, defs, seen)
                    seen.remove(e.name)
                    r
                } else e
            }
            is SymExpr.Add -> SymExpr.Add(expand(e.a, defs, seen), expand(e.b, defs, seen))
            is SymExpr.Sub -> SymExpr.Sub(expand(e.a, defs, seen), expand(e.b, defs, seen))
            is SymExpr.Mul -> SymExpr.Mul(expand(e.e, defs, seen), e.c)
            is SymExpr.Neg -> SymExpr.Neg(expand(e.e, defs, seen))
        }

        private fun expand(c: Constraint, defs: Map<String, SymExpr>): Constraint = when (c) {
            is Constraint.Rel -> Constraint.Rel(c.op, expand(c.lhs, defs), expand(c.rhs, defs))
            is Constraint.And -> Constraint.And(c.parts.map { expand(it, defs) })
            is Constraint.Or -> Constraint.Or(c.parts.map { expand(it, defs) })
            is Constraint.Not -> Constraint.Not(expand(c.inner, defs))
        }

        private fun intervalEval(e: SymExpr, dom: Map<String, Interval>): Interval = when (e) {
            is SymExpr.Const -> Interval(e.v, e.v)
            is SymExpr.Var -> dom[e.name] ?: FULL
            is SymExpr.Add -> intervalAdd(intervalEval(e.a, dom), intervalEval(e.b, dom))
            is SymExpr.Sub -> intervalSub(intervalEval(e.a, dom), intervalEval(e.b, dom))
            is SymExpr.Mul -> intervalMulConst(intervalEval(e.e, dom), e.c)
            is SymExpr.Neg -> intervalNeg(intervalEval(e.e, dom))
        }

        private enum class Truth { TRUE, FALSE, UNKNOWN }

        private fun relTruth(op: RelOp, a: Interval, b: Interval): Truth {
            return when (op) {
                RelOp.EQ -> when {
                    a.lo == a.hi && b.lo == b.hi && a.lo == b.lo -> Truth.TRUE
                    a.hi < b.lo || b.hi < a.lo -> Truth.FALSE
                    else -> Truth.UNKNOWN
                }
                RelOp.NE -> when {
                    a.lo == a.hi && b.lo == b.hi && a.lo == b.lo -> Truth.FALSE
                    a.hi < b.lo || b.hi < a.lo -> Truth.TRUE
                    else -> Truth.UNKNOWN
                }
                RelOp.LT -> when {
                    a.hi < b.lo -> Truth.TRUE
                    a.lo >= b.hi -> Truth.FALSE
                    else -> Truth.UNKNOWN
                }
                RelOp.LE -> when {
                    a.hi <= b.lo -> Truth.TRUE
                    a.lo > b.hi -> Truth.FALSE
                    else -> Truth.UNKNOWN
                }
                RelOp.GT -> when {
                    a.lo > b.hi -> Truth.TRUE
                    a.hi <= b.lo -> Truth.FALSE
                    else -> Truth.UNKNOWN
                }
                RelOp.GE -> when {
                    a.lo >= b.hi -> Truth.TRUE
                    a.hi < b.lo -> Truth.FALSE
                    else -> Truth.UNKNOWN
                }
            }
        }

        private fun truthInterval(c: Constraint, dom: Map<String, Interval>): Truth {
            return when (c) {
                is Constraint.Rel -> relTruth(c.op, intervalEval(c.lhs, dom), intervalEval(c.rhs, dom))
                is Constraint.And -> {
                    var anyUnknown = false
                    for (p in c.parts) {
                        when (truthInterval(p, dom)) {
                            Truth.FALSE -> return Truth.FALSE
                            Truth.TRUE -> Unit
                            Truth.UNKNOWN -> anyUnknown = true
                        }
                    }
                    if (anyUnknown) Truth.UNKNOWN else Truth.TRUE
                }
                is Constraint.Or -> {
                    var anyUnknown = false
                    for (p in c.parts) {
                        when (truthInterval(p, dom)) {
                            Truth.TRUE -> return Truth.TRUE
                            Truth.FALSE -> Unit
                            Truth.UNKNOWN -> anyUnknown = true
                        }
                    }
                    if (anyUnknown) Truth.UNKNOWN else Truth.FALSE
                }
                is Constraint.Not -> when (val t = truthInterval(c.inner, dom)) {
                    Truth.TRUE -> Truth.FALSE
                    Truth.FALSE -> Truth.TRUE
                    Truth.UNKNOWN -> Truth.UNKNOWN
                }
            }
        }

        /** 区间传播：对每个 Rel / And 内的 Rel，收敛目标变量域。 */
        private fun propagate(cons: List<Constraint>, dom: HashMap<String, Interval>) {
            val rels = mutableListOf<Constraint.Rel>()
            fun flatten(c: Constraint) {
                when (c) {
                    is Constraint.Rel -> rels.add(c)
                    is Constraint.And -> c.parts.forEach { flatten(it) }
                    // Or / Not 不能做合取式收缩，交由 truthInterval 判定，避免误报不可行。
                    is Constraint.Or -> Unit
                    is Constraint.Not -> Unit
                }
            }
            cons.forEach(::flatten)
            var changed = true
            var iter = 0
            while (changed && iter < 64) {
                changed = false
                iter++
                for (rel in rels) {
                    for (name in variablesOfRel(rel)) {
                        val bound = deriveBound(rel, name, dom) ?: continue
                        val cur = dom[name] ?: FULL
                        val next = intervalIntersect(cur, bound)
                        if (next.lo > next.hi || next != cur) {
                            dom[name] = next
                            changed = true
                            if (next.lo > next.hi) return // 空域
                        }
                    }
                }
            }
        }

        private fun variablesOfExpr(e: SymExpr): Set<String> = when (e) {
            is SymExpr.Var -> setOf(e.name)
            else -> LinkedHashSet<String>().apply {
                fun walk(x: SymExpr) {
                    when (x) {
                        is SymExpr.Const -> Unit
                        is SymExpr.Var -> add(x.name)
                        is SymExpr.Add -> { walk(x.a); walk(x.b) }
                        is SymExpr.Sub -> { walk(x.a); walk(x.b) }
                        is SymExpr.Mul -> walk(x.e)
                        is SymExpr.Neg -> walk(x.e)
                    }
                }
                walk(e)
            }
        }

        private fun variablesOfRel(rel: Constraint.Rel): Set<String> =
            variablesOfExpr(rel.lhs) + variablesOfExpr(rel.rhs)

        private fun intervalIntersect(a: Interval, b: Interval): Interval =
            Interval(maxOf(a.lo, b.lo), minOf(a.hi, b.hi))

        private fun variablesOfConstraint(c: Constraint): Set<String> = when (c) {
            is Constraint.Rel -> variablesOfExpr(c.lhs) + variablesOfExpr(c.rhs)
            is Constraint.And -> c.parts.flatMapTo(LinkedHashSet()) { variablesOfConstraint(it) }
            is Constraint.Or -> c.parts.flatMapTo(LinkedHashSet()) { variablesOfConstraint(it) }
            is Constraint.Not -> variablesOfConstraint(c.inner)
        }

        /** 由 Rel 推导目标变量 v 的域上/下界（保守，宽松时才收缩）。 */
        private fun deriveBound(rel: Constraint.Rel, target: String, dom: HashMap<String, Interval>): Interval? {
            val (a0, b0) = toAffine(rel.lhs, target, dom) ?: return null
            val (a1, b1) = toAffine(rel.rhs, target, dom) ?: return null
            val a = satSub(a0, a1)                 // v 的净系数
            val b = intervalSub(b0, b1)            // 净余区间（lhs op rhs → a*v + B op 0, B=b0-b1）
            if (a == 0L) return null               // 对 v 的独立约束→由 truthInterval 处理
            // 仅在余项为点时做收紧（早期简单、不误报不可行）
            if (b.lo != b.hi) return null
            val B = b.lo
            // a*v + B op 0
            val root = -B.toDouble() / a
            val lo: Long
            val hi: Long
            when (rel.op) {
                RelOp.EQ -> {
                    if (root != Math.floor(root)) return Interval(LONG_MAX, LONG_MIN) // 非整根→空
                    val k = root.toLong()
                    return Interval(k, k)
                }
                RelOp.NE -> return null
                RelOp.LT -> {
                    if (a > 0) { hi = ceilDiv(-B - 1, a); lo = dom[target]?.lo ?: LONG_MIN }
                    else { lo = ceilDiv(-B + 1, a); hi = dom[target]?.hi ?: LONG_MAX }
                }
                RelOp.LE -> {
                    if (a > 0) { hi = floorDiv(-B, a); lo = dom[target]?.lo ?: LONG_MIN }
                    else { lo = ceilDiv(-B, a); hi = dom[target]?.hi ?: LONG_MAX }
                }
                RelOp.GT -> {
                    if (a > 0) { lo = floorDiv(-B, a) + 1; hi = dom[target]?.hi ?: LONG_MAX }
                    else { hi = floorDiv(-B, a) - 1; lo = dom[target]?.lo ?: LONG_MIN }
                }
                RelOp.GE -> {
                    if (a > 0) { lo = ceilDiv(-B, a); hi = dom[target]?.hi ?: LONG_MAX }
                    else { hi = floorDiv(-B, a); lo = dom[target]?.lo ?: LONG_MIN }
                }
            }
            return Interval(lo, hi)
        }

        // ---------------- 具体解构造（sound witness） ----------------

        private fun evalConcrete(e: SymExpr, assign: Map<String, Long>): Long? = when (e) {
            is SymExpr.Const -> e.v
            is SymExpr.Var -> assign[e.name]
            is SymExpr.Add -> {
                val a = evalConcrete(e.a, assign) ?: return null
                val b = evalConcrete(e.b, assign) ?: return null
                satAdd(a, b)
            }
            is SymExpr.Sub -> {
                val a = evalConcrete(e.a, assign) ?: return null
                val b = evalConcrete(e.b, assign) ?: return null
                satSub(a, b)
            }
            is SymExpr.Mul -> {
                val a = evalConcrete(e.e, assign) ?: return null
                satMul(a, e.c)
            }
            is SymExpr.Neg -> {
                val a = evalConcrete(e.e, assign) ?: return null
                satNeg(a)
            }
        }

        private fun truthConcrete(c: Constraint, assign: Map<String, Long>): Boolean? {
            val cmp: (RelOp, Long?, Long?) -> Boolean? = { o, a, b ->
                if (a == null || b == null) null else when (o) {
                    RelOp.EQ -> a == b
                    RelOp.NE -> a != b
                    RelOp.LT -> a < b
                    RelOp.LE -> a <= b
                    RelOp.GT -> a > b
                    RelOp.GE -> a >= b
                }
            }
            return when (c) {
                is Constraint.Rel -> cmp(c.op, evalConcrete(c.lhs, assign), evalConcrete(c.rhs, assign))
                is Constraint.And -> {
                    var any = false
                    for (p in c.parts) when (truthConcrete(p, assign)) {
                        false -> return false
                        true -> Unit
                        null -> any = true
                    }
                    if (any) null else true
                }
                is Constraint.Or -> {
                    var anyUnknown = false
                    for (p in c.parts) when (truthConcrete(p, assign)) {
                        true -> return true
                        false -> Unit
                        null -> anyUnknown = true
                    }
                    if (anyUnknown) null else false
                }
                is Constraint.Not -> when (val t = truthConcrete(c.inner, assign)) {
                    null -> null
                    true -> false
                    false -> true
                }
            }
        }

        /** 尝试用区间域内的候选点构造全满足的解。 */
        private fun findConcreteWitness(cons: List<Constraint>, dom: Map<String, Interval>): Boolean {
            val vars = LinkedHashSet<String>()
            cons.forEach { vars += variablesOfConstraint(it) }
            if (vars.isEmpty()) return true
            val cands = HashMap<String, List<Long>>()
            for (n in vars) {
                val iv = dom[n] ?: FULL
                val list = LinkedHashSet<Long>()
                list.add(iv.lo)
                if (iv.hi > iv.lo) {
                    list.add(iv.hi)
                    val mid = iv.lo + (iv.hi - iv.lo) / 2
                    list.add(mid)
                }
                list.add(0L); list.add(1L); list.add(-1L)
                cands[n] = list.toList()
            }
            val order = vars.toList()
            var attempts = 0
            fun dfs(idx: Int, assign: HashMap<String, Long>): Boolean {
                if (attempts > 4096) return false
                if (idx == order.size) {
                    attempts++
                    if (cons.all { truthConcrete(it, assign) == true }) return true
                    return false
                }
                val n = order[idx]
                for (val_ in cands[n]!!) {
                    assign[n] = val_
                    if (dfs(idx + 1, assign)) return true
                }
                assign.remove(n)
                return false
            }
            val assign = HashMap<String, Long>()
            return dfs(0, assign)
        }
    }

    // ---------------- 比较算子 ----------------

    enum class RelOp { EQ, NE, LT, LE, GT, GE }

    // ---------------- 约束 ----------------

    sealed class Constraint {
        /** 比较运算：lhs op rhs */
        data class Rel(val op: RelOp, val lhs: SymExpr, val rhs: SymExpr) : Constraint()
        /** 逻辑与 */
        data class And(val parts: List<Constraint>) : Constraint()
        /** 逻辑或 */
        data class Or(val parts: List<Constraint>) : Constraint()
        /** 逻辑非 */
        data class Not(val inner: Constraint) : Constraint()
    }

    // ---------------- 求解结果 ----------------

    sealed class SolverValue {
        /** 精确整型值 */
        data class Exact(val v: Long) : SolverValue()
        /** 区间 */
        data class Interval(val lo: Long, val hi: Long) : SolverValue()
        /** 无法收敛为数值 → 返回符号哈希 + 表达式 */
        data class Symbolic(val hash: String, val expr: SymExpr) : SolverValue()
    }

    /** 路径可达性判定结果 */
    enum class Reachability { FEASIBLE, INFEASIBLE, UNKNOWN }

    // ---------------- 系统 ----------------

    /** 约束系统：符号变量 + 定义映射 + 约束列表。 */
    class ConstraintSystem {
        private val declared = LinkedHashSet<String>()
        private val defs = LinkedHashMap<String, SymExpr>()
        private val constraints = mutableListOf<Constraint>()

        /** 注册符号变量（返回 this 便于链式）。 */
        fun declare(name: String): ConstraintSystem {
            declared.add(name)
            defs.putIfAbsent(name, SymExpr.Var(name))
            return this
        }

        /** 符号变量 → 约束表达式 映射（用于替换推导）。 */
        fun define(name: String, expr: SymExpr): ConstraintSystem {
            declare(name)
            defs[name] = expr
            return this
        }

        /** 添加约束（AND 语义并入当前系统）。 */
        fun add(c: Constraint): ConstraintSystem {
            constraints.add(c)
            collectVars(c).forEach { declare(it) }
            return this
        }

        /** 便捷：添加比较约束。 */
        fun addRel(op: RelOp, lhs: SymExpr, rhs: SymExpr): ConstraintSystem = add(Constraint.Rel(op, lhs, rhs))

        /** 便捷：x op k。 */
        fun addEquals(v: String, k: Long): ConstraintSystem = addRel(RelOp.EQ, SymExpr.Var(v), c(k))

        // ---------------- 查询 ----------------
        fun variables(): Set<String> = declared.toSet()
        fun definitions(): Map<String, SymExpr> = defs.toMap()
        fun allConstraints(): List<Constraint> = constraints.toList()

        /** 解析：区间传播 + 替换，返回每个变量的 [SolverValue]。 */
        fun solve(): Map<String, SolverValue> {
            val defMap: Map<String, SymExpr> = defs
            val expanded = constraints.map { expand(it, defMap) }
            val dom = HashMap<String, Interval>()
            declared.forEach { dom[it] = FULL }

            // 1) 定义映射的替换：把 ``define`` 的表达式作为等式并入。
            val defConstraints = defs.entries.mapNotNull { (n, e) ->
                if (n !in declared) null else Constraint.Rel(RelOp.EQ, SymExpr.Var(n), expand(e, defMap))
            }

            // 2) 区间传播（Rel + And 复合）。
            propagate(expanded + defConstraints, dom)

            // 3) 收敛为 SolverValue。
            return declared.associateWith { name ->
                val iv = dom[name] ?: FULL
                when {
                    iv.lo == iv.hi -> SolverValue.Exact(iv.lo)
                    iv.lo > LONG_MIN || iv.hi < LONG_MAX -> SolverValue.Interval(iv.lo, iv.hi)
                    else -> SolverValue.Symbolic(symbolHash(SymExpr.Var(name)), SymExpr.Var(name))
                }
            }
        }

        /**
         * 路径可达性：给定一组路径条件（约束），判定是否存在可行解。
         *  - 任一变量域收缩为空 → INFEASIBLE；
         *  - 实值代入能构造出满足全部条件的解 → FEASIBLE；
         *  - 否则（不精确）→ UNKNOWN。
         */
        fun reachability(conditions: List<Constraint>? = null): Reachability {
            val conds = conditions ?: constraints.toList()
            val defMap: Map<String, SymExpr> = defs
            val expanded = conds.map { expand(it, defMap) }
            val join = if (expanded.isEmpty()) Constraint.And(emptyList()) else Constraint.And(expanded)
            val dom = HashMap<String, Interval>()
            declared.forEach { dom[it] = FULL }

            // 前缀传播，找空域（不可行证据）。
            propagate(expanded, dom)
            if (dom.values.any { it.lo > it.hi }) return Reachability.INFEASIBLE

            // 区间真值：若根为 definitely FALSE → INFEASIBLE。
            when (truthInterval(join, dom)) {
                Truth.FALSE -> return Reachability.INFEASIBLE
                Truth.TRUE -> return Reachability.FEASIBLE
                Truth.UNKNOWN -> Unit
            }

            // 尝试构造具体可行解（sound witness）。
            if (findConcreteWitness(expanded, dom)) return Reachability.FEASIBLE
            return Reachability.UNKNOWN
        }

        /** [reachability] 的别名 */
        fun isSatisfiable(): Reachability = reachability(null)

        // ---------------- 内部 ----------------

        private fun collectVars(c: Constraint): Set<String> {
            val out = LinkedHashSet<String>()
            fun ext(x: SymExpr) {
                when (x) {
                    is SymExpr.Const -> Unit
                    is SymExpr.Var -> out.add(x.name)
                    is SymExpr.Add -> { ext(x.a); ext(x.b) }
                    is SymExpr.Sub -> { ext(x.a); ext(x.b) }
                    is SymExpr.Mul -> ext(x.e)
                    is SymExpr.Neg -> ext(x.e)
                }
            }
            fun walk(x: Constraint) {
                when (x) {
                    is Constraint.Rel -> { ext(x.lhs); ext(x.rhs) }
                    is Constraint.And -> x.parts.forEach(::walk)
                    is Constraint.Or -> x.parts.forEach(::walk)
                    is Constraint.Not -> walk(x.inner)
                }
            }
            walk(c)
            return out
        }
    }

    /**
     * 从 [TraceSymbolizer.Symbolized] 输出构造约束集：
     *  - 每个热点 opcode（助记名→次数）建模为符号变量并与出现次数建立 EQ 约束；
     *  - 每条 listing 行建模为 op 变量 = 行序 约束；
     *  - 数字操作数建模为常量相等约束。
     * 这是一个松散的“符号化结果→约束集”适配入口，供上层将其作为路径条件
     * 交由 [solve] / [reachability] 分析。
     */
    fun fromTraceSymbolized(sym: TraceSymbolizer.Symbolized): ConstraintSystem {
        val cs = ConstraintSystem()
        sym.hotOpcodes.forEachIndexed { i, (mnem, count) ->
            val nm = "hot_$i:$mnem"
            cs.declare(nm)
            cs.addRel(RelOp.EQ, SymExpr.Var(nm), c(count.toLong()))
            cs.define(nm, c(count.toLong()))
        }
        if (sym.listing.isNotBlank()) {
            sym.listing.lines().forEachIndexed { i, line ->
                val t = line.trim().split(Regex("\\s+")).filter { it.isNotBlank() }
                if (t.isEmpty()) return@forEachIndexed
                val mnemonic = t[0]
                val lineVar = "insn_$i:$mnemonic"
                cs.declare(lineVar)
                cs.addRel(RelOp.EQ, SymExpr.Var(lineVar), c(i.toLong()))
                // 数字操作数 → 常量等于约束（模拟内部寄存器与立即数关系）
                t.drop(1).filter { it.toLongOrNull() != null }.forEachIndexed { k, opr ->
                    val cell = "${lineVar}_op$k"
                    cs.declare(cell)
                    cs.addRel(RelOp.EQ, SymExpr.Var(cell), c(opr.toLong()))
                }
            }
        }
        return cs
    }
}