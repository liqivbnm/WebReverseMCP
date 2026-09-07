package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import kotlinx.serialization.json.jsonObject

/**
 * 离线可执行沙箱（方向3 / ）。
 *
 * 纯 Kotlin 实现的轻量 JS-表达式解释器，不依赖页面 WebView / V8 运行时，因此：
 * - 可在无 CDP、无页面环境、甚至离线下（配合 file.read 取源码）执行解密/编码公式；
 * - 不受页面 Timing/反调试/eval 污染干扰，结果可复现；
 * - 覆盖常见加密线索的"最后落地"：base64/hex/url-utf8/位移/异或/字符转换等可编程片段。
 *
 * 安全边界：解释器无 DOM/网络/FS/定时器，仅纯计算 + 读入 ctx；执行次数/节点数有界。
 */
object OfflineSandboxTools {

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)
        return listOf(
            f.tool(
                "code.sandbox_eval",
                "离线执行 JS 表达式/解密片段（纯 Kotlin 沙箱，无需页面）：支持算术/位运算/比较/三元/数组/对象/成员访问/字符串方法与 btoa・atob・hex・utf8 等内建，可注入 ctx 变量",
                ToolCategory.REVERSE,
                PermissionScope.EXECUTE_JS,
                RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "expression" to Schemas.strSchema("要计算的表达式，如 (parseInt('41',16)^0x9f).toString(16) 或 btoa(ctx.p)"),
                    "ctx" to Schemas.strSchema("可选 JSON 对象注入到表达式作用域（如 {\"p\":\"abc\",\"key\":\"3b\"}）"),
                    "maxSteps" to Schemas.intSchema("执行步数上限（默认 100000，防死循环）"),
                ),
            ) { args ->
                val expr = ToolArgs.str(args, "expression")
                if (expr.isBlank()) return@tool McpToolResult.error("BAD_ARGS", "expression 不能为空")
                val maxSteps = ToolArgs.int(args, "maxSteps", 100000).coerceIn(1000, 1_000_000)
                val ctxJson = ToolArgs.str(args, "ctx")
                val ctxMap: Map<String, Any?> = if (ctxJson.isNotBlank()) {
                    try {
                        val obj = kotlinx.serialization.json.Json.parseToJsonElement(ctxJson).jsonObject
                        obj.mapValues { (_, v) -> jsonToValue(v) }
                    } catch (e: Exception) { emptyMap() }
                } else emptyMap()
                val engine = OfflineExpr(ctxMap, maxSteps)
                val out = runCatching { engine.eval(expr) }.getOrElse { e -> e }
                McpToolResult.json(
                    buildJsonObject {
                        put("expression", kotlinx.serialization.json.JsonPrimitive(expr.take(400)))
                        put(
                            "result",
                            kotlinx.serialization.json.JsonPrimitive(
                                when (out) {
                                    is Throwable -> "ERROR: ${out.message}"
                                    else -> valueToText(out)
                                },
                            ),
                        )
                        put("steps", kotlinx.serialization.json.JsonPrimitive(engine.stepCount))
                        put(
                            "type",
                            kotlinx.serialization.json.JsonPrimitive(
                                when (out) {
                                    is Throwable -> "error"
                                    is String -> "string"
                                    is Int, is Double, is Long -> "number"
                                    is Boolean -> "boolean"
                                    null -> "null"
                                    is Map<*, *> -> "object"
                                    is List<*> -> "array"
                                    else -> typeofText(out)
                                },
                            ),
                        )
                        put(
                            "hint",
                            kotlinx.serialization.json.JsonPrimitive(
                                "离线沙箱：适合对解密/编码片段做不可见算以剥离外层。若需完整 JS 语义（闭包/async），可改用 debugger.runtime_evaluate 在线执行",
                            ),
                        )
                    },
                )
            },
        )
    }

    private fun typeofText(v: Any?): String = if (v is NativeFn) "function" else "unknown"
    /** JSON -> 沙箱值 */
    private fun jsonToValue(v: kotlinx.serialization.json.JsonElement): Any? = when (v) {
        is kotlinx.serialization.json.JsonNull -> null
        is kotlinx.serialization.json.JsonPrimitive -> when {
            v.isString -> v.content
            v.content.toLongOrNull() != null -> v.content.toLong()
            else -> v.content.toDoubleOrNull() ?: v.content
        }
        is kotlinx.serialization.json.JsonArray -> ArrayList(v.map { jsonToValue(it) })
        is kotlinx.serialization.json.JsonObject -> LinkedHashMap(v.mapValues { (_, e) -> jsonToValue(e) })
    }
}

private fun valueToText(v: Any?): String = when (v) {
    null -> "null"
    is String -> v
    is Boolean -> v.toString().lowercase()
    is Int, is Long, is Double -> numToText(v)
    is Map<*, *> -> v.entries.joinToString(",", "{", "}") { "${it.key}=${valueToText(it.value)}" }
    is List<*> -> v.joinToString(",", "[", "]") { valueToText(it) }
    is NativeFn -> "[function]"
    else -> v.toString()
}
private fun numToText(v: Any): String = when (v) {
    is Double -> if (v == Math.floor(v) && !v.isInfinite()) "${v.toLong()}" else "$v"
    else -> "$v"
}

/** 生成 code.sandbox_eval 结果对象用的别名 */
private inline fun buildJsonObject(builder: kotlinx.serialization.json.JsonObjectBuilder.() -> Unit) =
    kotlinx.serialization.json.buildJsonObject(builder)
private fun JsonObjectBuilderAlias() {}

/**
 * 微型 JS 表达式引擎：词法 + 递归下降（优先级爬升）+ 延迟求值。
 * 只读、无副作用（读写 ctx 变量表），步数有界。
 */
private class OfflineExpr(
    private val vars: Map<String, Any?> = emptyMap(),
    private val maxSteps: Int = 100000,
) {
    var stepCount: Int = 0
        private set

    private val builtins: MutableMap<String, Any?> = LinkedHashMap<String, Any?>()

    init {
        builtins["btoa"] = NativeFn("btoa") { a -> java.util.Base64.getEncoder().encodeToString((argStr(a, 0)).toByteArray(Charsets.ISO_8859_1)) }
        builtins["atob"] = NativeFn("atob") { a -> String(java.util.Base64.getDecoder().decode(argStr(a, 0)), Charsets.ISO_8859_1) }
        builtins["utf8toHex"] = NativeFn("utf8toHex") { a -> toHex(argStr(a, 0).toByteArray(Charsets.UTF_8)) }
        builtins["hexToUtf8"] = NativeFn("hexToUtf8") { a -> String(fromHex(argStr(a, 0)), Charsets.UTF_8) }
        builtins["toHex"] = NativeFn("toHex") { a -> toHex(argStr(a, 0).toByteArray(Charsets.UTF_8)) }
        builtins["fromHex"] = NativeFn("fromHex") { a -> String(fromHex(argStr(a, 0)), Charsets.ISO_8859_1) }
        builtins["charCodeAt"] = NativeFn("charCodeAt") { a -> argStr(a, 0).getOrNull(idxArg(a, 1))?.code ?: Double.NaN }
        builtins["fromCharCode"] = NativeFn("fromCharCode") { a -> a.map { numOf(it).toInt() }.map { Char(it) }.joinToString("") }
        builtins["parseInt"] = NativeFn("parseInt") { a ->
            if (a.size > 1) argStr(a, 0).trim().toIntOrNull(numOf(a.getOrNull(1)).toInt())?.toDouble()
            else argStr(a, 0).trim().toDoubleOrNull()
                ?: argStr(a, 0).trim().removePrefix("0x").toLongOrNull(16)?.toDouble()
        }
        builtins["parseFloat"] = NativeFn("parseFloat") { a -> argStr(a, 0).toDoubleOrNull() }
        builtins["Number"] = NativeFn("Number") { a -> if (a.isEmpty()) 0.0 else numOf(a[0]) }
        builtins["String"] = NativeFn("String") { a -> if (a.isEmpty()) "" else valueToText(a[0]) }
        builtins["isNaN"] = NativeFn("isNaN") { a -> a.isEmpty() || numOf(a[0]).isNaN() }
        builtins["Math"] = LinkedHashMap<String, Any?>(
            mapOf(
                "PI" to Math.PI,
                "floor" to NativeFn("floor") { a -> Math.floor(numOf(a.getOrNull(0))) },
                "ceil" to NativeFn("ceil") { a -> Math.ceil(numOf(a.getOrNull(0))) },
                "round" to NativeFn("round") { a -> Math.round(numOf(a.getOrNull(0))).toDouble() },
                "abs" to NativeFn("abs") { a -> Math.abs(numOf(a.getOrNull(0))) },
                "sqrt" to NativeFn("sqrt") { a -> Math.sqrt(numOf(a.getOrNull(0))) },
                "pow" to NativeFn("pow") { a -> Math.pow(numOf(a.getOrNull(0)), numOf(a.getOrNull(1))) },
                "max" to NativeFn("max") { a -> a.maxOfOrNull { numOf(it) } ?: Double.NaN },
                "min" to NativeFn("min") { a -> a.minOfOrNull { numOf(it) } ?: Double.NaN },
            ),
        )
    }

    fun eval(script: String): Any? {
        val tokens = Lexer(script).tokenize()
        val ast = Parser(tokens).parseAll()
        var result: Any? = null
        for (node in ast) {
            tick()
            result = evalNode(node, env())
        }
        return result
    }

    private fun env(): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m.putAll(builtins)
        m.putAll(vars)
        return m
    }

    private fun tick() {
        stepCount++
        if (stepCount > maxSteps) throw IllegalStateException("执行步数超上限 $maxSteps（疑似死循环，检查表达式）")
    }

    // ---------- 求值 ----------
    private fun evalNode(node: Node, e: Map<String, Any?>): Any? {
        tick()
        return when (node) {
            is Num -> if (node.isInt) node.i.toDouble() else node.d
            is Text -> node.v
            is Bool -> node.v
            is Null -> null
            is ArrayLit -> ArrayList(node.items.map { evalNode(it, e) })
            is ObjectLit -> LinkedHashMap(node.entries.associate { (k, n) -> k to evalNode(n, e) })
            is Ident -> when (node.name) {
                "undefined" -> null
                "NaN" -> Double.NaN
                else -> e[node.name]
            }
            is Unary -> unary(node, e)
            is Binary -> binary(node, e)
            is Ternary -> if (truthy(evalNode(node.cond, e))) evalNode(node.thenExpr, e) else evalNode(node.elseExpr, e)
            is Member -> evalMember(node, e)
            is Call -> call(node, e)
            is Paren -> evalNode(node.inner, e)
        }
    }

    private fun unary(node: Unary, e: Map<String, Any?>): Any? {
        val v = evalNode(node.expr, e)
        return when (node.op) {
            "-" -> -numOf(v)
            "!" -> !truthy(v)
            "~" -> numOf(v).toInt().inv().toDouble()
            else -> v
        }
    }

    private fun binary(node: Binary, e: Map<String, Any?>): Any? {
        val l = evalNode(node.left, e)
        when (node.op) {
            "&&" -> return if (!truthy(l)) l else evalNode(node.right, e)
            "||" -> return if (truthy(l)) l else evalNode(node.right, e)
        }
        val r = evalNode(node.right, e)
        return when (node.op) {
            "+" -> if (l is String || r is String) valueToText(l) + valueToText(r) else numOf(l) + numOf(r)
            "-" -> numOf(l) - numOf(r)
            "*" -> numOf(l) * numOf(r)
            "/" -> numOf(l) / numOf(r)
            "%" -> numOf(l) % numOf(r)
            "===", "==" -> looseEq(l, r)
            "!==", "!=" -> !looseEq(l, r)
            "<" -> numOf(l) < numOf(r)
            ">" -> numOf(l) > numOf(r)
            "<=" -> numOf(l) <= numOf(r)
            ">=" -> numOf(l) >= numOf(r)
            "&" -> numOf(l).toInt() and numOf(r).toInt()
            "|" -> numOf(l).toInt() or numOf(r).toInt()
            "^" -> numOf(l).toInt() xor numOf(r).toInt()
            "<<" -> numOf(l).toInt() shl (numOf(r).toInt() and 31)
            ">>" -> numOf(l).toInt() shr (numOf(r).toInt() and 31)
            "in" -> if (l is String) r is Map<*, *> && (r as Map<*, *>).containsKey(l) else false
            else -> throw IllegalStateException("不支持的运算符 ${node.op}")
        }
    }

    private fun evalMember(node: Member, e: Map<String, Any?>): Any? {
        val base = evalNode(node.obj, e) ?: return null
        if (node.prop is Ident && node.prop.name == "length") {
            return when (base) {
                is String -> base.length.toDouble()
                is List<*> -> base.size.toDouble()
                else -> null
            }
        }
        val key = propKey(node.prop, e) ?: return null
        return when (base) {
            is Map<*, *> -> base[key]
            is List<*> -> key.toIntOrNull()?.takeIf { it in base.indices }?.let { base[it] }
            is String -> stringMember(base, key)
            else -> null
        }
    }

    private fun stringMember(s: String, key: String): Any? = when (key) {
        "length" -> s.length.toDouble()
        "toUpperCase" -> NativeFn("toUpperCase") { s.uppercase() }
        "toLowerCase" -> NativeFn("toLowerCase") { s.lowercase() }
        "trim" -> NativeFn("trim") { s.trim() }
        "substring" -> NativeFn("substring") { a -> s.substring(idxArg(a, 0), if (a.size > 1) idxArg(a, 1) else s.length) }
        "substr" -> NativeFn("substr") { a -> val st = idxArg(a, 0); s.substring(st, mins(st + if (a.size > 1) idxArg(a, 1) else s.length - st, s.length)) }
        "indexOf" -> NativeFn("indexOf") { a -> s.indexOf(argStr(a, 0)).toDouble() }
        "charAt" -> NativeFn("charAt") { a -> s.getOrNull(idxArg(a, 0)).toString() }
        "charCodeAt" -> NativeFn("charCodeAt") { a -> s.getOrNull(idxArg(a, 0))?.code?.toDouble() ?: Double.NaN }
        "slice" -> NativeFn("slice") { a -> s.slice(idxArg(a, 0)..mins(if (a.size > 1) idxArg(a, 1) else s.length, s.length)) }
        "split" -> NativeFn("split") { a -> s.split(argStr(a, 0)).let { ArrayList(it) } }
        "replace" -> NativeFn("replace") { a -> s.replace(argStr(a, 0), argStr(a, 1)) }
        "concat" -> NativeFn("concat") { a -> s + a.joinToString("") { valueToText(it) } }
        else -> null
    }

    private fun call(node: Call, e: Map<String, Any?>): Any? {
        val callable = evalNode(node.callee, e) ?: return null
        val args = node.args.map { evalNode(it, e) }
        return when (callable) {
            is NativeFn -> callable.invoke(args)
            else -> null
        }
    }

    // ---------- 辅助 ----------
    private fun propKey(n: Node, e: Map<String, Any?>): String? = when (n) {
        is Ident -> n.name
        is Text -> n.v
        is Num -> if (n.isInt) "${n.i}" else "${n.d}"
        else -> valueToText(evalNode(n, e))?.let { strValue -> strValue }
    }

    private fun truthy(v: Any?): Boolean = when (v) {
        null -> false
        is Boolean -> v
        is Number -> v.toDouble() != 0.0
        is String -> v.isNotEmpty()
        else -> true
    }
    private fun numOf(v: Any?): Double = when (v) {
        is Number -> v.toDouble()
        is Boolean -> if (v) 1.0 else 0.0
        is String -> v.toDoubleOrNull() ?: 0.0
        else -> 0.0
    }
    private fun looseEq(l: Any?, r: Any?): Boolean {
        if (l == null && r == null) return true
        if (l == null || r == null) return false
        if (l is Number && r is Number) return numOf(l) == numOf(r)
        if (l is String && r is String) return l == r
        if (l is Boolean || r is Boolean) return truthy(l) == truthy(r)
        return "$l" == "$r"
    }

    private fun argStr(a: List<Any?>, i: Int): String = valueToText(a.getOrNull(i))
    private fun argNum(a: List<Any?>): Double = numOf(a.getOrNull(0))
    private fun idxArg(a: List<Any?>, i: Int): Int = numOf(a.getOrNull(i)).toInt().coerceAtLeast(0)
    private fun mins(a: Int, b: Int): Int = minOf(a, b)
    private fun toHex(b: ByteArray): String = b.joinToString("") { "%02x".format(it.toInt() and 0xff) }
    private fun fromHex(s: String): ByteArray {
        val cs = s.filterNot { it.isWhitespace() }
        if (cs.length % 2 != 0) throw IllegalArgumentException("hex 长度必须为偶数")
        return ByteArray(cs.length / 2) { i -> cs.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
    }
}

/** 内建函数包装 */
private class NativeFn(val name: String, private val f: (List<Any?>) -> Any?) {
    fun invoke(a: List<Any?>): Any? = f(a)
}

// ---------------- AST ----------------
private sealed class Node
private class Num(val d: Double, val isInt: Boolean = false, val i: Long = 0) : Node()
private class Text(val v: String) : Node()
private class Bool(val v: Boolean) : Node()
private class Null : Node()
private class Ident(val name: String) : Node()
private class Unary(val op: String, val expr: Node) : Node()
private class Binary(val op: String, val left: Node, val right: Node) : Node()
private class Ternary(val cond: Node, val thenExpr: Node, val elseExpr: Node) : Node()
private class Member(val obj: Node, val prop: Node) : Node()
private class Call(val callee: Node, val args: List<Node>) : Node()
private class ArrayLit(val items: List<Node>) : Node()
private class ObjectLit(val entries: List<Pair<String, Node>>) : Node()
private class Paren(val inner: Node) : Node()

// ---------------- 词法 ----------------
private class Lexer(private val src: String) {
    private var pos = 0
    fun tokenize(): List<Tok> {
        val out = ArrayList<Tok>()
        while (pos < src.length) {
            val c = src[pos]
            if (c.isWhitespace()) { pos++; continue }
            val two = if (pos + 1 < src.length) src.substring(pos, pos + 2) else ""
            when {
                two == "&&" || two == "||" || two == "==" || two == "!=" || two == "<=" || two == ">=" || two == "===" || two == "!==" || two == "<<" || two == ">>" -> { out.add(sym(two)); pos += 2 }
                c.isDigit() || (c == '.' && pos + 1 < src.length && src[pos + 1].isDigit()) -> out.add(number())
                c == '"' || c == '\'' -> out.add(string(c))
                isIdStart(c) -> out.add(word())
                "+-*/%!~&|^<>?:.,()[]{};".any { it == c } -> { out.add(sym(c.toString())); pos++ }
                else -> pos++ // 未知字符忽略
            }
        }
        out.add(sym("\u0000")) // EOF
        return out
    }
    private fun sym(s: String) = Tok(TokKind.SYM, s)
    private fun isIdStart(c: Char) = c.isLetter() || c == '_' || c == '$'
    private fun isIdPart(c: Char) = c.isLetterOrDigit() || c == '_' || c == '$'
    private fun number(): Tok {
        val st = pos
        while (pos < src.length && (src[pos].isDigit() || src[pos] == '.')) pos++
        val raw = src.substring(st, pos)
        return Tok(TokKind.NUM, raw)
    }
    private fun string(q: Char): Tok {
        val sb = StringBuilder(); pos++
        while (pos < src.length) {
            val c = src[pos]
            if (c == q) { pos++; break }
            if (c == '\\' && pos + 1 < src.length) {
                val n = src[pos + 1]
                when (n) {
                    'n' -> sb.append('\n'); 't' -> sb.append('\t'); 'r' -> sb.append('\r'); '\\' -> sb.append('\\')
                    '\'' -> sb.append('\''); '"' -> sb.append('"'); 'x' -> { if (pos + 3 < src.length) { sb.append(src.substring(pos + 2, pos + 4).toInt(16).toChar()); pos += 2 } }
                    'u' -> { if (pos + 5 < src.length) { sb.append(src.substring(pos + 2, pos + 6).toInt(16).toChar()); pos += 4 } }
                    else -> sb.append(n)
                }
                pos += 2
            } else { sb.append(c); pos++ }
        }
        return Tok(TokKind.STR, sb.toString())
    }
    private fun word(): Tok {
        val st = pos
        while (pos < src.length && isIdPart(src[pos])) pos++
        val w = src.substring(st, pos)
        return Tok(TokKind.ID, w)
    }
}
private enum class TokKind { NUM, STR, ID, SYM }
private class Tok(val kind: TokKind, val text: String)

// ---------------- 语法解析 ----------------
private class Parser(private val toks: List<Tok>) {
    private var i = 0
    private fun peek(): Tok = toks[i]
    private fun next(): Tok = toks[i++]
    private fun isSym(s: String) = peek().kind == TokKind.SYM && peek().text == s
    private fun eatSym(s: String): Boolean { if (isSym(s)) { i++; return true }; return false }

    fun parseAll(): List<Node> {
        val out = ArrayList<Node>()
        while (!isSym("\u0000")) out.add(expression())
        return out
    }

    fun expression(prec: Int = 0): Node {
        var left = primary()
        var p = precOf(peek())
        while (p > 0 && p >= prec) {
            if (prec > 0 && p < prec) break
            if (peek().text == "?") {
                i++ // '?'
                val t = expression(0); eatSym(":"); val f = expression(0)
                left = Ternary(left, t, f)
            } else {
                val op = next().text
                val right = expression(p + 1)
                left = Binary(op, left, right)
            }
            p = precOf(peek())
            if (isSym("\u0000")) break
        }
        return left
    }

    private fun primary(): Node {
        val t = next()
        return when (t.kind) {
            TokKind.NUM -> {
                val d = if (t.text.contains('.')) t.text.toDoubleOrNull() else null
                if (d != null) Num(d) else { when { t.text.toLongOrNull() != null -> Num(t.text.toLong().toDouble(), true, t.text.toLong()); else -> Num(t.text.toDoubleOrNull() ?: 0.0) } }
            }
            TokKind.STR -> primaryTail(Text(t.text))
            TokKind.ID -> when (t.text) {
                "true" -> primaryTail(Bool(true)); "false" -> primaryTail(Bool(false)); "null", "undefined" -> primaryTail(Null())
                else -> primaryTail(Ident(t.text))
            }
            TokKind.SYM -> when (t.text) {
                "(" -> regexpParen()
                "[" -> {
                    val items = ArrayList<Node>()
                    if (!eatSym("]")) { do { items.add(expression()) } while (eatSym(",") && !isSym("]")); eatSym("]") }
                    primaryTail(ArrayLit(items))
                }
                "{" -> {
                    val entries = ArrayList<Pair<String, Node>>()
                    if (!eatSym("}")) {
                        do {
                            val k = next()
                            val key = when (k.kind) { TokKind.ID, TokKind.STR -> k.text; else -> k.text }
                            eatSym(":"); entries.add(key to expression())
                        } while (eatSym(",") && !isSym("}"))
                        eatSym("}")
                    }
                    primaryTail(ObjectLit(entries))
                }
                "-", "!", "~" -> Unary(t.text, primary())
                else -> throw IllegalStateException("意外的符号 ${t.text}")
            }
        }
    }

    private fun regexpParen(): Node {
        // '(' 进入表达式，直到括号闭合
        val inner = expression()
        eatSym(")")
        return primaryTail(Paren(inner))
    }

    private fun primaryTail(n: Node): Node {
        var cur = n
        while (true) {
            if (isSym(".")) { i++; val prop = next(); cur = Member(cur, Ident(prop.text)) }
            else if (isSym("[")) { i++; val idx = expression(); eatSym("]"); cur = Member(cur, idx) }
            else if (isSym("(")) {
                i++
                val args = ArrayList<Node>()
                if (!isSym(")")) { do { args.add(expression()) } while (eatSym(",")) }
                eatSym(")")
                cur = Call(cur, args)
            } else break
        }
        return cur
    }

    private fun precOf(t: Tok): Int = if (t.kind == TokKind.SYM) when (t.text) {
        "||" -> 1; "&&" -> 2; "|" -> 3; "^" -> 4; "&" -> 5
        "==", "!=", "===", "!==" -> 6
        "<", ">", "<=", ">=" -> 7
        "<<", ">>" -> 8
        "+", "-" -> 9
        "*", "/", "%" -> 10
        "?" -> 2
        else -> 0
    } else 0
}