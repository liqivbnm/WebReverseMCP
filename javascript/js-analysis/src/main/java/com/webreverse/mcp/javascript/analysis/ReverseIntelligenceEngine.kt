package com.webreverse.mcp.javascript.analysis

/**
 * Reverse intelligence layer .
 *
 * This layer intentionally works on the raw source text and does not require a
 * successful AST build. It complements AST/SSA rather than competing with it:
 * - lexical recovery for partially-supported / mangled JS
 * - constant-string reconstruction (concat + template fragments)
 * - endpoint and auth/token sink recovery
 * - crypto / encoding / entropy pipeline hints
 * - JSVMP / WASM / anti-debug / bundler fingerprints
 * - evidence-weighted target ranking
 *
 * The output is deliberately evidence-centric. It never claims an algorithm is
 * "proven" from a single regex hit; the confidence is the strength of the
 * available evidence and the nextActions point to dynamic validation.
 */
class ReverseIntelligenceEngine {

    enum class Kind {
        ENDPOINT, TOKEN_SOURCE, TOKEN_SINK, CRYPTO_PIPELINE, WASM_BOUNDARY,
        JSVMP, ANTI_DEBUG, OBFUSCATION, BUNDLER, DYNAMIC_CODE, ENVIRONMENT,
        ENCODING, RANDOMNESS,
    }

    data class Evidence(
        val kind: String,
        val line: Int,
        val confidence: Double,
        val detail: String,
        val snippet: String = "",
    )

    data class Target(
        val kind: Kind,
        val name: String,
        val line: Int,
        val score: Double,
        val confidence: Double,
        val evidence: List<Evidence>,
        val nextActions: List<String>,
    )

    data class StringFact(
        val value: String,
        val line: Int,
        val expression: String,
        val decoded: Boolean,
    )

    data class Report(
        val ok: Boolean,
        val sourceChars: Int,
        val sourceLines: Int,
        val stringsRecovered: Int,
        val endpointsRecovered: Int,
        val tokenSignals: Int,
        val cryptoSignals: Int,
        val wasmSignals: Int,
        val jsvmpSignals: Int,
        val antiDebugSignals: Int,
        val bundlerSignals: Int,
        val targets: List<Target>,
        val strings: List<StringFact> = emptyList(),
        val pipelineHints: List<String> = emptyList(),
        val degradedParserRecovery: Boolean = false,
        val readiness: Double = 0.0,
        val warnings: List<String> = emptyList(),
    )

    private data class Literal(val raw: String, val decoded: String, val line: Int, val start: Int)

    private val endpointCall = Regex(
        """(?i)\b(fetch|axios\.(?:get|post|put|patch|delete|request)|(?:api|http|request)\.(?:get|post|put|patch|delete|request)|XMLHttpRequest\b)"""
    )
    private val httpUrl = Regex("""(?i)(?:https?|wss?)://[^\s'\"`<>\\)\\]]+""")
    private val pathUrl = Regex("""['\"]((?:/api(?:/|$)|/v\d+(?:/|$)|/graphql(?:/|$)|/(?:auth|login|logout|token|sign|signature|verify|user|account|config)(?:/|$))[^'\"`<>]{0,240})['\"]""", RegexOption.IGNORE_CASE)
    private val authName = Regex("""(?i)(?:authorization|access[-_]?token|refresh[-_]?token|id[_-]?token|bearer|csrf|xsrf|signature|sign|signdata|nonce|timestamp|api[-_]?key|appsecret|secret|session|cookie)""")
    private val cryptoCall = Regex("""(?i)\b(?:crypto\.subtle|CryptoJS|jsencrypt|jsrsasign|forge|sjcl|elliptic|tweetnacl|md5|sha(?:1|224|256|384|512)?|hmac|aes|des|3des|rc4|chacha20|salsa20|sm[234]|rsa|ecdh|ecdsa|pbkdf2|argon2)\b""")
    private val encodingCall = Regex("""(?i)\b(?:btoa|atob|encodeURI(?:Component)?|decodeURI(?:Component)?|TextEncoder|TextDecoder|Buffer\.from|base64|hex|charCodeAt|fromCharCode|unescape|escape)\b""")
    private val entropyCall = Regex("""(?i)\b(?:Math\.random|crypto\.getRandomValues|crypto\.randomUUID|Date\.now|performance\.now|new\s+Date)\b""")
    private val wasmCall = Regex("""(?i)\b(?:WebAssembly\.(?:instantiate|instantiateStreaming|compile|compileStreaming|Module|Instance)|WebAssembly|\.wasm\b|wasm[-_.]bindgen|__wbindgen)""")
    private val jsvmpCall = Regex("""(?i)\b(?:switch\s*\(.*\)|while\s*\([^)]*\+\+[^)]*\)|dispatch|opcode|bytecode|programCounter|pc\s*\+\+|stackPointer|handlerTable|case\s+0x[0-9a-f]+\s*:)""")
    private val antiDebugCall = Regex("""(?i)\b(?:debugger\b|console\.debug|console\.clear|devtools|disableDevtools|anti[-_]?debug|toString\s*\(\s*\)\s*\.match|Function\s*\(\s*['\"]debugger|setInterval\s*\([^)]*(?:debugger|devtools))""")
    private val dynamicCodeCall = Regex("""(?i)\b(?:eval|Function|setTimeout|setInterval)\s*\(""")
    private val bundlerCall = Regex("""(?i)(?:webpackChunk|webpackJsonp|__webpack_require__|__vite__mapDeps|import\.meta\.glob|vite/client|parcelRequire|System\.register|define\s*\(\s*\[\s*['\"]exports)""")
    private val envCall = Regex("""(?i)\b(?:navigator\.(?:userAgent|platform|language|languages|hardwareConcurrency|deviceMemory)|window\.(?:innerWidth|innerHeight|devicePixelRatio)|screen\.|location\.(?:host|hostname|href)|document\.cookie|localStorage\.|sessionStorage\.|indexedDB\.|performance\.)""")

    fun analyze(source: String, topN: Int = 60): Report {
        if (source.isBlank()) {
            return Report(false, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, emptyList(), readiness = 0.0, warnings = listOf("source 为空"))
        }

        val lines = source.count { it == '\n' } + 1
        val literals = scanLiterals(source)
        val recovered = LinkedHashMap<String, StringFact>()
        literals.forEach { lit ->
            val v = lit.decoded.trim()
            if (v.isNotEmpty() && v.length <= 4_096) {
                recovered.putIfAbsent("${lit.line}:$v", StringFact(v, lit.line, lit.raw, lit.raw != lit.decoded))
            }
        }
        recoverConstantConcats(source, recovered)

        val evidence = mutableListOf<Evidence>()
        val pipelineHints = LinkedHashSet<String>()
        fun lineOf(offset: Int): Int = source.substring(0, offset.coerceIn(0, source.length)).count { it == '\n' } + 1
        fun addRegex(regex: Regex, kind: String, confidence: Double, detailPrefix: String = "") {
            regex.findAll(source).take(800).forEach { m ->
                val line = lineOf(m.range.first)
                val snippet = context(source, m.range.first, 180)
                evidence += Evidence(kind, line, confidence, if (detailPrefix.isBlank()) m.value.take(160) else "$detailPrefix: ${m.value.take(120)}", snippet)
            }
        }

        addRegex(endpointCall, "network-call", 0.88, "HTTP sink")
        addRegex(httpUrl, "absolute-url", 0.92, "硬编码 URL")
        addRegex(pathUrl, "api-path", 0.82, "高价值 API path")
        addRegex(cryptoCall, "crypto-call", 0.78, "crypto/签名 API")
        addRegex(encodingCall, "encoding-call", 0.70, "编码/解码链")
        addRegex(entropyCall, "entropy", 0.76, "时钟/随机性输入")
        addRegex(wasmCall, "wasm", 0.92, "JS↔WASM 边界")
        addRegex(jsvmpCall, "jsvmp", 0.74, "解释器/dispatch 特征")
        addRegex(antiDebugCall, "anti-debug", 0.82, "反调试")
        addRegex(dynamicCodeCall, "dynamic-code", 0.84, "动态代码执行")
        addRegex(bundlerCall, "bundler", 0.78, "打包器 runtime")
        addRegex(envCall, "environment", 0.72, "浏览器环境读取")

        // Name/value signals: headers, params, object keys and common token variables.
        Regex("""(?i)\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]{1,500})""").findAll(source).take(2000).forEach { m ->
            val name = m.groupValues[1]
            val rhs = m.groupValues[2]
            val lower = "$name $rhs".lowercase()
            if (authName.containsMatchIn(name) || authName.containsMatchIn(rhs.take(220))) {
                val line = lineOf(m.range.first)
                evidence += Evidence("token-binding", line, 0.87, "$name = ${rhs.take(180)}", context(source, m.range.first, 220))
            }
            if (encodingCall.containsMatchIn(rhs) && (authName.containsMatchIn(name) || rhs.contains("fetch", true))) {
                pipelineHints += "$name: encoding/decoding + auth/network context"
            }
            if (cryptoCall.containsMatchIn(rhs) && (authName.containsMatchIn(name) || endpointNearby(source, m.range.first))) {
                pipelineHints += "$name: crypto result likely feeds request/signature"
            }
            if (lower.contains("toString") && lower.contains("16") && (authName.containsMatchIn(name) || endpointNearby(source, m.range.first))) {
                pipelineHints += "$name: hex-like serialization candidate"
            }
        }

        // Endpoint candidate extraction from calls and nearby string/constants.
        val endpointTargets = mutableListOf<Target>()
        endpointCall.findAll(source).take(600).forEach { m ->
            val start = m.range.first
            val window = source.substring(start, minOf(source.length, start + 1_200))
            val url = httpUrl.find(window)?.value
                ?: pathUrl.find(window)?.groupValues?.getOrNull(1)
                ?: findNamedConstantUrl(window, recovered)
            val method = inferMethod(m.value, window)
            val authNearby = authName.find(window)?.value
            val cryptoNearby = cryptoCall.find(window)?.value
            val score = (0.54 + (if (url != null) 0.20 else 0.0) + (if (authNearby != null) 0.14 else 0.0) + (if (cryptoNearby != null) 0.12 else 0.0)).coerceAtMost(1.0)
            val line = lineOf(start)
            val ev = mutableListOf(
                Evidence("network-call", line, 0.88, "HTTP sink: ${m.value}", context(source, start, 200))
            )
            if (url != null) ev += Evidence("endpoint", line, 0.91, "$method $url")
            if (authNearby != null) ev += Evidence("auth-context", line, 0.87, "附近命中 $authNearby")
            if (cryptoNearby != null) ev += Evidence("crypto-context", line, 0.82, "附近命中 $cryptoNearby")
            endpointTargets += Target(
                Kind.ENDPOINT,
                "$method ${url ?: "<dynamic-url>"}",
                line,
                score * 100.0,
                score,
                ev.distinctBy { "${it.kind}|${it.line}|${it.detail}" },
                listOf("定位 initiator/callsite", "追踪 URL 与 body/header 表达式", "使用 runtime capture + reverse.value_link 验证")
            )
        }

        // Token sources/sinks are intentionally separate: this distinction is useful
        // when a token is produced far away from the network call.
        val tokenTargets = mutableListOf<Target>()
        evidence.filter { it.kind == "token-binding" }.take(160).forEach { e ->
            val high = if (cryptoCall.containsMatchIn(e.detail)) 0.93 else 0.87
            tokenTargets += Target(
                Kind.TOKEN_SOURCE,
                e.detail.take(180),
                e.line,
                high * 100.0,
                high,
                listOf(e) + evidence.filter { it.line in (e.line - 3)..(e.line + 3) && it.kind in setOf("encoding-call", "entropy", "environment") }.take(4),
                listOf("追踪 RHS 输入来源", "寻找第一次进入 header/query/body 的 sink", "建立 browser runtime 值指纹")
            )
        }
        endpointTargets.filter { it.evidence.any { e -> e.kind == "auth-context" || e.kind == "crypto-context" } }.forEach { t ->
            tokenTargets += Target(
                Kind.TOKEN_SINK,
                "${t.name} ← auth/crypto context",
                t.line,
                (t.score + 8.0).coerceAtMost(100.0),
                (t.confidence + 0.05).coerceAtMost(0.99),
                t.evidence,
                listOf("追踪 header/query/body 实际值", "reverse.trace", "reverse.validate")
            )
        }

        val cryptoTargets = buildCryptoTargets(source, evidence, pipelineHints)
        val specialTargets = buildSpecialTargets(evidence)
        val targets = (endpointTargets + tokenTargets + cryptoTargets + specialTargets)
            .sortedWith(compareByDescending<Target> { it.score }.thenBy { it.line })
            .distinctBy { "${it.kind}|${it.line}|${it.name}" }
            .take(topN.coerceIn(1, 200))

        val endpointCount = endpointTargets.size
        val tokenCount = tokenTargets.size
        val cryptoCount = cryptoTargets.size
        val wasmCount = evidence.count { it.kind == "wasm" }
        val jsvmpCount = evidence.count { it.kind == "jsvmp" }
        val antiDebugCount = evidence.count { it.kind == "anti-debug" }
        val bundlerCount = evidence.count { it.kind == "bundler" }
        val dimensionCount = listOf(endpointCount, tokenCount, cryptoCount, wasmCount, jsvmpCount, antiDebugCount, bundlerCount).count { it > 0 }
        val diversity = (recovered.values.count { it.decoded && it.value.length >= 6 }.toDouble() / recovered.size.coerceAtLeast(1)).coerceIn(0.0, 1.0)
        val readiness = (0.42 + dimensionCount * 0.055 + diversity * 0.11 + minOf(targets.size, 20) * 0.006).coerceIn(0.0, 0.985)

        return Report(
            ok = true,
            sourceChars = source.length,
            sourceLines = lines,
            stringsRecovered = recovered.size,
            endpointsRecovered = endpointCount,
            tokenSignals = tokenCount,
            cryptoSignals = cryptoCount,
            wasmSignals = wasmCount,
            jsvmpSignals = jsvmpCount,
            antiDebugSignals = antiDebugCount,
            bundlerSignals = bundlerCount,
            targets = targets,
            strings = recovered.values.sortedWith(compareBy({ it.line }, { it.value })).take(500),
            pipelineHints = pipelineHints.take(100),
            degradedParserRecovery = false,
            readiness = readiness,
            warnings = buildWarnings(source, evidence),
        )
    }

    private fun buildCryptoTargets(source: String, evidence: List<Evidence>, hints: Set<String>): List<Target> {
        val out = mutableListOf<Target>()
        val crypto = evidence.filter { it.kind == "crypto-call" }
        crypto.take(180).forEach { e ->
            val nearby = evidence.filter { it.line in (e.line - 6)..(e.line + 6) }
            val enc = nearby.count { it.kind == "encoding-call" }
            val entropy = nearby.count { it.kind == "entropy" }
            val network = nearby.any { it.kind == "network-call" || it.kind == "api-path" || it.kind == "absolute-url" }
            val score = (0.72 + enc * 0.05 + entropy * 0.04 + if (network) 0.10 else 0.0).coerceAtMost(0.98)
            val algorithm = classifyCryptoWindow(source, e.line)
            out += Target(
                Kind.CRYPTO_PIPELINE,
                algorithm,
                e.line,
                score * 100.0,
                score,
                nearby.filter { it.kind in setOf("crypto-call", "encoding-call", "entropy", "network-call", "token-binding") }.take(8),
                listOf("向上追踪明文输入", "确认 key/iv/nonce 生命周期", "捕获真实输出并做 differential validation")
            )
        }
        if (hints.isNotEmpty() && out.isNotEmpty()) {
            out += Target(
                Kind.ENCODING,
                "encoding/crypto pipeline hints",
                out.first().line,
                91.0,
                0.91,
                hints.take(6).map { Evidence("pipeline", out.first().line, 0.84, it) },
                listOf("将编码层与 crypto layer 拆开验证", "避免把 base64/hex 当作加密算法")
            )
        }
        return out
    }

    private fun buildSpecialTargets(evidence: List<Evidence>): List<Target> {
        val out = mutableListOf<Target>()
        fun one(kind: Kind, evidenceKind: String, score: Double, action: List<String>) {
            evidence.filter { it.kind == evidenceKind }.take(80).forEach { e ->
                out += Target(kind, e.detail.take(180), e.line, score * 100.0, score, listOf(e), action)
            }
        }
        one(Kind.WASM_BOUNDARY, "wasm", 0.93, listOf("识别 export/import boundary", "做 memory provenance", "追踪 ptr/len -> input/output"))
        one(Kind.JSVMP, "jsvmp", 0.79, listOf("执行 vmp.verify", "恢复 opcode->handler ISA", "把 runtime trace 与 handler 对齐"))
        one(Kind.ANTI_DEBUG, "anti-debug", 0.84, listOf("隔离 anti-debug side effects", "优先使用 script rewrite/回放", "记录是否改变算法输入"))
        one(Kind.DYNAMIC_CODE, "dynamic-code", 0.86, listOf("捕获 eval/Function 的最终字符串", "对生成代码再跑 AST/SSA", "建立生成代码与原调用点的 provenance"))
        one(Kind.BUNDLER, "bundler", 0.78, listOf("解析 chunk/module 边界", "优先回溯 import/export", "按 module 而不是文件全文做 diff"))
        one(Kind.ENVIRONMENT, "environment", 0.70, listOf("建立最小 browser shim", "记录环境值是否进入签名/token", "做 environment differential"))
        one(Kind.RANDOMNESS, "entropy", 0.76, listOf("记录 seed/timestamp/randomness", "判断是否是 nonce/anti-replay 输入", "固定/扰动样本做差分"))
        return out
    }

    private fun classifyCryptoWindow(source: String, line: Int): String {
        val ls = source.split('\n')
        val from = (line - 7).coerceAtLeast(1)
        val to = (line + 7).coerceAtMost(ls.size)
        val text = ls.subList(from - 1, to).joinToString(" ").lowercase()
        val names = listOf(
            "AES-GCM" to listOf("aes-gcm"),
            "AES-CBC" to listOf("aes-cbc"),
            "ChaCha20" to listOf("chacha20", "chacha"),
            "SM3" to listOf("sm3"),
            "SM4" to listOf("sm4"),
            "SHA-256/HMAC" to listOf("sha-256", "sha256", "hmac"),
            "RSA" to listOf("rsa", "rsassa", "rsa-oaep"),
            "ECDSA/ECDH" to listOf("ecdsa", "ecdh"),
            "MD5" to listOf("md5"),
            "CRC32" to listOf("crc32"),
            "Custom bitwise cipher" to listOf(">>>", "<<", "^", "Math.imul"),
        )
        return names.firstOrNull { (_, keys) -> keys.any { text.contains(it) } }?.first ?: "Crypto/signature candidate"
    }

    private fun findNamedConstantUrl(window: String, recovered: Map<String, StringFact>): String? {
        val identifiers = Regex("""\b[A-Za-z_$][A-Za-z0-9_$]{0,80}\b""").findAll(window).map { it.value }.toSet()
        for (id in identifiers) {
            val hit = recovered.values.firstOrNull { it.expression.contains(Regex("""\b${Regex.escape(id)}\b""")) && (it.value.startsWith("/") || it.value.startsWith("http")) }
            if (hit != null) return hit.value
        }
        return recovered.values.firstOrNull { it.value.startsWith("/") || it.value.startsWith("http") }?.value
    }

    private fun inferMethod(callee: String, window: String): String = when {
        Regex("""(?i)\bpost\b""").containsMatchIn(callee + " " + window.take(180)) -> "POST"
        Regex("""(?i)\bput\b""").containsMatchIn(callee + " " + window.take(180)) -> "PUT"
        Regex("""(?i)\bpatch\b""").containsMatchIn(callee + " " + window.take(180)) -> "PATCH"
        Regex("""(?i)\bdelete\b""").containsMatchIn(callee + " " + window.take(180)) -> "DELETE"
        else -> "GET"
    }

    private fun endpointNearby(source: String, offset: Int): Boolean {
        val from = (offset - 700).coerceAtLeast(0)
        val to = (offset + 700).coerceAtMost(source.length)
        return endpointCall.containsMatchIn(source.substring(from, to)) || pathUrl.containsMatchIn(source.substring(from, to))
    }

    private fun context(source: String, offset: Int, width: Int): String {
        val start = (offset - width / 2).coerceAtLeast(0)
        val end = (offset + width / 2).coerceAtMost(source.length)
        return source.substring(start, end).replace('\n', ' ').replace(Regex("\\s+"), " ").take(width)
    }

    private fun buildWarnings(source: String, evidence: List<Evidence>): List<String> {
        val out = mutableListOf<String>()
        if (source.length > 2_000_000) out += "超大脚本：建议按 chunk/module 切片后再做深度 SSA/taint"
        if (evidence.count { it.kind == "dynamic-code" } > 3) out += "存在多处动态代码：静态结果可能不完整，应捕获生成后的代码再分析"
        if (evidence.count { it.kind == "anti-debug" } > 0) out += "检测到 anti-debug：runtime capture 结果可能被污染，需要隔离/重写"
        if (evidence.count { it.kind == "wasm" } > 0) out += "存在 WASM：JS 侧仅是边界，算法核心需继续做 memory/function provenance"
        return out.take(12)
    }

    private fun recoverConstantConcats(source: String, out: MutableMap<String, StringFact>) {
        val env = LinkedHashMap<String, String>()
        val assignments = Regex("""(?m)\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*([^;\n]{1,1000})""")
        repeat(4) {
            assignments.findAll(source).forEach { m ->
                val value = resolveStringExpression(m.groupValues[2], env) ?: return@forEach
                env[m.groupValues[1]] = value
                val line = source.substring(0, m.range.first).count { it == '\n' } + 1
                if (value.length in 2..4096 && (value.startsWith("/") || value.startsWith("http") || value.length > 8)) {
                    out.putIfAbsent("const:$line:${m.groupValues[1]}", StringFact(value, line, "${m.groupValues[1]} = ${m.groupValues[2].trim()}", true))
                }
            }
        }
    }

    private fun resolveStringExpression(expr: String, env: Map<String, String>): String? {
        val pieces = splitPlus(expr)
        if (pieces.size <= 1 && !isStringLiteral(expr.trim()) && !env.containsKey(expr.trim())) return null
        val out = StringBuilder()
        for (p in pieces) {
            val t = p.trim()
            val literal = decodeLiteral(t)
            val part = when {
                literal != null -> literal
                env.containsKey(t) -> env[t]
                t.matches(Regex("""^[A-Za-z_$][A-Za-z0-9_$]*$""")) -> return null
                else -> return null
            }
            out.append(part)
            if (out.length > 4096) return null
        }
        return out.toString()
    }

    private fun splitPlus(expr: String): List<String> {
        val out = mutableListOf<String>()
        var start = 0
        var quote: Char? = null
        var escaped = false
        var depth = 0
        for (i in expr.indices) {
            val c = expr[i]
            if (quote != null) {
                if (escaped) escaped = false
                else if (c == '\\') escaped = true
                else if (c == quote) quote = null
                continue
            }
            when (c) {
                '\'', '"', '`' -> quote = c
                '(', '[', '{' -> depth++
                ')', ']', '}' -> depth = (depth - 1).coerceAtLeast(0)
                '+' -> if (depth == 0) { out += expr.substring(start, i); start = i + 1 }
            }
        }
        out += expr.substring(start)
        return out.map { it.trim() }.filter { it.isNotEmpty() }
    }

    private fun isStringLiteral(text: String): Boolean = text.length >= 2 && ((text.first() == '\'' && text.last() == '\'') || (text.first() == '"' && text.last() == '"') || (text.first() == '`' && text.last() == '`'))

    private fun decodeLiteral(text: String): String? {
        if (!isStringLiteral(text)) return null
        val quote = text.first()
        val body = text.substring(1, text.length - 1)
        if (quote == '`' && Regex("""\$\{""").containsMatchIn(body)) return body.replace(Regex("""\$\{[^}]+}"""), "{expr}")
        return decodeEscapes(body)
    }

    private fun scanLiterals(source: String): List<Literal> {
        val out = mutableListOf<Literal>()
        var i = 0
        var line = 1
        while (i < source.length) {
            val c = source[i]
            if (c == '\n') { line++; i++; continue }
            if (c.isWhitespace()) { i++; continue }
            if (c == '/' && i + 1 < source.length && source[i + 1] == '/') {
                i += 2; while (i < source.length && source[i] != '\n') i++; continue
            }
            if (c == '/' && i + 1 < source.length && source[i + 1] == '*') {
                i += 2
                while (i + 1 < source.length && !(source[i] == '*' && source[i + 1] == '/')) { if (source[i] == '\n') line++; i++ }
                i = (i + 2).coerceAtMost(source.length); continue
            }
            if (c == '\'' || c == '"' || c == '`') {
                val start = i
                val quote = c
                i++
                val sb = StringBuilder()
                var escaped = false
                while (i < source.length) {
                    val ch = source[i]
                    if (escaped) {
                        sb.append('\\').append(ch)
                        escaped = false
                        i++
                        continue
                    }
                    if (ch == '\\') { escaped = true; i++; continue }
                    if (ch == quote) break
                    if (ch == '\n') line++
                    sb.append(ch)
                    i++
                }
                if (i < source.length) i++
                val raw = source.substring(start, i)
                val decoded = decodeEscapes(sb.toString())
                out += Literal(raw, decoded, line, start)
                continue
            }
            i++
        }
        return out
    }

    private fun decodeEscapes(value: String): String {
        var s = value
        s = Regex("""\\u\{([0-9a-fA-F]{1,6})}""").replace(s) { m -> codePoint(m.groupValues[1]) }
        s = Regex("""\\u([0-9a-fA-F]{4})""").replace(s) { m -> codePoint(m.groupValues[1]) }
        s = Regex("""\\x([0-9a-fA-F]{2})""").replace(s) { m -> codePoint(m.groupValues[1]) }
        val map = mapOf("\\n" to "\n", "\\r" to "\r", "\\t" to "\t", "\\b" to "\b", "\\f" to "\u000C", "\\v" to "\u000B")
        map.forEach { (k, v) -> s = s.replace(k, v) }
        s = s.replace("\\'", "'").replace("\\\"", "\"").replace("\\`", "`").replace("\\\\", "\\")
        return s
    }

    private fun codePoint(hex: String): String = runCatching { String(Character.toChars(hex.toInt(16))) }.getOrDefault("�")
}
