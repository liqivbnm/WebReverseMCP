package com.webreverse.mcp.javascript.analysis

import com.webreverse.mcp.core.common.model.NetworkEntry
import java.net.URI

/**
 * Generic web-reversing target profiler.
 *
 * It deliberately avoids site-specific signatures. The output is a capability
 * vector that helps an agent choose the next investigation path from evidence:
 * page source + observed network + lightweight runtime facts.
 */
class UniversalTargetProfiler {
    enum class Kind {
        API_CLIENT, AUTHENTICATION, TOKEN, CRYPTO_SIGNATURE, ENCODING,
        GRAPHQL, WEBSOCKET, EVENT_STREAM, GRPC, WASM, JSVMP, ANTI_DEBUG,
        DYNAMIC_CODE, WORKER, SERVICE_WORKER, STORAGE, ENVIRONMENT,
        BUNDLER, SOURCE_MAP, OBFUSCATION, SERIALIZATION, CAPTCHA_CHALLENGE,
        FILE_UPLOAD, MEDIA_PIPELINE,
    }

    data class Signal(
        val kind: Kind,
        val score: Double,
        val confidence: Double,
        val evidence: List<String>,
        val nextActions: List<String>,
    )

    data class Profile(
        val version: String = "1.0",
        val detected: List<Signal>,
        val primaryTracks: List<Kind>,
        val blindSpots: List<String>,
        val coverage: Double,
        val environment: Map<String, String>,
        val recommendedTools: List<String>,
    )

    fun profile(
        source: String,
        network: List<NetworkEntry> = emptyList(),
        runtimeJson: String = "",
    ): Profile {
        val src = source
        val signals = mutableListOf<Signal>()
        fun add(kind: Kind, score: Double, confidence: Double, vararg evidence: String, actions: List<String>) {
            if (evidence.any { it.isNotBlank() }) signals += Signal(kind, score.coerceIn(0.0, 100.0), confidence.coerceIn(0.0, 1.0), evidence.filter { it.isNotBlank() }.take(6), actions.take(5))
        }

        val apiCount = Regex("""(?i)\b(fetch|axios\.|XMLHttpRequest|\.open\s*\(|\.send\s*\()""").findAll(src).count()
        val networkApis = network.count { it.resourceType.name == "XHR" || it.resourceType.name == "FETCH" || it.method.name != "GET" }
        if (apiCount > 0 || networkApis > 0) add(Kind.API_CLIENT, (35 + apiCount.coerceAtMost(20) * 2 + networkApis.coerceAtMost(20) * 1.5), 0.91, "JS HTTP callsites=$apiCount", "observed XHR/Fetch=${networkApis}", actions = listOf("network.recon", "network.initiator", "reverse.page_triage"))

        val auth = Regex("""(?i)authorization|bearer|access[_-]?token|refresh[_-]?token|csrf|xsrf|session|cookie|api[_-]?key|appsecret|signature|nonce|timestamp""")
        val authHits = auth.findAll(src).count() + network.sumOf { (it.requestHeaders.keys + it.queryParams.keys).count(auth::containsMatchIn) }
        if (authHits > 0) add(Kind.AUTHENTICATION, (30 + authHits.coerceAtMost(30) * 1.7), 0.92, "auth-related symbols/headers=$authHits", actions = listOf("reverse.analyze_source", "reverse.value_link", "reverse.causality"))
        if (Regex("""(?i)access[_-]?token|refresh[_-]?token|id[_-]?token|authorization|bearer|csrf|xsrf""").containsMatchIn(src)) add(Kind.TOKEN, 58.0, 0.88, "token variable/header vocabulary", actions = listOf("reverse.signature_candidates", "reverse.trace", "reverse.validate"))

        val crypto = Regex("""(?i)crypto\.subtle|CryptoJS|jsencrypt|jsrsasign|forge|tweetnacl|hmac|sha(?:1|224|256|384|512)?|aes|des|chacha20|salsa20|sm2|sm3|sm4|rsa|ecdh|ecdsa|pbkdf2|md5""")
        val cryptoHits = crypto.findAll(src).count()
        if (cryptoHits > 0) add(Kind.CRYPTO_SIGNATURE, (45 + cryptoHits.coerceAtMost(30) * 1.8), 0.93, "crypto/signature symbols=$cryptoHits", actions = listOf("reverse.signature_candidates", "reverse.trace", "reverse.validate", "wasm.recognize_crypto"))
        val enc = Regex("""(?i)btoa|atob|TextEncoder|TextDecoder|base64|charCodeAt|fromCharCode|hex|encodeURIComponent|decodeURIComponent|Buffer\.from""").findAll(src).count()
        if (enc > 0) add(Kind.ENCODING, (25 + enc.coerceAtMost(20) * 2.0), 0.82, "encoding primitives=$enc", actions = listOf("reverse.intelligence", "reverse.value_link", "reverse.validate"))

        if (Regex("""(?i)graphql|/graphql\b|apollo|urql""").containsMatchIn(src) || network.any { it.url.contains("graphql", true) }) add(Kind.GRAPHQL, 86.0, 0.95, "GraphQL vocabulary/endpoint", actions = listOf("network.recon", "reverse.analyze_source", "reverse.validate"))
        if (Regex("""(?i)WebSocket|new\s+WebSocket|wss://""").containsMatchIn(src) || network.any { it.resourceType.name == "WEBSOCKET" || it.url.startsWith("ws", true) }) add(Kind.WEBSOCKET, 84.0, 0.96, "WebSocket usage/observed WS", actions = listOf("event.wait", "network.websocket", "network.cdp_ws_analyze", "network.cdp_ws_connections", "reverse.causality"))
        if (Regex("""(?i)EventSource|text/event-stream|event-source""").containsMatchIn(src) || network.any { it.resourceType.name == "EVENTSOURCE" || it.mimeType.contains("text/event-stream", true) }) add(Kind.EVENT_STREAM, 78.0, 0.93, "SSE/EventSource", actions = listOf("network.recon", "event.wait", "network.cdp_sse_messages", "reverse.trace"))
        // gRPC 识别（Content-Type: application/grpc 或源码中的 grpc 调用标记）——
        // gRPC 走 HTTP/2 二进制通道，识别后引导用 network.cdp_requests 定位并解析 protobuf 帧
        if (Regex("""(?i)application/grpc|grpc-web|grpc\.Client|@grpc/|grpc_tools|grpc-js""").containsMatchIn(src) || network.any { it.mimeType.contains("application/grpc", true) }) add(Kind.GRPC, 80.0, 0.90, "gRPC/grpc-web endpoint", actions = listOf("network.attach_cdp", "network.cdp_requests", "network.get_response_body", "reverse.validate"))

        val wasm = Regex("""(?i)WebAssembly|\.wasm\b|wasm[-_.]bindgen|__wbindgen""").findAll(src).count()
        if (wasm > 0 || network.any { it.url.endsWith(".wasm", true) }) add(Kind.WASM, (60 + wasm.coerceAtMost(20) * 2.0), 0.96, "WASM boundary hits=$wasm", actions = listOf("wasm.dump_module", "wasm.disassemble_func", "reverse.wasm_provenance", "reverse.js_wasm_provenance_chain"))

        val jsvmp = Regex("""(?i)dispatcher|dispatchTable|opcode|bytecode|programCounter|stackPointer|handlerTable|\bcase\s+0x[0-9a-f]+\s*:""").findAll(src).count()
        if (jsvmp >= 2) add(Kind.JSVMP, (40 + jsvmp.coerceAtMost(30) * 2.0), 0.83, "VM-like dispatcher markers=$jsvmp", actions = listOf("vmp.verify", "reverse.jsvmp_vm_ssa", "reverse.trace"))

        val anti = Regex("""(?i)\bdebugger\b|devtools|disableDevtools|console\.(clear|debug)|toString\s*\(.*match|Function\s*\(\s*['"]debugger""").findAll(src).count()
        if (anti > 0) add(Kind.ANTI_DEBUG, (35 + anti.coerceAtMost(25) * 2.2), 0.90, "anti-debug markers=$anti", actions = listOf("reverse.detect_protection", "reverse.intercept_debugger", "reverse.trace"))

        val dynamic = Regex("""(?i)\beval\s*\(|new\s+Function\s*\(|\bFunction\s*\(|setTimeout\s*\([^,]+,""").findAll(src).count()
        if (dynamic > 0) add(Kind.DYNAMIC_CODE, (36 + dynamic.coerceAtMost(20) * 2.4), 0.90, "dynamic-code callsites=$dynamic", actions = listOf("capture generated code", "reverse.intelligence", "reverse.analyze_source"))

        if (Regex("""(?i)new\s+(Worker|SharedWorker)|importScripts\(|navigator\.serviceWorker|serviceWorker\.register""").containsMatchIn(src)) add(Kind.WORKER, 70.0, 0.92, "worker/service-worker references", actions = listOf("worker.list", "worker.sources", "reverse.worker_dataflow"))
        if (Regex("""(?i)navigator\.serviceWorker|serviceWorker\.register""").containsMatchIn(src)) add(Kind.SERVICE_WORKER, 80.0, 0.95, "service-worker registration/control", actions = listOf("worker.inspect", "storage.service_workers", "reverse.worker_dataflow"))
        if (Regex("""(?i)localStorage|sessionStorage|indexedDB|document\.cookie|CacheStorage|caches\.""").containsMatchIn(src)) add(Kind.STORAGE, 62.0, 0.90, "browser storage/cookie APIs", actions = listOf("storage.cookies", "storage.local", "storage.indexeddb", "reverse.value_link"))
        if (Regex("""(?i)navigator\.|screen\.|devicePixelRatio|hardwareConcurrency|userAgent|webdriver|canvas|WebGLRenderingContext|AudioContext""").containsMatchIn(src)) add(Kind.ENVIRONMENT, 60.0, 0.82, "browser fingerprint/environment reads", actions = listOf("reverse.capture_environment", "reverse.run_environment", "reverse.infer_environment"))

        val bundler = Regex("""(?i)__webpack_require__|webpackChunk|webpackJsonp|vite/client|__vite__mapDeps|parcelRequire|System\.register|import\.meta\.glob""").findAll(src).count()
        if (bundler > 0) add(Kind.BUNDLER, (45 + bundler.coerceAtMost(20) * 2.0), 0.93, "bundler runtime markers=$bundler", actions = listOf("parse.imports_exports", "reverse.intelligence", "source-map.inspect"))
        if (Regex("""(?i)# sourceMappingURL=|sourceMappingURL=|webpack://|\.map(?:[?#]|$)""").containsMatchIn(src) || network.any { it.url.endsWith(".map", true) }) add(Kind.SOURCE_MAP, 72.0, 0.90, "source-map reference/asset", actions = listOf("source-map.inspect", "debugger.list_scripts", "reverse.analyze_source"))
        if (Regex("""(?i)_0x[a-f0-9]{3,}|while\s*\(!!\[\]\)|array\s+of\s+strings|control\s*flow\s*flatten""").containsMatchIn(src)) add(Kind.OBFUSCATION, 68.0, 0.80, "obfuscation-style identifiers/control flow", actions = listOf("static.quality", "reverse.intelligence", "reverse.analyze_source"))
        if (Regex("""(?i)protobuf|msgpack|messagepack|cbor|avro|bson|serialize|deserialize|TextEncoder|ArrayBuffer\b""").containsMatchIn(src)) add(Kind.SERIALIZATION, 54.0, 0.78, "binary/structured serialization markers", actions = listOf("reverse.intelligence", "reverse.validate", "network.recon"))
        if (Regex("""(?i)captcha|recaptcha|hcaptcha|turnstile|challenge|pow|proof[-_ ]of[-_ ]work""").containsMatchIn(src)) add(Kind.CAPTCHA_CHALLENGE, 73.0, 0.87, "challenge/PoW/CAPTCHA vocabulary", actions = listOf("reverse.analyze_source", "reverse.trace", "reverse.validate"))
        if (Regex("""(?i)FormData|multipart/form-data|upload|ArrayBuffer|Blob|FileReader|\.files\b""").containsMatchIn(src)) add(Kind.FILE_UPLOAD, 47.0, 0.76, "file/multipart APIs", actions = listOf("network.recon", "reverse.causality", "reverse.validate"))
        if (Regex("""(?i)<video|MediaSource|SourceBuffer|HLS|DASH|m3u8|mpd|MediaRecorder|RTCPeerConnection""").containsMatchIn(src) || network.any { it.url.contains("m3u8", true) || it.url.contains(".mpd", true) }) add(Kind.MEDIA_PIPELINE, 48.0, 0.78, "media/streaming APIs", actions = listOf("network.recon", "event.wait", "reverse.causality"))

        val observedKinds = signals.sortedByDescending { it.score }
        val primary = observedKinds.take(6).map { it.kind }
        val blindSpots = buildBlindSpots(observedKinds, source, network, runtimeJson)
        val environment = mapOf(
            "networkEntries" to network.size.toString(),
            "scriptChars" to source.length.toString(),
            "runtimePresent" to runtimeJson.isNotBlank().toString(),
            "requestDomains" to network.mapNotNull { runCatching { URI(it.url).host }.getOrNull() }.distinct().size.toString(),
            "websocketObserved" to network.count { it.resourceType.name == "WEBSOCKET" }.toString(),
        )
        val coverage = coverageScore(observedKinds, source, network, runtimeJson)
        val tools = linkedSetOf<String>().apply {
            add("reverse.page_triage")
            add("reverse.intelligence")
            observedKinds.take(8).flatMap { it.nextActions }.forEach { add(it) }
            add("reverse.quality_gate")
            add("reverse.validate")
        }.take(20)
        return Profile(detected = observedKinds.take(20), primaryTracks = primary, blindSpots = blindSpots, coverage = coverage, environment = environment, recommendedTools = tools)
    }

    private fun coverageScore(signals: List<Signal>, source: String, network: List<NetworkEntry>, runtime: String): Double {
        var score = 15.0
        if (source.isNotBlank()) score += 25
        if (signals.any { it.kind == Kind.API_CLIENT }) score += 15
        if (network.isNotEmpty()) score += 15
        if (runtime.isNotBlank()) score += 10
        if (signals.any { it.kind == Kind.CRYPTO_SIGNATURE || it.kind == Kind.WASM || it.kind == Kind.JSVMP }) score += 8
        if (signals.any { it.kind == Kind.SOURCE_MAP || it.kind == Kind.BUNDLER }) score += 5
        if (signals.any { it.kind == Kind.WORKER || it.kind == Kind.SERVICE_WORKER }) score += 4
        return score.coerceIn(0.0, 100.0)
    }

    private fun buildBlindSpots(signals: List<Signal>, source: String, network: List<NetworkEntry>, runtime: String): List<String> {
        val kinds = signals.map { it.kind }.toSet()
        val out = mutableListOf<String>()
        if (source.isBlank()) out += "缺少脚本源码：无法进行可靠静态/混淆/crypto/JSVMP 分析"
        if (network.isEmpty()) out += "尚无真实网络样本：接口与签名链只能做静态推断"
        if (runtime.isBlank()) out += "缺少运行时环境快照：无法确认环境分支与动态生成值"
        if (Kind.API_CLIENT in kinds && network.none { it.initiatorStack.isNotBlank() }) out += "缺少 request→initiator stack：调用链尚未闭合"
        if ((Kind.CRYPTO_SIGNATURE in kinds || Kind.TOKEN in kinds) && network.none { it.requestHeaders.isNotEmpty() || it.requestBody != null }) out += "缺少完整请求头/Body：token/signature 尚未与真实 sink 对齐"
        if (Kind.WASM in kinds && !source.contains("memory", true)) out += "WASM 边界已发现，但 linear-memory provenance 尚未形成"
        if (Kind.JSVMP in kinds && !signals.any { it.kind == Kind.DYNAMIC_CODE }) out += "疑似 VM/dispatcher，但尚未捕获 opcode handler 的运行时证据"
        if (Kind.SOURCE_MAP !in kinds && source.isNotBlank()) out += "尚未确认 source-map：压缩/打包代码可能仍未映射到原始模块"
        return out.distinct().take(10)
    }
}
