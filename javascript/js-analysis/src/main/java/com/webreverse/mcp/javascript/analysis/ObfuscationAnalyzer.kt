package com.webreverse.mcp.javascript.analysis

import com.webreverse.mcp.javascript.parser.JsParser
import kotlinx.serialization.Serializable

/** 混淆检测结果 */
@Serializable
data class ObfuscationReport(
    val score: Int = 0,
    val isObfuscated: Boolean = false,
    val isMinified: Boolean = false,
    val detected: List<String> = emptyList(),
    val details: Map<String, String> = emptyMap(),
    val entropy: Double = 0.0,
    val identifierCount: Int = 0,
    val stringArrayCount: Int = 0,
    val controlFlowFlattening: Boolean = false,
    val antiDebug: Boolean = false,
    val dynamicCode: Boolean = false,
    val selfIntegrityCheck: Boolean = false,
    val environmentDetection: Boolean = false,
)

/** 混淆检测器 */
class ObfuscationAnalyzer(private val parser: JsParser = JsParser()) {

    fun analyze(source: String): ObfuscationReport {
        val detected = mutableListOf<String>()
        var score = 0

        val isMinified = parser.isMinified(source)
        if (isMinified) {
            detected.add("Minified Code")
            score += 10
        }

        // 标识符熵
        val identifiers = parser.extractIdentifiers(source)
        val entropy = calculateEntropy(identifiers)
        if (entropy > 3.5) {
            detected.add("High Identifier Entropy")
            score += 15
        }

        // 短标识符（变量重命名）
        val shortIdentifiers = identifiers.count { it.length <= 2 }
        if (identifiers.isNotEmpty() && shortIdentifiers.toDouble() / identifiers.size > 0.5) {
            detected.add("Variable Renaming (short identifiers)")
            score += 10
        }

        // 字符串数组编码
        val strings = parser.extractStrings(source)
        val stringArrayCount = strings.count { it.length > 4 && it.all { c -> c.isLetterOrDigit() } }
        if (stringArrayCount > 20) {
            detected.add("String Array Encoding")
            score += 20
        }

        // 控制流平坦化
        val controlFlowFlattening = detectControlFlowFlattening(source)
        if (controlFlowFlattening) {
            detected.add("Control Flow Flattening")
            score += 20
        }

        // 死代码
        val deadCode = detectDeadCode(source)
        if (deadCode) {
            detected.add("Dead Code Injection")
            score += 5
        }

        // 反调试
        val antiDebug = detectAntiDebug(source)
        if (antiDebug) {
            detected.add("Anti Debug")
            score += 15
        }

        // 环境检测
        val environmentDetection = detectEnvironmentDetection(source)
        if (environmentDetection) {
            detected.add("Environment Detection")
            score += 5
        }

        // 动态代码
        val dynamicCode = detectDynamicCode(source)
        if (dynamicCode) {
            detected.add("Dynamic Code Generation")
            score += 15
        }

        // 自完整性检查
        val selfIntegrityCheck = detectSelfIntegrityCheck(source)
        if (selfIntegrityCheck) {
            detected.add("Self Integrity Check")
            score += 10
        }

        // 反调试：DevTools 检测
        val devToolsDetection = detectDevToolsDetection(source)
        if (devToolsDetection) {
            detected.add("DevTools Detection")
            score += 10
        }

        // 时间检测
        val timeDetection = detectTimeDetection(source)
        if (timeDetection) {
            detected.add("Time-based Detection")
            score += 5
        }

        // Function.toString 检测
        val functionToString = source.contains("Function.prototype.toString") ||
            source.contains(".toString.call(") ||
            source.contains("constructor.toString")
        if (functionToString) {
            detected.add("Function.toString Detection")
            score += 10
        }

        // Proxy / Reflect
        val proxy = source.contains("new Proxy(")
        val reflect = source.contains("Reflect.")
        if (proxy || reflect) {
            detected.add("Proxy/Reflect Usage")
            score += 5
        }

        // WebAssembly
        val wasm = source.contains("WebAssembly.instantiate") || source.contains("WebAssembly.compile")
        if (wasm) {
            detected.add("WebAssembly Usage")
            score += 5
        }

        // JSVMP / 虚拟机保护（VM 派发循环三形态，路由到 jsvmp.* 工具链）
        val jsvmp = detectJsvmp(source)
        if (jsvmp) {
            detected.add("JSVMP / VM Protection")
            score += 25
        }

        // 字符串数组 + 解码器三件套（javascript-obfuscator 标准布局，路由到 static.decrypt_*）
        val stringArray = detectStringArrayDecoder(source)
        if (stringArray) {
            detected.add("String Array + Decoder")
            score += 15
        }

        // Base64 / Hex 编码字符串（算法还原高频中间态）
        val encodedStrings = detectEncodedStrings(source)
        if (encodedStrings) {
            detected.add("Base64/Hex Encoded Strings")
            score += 8
        }

        // RC4 / 自研加密特征（charCodeAt 异或链 + 大数组）
        val customCrypto = detectCustomCrypto(source)
        if (customCrypto) {
            detected.add("Custom Crypto (RC4-like)")
            score += 10
        }

        score = score.coerceIn(0, 100)

        return ObfuscationReport(
            score = score,
            isObfuscated = score >= 40,
            isMinified = isMinified,
            detected = detected,
            entropy = entropy,
            identifierCount = identifiers.size,
            stringArrayCount = stringArrayCount,
            controlFlowFlattening = controlFlowFlattening,
            antiDebug = antiDebug,
            dynamicCode = dynamicCode,
            selfIntegrityCheck = selfIntegrityCheck,
            environmentDetection = environmentDetection,
        )
    }

    private fun calculateEntropy(identifiers: List<String>): Double {
        if (identifiers.isEmpty()) return 0.0
        val charCounts = HashMap<Char, Int>()
        identifiers.forEach { id -> id.forEach { c -> charCounts[c] = (charCounts[c] ?: 0) + 1 } }
        val total = charCounts.values.sum().toDouble()
        return -charCounts.values.sumOf { count ->
            val p = count / total
            p * (Math.log(p) / Math.log(2.0))
        }
    }

    private fun detectControlFlowFlattening(source: String): Boolean {
        // 检测 while(true) + switch 模式
        val hasWhileTrue = source.contains("while(true)") || source.contains("while (true)")
        val hasSwitch = source.contains("switch(") || source.contains("switch (")
        val hasCase = Regex("""case\s+0x[0-9a-fA-F]+:""").containsMatchIn(source)
        return (hasWhileTrue && hasSwitch) || (hasCase && hasSwitch)
    }

    private fun detectDeadCode(source: String): Boolean {
        // 检测不可达代码特征：大量随机字符串、无意义表达式
        val randomStrings = Regex("""["'][A-Za-z0-9]{40,}["']""").findAll(source).count()
        return randomStrings > 5
    }

    private fun detectAntiDebug(source: String): Boolean {
        return source.contains("debugger") &&
            (source.contains("setInterval") || source.contains("setTimeout")) ||
            source.contains("Function('debugger'") ||
            source.contains("constructor('debugger'")
    }

    private fun detectEnvironmentDetection(source: String): Boolean {
        return source.contains("navigator.userAgent") ||
            source.contains("navigator.platform") ||
            source.contains("navigator.language") ||
            source.contains("screen.width") ||
            source.contains("window.chrome") ||
            source.contains("navigator.webdriver")
    }

    private fun detectDynamicCode(source: String): Boolean {
        return source.contains("eval(") ||
            source.contains("new Function(") ||
            source.contains("Function(") ||
            source.contains("setTimeout(\"") ||
            source.contains("setInterval(\"") ||
            source.contains("document.write(")
    }

    private fun detectSelfIntegrityCheck(source: String): Boolean {
        return source.contains("toString()") && source.contains("constructor") ||
            source.contains("Function.prototype.toString")
    }

    private fun detectDevToolsDetection(source: String): Boolean {
        return source.contains("window.outerWidth") ||
            source.contains("window.outerHeight") ||
            source.contains("console.log") && source.contains("debugger") ||
            source.contains("devtools")
    }

    private fun detectTimeDetection(source: String): Boolean {
        return source.contains("Date.now()") && source.contains("performance.now()") ||
            source.contains("new Date().getTime()")
    }

    // ---------------- ：算法还原路由增强 ----------------

    /** JSVMP 检测：VM 派发循环三形态（switch / if-tree / array-of-handlers） */
    private fun detectJsvmp(source: String): Boolean {
        val hasWhileTrue = Regex("""while\s*\(\s*(!!?\s*[]\d]|1\b|true\b)|for\s*\(\s*;;\s*\)""").containsMatchIn(source)
        if (!hasWhileTrue) return false
        val hasSwitch = Regex("""\bswitch\s*\(""").containsMatchIn(source)
        val hexCases = Regex("""case\s+0x[0-9a-fA-F]{1,6}\s*:""").findAll(source).count()
        if (hasSwitch && hexCases >= 8) return true
        // if/else-if 比较链（decision-tree 派发）
        val treeConsts = Regex("""(?:===|==)\s*(0x[0-9a-fA-F]{1,6}|\d{1,6})\s*\)""").findAll(source).count()
        if (treeConsts >= 10) return true
        // 数组派发：handler 数组 + 索引调用
        val arrayDispatch = Regex(
            """(?:var|let|const)\s+[A-Za-z_$][\w$]{0,20}\s*=\s*\[[^\]]{200,}\]""",
        ).containsMatchIn(source) &&
            Regex("""[A-Za-z_$][\w$]{0,20}\s*\[\s*[A-Za-z_$][\w$]{0,20}\s*\[\s*[A-Za-z_$][\w$]{0,20}\s*(?:\+\+)?\s*\]\s*\]\s*\(\s*\)""").containsMatchIn(source)
        return arrayDispatch
    }

    /** 字符串数组 + 解码器三件套：大数组 + 解码函数 + 调用点 */
    private fun detectStringArrayDecoder(source: String): Boolean {
        val bigArray = Regex("""(?:var|let|const)\s+[A-Za-z_$][\w$]{0,20}\s*=\s*\[[^\]]{400,}\]""").containsMatchIn(source)
        if (!bigArray) return false
        val decoderCall = Regex("""[A-Za-z_$][\w$]{2,}\s*\(\s*['"](?:0x[0-9a-fA-F]{1,6}|\d{1,5})['"]\s*\)""").containsMatchIn(source)
        val hasFromCharCode = source.contains("fromCharCode")
        val hasShift = Regex("""\.shift\s*\(\s*\)""").containsMatchIn(source)
        return decoderCall && (hasFromCharCode || hasShift)
    }

    /** Base64 / Hex 编码字符串密度 */
    private fun detectEncodedStrings(source: String): Boolean {
        val base64 = Regex("""['"][A-Za-z0-9+/]{24,}={0,2}['"]""").findAll(source).count()
        val hex = Regex("""['"][0-9a-fA-F]{32,}['"]""").findAll(source).count()
        return base64 >= 3 || hex >= 3
    }

    /** RC4 / 自研加密：charCodeAt 异或链 + 大数组 + 循环 */
    private fun detectCustomCrypto(source: String): Boolean {
        val hasCharCode = source.contains("charCodeAt")
        val hasXor = Regex("""\^\s*(0x[0-9a-fA-F]{1,4}|\d{1,5})""").containsMatchIn(source)
        val hasFromCharCode = source.contains("fromCharCode")
        val hasLoop = Regex("""for\s*\([^)]{0,60}i\s*[<<=]""").containsMatchIn(source) ||
            Regex("""while\s*\(""").containsMatchIn(source)
        return hasCharCode && hasXor && hasFromCharCode && hasLoop
    }
}
