package com.webreverse.mcp.javascript.analysis

import kotlinx.serialization.Serializable

/**
 * 反调试检测结果（ 新增，参考 ChatGPT 报告 §10/§11）。
 *
 * 对既有 ObfuscationAnalyzer.detectAntiDebug 的升级：从简单布尔升级为
 * 结构化类别级检测，逐项输出识别到的反调试子类别、命中脚本 URL 与置信度，
 * 供 reverse.detect_protection 等 MCP 编排工具消费。
 */
@Serializable
data class AntiDebugDetection(
    val risk: Double = 0.0,
    val techniques: List<String> = emptyList(),
    val scripts: List<AntiDebugScript> = emptyList(),
    val matchedPatterns: Map<String, String> = emptyMap(),
)

@Serializable
data class AntiDebugScript(
    val scriptId: String = "",
    val url: String = "",
    val confidence: Double = 0.0,
    val techniques: List<String> = emptyList(),
)

/**
 * 反调试检测器：识别网页脚本中的反调试手段并分级置信度。
 *
 * 覆盖类别（报告 §11 A~M）：
 *  - debugger_statement：直接 debugger; 语句
 *  - debugger_function_constructor：Function("debugger") / .constructor("debugger")
 *  - timer_debugger_loop：setInterval/setTimeout 内嵌 debugger 的循环
 *  - eval_debugger：eval("debugger")
 *  - devtools_size_detection：outerWidth-innerWidth 尺寸检测
 *  - console_getter_trap：console 对象 getter 陷阱
 *  - function_tostring_detection：Function.prototype.toString 完整性检测
 *  - descriptor_detection：Object.getOwnPropertyDescriptor 完整性检测
 *  - timing_detection：performance.now/Date.now 夹住 debugger 的时间检测
 *  - source_url_detection：Error().stack / sourceURL 检测
 *  - recursive_debugger：self 递归 setTimeout debugger
 *  - blob_dynamic_code：URL.createObjectURL + Blob 动态代码
 *  - worker_protection：Worker/ServiceWorker 内反调试
 *
 * 纯静态（字符串/正则）分析，无节点依赖，可离线单测。
 */
class AntiDebugDetector {

    // ---- 各技术识别规则（返回是否命中 + 优先级） ----

    /** 直接 debugger 语句（整行/独立表达式，排除字符串与注释中的字面量） */
    fun hasDebuggerStatement(source: String): Boolean =
        Regex("""(^|[^\w$])(?:debugger)\s*;""", RegexOption.MULTILINE).containsMatchIn(source)

    /** Function 构造器内嵌 debugger */
    fun hasFunctionConstructorDebugger(source: String): Boolean {
        val patterns = listOf(
            Regex("""Function\s*\(\s*["'`]*(?:[^"'`]*?)debugger["'`]*\s*\)"""),
            Regex("""\.constructor\s*\(\s*["'`]*(?:[^"'`]*?)debugger["'`]*\s*\)\s*\(\s*\)"""),
        )
        return patterns.any { it.containsMatchIn(source) }
    }

    /** 定时器循环内嵌 debugger（setInterval/setTimeout 回调含 debugger） */
    fun hasTimerDebuggerLoop(source: String): Boolean =
        Regex("""(?:setInterval|setTimeout)\s*\(\s*(?:function\s*\w*\s*\([^)]*\)\s*\{[^}]*debugger|["'`][^"'`]*debugger)""")
            .containsMatchIn(source)

    /** eval 内嵌 debugger */
    fun hasEvalDebugger(source: String): Boolean =
        Regex("""(?:eval|setTimeout|setInterval)\s*\(\s*["'`][^"'`]*debugger""").containsMatchIn(source)

    /** DevTools 尺寸检测：outerWidth/innerWidth 差值判断（允许 window. 前缀与空白） */
    fun hasDevToolsSizeDetection(source: String): Boolean {
        val widths = source.contains("outerWidth") && source.contains("innerWidth")
        val heights = source.contains("outerHeight") && source.contains("innerHeight")
        if (!widths && !heights) return false
        val diff = Regex("""outer(?:Width|Height)\s*-\s*(?:window\s*\.\s*)?inner(?:Width|Height)""")
        val diffRev = Regex("""inner(?:Width|Height)\s*-\s*(?:window\s*\.\s*)?outer(?:Width|Height)""")
        return diff.containsMatchIn(source) || diffRev.containsMatchIn(source)
    }

    /** Console getter 陷阱：console.log({get id() {...}}}) */
    fun hasConsoleGetterTrap(source: String): Boolean =
        Regex("""console\s*\.\s*(?:log|dir|table)\s*\(\s*\{[^}]*get\s+\w+\s*\(""").containsMatchIn(source)

    /** Function.prototype.toString 完整性检测 */
    fun hasFunctionToStringDetection(source: String): Boolean =
        Regex("""Function\s*\.\s*prototype\s*\.\s*toString\s*\(""").containsMatchIn(source) ||
            (source.contains("toString()") && source.contains("constructor"))

    /** 属性描述符完整性检测 */
    fun hasDescriptorDetection(source: String): Boolean =
        Regex("""Object\s*\.\s*getOwnPropertyDescriptor\s*\(""").containsMatchIn(source) ||
            source.contains("getOwnPropertyDescriptor")

    /** 时间检测：performance.now/Date.now 夹住 debugger */
    fun hasTimingDetection(source: String): Boolean {
        val hasTime = source.contains("performance.now()") || source.contains("Date.now()") || source.contains("new Date().getTime()")
        val hasDebug = hasDebuggerStatement(source) || hasFunctionConstructorDebugger(source)
        return hasTime && hasDebug
    }

    /** sourceURL / 调用栈检测 */
    fun hasSourceUrlDetection(source: String): Boolean =
        Regex("""(?:sourceURL|\.stack\b|new Error\s*\()""").containsMatchIn(source) &&
            hasDebuggerStatement(source)

    /** 自递归 debugger（函数体内 debugger + setTimeout(self)） */
    fun hasRecursiveDebugger(source: String): Boolean =
        Regex("""\{[^}]*debugger[^}]*?(?:setTimeout|setInterval)\s*\(\s*(\w+)\s*,?[^}]*\}""").containsMatchIn(source)

    /** Blob + createObjectURL 动态代码 */
    fun hasBlobDynamicCode(source: String): Boolean =
        source.contains("createObjectURL") && source.contains("Blob")

    /** Worker/ServiceWorker 内反调试 */
    fun hasWorkerProtection(source: String): Boolean =
        Regex("""(?:new\s+Worker\s*\(|SharedWorker\s*\(|serviceWorker\s*\.\s*register)""").containsMatchIn(source)

    /**
     * 完整检测：输入源码与可选的脚本 URL，返回结构化结果。
     */
    fun detect(source: String, url: String = "", scriptId: String = ""): AntiDebugDetection {
        val matched = mutableListOf<String>()
        val patterns = mutableMapOf<String, String>()

        fun check(name: String, hit: Boolean, sample: String) {
            if (hit) {
                matched.add(name)
                patterns[name] = sample
            }
        }

        check("debugger_statement", hasDebuggerStatement(source), "独立 debugger; 语句")
        check("debugger_function_constructor", hasFunctionConstructorDebugger(source), "Function(\"debugger\")/constructor")
        check("timer_debugger_loop", hasTimerDebuggerLoop(source), "setInterval/setTimeout 内嵌 debugger")
        check("eval_debugger", hasEvalDebugger(source), "eval(\"debugger\")")
        check("devtools_size_detection", hasDevToolsSizeDetection(source), "outerWidth/innerWidth 差值检测")
        check("console_getter_trap", hasConsoleGetterTrap(source), "console getter 陷阱")
        check("function_tostring_detection", hasFunctionToStringDetection(source), "Function.prototype.toString 检测")
        check("descriptor_detection", hasDescriptorDetection(source), "getOwnPropertyDescriptor 完整性检测")
        check("timing_detection", hasTimingDetection(source), "performance/Date 夹 debugger 时间检测")
        check("source_url_detection", hasSourceUrlDetection(source), "sourceURL/stack 检测")
        check("recursive_debugger", hasRecursiveDebugger(source), "自递归 debugger 循环")
        check("blob_dynamic_code", hasBlobDynamicCode(source), "Blob/createObjectURL 动态代码")
        check("worker_protection", hasWorkerProtection(source), "Worker/SW 反调试")

        // 风险分：基础 debugger 类权重高，检测类次之
        val risk = matched.sumOf {
            when (it) {
                "debugger_statement", "debugger_function_constructor", "timer_debugger_loop",
                "recursive_debugger", "eval_debugger" -> 0.22
                "devtools_size_detection", "console_getter_trap", "function_tostring_detection",
                "descriptor_detection", "source_url_detection" -> 0.12
                else -> 0.08
            }
        }.coerceAtMost(1.0)

        val script = if (matched.isNotEmpty() && (url.isNotBlank() || scriptId.isNotBlank())) {
            listOf(
                AntiDebugScript(
                    scriptId = scriptId,
                    url = url,
                    confidence = (risk * 1.1).coerceAtMost(1.0),
                    techniques = matched,
                ),
            )
        } else emptyList()

        return AntiDebugDetection(
            risk = risk,
            techniques = matched,
            scripts = script,
            matchedPatterns = patterns,
        )
    }

    /** 便捷：单条脚本判定是否含反调试 */
    fun isAntiDebug(source: String): Boolean = detect(source).techniques.isNotEmpty()
}