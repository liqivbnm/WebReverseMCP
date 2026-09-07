package com.webreverse.mcp.mcp.prompts

import com.webreverse.mcp.core.mcp.McpPrompt
import com.webreverse.mcp.core.mcp.PromptArgument
import com.webreverse.mcp.core.mcp.PromptContent
import com.webreverse.mcp.core.mcp.PromptMessage
import com.webreverse.mcp.core.mcp.PromptResult

/**
 * 内置 MCP Prompts：为 AI Agent 提供标准化的逆向分析工作流模板。
 */
object Prompts {

    fun all(): List<McpPrompt> = listOf(
        analyzePage(),
        analyzeJavaScript(),
        analyzeNetwork(),
        analyzeLoginFlow(),
        analyzeApi(),
        analyzeObfuscation(),
        analyzeJsvmp(),
        analyzeWasmCrypto(),
        findFunction(),
        traceFunction(),
        traceRequest(),
        debugJavaScript(),
        inspectDom(),
        analyzeStorage(),
        generateReverseEngineeringReport(),
        evidenceWorkflow(),
    )

    /* * ：证据驱动逆向工作流（流水线编排） */
    private fun evidenceWorkflow() = prompt(
        "evidence_workflow",
        "证据驱动逆向工作流：用流水线编排代替逐个调工具，图谱沉淀全部发现（推荐起点）",
        listOf(PromptArgument("goal", "逆向目标（如：还原登录接口的签名算法）", true)),
    ) { args ->
        val goal = args["goal"] ?: ""
        PromptResult(
            description = "证据驱动逆向工作流",
            messages = listOf(
                user(
                    """
                    逆向目标：$goal

                    请按证据驱动工作流执行（结果自动汇入证据库与图谱，跨工具可查）：
                    1. pipeline.run name=recon —— 页面全景侦察（框架/端点/脚本/存储入图谱）
                    2. 根据目标选择深挖链路：
                       - 接口逆向 → pipeline.run name=api_trace urlPattern=<接口关键词>
                       - 令牌溯源 → pipeline.run name=token_trace
                       - 签名定位 → hook.add type=crypto 安装加密拦截后触发目标行为，再 pipeline.run name=crypto_link
                    3. 验证现场：debugger.set_breakpoint 断点命中后 pipeline.run name=snapshot 抓运行时现场
                    4. 过程中随时 evidence.query 查证据、graph.query node=<key> 查链路、graph.stats 看全景
                    5. 阶段性结论用 evidence.record 记录，重要发现已自动写入工作区 Finding
                    最终输出：目标链路还原报告（图谱路径：谁 调用/生成/签名了 什么），并给出未闭合的疑点。
                    """.trimIndent(),
                ),
            ),
        )
    }

    private fun analyzePage() = prompt(
        "analyze_page",
        "分析当前页面：URL、DOM、框架、脚本、API 与安全概况",
        listOf(PromptArgument("url", "目标 URL", false)),
    ) { args ->
        val url = args["url"] ?: ""
        PromptResult(
            description = "分析当前页面",
            messages = listOf(
                user(
                    """
                    请对当前页面进行完整分析${if (url.isNotBlank()) "（目标：$url）" else ""}：
                    1. 读取 browser://current-page 获取 URL/标题
                    2. 调用 page.framework_detect 检测框架
                    3. 调用 page.api_list 提取页面 API
                    4. 调用 page.script_list 列出脚本
                    5. 调用 page.security 检查安全配置
                    6. 调用 page.environment 分析运行环境
                    输出结构化分析报告，包含：技术栈、API 清单、脚本清单、安全风险、可疑点。
                    """.trimIndent(),
                ),
            ),
        )
    }

    private fun analyzeJavaScript() = prompt(
        "analyze_javascript",
        "分析页面 JavaScript：AST、混淆、格式化、字符串与 URL 提取",
        listOf(PromptArgument("source", "JS 源码或 URL", true)),
    ) { args ->
        val source = args["source"] ?: ""
        PromptResult(
            description = "分析 JavaScript 代码",
            messages = listOf(
                user(
                    """
                    请分析以下 JavaScript 代码：
                    $source
                    1. 调用 js.parse_ast 解析 AST
                    2. 调用 js.detect_obfuscation 检测混淆
                    3. 调用 js.beautify 格式化
                    4. 调用 js.extract_strings 提取字符串
                    5. 调用 js.extract_urls 提取 URL
                    6. 调用 re.find_api / re.find_fetch / re.find_crypto 搜索关键 API
                    输出：混淆评分、检测到的混淆技术、API 调用清单、可疑代码位置。
                    """.trimIndent(),
                ),
            ),
        )
    }

    private fun analyzeNetwork() = prompt(
        "analyze_network",
        "分析网络流量：请求、响应、时序、调用链与敏感接口",
        listOf(PromptArgument("filter", "过滤条件（URL/方法/状态）", false)),
    ) { args ->
        val filter = args["filter"] ?: ""
        PromptResult(
            description = "分析网络流量",
            messages = listOf(
                user(
                    """
                    请分析当前页面的网络流量${if (filter.isNotBlank()) "（过滤：$filter）" else ""}：
                    1. 调用 network.list 获取请求列表
                    2. 调用 network.search 搜索关键接口
                    3. 调用 network.initiator 分析调用链
                    4. 调用 re.find_sensitive_api 找出敏感接口
                    5. 调用 re.trace_network 追踪请求链路
                    输出：API 清单、请求-响应摘要、调用链、敏感接口风险提示。
                    """.trimIndent(),
                ),
            ),
        )
    }

    private fun analyzeLoginFlow() = prompt(
        "analyze_login_flow",
        "分析登录流程：UI -> 事件 -> 校验 -> Token -> 请求 -> 存储",
        listOf(PromptArgument("url", "登录页 URL", false)),
    ) { args ->
        val url = args["url"] ?: ""
        PromptResult(
            description = "分析登录流程",
            messages = listOf(
                user(
                    """
                    请分析登录流程${if (url.isNotBlank()) "（登录页：$url）" else ""}：
                    1. 获取当前 URL 与 DOM
                    2. 调用 dom.query 找到登录按钮/表单
                    3. 分析事件监听（onclick/submit）
                    4. 调用 re.find_login_flow 查找登录相关函数
                    5. 调用 re.find_token 定位 Token 生成位置
                    6. 调用 re.find_auth_flow 分析认证流程
                    7. 设置 network 监听并捕获登录请求
                    8. 分析请求调用栈与 Token 生成
                    输出 Login Flow Graph：UI -> Event Handler -> Validation -> Token Generator -> Request Builder -> fetch() -> POST /api/login -> Response -> Storage。
                    """.trimIndent(),
                ),
            ),
        )
    }

    private fun analyzeApi() = prompt(
        "analyze_api",
        "分析 API：端点、方法、参数、认证与调用方",
        listOf(PromptArgument("endpoint", "API 端点（可选）", false)),
    ) { args ->
        val endpoint = args["endpoint"] ?: ""
        PromptResult(
            description = "分析 API",
            messages = listOf(
                user(
                    """
                    请分析页面 API${if (endpoint.isNotBlank()) "（重点：$endpoint）" else ""}：
                    1. 调用 re.find_api 提取全部 API 端点
                    2. 调用 re.find_endpoints 补充端点
                    3. 分析每个 API 的 Method / Headers / Query / Body
                    4. 调用 re.trace_function 追踪调用方函数
                    5. 分析认证方式与敏感参数
                    输出 API Inventory：Endpoint / Source / Caller / Request / Response / Related Function。
                    """.trimIndent(),
                ),
            ),
        )
    }

    private fun analyzeObfuscation() = prompt(
        "analyze_obfuscation",
        "分析 JS 混淆：评分、技术识别与反调试检测",
        listOf(PromptArgument("source", "JS 源码或 URL", true)),
    ) { args ->
        val source = args["source"] ?: ""
        PromptResult(
            description = "分析 JavaScript 混淆",
            messages = listOf(
                user(
                    """
                    请分析以下 JS 的混淆程度：
                    $source
                    1. 调用 js.detect_obfuscation 计算混淆评分
                    2. 调用 re.detect_obfuscator 识别混淆工具
                    3. 检测字符串数组、控制流平坦化、反调试、完整性检查
                    4. 调用 js.extract_strings 尝试提取原始字符串
                    输出：Obfuscation Score、Detected 技术列表、反调试手段、可读性评估。
                    """.trimIndent(),
                ),
            ),
        )
    }

    /* * ：JSVMP 算法还原工作流提示词 */
    private fun analyzeJsvmp() = prompt(
        "analyze_jsvmp",
        "JSVMP 算法还原：定位派发循环 -> 采样 trace -> 重建 ISA -> 反编译伪代码",
        listOf(PromptArgument("source", "JS 源码或 URL（含 VM 的脚本）", true)),
    ) { args ->
        val source = args["source"] ?: ""
        PromptResult(
            description = "JSVMP 算法还原",
            messages = listOf(
                user(
                    """
                    请对以下 JSVMP（JS 虚拟机保护）代码做算法还原：
                    $source

                    按此流水线执行（静态优先，动态补充）：
                    1. debugger.detect_vmp 定位派发循环（while+switch / if-tree 两种形态都会输出 line+column）
                    2. debugger.trace_vmp + get_vmp_trace 采样运行时 opcode 序列（零暂停，先触发目标行为再采集）
                    3. jsvmp.analyze 深度分析：handler 语义分类 + VM 状态变量识别（pc/sp/ctx/字节码数组）+ 指令流提取
                    4. jsvmp.handlers 看 opcode->语义 ISA 表；对低置信 handler 用 jsvmp.validate 喂运行时 (a,b,out) 样本自动裁决
                    5. jsvmp.decompile 反编译字节码载体为伪代码（若提示运行时解密，改用 jsvmp.trace_decompile 走运行时 trace）
                    6. 有基线对比需求时 debugger.diff_vmp_trace 隔离目标动作独有的 opcode 区段（最快定位签名算法路径）
                    7. 用 jsvmp.resolve_vpc 重建控制流（静态 pc 变量未识别时）
                    输出：VM ISA 表 + 反编译伪代码 + 目标算法在伪代码中的位置（pc 区间）+ 未闭合疑点。
                    """.trimIndent(),
                ),
            ),
        )
    }

    /* * ：WASM 加密算法识别工作流提示词 */
    private fun analyzeWasmCrypto() = prompt(
        "analyze_wasm_crypto",
        "WASM 加密算法识别：模块清单 -> 算法识别 -> 反汇编 -> 内存验证",
        listOf(PromptArgument("moduleIndex", "WASM 模块序号（可选，默认全部）", false)),
    ) { args ->
        val moduleIndex = args["moduleIndex"] ?: ""
        PromptResult(
            description = "WASM 加密算法识别",
            messages = listOf(
                user(
                    """
                    请识别页面 WASM 模块中的加密算法${if (moduleIndex.isNotBlank()) "（模块序号：$moduleIndex）" else ""}：

                    按此流水线执行：
                    1. wasm.list_modules 列出已捕获的 WASM 模块（体积/来源/imports/exports）
                    2. wasm.dump_module 解析模块结构：函数签名/name section/加密热点函数（cryptoHotspots）
                    3. wasm.recognize_crypto 算法识别：常量指纹 + 指令模式 + 算法级 Identification
                       （支持 AES/SHA-1/SHA-256/SHA-512/MD5/SM3/SM4/ChaCha20/Salsa20/xxHash/MurmurHash/TEA/XTEA/SipHash/DES/CRC32/Base64/HMAC）
                    4. 对高置信算法函数 wasm.disassemble_func 反汇编伪代码（按导出名或函数索引）
                    5. wasm.cfg_ssa 做基本块/SSA 视图，确认轮函数结构与常量表
                    6. wasm.inspect_memory 定位明文输入/密文输出偏移，验证算法输入输出
                    7. 需要改常量/密钥时 wasm.write_memory 打补丁后重放观察
                    输出：识别出的算法清单（含置信度与函数定位）、关键函数伪代码、算法输入输出内存偏移、还原结论。
                    """.trimIndent(),
                ),
            ),
        )
    }

    private fun findFunction() = prompt(
        "find_function",
        "查找函数：按名称/关键字在页面源码中定位",
        listOf(PromptArgument("keyword", "函数名或关键字", true)),
    ) { args ->
        val keyword = args["keyword"] ?: ""
        PromptResult(
            description = "查找函数",
            messages = listOf(
                user(
                    """
                    请在页面源码中查找与 "$keyword" 相关的函数：
                    1. 调用 js.search_source 搜索源码
                    2. 调用 js.find_function 定位函数定义
                    3. 调用 js.find_symbol 查找符号
                    4. 分析函数调用关系与调用方
                    输出：函数定义位置、调用方、参数、返回值、相关代码片段。
                    """.trimIndent(),
                ),
            ),
        )
    }

    private fun traceFunction() = prompt(
        "trace_function",
        "追踪函数调用链：DOM -> 事件 -> 函数 -> 网络",
        listOf(PromptArgument("function", "目标函数名", true)),
    ) { args ->
        val function = args["function"] ?: ""
        PromptResult(
            description = "追踪函数调用链",
            messages = listOf(
                user(
                    """
                    请追踪函数 "$function" 的完整调用链：
                    1. 调用 re.trace_function 追踪函数
                    2. 调用 re.trace_dom 分析 DOM 绑定
                    3. 调用 re.trace_event 分析事件触发
                    4. 调用 re.trace_network 分析网络调用
                    5. 设置断点观察运行时行为
                    输出调用关系图：button#id -> onclick -> $function -> ... -> fetch()。
                    """.trimIndent(),
                ),
            ),
        )
    }

    private fun traceRequest() = prompt(
        "trace_request",
        "追踪请求：从网络请求回溯到前端代码",
        listOf(PromptArgument("url", "请求 URL 关键字", true)),
    ) { args ->
        val url = args["url"] ?: ""
        PromptResult(
            description = "追踪网络请求",
            messages = listOf(
                user(
                    """
                    请追踪包含 "$url" 的网络请求：
                    1. 调用 network.search 找到请求
                    2. 调用 network.initiator 获取发起者
                    3. 调用 re.trace_network 回溯调用链
                    4. 调用 js.search_source 定位前端代码
                    5. 分析请求构造函数与参数来源
                    输出：Network -> Caller -> Function -> DOM 的完整链路。
                    """.trimIndent(),
                ),
            ),
        )
    }

    private fun debugJavaScript() = prompt(
        "debug_javascript",
        "调试 JavaScript：设置断点、观察变量、逐步执行",
        listOf(PromptArgument("function", "目标函数（可选）", false)),
    ) { args ->
        val function = args["function"] ?: ""
        PromptResult(
            description = "调试 JavaScript",
            messages = listOf(
                user(
                    """
                    请调试页面 JavaScript${if (function.isNotBlank()) "（目标函数：$function）" else ""}：
                    1. 调用 debugger.set_breakpoint 设置断点
                    2. 调用 debugger.watch 添加 Watch 表达式
                    3. 调用 debugger.pause 暂停执行
                    4. 调用 debugger.call_stack 查看调用栈
                    5. 调用 debugger.scopes / debugger.locals 查看变量
                    6. 调用 debugger.step_over / step_into 逐步执行
                    输出：断点命中记录、调用栈、变量快照、执行流程。
                    """.trimIndent(),
                ),
            ),
        )
    }

    private fun inspectDom() = prompt(
        "inspect_dom",
        "检查 DOM：查询元素、属性、样式与事件监听",
        listOf(PromptArgument("selector", "CSS 选择器", true)),
    ) { args ->
        val selector = args["selector"] ?: ""
        PromptResult(
            description = "检查 DOM 元素",
            messages = listOf(
                user(
                    """
                    请检查 DOM 元素 "$selector"：
                    1. 调用 dom.query 查询元素
                    2. 调用 dom.get_html 获取 HTML
                    3. 调用 dom.get_attribute 获取属性
                    4. 调用 dom.get_style 获取样式
                    5. 调用 dom.get_rect 获取布局信息
                    6. 分析事件监听与关联函数
                    输出：元素结构、属性、样式、事件、关联 JS 函数。
                    """.trimIndent(),
                ),
            ),
        )
    }

    private fun analyzeStorage() = prompt(
        "analyze_storage",
        "分析存储：Cookie、LocalStorage、SessionStorage 与缓存",
        listOf(PromptArgument("type", "存储类型（可选）", false)),
    ) { args ->
        val type = args["type"] ?: ""
        PromptResult(
            description = "分析浏览器存储",
            messages = listOf(
                user(
                    """
                    请分析页面存储${if (type.isNotBlank()) "（类型：$type）" else ""}：
                    1. 调用 storage.cookies 读取 Cookie（脱敏）
                    2. 调用 storage.local 读取 LocalStorage
                    3. 调用 storage.session 读取 SessionStorage
                    4. 调用 storage.search 搜索关键键值
                    5. 分析存储中的认证信息与业务数据
                    注意：敏感值必须脱敏，禁止输出明文 Cookie/Token。
                    """.trimIndent(),
                ),
            ),
        )
    }

    private fun generateReverseEngineeringReport() = prompt(
        "generate_reverse_engineering_report",
        "生成逆向分析报告：汇总所有分析结果",
        listOf(PromptArgument("workspaceId", "工作区 ID", false)),
    ) { args ->
        val workspaceId = args["workspaceId"] ?: ""
        PromptResult(
            description = "生成逆向分析报告",
            messages = listOf(
                user(
                    """
                    请生成一份完整的逆向分析报告${if (workspaceId.isNotBlank()) "（工作区：$workspaceId）" else ""}：
                    1. 汇总页面信息、框架、API 清单
                    2. 汇总 JS 混淆分析与关键函数
                    3. 汇总网络请求与调用链
                    4. 汇总存储分析与安全发现
                    5. 调用 re.generate_report 生成结构化报告
                    输出：技术栈、API Inventory、混淆分析、调用链、安全风险、逆向结论与建议。
                    """.trimIndent(),
                ),
            ),
        )
    }

    private fun prompt(
        name: String,
        description: String,
        arguments: List<PromptArgument>,
        block: (Map<String, String>) -> PromptResult,
    ): McpPrompt = object : McpPrompt {
        override val name = name
        override val description = description
        override val arguments = arguments

        override suspend fun get(arguments: Map<String, String>): PromptResult = try {
            block(arguments)
        } catch (e: Exception) {
            PromptResult(
                description = "生成失败",
                messages = listOf(user("Prompt 生成失败：${e.message}")),
            )
        }
    }

    private fun user(text: String): PromptMessage =
        PromptMessage(role = "user", content = PromptContent(type = "text", text = text))
}
