package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.ToolRegistry

/**
 * MCP Tool 模块化注册入口。
 * 通过 registerAll 批量注册所有分类工具，避免手工把 100+ 工具写进一个文件。
 */
object ToolModule {

    /** 注册所有工具到注册表 */
    fun registerAll(deps: ToolDependencies, registry: ToolRegistry = deps.toolRegistry): ToolRegistry {
        // CDP WS 帧转发 EventBus：event.wait network.websocket 即时捕获
        // 透传 opcode（1=文本 / 2=二进制），实时事件可区分二进制帧
        com.webreverse.mcp.devtools.network.CdpNetworkMonitor.wsFrameSink =
            { tabId, url, direction, payload, opcode ->
                deps.eventBus.tryEmit(
                    com.webreverse.mcp.core.common.event.NetworkEvent.WebSocketFrame(tabId, url, direction, payload, opcode),
                )
            }
        // CDP SSE 消息转发 EventBus：event.wait network.sse 即时捕获
        com.webreverse.mcp.devtools.network.CdpNetworkMonitor.sseMessageSink =
            { tabId, url, eventName, data ->
                deps.eventBus.tryEmit(
                    com.webreverse.mcp.core.common.event.NetworkEvent.SseMessage(tabId, url, eventName, data),
                )
            }
        // CDP 抓取的请求同样转发 network.request 事件（entryId 即 CDP
        // requestId，事件 → network.initiator 直达调用栈）。此前只有注入式 hook
        // 的请求发事件，attach_cdp 后 event.wait network.request 一直超时。
        com.webreverse.mcp.devtools.network.CdpNetworkMonitor.requestSink =
            { tabId, requestId, url, method ->
                deps.eventBus.tryEmit(
                    com.webreverse.mcp.core.common.event.NetworkEvent.RequestStarted(requestId, tabId, url, method),
                )
            }
        registry.registerAll(BrowserTools.all(deps))
        registry.registerAll(TabTools.all(deps))
        registry.registerAll(DomTools.all(deps))
        registry.registerAll(JavaScriptTools.all(deps))
        registry.registerAll(DebuggerTools.all(deps))
        registry.registerAll(NetworkTools.all(deps))
        registry.registerAll(StorageTools.all(deps))
        registry.registerAll(HookTools.all(deps))
        registry.registerAll(PageTools.all(deps))
        registry.registerAll(ReverseEngineeringTools.all(deps))
        registry.registerAll(WasmTools.all(deps))
        // 新增：JSVMP 深度分析 / 静态画像 / 动态追踪
        registry.registerAll(VmpTools.all(deps))
        registry.registerAll(StaticTools.all(deps))
        registry.registerAll(DynamicTools.all(deps))
        // 离线可执行沙箱（code.sandbox_eval，纯 Kotlin 表达式/解密引擎）
        registry.registerAll(OfflineSandboxTools.all(deps))
        // 可插拔真 Chrome/CDP 后端（browser.attach_remote / 互斥切换）
        registry.registerAll(RemoteBackendTools.all(deps))
        registry.registerAll(FrameTools.all(deps))
        registry.registerAll(WorkerTools.all(deps))
        registry.registerAll(PerformanceTools.all(deps))
        registry.registerAll(EventTools.all(deps))
        registry.registerAll(WorkspaceTools.all(deps))
        // 核心：证据库 / 逆向图谱 / 分析流水线（把工具产出收敛为知识图谱）
        registry.registerAll(EvidenceTools.all(deps))
        // 逆向调查引擎（Investigation-first：investigation.start/next/status ...）
        registry.registerAll(InvestigationTools.all(deps))
        // 逆向能力发现 + 复合工具（reverse.capabilities/tools/toolbox + network.inspect）
        registry.registerAll(ReverseDiscoveryTools.all(deps))
        registry.registerAll(FileTools.all(deps))
        registry.registerAll(McpTools.all(deps))
        registry.registerAll(SystemTools.all(deps))
        // 内置终端 + Host Tools 管理（terminal.exec / run_python / install ...）
        registry.registerAll(com.webreverse.mcp.mcp.tools.terminal.TerminalTools.all(deps))
        // 用户脚本管理（user_script.create / list / get / update / delete / set_enabled）
        registry.registerAll(UserScriptTools.all(deps))
        // 高层超级工具 reverse.*（统一分析入口 + 因果推理 + 自适应规划 + Agent Hints）
        registry.registerAll(ReverseSuperTools.all(deps))
        // 页面级一键逆向分诊，把已有分析引擎收敛成 Agent 第一入口。
        registry.registerAll(ReverseTriageTools.all(deps))
        // 深层分析工具链（WASM 内存溯源 + JS↔WASM 数据流 / JSVMP Micro-IR+签名库+差分语义 / 验证闭环引擎）
        registry.registerAll(AdvancedAnalysisTools.all(deps))
        // Memory SSA / WASM provenance / Worker DataFlow / JSVMP VM-SSA 深层引擎。
        registry.registerAll(DeepReverseTools.all(deps))
        // 增强能力工具层（动态验证批量 / WASM 结构化反编译 / ES import-export / 静态×运行时污点联合 / 约束求解符号执行）
        registry.registerAll(EnhancedAnalysisTools.all(deps))
        // 通用目标画像/能力向量，避免 Agent 依赖站点特征进行逆向路线选择
        registry.registerAll(UniversalReverseTools.all(deps))
        // 一键自动逆向编排（auto_pilot / jsvmp.auto_deobfuscate / wasm.auto_decompile）
        registry.registerAll(AutoPilotTools.all(deps))
        // 静态 ←→ 运行时打通 + Agent 胶水消除
        // - jsvmp.bytecode_dump：JSVMP 字节码运行时解码 dump + ISA 对照
        registry.registerAll(JsvmpRuntimeTools.all(deps))
        // - wasm.trace_calls/trace_export/trace_read：WASM 导出函数调用记录 + 定向深度追踪
        registry.registerAll(WasmTraceTools.all(deps))
        // - sourcemap.recover：Source Map 整包自动还原为原始源码树
        registry.registerAll(SourcemapRecoveryTools.all(deps))
        // - hook.generate/generate_install/gen_read：任意目标 hook 脚本自动生成
        registry.registerAll(HookAutoGenTools.all(deps))
        // 按命名空间聚合为枢纽工具（410+ → 约 34 个），原工具保留可直调；
        // tools/list 只返回枢纽或全量（registry.hubMode）， 起由设置页手动开关（不再提供 mcp.tool_mode）
        HubTools.buildAndRegister(registry)
        return registry
    }

    /** 按分类列出工具 */
    fun listByCategory(registry: ToolRegistry): Map<String, List<String>> =
        registry.listMetadata().groupBy({ it.category.name }, { it.name })

    /** 统计各分类数量 */
    fun countByCategory(registry: ToolRegistry): Map<String, Int> =
        registry.listMetadata().groupingBy { it.category.name }.eachCount()
}
