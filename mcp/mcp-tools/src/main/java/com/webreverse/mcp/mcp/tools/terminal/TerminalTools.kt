package com.webreverse.mcp.mcp.tools.terminal

import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.common.util.WorkDir
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import com.webreverse.mcp.mcp.tools.Schemas
import com.webreverse.mcp.mcp.tools.ToolArgs
import com.webreverse.mcp.mcp.tools.ToolDependencies
import com.webreverse.mcp.mcp.tools.ToolFactory
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.put
import java.io.File

/**
 * Terminal Tools：内置真实终端 + Host Tools 管理。
 *
 * 让 AI 能：
 * - 在设备上执行任意 shell 命令（terminal.exec）
 * - 运行 Python 代码并查看输出、自测修复 bug（terminal.run_python）
 * - 运行脚本文件（terminal.run_script）
 * - 从 Termux 源安装工具（git/python/make 等，terminal.install）
 * - 用 pip 安装 Python 库（terminal.pip_install）
 * - 查看已安装工具与环境（terminal.status / terminal.list_tools / terminal.env）
 */
object TerminalTools {

    /** NDK 后台下载协程作用域（terminal.ndk install 异步下载用） */
    private val ndkScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /** NDK 下载任务是否进行中（防重复触发） */
    @Volatile
    private var downloadJobActive = false

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)
        val engine = deps.terminalEngine
        val hostTools = deps.hostToolsManager
        val downloader = deps.hostToolsDownloader

        return listOf(
            // ---------- 状态 ----------
            f.tool(
                "terminal.status", "获取终端与 Host Tools 状态（是否安装、Python/Git 路径、架构、额外工具包）", ToolCategory.SYSTEM,
                PermissionScope.READ_FILE, RiskLevel.LOW,
            ) { _ ->
                val state = hostTools.state.value
                McpToolResult.json(
                    buildJsonObject {
                        put("shell", JsonPrimitive(engine.shellPath()))
                        put("home", JsonPrimitive(TerminalPaths.homeDir.absolutePath))
                        put("hostTools", JsonPrimitive(state.javaClass.simpleName))
                        when (state) {
                            is HostToolsState.Installed -> {
                                put("arch", JsonPrimitive(state.arch))
                                put("prefixDir", JsonPrimitive(state.prefixDir.absolutePath))
                                put("git", JsonPrimitive(state.gitPath?.absolutePath ?: ""))
                                put("python", JsonPrimitive(state.pythonPath?.absolutePath ?: ""))
                                put("perl", JsonPrimitive(state.perlPath?.absolutePath ?: ""))
                                put(
                                    "additionalPackages",
                                    JsonArray(state.additionalPackages.map { JsonPrimitive(it) }),
                                )
                            }
                            is HostToolsState.Downloading -> {
                                put("progress", JsonPrimitive(state.progress))
                                put("message", JsonPrimitive(state.message))
                            }
                            is HostToolsState.Extracting -> {
                                put("progress", JsonPrimitive(state.progress))
                                put("message", JsonPrimitive(state.message))
                            }
                            is HostToolsState.Configuring -> {
                                put("progress", JsonPrimitive(state.progress))
                                put("message", JsonPrimitive(state.message))
                            }
                            is HostToolsState.Failed -> put("message", JsonPrimitive(state.message))
                            HostToolsState.NotInstalled -> {
                                put(
                                    "hint",
                                    JsonPrimitive("Host Tools 未安装。用 terminal.install 安装 git/python/perl（从 Termux 官方源下载）"),
                                )
                            }
                        }
                    },
                )
            },

            // ---------- 命令执行 ----------
            f.tool(
                "terminal.exec", "在设备终端执行 shell 命令并返回输出与退出码。可运行 git、python、make 等已安装工具，也可测试脚本、修复 bug。注意：命令在 Android 沙箱内执行，权限受限；默认工作目录与 file.* 工具一致，都是统一存储目录（设置里的工作目录，file.workdir 可查），file.write 落盘的文件直接 ls 即可看到。重要：沙箱内无法写入系统 /tmp（Android 应用 uid 无权限，curl -o /tmp 会报 exit 23）；临时/下载文件请写入当前工作目录或 \$TMPDIR（即 工作目录/tmp，见 file.workdir）", ToolCategory.SYSTEM,
                PermissionScope.WRITE_FILE, RiskLevel.HIGH, timeoutMs = 180_000,
                inputSchema = Schemas.objectSchema(
                    "command" to Schemas.strSchema("要执行的 shell 命令（支持管道/重定向/&& 等）"),
                    "workingDir" to Schemas.strSchema("工作目录（默认统一存储目录，与 file.* 一致）"),
                    "timeoutMs" to Schemas.intSchema("超时毫秒（默认 60000，最大 300000）"),
                ),
            ) { args ->
                val command = ToolArgs.str(args, "command")
                if (command.isBlank()) return@tool McpToolResult.error("INVALID_ARGUMENTS", "command 不能为空")
                val workingDir = ToolArgs.optStr(args, "workingDir")?.takeIf { it.isNotBlank() }?.let { File(it) }
                val timeout = ToolArgs.long(args, "timeoutMs", 60_000L).coerceIn(5_000L, 300_000L)
                val result = engine.execute(command, workingDir, timeoutMs = timeout)
                val actualCwd = (workingDir ?: TerminalPaths.homeDir).absolutePath
                McpToolResult.json(
                    buildJsonObject {
                        put("command", JsonPrimitive(result.command))
                        put("cwd", JsonPrimitive(actualCwd))
                        put("exitCode", JsonPrimitive(result.exitCode))
                        put("timedOut", JsonPrimitive(result.timedOut))
                        put("output", JsonPrimitive(result.output))
                        put(
                            "truncated",
                            JsonPrimitive(result.output.length > 200_000),
                        )
                        // 终端与 file.* 已统一到同一存储目录（此前的两套目录问题不再存在）。
                        // 固定回传 cwd，AI 一眼可知文件落点。
                        put("cwdNote", JsonPrimitive("本次工作目录：$actualCwd（与 file.* 工具统一，file.write 落盘的文件就在这里）"))
                    },
                )
            },

            // ---------- 终端沙箱策略 ----------
            f.tool(
                "terminal.sandbox", "终端沙箱策略查询：预览任意命令是否会被沙箱放行/拦截，或列出策略摘要。" +
                    "所有 terminal.exec/run_python/run_script 命令都经沙箱把关。action=preview 返回该命令的裁决（ALLOW/DENY）；action=policy 列出 denylist 与危险模式摘要。不支持授权——拦截即硬阻断，无人工放行通道（避免 AI 自授权安全隐患）", ToolCategory.SYSTEM,
                PermissionScope.CONTROL_MCP, RiskLevel.MEDIUM, timeoutMs = 15_000,
                inputSchema = Schemas.objectSchema(
                    "action" to Schemas.strSchema("preview / policy"),
                    "command" to Schemas.strSchema("要预览的命令（action=preview 需要）"),
                    "workingDir" to Schemas.strSchema("工作目录（preview 时校验）"),
                ),
            ) { args ->
                val action = ToolArgs.str(args, "action", "policy").lowercase()
                when (action) {
                    "preview" -> {
                        val command = ToolArgs.str(args, "command")
                        val workingDir = ToolArgs.optStr(args, "workingDir")?.takeIf { it.isNotBlank() }?.let { File(it) }
                        if (command.isBlank()) return@tool McpToolResult.error("INVALID_ARGUMENTS", "command 不能为空（preview 需提供要预览的命令）")
                        val decision = engine.sandboxPolicy.check(command, workingDir)
                        McpToolResult.json(
                            buildJsonObject {
                                put("command", JsonPrimitive(command))
                                put("status", JsonPrimitive(decision.status.name))
                                put("allowed", JsonPrimitive(decision.allowed))
                                put("reason", JsonPrimitive(decision.reason))
                                put("matchedRule", JsonPrimitive(decision.matchedRule))
                            },
                        )
                    }
                    else -> {
                        // policy 摘要
                        McpToolResult.json(
                            buildJsonObject {
                                put("allowlistCount", JsonPrimitive(TerminalSandbox.ALLOWLIST.size))
                                put(
                                    "denylist",
                                    JsonArray(TerminalSandbox.DENYLIST.sorted().map { JsonPrimitive(it) }),
                                )
                                put(
                                    "dangerousPatternCount",
                                    JsonPrimitive(TerminalSandbox.DANGEROUS_PATTERNS.size),
                                )
                                put(
                                    "cwdRoots",
                                    JsonArray(listOf(
                                        TerminalPaths.homeDir.absolutePath,
                                        TerminalPaths.scriptsDir.absolutePath,
                                    ).map { JsonPrimitive(it) }),
                                )
                                put(
                                    "hint",
                                    JsonPrimitive("用 action=preview 对具体命令做裁决；拦截为硬阻断，无授权通道"),
                                )
                            },
                        )
                    }
                }
            },

            // ---------- Python ----------
            f.tool(
                "terminal.run_python", "运行 Python 代码并返回输出与退出码。AI 可用它测试 Python 代码、自测修复 bug。代码写入临时文件后用 python3 执行（需先 terminal.install 安装 Host Tools）", ToolCategory.SYSTEM,
                PermissionScope.WRITE_FILE, RiskLevel.HIGH, timeoutMs = 180_000,
                inputSchema = Schemas.objectSchema(
                    "code" to Schemas.strSchema("Python 源码"),
                    "args" to Schemas.arraySchema("命令行参数（可选）"),
                    "timeoutMs" to Schemas.intSchema("超时毫秒（默认 120000）"),
                ),
            ) { args ->
                val code = ToolArgs.str(args, "code")
                if (code.isBlank()) return@tool McpToolResult.error("INVALID_ARGUMENTS", "code 不能为空")
                val argList = parseStringArray(args, "args")
                val timeout = ToolArgs.long(args, "timeoutMs", 120_000L).coerceIn(5_000L, 300_000L)
                val result = engine.runPython(code, argList, timeoutMs = timeout)
                McpToolResult.json(
                    buildJsonObject {
                        put("exitCode", JsonPrimitive(result.exitCode))
                        put("timedOut", JsonPrimitive(result.timedOut))
                        put("output", JsonPrimitive(result.output))
                    },
                )
            },

            // ---------- 脚本 ----------
            f.tool(
                "terminal.run_script", "运行脚本文件（.py 用 python3，其他用 sh）。适合运行 file.write 落盘的脚本；路径找不到时自动按 file 工作目录 → 终端 HOME 顺序解析相对路径", ToolCategory.SYSTEM,
                PermissionScope.WRITE_FILE, RiskLevel.HIGH, timeoutMs = 180_000,
                inputSchema = Schemas.objectSchema(
                    "path" to Schemas.strSchema("脚本文件路径（绝对路径，或相对路径——按 file 工作目录 → 终端 HOME 顺序解析）"),
                    "args" to Schemas.arraySchema("命令行参数（可选）"),
                    "timeoutMs" to Schemas.intSchema("超时毫秒（默认 120000）"),
                ),
            ) { args ->
                val path = ToolArgs.str(args, "path")
                if (path.isBlank()) return@tool McpToolResult.error("INVALID_ARGUMENTS", "path 不能为空")
                // 修复（实测问题：AI 用 file.write 把脚本写进 file 工作目录后，
                // 直接把文件名/相对路径传过来执行失败——terminal 与 file 是两套工作目录）。
                // 现在按 原样 → file 工作目录 → 终端 HOME 顺序自动解析，并回传实际路径。
                var scriptFile = File(path)
                if (!scriptFile.exists()) {
                    scriptFile = listOf(File(WorkDir.get(), path), File(TerminalPaths.homeDir, path))
                        .firstOrNull { it.exists() }
                        ?: scriptFile
                }
                val argList = parseStringArray(args, "args")
                val timeout = ToolArgs.long(args, "timeoutMs", 120_000L).coerceIn(5_000L, 300_000L)
                val result = engine.runScript(scriptFile.absolutePath, argList, timeoutMs = timeout)
                McpToolResult.json(
                    buildJsonObject {
                        put("path", JsonPrimitive(path))
                        if (scriptFile.absolutePath != path) {
                            put("resolvedPath", JsonPrimitive(scriptFile.absolutePath))
                        }
                        put("exitCode", JsonPrimitive(result.exitCode))
                        put("timedOut", JsonPrimitive(result.timedOut))
                        put("output", JsonPrimitive(result.output))
                    },
                )
            },

            // ---------- 安装工具 ----------
            f.tool(
                "terminal.install", "安装工具包（从 Termux 官方源下载预编译 .deb）。默认安装 git/perl/python/python-pip；可指定额外包名如 make、cmake、nodejs、curl 等。安装前先经 ToolRegistry 全来源扫描（host/系统/root/Termux），已存在的工具自动跳过，仅安装缺失的包", ToolCategory.SYSTEM,
                PermissionScope.WRITE_FILE, RiskLevel.HIGH, timeoutMs = 600_000,
                inputSchema = Schemas.objectSchema(
                    "packages" to Schemas.arraySchema("要安装的包名列表（留空则安装默认 git/python/perl）"),
                    "force" to Schemas.boolSchema("强制重新安装（默认 false：已可用则跳过）"),
                ),
            ) { args ->
                val packages = parseStringArray(args, "packages")
                val force = ToolArgs.bool(args, "force", false)
                val hostPrefix = hostTools.getPrefixDir()

                // 智能跳过——已可用的包不重复安装
                val requested = if (packages.isEmpty()) HostToolsManager.REQUIRED_PACKAGES else packages
                val (alreadyOk, missing) = if (force) {
                    emptyList<String>() to requested
                } else {
                    requested.partition { pkg ->
                        val cmds = ToolRegistry.commandsOfPackage(pkg)
                        // 任一关键命令可解析即视为可用
                        cmds.any { ToolRegistry.resolve(it, hostPrefix) != null }
                    }
                }

                if (missing.isEmpty()) {
                    return@tool McpToolResult.json(
                        buildJsonObject {
                            put("success", JsonPrimitive(true))
                            put("installed", JsonArray(emptyList()))
                            put("skipped", JsonArray(alreadyOk.map { JsonPrimitive(it) }))
                            put(
                                "message",
                                JsonPrimitive(
                                    "所有请求的工具均已可用（经 ToolRegistry 扫描 host/系统/root/Termux 来源），" +
                                        "无需安装。直接用 terminal.exec 使用即可。",
                                ),
                            )
                        },
                    )
                }

                val result = if (packages.isEmpty() && !hostTools.isCoreInstalledOnDisk() && missing.size == requested.size) {
                    // 冷启动：默认核心包（git/perl/python/python-pip）全部缺失，
                    // 且磁盘上确实没有 Host Tools 核心 → 全量重建安装（重建 prefix）。
                    // 用 isCoreInstalledOnDisk（磁盘判定）兜底——即使上次附加包
                    // 安装失败把状态置为 Failed，只要 git 等核心仍在磁盘，就走下方增量安装，
                    // 绝不因状态异常而重复下载/重建整个 Host Tools。
                    downloader.downloadAndExtract().map { HostToolsManager.REQUIRED_PACKAGES }
                } else {
                    // 已装核心走增量安装：只装缺失的包，不重建 prefix，不重复下载已装工具。
                    downloader.installAdditionalPackages(missing)
                }
                result.fold(
                    onSuccess = { installed ->
                        McpToolResult.json(
                            buildJsonObject {
                                put("success", JsonPrimitive(true))
                                put(
                                    "installed",
                                    JsonArray(installed.map { JsonPrimitive(it) }),
                                )
                                put(
                                    "skipped",
                                    JsonArray(alreadyOk.map { JsonPrimitive(it) }),
                                )
                                put(
                                    "message",
                                    buildString {
                                        append("安装完成（跳过已可用: ")
                                        append(if (alreadyOk.isEmpty()) "无" else alreadyOk.joinToString(", "))
                                        append("）。可用 terminal.status 查看状态，terminal.exec 执行命令")
                                    },
                                )
                            },
                        )
                    },
                    onFailure = { e ->
                        McpToolResult.error("INSTALL_FAILED", "安装失败: ${e.message}")
                    },
                )
            },

            // ---------- 工具解析 ----------
            f.tool(
                "terminal.which", "解析命令的完整可执行文件路径（全来源扫描：host → 系统 → root → Termux）。安装新工具前先查此工具避免重复安装", ToolCategory.SYSTEM,
                PermissionScope.READ_FILE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "command" to Schemas.strSchema("命令名（如 python3、curl、openssl）"),
                ),
            ) { args ->
                val command = ToolArgs.str(args, "command").trim()
                if (command.isEmpty()) return@tool McpToolResult.error("INVALID_ARGUMENTS", "command 不能为空")
                val hostPrefix = hostTools.getPrefixDir()
                val found = ToolRegistry.resolve(command, hostPrefix)
                if (found != null) {
                    val source = ToolRegistry.candidateDirs(hostPrefix)
                        .firstOrNull { it.first.absolutePath == found.parentFile?.absolutePath }
                        ?.second ?: "path"
                    McpToolResult.json(
                        buildJsonObject {
                            put("found", JsonPrimitive(true))
                            put("command", JsonPrimitive(command))
                            put("path", JsonPrimitive(found.absolutePath))
                            put("source", JsonPrimitive(source))
                        },
                    )
                } else {
                    McpToolResult.json(
                        buildJsonObject {
                            put("found", JsonPrimitive(false))
                            put("command", JsonPrimitive(command))
                            put(
                                "hint",
                                JsonPrimitive(
                                    "未找到。可用 terminal.list_tools 查看已可用工具，或 terminal.install 安装。",
                                ),
                            )
                        },
                    )
                }
            },

            // ---------- pip ----------
            f.tool(
                "terminal.pip_install", "用 pip 安装 Python 库（默认走清华镜像 https://pypi.tuna.tsinghua.edu.cn/simple，支持任意包如 crypto、pycryptodome、requests、cryptography）。python/pip 经 ToolRegistry 全来源解析，系统或 Termux 已装的 Python 也能直接使用；库安装到该 Python 的 site-packages", ToolCategory.SYSTEM,
                PermissionScope.WRITE_FILE, RiskLevel.HIGH, timeoutMs = 600_000,
                inputSchema = Schemas.objectSchema(
                    "packages" to Schemas.arraySchema("要安装的 Python 包名列表"),
                ),
            ) { args ->
                val packages = parseStringArray(args, "packages")
                if (packages.isEmpty()) return@tool McpToolResult.error("INVALID_ARGUMENTS", "packages 不能为空")
                val python = engine.resolvePython()
                    ?: return@tool McpToolResult.error(
                        "PYTHON_NOT_INSTALLED",
                        "未找到 python 解释器（已扫描 host/系统/root/Termux）。可用 terminal.which python3 查看解析情况，或 terminal.install 安装。",
                    )
                val result = engine.execute(
                    "\"${python.absolutePath}\" -m pip install -i ${HostToolsManager.PIP_INDEX_URL} ${packages.joinToString(" ") { quote(it) }} --no-warn-script-location",
                    timeoutMs = 600_000,
                )
                McpToolResult.json(
                    buildJsonObject {
                        put("exitCode", JsonPrimitive(result.exitCode))
                        put("output", JsonPrimitive(result.output))
                        put(
                            "success",
                            JsonPrimitive(result.exitCode == 0),
                        )
                    },
                )
            },

            // ---------- 列出工具 ----------
            f.tool(
                "terminal.list_tools", "列出设备上所有可用工具（全来源扫描 host/系统/root/Termux，含 git/python/perl/curl/openssl 等常用逆向命令及其路径与来源）", ToolCategory.SYSTEM,
                PermissionScope.READ_FILE, RiskLevel.LOW,
            ) { _ ->
                val hostPrefix = hostTools.getPrefixDir()
                val entries = ToolRegistry.scan(hostPrefix, refresh = true)
                val bySource = entries.groupBy { it.source }
                McpToolResult.json(
                    buildJsonObject {
                        put("count", JsonPrimitive(entries.size))
                        put(
                            "tools",
                            JsonArray(
                                entries.map { e ->
                                    buildJsonObject {
                                        put("name", JsonPrimitive(e.name))
                                        put("path", JsonPrimitive(e.path))
                                        put("source", JsonPrimitive(e.source))
                                    }
                                },
                            ),
                        )
                        put(
                            "bySource",
                            buildJsonObject {
                                bySource.forEach { (src, list) ->
                                    put(src, JsonArray(list.map { JsonPrimitive(it.name) }))
                                }
                            },
                        )
                        put(
                            "hint",
                            JsonPrimitive(
                                "来源: host=本应用安装, system=Android 系统, root=root 方案, termux=已装 Termux。" +
                                    "terminal.exec 可直接使用以上全部工具。",
                            ),
                        )
                    },
                )
            },

            // ---------- 环境变量 ----------
            f.tool(
                "terminal.env", "获取终端环境变量（PATH、HOME、PYTHONHOME 等），了解可用命令", ToolCategory.SYSTEM,
                PermissionScope.READ_FILE, RiskLevel.LOW,
            ) { _ ->
                val env = engine.buildEnvironment()
                McpToolResult.json(
                    buildJsonObject {
                        put(
                            "env",
                            buildJsonObject {
                                env.forEach { (k, v) -> put(k, JsonPrimitive(v)) }
                            },
                        )
                    },
                )
            },

            // ---------- 卸载 ----------
            f.tool(
                "terminal.uninstall", "卸载 Host Tools（删除已安装的 git/python/perl 及额外工具）", ToolCategory.SYSTEM,
                PermissionScope.WRITE_FILE, RiskLevel.HIGH,
            ) { _ ->
                withContext(Dispatchers.IO) {
                    hostTools.uninstall()
                    McpToolResult.json(
                        buildJsonObject {
                            put("success", JsonPrimitive(true))
                            put("message", JsonPrimitive("Host Tools 已卸载"))
                        },
                    )
                }
            },

            // ---------- NDK（终端内置 NDK，pip 编译 C 扩展用） ----------
            f.tool(
                "terminal.ndk", "管理终端内置 NDK（Android NDK 工具链）。action=status 查询安装状态与进度；action=install 从 GitHub 下载 HomuHomu833/android-ndk-custom r29（aarch64 定制版，约 1GB，后台下载，需再轮询 status）；action=uninstall 卸载。安装后终端自动注入 NDK clang 编译环境（CC/CXX/AR/RANLIB 等），pip install pycryptodome / cryptography 等带 C 扩展的 Python 库可直接本地编译（需先安装 Host Tools 的 python）。安装状态可用 terminal.exec 'echo \$CC' 验证", ToolCategory.SYSTEM,
                PermissionScope.WRITE_FILE, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "action" to Schemas.strSchema("操作：status（查询）/ install（下载安装）/ uninstall（卸载）"),
                ),
            ) { args ->
                val ndk = deps.ndkManager
                val ndkDl = deps.ndkDownloader
                if (ndk == null || ndkDl == null) {
                    return@tool McpToolResult.error("NOT_SUPPORTED", "NDK 管理组件未初始化")
                }
                when (ToolArgs.str(args, "action", "status").lowercase()) {
                    "install" -> {
                        if (ndk.isInstalledOnDisk()) {
                            return@tool McpToolResult.json(
                                buildJsonObject {
                                    put("success", JsonPrimitive(true))
                                    put("alreadyInstalled", JsonPrimitive(true))
                                    put("message", JsonPrimitive("NDK 已安装，无需重复安装。可用 action=status 查看详情"))
                                },
                            )
                        }
                        if (downloadJobActive) {
                            return@tool McpToolResult.json(
                                buildJsonObject {
                                    put("success", JsonPrimitive(true))
                                    put("started", JsonPrimitive(false))
                                    put("message", JsonPrimitive("NDK 下载已在进行中，用 action=status 查询进度"))
                                },
                            )
                        }
                        val version = ndk.availableVersions.firstOrNull { it.isRecommended }
                            ?: ndk.availableVersions.firstOrNull()
                            ?: return@tool McpToolResult.error("NO_VERSION", "无可用的 NDK 版本")
                        downloadJobActive = true
                        ndkScope.launch {
                            try {
                                ndkDl.downloadAndExtract(version)
                            } finally {
                                downloadJobActive = false
                            }
                        }
                        McpToolResult.json(
                            buildJsonObject {
                                put("success", JsonPrimitive(true))
                                put("started", JsonPrimitive(true))
                                put("version", JsonPrimitive(version.displayName))
                                put("downloadUrl", JsonPrimitive(version.downloadUrl))
                                put(
                                    "message",
                                    JsonPrimitive("已开始后台下载 NDK（体积较大，约数百 MB~1GB）。用 action=status 轮询进度；安装完成后终端 pip 即可编译 C 扩展"),
                                )
                            },
                        )
                    }
                    "uninstall" -> {
                        withContext(Dispatchers.IO) {
                            ndk.uninstall()
                            McpToolResult.json(
                                buildJsonObject {
                                    put("success", JsonPrimitive(true))
                                    put("message", JsonPrimitive("NDK 已卸载"))
                                },
                            )
                        }
                    }
                    else -> {
                        // status（默认）
                        val state = ndk.state.value
                        val env = if (ndk.isInstalledOnDisk()) ndk.getEnvironment() else emptyMap()
                        McpToolResult.json(
                            buildJsonObject {
                                put("state", JsonPrimitive(state.javaClass.simpleName))
                                when (state) {
                                    is NdkState.Installed -> {
                                        put("version", JsonPrimitive(state.version))
                                        put("ndkPath", JsonPrimitive(state.ndkPath))
                                        put("binDir", JsonPrimitive(state.binDir))
                                        put("targetTriple", JsonPrimitive(ndk.targetTriple()))
                                        put("cc", JsonPrimitive(env["CC"] ?: ""))
                                        put("hint", JsonPrimitive("终端内 pip install <带C扩展的库> 会自动用 NDK clang 编译"))
                                    }
                                    is NdkState.Downloading -> {
                                        put("progress", JsonPrimitive(state.progress))
                                        put("receivedBytes", JsonPrimitive(state.receivedBytes))
                                        put("totalBytes", JsonPrimitive(state.totalBytes))
                                    }
                                    is NdkState.Extracting -> put("progress", JsonPrimitive(state.progress))
                                    is NdkState.Configuring -> put("progress", JsonPrimitive(state.progress))
                                    is NdkState.Failed -> put("message", JsonPrimitive(state.message))
                                    NdkState.NotInstalled -> {
                                        put(
                                            "hint",
                                            JsonPrimitive(
                                                "NDK 未安装。action=install 下载（源: " +
                                                    (ndk.availableVersions.firstOrNull()?.downloadUrl ?: "") + "）",
                                            ),
                                        )
                                    }
                                }
                            },
                        )
                    }
                }
            },
        )
    }

    // ---------------- 辅助 ----------------

    /** 解析字符串数组参数（兼容 JSON 数组） */
    private fun parseStringArray(args: kotlinx.serialization.json.JsonObject, key: String): List<String> {
        val v = args[key] ?: return emptyList()
        return when (v) {
            is JsonArray -> v.mapNotNull { (it as? JsonPrimitive)?.content }
            is JsonPrimitive -> {
                val content = v.content.trim()
                if (content.startsWith("[")) {
                    runCatching {
                        kotlinx.serialization.json.Json.parseToJsonElement(content).jsonArray
                            .mapNotNull { (it as? JsonPrimitive)?.content }
                    }.getOrElse { listOf(content) }
                } else {
                    listOf(content)
                }
            }
            else -> emptyList()
        }
    }

    /** shell 参数引用 */
    private fun quote(s: String): String = "'" + s.replace("'", "'\\''") + "'"
}
