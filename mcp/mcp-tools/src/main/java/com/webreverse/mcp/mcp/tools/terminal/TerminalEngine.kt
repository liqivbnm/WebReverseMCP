package com.webreverse.mcp.mcp.tools.terminal

import android.content.Context
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * 终端引擎。
 *
 * 提供两类能力：
 * 1. 一次性命令执行（MCP 工具用）：`sh -c <command>`，带超时，返回完整输出。
 * 2. 交互式 shell 会话（终端 UI 用）：常驻 `sh -i` 进程，命令写入 stdin、
 *    输出流式返回，支持 `cd` 等状态在命令间保持。
 *
 * 关键升级——shell 驱动的提示符标记（修复“命令完成后不自动换行”）：
 * - 交互会话改用 `sh -i`（mksh 强制交互模式），通过环境变量注入带
 *   会话随机数的 PS1/PS2 标记（如 `__WRPa3f9c__ `）。
 * - mksh 在就绪等待下一条命令时输出 PS1、需要续行时输出 PS2，
 *   会话解析输出流中的标记即可精确知道“命令已结束/需要续行”，
 *   而不是靠超时猜测。
 * - 标记出现时若上一行输出未以换行结尾（如 `curl -s` 的 HTML 输出），
 *   自动补一个换行再渲染提示符——与真实终端的 PROMPT_SP 行为一致。
 * - 兼容性探测：启动前用一次性子进程验证 `sh -i` + env PS1 是否生效；
 *   不支持（极少数非 mksh 设备）时回退旧版“输出以 \n 结尾才显示提示符”逻辑。
 *
 * 环境变量自动注入 Host Tools（git/python/perl）路径、NDK 编译工具链
 * （CC/CXX/AR/RANLIB/CPPFLAGS 等）与 ToolRegistry 扫描出的
 * 系统工具目录与 PATH，使终端内可直接使用一切已安装的工具——包括
 * `pip install pycryptodome` 等带 C 扩展的第三方库（NDK clang 自动编译）。
 */
class TerminalEngine(
    private val context: Context,
    private val hostTools: HostToolsManager,
    private val ndkManager: NdkManager? = null,
) {

    /* * 终端沙箱：命令/工作目录边界（ 起强制）
     *
     * 首次访问时才创建（不能在构造期访问 TerminalPaths，见下）。
     * 终端 HOME 已统一为设置里的存储目录（WorkDir）——用户在设置页
     * 更改存储目录后无需重启，沙箱根随 homeDir 变化自动重建，
     * 避免旧根固化导致新目录下的命令被误拦。
     */
    @Volatile
    private var sandboxHome: String? = null

    @Volatile
    private var sandboxWorkspace: String? = null

    @Volatile
    private var sandboxInstance: TerminalSandbox? = null

    private val sandbox: TerminalSandbox
        get() {
            val home = TerminalPaths.homeDir.absolutePath
            val workspace = TerminalPaths.workspaceDir.absolutePath
            sandboxInstance?.takeIf {
                sandboxHome == home && sandboxWorkspace == workspace
            }?.let { return it }
            val instance = TerminalSandbox(
                allowedRoots = listOfNotNull(
                    TerminalPaths.homeDir,
                    TerminalPaths.scriptsDir,
                    TerminalPaths.hostToolsRootDir,
                    // 一次性命令的默认工作目录=设置里的工作区目录，须在沙箱白名单内
                    // （否则 AI 保存 Python/JS 等文件到工作区会被 cwd-sandbox 误拦）
                    TerminalPaths.workspaceDir,
                    // NDK 安装目录（允许终端内查看/使用 NDK 工具链）
                    ndkManager?.let { TerminalPaths.ndkRootDir },
                ),
            )
            sandboxInstance = instance
            sandboxHome = home
            sandboxWorkspace = workspace
            return instance
        }

    /** 访问沙箱（供 MCP 工具层查询） */
    val sandboxPolicy: TerminalSandbox get() = sandbox

    /** 终端输出缓冲上限（防止无限增长撑爆内存） */
    private val maxOutputChars = 512 * 1024

    companion object {
        /** 生成会话随机数（5 位 hex，避免与命令输出碰撞）。
         *
         * 修复：`or 0x10000` 保证结果落在 0x10000..0xFFFFE，
         * toHexString 恰好输出 5 位，原实现误用 substring(1, 6)
         * （end=6 超出长度 5）导致 StringIndexOutOfBoundsException，
         * 进入终端界面即崩溃。改用 take(5)+padStart 防御性截取，
         * 任何输入都不会越界。
         */
        private fun newNonce(): String =
            Integer.toHexString((Math.random() * 0xFFFFF).toInt() or 0x10000)
                .take(5)
                .padStart(5, '0')
    }

    /** 构建子进程环境变量（PATH 由 ToolRegistry 汇总全部可用目录） */
    fun buildEnvironment(extra: Map<String, String> = emptyMap()): Map<String, String> {
        val prefixDir = hostTools.getPrefixDir()
        val libDir = File(prefixDir, "lib")

        val env = mutableMapOf<String, String>()

        // NDK 编译工具链：pip-bin wrapper 目录前置到 PATH，
        // 并注入 CC/CXX/AR/RANLIB/CPPFLAGS/LDFLAGS 等变量。
        // distutils/setuptools 会读取这些环境变量覆盖 sysconfig 默认值，
        // 因此 pip install pycryptodome 等带 C 扩展的库会自动用 NDK clang 编译。
        val ndkPathPrefix = ndkManager?.pathPrefixDir()
        env["PATH"] = if (ndkPathPrefix != null) {
            ndkPathPrefix.absolutePath + ":" + ToolRegistry.buildPath(prefixDir)
        } else {
            ToolRegistry.buildPath(prefixDir)
        }

        // HOME / TMPDIR：shell 运行环境固定在应用私有目录（保持完成标记与
        // 换行回车行为稳定）；文件落盘位置由 cwd（homeDir=工作区目录）决定。
        env["HOME"] = TerminalPaths.shellHomeDir.absolutePath
        env["TMPDIR"] = TerminalPaths.tmpDir.absolutePath

        // LD_LIBRARY_PATH
        if (libDir.exists()) {
            env["LD_LIBRARY_PATH"] = libDir.absolutePath
        }

        // Host Tools 专属环境（GIT_EXEC_PATH / PYTHONHOME / SSL 证书等）
        env.putAll(hostTools.getEnvironment())

        // NDK 编译环境（CC/CXX/AR/RANLIB/STRIP/CPPFLAGS/LDFLAGS/ANDROID_NDK_HOME 等）
        ndkManager?.getEnvironment()?.let { env.putAll(it) }

        // 用户额外环境
        env.putAll(extra)

        return env
    }

    /**
     * 一次性执行命令。
     *
     * @param command 要执行的命令（交给 sh -c）
     * @param workingDir 工作目录（默认 HOME）
     * @param env 额外环境变量
     * @param timeoutMs 超时（毫秒），超时后强制终止并返回 timedOut=true
     */
    suspend fun execute(
        command: String,
        workingDir: File? = null,
        env: Map<String, String> = emptyMap(),
        timeoutMs: Long = 60_000,
    ): TerminalResult {
        // 默认工作目录 = 设置里的工作区目录（AI 保存的 Python/JS 等文件落在其中）。
        // 仅作用于一次性执行（不经回显标记机制，共享存储 cwd 无换行问题）；
        // 交互式会话的 cwd 仍固定为私有 homeDir，保证换行回车正常。
        val resolvedDir = workingDir ?: TerminalPaths.workspaceDir

        // ---- 沙箱前校验：cwd 越界 / 禁止命令 / 危险模式直接拒绝 ----
        val decision = sandbox.check(command, resolvedDir)
        if (decision.status == TerminalSandbox.Status.DENY) {
            return TerminalResult(
                command = command,
                output = "[沙箱拦截] ${decision.reason}\n" +
                    "（匹配规则: ${decision.matchedRule}）",
                exitCode = -1,
            )
        }

        return withContext(Dispatchers.IO) {
        val process = ProcessBuilder("/system/bin/sh", "-c", command)
            .apply {
                directory(resolvedDir)
                environment().putAll(buildEnvironment(env))
                redirectErrorStream(true)
            }
            .start()

        val output = StringBuilder()
        val reader = process.inputStream.bufferedReader()
        val readJob = launch(Dispatchers.IO) {
            try {
                while (true) {
                    val line = reader.readLine() ?: break
                    output.append(line).append('\n')
                    // （P0-2 修复）：一次性命令输出加上限。原读循环无任何
                    // 限制——cat 一个大文件 / ls -R / find / 会把 StringBuilder
                    // 无限撑爆直到 Android 堆 OOM 崩溃整个进程。超限即截断并
                    // 强杀子进程（不再继续产出）。
                    if (output.length > maxOutputChars) {
                        output.append("\n[输出已达 ${maxOutputChars} 字符上限被截断，进程已终止。建议改用 file.read 分页或输出重定向到文件]\n")
                        runCatching { process.destroyForcibly() }
                        break
                    }
                }
            } catch (_: Exception) {
                // 进程被终止时读取中断
            }
        }

        val finished = try {
            process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)
        } catch (e: InterruptedException) {
            process.destroyForcibly()
            false
        }

        if (!finished) {
            process.destroyForcibly()
            readJob.cancel()
            TerminalResult(command, output.toString(), -1, timedOut = true)
        } else {
            readJob.join()
            TerminalResult(command, output.toString(), process.exitValue(), timedOut = false)
        }
        }
    }

    /**
     * 以 argv 直传方式执行命令（报告 P0-7：绕过 shell 二次解释）。
     *
     * 与 [execute]（sh -c 语义，命令字符串交给 shell）不同，本方法把
     * 解释器/脚本/参数作为独立 argv 交给 ProcessBuilder——路径或参数含
     * `$`、反引号、`"`、反斜杠、换行或空格时，不会被 shell 二次解释或注入。
     * 用于 runNode / runScript 等"解释器 + 脚本文件 + 参数"场景，天然防盗
     * 与畸形参数导致的静默错位。
     */
    suspend fun executeList(
        command: List<String>,
        workingDir: File? = null,
        env: Map<String, String> = emptyMap(),
        timeoutMs: Long = 60_000,
    ): TerminalResult {
        if (command.isEmpty()) return TerminalResult("", "空命令", -1)
        val display = command.joinToString(" ")
        // 默认工作目录=工作区目录（仅一次性执行；交互式会话 cwd 仍固定为私有 homeDir）
        val resolvedDir = workingDir ?: TerminalPaths.workspaceDir
        val decision = sandbox.check(display, resolvedDir)
        if (decision.status == TerminalSandbox.Status.DENY) {
            return TerminalResult(
                command = display,
                output = "[沙箱拦截] ${decision.reason}\n（匹配规则: ${decision.matchedRule}）",
                exitCode = -1,
            )
        }
        return withContext(Dispatchers.IO) {
            val process = ProcessBuilder(command).apply {
                directory(resolvedDir)
                environment().putAll(buildEnvironment(env))
                redirectErrorStream(true)
            }.start()
            val output = StringBuilder()
            val reader = process.inputStream.bufferedReader()
            val readJob = launch(Dispatchers.IO) {
                try {
                    while (true) {
                        val line = reader.readLine() ?: break
                        output.append(line).append('\n')
                        // （P0-2 修复）：argv 直传执行同样施加输出上限（防 OOM）
                        if (output.length > maxOutputChars) {
                            output.append("\n[输出已达 ${maxOutputChars} 字符上限被截断，进程已终止]\n")
                            runCatching { process.destroyForcibly() }
                            break
                        }
                    }
                } catch (_: Exception) {
                    // 进程被终止时读取中断
                }
            }
            val finished = try {
                process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)
            } catch (e: InterruptedException) {
                process.destroyForcibly()
                false
            }
            if (!finished) {
                process.destroyForcibly()
                readJob.cancel()
                TerminalResult(display, output.toString(), -1, timedOut = true)
            } else {
                readJob.join()
                TerminalResult(display, output.toString(), process.exitValue(), timedOut = false)
            }
        }
    }

    /**
     * 解析 Python 解释器：Host Tools 优先，其次系统/其他来源（ToolRegistry）。
     */
    fun resolvePython(): File? =
        ToolRegistry.resolveAny("python3", "python", hostPrefix = hostTools.getPrefixDir())
            ?: hostTools.getPythonPath()

    /**
     * 执行 Python 代码。
     *
     * 将代码写入临时文件后执行，避免命令行转义问题。
     * 解释器经 ToolRegistry 全来源解析（Host Tools → 系统 → Termux），
     * 已安装即直接使用，不强制重新安装。
     */
    suspend fun runPython(
        code: String,
        args: List<String> = emptyList(),
        workingDir: File? = null,
        timeoutMs: Long = 120_000,
    ): TerminalResult {
        val python = resolvePython()
            ?: return TerminalResult(
                command = "python3",
                output = "错误: 未找到 python 解释器。已扫描 Host Tools / 系统目录 / Termux。\n" +
                    "可用 terminal.which python3 查看解析情况，或 terminal.install 安装。",
                exitCode = -1,
            )

        val scriptFile = File(TerminalPaths.tmpDir, "py_${System.currentTimeMillis()}.py")
        return try {
            scriptFile.writeText(code)
            val cmd = buildString {
                append("\"${python.absolutePath}\" \"${scriptFile.absolutePath}\"")
                for (a in args) {
                    append(" \"").append(a.replace("\"", "\\\"")).append("\"")
                }
            }
            execute(cmd, workingDir, timeoutMs = timeoutMs)
        } finally {
            scriptFile.delete()
        }
    }

    /**
     * 解析 Node 解释器：Host Tools 优先，其次系统/其他来源（ToolRegistry）。
     *
     * 应用内置终端可执行 node（沙箱 ALLOWLIST 已含 node/nodejs），
     * 未安装时可用 terminal.install nodejs 从 Termux 源安装。
     */
    fun resolveNode(): File? =
        ToolRegistry.resolveAny("node", "nodejs", hostPrefix = hostTools.getPrefixDir())

    /**
     * 执行 Node 代码（真实 Node 执行器）。
     *
     * 将代码写入临时文件后执行，避免命令行转义问题。
     * 先跑 `node --check` 做真实语法校验（等价于外部 node --check），
     * 语法通过后再执行。执行环境经 buildEnvironment 自动带上 OPENSSL_CONF，
     * 修复 Termux 版 node 读取 /data/data/com.termux/... 权限不足的问题。
     */
    suspend fun runNode(
        code: String,
        args: List<String> = emptyList(),
        workingDir: File? = null,
        timeoutMs: Long = 120_000,
        checkSyntax: Boolean = true,
    ): NodeRunResult {
        val node = resolveNode()
            ?: return NodeRunResult(
                syntaxValid = false,
                output = "错误: 未找到 node 解释器。已扫描 Host Tools / 系统目录 / Termux。\n" +
                    "可用 terminal.which node 查看解析情况，或 terminal.install nodejs 安装。",
                exitCode = -1,
            )

        val scriptFile = File(TerminalPaths.tmpDir, "node_${System.currentTimeMillis()}.js")
        return try {
            scriptFile.writeText(code)

            // 1) 真实 node --check 语法校验（argv 直传，不经 shell）
            var syntaxValid = true
            var syntaxOutput = ""
            if (checkSyntax) {
                val check = executeList(
                    listOf(node.absolutePath, "--check", scriptFile.absolutePath),
                    workingDir,
                    timeoutMs = 30_000,
                )
                syntaxValid = check.exitCode == 0
                syntaxOutput = check.output
                if (!syntaxValid) {
                    return NodeRunResult(
                        syntaxValid = false,
                        syntaxOutput = syntaxOutput,
                        output = syntaxOutput,
                        exitCode = check.exitCode,
                    )
                }
            }

            // 2) 执行（argv 直传：node <script> [args...]，参数含任何特殊字符均不被二次解释）
            val result = executeList(
                listOf(node.absolutePath, scriptFile.absolutePath) + args,
                workingDir,
                timeoutMs = timeoutMs,
            )
            NodeRunResult(
                syntaxValid = true,
                syntaxOutput = syntaxOutput,
                output = result.output,
                exitCode = result.exitCode,
                timedOut = result.timedOut,
            )
        } finally {
            scriptFile.delete()
        }
    }

    /**
     * 执行脚本文件（Python / Shell）。
     *
     * 根据扩展名选择解释器：.py → python（ToolRegistry 解析），其他 → sh。
     */
    suspend fun runScript(
        scriptPath: String,
        args: List<String> = emptyList(),
        workingDir: File? = null,
        timeoutMs: Long = 120_000,
    ): TerminalResult {
        val file = File(scriptPath)
        if (!file.exists()) {
            return TerminalResult(scriptPath, "错误: 脚本不存在: $scriptPath", -1)
        }
        return if (file.extension.lowercase() == "py") {
            val python = resolvePython()
                ?: return TerminalResult(
                    scriptPath,
                    "错误: 未找到 python 解释器（已扫描 Host Tools / 系统目录 / Termux），" +
                        "可用 terminal.install 安装。",
                    -1,
                )
            val cmd = listOf(python.absolutePath, file.absolutePath) + args
            executeList(cmd, workingDir, timeoutMs = timeoutMs)
        } else {
            val sh = ToolRegistry.resolve("sh", hostPrefix = hostTools.getPrefixDir())
                ?: File("/system/bin/sh")
            val cmd = listOf(sh.absolutePath, file.absolutePath) + args
            executeList(cmd, workingDir, timeoutMs = timeoutMs)
        }
    }

    /**
     * 创建交互式 shell 会话（终端 UI 使用）。
     *
     * 机制重构——放弃 `sh -i` + PS1 标记（依赖 mksh 交互行为，
     * 设备差异大且探测易失败，失败即退化为「提示符提前出现/不出现」的兼容模式），
     * 改为 **echo 完成标记注入**，对任何 shell（mksh/toybox/busybox/dash）通用：
     *
     * - 会话启动普通 `sh`（非交互，无 PS1 噪声）；
     * - [TerminalSession.sendInput] 提交命令时自动追加 `; echo __WRE(nonce)__`，
     *   命令（含子进程）执行完毕后标记才输出——输出顺序天然正确：
     *   命令输出 → 完成标记 → shellReady=true → 提示符换行显示；
     * - 未闭合引号/括号经平衡检测进入续行态（awaitingMore=true 显示 `> `），
     *   平衡后才注入标记，避免标记被吞进字符串字面量；
     * - 运行中程序（python REPL / read）的输入不注入、直接透传 stdin。
     */
    fun createSession(workingDir: File? = null): TerminalSession {
        val nonce = newNonce()
        val process = ProcessBuilder(listOf("/system/bin/sh"))
            .apply {
                directory(workingDir ?: TerminalPaths.homeDir)
                environment().putAll(buildEnvironment())
                redirectErrorStream(true)
            }
            .start()
        return TerminalSession(
            process,
            maxOutputChars,
            markerP1 = "__WRE${nonce}__",
        )
    }

    /** 获取可用的 shell 路径（优先 Host Tools 的 sh，其次系统 sh） */
    fun shellPath(): String {
        val hostSh = File(hostTools.getPrefixDir(), "bin/sh")
        return if (hostSh.exists()) hostSh.absolutePath else "/system/bin/sh"
    }

    /** 获取 python3 路径（未安装返回 null；全来源解析） */
    fun pythonPath(): String? = resolvePython()?.absolutePath

    /** 获取 git 路径（未安装返回 null；全来源解析） */
    fun gitPath(): String? =
        (ToolRegistry.resolve("git", hostPrefix = hostTools.getPrefixDir())
            ?: hostTools.getGitPath())?.absolutePath
}

/** 命令执行结果 */
data class TerminalResult(
    val command: String,
    val output: String,
    val exitCode: Int,
    val timedOut: Boolean = false,
)

/* * Node 执行结果（真实 node --check + 执行） */
data class NodeRunResult(
    val syntaxValid: Boolean,
    val syntaxOutput: String = "",
    val output: String = "",
    val exitCode: Int = 0,
    val timedOut: Boolean = false,
)

/** 终端输出行（终端式控制台模型：区分错误输出与用户输入回显） */
data class TerminalLine(
    val text: String,
    val isError: Boolean = false,
    val isInput: Boolean = false,
)

/**
 * 交互式 shell 会话。
 *
 * 沙盒 I/O 方式（借鉴 NdkCompiler RuntimeEngine）：
 * - 字符流读取（非按行）：printf/echo -n 等无换行的提示文本也能实时显示
 * - 部分行追加：无 \n 的输出追加到上一行末尾，后续输出拼接到同一行
 * - 输入回显：用户输入追加到不完整的提示行末尾，模拟真实终端"提示+输入"效果
 * - stdin 保持开放：支持运行中交互式输入（sendInput）与 EOF（closeStdin）
 * - 输出行模型：TerminalLine(text, isError, isInput)，UI 可区分着色
 *
 * 标记模式（markerP1/markerP2 非空时启用）：
 * - `sh -i` 就绪时输出 PS1 标记 → shellReady=true，并强制完成当前行
 *   （即“命令输出未以 \n 结尾时自动换行再显示提示符”，如 curl -s 的输出）
 * - 需要续行（引号/for-do/heredoc 未闭合）时输出 PS2 标记 → awaitingMore=true
 * - 程序运行中（含 read -p 等待输入）无标记 → 不渲染提示符，输入直接
 *   追加到当前行，行为与真实终端一致
 * - 会话内 cd、环境变量等状态在命令间保持，模拟真实终端体验
 */
class TerminalSession(
    private val process: Process,
    private val maxOutputChars: Int = 512 * 1024,
    private val markerP1: String? = null,
    private val markerP2: String? = null,
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val _outputLines = MutableStateFlow<List<TerminalLine>>(emptyList())
    val outputLines: StateFlow<List<TerminalLine>> = _outputLines.asStateFlow()

    private val _running = MutableStateFlow(true)
    val running: StateFlow<Boolean> = _running.asStateFlow()

    private val _stdinOpen = MutableStateFlow(true)
    val stdinOpen: StateFlow<Boolean> = _stdinOpen.asStateFlow()

    /** 当前工作目录（用于提示符显示，cd 命令自动更新） */
    private val _cwd = MutableStateFlow(TerminalPaths.homeDir.absolutePath)
    val cwd: StateFlow<String> = _cwd.asStateFlow()

    /** 上一行是否已完成（以 \n 结尾）。标记模式下标记出现也会置 true */
    private val _lastLineComplete = MutableStateFlow(true)
    val lastLineComplete: StateFlow<Boolean> = _lastLineComplete.asStateFlow()

    /** shell 是否就绪等待下一条命令（PS1 标记驱动；标记模式的权威状态） */
    private val _shellReady = MutableStateFlow(true)
    val shellReady: StateFlow<Boolean> = _shellReady.asStateFlow()

    /** shell 是否等待续行（PS2 标记驱动：未闭合的引号/块/heredoc） */
    private val _awaitingMore = MutableStateFlow(false)
    val awaitingMore: StateFlow<Boolean> = _awaitingMore.asStateFlow()

    /** 是否至少观测到一个标记（标记模式确认生效） */
    private val _markerSeen = MutableStateFlow(markerP1 == null)
    val markerSeen: StateFlow<Boolean> = _markerSeen.asStateFlow()

    /** 标记模式是否启用 */
    val markerMode: Boolean get() = markerP1 != null

    /**
     * 挂起的输出尾巴：可能是一个未完整到达的标记前缀。
     * 若下一段输出证明它不是标记，会作为普通文本补发。
     */
    private var pendingTail = StringBuilder()

    /**
     * 未完成命令的累计缓冲（续行态）：
     * 用户输入未闭合引号/括号/操作符时逐行累计，整体平衡后才注入完成标记。
     */
    private var pendingCommand = StringBuilder()

    /** 线程安全的输出缓冲，统一收集 stdout / stderr / 用户输入 */
    private val outputBuffer = java.util.Collections.synchronizedList(mutableListOf<TerminalLine>())

    /** mksh 无 tty 运行时的启动告警，直接吞掉不显示 */
    private val suppressPatterns = listOf(
        "can't access tty", "cannot access tty", "job control turned off",
        "won't have full job control",
    )

    /**
     * 判断命令文本是否「完整可执行」：
     * - 引号（'…"）闭合；
     * - 括号 ( [ { 深度归零；
     * - 行尾无续行语义（反斜杠 / 管道 / && / ||）。
     *
     * 不完整时 shell 会等待续行（PS2 语义），此时不能注入完成标记
     * （否则标记会被吞进字符串字面量或管道右操作数）。
     */
    private fun isCommandBalanced(cmd: String): Boolean {
        var singleQuote = false
        var doubleQuote = false
        var escape = false
        var depth = 0
        var i = 0
        while (i < cmd.length) {
            val c = cmd[i]
            if (escape) {
                escape = false
            } else when {
                singleQuote -> if (c == '\'') singleQuote = false
                doubleQuote -> when (c) {
                    '\\' -> escape = true
                    '"' -> doubleQuote = false
                }
                else -> when (c) {
                    '\\' -> escape = true
                    '\'' -> singleQuote = true
                    '"' -> doubleQuote = true
                    '(', '[', '{' -> depth++
                    ')', ']', '}' -> depth--
                    // 注释：非引号状态下「空白/行首 + #」到行尾忽略
                    // （${#var}、$#、a#b 均不满足前导空白条件，不受影响）
                    '#' -> {
                        val prev = if (i > 0) cmd[i - 1] else ' '
                        if (prev == ' ' || prev == '\t' || prev == '\n') {
                            val nl = cmd.indexOf('\n', i)
                            i = if (nl < 0) cmd.length else nl
                        }
                    }
                }
            }
            i++
        }
        if (singleQuote || doubleQuote || escape || depth > 0) return false
        val trimmed = cmd.trimEnd()
        if (trimmed.isEmpty()) return true
        // 行尾续行操作符：shell 等待后续输入
        if (trimmed.endsWith("|") || trimmed.endsWith("&&") || trimmed.endsWith("||")) return false
        return true
    }

    /**
     * 构造注入完成标记的写入行（分号直连，不使用块包裹）。
     *
     * `cmd; echo MARKER` 是同一逻辑行：shell 一次性读入解析后才执行，
     * 后续 stdin（read 的输入 / python REPL 的输入）不会被标记污染；
     * 而独立标记行会被交互程序当作输入消费、块包裹 `{ cmd; }` 会因
     * shell 预读 stdin 缓冲导致块内 read 读不到输入（dash/mksh 实测）。
     *
     * - 尾部 `;`：复用已有分隔符（`echo hi;; echo M` 非法 → `echo hi; echo M`）；
     * - 尾部 `&`：后台命令后直连（`sleep 5 & echo M` 合法，标记立即输出）；
     * - 空行：仅注入标记（提示符重现）。
     */
    private fun buildInjectedLine(line: String): String {
        val marker = markerP1 ?: return line
        val trimmed = line.trimEnd()
        return when {
            trimmed.isEmpty() -> "echo $marker"
            trimmed.endsWith(";") || trimmed.endsWith("&") -> "$trimmed echo $marker"
            else -> "$trimmed; echo $marker"
        }
    }

    /** 向 shell 发送一行输入（自动追加换行，并回显到控制台） */
    fun sendInput(line: String) {
        if (!process.isAlive || !_stdinOpen.value) return
        try {
            // ---- 1. 判定输入路径：shell 命令（就绪/续行） vs 运行中程序的输入 ----
            val commandPath = markerMode && (_shellReady.value || _awaitingMore.value)
            var balanced = true
            val toWrite: String = if (commandPath) {
                if (pendingCommand.isNotEmpty()) pendingCommand.append('\n')
                pendingCommand.append(line)
                balanced = isCommandBalanced(pendingCommand.toString())
                if (balanced) {
                    // 完整命令（含续行拼接完成）：分号直连注入标记。
                    // 续行场景下与先前行拼成同一逻辑行 `...line; echo M`，
                    // shell 一次解析，标记不会被交互程序当作输入消费。
                    pendingCommand.setLength(0)
                    buildInjectedLine(line)
                } else {
                    // 未闭合：原样发送，shell 等待续行（PS2 语义），不注入标记
                    line
                }
            } else {
                // 运行中程序（python REPL / read / heredoc 内容）：直接透传 stdin
                line
            }

            // ---- 2. 写入 stdin ----
            process.outputStream.write((toWrite + "\n").toByteArray(Charsets.UTF_8))
            process.outputStream.flush()

            // ---- 3. cd 命令更新当前目录（提示符随之变化）----
            resolveCd(line)?.let { _cwd.value = it }

            // ---- 4. 回显（须在状态迁移前计算，反映提交前的提示符状态）----
            val echo = when {
                markerMode && _awaitingMore.value -> "> $line"
                markerMode && _shellReady.value -> promptText() + " " + line
                markerMode -> line
                _lastLineComplete.value -> promptText() + " " + line
                else -> line
            }

            // ---- 5. 状态迁移：命令已提交 → 等待完成标记；未闭合 → 续行态 ----
            if (commandPath) {
                _shellReady.value = false
                _awaitingMore.value = !balanced
            }
            appendInputLine(echo)
        } catch (_: Exception) {
            _stdinOpen.value = false
        }
    }

    init {
        // stdout 字符流读取（实时显示无换行提示；stderr 已 redirectErrorStream 合并）
        scope.launch {
            try {
                val reader = process.inputStream.bufferedReader()
                val charBuffer = CharArray(1024)
                var read: Int
                while (reader.read(charBuffer).also { read = it } != -1) {
                    if (read > 0) {
                        appendOutputText(String(charBuffer, 0, read), isError = false)
                    }
                }
            } catch (_: Exception) {
                // 进程被终止时读取中断
            } finally {
                _running.value = false
            }
        }
    }

    /**
     * 追加程序输出文本（可能包含多行、不完整的行或提示符标记）。
     *
     * 处理管线：
     * 1. 与挂起的尾巴拼接；
     * 2. 提取 PS1/PS2 标记：标记前的文本按普通输出渲染，
     *    标记本身触发状态迁移（shellReady / awaitingMore + 强制换行）；
     * 3. 尾部若为标记的可能前缀则挂起等待下一段；
     * 4. 其余按行模型渲染（遇 \n 完成行；无 \n 追加到上一行末尾）。
     */
    private fun appendOutputText(text: String, isError: Boolean) {
        if (text.isEmpty()) return
        synchronized(outputBuffer) {
            var data = pendingTail.toString() + text
            pendingTail.setLength(0)

            // ---- 标记提取 ----
            if (markerP1 != null) {
                while (true) {
                    val i1 = data.indexOf(markerP1)
                    val i2 = markerP2?.let { data.indexOf(it) } ?: -1
                    val idx = when {
                        i1 < 0 && i2 < 0 -> break
                        i1 < 0 -> i2
                        i2 < 0 -> i1
                        else -> minOf(i1, i2)
                    }
                    // 标记前的文本正常渲染
                    emitRawLines(data.substring(0, idx), isError)
                    val markerLen = if (idx == i1) markerP1.length else (markerP2?.length ?: 0)
                    data = data.substring(idx + markerLen)
                    val isP1 = idx == i1
                    onMarker(isP1)
                }
                // 挂起可能成为标记前缀的尾巴
                val hold = longestMarkerPrefixSuffix(data)
                if (hold > 0) {
                    pendingTail.append(data.substring(data.length - hold))
                    data = data.substring(0, data.length - hold)
                }
            }

            emitRawLines(data, isError)
            trimBuffer()
            _outputLines.value = outputBuffer.toList()
        }
    }

    /** 标记到达：PS1 = shell 就绪；PS2 = 等待续行 */
    private fun onMarker(isP1: Boolean) {
        _markerSeen.value = true
        // 标记意味着 shell 接管了输出：上一行视为已完成（自动换行的核心）
        _lastLineComplete.value = true
        if (isP1) {
            _shellReady.value = true
            _awaitingMore.value = false
        } else {
            _awaitingMore.value = true
            _shellReady.value = false
        }
    }

    /**
     * data 尾部是否可能是标记的（不完整）前缀：返回应挂起的长度。
     * 例：marker="__WRPa3f9c__ "，data 以 "__WRPa3" 结尾 → 挂起 7 字符。
     */
    private fun longestMarkerPrefixSuffix(data: String): Int {
        val maxCheck = minOf(data.length, ((markerP1?.length ?: 0)).let { m ->
            maxOf(m, markerP2?.length ?: 0)
        })
        for (len in maxCheck downTo 1) {
            val suffix = data.substring(data.length - len)
            if (markerP1 != null && markerP1.startsWith(suffix)) return len
            if (markerP2 != null && markerP2.startsWith(suffix)) return len
        }
        return 0
    }

    /** 按行模型渲染原始文本（无标记语义） */
    private fun emitRawLines(text: String, isError: Boolean) {
        if (text.isEmpty()) return
        var remaining = text
        while (remaining.isNotEmpty()) {
            val nlIndex = remaining.indexOf('\n')
            if (nlIndex == -1) {
                val segment = remaining.replace("\r", "")
                appendSegment(segment, isError, complete = false)
                remaining = ""
            } else {
                val segment = remaining.substring(0, nlIndex).replace("\r", "")
                appendSegment(segment, isError, complete = true)
                remaining = remaining.substring(nlIndex + 1)
            }
        }
    }

    /** 追加一段（行或行片段），吞掉 mksh 启动告警 */
    private fun appendSegment(segment: String, isError: Boolean, complete: Boolean) {
        if (complete) {
            if (suppressPatterns.any { segment.contains(it, ignoreCase = true) }) {
                _lastLineComplete.value = true
                return
            }
        }
        if (segment.isNotEmpty()) {
            if (!_lastLineComplete.value && outputBuffer.isNotEmpty()) {
                val last = outputBuffer.last()
                outputBuffer[outputBuffer.lastIndex] = last.copy(text = last.text + segment)
            } else {
                outputBuffer.add(TerminalLine(segment, isError = isError))
            }
        }
        if (complete) {
            _lastLineComplete.value = true
        } else if (segment.isNotEmpty()) {
            _lastLineComplete.value = false
        }
    }

    /** 追加用户输入行（终端式回显：追加到不完整提示行末尾） */
    private fun appendInputLine(text: String) {
        synchronized(outputBuffer) {
            if (!_lastLineComplete.value && outputBuffer.isNotEmpty()) {
                val last = outputBuffer.last()
                outputBuffer[outputBuffer.lastIndex] =
                    last.copy(text = last.text + text, isInput = false)
            } else {
                outputBuffer.add(TerminalLine(text, isInput = true))
            }
            _lastLineComplete.value = true
            trimBuffer()
            _outputLines.value = outputBuffer.toList()
        }
    }

    /** 裁剪最旧的输出，防止内存无限增长 */
    private fun trimBuffer() {
        var total = 0
        var dropCount = 0
        for (i in outputBuffer.indices.reversed()) {
            total += outputBuffer[i].text.length
            if (total > maxOutputChars) {
                dropCount = i + 1
                break
            }
        }
        if (dropCount > 0) {
            repeat(dropCount) { outputBuffer.removeAt(0) }
        }
    }

    /** 终端提示符文本：home 显示 ~，其他显示完整路径，末尾加 $ */
    fun promptText(): String {
        val c = _cwd.value
        val display = if (c == TerminalPaths.homeDir.absolutePath) "~" else c
        return "$display \$"
    }

    /** 解析 cd 命令的目标路径；非 cd 命令返回 null */
    private fun resolveCd(command: String): String? {
        val trimmed = command.trim()
        if (trimmed == "cd") return TerminalPaths.homeDir.absolutePath
        if (!trimmed.startsWith("cd ")) return null
        val target = trimmed.substring(3).trim().trim('"', '\'')
        if (target.isEmpty()) return TerminalPaths.homeDir.absolutePath
        val resolved = when {
            target == "~" -> TerminalPaths.homeDir.absolutePath
            target.startsWith("~/") -> File(TerminalPaths.homeDir, target.substring(2)).absolutePath
            target.startsWith("/") -> target
            else -> File(_cwd.value, target).absolutePath
        }
        return normalizePath(resolved)
    }

    /** 规范化路径（解析 . 和 ..） */
    private fun normalizePath(path: String): String {
        val parts = mutableListOf<String>()
        path.split("/").forEach { p ->
            when (p) {
                "", "." -> {}
                ".." -> if (parts.isNotEmpty()) parts.removeAt(parts.size - 1)
                else -> parts.add(p)
            }
        }
        return "/" + parts.joinToString("/")
    }

    /** 关闭标准输入（发送 EOF），通知程序输入结束 */
    fun closeStdin() {
        if (!_stdinOpen.value) return
        try {
            process.outputStream.close()
        } catch (_: Exception) {
            // 忽略
        }
        _stdinOpen.value = false
        synchronized(outputBuffer) {
            outputBuffer.add(TerminalLine("[EOF] 标准输入已关闭", isInput = true))
            _lastLineComplete.value = true
            _outputLines.value = outputBuffer.toList()
        }
    }

    /** 终止会话 */
    fun kill() {
        try {
            process.destroyForcibly()
        } catch (_: Exception) {
            // 忽略
        }
        _stdinOpen.value = false
        _running.value = false
        scope.cancel()
    }

    /** 清空输出缓冲 */
    fun clear() {
        synchronized(outputBuffer) {
            outputBuffer.clear()
            _lastLineComplete.value = true
            _outputLines.value = emptyList()
        }
    }

    /** 会话是否仍在运行 */
    val isAlive: Boolean get() = process.isAlive
}
