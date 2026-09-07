package com.webreverse.mcp.mcp.tools.terminal

import android.content.Context
import android.os.Build
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.File

/**
 * Host Tools 管理器。
 *
 * 管理 Git、Python、Perl 等工具的安装与状态。
 * 从 Termux 官方软件源下载预编译 .deb 包，解压到应用私有目录。
 *
 * Termux 已完成上述工具在 Android 平台的全架构交叉编译，
 * 直接提取二进制打包即可使用。
 *
 * 安装目录结构（镜像 Termux 的 /data/data/com.termux/files/usr/）：
 * - prefix/bin/     — git, python3, perl 等可执行文件
 * - prefix/lib/     — 共享库 (.so)
 * - prefix/libexec/ — git-core 子命令 (git-submodule 等)
 * - prefix/share/   — 数据文件 (git-core/templates 等)
 * - prefix/etc/     — 配置文件 (SSL 证书等)
 */
class HostToolsManager(private val context: Context) {

    private val _state = MutableStateFlow<HostToolsState>(HostToolsState.NotInstalled)
    val state: StateFlow<HostToolsState> = _state.asStateFlow()

    /**
     * 最近一次实际命中的软件源 base。
     * 记录真正下载索引/包用到的源（中科大镜像或官方源），
     * 供 UI 动态展示"来源"，避免硬编码文案误导用户以为总走官方源。
     */
    private val _lastRepoBase = MutableStateFlow<String?>(null)
    val lastRepoBase: StateFlow<String?> = _lastRepoBase.asStateFlow()

    /** 记录最近一次实际使用的软件源 base。 */
    fun setRepoBase(base: String) {
        _lastRepoBase.value = base
    }

    /** 将软件源 base 转成可读标签（供 UI 展示）。 */
    fun repoBaseLabel(base: String?): String = when {
        base == null -> "中科大镜像优先" // 尚未安装时展示默认策略
        base.contains("ustc.edu.cn") -> "中科大镜像"
        base.contains("nju.edu.cn") -> "南京大学镜像"
        base.contains("packages.termux.dev") -> "Termux 官方软件源"
        else -> base
    }

    companion object {
        /**
         * Termux 软件源基础 URL 列表（按优先级尝试）。
         * 清华镜像 termux 仓库已停止同步（数据停在 2021 年）且对部分网络返回
         * HTTP 403，故替换为同步最新的中科大镜像（首选）与南京大学镜像（备选），
         * 官方源 https://packages.termux.dev 仅作最后兜底。
         * 下载索引时按序尝试，任一成功即用该源拉取后续 .deb，保证索引与包同源。
         */
        val TERMUX_REPO_BASES = listOf(
            "https://mirrors.ustc.edu.cn/termux/apt/termux-main",
            "https://mirror.nju.edu.cn/termux/apt/termux-main",
            "https://packages.termux.dev/apt/termux-main",
        )

        /** Termux 软件源基础 URL（默认先走中科大镜像，官方源兜底详见 [TERMUX_REPO_BASES]）。 */
        const val TERMUX_REPO_BASE: String = "https://mirrors.ustc.edu.cn/termux/apt/termux-main"

        /**
         * PyPI 源（pip 安装 Python 库）。
         * 默认切换为清华镜像 https://pypi.tuna.tsinghua.edu.cn/simple，
         * 国内网络下 pip 安装更快更稳；支持安装任意 Python 库（crypto、
         * pycryptodome、requests、cryptography、pycparser 等），
         * 与官方 PyPI 完整兼容（包名/版本与官方一致，仅镜像分发）。
         */
        const val PIP_INDEX_URL = "https://pypi.tuna.tsinghua.edu.cn/simple"

        /** Termux 安装前缀（.deb 包内文件的根路径） */
        const val TERMUX_PREFIX = "data/data/com.termux/files/usr"

        /**
         * 默认安装的 .deb 包列表。
         *
         * - git: 版本控制（git clone / submodule）
         * - perl: git-submodule 等子命令的运行时依赖
         * - python: Python 解释器（AI 测试 Python 代码的核心）
         * - python-pip: pip 包管理器（pip install 任意 Python 库）
         */
        val REQUIRED_PACKAGES = listOf("git", "perl", "python", "python-pip")

        /**
         * 常用额外工具包推荐列表（供 UI 快速安装使用）。
         */
        val RECOMMENDED_PACKAGES = listOf(
            "make", "gawk", "pkg-config", "autoconf", "automake",
            "libtool", "sed", "grep", "tar", "coreutils",
            "curl", "wget", "zip", "unzip", "nodejs",
        )

        /**
         * 获取设备架构对应的 Termux 架构名。
         */
        fun getTermuxArch(): String {
            val abi = Build.SUPPORTED_ABIS.firstOrNull() ?: "arm64-v8a"
            return when {
                abi.startsWith("arm64") -> "aarch64"
                abi.startsWith("arm") -> "arm"
                abi.startsWith("x86_64") -> "x86_64"
                abi.startsWith("x86") -> "i686"
                else -> "aarch64"
            }
        }

        /** 获取 Packages 索引文件 URL（gzip 压缩） */
        fun getPackagesIndexUrl(arch: String): String {
            return "$TERMUX_REPO_BASE/dists/stable/main/binary-$arch/Packages.gz"
        }
    }

    /**
     * 检测已安装的 Host Tools。
     */
    fun detectInstalled() {
        val prefixDir = TerminalPaths.hostToolsPrefixDir
        if (!prefixDir.exists() || prefixDir.list()?.isEmpty() != false) {
            _state.value = HostToolsState.NotInstalled
            return
        }

        val binDir = File(prefixDir, "bin")
        if (!binDir.exists()) {
            _state.value = HostToolsState.NotInstalled
            return
        }

        val gitPath = findExecutable(binDir, "git")
        val pythonPath = findPython(binDir)
        val perlPath = findExecutable(binDir, "perl")

        // git 是必须的，没有 git 视为未安装
        if (gitPath == null) {
            _state.value = HostToolsState.NotInstalled
            return
        }

        val arch = getTermuxArch()
        val additionalPackages = getInstalledAdditionalPackages()
        _state.value = HostToolsState.Installed(
            prefixDir = prefixDir,
            gitPath = gitPath,
            pythonPath = pythonPath,
            perlPath = perlPath,
            arch = arch,
            additionalPackages = additionalPackages,
        )
    }

    /** 磁盘级 Host Tools 核心是否已装（不依赖内存状态，重启/安装失败后仍可靠）。
     *
     * 判断“Host Tools 核心（git 等）是否已实际落地到磁盘”。
     * 即使上次附加包安装失败把 StateFlow 置为 Failed，只要 git 二进制还在，
     * 就视为核心已装，后续 install 走增量安装而非全量重建，避免重复下载 Host Tools。
     */
    fun isCoreInstalledOnDisk(): Boolean {
        val prefixDir = TerminalPaths.hostToolsPrefixDir
        if (!prefixDir.isDirectory) return false
        val binDir = File(prefixDir, "bin")
        return binDir.isDirectory && File(binDir, "git").isFile
    }

    /** 在目录中查找指定名称的可执行文件 */
    private fun findExecutable(dir: File, name: String): File? {
        if (!dir.exists() || !dir.isDirectory) return null
        val file = File(dir, name)
        if (file.exists() && file.isFile) {
            if (!file.canExecute()) {
                file.setExecutable(true, false)
            }
            return file
        }
        return null
    }

    /** 查找 Python 解释器（python3.X 或 python3） */
    private fun findPython(binDir: File): File? {
        if (!binDir.exists()) return null
        val pythonVersioned = binDir.listFiles()
            ?.filter { it.name.matches(Regex("python3\\.\\d+")) && it.isFile }
            ?.maxByOrNull { it.name.substringAfter("python3.").toIntOrNull() ?: 0 }
        if (pythonVersioned != null) {
            if (!pythonVersioned.canExecute()) {
                pythonVersioned.setExecutable(true, false)
            }
            return pythonVersioned
        }
        return findExecutable(binDir, "python3")
    }

    /** 获取 prefix 目录 */
    fun getPrefixDir(): File = TerminalPaths.hostToolsPrefixDir

    /** 获取 git 可执行文件路径 */
    fun getGitPath(): File? {
        val current = _state.value
        return if (current is HostToolsState.Installed) current.gitPath else null
    }

    /** 获取 python3 可执行文件路径 */
    fun getPythonPath(): File? {
        val current = _state.value
        return if (current is HostToolsState.Installed) current.pythonPath else null
    }

    /** 获取 perl 可执行文件路径 */
    fun getPerlPath(): File? {
        val current = _state.value
        return if (current is HostToolsState.Installed) current.perlPath else null
    }

    /** Host Tools 是否已安装 */
    fun isInstalled(): Boolean = _state.value is HostToolsState.Installed

    /** 获取额外安装包清单文件 */
    fun getAdditionalPackagesFile(): File {
        return File(TerminalPaths.hostToolsPrefixDir, ".additional_packages")
    }

    /** 读取已安装的额外包列表 */
    fun getInstalledAdditionalPackages(): List<String> {
        synchronized(packageLock) {
            val file = getAdditionalPackagesFile()
            if (!file.exists()) return emptyList()
            return try {
                file.readLines().map { it.trim() }.filter { it.isNotBlank() }
            } catch (_: Exception) {
                emptyList()
            }
        }
    }

    /** 同步锁，保证额外包清单文件的读写线程安全 */
    private val packageLock = Any()

    /** 追加记录一个额外安装的包名到清单文件 */
    fun addAdditionalPackage(packageName: String) {
        synchronized(packageLock) {
            val current = getInstalledAdditionalPackages().toMutableList()
            if (packageName !in current) {
                current.add(packageName)
                getAdditionalPackagesFile().writeText(current.joinToString("\n"))
            }
        }
    }

    /**
     * 获取环境变量配置，用于注入到子进程。
     *
     * 关键：Termux 的 git/python 编译时 prefix 硬编码为 /data/data/com.termux/files/usr，
     * 迁移到应用私有目录后，必须通过环境变量告知工具新的路径。
     */
    fun getEnvironment(): Map<String, String> {
        val prefixDir = TerminalPaths.hostToolsPrefixDir
        val binDir = File(prefixDir, "bin")
        val libDir = File(prefixDir, "lib")
        val gitCoreDir = File(prefixDir, "libexec/git-core")
        val templateDir = File(prefixDir, "share/git-core/templates")
        val certFile = File(prefixDir, "etc/tls/cert.pem")

        val env = mutableMapOf<String, String>()

        // PATH
        env["HOST_TOOLS_BIN"] = binDir.absolutePath

        // LD_LIBRARY_PATH
        env["HOST_TOOLS_LIB"] = libDir.absolutePath

        // GIT_EXEC_PATH: git 查找 git-submodule 等子命令的目录
        if (gitCoreDir.exists()) {
            env["GIT_EXEC_PATH"] = gitCoreDir.absolutePath
        }

        // GIT_TEMPLATE_DIR: git init / clone 复制模板的来源
        if (templateDir.exists()) {
            env["GIT_TEMPLATE_DIR"] = templateDir.absolutePath
        }

        // SSL 证书
        if (certFile.exists()) {
            env["SSL_CERT_FILE"] = certFile.absolutePath
            env["GIT_SSL_CAINFO"] = certFile.absolutePath
        }

        // PYTHONHOME 和 PYTHONPATH
        val pythonPath = getPythonPath()
        if (pythonPath != null) {
            env["PYTHONHOME"] = prefixDir.absolutePath
            val libPythonDir = File(libDir, "python3")
            if (libPythonDir.exists()) {
                libPythonDir.listFiles()?.forEach { verDir ->
                    if (verDir.name.matches(Regex("3\\.\\d+"))) {
                        val sitePackages = File(verDir, "site-packages")
                        if (sitePackages.exists()) {
                            env["PYTHONPATH"] = sitePackages.absolutePath
                        }
                    }
                }
            }
        }

        // PERL5LIB
        val perlPath = getPerlPath()
        if (perlPath != null) {
            val perl5LibPaths = findPerlLibPaths(libDir)
            if (perl5LibPaths.isNotEmpty()) {
                env["PERL5LIB"] = perl5LibPaths.joinToString(":")
            }
        }

        // OPENSSL_CONF：修复 Termux 版 node 的 OpenSSL 配置权限问题。
        // Termux 源编译的 node 把 OpenSSL 配置路径硬编码为
        // /data/data/com.termux/files/usr/etc/tls/openssl.cnf（Termux 私有目录），
        // 应用进程无权读取，导致 `node --check` / `node` 直接报
        // "OpenSSL configuration error ... Permission denied ... fopen(..., rb)"。
        // 显式设置 OPENSSL_CONF 指向应用自有前缀下的配置文件（缺失则生成最小配置），
        // 让 node 及所有 OpenSSL 工具读取应用可读的配置。
        val opensslConf = File(prefixDir, "etc/tls/openssl.cnf")
        if (!opensslConf.exists()) {
            runCatching {
                opensslConf.parentFile?.mkdirs()
                opensslConf.writeText(
                    """
                    # WebReverse MCP 自有的最小 OpenSSL 配置
                    # 修复 Termux 版 node 默认读取 /data/data/com.termux/... 权限不足的问题
                    openssl_conf = openssl_init

                    [openssl_init]
                    providers = provider_sect

                    [provider_sect]
                    default = default_sect

                    [default_sect]
                    activate = 1
                    """.trimIndent(),
                )
            }
        }
        if (opensslConf.exists()) {
            env["OPENSSL_CONF"] = opensslConf.absolutePath
        }

        return env
    }

    /** 扫描 prefix/lib/perl5 目录，构建 PERL5LIB 路径列表 */
    private fun findPerlLibPaths(libDir: File): List<String> {
        val perl5Dir = File(libDir, "perl5")
        if (!perl5Dir.exists() || !perl5Dir.isDirectory) return emptyList()

        val paths = mutableListOf<String>()
        val versionDirs = perl5Dir.listFiles()
            ?.filter { it.isDirectory && it.name.matches(Regex("\\d+\\.\\d+\\.\\d+")) }
            ?.sortedByDescending { it.name }
            ?: return emptyList()

        for (verDir in versionDirs) {
            val verName = verDir.name
            val sitePerlVerDir = File(perl5Dir, "site_perl/$verName")
            if (sitePerlVerDir.isDirectory) {
                findArchDir(sitePerlVerDir)?.let { paths.add(it.absolutePath) }
                paths.add(sitePerlVerDir.absolutePath)
            }
            findArchDir(verDir)?.let { paths.add(it.absolutePath) }
            paths.add(verDir.absolutePath)
        }
        return paths
    }

    /** 在版本目录下查找架构相关子目录（如 aarch64-android） */
    private fun findArchDir(versionDir: File): File? {
        if (!versionDir.isDirectory) return null
        versionDir.listFiles()?.forEach { subDir ->
            if (subDir.isDirectory &&
                File(subDir, "Config.pm").exists() &&
                File(subDir, "Config_heavy.pl").exists()
            ) {
                return subDir
            }
        }
        return null
    }

    fun setState(state: HostToolsState) {
        _state.value = state
    }

    /** 卸载 Host Tools */
    fun uninstall() {
        TerminalPaths.deleteRecursively(TerminalPaths.hostToolsPrefixDir)
        TerminalPaths.deleteRecursively(TerminalPaths.hostToolsRootDir)
        TerminalPaths.deleteRecursively(TerminalPaths.hostToolsDownloadDir)
        TerminalPaths.hostToolsRootDir.mkdirs()
        TerminalPaths.hostToolsPrefixDir.mkdirs()
        _state.value = HostToolsState.NotInstalled
    }
}
