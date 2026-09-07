package com.webreverse.mcp.mcp.tools.terminal

import java.io.File

/**
 * 通用工具发现注册表。
 *
 * 执行前先
 * 「配置覆盖 → PATH 搜索 → 常见安装位置兜底」解析可执行文件，而不是
 * 一律重新下载安装。
 *
 * 扫描范围（按优先级）：
 * 1. host  — 本应用 Host Tools prefix/bin（Termux .deb 解包，自有安装）
 * 2. system — Android 系统自带（/system/bin 等，toybox/mksh 生态）
 * 3. root  — root 方案目录（magisk/su，通常仅 rooted 设备可读）
 * 4. termux — 已安装的 Termux（Android 10+ 受 SELinux 限制多数不可读，
 *    但部分设备/旧系统可直通，扫描失败自动跳过）
 *
 * 终端 exec / run_python / run_script / install 均先经 ToolRegistry 解析，
 * 已存在的工具直接使用，只有全部来源都找不到时才提示安装。
 */
object ToolRegistry {

    /** 工具来源 */
    const val SRC_HOST = "host"
    const val SRC_SYSTEM = "system"
    const val SRC_ROOT = "root"
    const val SRC_TERMUX = "termux"

    /** 系统级候选目录（存在才纳入 PATH） */
    private val SYSTEM_BIN_DIRS = listOf(
        "/system/bin", "/system/xbin", "/vendor/bin",
        "/system_ext/bin", "/oem/bin",
    )

    /** root 方案候选目录 */
    private val ROOT_BIN_DIRS = listOf(
        "/sbin", "/su/bin", "/magisk/.core/bin", "/debug_ramdisk/su/bin",
    )

    /** Termux 候选目录（多用户场景 /data/user/N/... 与 /data/data/... 等价） */
    private val TERMUX_BIN_DIRS = listOf(
        "/data/data/com.termux/files/usr/bin",
        "/data/user/0/com.termux/files/usr/bin",
    )

    /**
     * 常用工具名清单（terminal.list_tools / which 的默认扫描集）。
     * 覆盖逆向工作流高频命令：下载、脚本、文本处理、二进制查看、构建。
     */
    val COMMON_TOOLS: List<String> = listOf(
        // shell 与基础
        "sh", "bash", "toybox", "busybox", "mksh",
        // 解释器与运行时
        "python3", "python", "pip", "pip3", "node", "npm", "perl", "ruby", "php", "lua",
        // 下载与网络
        "curl", "wget", "openssl", "ssh", "scp", "tcpdump", "ping", "nslookup",
        // 文本/数据处理
        "grep", "sed", "awk", "jq", "xxd", "hexdump", "diff", "sort", "tr", "cut",
        // 压缩
        "tar", "gzip", "gunzip", "zip", "unzip", "xz", "bzip2",
        // 构建与版本控制
        "git", "make", "cmake", "clang", "gcc", "cc", "ld", "ar",
        // 数据库与杂项
        "sqlite3", "file", "stat", "find", "which",
    )

    /**
     * Termux 包名 -> 提供的命令（terminal.install 跳过已装包的判定依据）。
     */
    val PACKAGE_COMMANDS: Map<String, List<String>> = mapOf(
        "git" to listOf("git"),
        "perl" to listOf("perl"),
        "python" to listOf("python3", "python"),
        "python-pip" to listOf("pip", "pip3"),
        "python-static" to listOf("python3", "python"),
        "nodejs" to listOf("node", "npm", "npx"),
        "nodejs-lts" to listOf("node", "npm", "npx"),
        "curl" to listOf("curl"),
        "wget" to listOf("wget"),
        "make" to listOf("make"),
        "cmake" to listOf("cmake"),
        "clang" to listOf("clang", "gcc"),
        "jq" to listOf("jq"),
        "openssh" to listOf("ssh", "scp"),
        "openssl" to listOf("openssl"),
        "sqlite" to listOf("sqlite3"),
        "zip" to listOf("zip"),
        "unzip" to listOf("unzip"),
        "coreutils" to listOf("stat", "sort", "tr", "cut"),
        "grep" to listOf("grep"),
        "sed" to listOf("sed"),
        "gawk" to listOf("awk"),
        "busybox" to listOf("busybox"),
        "hexyl" to listOf("hexyl"),
    )

    /** 一个已发现的工具 */
    data class ToolEntry(
        val name: String,
        val path: String,
        val source: String,
    )

    /** 候选目录（含来源标注），host prefix 优先 */
    fun candidateDirs(hostPrefix: File?): List<Pair<File, String>> {
        val dirs = mutableListOf<Pair<File, String>>()
        if (hostPrefix != null) {
            val bin = File(hostPrefix, "bin")
            if (bin.isDirectory) dirs.add(bin to SRC_HOST)
        }
        SYSTEM_BIN_DIRS.forEach { d -> if (File(d).isDirectory) dirs.add(File(d) to SRC_SYSTEM) }
        ROOT_BIN_DIRS.forEach { d -> if (File(d).isDirectory && File(d).canRead()) dirs.add(File(d) to SRC_ROOT) }
        TERMUX_BIN_DIRS.forEach { d ->
            val f = File(d)
            // canExecute 对不可访问目录返回 false，自动过滤 SELinux 拒绝的场景
            if (f.isDirectory && f.canRead()) dirs.add(f to SRC_TERMUX)
        }
        return dirs
    }

    /** 扫描常用工具（带 5s 结果缓存，避免每次调用全盘 IO） */
    @Volatile
    private var cache: Pair<Long, List<ToolEntry>>? = null
    private const val CACHE_MS = 5_000L

    fun scan(hostPrefix: File? = null, refresh: Boolean = false): List<ToolEntry> {
        val now = System.currentTimeMillis()
        if (!refresh) {
            cache?.let { (ts, entries) ->
                if (now - ts < CACHE_MS) return entries
            }
        }
        val dirs = candidateDirs(hostPrefix)
        val found = mutableListOf<ToolEntry>()
        val seen = mutableSetOf<String>()
        for (name in COMMON_TOOLS) {
            for ((dir, src) in dirs) {
                val f = File(dir, name)
                if (f.isFile && (f.canExecute() || runCatching { f.setExecutable(true, false) }.getOrDefault(false))) {
                    found.add(ToolEntry(name, f.absolutePath, src))
                    seen.add(name)
                    break // 高优先级来源命中即可
                }
            }
        }
        cache = now to found
        return found
    }

    /** 解析单个命令名 -> 可执行文件（host → system → root → termux） */
    fun resolve(name: String, hostPrefix: File? = null): File? {
        if (name.isBlank()) return null
        // 含路径分隔符：直接按文件处理
        if (name.contains('/')) {
            val f = File(name)
            return f.takeIf { it.isFile && it.canExecute() }
        }
        val dirs = candidateDirs(hostPrefix)
        for ((dir, _) in dirs) {
            val f = File(dir, name)
            if (f.isFile && (f.canExecute() || runCatching { f.setExecutable(true, false) }.getOrDefault(false))) {
                return f
            }
        }
        return null
    }

    /** 解析多个候选名（如 python3 / python），返回第一个命中 */
    fun resolveAny(vararg names: String, hostPrefix: File? = null): File? {
        for (n in names) {
            resolve(n, hostPrefix)?.let { return it }
        }
        return null
    }

    /** 构建 PATH：host bin 优先，其余存在的目录依次拼接，最后保留原 PATH */
    fun buildPath(hostPrefix: File?): String {
        val parts = candidateDirs(hostPrefix).map { it.first.absolutePath }
        return (parts + "/system/bin" + "/system/xbin" + (System.getenv("PATH") ?: ""))
            .filter { it.isNotBlank() }
            .joinToString(":")
    }

    /** 包名 -> 命令名列表（未映射的包默认提供同名命令） */
    fun commandsOfPackage(pkg: String): List<String> =
        PACKAGE_COMMANDS[pkg] ?: listOf(pkg)

    /** 判定包是否已可用（其任一关键命令可解析即视为可用） */
    fun packageAvailable(pkg: String, hostPrefix: File? = null): List<String> {
        return commandsOfPackage(pkg).filter { resolve(it, hostPrefix) != null }
    }
}
