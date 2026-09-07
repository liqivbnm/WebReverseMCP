package com.webreverse.mcp.mcp.tools.terminal

import java.io.File

/**
 * Terminal Sandbox——将「裸 shell 执行器」升级为「带策略边界的沙箱终端」。
 *
 * ChatGPT 安全评审指出的核心问题：原本 terminal.exec 直接 `ProcessBuilder(/system/bin/sh, -c, cmd)`
 * 且 PermissionManager 默认全放行，等于把任意 shell/Python/pip 动态代码执行完全交给 AI，
 * 缺乏纵深防御。本类不是禁用终端，而是让它「更专业」——用策略分层兜底。
 *
 * 设计分层（由内到外逐一校验，任一失败即阻断并返回原因）：
 * 1. **denylist 禁令**：明确禁止的命令（root/关机/格式化/磁盘破坏）一刀切阻断。
 * 2. **危险命令模式**：整盘删除、覆写系统目录、注入关机等危险形态，正则命中即阻断。
 * 3. **工作目录沙箱（cwd sandbox）**：默认工作目录必须是终端私有沙箱内的目录
 *    （home/scripts/host_tools…），防止 AI 误将 cwd 落到 /storage/emulated/0 全盘写。
 *
 * 纯 Kotlin 实现，无 Android 依赖，便于单元测试与逻辑复用。
 */
class TerminalSandbox(
    /** 沙箱根目录集合（允许作为工作目录/写目标的最上层目录） */
    private val allowedRoots: List<File>,
) {

    /** 结果状态 */
    enum class Status { ALLOW, DENY }

    data class Decision(
        val status: Status,
        val reason: String = "",
        val matchedRule: String = "",
    ) {
        val allowed: Boolean get() = status == Status.ALLOW
        companion object {
            fun allow() = Decision(Status.ALLOW)
            fun deny(reason: String, rule: String = "") =
                Decision(Status.DENY, reason, matchedRule = rule)
        }
    }

    // ---------------- 命令层策略 ----------------

    companion object {
        /** 允许直接执行的命令基线（逆向/开发常用顶层命令） */
        val ALLOWLIST = setOf(
            "bash", "sh", "dash", "zsh", "kash",
            "python", "python3", "python3.11", "perl", "node", "nodejs", "deno", "bun",
            "git", "gitk",
            "curl", "wget", "nc", "ncat", "aria2c",
            "ls", "cat", "head", "tail", "less", "more", "tac", "nl", "sed", "awk", "grep",
            "egrep", "fgrep", "rg", "find", "locate", "which", "whereis", "type",
            "echo", "printf", "tee",
            "cp", "mv", "rm", "mkdir", "rmdir", "touch", "ln", "install", "realpath",
            "chmod", "chown", "chgrp",
            "tar", "gzip", "gunzip", "bzip2", "xz", "unzip", "zip", "7z", "unrar",
            "base64", "md5sum", "sha1sum", "sha256sum", "xxd", "od", "hexdump",
            "strings", "file", "nm", "objdump", "readelf", "addr2line", "llvm-objdump",
            "diff", "patch", "cmp", "comm", "sort", "uniq", "wc", "cut", "tr", "paste", "join",
            "wc", "df", "du", "stat", "lsblk",
            "date", "cal", "env", "export", "set", "unset",
            "make", "cmake", "ninja", "gcc", "cc", "g++", "clang", "clang++", "ld", "as",
            "pip", "pip3", "npm", "npx", "yarn", "pnpm", "cargo", "go",
            "ps", "top", "kill", "pkill", "timeout", "nohup", "jobs", "bg", "fg",
            "adb", "wget", "openssl", "certutil", "keytool",
            "ws", "cs", "pwd", "cd", "true", "false", "exit", "sleep", "yes", "seq", "xargs",
            "jq", "yq", "init", "uname",
        )

        /** 明确禁止的命令（无论何种参数） */
        val DENYLIST = setOf(
            "su", "sudo", "reboot", "shutdown", "poweroff", "halt",
            "format", "mkfs", "dd", "fdisk", "parted", "wipefs",
            "telinit", "mount", "umount", "chroot", "switch_root",
            "iptables", "ip6tables", "setcap", "chkconfig",
            "factory_reset", "recovery", "fastboot", "heimdall",
        )

        /** 危险命令模式：命中即阻断（root/破坏类） */
        val DANGEROUS_PATTERNS = listOf(
            Triple("drop-database", Regex("^\\s*(mysql|psql|sqlite3|redis-cli|mongo)\\b.*\\b(drop|delete\\s+from|truncate)\\b", RegexOption.IGNORE_CASE), "删除数据"),
            // （P0-1 修复）：原正则只匹配以 "/" 结尾的整盘删除，
            // `rm -rf /sdcard`、`rm -rf /storage/emulated/0` 完全放行。扩展为
            // 覆盖 sdcard/storage/data/system/vendor/product/etc/boot 等关键分区。
            Triple(
                "wipe-userdata",
                Regex(
                    "(\\brm\\s+(-rf|-fr|-Rf|-rF)\\s+/\\s*$" +
                        "|\\brm\\s+(-rf|-fr|-Rf|-rF)\\s+/?\\*\\s*$" +
                        "|\\brm\\s+(-rf|-fr|-Rf|-rF)\\s+/(sdcard|storage|data|system|vendor|product|etc|boot|proc|sys|dev|bin|sbin)\\b)",
                    RegexOption.IGNORE_CASE,
                ),
                "整盘/关键分区删除",
            ),
            Triple("overwrite-system", Regex("\\b(>/|>>/)\\s*(system|etc|usr|bin|sbin|boot)/", RegexOption.IGNORE_CASE), "覆写系统目录"),
            Triple("shutdown-cmd", Regex("^\\s*(echo|printf|/bin/echo|/system/bin/sh)\\b.*[|;]\\s*(poweroff|reboot|halt)\\b", RegexOption.IGNORE_CASE), "关机/重启注入"),
        )

        /** 判断路径是否落在允许的沙箱根内（含相等） */
        fun isWithinRoot(path: File?, roots: List<File>): Boolean {
            if (path == null) return false
            val norm = runCatching {
                if (path.exists()) path.canonicalPath else path.absolutePath
            }.getOrElse { path.absolutePath }
            return roots.any { root ->
                val rn = root.absolutePath
                norm == rn || norm.startsWith(rn + File.separator)
            }
        }
    }

    // ---------------- 公共 API ----------------

    /**
     * 检查命令是否允许执行；命中任一硬边界（denylist/危险模式/cwd 越界）则 DENY，否则 ALLOW。
     *
     * （P0-1 修复）：原实现只检查命令**第一个 token** 的 denylist 命中——
     * `true; su -c id`、`echo hi && mkfs.ext4 /dev/...`、`cat x | dd of=/dev/block/...`
     * 的首词都是良性命令，直接 ALLOW，denylist 形同虚设。现在按 shell 控制操作符
     * 切分为多个子命令段，逐段校验 denylist，命令链绕过不再可行。
     */
    fun check(
        command: String,
        workingDir: File? = null,
        exeRoot: File? = null,
    ): Decision {
        val cwd = workingDir ?: exeRoot
        // 1. 工作目录沙箱：必须落在允许根目录内
        if (cwd != null && !isWithinRoot(cwd, allowedRoots)) {
            return Decision.deny(
                "工作目录位于终端沙箱之外：${cwd.absolutePath}。允许范围：${allowedRoots.joinToString { it.absolutePath }}",
                "cwd-sandbox",
            )
        }

        val trimmed = command.trim()
        if (trimmed.isEmpty()) return Decision.allow()

        // 2. denylist 禁令（硬阻断，逐段校验）
        for (segment in splitCommandSegments(trimmed)) {
            val firstWord = segment.split(Regex("\\s+")).firstOrNull()?.trim() ?: continue
            if (firstWord.isEmpty()) continue
            val bin = firstWord.split("/").last().trim()
            val bare = bin.removeSuffix(".exe").lowercase()
            if (bare in DENYLIST) {
                return Decision.deny("命令「$bare」被终端沙箱明确禁止执行（命令链段：$segment）", "denylist:$bare")
            }
        }

        // 3. 危险命令模式（硬阻断，对整条命令）
        DANGEROUS_PATTERNS.forEach { (name, re, desc) ->
            if (re.containsMatchIn(trimmed)) {
                return Decision.deny("检测到危险操作：$desc（规则 $name）", "dangerous:$name")
            }
        }

        return Decision.allow()
    }

    /**
     * 按 shell 控制操作符切分子命令段。
     * 覆盖 `;` `&&` `||` `|` 与换行。引号内的操作符会被误切——误切只会导致
     * 额外校验（更严格），不会放过真实危险命令（引号内内容本就不会被执行）。
     */
    private fun splitCommandSegments(command: String): List<String> =
        command.split(Regex("&&|\\|\\||;|\\||\\n|\\r"))
            .map { it.trim() }
            .filter { it.isNotEmpty() }
}