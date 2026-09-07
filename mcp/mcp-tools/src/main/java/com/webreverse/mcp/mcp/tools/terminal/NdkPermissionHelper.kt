package com.webreverse.mcp.mcp.tools.terminal

import java.io.File

/**
 * NDK 工具链权限与符号链接包装修复器（移植自 NdkCompiler 的 PermissionHelper）。
 *
 * 背景：
 * 官方 LLVM/NDK 中大量工具依赖符号链接，通过程序名（argv[0]）决定自身工作模式，例如：
 *   ld.lld       -> lld
 *   llvm-ranlib  -> llvm-ar
 *   lld-link     -> lld
 *   wasm-ld      -> lld
 *   clang        -> clang-21
 *   clang++      -> clang-21
 *
 * NDK 归档解压到应用私有目录后，Linux 符号链接可能丢失，表现为两种形态：
 *
 * 1. **文本包装文件**：符号链接变成只含一行目标程序名的普通文本文件，例如：
 *    ld.lld      内容：lld
 *    llvm-ranlib 内容：llvm-ar
 *
 * 2. **空文件**（tar.xz 流式解压时常见）：符号链接变成 0 字节空文件。
 *
 * 解决方案：
 * - 对文本包装文件：直接读取内容作为目标。
 * - 对空文件：使用 [KNOWN_SYMLINK_TARGETS] 已知映射表确定目标；
 *   对 clang/clang++ 动态查找同目录下的 clang-XX ELF 二进制。
 *
 * 然后将包装文件转换为 shell 包装脚本，使用 `exec -a <文件名>` 恢复 argv[0]：
 *   #!/system/bin/sh
 *   DIR=$(cd "$(dirname "$0")" && pwd)
 *   exec -a ld.lld "$DIR/lld" "$@"
 */
object NdkPermissionHelper {

    interface PermissionListener {
        fun onLog(message: String)
    }

    /**
     * NDK 已知符号链接映射表（空文件兜底恢复，移植自 NdkCompiler）。
     */
    private val KNOWN_SYMLINK_TARGETS = mapOf(
        // 链接器：均指向 lld（真实 ELF 二进制）
        "ld.lld" to "lld",
        "ld" to "lld",
        "lld-link" to "lld",
        "wasm-ld" to "lld",
        "ld64.lld" to "lld",
        // LLVM 工具
        "llvm-ranlib" to "llvm-ar",
        "llvm-lib" to "llvm-dlltool",
        "llvm-strip" to "llvm-objcopy",
        "llvm-addr2line" to "llvm-symbolizer",
    )

    /** 需要动态探测目标的工具（clang → clang-XX，版本号随 NDK 版本变化） */
    private val DYNAMIC_SYMLINK_TOOLS = setOf("clang", "clang++")

    /**
     * 修复 NDK 工具链：
     * 1. 扫描 bin 目录，将"伪符号链接"文本文件和空文件转换为带 `exec -a` 的 shell 包装脚本。
     * 2. 遍历 prebuilt 目录，为 bin/libexec 下的文件及无扩展名文件设置可执行权限。
     *
     * host tag 通过扫描 toolchains/llvm/prebuilt/ 动态探测（兼容 linux-arm64 /
     * linux-aarch64 等不同 NDK 来源）。
     *
     * @param ndkPath NDK 根目录（包含 source.properties 与 toolchains/ 目录）
     * @param listener 日志回调，可为 null
     * @return true 表示权限设置全部成功
     */
    fun makeToolchainExecutable(ndkPath: File, listener: PermissionListener?): Boolean {
        val hostTag = detectHostTag(ndkPath)
        if (hostTag == null) {
            listener?.onLog("LLVM prebuilt directory not found under: ${ndkPath.absolutePath}")
            return false
        }
        val llvmDir = File(ndkPath, "toolchains/llvm/prebuilt/$hostTag")

        var wrapperFailed = 0

        val binDir = File(llvmDir, "bin")
        if (binDir.exists() && binDir.isDirectory) {
            listener?.onLog("Fixing LLVM wrapper files in bin directory: ${binDir.absolutePath}")
            listener?.onLog("Total files in bin: ${(binDir.listFiles()?.size ?: 0)}")

            var fixedCount = 0
            var fixedEmptyCount = 0
            var skippedElf = 0
            var skippedScript = 0
            var skippedLarge = 0
            var scanDetailCount = 0

            binDir.listFiles()?.sortedBy { it.name }?.forEach { file ->
                if (file.isFile) {
                    try {
                        // 先用 4 字节 ELF 魔数检查，避免对大文件整体 readBytes 导致 OOM
                        if (isElfFile(file)) {
                            skippedElf++
                            return@forEach
                        }

                        val fileSize = file.length()

                        // 非 ELF 文件：检查是否是伪符号链接文本或已有 shell 脚本
                        if (fileSize > 2048) {
                            skippedLarge++
                            return@forEach
                        }

                        val rawContent = file.readText()
                        val content = rawContent.lines().firstOrNull { it.trim().isNotEmpty() }?.trim() ?: ""

                        // 已有的 shell 脚本（以 #! 开头）跳过
                        if (rawContent.trimStart().startsWith("#!")) {
                            skippedScript++
                            return@forEach
                        }

                        // 详细诊断：前 20 个非 ELF 文件输出详细信息便于排查
                        if (scanDetailCount < 20) {
                            scanDetailCount++
                            val preview = if (content.isEmpty()) "<empty>"
                            else if (content.length > 60) content.take(60) + "..."
                            else content
                            listener?.onLog("[SCAN] ${file.name} size=$fileSize content=\"$preview\"")
                        }

                        val isValidTarget = content.isNotEmpty() &&
                            !content.startsWith("#") &&
                            !content.startsWith("<") &&
                            !content.contains('\u0000') &&
                            content.all { ch ->
                                ch.isLetterOrDigit() || ch == '_' || ch == '-' || ch == '.' || ch == '/'
                            } &&
                            content != file.name

                        if (isValidTarget) {
                            // 情况 1：文本包装文件 —— 内容即为目标名
                            val fileName = file.name
                            val scriptContent = buildWrapperScript(fileName, content)
                            file.writeText(scriptContent, Charsets.UTF_8)
                            file.setExecutable(true, false)
                            fixedCount++
                            listener?.onLog("[FIXED] Converted symlink wrapper: $fileName -> $content")
                        } else if (content.isEmpty()) {
                            // 情况 2：空文件 —— 使用已知映射表恢复符号链接
                            val resolvedTarget = resolveKnownTarget(file.name, binDir)
                            if (resolvedTarget != null) {
                                val scriptContent = buildWrapperScript(file.name, resolvedTarget)
                                file.writeText(scriptContent, Charsets.UTF_8)
                                file.setExecutable(true, false)
                                fixedCount++
                                fixedEmptyCount++
                                listener?.onLog("[FIXED] Empty file restored as symlink wrapper: ${file.name} -> $resolvedTarget")
                            } else {
                                listener?.onLog("[WARN] Empty file with unknown target: ${file.name} (cannot auto-fix)")
                            }
                        }
                    } catch (e: Exception) {
                        wrapperFailed++
                        listener?.onLog("[ERROR] Wrapping file ${file.name} failed: ${e.localizedMessage}")
                    }
                }
            }

            listener?.onLog("--- Scan Summary ---")
            listener?.onLog("ELF binaries skipped: $skippedElf")
            listener?.onLog("Existing shell scripts skipped: $skippedScript")
            listener?.onLog("Large files skipped (>2048B): $skippedLarge")
            listener?.onLog("Symlink wrappers converted (FIXED): $fixedCount")
            listener?.onLog("  - from text content: ${fixedCount - fixedEmptyCount}")
            listener?.onLog("  - from empty files (mapping table): $fixedEmptyCount")
            if (wrapperFailed > 0) {
                listener?.onLog("Wrapper conversion failures: $wrapperFailed")
            }
            listener?.onLog("-------------------")
        }

        listener?.onLog("Scanning and setting executable permissions for toolchain files...")
        var updatedCount = 0
        var failedCount = 0

        llvmDir.walkTopDown().forEach { file ->
            if (file.isFile) {
                val parentName = file.parentFile?.name
                if (parentName == "bin" || parentName == "libexec" || !file.name.contains(".")) {
                    val success = file.setExecutable(true, false)
                    if (success && file.canExecute()) {
                        updatedCount++
                        if (updatedCount <= 15) {
                            listener?.onLog("Successfully set permissions: ${file.name}")
                        }
                    } else {
                        failedCount++
                        listener?.onLog("Failed to set executable on: ${file.name}")
                    }
                }
            }
        }

        listener?.onLog("Permission process completed. Set executable on $updatedCount files. Failures: $failedCount")
        return failedCount == 0 && wrapperFailed == 0
    }

    /**
     * 动态探测 NDK 的 host tag 目录（扫描 toolchains/llvm/prebuilt/ 下含 bin 的子目录）。
     * 兼容 HomuHomu833 r29 (linux-arm64) 与 termux-ndk (linux-aarch64) 等来源。
     */
    fun detectHostTag(ndkPath: File): String? {
        val prebuiltDir = File(ndkPath, "toolchains/llvm/prebuilt")
        if (!prebuiltDir.isDirectory) return null
        prebuiltDir.listFiles()?.forEach { subDir ->
            if (subDir.isDirectory && File(subDir, "bin").exists()) {
                return subDir.name
            }
        }
        return null
    }

    /**
     * 为空文件解析符号链接目标（映射表 + clang-XX 动态探测）。
     */
    private fun resolveKnownTarget(fileName: String, binDir: File): String? {
        KNOWN_SYMLINK_TARGETS[fileName]?.let { target ->
            val targetFile = File(binDir, target)
            if (targetFile.exists() && targetFile.length() > 0) {
                return target
            }
        }

        if (fileName in DYNAMIC_SYMLINK_TOOLS) {
            val searchPrefixes = if (fileName == "clang++") {
                listOf("clang++-", "clang-")
            } else {
                listOf("clang-")
            }
            for (prefix in searchPrefixes) {
                binDir.listFiles()
                    ?.filter { it.isFile && it.name.startsWith(prefix) }
                    ?.filter { isElfFile(it) }
                    ?.maxByOrNull {
                        it.name.substringAfterLast("-").toIntOrNull() ?: 0
                    }
                    ?.let { return it.name }
            }
        }

        return null
    }

    private fun isElfFile(file: File): Boolean {
        if (!file.exists() || file.length() < 4) return false
        return try {
            val header = ByteArray(4)
            file.inputStream().use { input ->
                var bytesRead = 0
                while (bytesRead < 4) {
                    val n = input.read(header, bytesRead, 4 - bytesRead)
                    if (n == -1) break
                    bytesRead += n
                }
                bytesRead == 4 &&
                    header[0] == 0x7f.toByte() &&
                    header[1] == 0x45.toByte() &&
                    header[2] == 0x4c.toByte() &&
                    header[3] == 0x46.toByte()
            }
        } catch (_: Exception) {
            false
        }
    }

    /**
     * 构建带 `exec -a` 的 shell 包装脚本（恢复 argv[0]）。
     */
    private fun buildWrapperScript(fileName: String, target: String): String {
        val targetPath = if (target.startsWith("/")) {
            "\"$target\""
        } else {
            "\"\$DIR/$target\""
        }
        return "#!/system/bin/sh\n" +
            "DIR=\$(cd \"\$(dirname \"\$0\")\" && pwd)\n" +
            "exec -a $fileName $targetPath \"\$@\"\n"
    }
}
