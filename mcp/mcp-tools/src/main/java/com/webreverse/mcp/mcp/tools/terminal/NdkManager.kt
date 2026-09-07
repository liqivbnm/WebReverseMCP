package com.webreverse.mcp.mcp.tools.terminal

import android.os.Build
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.File

/**
 * 可下载的 NDK 版本信息。
 *
 * @param downloadUrl 官方下载地址（下载源列表的最后一项，兜底）
 * @param mirrorUrls 镜像加速地址列表：下载时按
 *   mirrorUrls + downloadUrl 的顺序逐个尝试，前一个失败自动切换下一个
 *   （与 Host Tools 的镜像回退逻辑一致）
 * @param archiveFormat 压缩格式：zip / tar.xz
 * @param stripComponents 解压时去除的路径层级（tar.xz 通常为 0）
 * @param sizeBytes 归档大小（供 UI 提示，可为 0 表示未知）
 */
data class NdkVersionInfo(
    val name: String,
    val displayName: String,
    val downloadUrl: String,
    val mirrorUrls: List<String> = emptyList(),
    val archiveFormat: String = "zip",
    val stripComponents: Int = 0,
    val sizeBytes: Long = 0,
    val isRecommended: Boolean = false,
) {
    /** 完整下载源列表：镜像优先，GitHub 官方兜底 */
    val downloadUrls: List<String> get() = mirrorUrls + downloadUrl
}

/**
 * 已安装的 NDK 信息。
 */
data class InstalledNdk(
    val dirName: String,
    val ndkPath: File,
    val version: String,
    val binDir: File,
    val isActive: Boolean,
)

/**
 * NDK 管理器（移植自 NdkCompiler 的 NdkManager 并适配 WebReverseMCP）。
 *
 * 职责：
 * - 维护可下载 NDK 版本列表（HomuHomu833/android-ndk-custom，aarch64 设备可本地运行）
 * - 扫描/检测已安装的 NDK（filesDir/ndk 下的多版本共存）
 * - 查找真实 ELF 编译器（clang-XX）——NDK bin 下 clang 是符号链接/包装文件
 * - 生成 pip 编译工具链 wrapper（pip-bin/）：clang/clang++/ar/ranlib/strip/nm/ld
 *   带 --target=aarch64-linux-android24，供 pip 安装 C 扩展（pycryptodome 等）时使用
 * - 构建终端注入的 NDK 环境变量（CC/CXX/AR/RANLIB/STRIP/CPPFLAGS/LDFLAGS 等）
 */
class NdkManager {

    private val _state = MutableStateFlow<NdkState>(NdkState.NotInstalled)
    val state: StateFlow<NdkState> = _state.asStateFlow()

    fun setState(state: NdkState) {
        _state.value = state
    }

    /**
     * 可下载的 NDK 版本列表。
     *
     * 链接沿用 NdkCompiler 的 NDK 下载源（HomuHomu833/android-ndk-custom r29）：
     * 在 Android arm64 设备上本地运行的定制 NDK（LLVM 21，host=linux-arm64），
     * 搭配 Termux python 即可在终端内 pip 编译安装带 C 扩展的第三方库。
     *
     * 下载源按序回退（与 Host Tools 逻辑一致）——
     * gh-proxy.com 镜像 → gh.jasonzeng.dev 镜像 → GitHub 官方（兜底）。
     */
    val availableVersions: List<NdkVersionInfo> = listOf(
        NdkVersionInfo(
            name = "r29-android-aarch64",
            displayName = "Android NDK r29 (aarch64)",
            downloadUrl = "https://github.com/HomuHomu833/android-ndk-custom/releases/download/r29/android-ndk-r29-aarch64-linux-android.tar.xz",
            mirrorUrls = listOf(
                "https://gh-proxy.com/https://github.com/HomuHomu833/android-ndk-custom/releases/download/r29/android-ndk-r29-aarch64-linux-android.tar.xz",
                "https://gh.jasonzeng.dev/https://github.com/HomuHomu833/android-ndk-custom/releases/download/r29/android-ndk-r29-aarch64-linux-android.tar.xz",
            ),
            archiveFormat = "tar.xz",
            stripComponents = 0,
            sizeBytes = 0,
            isRecommended = true,
        ),
    )

    /**
     * 设备架构对应的 Android triple（用于 --target）。
     * Termux python 以 API 24 编译（termux min sdk），编译目标对齐 API 24 保证 libc 兼容。
     */
    fun androidTriple(): String {
        val abi = Build.SUPPORTED_ABIS.firstOrNull() ?: "arm64-v8a"
        return when {
            abi.startsWith("arm64") -> "aarch64-linux-android"
            abi.startsWith("x86_64") -> "x86_64-linux-android"
            abi.startsWith("armeabi") -> "armv7a-linux-androideabi"
            abi.startsWith("x86") -> "i686-linux-android"
            else -> "aarch64-linux-android"
        }
    }

    /** 编译目标 API（对齐 Termux python 的编译 API 级别） */
    val targetApi: Int = 24

    /** 完整 target triple：aarch64-linux-android24 */
    fun targetTriple(): String = "${androidTriple()}$targetApi"

    // ==================== 安装检测 ====================

    /**
     * 扫描 ndkRootDir 下所有已安装的 NDK 版本。
     * 兼容两种布局：versionDir 下直接是 NDK 根，或 versionDir/archiveTopDir 才是 NDK 根。
     */
    fun scanInstalledNdkVersions(): List<InstalledNdk> {
        val result = mutableListOf<InstalledNdk>()
        val activePath = (_state.value as? NdkState.Installed)?.ndkPath
        val rootDir = TerminalPaths.ndkRootDir
        if (!rootDir.isDirectory) return result

        rootDir.listFiles()?.filter { it.isDirectory && it.name != "pip-bin" }?.forEach { subDir ->
            // 布局 1：source.properties 直接在子目录层
            detectNdkInDir(subDir)?.let { ndk ->
                result.add(
                    InstalledNdk(
                        dirName = subDir.name,
                        ndkPath = ndk.first,
                        version = ndk.second,
                        binDir = binDirOf(ndk.first),
                        isActive = ndk.first.absolutePath == activePath,
                    ),
                )
                return@forEach
            }
            // 布局 2：子目录内还有一层归档顶层目录
            subDir.listFiles()?.filter { it.isDirectory }?.forEach { inner ->
                detectNdkInDir(inner)?.let { ndk ->
                    result.add(
                        InstalledNdk(
                            dirName = subDir.name,
                            ndkPath = ndk.first,
                            version = ndk.second,
                            binDir = binDirOf(ndk.first),
                            isActive = ndk.first.absolutePath == activePath,
                        ),
                    )
                }
            }
        }
        return result.sortedBy { it.dirName }
    }

    /**
     * 检测 NDK 安装状态并更新 StateFlow。
     * 扫描 ndkRootDir（含 pip-bin wrapper 重建），无安装则 NotInstalled。
     */
    fun detectInstalled() {
        val installed = scanInstalledNdkVersions()
        if (installed.isEmpty()) {
            _state.value = NdkState.NotInstalled
            return
        }
        // 优先已激活版本，否则选版本号最新的
        val chosen = installed.firstOrNull { it.isActive }
            ?: installed.maxByOrNull { it.version.split(".").firstOrNull()?.toIntOrNull() ?: 0 }
            ?: installed.first()
        _state.value = NdkState.Installed(
            ndkPath = chosen.ndkPath.absolutePath,
            version = chosen.version,
            binDir = chosen.binDir.absolutePath,
            arch = HostToolsManager.getTermuxArch(),
        )
        // 确保 pip 工具链 wrapper 与当前激活版本一致
        runCatching { regeneratePipToolchain() }
    }

    /** 检测目录（或其一层子目录）中是否存在有效 NDK，返回 (ndkPath, version) */
    fun detectNdkInDir(dir: File): Pair<File, String>? {
        if (!dir.isDirectory) return null
        val props = File(dir, "source.properties")
        if (props.isFile) {
            val binDir = binDirOf(dir)
            if (binDir.isDirectory) {
                return dir to (parseNdkVersion(props) ?: dir.name)
            }
        }
        return null
    }

    /**
     * 获取 NDK 工具链 bin 目录：动态探测 host tag
     * （HomuHomu833 r29 为 linux-arm64，termux-ndk 为 linux-aarch64），失败回退按设备架构猜。
     */
    private fun binDirOf(ndkPath: File): File {
        val hostTag = NdkPermissionHelper.detectHostTag(ndkPath) ?: guessHostTag()
        return File(ndkPath, "toolchains/llvm/prebuilt/$hostTag/bin")
    }

    private fun guessHostTag(): String {
        val abi = Build.SUPPORTED_ABIS.firstOrNull() ?: "arm64-v8a"
        return when {
            abi.startsWith("arm64") -> "linux-aarch64"
            abi.startsWith("x86_64") -> "linux-x86_64"
            abi.startsWith("armeabi") -> "linux-arm"
            abi.startsWith("x86") -> "linux-x86"
            else -> "linux-aarch64"
        }
    }

    private fun parseNdkVersion(sourceProps: File): String? {
        return try {
            sourceProps.readLines().firstOrNull { it.startsWith("Pkg.Revision") }
                ?.substringAfter('=')?.trim()
        } catch (_: Exception) {
            null
        }
    }

    /** 获取当前激活 NDK 的安装根（含 source.properties 的目录），未安装返回 null */
    fun getInstalledNdkPath(): File? {
        return (_state.value as? NdkState.Installed)?.let { File(it.ndkPath) }
            ?: scanInstalledNdkVersions().firstOrNull()?.ndkPath
    }

    /** 获取当前激活 NDK 的工具链 bin 目录 */
    fun getBinDir(): File? {
        val ndkPath = getInstalledNdkPath() ?: return null
        val binDir = binDirOf(ndkPath)
        return if (binDir.isDirectory) binDir else null
    }

    /** NDK 是否已安装（磁盘级判断，不依赖内存状态） */
    fun isInstalledOnDisk(): Boolean = getBinDir() != null

    // ==================== 真实编译器查找（移植 NdkCompiler.NdkManager.findRealCompiler） ====================

    /**
     * 查找 bin 目录中真正的 clang 编译器 ELF 二进制文件。
     *
     * NDK bin 目录中 clang 是符号链接 → clang-XX（真实 ELF 二进制）。
     * 按优先级：
     * 1. clang-XX / clang++-XX（真实 ELF 二进制，版本号取最大）
     * 2. clang / clang++（跟随符号链接验证 ELF）
     * 3. 任意 clang* 开头的最大 ELF 文件
     */
    fun findRealCompiler(isCpp: Boolean): File? {
        val binDir = getBinDir() ?: return null
        val allFiles = binDir.listFiles() ?: return null

        val prefix = if (isCpp) "clang++-" else "clang-"
        val versionSuffix = prefix.length
        allFiles
            .filter { it.isFile && it.name.startsWith(prefix) }
            .filter { f -> f.name.length > versionSuffix && f.name[versionSuffix].isDigit() }
            .filter { isElfFile(resolveSymlink(it)) }
            .maxByOrNull { it.name }
            ?.let { return it }

        val fallbackName = if (isCpp) "clang++" else "clang"
        val fallback = File(binDir, fallbackName)
        if (fallback.exists() && isElfFile(resolveSymlink(fallback))) {
            return fallback
        }

        return allFiles
            .filter { it.isFile && it.name.startsWith("clang") && !it.name.endsWith(".sh") }
            .filter { isElfFile(resolveSymlink(it)) }
            .sortedByDescending { it.length() }
            .firstOrNull()
    }

    private fun resolveSymlink(file: File): File {
        return try {
            if (java.nio.file.Files.isSymbolicLink(file.toPath())) {
                file.canonicalFile
            } else {
                file
            }
        } catch (_: Exception) {
            file
        }
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

    // ==================== pip 编译工具链 ====================

    /**
     * 查找 Termux python 的头文件目录（Python.h 所在）：
     * <prefix>/include/python3.X
     */
    fun findPythonIncludeDir(): File? {
        val includeDir = File(TerminalPaths.hostToolsPrefixDir, "include")
        if (!includeDir.isDirectory) return null
        return includeDir.listFiles()
            ?.filter { it.isDirectory && it.name.matches(Regex("python3\\.\\d+")) }
            ?.maxByOrNull { it.name.substringAfter("python3.").toIntOrNull() ?: 0 }
    }

    /**
     * （重新）生成 pip 编译工具链 wrapper 目录（ndkRootDir/pip-bin/）。
     *
     * wrapper 均为 #!/system/bin/sh 脚本，exec 真实 NDK ELF 二进制并显式带
     * --target=<triple>，绕开 NDK wrapper shebang（#!/usr/bin/env sh 在 Android
     * 上不可用）与 argv[0] 丢失问题——与 NdkCompiler CompilerEngine 的核心策略一致。
     *
     * 生成后 pip / distutils 的 CC/CXX（由 TerminalEngine 注入环境变量）即得到
     * 能编译 Android aarch64 代码的 clang，pip install pycryptodome 等带 C 扩展的
     * 库可直接编译。
     *
     * @return wrapper 目录，或 null（NDK 未安装 / 生成失败）
     */
    fun regeneratePipToolchain(): File? {
        val clang = findRealCompiler(isCpp = false)
        val clangxx = findRealCompiler(isCpp = true)
        if (clang == null) return null

        val pipBin = TerminalPaths.ndkPipBinDir
        pipBin.deleteRecursively()
        pipBin.mkdirs()

        val target = targetTriple()
        val ndkBin = clang.parentFile?.absolutePath ?: return null

        // 生成 wrapper：exec 真实 ELF 二进制 + 显式 --target。
        // 注意 $@ 在 Kotlin 中按字面输出（$ 后非标识符字符），无需转义。
        fun execLine(binName: String, extraArgs: String = ""): String =
            "exec \"$ndkBin/$binName\" --target=$target$extraArgs \"\$@\""

        // cc/clang：优先调用真实 clang-XX ELF；clang++ 未探测到时回退用 clang -x c++
        writeWrapper(File(pipBin, "clang"), execLine(clang.name))
        writeWrapper(File(pipBin, "cc"), execLine(clang.name))
        if (clangxx != null) {
            writeWrapper(File(pipBin, "clang++"), execLine(clangxx.name))
            writeWrapper(File(pipBin, "c++"), execLine(clangxx.name))
        } else {
            writeWrapper(File(pipBin, "clang++"), execLine(clang.name, " -x c++"))
            writeWrapper(File(pipBin, "c++"), execLine(clang.name, " -x c++"))
        }

        // binutils（llvm-* 均为真实 ELF 或已修复的 exec -a wrapper，可直接 exec）
        writeWrapper(File(pipBin, "ar"), "exec \"$ndkBin/llvm-ar\" \"\$@\"")
        writeWrapper(File(pipBin, "ranlib"), "exec \"$ndkBin/llvm-ranlib\" \"\$@\"")
        writeWrapper(File(pipBin, "strip"), "exec \"$ndkBin/llvm-strip\" \"\$@\"")
        writeWrapper(File(pipBin, "nm"), "exec \"$ndkBin/llvm-nm\" \"\$@\"")
        writeWrapper(File(pipBin, "readelf"), "exec \"$ndkBin/llvm-readelf\" \"\$@\"")
        writeWrapper(File(pipBin, "objdump"), "exec \"$ndkBin/llvm-objdump\" \"\$@\"")
        if (File(ndkBin, "ld.lld").exists()) {
            writeWrapper(File(pipBin, "ld"), "exec \"$ndkBin/ld.lld\" \"\$@\"")
        }
        return pipBin
    }

    private fun writeWrapper(file: File, execLine: String) {
        file.writeText("#!/system/bin/sh\n$execLine\n")
        file.setExecutable(true, false)
    }

    // ==================== 终端环境注入 ====================

    /**
     * 构建注入终端子进程的 NDK 编译环境变量。
     *
     * distutils/setuptools 的 customize_compiler 会读取 CC/CXX/AR/RANLIB/STRIP/
     * CPPFLAGS/CFLAGS/LDSHARED 等环境变量覆盖 sysconfig 默认值，因此注入这些
     * 变量后 `pip install <带C扩展的库>` 会自动使用 NDK clang 编译。
     *
     * @return 变量表；NDK 未安装时返回空表（不干扰原有终端环境）
     */
    fun getEnvironment(): Map<String, String> {
        if (!isInstalledOnDisk()) return emptyMap()
        val pipBin = TerminalPaths.ndkPipBinDir
        if (!File(pipBin, "clang").isFile) return emptyMap()

        val env = mutableMapOf<String, String>()
        val prefixDir = TerminalPaths.hostToolsPrefixDir

        // 编译器族（distutils 约定的环境变量）
        env["CC"] = File(pipBin, "clang").absolutePath
        env["CXX"] = File(pipBin, "clang++").absolutePath
        env["AR"] = File(pipBin, "ar").absolutePath
        env["RANLIB"] = File(pipBin, "ranlib").absolutePath
        env["STRIP"] = File(pipBin, "strip").absolutePath
        env["NM"] = File(pipBin, "nm").absolutePath
        env["LD"] = File(pipBin, "ld").absolutePath
        env["READELF"] = File(pipBin, "readelf").absolutePath

        // Termux python 的头文件与库路径（Python.h / libpython）
        val cppFlags = StringBuilder()
        findPythonIncludeDir()?.let {
            cppFlags.append("-I${it.absolutePath}")
        }
        val prefixInclude = File(prefixDir, "include")
        if (prefixInclude.isDirectory) {
            if (cppFlags.isNotEmpty()) cppFlags.append(' ')
            cppFlags.append("-I${prefixInclude.absolutePath}")
        }
        if (cppFlags.isNotEmpty()) {
            env["CPPFLAGS"] = cppFlags.toString()
        }
        val prefixLib = File(prefixDir, "lib")
        if (prefixLib.isDirectory) {
            env["LDFLAGS"] = "-L${prefixLib.absolutePath}"
        }

        // 供脚本/用户查询的路径提示
        env["ANDROID_NDK_HOME"] = getInstalledNdkPath()?.absolutePath ?: ""
        env["NDK_TARGET"] = targetTriple()

        return env
    }

    /** NDK 环境的 PATH 前缀目录（pip-bin），TerminalEngine.buildEnvironment 使用 */
    fun pathPrefixDir(): File? {
        val pipBin = TerminalPaths.ndkPipBinDir
        return if (File(pipBin, "clang").isFile) pipBin else null
    }

    // ==================== 卸载 ====================

    /** 卸载 NDK（删除所有版本与 pip 工具链），状态回 NotInstalled */
    fun uninstall() {
        TerminalPaths.deleteRecursively(TerminalPaths.ndkRootDir)
        TerminalPaths.deleteRecursively(TerminalPaths.ndkDownloadDir)
        TerminalPaths.ndkRootDir.mkdirs()
        TerminalPaths.ndkPipBinDir.mkdirs()
        _state.value = NdkState.NotInstalled
    }
}
