package com.webreverse.mcp.mcp.tools.terminal

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.apache.commons.compress.archivers.ar.ArArchiveInputStream
import org.apache.commons.compress.archivers.tar.TarArchiveEntry
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream
import org.tukaani.xz.XZInputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.zip.GZIPInputStream

/**
 * Host Tools 下载与安装器。
 *
 * 从 Termux 官方软件源下载预编译 .deb 包，解压到应用私有目录。
 *
 * 安装流程：
 * 1. 下载 Termux Packages 索引 (Packages.gz)
 * 2. 解析索引并解析 git/python 的完整依赖链
 * 3. 下载所有 .deb 包
 * 4. 逐个解压 .deb (ar 归档 → data.tar.xz → tar 归档)
 * 5. 修复脚本 shebang（将 Termux 路径替换为本应用路径）
 * 6. 设置可执行权限
 * 7. 创建系统工具符号链接（sh, env, cat 等 → /system/bin/）
 */
class HostToolsDownloader(
    private val context: Context,
    private val manager: HostToolsManager,
) {

    companion object {
        private const val CONNECT_TIMEOUT = 30000
        private const val READ_TIMEOUT = 120000
        private const val BUFFER_SIZE = 64 * 1024
    }

    /** 包信息 */
    data class PackageInfo(
        val name: String,
        val version: String,
        val filename: String,
        val depends: List<List<String>>,
        val provides: List<String>,
        val size: Long,
    )

    /** 待处理的符号链接 */
    private data class SymlinkInfo(
        val linkPath: File,
        val target: String,
        val isAbsolute: Boolean,
    )

    /**
     * 下载并安装 Host Tools。
     */
    suspend fun downloadAndExtract(): Result<File> = withContext(Dispatchers.IO) {
        try {
            manager.setState(HostToolsState.Downloading(0, "正在获取软件包索引..."))

            val arch = HostToolsManager.getTermuxArch()
            val prefixDir = TerminalPaths.hostToolsPrefixDir

            // 清理旧安装（仅冷启动全量重建时刷前缀）。
            // 不再清空下载临时目录——保留上次失败/中断遗留的 .deb，
            // 失败重试时按“文件名+size”直接复用，避免重复下载 python 等大包。
            TerminalPaths.deleteRecursively(prefixDir)
            prefixDir.mkdirs()
            TerminalPaths.hostToolsDownloadDir.mkdirs()

            // 1. 下载并解析 Packages 索引（中科大镜像优先，官方源兜底）
            val source = downloadAndParsePackagesIndex(arch)
            val packagesIndex = source.packages
            // 记录实际命中的软件源，供 UI 展示"来源"
            manager.setRepoBase(source.base)

            // 2. 解析依赖
            val requiredPackages = resolveDependencies(packagesIndex, HostToolsManager.REQUIRED_PACKAGES)

            val totalSize = requiredPackages.sumOf { it.size }
            val sizeStr = TerminalPaths.formatSize(totalSize)
            manager.setState(HostToolsState.Downloading(0, "需下载 ${requiredPackages.size} 个包 ($sizeStr)"))

            // 3. 下载所有 .deb 包
            val debFiles = mutableListOf<File>()
            for ((index, pkg) in requiredPackages.withIndex()) {
                val progress = (index * 100 / requiredPackages.size)
                manager.setState(
                    HostToolsState.Downloading(
                        progress,
                        "下载 ${pkg.name} (${index + 1}/${requiredPackages.size})",
                    ),
                )
                val debFile = downloadDebPackage(pkg, source.base)
                debFiles.add(debFile)
            }

            // 4. 解压所有 .deb 包
            manager.setState(HostToolsState.Extracting(0, "正在解压软件包..."))
            for ((index, debFile) in debFiles.withIndex()) {
                val progress = (index * 100 / debFiles.size)
                manager.setState(
                    HostToolsState.Extracting(
                        progress,
                        "解压: ${debFile.nameWithoutExtension} (${index + 1}/${debFiles.size})",
                    ),
                )
                extractDeb(debFile, prefixDir)
            }

            // 5. 修复 shebang
            manager.setState(HostToolsState.Configuring(0, "修复脚本路径..."))
            fixShebangs(prefixDir)

            // 6. 设置可执行权限
            manager.setState(HostToolsState.Configuring(40, "设置可执行权限..."))
            setExecutablePermissions(prefixDir)

            // 7. 创建系统工具符号链接（sh, env, cat 等 → /system/bin/）
            manager.setState(HostToolsState.Configuring(50, "创建系统工具链接..."))
            createSystemSymlinks(prefixDir)

            // 8. 创建 python3 符号链接
            manager.setState(HostToolsState.Configuring(60, "配置 Python 环境..."))
            ensurePythonSymlink(prefixDir)

            // 9. 检测安装结果
            manager.setState(HostToolsState.Configuring(95, "验证安装..."))
            manager.detectInstalled()

            // 清理下载文件
            TerminalPaths.deleteRecursively(TerminalPaths.hostToolsDownloadDir)

            val state = manager.state.value
            if (state is HostToolsState.Installed) {
                Result.success(state.prefixDir)
            } else {
                Result.failure(Exception("Host Tools 安装完成但未找到 git 可执行文件"))
            }
        } catch (e: Exception) {
            manager.setState(HostToolsState.Failed(e.message ?: "未知错误"))
            Result.failure(e)
        }
    }

    /**
     * 在已有安装基础上安装额外的 Termux 包。
     */
    suspend fun installAdditionalPackages(packageNames: List<String>): Result<List<String>> = withContext(Dispatchers.IO) {
        try {
            val arch = HostToolsManager.getTermuxArch()
            val prefixDir = TerminalPaths.hostToolsPrefixDir
            TerminalPaths.hostToolsDownloadDir.mkdirs()

            manager.setState(HostToolsState.Configuring(0, "正在获取软件包索引..."))

            // 1. 下载并解析 Packages 索引（中科大镜像优先，官方源兜底）
            val source = downloadAndParsePackagesIndex(arch)
            val packagesIndex = source.packages
            // 记录实际命中的软件源，供 UI 展示"来源"
            manager.setRepoBase(source.base)

            // 2. 解析依赖（排除已安装的包，避免重复下载）
            // 修复假成功：原实现盲目把 REQUIRED_PACKAGES 全部加入已装集合——
            // Host Tools 从未引导（prefix 为空）时，请求 python/python-pip 会全部命中
            // "已装"判定而短路返回 success([])，terminal.install 报告"安装完成"却
            // 什么都没装（实测 terminal.exec 里 python3/node 均 inaccessible）。
            // 现按 ToolRegistry 实际解析命令判定：命令在 host/系统/root/Termux
            // 任一来源可解析，该包才算已装。
            val alreadyInstalled = mutableSetOf<String>()
            for (pkg in manager.getInstalledAdditionalPackages()) {
                alreadyInstalled.add(pkg)
            }
            for (pkg in HostToolsManager.REQUIRED_PACKAGES) {
                val cmds = ToolRegistry.commandsOfPackage(pkg)
                if (cmds.isNotEmpty() && cmds.any { ToolRegistry.resolve(it, prefixDir) != null }) {
                    alreadyInstalled.add(pkg)
                }
            }

            val toInstall = packageNames.filter { it !in alreadyInstalled }
            if (toInstall.isEmpty()) {
                manager.setState(HostToolsState.Configuring(100, "所有包已安装"))
                manager.detectInstalled()
                return@withContext Result.success(emptyList())
            }

            manager.setState(HostToolsState.Configuring(10, "解析依赖: ${toInstall.joinToString()}"))
            val requiredPackages = resolveDependencies(packagesIndex, toInstall)

            val newPackages = requiredPackages.filter { it.name !in alreadyInstalled }

            if (newPackages.isEmpty()) {
                manager.setState(HostToolsState.Configuring(100, "所有依赖包已安装"))
                manager.detectInstalled()
                return@withContext Result.success(emptyList())
            }

            val totalSize = newPackages.sumOf { it.size }
            val sizeStr = TerminalPaths.formatSize(totalSize)
            manager.setState(HostToolsState.Downloading(0, "下载 ${newPackages.size} 个包 ($sizeStr)"))

            // 3. 下载所有 .deb 包
            val debFiles = mutableListOf<File>()
            for ((index, pkg) in newPackages.withIndex()) {
                val progress = (index * 100 / newPackages.size)
                manager.setState(
                    HostToolsState.Downloading(
                        progress,
                        "下载 ${pkg.name} (${index + 1}/${newPackages.size})",
                    ),
                )
                val debFile = downloadDebPackage(pkg, source.base)
                debFiles.add(debFile)
            }

            // 4. 解压所有 .deb 包（增量解压，不清理现有文件）
            manager.setState(HostToolsState.Extracting(0, "解压软件包..."))
            for ((index, debFile) in debFiles.withIndex()) {
                val progress = (index * 100 / debFiles.size)
                manager.setState(
                    HostToolsState.Extracting(
                        progress,
                        "解压: ${debFile.nameWithoutExtension} (${index + 1}/${debFiles.size})",
                    ),
                )
                extractDeb(debFile, prefixDir)
            }

            // 5. 后处理（与主安装相同）
            manager.setState(HostToolsState.Configuring(0, "修复脚本路径..."))
            fixShebangs(prefixDir)
            setExecutablePermissions(prefixDir)
            createSystemSymlinks(prefixDir)

            // 6. 记录已安装的额外包
            for (pkgName in toInstall) {
                manager.addAdditionalPackage(pkgName)
            }

            // 7. 清理下载文件
            TerminalPaths.deleteRecursively(TerminalPaths.hostToolsDownloadDir)

            // 8. 重新检测安装状态
            manager.setState(HostToolsState.Configuring(95, "验证安装..."))
            manager.detectInstalled()

            Result.success(toInstall)
        } catch (e: Exception) {
            // 附加包安装失败时，不要把已可用的 Host Tools 核心误判为“未安装”。
            // 回退重新探测磁盘：只要 git 等核心二进制仍在，就保持 Installed 状态，
            // 避免后续 terminal.install 因状态 Failed 而触发全量重建、重复下载 Host Tools。
            // 真正连核心都损坏时（重新探测仍非 Installed）才置 Failed。
            runCatching { manager.detectInstalled() }
            if (manager.state.value !is HostToolsState.Installed) {
                manager.setState(HostToolsState.Failed(e.message ?: "未知错误"))
            }
            Result.failure(e)
        }
    }

    // ==================== Packages 索引 ====================

    /**
     * 索引解析结果：携带实际成功拉取的软件源 base，
     * 后续 .deb 一律从同一源下载，保证索引与包同源、校验一致。
     */
    private data class IndexResult(val base: String, val packages: Map<String, PackageInfo>)

    /**
     * 下载并解析 Termux Packages 索引。
     * 按序尝试镜像源（中科大优先，南大/官方源兜底），
     * 单源网络抖动/暂时不可达时自动切换到下一源，避免整次安装直接失败。
     */
    private fun downloadAndParsePackagesIndex(arch: String): IndexResult {
        var lastError: Exception? = null
        for (base in HostToolsManager.TERMUX_REPO_BASES) {
            try {
                // 尝试从该源下载为临时索引并解析
                val tempIndex = File(TerminalPaths.hostToolsDownloadDir, "Packages.$arch.gz")
                val packages = try {
                    downloadIndex(base, arch, tempIndex)
                } finally {
                    tempIndex.delete()
                }
                if (packages.isNotEmpty()) {
                    return IndexResult(base, packages)
                }
                lastError = Exception("Packages 索引为空或解析失败: $base")
            } catch (e: Exception) {
                lastError = e
            }
        }
        // 所有源均失败
        throw lastError ?: Exception("下载 Packages 索引失败")
    }

    /** 从指定 base 下载并解析 Packages.gz，返回包 map */
    private fun downloadIndex(base: String, arch: String, indexFile: File): Map<String, PackageInfo> {
        val url = "$base/dists/stable/main/binary-$arch/Packages.gz"
        TerminalPaths.hostToolsDownloadDir.mkdirs()

        val connection = (URL(url).openConnection() as HttpURLConnection).apply {
            connectTimeout = CONNECT_TIMEOUT
            readTimeout = READ_TIMEOUT
        }
        try {
            connection.connect()
            if (connection.responseCode != 200) {
                throw Exception("下载 Packages 索引失败: HTTP ${connection.responseCode} ($base)")
            }
            connection.inputStream.use { input ->
                FileOutputStream(indexFile).use { output ->
                    input.copyTo(output, BUFFER_SIZE)
                }
            }
        } finally {
            connection.disconnect()
        }

        // 解压并解析（gzip 格式）
        val packages = mutableMapOf<String, PackageInfo>()
        val providesMap = mutableMapOf<String, String>()

        GZIPInputStream(FileInputStream(indexFile)).use { gzStream ->
            val text = gzStream.bufferedReader().readText()
            for (stanza in text.split("\n\n")) {
                if (stanza.isBlank()) continue
                val pkg = parsePackageStanza(stanza) ?: continue
                packages[pkg.name] = pkg
                for (prov in pkg.provides) {
                    providesMap[prov] = pkg.name
                }
            }
        }

        return packages
    }

    /** 解析单个包 stanza */
    private fun parsePackageStanza(stanza: String): PackageInfo? {
        val fields = mutableMapOf<String, String>()
        var currentKey: String? = null

        for (line in stanza.split("\n")) {
            if (line.isBlank()) continue
            val key = currentKey
            if (line.startsWith(" ") && key != null) {
                fields[key] = (fields[key] ?: "") + "\n" + line.trim()
            } else if (line.contains(":")) {
                val idx = line.indexOf(":")
                val key = line.substring(0, idx).trim()
                val value = line.substring(idx + 1).trim()
                fields[key] = value
                currentKey = key
            }
        }

        val name = fields["Package"] ?: return null
        val version = fields["Version"] ?: ""
        val filename = fields["Filename"] ?: return null

        // 解析 Depends（逗号分隔，可能包含 | 替代依赖）
        val depends = fields["Depends"]?.split(",")?.mapNotNull { dep ->
            val alternatives = dep.trim().split("|").mapNotNull { alt ->
                val depName = alt.trim().split("(")[0].trim()
                if (depName.isNotBlank()) depName else null
            }
            if (alternatives.isNotEmpty()) alternatives else null
        } ?: emptyList()

        // 解析 Provides
        val provides = fields["Provides"]?.split(",")?.mapNotNull { prov ->
            val provName = prov.trim().split("(")[0].trim()
            if (provName.isNotBlank()) provName else null
        } ?: emptyList()

        val size = fields["Size"]?.toLongOrNull() ?: 0L

        return PackageInfo(name, version, filename, depends, provides, size)
    }

    // ==================== 依赖解析 ====================

    /** 递归解析所有依赖 */
    private fun resolveDependencies(
        packagesIndex: Map<String, PackageInfo>,
        rootPackages: List<String>,
    ): List<PackageInfo> {
        val resolved = mutableMapOf<String, PackageInfo>()
        val queue = ArrayDeque<String>()
        val providesMap = mutableMapOf<String, String>()

        for (pkg in packagesIndex.values) {
            for (prov in pkg.provides) {
                providesMap[prov] = pkg.name
            }
        }

        for (pkgName in rootPackages) {
            queue.add(pkgName)
        }

        while (queue.isNotEmpty()) {
            val name = queue.removeFirst()
            if (resolved.containsKey(name)) continue

            var pkg = packagesIndex[name]
            if (pkg == null) {
                val providerName = providesMap[name]
                if (providerName != null) {
                    pkg = packagesIndex[providerName]
                }
            }

            if (pkg == null) {
                continue
            }

            resolved[name] = pkg

            for (depAlternatives in pkg.depends) {
                val depToAdd = depAlternatives.firstOrNull { alt ->
                    packagesIndex.containsKey(alt) || providesMap.containsKey(alt)
                } ?: depAlternatives.firstOrNull()
                if (depToAdd != null && !resolved.containsKey(depToAdd)) {
                    queue.add(depToAdd)
                }
            }
        }

        return resolved.values.toList()
    }

    // ==================== .deb 下载 ====================

    /* * 下载单个 .deb 包（支持缓存复用，失败重试不重复拉取大包） */
    private fun downloadDebPackage(pkg: PackageInfo, base: String): File {
        val targetFile = File(TerminalPaths.hostToolsDownloadDir, File(pkg.filename).name)

        // 缓存复用：已有同名且尺寸匹配的 .deb 直接跳过下载。
        // 只有在之前下载中断/损坏（尺寸为 0 或与索引 Size 不符）时才重新拉取。
        if (targetFile.isFile && targetFile.length() > 0 && (pkg.size <= 0 || targetFile.length() == pkg.size)) {
            return targetFile
        }

        // 尺寸不符：把残缺文件设为可覆盖（先删），重新下载
        if (targetFile.exists()) {
            targetFile.delete()
        }

        val url = "$base/${pkg.filename}"
        val connection = (URL(url).openConnection() as HttpURLConnection).apply {
            connectTimeout = CONNECT_TIMEOUT
            readTimeout = READ_TIMEOUT
        }
        try {
            connection.connect()
            if (connection.responseCode != 200) {
                throw Exception("下载 ${pkg.name} 失败: HTTP ${connection.responseCode}")
            }
            connection.inputStream.use { input ->
                FileOutputStream(targetFile).use { output ->
                    input.copyTo(output, BUFFER_SIZE)
                }
            }
        } finally {
            connection.disconnect()
        }

        if (!targetFile.exists() || targetFile.length() == 0L) {
            targetFile.delete()
            throw Exception("下载的 ${pkg.name} 文件为空")
        }
        // 尺寸校验：索引已知大小且实际不符时，判为损坏，避免解压出残缺文件
        if (pkg.size > 0 && targetFile.length() != pkg.size) {
            targetFile.delete()
            throw Exception("下载的 ${pkg.name} 尺寸不符（应为 ${pkg.size}，实际 ${targetFile.length()}）")
        }

        return targetFile
    }

    // ==================== .deb 解压 ====================

    /** 解压单个 .deb 包到 prefix 目录 */
    private fun extractDeb(debFile: File, prefixDir: File) {
        val tempDir = File(prefixDir, ".tmp_${debFile.nameWithoutExtension}")
        tempDir.mkdirs()
        val pendingSymlinks = mutableListOf<SymlinkInfo>()

        try {
            // Step 1: 从 ar 归档提取 data.tar.*
            var dataTarName: String? = null
            val dataTarFile = File(tempDir, "data.tar")

            FileInputStream(debFile).use { fis ->
                ArArchiveInputStream(fis).use { arStream ->
                    var entry = arStream.nextEntry
                    while (entry != null) {
                        if (entry.name.startsWith("data.tar")) {
                            dataTarName = entry.name
                            FileOutputStream(dataTarFile).use { out ->
                                val buf = ByteArray(BUFFER_SIZE)
                                var n: Int
                                while (arStream.read(buf).also { n = it } != -1) {
                                    out.write(buf, 0, n)
                                }
                            }
                            break
                        }
                        entry = arStream.nextEntry
                    }
                }
            }

            if (dataTarName == null) {
                throw Exception("在 ${debFile.name} 中未找到 data.tar")
            }

            // Step 2: 创建解压流
            FileInputStream(dataTarFile).use { fis ->
                val decompressed = when {
                    dataTarName!!.endsWith(".xz") -> XZInputStream(fis)
                    dataTarName!!.endsWith(".gz") -> GZIPInputStream(fis)
                    dataTarName!!.endsWith(".zst") -> {
                        throw Exception("不支持的压缩格式: $dataTarName (zstd)")
                    }
                    else -> fis
                }

                // Step 3: 解压 tar 归档
                TarArchiveInputStream(decompressed).use { tarStream ->
                    var tarEntry: TarArchiveEntry? = tarStream.nextTarEntry
                    while (tarEntry != null) {
                        processTarEntry(tarEntry, tarStream, prefixDir, pendingSymlinks)
                        tarEntry = tarStream.nextTarEntry
                    }
                }
            }

            // Step 4: 处理符号链接（在所有文件解压完成后）
            for (symlink in pendingSymlinks) {
                createSymlink(symlink, prefixDir)
            }
        } finally {
            tempDir.deleteRecursively()
        }
    }

    /** 处理单个 tar 条目 */
    private fun processTarEntry(
        tarEntry: TarArchiveEntry,
        tarStream: TarArchiveInputStream,
        prefixDir: File,
        pendingSymlinks: MutableList<SymlinkInfo>,
    ) {
        val entryName = tarEntry.name.removePrefix("./")
        // 剥离 Termux 前缀路径
        val termuxPrefix = HostToolsManager.TERMUX_PREFIX
        val relativePath = when {
            entryName.startsWith(termuxPrefix + "/") -> entryName.substringAfter(termuxPrefix + "/")
            entryName == termuxPrefix -> ""
            entryName.startsWith("data/data/com.termux/files/") -> {
                entryName.removePrefix("data/data/com.termux/files/")
            }
            else -> entryName
        }

        if (relativePath.isBlank() || relativePath.startsWith("..")) {
            return
        }

        val outFile = File(prefixDir, relativePath)

        // 安全检查：防止路径穿越
        val canonicalTarget = prefixDir.canonicalFile
        val canonicalOut = outFile.canonicalFile
        if (!canonicalOut.path.startsWith(canonicalTarget.path)) {
            return
        }

        when {
            tarEntry.isSymbolicLink -> {
                val isAbs = tarEntry.linkName.startsWith("/")
                pendingSymlinks.add(SymlinkInfo(outFile, tarEntry.linkName, isAbs))
            }
            tarEntry.isDirectory -> {
                outFile.mkdirs()
            }
            tarEntry.isLink -> {
                // 硬链接：复制目标文件
                val targetName = tarEntry.linkName.removePrefix("./")
                    .removePrefix(termuxPrefix + "/")
                val targetFile = File(prefixDir, targetName)
                if (targetFile.exists()) {
                    outFile.parentFile?.mkdirs()
                    targetFile.copyTo(outFile, overwrite = true)
                    setExecIfBinary(relativePath, outFile)
                }
            }
            else -> {
                // 普通文件
                outFile.parentFile?.mkdirs()
                FileOutputStream(outFile).use { out ->
                    val buf = ByteArray(BUFFER_SIZE)
                    var n: Int
                    while (tarStream.read(buf).also { n = it } != -1) {
                        out.write(buf, 0, n)
                    }
                }
                setExecIfBinary(relativePath, outFile)
            }
        }
    }

    /** 如果文件在 bin/ 或 libexec/ 目录下，设置可执行权限 */
    private fun setExecIfBinary(relativePath: String, file: File) {
        if (relativePath.startsWith("bin/") || relativePath.startsWith("libexec/")) {
            file.setExecutable(true, false)
        }
    }

    /** 创建符号链接，失败时回退为复制文件 */
    private fun createSymlink(symlink: SymlinkInfo, prefixDir: File) {
        val linkPath = symlink.linkPath
        val target = symlink.target

        // 修复绝对路径中的 Termux 前缀
        val fixedTarget = if (target.startsWith("/data/data/com.termux/files/usr/")) {
            File(prefixDir, target.removePrefix("/data/data/com.termux/files/usr/")).absolutePath
        } else if (target.startsWith("/data/data/com.termux/files/")) {
            File(TerminalPaths.hostToolsRootDir, target.removePrefix("/data/data/com.termux/files/")).absolutePath
        } else {
            target
        }

        try {
            if (linkPath.exists()) linkPath.delete()
            linkPath.parentFile?.mkdirs()
            android.system.Os.symlink(fixedTarget, linkPath.absolutePath)
        } catch (e: Exception) {
            // 回退：复制目标文件
            val targetFile = if (target.startsWith("/")) {
                File(fixedTarget)
            } else {
                File(linkPath.parentFile, target)
            }
            val actualTarget = if (target.contains("com.termux")) {
                File(prefixDir, target.substringAfter("usr/"))
            } else {
                targetFile
            }
            if (actualTarget.exists() && actualTarget.isFile) {
                try {
                    actualTarget.copyTo(linkPath, overwrite = true)
                    if (linkPath.absolutePath.contains("/bin/")) {
                        linkPath.setExecutable(true, false)
                    }
                } catch (_: Exception) {
                    // 忽略复制失败
                }
            }
        }
    }

    // ==================== 后处理 ====================

    /**
     * 修复所有脚本中的 shebang。
     * 将 #!/data/data/com.termux/files/usr/ 替换为实际 prefix 路径。
     */
    private fun fixShebangs(prefixDir: File) {
        val termuxPrefix = "/data/data/com.termux/files/usr"
        val actualPrefix = prefixDir.absolutePath

        val scriptDirs = listOf(
            File(prefixDir, "bin"),
            File(prefixDir, "libexec/git-core"),
        )

        for (dir in scriptDirs) {
            if (!dir.exists() || !dir.isDirectory) continue
            dir.listFiles()?.forEach { file ->
                if (!file.isFile) return@forEach
                fixShebangInFile(file, termuxPrefix, actualPrefix)
            }
        }
    }

    /** 修复单个文件的 shebang */
    private fun fixShebangInFile(file: File, termuxPrefix: String, actualPrefix: String) {
        try {
            val firstLine = file.bufferedReader().use { it.readLine() } ?: return
            if (firstLine.startsWith("#!$termuxPrefix")) {
                val newShebang = firstLine.replace(termuxPrefix, actualPrefix)
                val content = file.readText()
                file.writeText(newShebang + "\n" + content.substringAfter("\n"))
                file.setExecutable(true, false)
            }
        } catch (_: Exception) {
            // 忽略二进制文件等无法读取的文件
        }
    }

    /** 设置所有 bin/ 和 libexec/ 目录下文件的可执行权限 */
    private fun setExecutablePermissions(prefixDir: File) {
        val binDir = File(prefixDir, "bin")
        if (binDir.exists()) {
            binDir.listFiles()?.forEach { file ->
                if (file.isFile) {
                    file.setExecutable(true, false)
                }
            }
        }

        val libexecDir = File(prefixDir, "libexec")
        if (libexecDir.exists()) {
            libexecDir.walkTopDown().forEach { file ->
                if (file.isFile) {
                    file.setExecutable(true, false)
                }
            }
        }
    }

    /**
     * 创建系统工具的符号链接。
     * Termux 包中的脚本 shebang 指向 <prefix>/bin/sh，但 sh 不在 git/perl/python
     * 的 .deb 包中，需要链接到 Android 系统的 /system/bin/sh。
     */
    private fun createSystemSymlinks(prefixDir: File) {
        val binDir = File(prefixDir, "bin")
        if (!binDir.exists()) binDir.mkdirs()

        val systemTools = listOf(
            "sh", "env", "cat", "cp", "mv", "rm", "mkdir", "rmdir",
            "ls", "ln", "chmod", "chown", "tr", "sed", "grep",
            "sort", "find", "wc", "head", "tail", "cut", "uname",
            "basename", "dirname", "test", "echo", "printf",
            "dd", "stat", "touch", "sleep",
        )

        for (tool in systemTools) {
            val link = File(binDir, tool)
            if (link.exists()) continue

            val systemPath = "/system/bin/$tool"
            val systemFile = File(systemPath)
            if (systemFile.exists()) {
                try {
                    android.system.Os.symlink(systemPath, link.absolutePath)
                } catch (_: Exception) {
                    try {
                        link.writeText("#!/system/bin/sh\nexec $systemPath \"\$@\"\n")
                        link.setExecutable(true, false)
                    } catch (_: Exception) {
                        // 忽略
                    }
                }
            }
        }
    }

    /** 确保 python3 符号链接存在 */
    private fun ensurePythonSymlink(prefixDir: File) {
        val binDir = File(prefixDir, "bin")
        val python3 = File(binDir, "python3")

        if (python3.exists()) return

        val pythonVersioned = binDir.listFiles()
            ?.filter { it.name.matches(Regex("python3\\.\\d+")) && it.canExecute() }
            ?.maxByOrNull { it.name.substringAfter("python3.").toIntOrNull() ?: 0 }

        if (pythonVersioned != null) {
            try {
                android.system.Os.symlink(pythonVersioned.name, python3.absolutePath)
            } catch (_: Exception) {
                pythonVersioned.copyTo(python3, overwrite = true)
                python3.setExecutable(true, false)
            }
        }
    }
}
