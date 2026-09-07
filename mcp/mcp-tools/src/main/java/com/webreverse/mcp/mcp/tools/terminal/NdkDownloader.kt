package com.webreverse.mcp.mcp.tools.terminal

import android.content.Context
import android.system.Os
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import org.apache.commons.compress.archivers.tar.TarArchiveEntry
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream
import org.apache.commons.compress.compressors.xz.XZCompressorInputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.zip.ZipInputStream

/**
 * NDK 自动下载与解压器（ 移植自 NdkCompiler； 优化下载逻辑； 镜像回退）。
 *
 * 采用两阶段处理：
 * 1. **下载阶段**：将压缩包完整下载到本地临时文件，按接收字节数显示下载进度。
 * 2. **解压阶段**：下载完成后，以流式方式单遍读取本地文件并解压，
 *    按已读取字节数显示解压进度；解压完成后删除临时压缩包。
 *
 * 下载逻辑优化：
 * - **断点续传**：下载中断（网络失败/用户取消）后保留 `.download` 部分文件，
 *   重试时通过 HTTP Range 请求从已下载字节处继续，不再从头重下 1GB+ 大包；
 * - **自动重试**：网络抖动自动重试（最多 3 次，指数退避），期间通过续传保持进度；
 * - **尺寸校验**：下载完成后校验 Content-Length 与实际字节数一致，防止解压残缺包；
 * - 服务器不支持 Range（返回 200 而非 206）时自动回退为全量重新下载。
 *
 * 镜像回退（与 Host Tools 逻辑一致）：
 * - 下载源按序尝试：gh-proxy.com 镜像 → gh.jasonzeng.dev 镜像 → GitHub 官方兜底；
 * - 单个镜像源失败立即切换下一个，全部镜像源一轮失败后经退避进入下一轮；
 * - 各镜像均为同一 GitHub 资产的代理，字节内容一致，`.download` 部分文件跨镜像续传安全。
 *
 * 支持多种压缩格式（zip / tar.xz），正确处理 Unix 符号链接与 wrapper 脚本。
 * 解压后符号链接若丢失，由 [NdkPermissionHelper] 统一修复为 `exec -a` 包装脚本
 * （恢复 argv[0]，使 ld.lld / llvm-ranlib 等 LLVM 工具正常工作）。
 *
 * 安装完成后自动生成 pip 编译工具链（NdkManager.regeneratePipToolchain），
 * 终端内 `pip install pycryptodome` 等带 C 扩展的库即可直接编译。
 *
 * 安装日志仅在安装过程中实时展示；**安装成功后自动清空**，不再持久化。
 */
class NdkDownloader(
    private val context: Context,
    private val ndkManager: NdkManager,
) {

    companion object {
        private const val BUFFER_SIZE = 8192
        private const val CONNECT_TIMEOUT = 30000
        private const val READ_TIMEOUT = 120000
        private const val MAX_LOG_LINES = 500

        /** 下载失败自动重试次数（每次重试通过断点续传保持进度） */
        private const val MAX_DOWNLOAD_RETRIES = 3
    }

    @Volatile
    private var isCancelled = false

    /** 下载进度（0-100） */
    private val _downloadProgress = MutableStateFlow(0)
    val downloadProgress: StateFlow<Int> = _downloadProgress.asStateFlow()

    // 注意：NDK 组件在 AppContainer 中构造时 TerminalPaths 可能尚未 init（init 块在
    // 属性之后执行），因此日志流必须 lazy 惰性初始化——首次 UI 订阅/写日志时
    // TerminalPaths 已就绪，避免 IllegalStateException("TerminalPaths 未初始化")。
    private val _installLogs: MutableStateFlow<List<String>> by lazy {
        MutableStateFlow<List<String>>(emptyList())
    }
    private val installLogsFlow: StateFlow<List<String>> by lazy { _installLogs.asStateFlow() }

    /** NDK 安装过程日志流（仅安装过程中实时展示；安装成功后清空，不持久化） */
    val installLogs: StateFlow<List<String>>
        get() = installLogsFlow

    fun cancel() {
        isCancelled = true
    }

    /**
     * 下载并安装 NDK。
     */
    suspend fun downloadAndExtract(version: NdkVersionInfo): Result<File> = withContext(Dispatchers.IO) {
        isCancelled = false
        _downloadProgress.value = 0
        var versionDir: File? = null
        val archiveFile = File(TerminalPaths.ndkRootDir, "${version.name}.download")

        try {
            // 每个版本解压到独立子目录，支持多版本共存
            versionDir = File(TerminalPaths.ndkRootDir, version.name)
            if (versionDir.exists()) {
                TerminalPaths.deleteRecursively(versionDir)
            }
            versionDir.mkdirs()

            // ==================== 阶段一：下载（镜像回退 + 断点续传 + 自动重试） ====================
            ndkManager.setState(NdkState.Downloading(0, 0, -1))

            // 镜像回退（与 Host Tools 逻辑一致）——
            // gh-proxy 镜像 → gh.jasonzeng 镜像 → GitHub 官方兜底。
            // 每轮依次尝试全部镜像源，单个镜像失败立即切换下一个；
            // 整轮失败后经退避再进入下一轮（已下载部分通过 Range 续传保持进度，
            // 各镜像均为同一 GitHub 资产的代理，字节内容一致，跨镜像续传安全）。
            val downloadUrls = version.downloadUrls
            var lastError: Exception? = null
            var downloadOk = false
            var round = 0
            while (round < MAX_DOWNLOAD_RETRIES && !downloadOk) {
                round++
                if (round > 1) {
                    appendInstallLog("[下载] 第 $round/$MAX_DOWNLOAD_RETRIES 轮尝试（已下载部分将继续续传）...")
                }
                for ((urlIndex, url) in downloadUrls.withIndex()) {
                    if (isCancelled) throw RuntimeException("下载已取消")
                    try {
                        appendInstallLog("[下载] 镜像源 ${urlIndex + 1}/${downloadUrls.size}: ${hostOf(url)}")
                        downloadToArchive(version, url, archiveFile)
                        downloadOk = true
                        break
                    } catch (e: Exception) {
                        if (isCancelled) throw RuntimeException("下载已取消")
                        lastError = e
                        appendInstallLog(
                            "[下载] 镜像源 ${urlIndex + 1} 失败: ${e.message}" +
                                if (urlIndex < downloadUrls.lastIndex) "，切换下一个镜像源" else "",
                        )
                    }
                }
                if (!downloadOk && round < MAX_DOWNLOAD_RETRIES) {
                    val backoffMs = round * 2000L
                    appendInstallLog("[下载] 全部镜像源本轮均失败，${backoffMs / 1000} 秒后重试")
                    delay(backoffMs)
                }
            }
            if (!downloadOk) {
                throw lastError ?: RuntimeException("下载失败")
            }

            _downloadProgress.value = 100
            appendInstallLog("[下载] 下载完成: ${TerminalPaths.formatSize(archiveFile.length())}")

            if (isCancelled) throw RuntimeException("下载已取消")

            // ==================== 阶段二：从本地文件流式解压 ====================
            appendInstallLog("[解压] 从本地文件流式解压，格式: ${version.archiveFormat}")
            ndkManager.setState(NdkState.Extracting(0, "流式解压中..."))

            val archiveSize = archiveFile.length().coerceAtLeast(1L)
            val fis = FileInputStream(archiveFile)
            val countingStream = CountingInputStream(fis) { read ->
                val progress = (read * 100 / archiveSize).toInt().coerceIn(0, 100)
                ndkManager.setState(NdkState.Extracting(progress, "流式解压中..."))
            }

            val extractedDir = when (version.archiveFormat) {
                "zip" -> extractZipStream(countingStream, versionDir)
                "tar.xz" -> extractTarXzStream(countingStream, version.stripComponents, versionDir)
                else -> throw RuntimeException("不支持的格式: ${version.archiveFormat}")
            }

            appendInstallLog("[解压] 流式解压完成")

            // 解压完成，删除临时压缩包以节省空间
            archiveFile.delete()

            // ==================== 阶段三：权限与符号链接修复 ====================
            appendInstallLog("[权限配置] 开始配置可执行文件及符号链接包装权限...")
            ndkManager.setState(NdkState.Configuring(30, "修复符号链接与权限..."))
            try {
                NdkPermissionHelper.makeToolchainExecutable(
                    extractedDir,
                    object : NdkPermissionHelper.PermissionListener {
                        override fun onLog(message: String) {
                            appendInstallLog("[权限配置] $message")
                        }
                    },
                )
            } catch (permException: Exception) {
                // 后处理失败时不删除已解压文件，仅记录警告日志
                appendInstallLog(
                    "[权限配置] 警告: 权限配置过程中发生错误（NDK 已安装但部分工具可能无法正常工作）: ${permException.message}",
                )
            }

            // ==================== 阶段四：生成 pip 编译工具链 + 检测 ====================
            ndkManager.setState(NdkState.Configuring(80, "生成 pip 编译工具链..."))
            ndkManager.detectInstalled()
            val pipBin = ndkManager.regeneratePipToolchain()
            if (pipBin != null) {
                appendInstallLog("[pip 工具链] 已生成: ${pipBin.absolutePath}")
                appendInstallLog("[pip 工具链] 终端内可直接 pip install <带C扩展的库>（如 pycryptodome）")
            } else {
                appendInstallLog("[pip 工具链] 警告: 未能生成 pip 编译工具链（未找到 clang ELF）")
            }

            appendInstallLog("[完成] NDK ${version.displayName} 安装成功: ${extractedDir.absolutePath}")

            Result.success(extractedDir)
        } catch (e: Exception) {
            // 取消或失败时清理半成品解压目录，避免残留占空间；
            // 下载临时文件保留——支持下次点击安装时断点续传，不重头下载。
            versionDir?.let { dir ->
                if (dir.exists()) {
                    try { TerminalPaths.deleteRecursively(dir) } catch (_: Exception) {}
                }
            }
            if (isCancelled) {
                ndkManager.setState(NdkState.NotInstalled)
            } else {
                appendInstallLog("[失败] ${e.message}")
                ndkManager.setState(NdkState.Failed(e.message ?: "下载失败"))
            }
            Result.failure(e)
        } finally {
            // 安装成功后清空日志，不再需要显示
            if (ndkManager.state.value is NdkState.Installed) {
                _installLogs.value = emptyList()
            }
        }
    }

    /**
     * 下载 NDK 归档到本地临时文件（支持断点续传；URL 由调用方指定）。
     *
     * - 若本地已有部分下载文件（`.download`），通过 HTTP Range 从已下载字节处续传；
     *   各镜像源均为同一 GitHub 资产的代理，字节内容一致，跨镜像续传安全；
     * - 服务器返回 206 表示支持续传，返回 200 表示不支持（自动回退全量重下）；
     * - 下载完成校验 Content-Length 与实际字节数，不符视为损坏并抛错（保留文件供重试）。
     */
    private suspend fun downloadToArchive(version: NdkVersionInfo, url: String, archiveFile: File) = withContext(Dispatchers.IO) {
        val partialSize = if (archiveFile.exists()) archiveFile.length() else 0L

        val connection = followRedirects(URL(url), rangeOffset = partialSize)
        try {
            connection.connect()

            val responseCode = connection.responseCode
            if (responseCode !in 200..299) {
                throw RuntimeException("下载失败，HTTP $responseCode")
            }

            val resuming = responseCode == 206 && partialSize > 0
            val contentLength = connection.contentLengthLong
            val totalBytes = if (resuming) partialSize + contentLength else contentLength
            val alreadyReceived = if (resuming) partialSize else 0L

            appendInstallLog(
                "[下载] " +
                    (if (resuming) "断点续传，从 ${TerminalPaths.formatSize(partialSize)} 处继续" else "开始下载") +
                    (if (totalBytes > 0) "，总大小: ${TerminalPaths.formatSize(totalBytes)}" else ""),
            )
            ndkManager.setState(NdkState.Downloading(if (resuming) 0 else _downloadProgress.value, alreadyReceived, totalBytes))

            if (isCancelled) throw RuntimeException("下载已取消")

            // 服务器不支持 Range 时丢弃旧部分文件，全量重下
            if (!resuming && archiveFile.exists()) {
                archiveFile.delete()
            }

            connection.inputStream.use { input ->
                FileOutputStream(archiveFile, resuming).use { output ->
                    val buffer = ByteArray(BUFFER_SIZE)
                    var received = alreadyReceived
                    while (true) {
                        if (isCancelled) throw RuntimeException("下载已取消")
                        val n = input.read(buffer)
                        if (n <= 0) break
                        output.write(buffer, 0, n)
                        received += n
                        val progress = if (totalBytes > 0) {
                            (received * 100 / totalBytes).toInt().coerceIn(0, 100)
                        } else {
                            _downloadProgress.value
                        }
                        _downloadProgress.value = progress
                        ndkManager.setState(NdkState.Downloading(progress, received, totalBytes))
                    }
                }
            }

            // 尺寸校验：Content-Length 已知且与实际不符 → 残缺，保留文件供下次续传
            val finalSize = archiveFile.length()
            if (totalBytes > 0 && finalSize != totalBytes) {
                throw RuntimeException(
                    "下载不完整（应为 ${TerminalPaths.formatSize(totalBytes)}，实际 ${TerminalPaths.formatSize(finalSize)}）",
                )
            }
        } finally {
            connection.disconnect()
        }
    }

    private fun appendInstallLog(message: String) {
        _installLogs.value = (_installLogs.value + message).takeLast(MAX_LOG_LINES)
    }

    /** 提取 URL 的 host（含 scheme），用于日志中展示当前镜像源（避免刷出超长完整链接） */
    private fun hostOf(url: String): String {
        return try {
            val u = URL(url)
            "${u.protocol}://${u.host}"
        } catch (_: Exception) {
            url
        }
    }

    /**
     * 建立 HTTP 连接并手动跟随重定向。
     *
     * @param rangeOffset 断点续传起始字节（0 表示从头下载，>0 时携带 Range 头）。
     *   Range 头需在每一跳都设置——GitHub release 会 302 到 objects.githubusercontent.com。
     */
    private fun followRedirects(url: URL, maxRedirects: Int = 5, rangeOffset: Long = 0): HttpURLConnection {
        var currentUrl = url
        var redirects = 0
        while (redirects < maxRedirects) {
            val conn = currentUrl.openConnection() as HttpURLConnection
            conn.instanceFollowRedirects = false
            conn.connectTimeout = CONNECT_TIMEOUT
            conn.readTimeout = READ_TIMEOUT
            conn.setRequestProperty("User-Agent", "WebReverseMCP/1.0.0")
            if (rangeOffset > 0) {
                conn.setRequestProperty("Range", "bytes=$rangeOffset-")
            }
            try {
                val code = conn.responseCode
                if (code in 300..399) {
                    val location = conn.getHeaderField("Location")
                    conn.disconnect()
                    if (location.isNullOrBlank()) throw RuntimeException("重定向位置为空")
                    currentUrl = URL(currentUrl, location)
                    redirects++
                    continue
                }
                return conn
            } catch (e: Exception) {
                conn.disconnect()
                throw e
            }
        }
        throw RuntimeException("重定向次数过多")
    }

    // ==================== ZIP 流式解压 ====================

    /**
     * 流式解压 zip：直接从本地文件输入流顺序读取并解压，单遍完成。
     * zip 内的符号链接会被解压为普通文本文件/空文件，随后由
     * [NdkPermissionHelper] 统一转换为 `exec -a` 包装脚本恢复 argv[0]。
     */
    private suspend fun extractZipStream(input: InputStream, targetDir: File): File = withContext(Dispatchers.IO) {
        targetDir.mkdirs()
        appendInstallLog("[解压] 使用 ZipInputStream 流式解压 zip...")

        var processedEntries = 0
        ZipInputStream(input).use { zis ->
            var entry = zis.nextEntry
            while (entry != null) {
                if (isCancelled) throw RuntimeException("解压已取消")

                val outputFile = File(targetDir, entry.name)
                // 安全检查：防止路径穿越（zip slip）
                if (!outputFile.canonicalPath.startsWith(targetDir.canonicalPath)) {
                    zis.closeEntry()
                    entry = zis.nextEntry
                    continue
                }

                if (entry.isDirectory) {
                    outputFile.mkdirs()
                } else {
                    outputFile.parentFile?.mkdirs()
                    FileOutputStream(outputFile).use { zis.copyTo(it) }
                    if (entry.name.contains("/bin/") || entry.name.endsWith(".sh")) {
                        outputFile.setExecutable(true, false)
                    }
                }

                processedEntries++
                zis.closeEntry()
                entry = zis.nextEntry
            }
        }

        appendInstallLog("[解压] zip 流式解压完成，共处理 $processedEntries 个条目")
        findNdkRoot(targetDir) ?: targetDir
    }

    // ==================== TAR.XZ 流式解压 ====================

    /**
     * 流式解压 tar.xz：单遍完成，进度按已读取字节数驱动。
     *
     * 正确处理 tar 归档中的符号链接：
     * - 硬链接（LF_LINK）：跳过，目标文件已解压
     * - 符号链接（LF_SYMLINK）：通过 [createSymlinkOrWrapper] 创建符号链接或 wrapper 脚本
     */
    private suspend fun extractTarXzStream(
        input: InputStream,
        stripComponents: Int,
        targetDir: File,
    ): File = withContext(Dispatchers.IO) {
        targetDir.mkdirs()
        appendInstallLog("[解压] 使用 Commons Compress + tukaani xz 流式解压 tar.xz（单遍）...")

        var processedEntries = 0

        XZCompressorInputStream(input).use { xzis ->
            TarArchiveInputStream(xzis).use { tis ->
                var entry = tis.nextEntry as? TarArchiveEntry
                while (entry != null) {
                    if (isCancelled) throw RuntimeException("解压已取消")

                    val entryName = stripPathComponents(entry.name, stripComponents)
                    if (entryName.isNotEmpty()) {
                        val outputFile = File(targetDir, entryName)

                        // 安全检查：防止路径穿越（tar slip）
                        if (!outputFile.canonicalPath.startsWith(targetDir.canonicalPath)) {
                            entry = tis.nextEntry as? TarArchiveEntry
                            continue
                        }

                        when {
                            entry.isSymbolicLink -> {
                                outputFile.parentFile?.mkdirs()
                                if (outputFile.exists()) outputFile.delete()
                                createSymlinkOrWrapper(outputFile, entry.linkName)
                            }
                            entry.isLink -> {
                                // 硬链接跳过（目标文件已解压）
                            }
                            entry.isDirectory -> {
                                outputFile.mkdirs()
                            }
                            else -> {
                                outputFile.parentFile?.mkdirs()
                                FileOutputStream(outputFile).use { out ->
                                    tis.copyTo(out)
                                }
                                if (entryName.contains("/bin/") || entryName.endsWith(".sh")) {
                                    outputFile.setExecutable(true, false)
                                }
                            }
                        }
                    }

                    processedEntries++
                    entry = tis.nextEntry as? TarArchiveEntry
                }
            }
        }

        appendInstallLog("[解压] tar.xz 流式解压完成，共处理 $processedEntries 个条目")
        findNdkRoot(targetDir) ?: targetDir
    }

    /**
     * 去除路径前缀（等效于 tar --strip-components=N）。
     */
    private fun stripPathComponents(path: String, count: Int): String {
        if (count <= 0) return path
        val parts = path.split("/")
        return if (parts.size > count) {
            parts.drop(count).joinToString("/")
        } else {
            ""
        }
    }

    // ==================== 符号链接处理 ====================

    /**
     * 创建符号链接，失败时回退到 shell wrapper 脚本（exec -a 恢复 argv[0]）。
     */
    private fun createSymlinkOrWrapper(linkFile: File, target: String) {
        try {
            Os.symlink(target, linkFile.absolutePath)
        } catch (_: Exception) {
            val fileName = linkFile.name
            linkFile.writeText(
                "#!/system/bin/sh\n" +
                    "DIR=\$(cd \"\$(dirname \"\$0\")\" && pwd)\n" +
                    "exec -a $fileName \"\$DIR/$target\" \"\$@\"\n",
            )
            linkFile.setExecutable(true, false)
        }
    }

    // ==================== 工具方法 ====================

    /**
     * 计数输入流：累计已读取字节数，并通过回调驱动进度。
     */
    private class CountingInputStream(
        private val source: InputStream,
        private val onRead: (Long) -> Unit,
    ) : InputStream() {
        private var totalRead = 0L

        override fun read(): Int {
            val b = source.read()
            if (b != -1) {
                totalRead++
                onRead(totalRead)
            }
            return b
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            val n = source.read(b, off, len)
            if (n > 0) {
                totalRead += n
                onRead(totalRead)
            }
            return n
        }

        override fun available(): Int = try { source.available() } catch (_: Exception) { 0 }

        override fun close() = source.close()
    }

    private fun findNdkRoot(baseDir: File): File? {
        if (File(baseDir, "source.properties").exists()) return baseDir
        baseDir.listFiles()?.forEach { sub ->
            if (sub.isDirectory && File(sub, "source.properties").exists()) return sub
        }
        return null
    }
}
