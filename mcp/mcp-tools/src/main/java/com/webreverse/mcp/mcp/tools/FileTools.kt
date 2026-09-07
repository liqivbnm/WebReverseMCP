package com.webreverse.mcp.mcp.tools

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.util.Base64
import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.common.util.WorkDir
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.io.File
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

/**
 * File Tools：本地文件系统操作。
 *
 * 设计目标（源自真实逆向工作流痛点）：
 * - AI 下载 JS/HAR 后无法离线阅读 → file.read / file.search
 * - AI 无法把逆向成果落盘为脚本 → file.write / file.append
 * - 无法把文件交给用户 → file.open / file.share
 *
 * 路径规则：绝对路径直接使用；相对路径相对于工作目录（WorkDir）。
 * 安全规则：拒绝访问 /proc /sys /dev /system 等系统保护目录。
 */
object FileTools {

    /** 单文件读取硬上限（防止把超大文件灌进上下文） */
    private const val HARD_READ_LIMIT_BYTES = 32L * 1024 * 1024

    /**
     * （P1-4 修复）：base64 模式独立硬上限。
     * 原实现沿用 32MB 上限——原始字节经 base64 膨胀至 ~43MB 字符串，再装入
     * JSON 字符串与 McpToolResult 双份持有，单次调用瞬时内存可超 100MB，
     * 而 Android 应用堆通常仅 256-512MB，必然 OOM。二进制大文件应走
     * file.readRange / file.chunk 分块。
     */
    private const val HARD_READ_LIMIT_BASE64_BYTES = 4L * 1024 * 1024

    /**
     * （修复）：单次写入硬上限（解码后字节数）。
     * 背景：MCP 传输层 HTTP 请求体上限 8MB（McpServer.MAX_REQUEST_BYTES），
     * base64 会把原始字节膨胀 33%，再加 JSON 参数结构开销，单次 file.write 实际
     * 只能安全携带约 5MB 原始内容。此前 file.write 无体积护栏，AI 写大文件时
     * 请求体超限被传输层直接拒绝（HTTP 413 / WS 帧超限），客户端表现为
     * “JSON 解析失败”，且无任何可读提示。现加入写前/写后双重校验，
     * 超限返回明确错误并引导改用 file.append 分批追加或 terminal.exec 写入。
     */
    private const val MAX_WRITE_BYTES = 5 * 1024 * 1024
    private val BLOCKED_PREFIXES = listOf(
        "/proc", "/sys", "/dev", "/system", "/vendor", "/apex", "/system_ext", "/odm", "/sbin", "/root",
    )

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)
        return listOf(
            // ---------- 工作目录 ----------
            f.tool(
                "file.workdir", "获取当前工作目录（下载与分析产物的默认存放位置）", ToolCategory.FILE,
                PermissionScope.READ_FILE, RiskLevel.LOW,
            ) { _ ->
                val ctx = contextOf(deps)
                McpToolResult.json(
                    buildJsonObject {
                        put("path", JsonPrimitive(WorkDir.get()))
                        put("writable", JsonPrimitive(WorkDir.isWritable()))
                        put("fallbackPath", JsonPrimitive(WorkDir.directory(ctx).absolutePath))
                        put("hint", JsonPrimitive("未授予所有文件权限时，实际可写位置为 fallbackPath"))
                        // 终端与 file.* 已统一存储目录——terminal.exec 的默认
                        // 工作目录（terminalHome）就是本目录，AI 落盘/读取不再有两套位置。
                        put("terminalHome", JsonPrimitive(com.webreverse.mcp.mcp.tools.terminal.TerminalPaths.homeDir.absolutePath))
                        put("terminalNote", JsonPrimitive("terminal.exec 等终端工具默认工作目录与 file.* 一致（terminalHome = 本目录）；脚本也可存放于其下 scripts/ 子目录"))
                    },
                )
            },
            f.tool(
                "file.set_workdir", "设置工作目录（需已授予所有文件权限）", ToolCategory.FILE,
                PermissionScope.WRITE_FILE, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "path" to Schemas.strSchema("新的工作目录绝对路径"),
                ),
            ) { args ->
                val path = ToolArgs.str(args, "path")
                if (path.isBlank()) return@tool McpToolResult.error("INVALID_ARGUMENTS", "path 不能为空")
                val ok = WorkDir.set(contextOf(deps), path)
                if (ok) McpToolResult.json(
                    buildJsonObject {
                        put("success", JsonPrimitive(true))
                        put("path", JsonPrimitive(WorkDir.get()))
                    },
                ) else McpToolResult.error("SET_WORKDIR_FAILED", "目录不可写或创建失败: $path")
            },

            // ---------- 读 ----------
            f.tool(
                "file.read", "读取文件内容：文本按行分页返回（offset/limit 翻页；超长行用 colOffset/colLimit 按列分段），二进制按字节偏移返回 base64。逆向下载的 JS/HAR 等大文件离线阅读用这个工具。" +
                    "minified/打包 JS 常是整文件一行：必须用 colOffset（配合响应里的 nextColOffset 游标）按列分段读，否则只能看到开头几千字符。响应带 nextOffset/nextColOffset 续读游标，翻页读完整文件", ToolCategory.FILE,
                PermissionScope.READ_FILE, RiskLevel.LOW, timeoutMs = 60_000,
                inputSchema = Schemas.objectSchema(
                    "path" to Schemas.strSchema("文件路径（相对工作目录或绝对路径）"),
                    "offset" to Schemas.intSchema("起始行号（0 基，默认 0；base64 模式下为字节偏移）"),
                    "limit" to Schemas.intSchema("读取行数（默认 200）"),
                    "colOffset" to Schemas.intSchema("行内起始列（0 基字符偏移，默认 0，对窗口内每一行生效）——超长行/minified 单行文件分段阅读"),
                    "colLimit" to Schemas.intSchema("单行最多返回字符数（默认 4000，最大 100000）；行被截断时响应带 nextColOffset 续读游标"),
                    "format" to Schemas.strSchema("输出格式：lines（JSON 行数组，默认）/ text（紧凑纯文本，每行前缀 行号|，响应体积更小，长文件推荐）"),
                    "maxBytes" to Schemas.intSchema("单次返回的最大字节数（默认 524288，最大 33554432）"),
                    "base64" to Schemas.boolSchema("返回原始字节的 base64（二进制文件使用；offset 为字节偏移，响应带 nextOffset 可分页续读）"),
                ),
            ) { args ->
                val file = resolveFile(deps, ToolArgs.str(args, "path"))
                guard(file)?.let { return@tool McpToolResult.error("PATH_BLOCKED", it) }
                if (!file.exists()) return@tool McpToolResult.error("FILE_NOT_FOUND", "文件不存在: ${file.absolutePath}")
                if (file.isDirectory) return@tool McpToolResult.error("IS_DIRECTORY", "目标是目录，请用 file.list: ${file.absolutePath}")
                val wantBase64 = ToolArgs.bool(args, "base64")
                // （P1-4 修复）：base64 模式使用独立（更严格）上限，防 OOM
                val maxBytes = if (wantBase64) {
                    ToolArgs.long(args, "maxBytes", 524_288L).coerceIn(1024L, HARD_READ_LIMIT_BASE64_BYTES)
                } else {
                    ToolArgs.long(args, "maxBytes", 524_288L).coerceIn(1024L, HARD_READ_LIMIT_BYTES)
                }
                withContext(Dispatchers.IO) {
                    if (wantBase64) {
                        // 修复（分段读取）：base64 模式原先永远从字节 0 读起，
                        // 超过上限的二进制文件后半段没有任何工具能读到。现在 offset 作为
                        // 字节偏移参与分页，并回传 nextOffset 续读游标，AI 可翻页读完整个文件。
                        val byteOffset = ToolArgs.long(args, "offset", 0L).coerceIn(0L, file.length())
                        val payload = readRangeBytes(file, byteOffset, maxBytes + 1)
                        val truncated = payload.size.toLong() > maxBytes
                        val data = if (truncated) payload.copyOfRange(0, maxBytes.toInt()) else payload
                        val next = byteOffset + data.size
                        return@withContext McpToolResult.json(
                            buildJsonObject {
                                put("path", JsonPrimitive(file.absolutePath))
                                put("sizeBytes", JsonPrimitive(file.length()))
                                put("offset", JsonPrimitive(byteOffset))
                                put("returnedBytes", JsonPrimitive(data.size))
                                put("base64", JsonPrimitive(Base64.encodeToString(data, Base64.NO_WRAP)))
                                put("truncated", JsonPrimitive(truncated))
                                if (next < file.length()) {
                                    put("nextOffset", JsonPrimitive(next))
                                    put("pageHint", JsonPrimitive("还有 ${file.length() - next} 字节，传 offset=$next 续读"))
                                }
                            },
                        )
                    }
                    // 文本模式：按行流式读取窗口，凑满即止（报29：既不整读，也不再数到 EOF）
                    val offset = ToolArgs.int(args, "offset", 0).coerceAtLeast(0)
                    val limit = ToolArgs.int(args, "limit", 200).coerceIn(1, 10_000)
                    // 新增（分段读取核心）：colOffset/colLimit 行内列窗口。
                    // 实测痛点：minified/打包 JS 整个文件就是一行，原实现单行硬截断
                    // 4000 字符后提示「用 file.search 定位」——但 search 只返回匹配点
                    // 上下文，该行 4000 字符之后的正文没有任何工具能读到，大文件
                    // 阅读直接断路。现在按列分段 + nextColOffset 游标顺序续读。
                    val colOffset = ToolArgs.int(args, "colOffset", 0).coerceAtLeast(0)
                    val colLimit = ToolArgs.int(args, "colLimit", 4_000).coerceIn(100, 100_000)
                    val compactText = ToolArgs.str(args, "format", "lines").equals("text", ignoreCase = true)
                    val page = file.inputStream().bufferedReader(Charsets.UTF_8).use { reader ->
                        pageText(reader, offset, limit, colOffset, colLimit, maxBytes)
                    }
                    if (page.binary) {
                        return@withContext McpToolResult.error(
                            "BINARY_FILE",
                            "文件疑似二进制，请改用 base64=true 模式: ${file.absolutePath}",
                        )
                    }
                    McpToolResult.json(
                        buildJsonObject {
                            put("path", JsonPrimitive(file.absolutePath))
                            put("sizeBytes", JsonPrimitive(file.length()))
                            put("totalLines", JsonPrimitive(page.totalLines))
                            if (!page.totalLinesKnown) put("totalLinesKnown", JsonPrimitive(false))
                            put("offset", JsonPrimitive(offset))
                            put("colOffset", JsonPrimitive(colOffset))
                            put("returned", JsonPrimitive(page.returned))
                            put("truncated", JsonPrimitive(page.truncated))
                            if (page.truncated) {
                                put("nextOffset", JsonPrimitive(page.nextOffset))
                                put("pageHint", JsonPrimitive("传 offset=${page.nextOffset} 续读后续行（limit 可保持不变）"))
                            }
                            if (page.anyLineCut) {
                                put("nextColOffset", JsonPrimitive(page.nextColOffset))
                                put("colHint", JsonPrimitive("有超长行在 $colLimit 字符处被截断；对该行传 colOffset=${page.nextColOffset}（offset 保持该行行号）继续读后续内容"))
                            }
                            if (compactText) {
                                put("format", JsonPrimitive("text"))
                                val sb = StringBuilder(page.lines.sumOf { it.text.length + 12 })
                                for (l in page.lines) {
                                    sb.append(l.line).append('|').append(l.text)
                                    if (l.colTruncated) sb.append("…[colLimit 截断，colOffset=").append(page.nextColOffset).append(" 续读]")
                                    sb.append('\n')
                                }
                                put("content", JsonPrimitive(sb.toString().trimEnd('\n')))
                            } else {
                                put(
                                    "lines",
                                    JsonArray(
                                        page.lines.map { l ->
                                            buildJsonObject {
                                                put("line", JsonPrimitive(l.line))
                                                put("text", JsonPrimitive(l.text))
                                                if (l.colTruncated) put("colTruncated", JsonPrimitive(true))
                                            }
                                        },
                                    ),
                                )
                            }
                        },
                    )
                }
            },

            // 报29：按字节区间流式读取，避免整文件加载
            f.tool(
                "file.readRange", "按字节偏移读取文件指定区间（流式，内存只占区间大小）。读大型 JS/HAR 的特定字节段、定位加密 signature 所在位置用它，绝不整读", ToolCategory.FILE,
                PermissionScope.READ_FILE, RiskLevel.LOW, timeoutMs = 60_000,
                inputSchema = Schemas.objectSchema(
                    "path" to Schemas.strSchema("文件路径（相对工作目录或绝对路径）"),
                    "offset" to Schemas.longSchema("起始字节偏移（默认 0）"),
                    "length" to Schemas.longSchema("读取字节数（默认 65536，最大 8388608）"),
                    "base64" to Schemas.boolSchema("返回 base64（二进制区间用）"),
                ),
            ) { args ->
                val file = resolveFile(deps, ToolArgs.str(args, "path"))
                guard(file)?.let { return@tool McpToolResult.error("PATH_BLOCKED", it) }
                if (!file.exists() || !file.isFile) return@tool McpToolResult.error("FILE_NOT_FOUND", "文件不存在: ${file.absolutePath}")
                val offset = ToolArgs.long(args, "offset", 0L).coerceAtLeast(0)
                val length = ToolArgs.long(args, "length", 65_536L).coerceIn(1L, 8L * 1024 * 1024)
                val wantBase64 = ToolArgs.bool(args, "base64")
                withContext(Dispatchers.IO) {
                    val bytes = readRangeBytes(file, offset, length)
                    McpToolResult.json(
                        buildJsonObject {
                            put("path", JsonPrimitive(file.absolutePath))
                            put("sizeBytes", JsonPrimitive(file.length()))
                            put("offset", JsonPrimitive(offset))
                            put("length", JsonPrimitive(length))
                            put("bytesRead", JsonPrimitive(bytes.size))
                            put("truncated", JsonPrimitive(bytes.size.toLong() < length))
                            if (wantBase64) {
                                put("base64", JsonPrimitive(Base64.encodeToString(bytes, Base64.NO_WRAP)))
                            } else {
                                put("text", JsonPrimitive(String(bytes, Charsets.UTF_8)))
                            }
                        },
                    )
                }
            },
            f.tool(
                "file.chunk", "按字节块读取文件（offset = chunkIndex × chunkSize，流式）。可配合 file.hash 对超大文件分块定位，适合把几十 MB 混淆 JS 分块读完", ToolCategory.FILE,
                PermissionScope.READ_FILE, RiskLevel.LOW, timeoutMs = 60_000,
                inputSchema = Schemas.objectSchema(
                    "path" to Schemas.strSchema("文件路径"),
                    "chunkIndex" to Schemas.longSchema("块序号（默认 0）"),
                    "chunkSize" to Schemas.longSchema("每块字节数（默认 262144，最大 8388608）"),
                    "base64" to Schemas.boolSchema("返回 base64（默认 false，文本按 UTF-8 返回）"),
                ),
            ) { args ->
                val file = resolveFile(deps, ToolArgs.str(args, "path"))
                guard(file)?.let { return@tool McpToolResult.error("PATH_BLOCKED", it) }
                if (!file.exists() || !file.isFile) return@tool McpToolResult.error("FILE_NOT_FOUND", "文件不存在: ${file.absolutePath}")
                val chunkIndex = ToolArgs.long(args, "chunkIndex", 0L).coerceAtLeast(0)
                val chunkSize = ToolArgs.long(args, "chunkSize", 262_144L).coerceIn(1L, 8L * 1024 * 1024)
                val wantBase64 = ToolArgs.bool(args, "base64")
                withContext(Dispatchers.IO) {
                    val total = file.length()
                    val offset = chunkIndex * chunkSize
                    val bytes = readRangeBytes(file, offset, chunkSize)
                    McpToolResult.json(
                        buildJsonObject {
                            put("path", JsonPrimitive(file.absolutePath))
                            put("sizeBytes", JsonPrimitive(total))
                            put("chunkIndex", JsonPrimitive(chunkIndex))
                            put("chunkSize", JsonPrimitive(chunkSize))
                            put("offset", JsonPrimitive(offset))
                            put("bytesRead", JsonPrimitive(bytes.size))
                            put("chunkCount", JsonPrimitive((total + chunkSize - 1) / chunkSize))
                            put("truncated", JsonPrimitive(bytes.size.toLong() < chunkSize))
                            if (wantBase64) {
                                put("base64", JsonPrimitive(Base64.encodeToString(bytes, Base64.NO_WRAP)))
                            } else {
                                put("text", JsonPrimitive(String(bytes, Charsets.UTF_8)))
                            }
                        },
                    )
                }
            },
            f.tool(
                "file.preview", "流式读取文件开头做快速预览（自动识别文本/二进制）。先看大文件头部与类型，再决定用 readRange/chunk 精读", ToolCategory.FILE,
                PermissionScope.READ_FILE, RiskLevel.LOW, timeoutMs = 60_000,
                inputSchema = Schemas.objectSchema(
                    "path" to Schemas.strSchema("文件路径"),
                    "maxBytes" to Schemas.intSchema("预览字节数（默认 4096，最大 65536）"),
                    "base64" to Schemas.boolSchema("强制返回 base64（默认自动判断）"),
                ),
            ) { args ->
                val file = resolveFile(deps, ToolArgs.str(args, "path"))
                guard(file)?.let { return@tool McpToolResult.error("PATH_BLOCKED", it) }
                if (!file.exists() || !file.isFile) return@tool McpToolResult.error("FILE_NOT_FOUND", "文件不存在: ${file.absolutePath}")
                val maxBytes = ToolArgs.int(args, "maxBytes", 4096).coerceIn(64, 65_536)
                val forceBase64 = ToolArgs.bool(args, "base64")
                withContext(Dispatchers.IO) {
                    val bytes = readRangeBytes(file, 0L, maxBytes.toLong())
                    val isBinary = isBinaryPreview(bytes)
                    val asBase64 = forceBase64 || isBinary
                    McpToolResult.json(
                        buildJsonObject {
                            put("path", JsonPrimitive(file.absolutePath))
                            put("sizeBytes", JsonPrimitive(file.length()))
                            put("readBytes", JsonPrimitive(bytes.size))
                            put("detected", JsonPrimitive(if (isBinary) "binary" else "text"))
                            put("truncated", JsonPrimitive(bytes.size < maxBytes))
                            if (asBase64) {
                                put("base64", JsonPrimitive(Base64.encodeToString(bytes, Base64.NO_WRAP)))
                            } else {
                                // 文本预览：尽量切到完整行边界
                                val rawText = String(bytes, Charsets.UTF_8)
                                val cutIdx = rawText.lastIndexOf('\n')
                                put("text", JsonPrimitive(if (cutIdx > 0) rawText.substring(0, cutIdx) else rawText))
                            }
                        },
                    )
                }
            },

            // 报29：文件校验/去重识别（流式哈希，内存友好，支持大文件部分哈希）
            f.tool(
                "file.hash", "计算文件校验和（md5/sha1/sha256/sha512，默认 sha256）。用于识别/去重来自不同站点的相同混淆产物，或校验下载完整性", ToolCategory.FILE,
                PermissionScope.READ_FILE, RiskLevel.LOW, timeoutMs = 120_000,
                inputSchema = Schemas.objectSchema(
                    "path" to Schemas.strSchema("文件路径（相对工作目录或绝对路径）"),
                    "algorithm" to Schemas.strSchema("哈希算法：md5/sha1/sha256/sha512（默认 sha256）"),
                    "maxBytes" to Schemas.intSchema("仅对文件前 N 字节做部分哈希（大文件快速识别用）"),
                ),
            ) { args ->
                val hfile = resolveFile(deps, ToolArgs.str(args, "path"))
                guard(hfile)?.let { return@tool McpToolResult.error("PATH_BLOCKED", it) }
                if (!hfile.exists() || !hfile.isFile) return@tool McpToolResult.error("FILE_NOT_FOUND", "文件不存在: ${hfile.absolutePath}")
                val algo = ToolArgs.optStr(args, "algorithm")?.lowercase() ?: "sha256"
                val supported = setOf("md5", "sha1", "sha256", "sha512")
                if (algo !in supported) return@tool McpToolResult.error("INVALID_ARGUMENT", "不支持算法: $algo（可用: ${supported.joinToString("/")}）")
                val maxBytes = ToolArgs.long(args, "maxBytes", -1L).takeIf { it > 0 }
                withContext(Dispatchers.IO) {
                    val digest = MessageDigest.getInstance(algo)
                    var total = 0L
                    hfile.inputStream().buffered().use { ins ->
                        val buf = ByteArray(64 * 1024)
                        while (true) {
                            val r = ins.read(buf)
                            if (r < 0) break
                            if (maxBytes != null && total + r > maxBytes) {
                                digest.update(buf, 0, (maxBytes - total).toInt())
                                total = maxBytes
                                break
                            }
                            digest.update(buf, 0, r)
                            total += r
                        }
                    }
                    val hex = digest.digest().joinToString("") { "%02x".format(it) }
                    McpToolResult.json(
                        buildJsonObject {
                            put("path", JsonPrimitive(hfile.absolutePath))
                            put("algorithm", JsonPrimitive(algo))
                            put("hash", JsonPrimitive(hex))
                            put("sizeBytes", JsonPrimitive(total))
                            put("partial", JsonPrimitive(maxBytes != null))
                        },
                    )
                }
            },

            // ---------- 写 ----------
            f.tool(
                "file.write", "创建或覆盖写入文件（把逆向成果、Python/JS 脚本落盘用这个工具）。支持文本与 base64 二进制，自动创建父目录。" +
                    "单次写入上限约 5MB（解码后字节；受 MCP 传输层 8MB 请求上限约束，base64 会膨胀 33%）。" +
                    "超长内容请用 file.append 分批追加（每批 < 5MB），或 terminal.exec 的 cat heredoc / curl 写入", ToolCategory.FILE,
                PermissionScope.WRITE_FILE, RiskLevel.MEDIUM, timeoutMs = 60_000,
                inputSchema = Schemas.objectSchema(
                    "path" to Schemas.strSchema("目标文件路径（相对工作目录或绝对路径）"),
                    "content" to Schemas.strSchema("文本内容（与 contentBase64 二选一）"),
                    "contentBase64" to Schemas.strSchema("base64 内容（二进制文件使用，与 content 二选一）"),
                    "overwrite" to Schemas.boolSchema("文件已存在时是否覆盖（默认 true）"),
                ),
            ) { args ->
                val file = resolveFile(deps, ToolArgs.str(args, "path"))
                guard(file)?.let { return@tool McpToolResult.error("PATH_BLOCKED", it) }
                val content = ToolArgs.optStr(args, "content")
                val contentB64 = ToolArgs.optStr(args, "contentBase64")
                if (content == null && contentB64 == null) {
                    return@tool McpToolResult.error("INVALID_ARGUMENTS", "必须提供 content 或 contentBase64")
                }
                // 写前预检（避免解码超大 base64 白费内存），base64 按 4/3 膨胀估算
                if (content != null && content.length > MAX_WRITE_BYTES) {
                    return@tool McpToolResult.error(
                        "CONTENT_TOO_LARGE",
                        "content 文本 ${content.length} 字符超过单次写入上限 ${MAX_WRITE_BYTES / (1024 * 1024)}MB。" +
                            "请改用 file.append 分批追加（每批 < ${MAX_WRITE_BYTES / (1024 * 1024)}MB），或 terminal.exec 用 cat heredoc 写入",
                    )
                }
                if (contentB64 != null && contentB64.length > MAX_WRITE_BYTES * 4 / 3 + 1024) {
                    return@tool McpToolResult.error(
                        "CONTENT_TOO_LARGE",
                        "contentBase64 字符串 ${contentB64.length} 字符超过单次写入上限（解码后约 ${MAX_WRITE_BYTES / (1024 * 1024)}MB）。" +
                            "请改用 file.append 分批追加，或 terminal.exec 用 curl/脚本写入",
                    )
                }
                val overwrite = ToolArgs.bool(args, "overwrite", true)
                if (file.exists() && !overwrite) {
                    return@tool McpToolResult.error("FILE_EXISTS", "文件已存在且 overwrite=false: ${file.absolutePath}")
                }
                withContext(Dispatchers.IO) {
                    file.parentFile?.mkdirs()
                    val bytes = contentB64?.let {
                        runCatching { Base64.decode(it, Base64.NO_WRAP) }.getOrNull()
                            ?: return@withContext McpToolResult.error("INVALID_BASE64", "contentBase64 解码失败")
                    } ?: content!!.toByteArray(Charsets.UTF_8)
                    // 写后二次校验（解码/编码后真实字节数），防膨胀绕过预检
                    if (bytes.size > MAX_WRITE_BYTES) {
                        return@withContext McpToolResult.error(
                            "CONTENT_TOO_LARGE",
                            "解码后 ${bytes.size} 字节超过单次写入上限 ${MAX_WRITE_BYTES / (1024 * 1024)}MB。" +
                                "请改用 file.append 分批追加（每批 < ${MAX_WRITE_BYTES / (1024 * 1024)}MB）",
                        )
                    }
                    file.writeBytes(bytes)
                    McpToolResult.json(
                        buildJsonObject {
                            put("path", JsonPrimitive(file.absolutePath))
                            put("sizeBytes", JsonPrimitive(file.length()))
                            put("bytesWritten", JsonPrimitive(bytes.size))
                        },
                    )
                }
            },
            f.tool(
                "file.append", "向文件末尾追加内容（不存在则创建）。适合分批写出长脚本——每次调用也有约 5MB 单次上限（同 file.write，受 8MB 传输层约束），大文件按批次循环追加即可", ToolCategory.FILE,
                PermissionScope.WRITE_FILE, RiskLevel.MEDIUM, timeoutMs = 60_000,
                inputSchema = Schemas.objectSchema(
                    "path" to Schemas.strSchema("目标文件路径"),
                    "content" to Schemas.strSchema("追加的文本内容（与 contentBase64 二选一）"),
                    "contentBase64" to Schemas.strSchema("追加的 base64 内容（与 content 二选一）"),
                    "newline" to Schemas.boolSchema("追加后是否补换行符（默认 true）"),
                ),
            ) { args ->
                val file = resolveFile(deps, ToolArgs.str(args, "path"))
                guard(file)?.let { return@tool McpToolResult.error("PATH_BLOCKED", it) }
                val content = ToolArgs.optStr(args, "content")
                val contentB64 = ToolArgs.optStr(args, "contentBase64")
                if (content == null && contentB64 == null) {
                    return@tool McpToolResult.error("INVALID_ARGUMENTS", "必须提供 content 或 contentBase64")
                }
                // 与 file.write 相同的单次写入护栏
                if (content != null && content.length > MAX_WRITE_BYTES) {
                    return@tool McpToolResult.error(
                        "CONTENT_TOO_LARGE",
                        "content 文本 ${content.length} 字符超过单次追加上限 ${MAX_WRITE_BYTES / (1024 * 1024)}MB。" +
                            "请把内容拆成多批 file.append 依次追加（每批 < ${MAX_WRITE_BYTES / (1024 * 1024)}MB）",
                    )
                }
                if (contentB64 != null && contentB64.length > MAX_WRITE_BYTES * 4 / 3 + 1024) {
                    return@tool McpToolResult.error(
                        "CONTENT_TOO_LARGE",
                        "contentBase64 字符串 ${contentB64.length} 字符超过单次追加上限（解码后约 ${MAX_WRITE_BYTES / (1024 * 1024)}MB）。" +
                            "请拆成多批 file.append 依次追加",
                    )
                }
                withContext(Dispatchers.IO) {
                    file.parentFile?.mkdirs()
                    val body = contentB64?.let {
                        runCatching { Base64.decode(it, Base64.NO_WRAP) }.getOrNull()
                            ?: return@withContext McpToolResult.error("INVALID_BASE64", "contentBase64 解码失败")
                    } ?: content!!.toByteArray(Charsets.UTF_8)
                    if (body.size > MAX_WRITE_BYTES) {
                        return@withContext McpToolResult.error(
                            "CONTENT_TOO_LARGE",
                            "解码后 ${body.size} 字节超过单次追加上限 ${MAX_WRITE_BYTES / (1024 * 1024)}MB，请拆批追加",
                        )
                    }
                    val extra = if (ToolArgs.bool(args, "newline", true) && content != null) "\n".toByteArray() else ByteArray(0)
                    java.io.FileOutputStream(file, true).use { it.write(body); it.write(extra) }
                    McpToolResult.json(
                        buildJsonObject {
                            put("path", JsonPrimitive(file.absolutePath))
                            put("sizeBytes", JsonPrimitive(file.length()))
                            put("bytesAppended", JsonPrimitive(body.size + extra.size))
                        },
                    )
                }
            },

            // ---------- 目录浏览 ----------
            f.tool(
                "file.list", "列出目录内容（文件名/大小/修改时间），支持通配符过滤与递归", ToolCategory.FILE,
                PermissionScope.READ_FILE, RiskLevel.LOW, timeoutMs = 60_000,
                inputSchema = Schemas.objectSchema(
                    "path" to Schemas.strSchema("目录路径（默认工作目录）"),
                    "pattern" to Schemas.strSchema("通配符过滤，如 *.js（默认全部）"),
                    "recursive" to Schemas.boolSchema("是否递归子目录（默认 false）"),
                    "limit" to Schemas.intSchema("最多返回条目数（默认 200）"),
                ),
            ) { args ->
                val dir = resolveFile(deps, ToolArgs.str(args, "path"))
                guard(dir)?.let { return@tool McpToolResult.error("PATH_BLOCKED", it) }
                if (!dir.exists()) return@tool McpToolResult.error("DIR_NOT_FOUND", "目录不存在: ${dir.absolutePath}")
                if (!dir.isDirectory) return@tool McpToolResult.error("NOT_DIRECTORY", "目标是文件: ${dir.absolutePath}")
                val pattern = ToolArgs.optStr(args, "pattern")?.takeIf { it.isNotBlank() }
                val recursive = ToolArgs.bool(args, "recursive")
                val limit = ToolArgs.int(args, "limit", 200).coerceIn(1, 5000)
                withContext(Dispatchers.IO) {
                    val files = if (recursive) dir.walkTopDown().filter { it != dir }.toList()
                    else dir.listFiles()?.toList() ?: emptyList()
                    val filtered = pattern?.let { p -> files.filter { globMatches(it.name, p) } } ?: files
                    val sorted = filtered.sortedWith(compareByDescending<File> { it.isDirectory }.thenBy { it.name.lowercase() })
                    val entries = sorted.take(limit).map { file ->
                        buildJsonObject {
                            put("name", JsonPrimitive(file.name))
                            put("path", JsonPrimitive(file.absolutePath))
                            put("isDirectory", JsonPrimitive(file.isDirectory))
                            put("sizeBytes", JsonPrimitive(if (file.isFile) file.length() else -1))
                            put("lastModified", JsonPrimitive(formatTime(file.lastModified())))
                        }
                    }
                    McpToolResult.json(
                        buildJsonObject {
                            put("directory", JsonPrimitive(dir.absolutePath))
                            put("count", JsonPrimitive(entries.size))
                            put("totalMatched", JsonPrimitive(filtered.size))
                            put("truncated", JsonPrimitive(filtered.size > entries.size))
                            put("entries", JsonArray(entries))
                        },
                    )
                }
            },
            f.tool(
                "file.tree", "以树形结构展示目录（限制深度与条目数）", ToolCategory.FILE,
                PermissionScope.READ_FILE, RiskLevel.LOW, timeoutMs = 60_000,
                inputSchema = Schemas.objectSchema(
                    "path" to Schemas.strSchema("目录路径（默认工作目录）"),
                    "depth" to Schemas.intSchema("最大深度（默认 3）"),
                    "maxEntries" to Schemas.intSchema("最多条目数（默认 200）"),
                ),
            ) { args ->
                val dir = resolveFile(deps, ToolArgs.str(args, "path"))
                guard(dir)?.let { return@tool McpToolResult.error("PATH_BLOCKED", it) }
                if (!dir.exists() || !dir.isDirectory) {
                    return@tool McpToolResult.error("DIR_NOT_FOUND", "目录不存在: ${dir.absolutePath}")
                }
                val maxDepth = ToolArgs.int(args, "depth", 3).coerceIn(1, 10)
                val maxEntries = ToolArgs.int(args, "maxEntries", 200).coerceIn(1, 2000)
                withContext(Dispatchers.IO) {
                    val counter = intArrayOf(0)
                    val tree = buildTree(dir, 0, maxDepth, maxEntries, counter)
                    McpToolResult.json(
                        buildJsonObject {
                            put("root", JsonPrimitive(dir.absolutePath))
                            put("entries", JsonPrimitive(counter[0]))
                            put("truncated", JsonPrimitive(counter[0] >= maxEntries))
                            put("tree", tree)
                        },
                    )
                }
            },

            // ---------- 元信息 ----------
            f.tool(
                "file.stat", "获取文件/目录元信息（大小、修改时间、可读写性、MIME 类型）", ToolCategory.FILE,
                PermissionScope.READ_FILE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("path" to Schemas.strSchema("文件或目录路径")),
            ) { args ->
                val file = resolveFile(deps, ToolArgs.str(args, "path"))
                guard(file)?.let { return@tool McpToolResult.error("PATH_BLOCKED", it) }
                McpToolResult.json(
                    buildJsonObject {
                        put("exists", JsonPrimitive(file.exists()))
                        if (file.exists()) {
                            put("path", JsonPrimitive(file.absolutePath))
                            put("name", JsonPrimitive(file.name))
                            put("parent", JsonPrimitive(file.parent ?: ""))
                            put("isDirectory", JsonPrimitive(file.isDirectory))
                            put("isFile", JsonPrimitive(file.isFile))
                            put("sizeBytes", JsonPrimitive(file.length()))
                            put("lastModified", JsonPrimitive(formatTime(file.lastModified())))
                            put("canRead", JsonPrimitive(file.canRead()))
                            put("canWrite", JsonPrimitive(file.canWrite()))
                            put("extension", JsonPrimitive(file.extension))
                            put("mimeType", JsonPrimitive(mimeOf(file.name)))
                        }
                    },
                )
            },
            f.tool(
                "file.exists", "检查文件或目录是否存在", ToolCategory.FILE,
                PermissionScope.READ_FILE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("path" to Schemas.strSchema("文件或目录路径")),
            ) { args ->
                val file = resolveFile(deps, ToolArgs.str(args, "path"))
                McpToolResult.json(
                    buildJsonObject {
                        put("path", JsonPrimitive(file.absolutePath))
                        put("exists", JsonPrimitive(file.exists()))
                        put("isDirectory", JsonPrimitive(file.isDirectory))
                        put("isFile", JsonPrimitive(file.isFile))
                    },
                )
            },

            // ---------- 目录操作 ----------
            f.tool(
                "file.mkdir", "创建目录（支持多级）", ToolCategory.FILE,
                PermissionScope.WRITE_FILE, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema("path" to Schemas.strSchema("目录路径")),
            ) { args ->
                val dir = resolveFile(deps, ToolArgs.str(args, "path"))
                guard(dir)?.let { return@tool McpToolResult.error("PATH_BLOCKED", it) }
                withContext(Dispatchers.IO) {
                    if (dir.exists()) {
                        McpToolResult.json(
                            buildJsonObject {
                                put("created", JsonPrimitive(false))
                                put("path", JsonPrimitive(dir.absolutePath))
                                put("reason", JsonPrimitive("目录已存在"))
                            },
                        )
                    } else {
                        val ok = dir.mkdirs()
                        if (ok) McpToolResult.json(
                            buildJsonObject {
                                put("created", JsonPrimitive(true))
                                put("path", JsonPrimitive(dir.absolutePath))
                            },
                        ) else McpToolResult.error("MKDIR_FAILED", "创建失败（权限不足？）: ${dir.absolutePath}")
                    }
                }
            },
            f.tool(
                "file.delete", "删除文件或目录（目录需 recursive=true 才能删除非空内容）", ToolCategory.FILE,
                PermissionScope.WRITE_FILE, RiskLevel.HIGH, timeoutMs = 60_000,
                inputSchema = Schemas.objectSchema(
                    "path" to Schemas.strSchema("目标路径"),
                    "recursive" to Schemas.boolSchema("目录递归删除（默认 false，非空目录会拒绝）"),
                ),
            ) { args ->
                val file = resolveFile(deps, ToolArgs.str(args, "path"))
                guard(file)?.let { return@tool McpToolResult.error("PATH_BLOCKED", it) }
                if (!file.exists()) return@tool McpToolResult.error("FILE_NOT_FOUND", "路径不存在: ${file.absolutePath}")
                val recursive = ToolArgs.bool(args, "recursive")
                withContext(Dispatchers.IO) {
                    if (file.isDirectory && !recursive && file.listFiles()?.isNotEmpty() == true) {
                        return@withContext McpToolResult.error(
                            "DIR_NOT_EMPTY",
                            "目录非空，需 recursive=true: ${file.absolutePath}",
                        )
                    }
                    val ok = if (recursive) file.deleteRecursively() else file.delete()
                    if (ok) McpToolResult.json(
                        buildJsonObject {
                            put("deleted", JsonPrimitive(true))
                            put("path", JsonPrimitive(file.absolutePath))
                        },
                    ) else McpToolResult.error("DELETE_FAILED", "删除失败（权限不足？）: ${file.absolutePath}")
                }
            },

            // ---------- 复制/移动 ----------
            f.tool(
                "file.copy", "复制文件或目录（目录递归复制）", ToolCategory.FILE,
                PermissionScope.WRITE_FILE, RiskLevel.MEDIUM, timeoutMs = 120_000,
                inputSchema = Schemas.objectSchema(
                    "source" to Schemas.strSchema("源路径"),
                    "destination" to Schemas.strSchema("目标路径（目录则复制到其内）"),
                    "overwrite" to Schemas.boolSchema("目标存在时是否覆盖（默认 true）"),
                ),
            ) { args ->
                val src = resolveFile(deps, ToolArgs.str(args, "source"))
                guard(src)?.let { return@tool McpToolResult.error("PATH_BLOCKED", it) }
                if (!src.exists()) return@tool McpToolResult.error("FILE_NOT_FOUND", "源不存在: ${src.absolutePath}")
                val dst = resolveFile(deps, ToolArgs.str(args, "destination"))
                guard(dst)?.let { return@tool McpToolResult.error("PATH_BLOCKED", it) }
                val overwrite = ToolArgs.bool(args, "overwrite", true)
                withContext(Dispatchers.IO) {
                    val target = if (dst.isDirectory) File(dst, src.name) else dst
                    if (target.exists() && !overwrite) {
                        return@withContext McpToolResult.error("FILE_EXISTS", "目标已存在: ${target.absolutePath}")
                    }
                    val count = copyRecursive(src, target)
                    McpToolResult.json(
                        buildJsonObject {
                            put("copied", JsonPrimitive(true))
                            put("from", JsonPrimitive(src.absolutePath))
                            put("to", JsonPrimitive(target.absolutePath))
                            put("entries", JsonPrimitive(count))
                            put("sizeBytes", JsonPrimitive(target.length()))
                        },
                    )
                }
            },
            f.tool(
                "file.move", "移动或重命名文件/目录", ToolCategory.FILE,
                PermissionScope.WRITE_FILE, RiskLevel.MEDIUM, timeoutMs = 120_000,
                inputSchema = Schemas.objectSchema(
                    "source" to Schemas.strSchema("源路径"),
                    "destination" to Schemas.strSchema("目标路径（目录则移动到其内）"),
                ),
            ) { args ->
                val src = resolveFile(deps, ToolArgs.str(args, "source"))
                guard(src)?.let { return@tool McpToolResult.error("PATH_BLOCKED", it) }
                if (!src.exists()) return@tool McpToolResult.error("FILE_NOT_FOUND", "源不存在: ${src.absolutePath}")
                val dst = resolveFile(deps, ToolArgs.str(args, "destination"))
                guard(dst)?.let { return@tool McpToolResult.error("PATH_BLOCKED", it) }
                withContext(Dispatchers.IO) {
                    val target = if (dst.isDirectory) File(dst, src.name) else dst
                    target.parentFile?.mkdirs()
                    val ok = if (src.renameTo(target)) true else {
                        // 跨分区：复制后删源
                        copyRecursive(src, target) > 0 && src.deleteRecursively()
                    }
                    if (ok) McpToolResult.json(
                        buildJsonObject {
                            put("moved", JsonPrimitive(true))
                            put("from", JsonPrimitive(src.absolutePath))
                            put("to", JsonPrimitive(target.absolutePath))
                        },
                    ) else McpToolResult.error("MOVE_FAILED", "移动失败（目标存在或权限不足）")
                }
            },

            // ---------- 内容搜索（逆向核心） ----------
            f.tool(
                "file.search", "在文件或目录中搜索文本/正则（本地 grep）。逆向下载的 JS 大文件时用它定位 sign/md5/encrypt 等关键代码，压缩单行大文件会自动截取匹配点上下文窗口（contextChars 可调，默认单侧 120 字符，最大 2000）", ToolCategory.FILE,
                PermissionScope.READ_FILE, RiskLevel.LOW, timeoutMs = 120_000,
                inputSchema = Schemas.objectSchema(
                    "path" to Schemas.strSchema("文件或目录路径（目录默认递归）"),
                    "query" to Schemas.strSchema("搜索关键词或正则表达式"),
                    "isRegex" to Schemas.boolSchema("query 是否为正则表达式（默认 false）"),
                    "ignoreCase" to Schemas.boolSchema("忽略大小写（默认 false）"),
                    "filePattern" to Schemas.strSchema("文件名通配符，如 *.js（默认全部文本文件）"),
                    "recursive" to Schemas.boolSchema("目录递归（默认 true）"),
                    "maxResults" to Schemas.intSchema("最多返回匹配数（默认 50）"),
                    "contextChars" to Schemas.intSchema("超长行时匹配点前后展示的字符窗口（默认 120）"),
                ),
            ) { args ->
                val root = resolveFile(deps, ToolArgs.str(args, "path"))
                guard(root)?.let { return@tool McpToolResult.error("PATH_BLOCKED", it) }
                if (!root.exists()) return@tool McpToolResult.error("FILE_NOT_FOUND", "路径不存在: ${root.absolutePath}")
                val query = ToolArgs.str(args, "query")
                if (query.isBlank()) return@tool McpToolResult.error("INVALID_ARGUMENTS", "query 不能为空")
                val isRegex = ToolArgs.bool(args, "isRegex")
                val ignoreCase = ToolArgs.bool(args, "ignoreCase")
                val filePattern = ToolArgs.optStr(args, "filePattern")?.takeIf { it.isNotBlank() }
                val recursive = ToolArgs.bool(args, "recursive", true)
                val maxResults = ToolArgs.int(args, "maxResults", 50).coerceIn(1, 500)
                val contextChars = ToolArgs.int(args, "contextChars", 120).coerceIn(20, 2000)
                val regex: Regex? = try {
                    if (isRegex) {
                        val opts: Set<RegexOption> = if (ignoreCase) setOf(RegexOption.IGNORE_CASE) else emptySet()
                        query.toRegex(opts)
                    } else {
                        null
                    }
                } catch (e: Exception) {
                    return@tool McpToolResult.error("INVALID_REGEX", "正则表达式无效: ${e.message}")
                }
                withContext(Dispatchers.IO) {
                    val files = if (root.isDirectory) {
                        (if (recursive) root.walkTopDown() else root.walkTopDown().maxDepth(1))
                            .filter { it.isFile }.toList()
                    } else listOf(root)
                    val candidates = files.filter { filePattern == null || globMatches(it.name, filePattern) }
                    val matches = ArrayList<kotlinx.serialization.json.JsonObject>()
                    var scanned = 0
                    var skippedBinary = 0
                    var truncated = false
                    outer@ for (file in candidates) {
                        scanned++
                        var anyBinary = false
                        var idx = -1
                        var done = false
                        try {
                            // 报29：逐行流式搜索，不再 readBytes+split 整读，大文件也不跳读
                            file.inputStream().bufferedReader(Charsets.UTF_8).use { reader ->
                                while (true) {
                                    val line = reader.readLine() ?: break
                                    idx++
                                    if (line.indexOf('\u0000') >= 0) { anyBinary = true; break }
                                    var col = -1
                                    if (regex != null) {
                                        val m = regex.find(line)
                                        if (m != null) col = m.range.first
                                    } else if (ignoreCase) {
                                        col = line.lowercase().indexOf(query.lowercase())
                                    } else {
                                        col = line.indexOf(query)
                                    }
                                    if (col >= 0) {
                                        // 修复（实测问题：AI 调大 contextChars 想看更多上下文，
                                        // 结果仍被 take(600) 钉死在 600 字符，参数形同虚设）。
                                        // 上限改为随 contextChars 放大（单侧 2000 → 最多约 4100 字符），
                                        // 兼顾响应体积与"看清楚命中点周围代码"的实际需要。
                                        val context = if (line.length > 500) {
                                            val start = (col - contextChars).coerceAtLeast(0)
                                            val end = (col + contextChars).coerceAtMost(line.length)
                                            "…" + line.substring(start, end) + "…"
                                        } else line.trim()
                                        matches.add(
                                            buildJsonObject {
                                                put("file", JsonPrimitive(file.absolutePath))
                                                put("fileName", JsonPrimitive(file.name))
                                                put("line", JsonPrimitive(idx))
                                                put("column", JsonPrimitive(col))
                                                put("context", JsonPrimitive(context.take(contextChars * 2 + 100)))
                                            },
                                        )
                                        if (matches.size >= maxResults) { truncated = true; done = true; break }
                                    }
                                }
                            }
                        } catch (e: Exception) {
                            anyBinary = true
                        }
                        if (anyBinary) skippedBinary++
                        if (done) break@outer
                    }
                    McpToolResult.json(
                        buildJsonObject {
                            put("root", JsonPrimitive(root.absolutePath))
                            put("query", JsonPrimitive(query))
                            put("count", JsonPrimitive(matches.size))
                            put("scannedFiles", JsonPrimitive(scanned))
                            put("skippedBinary", JsonPrimitive(skippedBinary))
                            put("truncated", JsonPrimitive(truncated))
                            put("matches", JsonArray(matches))
                        },
                    )
                }
            },

            // ---------- 打开/分享 ----------
            f.tool(
                "file.open", "用系统应用打开文件（如用浏览器打开 HTML、播放器播放音频，会在设备上唤起对应 App）", ToolCategory.FILE,
                PermissionScope.READ_FILE, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "path" to Schemas.strSchema("文件路径"),
                    "mimeType" to Schemas.strSchema("强制指定 MIME 类型（默认按扩展名推断）"),
                ),
            ) { args ->
                val file = resolveFile(deps, ToolArgs.str(args, "path"))
                guard(file)?.let { return@tool McpToolResult.error("PATH_BLOCKED", it) }
                if (!file.exists()) return@tool McpToolResult.error("FILE_NOT_FOUND", "文件不存在: ${file.absolutePath}")
                if (file.isDirectory) return@tool McpToolResult.error("IS_DIRECTORY", "目标是目录: ${file.absolutePath}")
                val ctx = contextOf(deps)
                val mime = ToolArgs.optStr(args, "mimeType")?.takeIf { it.isNotBlank() } ?: mimeOf(file.name)
                val uri = contentUriFor(ctx, file)
                val intent = Intent(Intent.ACTION_VIEW).apply {
                    setDataAndType(uri, mime)
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                try {
                    ctx.startActivity(intent)
                    McpToolResult.json(
                        buildJsonObject {
                            put("opened", JsonPrimitive(true))
                            put("path", JsonPrimitive(file.absolutePath))
                            put("mimeType", JsonPrimitive(mime))
                        },
                    )
                } catch (e: Exception) {
                    McpToolResult.error("NO_HANDLER", "设备上没有能打开 $mime 的应用: ${e.message}")
                }
            },
            f.tool(
                "file.share", "弹出系统分享面板分享文件（发送给微信/QQ/邮件等）", ToolCategory.FILE,
                PermissionScope.READ_FILE, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "path" to Schemas.strSchema("文件路径"),
                    "mimeType" to Schemas.strSchema("强制指定 MIME 类型（默认按扩展名推断）"),
                ),
            ) { args ->
                val file = resolveFile(deps, ToolArgs.str(args, "path"))
                guard(file)?.let { return@tool McpToolResult.error("PATH_BLOCKED", it) }
                if (!file.exists()) return@tool McpToolResult.error("FILE_NOT_FOUND", "文件不存在: ${file.absolutePath}")
                val ctx = contextOf(deps)
                val mime = ToolArgs.optStr(args, "mimeType")?.takeIf { it.isNotBlank() } ?: mimeOf(file.name)
                val uri = contentUriFor(ctx, file)
                val send = Intent(Intent.ACTION_SEND).apply {
                    type = mime
                    putExtra(Intent.EXTRA_STREAM, uri)
                    putExtra(Intent.EXTRA_SUBJECT, file.name)
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                }
                try {
                    ctx.startActivity(Intent.createChooser(send, "分享 ${file.name}").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                    McpToolResult.json(
                        buildJsonObject {
                            put("shared", JsonPrimitive(true))
                            put("path", JsonPrimitive(file.absolutePath))
                            put("mimeType", JsonPrimitive(mime))
                        },
                    )
                } catch (e: Exception) {
                    McpToolResult.error("SHARE_FAILED", "分享失败: ${e.message}")
                }
            },

            // ---------- 压缩 ----------
            f.tool(
                "file.zip", "把文件或目录打包为 zip", ToolCategory.FILE,
                PermissionScope.WRITE_FILE, RiskLevel.MEDIUM, timeoutMs = 300_000,
                inputSchema = Schemas.objectSchema(
                    "source" to Schemas.strSchema("源文件或目录"),
                    "destination" to Schemas.strSchema("目标 zip 路径（默认 工作目录/<源名>.zip）"),
                ),
            ) { args ->
                val src = resolveFile(deps, ToolArgs.str(args, "source"))
                guard(src)?.let { return@tool McpToolResult.error("PATH_BLOCKED", it) }
                if (!src.exists()) return@tool McpToolResult.error("FILE_NOT_FOUND", "源不存在: ${src.absolutePath}")
                val dst = ToolArgs.optStr(args, "destination")?.takeIf { it.isNotBlank() }
                    ?.let { resolveFile(deps, it) }
                    ?: File(WorkDir.directory(contextOf(deps)), "${src.name}.zip")
                guard(dst)?.let { return@tool McpToolResult.error("PATH_BLOCKED", it) }
                withContext(Dispatchers.IO) {
                    dst.parentFile?.mkdirs()
                    var entries = 0
                    ZipOutputStream(dst.outputStream().buffered()).use { zos ->
                        val roots = if (src.isDirectory) src.listFiles()?.toList() ?: emptyList() else listOf(src)
                        fun writeEntry(file: File, entryName: String) {
                            if (file.isDirectory) {
                                val children = file.listFiles()?.sortedBy { it.name } ?: return
                                for (child in children) writeEntry(child, "$entryName${child.name}${if (child.isDirectory) "/" else ""}")
                            } else {
                                zos.putNextEntry(ZipEntry(entryName))
                                file.inputStream().use { it.copyTo(zos) }
                                zos.closeEntry()
                                entries++
                            }
                        }
                        for (r in roots) writeEntry(r, r.name + if (r.isDirectory) "/" else "")
                    }
                    McpToolResult.json(
                        buildJsonObject {
                            put("zipped", JsonPrimitive(true))
                            put("path", JsonPrimitive(dst.absolutePath))
                            put("entries", JsonPrimitive(entries))
                            put("sizeBytes", JsonPrimitive(dst.length()))
                        },
                    )
                }
            },
            f.tool(
                "file.unzip", "解压 zip 到目录（自动防护 Zip Slip 路径穿越）", ToolCategory.FILE,
                PermissionScope.WRITE_FILE, RiskLevel.MEDIUM, timeoutMs = 300_000,
                inputSchema = Schemas.objectSchema(
                    "path" to Schemas.strSchema("zip 文件路径"),
                    "destination" to Schemas.strSchema("解压目标目录（默认 工作目录/<zip名>/）"),
                ),
            ) { args ->
                val zip = resolveFile(deps, ToolArgs.str(args, "path"))
                guard(zip)?.let { return@tool McpToolResult.error("PATH_BLOCKED", it) }
                if (!zip.exists() || !zip.isFile) {
                    return@tool McpToolResult.error("FILE_NOT_FOUND", "zip 文件不存在: ${zip.absolutePath}")
                }
                val dst = ToolArgs.optStr(args, "destination")?.takeIf { it.isNotBlank() }
                    ?.let { resolveFile(deps, it) }
                    ?: File(WorkDir.directory(contextOf(deps)), zip.nameWithoutExtension)
                guard(dst)?.let { return@tool McpToolResult.error("PATH_BLOCKED", it) }
                withContext(Dispatchers.IO) {
                    dst.mkdirs()
                    var count = 0
                    ZipFile(zip).use { zf ->
                        val entries = zf.entries()
                        while (entries.hasMoreElements()) {
                            val entry = entries.nextElement()
                            val out = File(dst, entry.name)
                            // Zip Slip 防护
                            val canonicalDst = dst.canonicalPath + File.separator
                            if (!out.canonicalPath.startsWith(canonicalDst)) {
                                return@withContext McpToolResult.error("ZIP_SLIP_BLOCKED", "非法条目路径: ${entry.name}")
                            }
                            if (entry.isDirectory) {
                                out.mkdirs()
                            } else {
                                out.parentFile?.mkdirs()
                                zf.getInputStream(entry).use { input ->
                                    out.outputStream().use { input.copyTo(it) }
                                }
                                count++
                            }
                        }
                    }
                    McpToolResult.json(
                        buildJsonObject {
                            put("unzipped", JsonPrimitive(true))
                            put("path", JsonPrimitive(zip.absolutePath))
                            put("destination", JsonPrimitive(dst.absolutePath))
                            put("files", JsonPrimitive(count))
                        },
                    )
                }
            },
        )
    }

    // ---------------- 私有辅助 ----------------

    private fun contextOf(deps: ToolDependencies): Context = deps.browserService.appContext()

    /** 解析路径：空 → 工作目录；相对 → 工作目录下（强制约束在工作区内）；绝对 → 原样 */
    private fun resolveFile(deps: ToolDependencies, rawPath: String): File {
        val trimmed = rawPath.trim()
        return when {
            trimmed.isEmpty() -> WorkDir.directory(contextOf(deps))
            trimmed.startsWith("/") -> File(trimmed)
            else -> {
                val ws = WorkDir.directory(contextOf(deps))
                val wf = File(ws, trimmed)
                // 报27/28：工作区相对路径必须始终落在工作区内。
                // 用 canonicalPath（跟随符号链接）做双重校验：既挡 .. 穿越，也挡符号链接逃逸。
                val wsCanon = try { ws.canonicalPath } catch (e: Exception) { ws.path }
                val cf = try { wf.canonicalPath } catch (e: Exception) { wf.absolutePath }
                val inside = cf == wsCanon || cf.startsWith(wsCanon + File.separatorChar)
                if (!inside) {
                    // 越界 → 返回会被 guard() 拦截的哨兵路径（BLOCKED_PREFIXES 含 /proc）
                    File("/proc/self/__ws_escape_blocked")
                } else {
                    wf
                }
            }
        }
    }

    /** 系统保护目录防护，返回 null 表示放行 */
    private fun guard(file: File): String? {
        val p = try {
            file.canonicalPath
        } catch (e: Exception) {
            file.absolutePath
        }
        if (BLOCKED_PREFIXES.any { p == it || p.startsWith("$it/") }) {
            return "路径 $p 位于系统保护目录，禁止访问"
        }
        return null
    }

    /** 流式读取 [offset, offset+length) 字节区间（跳过 + 定长读，内存只占区间大小）。文件过短时返回实际读到的部分 */
    private fun readRangeBytes(file: File, offset: Long, length: Long): ByteArray {
        val out = java.io.ByteArrayOutputStream(minOf(length, 64L * 1024).toInt())
        file.inputStream().buffered(64 * 1024).use { ins ->
            var skipped = 0L
            while (skipped < offset) {
                val s = ins.skip(offset - skipped)
                if (s <= 0) break
                skipped += s
            }
            val buf = ByteArray(64 * 1024)
            var remaining = length
            while (remaining > 0) {
                val r = ins.read(buf, 0, minOf(buf.size.toLong(), remaining).toInt())
                if (r < 0) break
                out.write(buf, 0, r)
                remaining -= r
            }
        }
        return out.toByteArray()
    }

    /** 预览用的文本/二进制启发式判定：含空字节，或 UTF-8 解码替换符占比过高 */
    private fun isBinaryPreview(bytes: ByteArray): Boolean {
        if (bytes.indexOf(0.toByte()) >= 0) return true
        val s = String(bytes, Charsets.UTF_8)
        val repl = s.count { it == '\uFFFD' }
        return repl * 10 > s.length.coerceAtLeast(1)
    }

    /** 简单通配符匹配（* 与 ?） */
    private fun globMatches(name: String, pattern: String): Boolean {
        val regex = pattern.replace(".", "\\.").replace("*", ".*").replace("?", ".")
        return name.matches(Regex(regex, RegexOption.IGNORE_CASE))
    }

    // ================= 文本分页核心（纯逻辑，可单测） =================

    /** 分页读出的一行：line 为 0 基行号，text 为列窗口后的内容，colTruncated 表示该行被 colLimit 截断 */
    internal data class PagedLine(val line: Long, val text: String, val colTruncated: Boolean)

    /**
     * file.read 文本模式分页结果。
     *
     * @param truncated 是否提前停止（后面还有未读内容：行方向看 nextOffset，列方向看 nextColOffset）
     * @param totalLines 精确总行数（totalLinesKnown=true 时可信；提前停止时为已读窗口估算）
     * @param anyLineCut 窗口内有行被 colLimit 截断
     * @param nextColOffset 超长行的续读列游标（colOffset + colLimit）
     * @param binary 读到 NUL 疑似二进制，调用方应转 base64 模式
     */
    internal data class TextPage(
        val offset: Int,
        val colOffset: Int,
        val lines: List<PagedLine>,
        val truncated: Boolean,
        val totalLines: Long,
        val totalLinesKnown: Boolean,
        val anyLineCut: Boolean,
        val nextColOffset: Int,
        val binary: Boolean,
    ) {
        val returned: Int get() = lines.size
        val nextOffset: Long get() = offset + lines.size.toLong()
    }

    /**
     * 文本分页核心循环（从 file.read 抽出以便单测）：
     * - 行窗口：跳过 offset 之前的行，最多收集 limit 行
     * - 列窗口：每行先取 colOffset 之后的子串，再截到 colLimit
     * - 字节预算：已有内容且再放一行会超 maxBytes → 停止（首行例外，保证总能读到东西）
     * - 提前停止前试探一行，区分「恰好读完」（truncated=false, totalLines 精确）与「还有更多」
     */
    internal fun pageText(
        reader: java.io.BufferedReader,
        offset: Int,
        limit: Int,
        colOffset: Int,
        colLimit: Int,
        maxBytes: Long,
    ): TextPage {
        var truncated = false
        var used = 0L
        var lineNo = 0L
        var totalLines = 0L
        var totalLinesKnown = true
        var anyLineCut = false
        var cutAtCol = 0
        var binaryDetected = false
        val out = ArrayList<PagedLine>(minOf(limit, 512))
        while (true) {
            val raw = reader.readLine() ?: break
            if (raw.indexOf('\u0000') >= 0) { binaryDetected = true; break }
            if (lineNo >= offset) {
                // 行内列窗口（对窗口内每一行生效）
                var display = if (colOffset > 0) {
                    if (colOffset < raw.length) raw.substring(colOffset) else ""
                } else {
                    raw
                }
                var lineCut = false
                if (display.length > colLimit) {
                    display = display.take(colLimit)
                    lineCut = true
                    anyLineCut = true
                    cutAtCol = colOffset + colLimit
                }
                // 字节预算：已有内容且再放一行会超限 → 先停止（首行例外，
                // 保证窗口起点总能读到东西；单行已被 colLimit 封顶）
                if (out.isNotEmpty() && used + display.length > maxBytes) {
                    truncated = true
                    break
                }
                used += display.length
                out.add(PagedLine(lineNo, display, lineCut))
                // 凑够行数或超字节预算：提前停止。先试探一行确认后面
                // 是否真有内容——恰好读完整个文件时不误报 truncated。
                if (out.size >= limit || used > maxBytes) {
                    if (reader.readLine() != null) {
                        truncated = true
                        totalLinesKnown = false
                    } else {
                        totalLines = lineNo + 1
                    }
                    break
                }
            }
            lineNo++
        }
        // 自然读到 EOF（未提前停止）时 totalLines 精确；提前停止时为已读窗口估算
        if (totalLinesKnown && totalLines == 0L) totalLines = lineNo
        if (truncated) totalLines = offset + out.size.toLong()
        return TextPage(
            offset = offset,
            colOffset = colOffset,
            lines = out,
            truncated = truncated,
            totalLines = totalLines,
            totalLinesKnown = totalLinesKnown && !truncated,
            anyLineCut = anyLineCut,
            nextColOffset = cutAtCol,
            binary = binaryDetected,
        )
    }

    private fun formatTime(millis: Long): String =
        if (millis <= 0) "" else SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date(millis))

    /** 常见扩展名 → MIME */
    private fun mimeOf(name: String): String {
        val ext = name.substringAfterLast('.', "").lowercase()
        return when (ext) {
            "txt", "log", "text", "conf", "ini" -> "text/plain"
            "js", "mjs", "cjs" -> "text/javascript"
            "json", "har", "map" -> "application/json"
            "html", "htm" -> "text/html"
            "css" -> "text/css"
            "xml" -> "text/xml"
            "svg" -> "image/svg+xml"
            "py" -> "text/x-python"
            "java" -> "text/x-java-source"
            "kt" -> "text/x-kotlin"
            "md", "markdown" -> "text/markdown"
            "csv", "tsv" -> "text/csv"
            "png" -> "image/png"
            "jpg", "jpeg" -> "image/jpeg"
            "gif" -> "image/gif"
            "webp" -> "image/webp"
            "bmp" -> "image/bmp"
            "pdf" -> "application/pdf"
            "zip" -> "application/zip"
            "gz" -> "application/gzip"
            "mp3", "m4a", "aac" -> "audio/mpeg"
            "wav" -> "audio/wav"
            "mp4", "m4v" -> "video/mp4"
            "apk" -> "application/vnd.android.package-archive"
            else -> "application/octet-stream"
        }
    }

    /** 公共存储路径 → FileProvider content:// URI，保证其他 App 能读取 */
    private fun contentUriFor(context: Context, file: File): Uri =
        androidx.core.content.FileProvider.getUriForFile(
            context,
            "${context.packageName}.fileprovider",
            file,
        )

    /** 递归复制，返回复制的文件数 */
    private fun copyRecursive(src: File, dst: File): Int {
        var count = 0
        if (src.isDirectory) {
            dst.mkdirs()
            src.listFiles()?.forEach { child ->
                count += copyRecursive(child, File(dst, child.name))
            }
        } else {
            dst.parentFile?.mkdirs()
            src.copyTo(dst, overwrite = true)
            count = 1
        }
        return count
    }

    /** 构建目录树 JSON */
    private fun buildTree(dir: File, depth: Int, maxDepth: Int, maxEntries: Int, counter: IntArray): kotlinx.serialization.json.JsonObject =
        buildJsonObject {
            put("name", JsonPrimitive(dir.name))
            put("path", JsonPrimitive(dir.absolutePath))
            put("type", JsonPrimitive("directory"))
            val children = dir.listFiles()?.sortedWith(
                compareByDescending<File> { it.isDirectory }.thenBy { it.name.lowercase() },
            ) ?: return@buildJsonObject
            put(
                "children",
                JsonArray(
                    children.mapNotNull { child ->
                        if (counter[0] >= maxEntries) return@mapNotNull null
                        counter[0]++
                        if (child.isDirectory) {
                            if (depth + 1 < maxDepth) buildTree(child, depth + 1, maxDepth, maxEntries, counter)
                            else buildJsonObject {
                                put("name", JsonPrimitive(child.name))
                                put("path", JsonPrimitive(child.absolutePath))
                                put("type", JsonPrimitive("directory"))
                                put("children", JsonPrimitive("[深度截断]"))
                            }
                        } else {
                            buildJsonObject {
                                put("name", JsonPrimitive(child.name))
                                put("path", JsonPrimitive(child.absolutePath))
                                put("type", JsonPrimitive("file"))
                                put("sizeBytes", JsonPrimitive(child.length()))
                            }
                        }
                    },
                ),
            )
        }
}
