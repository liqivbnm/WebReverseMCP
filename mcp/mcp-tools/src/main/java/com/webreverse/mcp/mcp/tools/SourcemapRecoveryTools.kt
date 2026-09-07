package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.common.util.WorkDir
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import com.webreverse.mcp.devtools.protocol.cdp.CdpScript
import com.webreverse.mcp.javascript.analysis.MappingEntry
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * Source Map 整包自动还原（Agent 少写胶水 第 1 块）。
 *
 * 背景：已有 SourceMapParser（VLQ/mappings 解码）、单点反查（locateOriginal/reverseLocate）
 * 与 debugger.list_source_maps（下载 + 缓存），但还原到「可读的整包原始源码树」
 * 仍需 Agent 手动逐文件拼胶水。
 *
 * sourcemap.recover 一次调用完成：
 * 1. CDP 列出所有声明 sourceMappingURL 的脚本，自动下载/复用缓存 map；
 * 2. sourcesContent 存在 → 按原始路径直接落盘（真实源码）；
 * 3. sourcesContent 缺失 → 按 mappings 从 bundle 切片近似还原（manifest 标记 approximate）；
 * 4. 输出源码树 + manifest.json + 可选 zip 包，供 file.read / file.search 直接离线分析。
 */
object SourcemapRecoveryTools {

    private const val MAX_FILE_BYTES = 8 * 1024 * 1024

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)

        return listOf(
            f.tool(
                "sourcemap.recover",
                "Source Map 整包自动还原：把页面上所有（或指定）带 sourceMappingURL 的脚本一键还原为原始源码树——" +
                    "sourcesContent 直接落盘，缺失时按 mappings 从 bundle 切片近似还原；输出文件清单 + manifest.json + 可选 zip。" +
                    "配合 file.read/file.search 即可离线阅读还原后的原始源码（webpack/rollup/vite 工程逆向标配）",
                ToolCategory.REVERSE,
                PermissionScope.READ_FILE, RiskLevel.LOW, timeoutMs = 300_000,
                inputSchema = Schemas.objectSchema(
                    "scriptId" to Schemas.strSchema("只还原指定脚本（来自 debugger.list_scripts；空=全部带 map 的脚本）"),
                    "urlContains" to Schemas.strSchema("按 URL 子串过滤脚本（如 bundle/app）"),
                    "outputDir" to Schemas.strSchema("输出目录（工作目录相对路径，默认 sourcemap/<host>）"),
                    "sourcesFilter" to Schemas.strSchema("只还原匹配的 source 文件（子串匹配，如 src/api/）"),
                    "zip" to Schemas.boolSchema("打包为 zip（默认 true）"),
                    "maxFiles" to Schemas.intSchema("单脚本最大还原文件数（默认 2000）", min = 1, max = 20000),
                ),
            ) { args ->
                val scriptId = ToolArgs.str(args, "scriptId")
                val urlContains = ToolArgs.str(args, "urlContains")
                val outputDirArg = ToolArgs.str(args, "outputDir")
                val sourcesFilter = ToolArgs.str(args, "sourcesFilter")
                val wantZip = ToolArgs.bool(args, "zip", true)
                val maxFiles = ToolArgs.int(args, "maxFiles", 2000).coerceIn(1, 20000)

                // ---------- CDP 附加 + 脚本与 map 收集 ----------
                if (deps.debuggerManager.backend != "cdp") {
                    val s = deps.activeSession()
                    deps.debuggerManager.attach(s.engine)
                }
                val session = deps.activeSession()
                val engine = session.engine
                val allScripts: List<CdpScript> = deps.debuggerManager.listScripts(engine)
                    .filter { !it.sourceMapUrl.isNullOrBlank() && it.url.isNotBlank() }
                if (allScripts.isEmpty()) {
                    return@tool McpToolResult.error(
                        "NO_SOURCE_MAPPED_SCRIPTS",
                        "页面没有声明 sourceMappingURL 的脚本（CDP Debugger.scriptParsed sourceMapURL）。" +
                            "确认页面已加载、debugger 已 attach（debugger.attach），" +
                            "或该站点的 map 已被移除（此时可尝试在 URL 后拼 .map 手动验证）",
                    )
                }
                val scoped = allScripts.filter { s ->
                    (scriptId.isBlank() || s.scriptId == scriptId) &&
                        (urlContains.isBlank() || s.url.contains(urlContains))
                }
                if (scoped.isEmpty()) {
                    return@tool McpToolResult.error(
                        "SCRIPT_NOT_MATCHED",
                        "过滤后无脚本；可用 debugger.list_scripts 查看带 sourcemap 的脚本清单",
                    )
                }
                // 触发 map 下载（listSourceMappedScripts 内部走 SourceMapService 缓存）
                val entries = deps.debuggerManager.listSourceMappedScripts(engine).associateBy { it.scriptUrl }

                // ---------- 输出目录 ----------
                val context = deps.browserService.appContext()
                val host = runCatching { java.net.URI(scoped.first().url).host ?: "site" }.getOrDefault("site")
                val outRoot = resolveOutDir(context, outputDirArg.ifBlank { "sourcemap/$host" })
                outRoot.mkdirs()
                if (!outRoot.isDirectory) {
                    return@tool McpToolResult.error("OUTPUT_DIR_FAILED", "输出目录创建失败: ${outRoot.absolutePath}")
                }

                var totalWritten = 0
                var totalApprox = 0
                var totalBytes = 0L
                val scriptReports = mutableListOf<kotlinx.serialization.json.JsonObject>()
                val allWrittenFiles = mutableListOf<Pair<File, Long>>()

                for (script in scoped) {
                    val entry = entries[script.url]
                    val info = entry?.info
                    if (info == null || !info.parsed) {
                        scriptReports += buildJsonObject {
                            put("scriptUrl", JsonPrimitive(script.url))
                            put("mapUrl", JsonPrimitive(entry?.sourceMapUrl ?: script.sourceMapUrl ?: ""))
                            put("status", JsonPrimitive("map_unavailable"))
                            put("error", JsonPrimitive(entry?.error ?: "sourcemap 解析失败"))
                        }
                        continue
                    }
                    // 脚本子目录：URL 尾段去扩展名（bundle.min.js → bundle.min）
                    val scriptDir = File(outRoot, sanitizeSegment(script.url.substringBefore('?').substringAfterLast('/').substringBeforeLast('.')).ifBlank { "script-${script.scriptId}" })
                    scriptDir.mkdirs()

                    val mappings = deps.sourceMapParser.decodeMappings(info)
                    // fallback 切片数据（惰性：任一 source 无 sourcesContent 才拉 bundle 源码）
                    var genLines: List<String>? = null
                    val generatedSource: String? = runCatching {
                        deps.debuggerManager.getScriptSource(engine, script.scriptId, 6_000_000).getOrNull()
                    }.getOrNull()

                    var written = 0
                    var approximated = 0
                    val fileReports = mutableListOf<kotlinx.serialization.json.JsonObject>()

                    for ((idx, source) in info.sources.withIndex()) {
                        if (written + approximated >= maxFiles) break
                        if (sourcesFilter.isNotBlank() && !source.contains(sourcesFilter)) continue
                        val rel = normalizeSourcePath(source, info.sourceRoot)
                            ?: continue
                        val outFile = File(scriptDir, rel)
                        // 防穿越校验
                        val rootCanon = try { scriptDir.canonicalPath } catch (e: Exception) { scriptDir.absolutePath }
                        val outCanon = try { outFile.canonicalPath } catch (e: Exception) { outFile.absolutePath }
                        if (!outCanon.startsWith(rootCanon + File.separatorChar)) continue
                        val content: String? = info.sourcesContent.getOrNull(idx)?.takeIf { it.isNotBlank() }
                        when {
                            content != null -> {
                                if (content.toByteArray().size > MAX_FILE_BYTES) continue
                                outFile.parentFile?.mkdirs()
                                outFile.writeText(content)
                                written++
                                totalWritten++
                                totalBytes += content.toByteArray().size
                                allWrittenFiles += outFile to outFile.length()
                                fileReports += buildJsonObject {
                                    put("source", JsonPrimitive(source))
                                    put("file", JsonPrimitive(outFile.absolutePath))
                                    put("mode", JsonPrimitive("sourcesContent"))
                                    put("lines", JsonPrimitive(content.count { it == '\n' } + 1))
                                }
                            }
                            generatedSource != null && mappings.isNotEmpty() -> {
                                if (genLines == null) genLines = generatedSource.split("\n")
                                val approx = approximateSlice(mappings, source, genLines!!)
                                    ?: continue
                                val text = buildString {
                                    appendLine("// [WebReverseMCP] 近似还原：sourcesContent 缺失，按 mappings 从 bundle 切片（非真实源码，行号对齐原始文件）")
                                    approx.forEach { (_, lineText) ->
                                        appendLine(lineText)
                                    }
                                }
                                if (text.toByteArray().size > MAX_FILE_BYTES) continue
                                outFile.parentFile?.mkdirs()
                                outFile.writeText(text)
                                approximated++
                                totalApprox++
                                totalBytes += text.toByteArray().size
                                allWrittenFiles += outFile to outFile.length()
                                fileReports += buildJsonObject {
                                    put("source", JsonPrimitive(source))
                                    put("file", JsonPrimitive(outFile.absolutePath))
                                    put("mode", JsonPrimitive("approximate_slice"))
                                    put("lines", JsonPrimitive(approx.size))
                                }
                            }
                            else -> fileReports += buildJsonObject {
                                put("source", JsonPrimitive(source))
                                put("file", JsonPrimitive(""))
                                put("mode", JsonPrimitive("skipped"))
                                put("error", JsonPrimitive("sourcesContent 缺失且 bundle 源码不可用"))
                            }
                        }
                    }

                    // manifest.json
                    val manifest = buildJsonObject {
                        put("scriptUrl", JsonPrimitive(script.url))
                        put("mapUrl", JsonPrimitive(entry.sourceMapUrl))
                        put("scriptId", JsonPrimitive(script.scriptId))
                        put("sources", JsonPrimitive(info.sources.size))
                        put("written", JsonPrimitive(written))
                        put("approximated", JsonPrimitive(approximated))
                        put("mappingsDecoded", JsonPrimitive(mappings.size))
                        put("files", JsonArray(fileReports))
                    }
                    File(scriptDir, "manifest.json").writeText(manifest.toString())
                    scriptReports += buildJsonObject {
                        put("scriptUrl", JsonPrimitive(script.url))
                        put("mapUrl", JsonPrimitive(entry.sourceMapUrl))
                        put("status", JsonPrimitive("ok"))
                        put("sources", JsonPrimitive(info.sources.size))
                        put("written", JsonPrimitive(written))
                        put("approximated", JsonPrimitive(approximated))
                        put("dir", JsonPrimitive(scriptDir.absolutePath))
                    }
                }

                // ---------- 可选 zip ----------
                var zipPath = ""
                if (wantZip && (totalWritten + totalApprox) > 0) {
                    val zipFile = File(outRoot.absolutePath + ".zip")
                    runCatching {
                        ZipOutputStream(zipFile.outputStream().buffered()).use { zos ->
                            fun put(file: File, name: String) {
                                if (file.isDirectory) {
                                    file.listFiles()?.sortedBy { it.name }?.forEach { put(it, "$name/${it.name}") }
                                } else {
                                    zos.putNextEntry(ZipEntry(name.ltrimSlash()))
                                    file.inputStream().use { it.copyTo(zos) }
                                    zos.closeEntry()
                                }
                            }
                            put(outRoot, outRoot.name)
                        }
                    }.onSuccess { zipPath = zipFile.absolutePath }
                }

                McpToolResult.json(
                    buildJsonObject {
                        put("outputDir", JsonPrimitive(outRoot.absolutePath))
                        put("scripts", JsonPrimitive(scriptReports.size))
                        put("filesWritten", JsonPrimitive(totalWritten))
                        put("filesApproximated", JsonPrimitive(totalApprox))
                        put("totalBytes", JsonPrimitive(totalBytes))
                        put("zip", JsonPrimitive(zipPath))
                        put("manifestHint", JsonPrimitive("每个脚本子目录内有 manifest.json（文件清单 + 还原模式标记）"))
                        put("scriptReports", JsonArray(scriptReports))
                        put(
                            "nextSteps",
                            JsonArray(
                                listOf(
                                    "file.search 在还原源码树里直接 grep（如 sign / encrypt / token）定位关键逻辑",
                                    "断点下钻用 debugger.set_source_breakpoint（原始源码行号）直接命中 bundle",
                                    "近似还原（approximate_slice）仅保留 bundle 内出现过的语句，非完整源码",
                                ).map { JsonPrimitive(it) }
                            ),
                        )
                    },
                )
            },
        )
    }

    // ---------------- 内部工具 ----------------

    /** 工作区相对/绝对路径解析（防穿越，复制 FileTools 语义） */
    private fun resolveOutDir(context: android.content.Context, raw: String): File {
        val trimmed = raw.trim().trimStart('/')
        val ws = WorkDir.directory(context)
        val f = File(ws, trimmed)
        val wsCanon = try { ws.canonicalPath } catch (e: Exception) { ws.path }
        val fCanon = try { f.canonicalPath } catch (e: Exception) { f.absolutePath }
        return if (fCanon.startsWith(wsCanon)) f else File(ws, "sourcemap")
    }

    private fun sanitizeSegment(name: String): String =
        name.replace(Regex("[^A-Za-z0-9._\\-]+"), "_").take(80)

    private fun String.ltrimSlash() = removePrefix("/")

    /**
     * source 路径规范化：剥 webpack:// 等 scheme + host、去 "./"、统一分隔符、去 query。
     * 无法得到安全相对路径时返回 null。
     */
    private fun normalizeSourcePath(source: String, sourceRoot: String): String? {
        var s = source.trim().replace('\\', '/')
        if (s.isBlank()) return null
        // webpack://app/./src/a.ts | webpack-internal:///./src/a.ts | ng:///src/a.ts
        val schemeIdx = s.indexOf("://")
        if (schemeIdx > 0) {
            s = s.substring(schemeIdx + 3)
            // 剥掉第一段（host：app、_N 等）
            s = s.substringAfter('/', s)
        }
        s = s.substringBefore('?').substringBefore('#')
        if (sourceRoot.isNotBlank()) {
            val root = sourceRoot.trimEnd('/')
            if (s.startsWith("$root/")) s = s.removePrefix("$root/")
        }
        while (s.startsWith("./")) s = s.removePrefix("./")
        while (s.startsWith("/")) s = s.removePrefix("/")
        s = s.replace(Regex("^\\[.*?]/"), "") // turbopack [app]/ 前缀
        // [..]/out.js（rollup 虚拟模块）→ out.js
        s = s.replace(Regex("\\[.*?]"), "_virtual_")
        // 拒绝绝对路径与穿越
        if (s.isBlank() || s.startsWith("/") || s.contains("..")) return null
        // Windows 盘符等极端情形
        if (Regex("^[A-Za-z]:").containsMatchIn(s)) return null
        val parts = s.split('/').filter { it.isNotBlank() && it != "." }
        if (parts.isEmpty()) return null
        return parts.joinToString("/")
    }

    /**
     * 近似切片：该 source 的所有 mapping 区间按 generated 顺序切片，
     * 聚合到原始行号（sourceLine），返回 (sourceLine -> text)。
     */
    private fun approximateSlice(
        mappings: List<MappingEntry>,
        source: String,
        genLines: List<String>,
    ): Map<Int, String>? {
        val mine = mappings.filter { it.source == source }
            .sortedWith(compareBy({ it.generatedLine }, { it.generatedColumn }))
        if (mine.isEmpty()) return null
        val buckets = sortedMapOf<Int, StringBuilder>()
        for ((i, m) in mine.withIndex()) {
            val next = mine.getOrNull(i + 1)
            val lineText = genLines.getOrNull(m.generatedLine) ?: continue
            val startCol = m.generatedColumn.coerceIn(0, lineText.length)
            val seg = if (next == null || next.generatedLine > m.generatedLine) {
                lineText.substring(startCol)
            } else {
                lineText.substring(startCol, next.generatedColumn.coerceIn(startCol, lineText.length))
            }.trim()
            if (seg.isBlank()) continue
            buckets.getOrPut(m.sourceLine) { StringBuilder() }
                .append(seg).append(' ')
        }
        if (buckets.isEmpty()) return null
        return buckets.mapValues { (_, sb) -> sb.toString().trim() }
    }
}
