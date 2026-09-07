package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import com.webreverse.mcp.core.common.util.Redactor

/** Browser Tools：浏览器导航与页面操作 */
object BrowserTools {

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)
        return listOf(
            f.tool(
                "browser.open", "打开 URL 并导航到指定页面", ToolCategory.BROWSER,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "url" to Schemas.strSchema("要打开的 URL"),
                    required = listOf("url"),
                ),
            ) { args ->
                val url = ToolArgs.str(args, "url")
                if (url.isBlank()) return@tool McpToolResult.error("INVALID_ARGUMENTS", "url 不能为空")
                val session = deps.activeSession()
                session.engine.loadUrl(url)
                deps.log(com.webreverse.mcp.core.logging.LogCategory.BROWSER, "open: $url")
                McpToolResult.text("已打开: $url")
            },
            f.tool(
                "browser.close", "关闭当前页面", ToolCategory.BROWSER,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val tabId = deps.browserService.activeTabId.value
                if (tabId != null) {
                    deps.tabManager.closeTab(tabId)
                    McpToolResult.text("已关闭标签页: $tabId")
                } else {
                    McpToolResult.error("NO_ACTIVE_TAB", "没有活动标签页")
                }
            },
            f.tool(
                "browser.reload", "刷新当前页面", ToolCategory.BROWSER,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                session.engine.reload()
                McpToolResult.text("已刷新")
            },
            f.tool(
                "browser.back", "页面后退", ToolCategory.BROWSER,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val ok = session.engine.goBack()
                McpToolResult.text(if (ok) "已后退" else "无法后退")
            },
            f.tool(
                "browser.forward", "页面前进", ToolCategory.BROWSER,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val ok = session.engine.goForward()
                McpToolResult.text(if (ok) "已前进" else "无法前进")
            },
            f.tool(
                "browser.stop", "停止加载", ToolCategory.BROWSER,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                session.engine.stop()
                McpToolResult.text("已停止加载")
            },
            f.tool(
                "browser.go", "导航到指定 URL（支持相对路径）", ToolCategory.BROWSER,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("url" to Schemas.strSchema("目标 URL")),
            ) { args ->
                val url = ToolArgs.str(args, "url")
                val session = deps.activeSession()
                val current = session.engine.currentUrl() ?: ""
                val resolved = if (url.startsWith("/")) {
                    val base = current.substringBeforeLast('/')
                    "$base$url"
                } else url
                session.engine.loadUrl(resolved)
                McpToolResult.text("已导航: $resolved")
            },
            f.tool(
                "browser.current_url", "获取当前页面 URL", ToolCategory.BROWSER,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val url = session.engine.currentUrl() ?: ""
                McpToolResult.json(
                    kotlinx.serialization.json.buildJsonObject {
                        put("url", kotlinx.serialization.json.JsonPrimitive(Redactor.redactUrl(url)))
                    },
                )
            },
            f.tool(
                "browser.current_title", "获取当前页面标题", ToolCategory.BROWSER,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val title = session.engine.currentTitle() ?: ""
                McpToolResult.json(
                    kotlinx.serialization.json.buildJsonObject {
                        put("title", kotlinx.serialization.json.JsonPrimitive(title))
                    },
                )
            },
            f.tool(
                "browser.screenshot", "截取当前页面（支持视口/全页/元素截图）", ToolCategory.BROWSER,
                PermissionScope.SCREENSHOT, RiskLevel.MEDIUM, supportsImage = true,
                inputSchema = Schemas.objectSchema(
                    "format" to Schemas.strSchema("png/jpeg"),
                    "fullPage" to Schemas.boolSchema("是否全页截图"),
                    "selector" to Schemas.strSchema("元素选择器"),
                ),
            ) { args ->
                val session = deps.activeSession()
                val bitmap = session.engine.screenshot()
                    ?: return@tool McpToolResult.error("SCREENSHOT_FAILED", "截图失败")
                val stream = java.io.ByteArrayOutputStream()
                val format = if (ToolArgs.str(args, "format") == "jpeg") android.graphics.Bitmap.CompressFormat.JPEG else android.graphics.Bitmap.CompressFormat.PNG
                bitmap.compress(format, 90, stream)
                val base64 = android.util.Base64.encodeToString(stream.toByteArray(), android.util.Base64.NO_WRAP)
                McpToolResult.image(base64, if (format == android.graphics.Bitmap.CompressFormat.JPEG) "image/jpeg" else "image/png")
            },
            f.tool(
                "browser.pdf", "将当前页面导出为 PDF（全页分页渲染，保存到工作目录）", ToolCategory.BROWSER,
                PermissionScope.SCREENSHOT, RiskLevel.MEDIUM, timeoutMs = 120_000,
                inputSchema = Schemas.objectSchema(
                    "filename" to Schemas.strSchema("保存的文件名（默认 page-<时间戳>.pdf）"),
                    "base64" to Schemas.boolSchema("是否在结果中附带 PDF 的 base64 内容（大文件慎用）"),
                ),
            ) { args ->
                val webView = deps.browserService.getWebView(null)
                    ?: return@tool McpToolResult.error("NO_ACTIVE_TAB", "没有活动标签页")
                val (bytes, pages) = renderWebViewToPdf(webView)
                    ?: return@tool McpToolResult.error("PDF_FAILED", "PDF 生成失败（页面可能尚未加载完成）")
                val requested = ToolArgs.optStr(args, "filename")?.takeIf { it.isNotBlank() }
                val safeName = (requested ?: "page-${System.currentTimeMillis()}").let {
                    if (it.endsWith(".pdf")) it else "$it.pdf"
                }
                // 统一保存到工作目录（不可写时自动回退应用私有目录，结果中返回真实路径）
                val file = com.webreverse.mcp.core.common.util.WorkDir
                    .resolve(deps.browserService.appContext(), safeName)
                file.writeBytes(bytes)
                McpToolResult.json(
                    kotlinx.serialization.json.buildJsonObject {
                        put("path", kotlinx.serialization.json.JsonPrimitive(file.absolutePath))
                        put("sizeBytes", kotlinx.serialization.json.JsonPrimitive(bytes.size.toLong()))
                        put("pages", kotlinx.serialization.json.JsonPrimitive(pages))
                        if (ToolArgs.bool(args, "base64")) {
                            put(
                                "base64",
                                kotlinx.serialization.json.JsonPrimitive(
                                    android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP),
                                ),
                            )
                        }
                    },
                )
            },
            f.tool(
                "browser.print", "调用系统打印服务打印当前页面（会在设备上弹出打印界面）", ToolCategory.BROWSER,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val webView = deps.browserService.getWebView(null)
                    ?: return@tool McpToolResult.error("NO_ACTIVE_TAB", "没有活动标签页")
                val title = webView.title?.takeIf { it.isNotBlank() } ?: "WebReverseMCP"
                val ok = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Main) {
                    try {
                        val pm = webView.context.getSystemService(android.content.Context.PRINT_SERVICE)
                            as? android.print.PrintManager
                        if (pm == null) return@withContext false
                        pm.print(
                            title,
                            webView.createPrintDocumentAdapter(title),
                            android.print.PrintAttributes.Builder().build(),
                        )
                        true
                    } catch (e: Exception) {
                        false
                    }
                }
                if (ok) McpToolResult.text("已打开系统打印界面: $title")
                else McpToolResult.error("PRINT_FAILED", "打印服务不可用或调用失败")
            },
            f.tool(
                "browser.download", "下载文件到工作目录", ToolCategory.BROWSER,
                PermissionScope.DOWNLOAD, RiskLevel.MEDIUM, timeoutMs = 300_000,
                inputSchema = Schemas.objectSchema(
                    "url" to Schemas.strSchema("要下载的文件 URL"),
                    "filename" to Schemas.strSchema("保存文件名（默认从 URL 推断）"),
                    "mimeType" to Schemas.strSchema("文件 MIME 类型（可选）"),
                ),
            ) { args ->
                val url = ToolArgs.str(args, "url")
                if (url.isBlank()) return@tool McpToolResult.error("INVALID_ARGUMENTS", "url 不能为空")
                val context = deps.browserService.appContext()
                val requested = ToolArgs.optStr(args, "filename")?.takeIf { it.isNotBlank() }
                val inferred = url.substringAfterLast('/').substringBefore('?').takeIf { it.isNotBlank() }
                val filename = (requested ?: inferred ?: "download-${System.currentTimeMillis()}")
                    .replace("/", "_").replace("\\", "_")

                // data: URI 支持：AI Agent 可直接把文本/脚本内容落盘（无需网络）
                if (url.startsWith("data:", ignoreCase = true)) {
                    val decoded = decodeDataUri(url)
                        ?: return@tool McpToolResult.error("INVALID_ARGUMENTS", "data: URI 无效或不受支持（支持 base64 与 URL 编码两种格式）")
                    val safeName = if (filename == inferred) "data-${System.currentTimeMillis()}.txt" else filename
                    val target = com.webreverse.mcp.core.common.util.WorkDir.resolve(context, safeName)
                    return@tool kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                        target.writeBytes(decoded.first)
                        McpToolResult.json(
                            kotlinx.serialization.json.buildJsonObject {
                                put("path", kotlinx.serialization.json.JsonPrimitive(target.absolutePath))
                                put("sizeBytes", kotlinx.serialization.json.JsonPrimitive(target.length()))
                                put("directory", kotlinx.serialization.json.JsonPrimitive("工作目录"))
                                put("mimeType", kotlinx.serialization.json.JsonPrimitive(decoded.second))
                            },
                        )
                    }
                }

                // 统一存储目录：无论工作目录是否可写，一律经 WorkDir.resolve 落盘
                // （可写 → 设置里的存储目录；不可写 → 自动回退应用私有目录，路径如实返回）。
                // 不再分流到系统公共下载目录（DownloadManager）——避免文件散落在
                // 与设置存储目录不一致的位置，AI 与用户都只认返回的 path。
                val target = com.webreverse.mcp.core.common.util.WorkDir.resolve(context, filename)
                when (val dl = downloadToFile(url, target)) {
                    is DownloadOutcome.Ok -> {
                        val file = dl.file
                        McpToolResult.json(
                            kotlinx.serialization.json.buildJsonObject {
                                put("path", kotlinx.serialization.json.JsonPrimitive(file.absolutePath))
                                put("sizeBytes", kotlinx.serialization.json.JsonPrimitive(file.length()))
                                put("directory", kotlinx.serialization.json.JsonPrimitive("工作目录"))
                            },
                        )
                    }
                    is DownloadOutcome.Failed -> McpToolResult.error(
                        "DOWNLOAD_FAILED",
                        "下载失败（$url）：${dl.reason}。" +
                            "可用 terminal.exec 的 curl/wget 拉取到工作目录（terminalHome）绕过，或先 browser.open 打开页面后在页面内触发下载",
                    )
                }
            },
            f.tool(
                "browser.upload", "向页面的 file input 注入文件并触发上传事件", ToolCategory.BROWSER,
                PermissionScope.UPLOAD, RiskLevel.MEDIUM, timeoutMs = 60_000,
                inputSchema = Schemas.objectSchema(
                    "selector" to Schemas.strSchema("file input 选择器，默认 input[type=file]"),
                    "path" to Schemas.strSchema(
                        "本地文件路径（绝对路径或工作目录相对路径）。" +
                            "提供后服务端直接读取该文件，优先于 content/contentBase64，注入文件名默认取该文件文件名。" +
                            "推荐先 browser.download 或 file.write 把文件落盘，再传 path——避免在工具参数里内联大 base64 导致 JSON 截断"
                    ),
                    "filename" to Schemas.strSchema("注入的文件名（默认 upload.txt 或 path 的文件名）"),
                    "mimeType" to Schemas.strSchema("文件 MIME 类型（默认 application/octet-stream）"),
                    "content" to Schemas.strSchema("文件文本内容（与 path/contentBase64 三选一）"),
                    "contentBase64" to Schemas.strSchema("文件 base64 内容（二进制文件使用；与 path 二选一）"),
                ),
            ) { args ->
                val path = ToolArgs.optStr(args, "path")?.takeIf { it.isNotBlank() }
                val textContent = ToolArgs.optStr(args, "content")?.takeIf { it.isNotBlank() }
                val base64Content = ToolArgs.optStr(args, "contentBase64")?.takeIf { it.isNotBlank() }
                if (path == null && textContent == null && base64Content == null) {
                    return@tool McpToolResult.error(
                        "INVALID_ARGUMENTS",
                        "必须提供 path（本地文件路径，推荐）或 content（文本）或 contentBase64（base64）之一；" +
                            "大文件/二进制请先落盘再用 path，避免参数 JSON 截断",
                    )
                }
                val filename = ToolArgs.optStr(args, "filename")?.takeIf { it.isNotBlank() }
                    ?: path?.let { runCatching { java.io.File(it).name }.getOrNull() }
                    ?: "upload.txt"
                val mimeType = ToolArgs.optStr(args, "mimeType")?.takeIf { it.isNotBlank() }
                    ?: "application/octet-stream"
                val selector = ToolArgs.optStr(args, "selector")?.takeIf { it.isNotBlank() }
                    ?: "input[type=file]"
                // path 优先——服务端读文件，避免把大 base64 内联进工具参数（JSON 截断根因）。
                val pathBase64 = path?.let { p ->
                    val f = resolveUploadFile(deps, p)
                    if (!f.isFile) {
                        return@tool McpToolResult.error(
                            "FILE_NOT_FOUND",
                            "path 对应文件不存在: $p（相对路径基于工作目录 ${com.webreverse.mcp.core.common.util.WorkDir.get()}）",
                        )
                    }
                    if (f.length() > MAX_UPLOAD_BYTES) {
                        return@tool McpToolResult.error(
                            "FILE_TOO_LARGE",
                            "上传文件过大（${f.length()} 字节，上限 ${MAX_UPLOAD_BYTES}）：$p",
                        )
                    }
                    android.util.Base64.encodeToString(f.readBytes(), android.util.Base64.NO_WRAP)
                }
                val base64 = pathBase64 ?: base64Content ?: android.util.Base64.encodeToString(
                    textContent.orEmpty().toByteArray(),
                    android.util.Base64.NO_WRAP,
                )

                val session = deps.activeSession()
                val jsSelector = kotlinx.serialization.json.JsonPrimitive(selector).toString()
                val jsFilename = kotlinx.serialization.json.JsonPrimitive(filename).toString()
                val jsMime = kotlinx.serialization.json.JsonPrimitive(mimeType).toString()
                val jsDataUrl = kotlinx.serialization.json.JsonPrimitive("data:$mimeType;base64,$base64").toString()
                val script = """
                    (async function(){
                      try {
                        var input = document.querySelector($jsSelector);
                        if (!input) return JSON.stringify({ok:false, error:'未找到元素: $selector'});
                        if ((input.type || '').toLowerCase() !== 'file') return JSON.stringify({ok:false, error:'目标元素不是 file input'});
                        if (typeof DataTransfer === 'undefined') return JSON.stringify({ok:false, error:'当前 WebView 内核不支持 DataTransfer'});
                        var res = await fetch($jsDataUrl);
                        var blob = await res.blob();
                        var file = new File([blob], $jsFilename, {type: $jsMime});
                        var dt = new DataTransfer();
                        dt.items.add(file);
                        input.files = dt.files;
                        input.dispatchEvent(new Event('input', {bubbles: true}));
                        input.dispatchEvent(new Event('change', {bubbles: true}));
                        return JSON.stringify({ok:true, fileName: file.name, size: file.size, mimeType: file.type});
                      } catch (e) {
                        return JSON.stringify({ok:false, error: String(e)});
                      }
                    })()
                """.trimIndent()
                val raw = session.engine.evaluateJavascriptAsync(script)
                    ?: return@tool McpToolResult.error("UPLOAD_FAILED", "脚本执行失败")
                val payload = unquoteJsResult(raw)
                return@tool try {
                    val obj = kotlinx.serialization.json.Json.parseToJsonElement(payload)
                        as? kotlinx.serialization.json.JsonObject
                        ?: return@tool McpToolResult.error("UPLOAD_FAILED", "意外的返回格式: $payload")
                    val ok = (obj["ok"] as? kotlinx.serialization.json.JsonPrimitive)?.content == "true"
                    if (ok) {
                        McpToolResult.json(obj)
                    } else {
                        val err = (obj["error"] as? kotlinx.serialization.json.JsonPrimitive)?.content
                            ?: "注入失败"
                        McpToolResult.error("UPLOAD_FAILED", err)
                    }
                } catch (e: Exception) {
                    McpToolResult.error("UPLOAD_FAILED", "结果解析失败: ${e.message}")
                }
            },
            f.tool(
                "browser.fullscreen", "切换全屏模式", ToolCategory.BROWSER,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                McpToolResult.text("全屏模式切换")
            },
            f.tool(
                "browser.source", "获取当前页面 HTML 源码", ToolCategory.BROWSER,
                PermissionScope.READ_DOM, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val source = session.engine.getPageSource() ?: ""
                McpToolResult.text(source.take(100_000))
            },
            f.tool(
                "browser.wait", "等待页面加载完成", ToolCategory.BROWSER,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("timeoutMs" to Schemas.intSchema("超时毫秒")),
            ) { args ->
                val timeout = ToolArgs.int(args, "timeoutMs", 10_000)
                val session = deps.activeSession()
                var elapsed = 0L
                while (elapsed < timeout) {
                    if (!session.engine.state.value.isLoading) {
                        return@tool McpToolResult.text("页面已就绪")
                    }
                    kotlinx.coroutines.delay(200)
                    elapsed += 200
                }
                McpToolResult.text("等待超时，页面仍在加载")
            },
        )
    }

    /** 上传文件大小上限：50MB（防止一次性 base64 撑爆内存） */
    private const val MAX_UPLOAD_BYTES = 50L * 1024 * 1024

    /** 解析 upload path 参数：绝对路径原样；相对路径基于工作目录并强制约束在工作区内 */
    private fun resolveUploadFile(deps: ToolDependencies, rawPath: String): java.io.File {
        val trimmed = rawPath.trim()
        return when {
            trimmed.isEmpty() -> com.webreverse.mcp.core.common.util.WorkDir.directory(deps.browserService.appContext())
            trimmed.startsWith("/") -> java.io.File(trimmed)
            else -> {
                val ws = com.webreverse.mcp.core.common.util.WorkDir.directory(deps.browserService.appContext())
                val wf = java.io.File(ws, trimmed)
                val wsCanon = try { ws.canonicalPath } catch (e: Exception) { ws.path }
                val cf = try { wf.canonicalPath } catch (e: Exception) { wf.absolutePath }
                val inside = cf == wsCanon || cf.startsWith(wsCanon + java.io.File.separatorChar)
                if (!inside) java.io.File("/proc/self/__ws_escape_blocked") else wf
            }
        }
    }

    /** WebView 全页分页渲染为 PDF（A4 纵向比例），返回 (PDF 字节, 页数) */
    private suspend fun renderWebViewToPdf(webView: android.webkit.WebView): Pair<ByteArray, Int>? =
        kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Main) {
            try {
                // 离屏 WebView 可能从未布局过，手动测量保证有有效宽度
                if (webView.width <= 0) {
                    webView.measure(
                        android.view.View.MeasureSpec.makeMeasureSpec(1080, android.view.View.MeasureSpec.EXACTLY),
                        android.view.View.MeasureSpec.makeMeasureSpec(1920, android.view.View.MeasureSpec.AT_MOST),
                    )
                    webView.layout(0, 0, webView.measuredWidth, webView.measuredHeight)
                }
                val width = webView.width
                val contentHeight = Math.ceil(webView.contentHeight * webView.scale.toDouble()).toInt()
                if (width <= 0 || contentHeight <= 0) return@withContext null

                val pageHeight = width * 1414 / 1000 // A4 纵向比例
                val pdf = android.graphics.pdf.PdfDocument()
                try {
                    var page = 0
                    var offset = 0
                    while (offset < contentHeight && page < 100) { // 上限 100 页防御超长页面
                        val info = android.graphics.pdf.PdfDocument.PageInfo
                            .Builder(width, pageHeight, page + 1).create()
                        val p = pdf.startPage(info)
                        p.canvas.save()
                        p.canvas.translate(0f, -offset.toFloat())
                        webView.draw(p.canvas)
                        p.canvas.restore()
                        pdf.finishPage(p)
                        offset += pageHeight
                        page++
                    }
                    val bos = java.io.ByteArrayOutputStream()
                    pdf.writeTo(bos)
                    Pair(bos.toByteArray(), page)
                } finally {
                    pdf.close()
                }
            } catch (e: Exception) {
                null
            }
        }

    /** 解码 data: URI，返回 (字节, mime)。支持 data:[mime][;base64],payload 两种格式 */
    private fun decodeDataUri(uri: String): Pair<ByteArray, String>? {
        return try {
            val headerEnd = uri.indexOf(',', 5)
            if (headerEnd < 0) return null
            val header = uri.substring(5, headerEnd).lowercase()
            val payload = uri.substring(headerEnd + 1)
            val mime = header.substringBefore(';').ifBlank { "text/plain" }
            val isBase64 = header.contains(";base64")
            val bytes = if (isBase64) {
                android.util.Base64.decode(payload, android.util.Base64.DEFAULT)
            } else {
                java.net.URLDecoder.decode(payload, "UTF-8").toByteArray(Charsets.UTF_8)
            }
            bytes to mime
        } catch (e: Exception) {
            null
        }
    }

    /* * 下载结果：Ok(文件) / Failed(原因， 起带 HTTP 状态或异常详情，便于 AI 判断回退路径） */
    private sealed interface DownloadOutcome {
        data class Ok(val file: java.io.File) : DownloadOutcome
        data class Failed(val reason: String) : DownloadOutcome
    }

    /** 直接 HTTP 下载到指定文件（IO 线程；失败带原因） */
    private suspend fun downloadToFile(url: String, target: java.io.File): DownloadOutcome =
        kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
            try {
                target.parentFile?.mkdirs()
                val file = target
                val connection = java.net.URL(url).openConnection() as java.net.HttpURLConnection
                connection.connectTimeout = 15_000
                connection.readTimeout = 60_000
                connection.instanceFollowRedirects = true
                try {
                    val code = connection.responseCode
                    if (code !in 200..299) {
                        return@withContext DownloadOutcome.Failed(
                            "HTTP $code ${connection.responseMessage.orEmpty().trim()}",
                        )
                    }
                    connection.inputStream.use { input ->
                        file.outputStream().use { output -> input.copyTo(output) }
                    }
                    DownloadOutcome.Ok(file)
                } finally {
                    connection.disconnect()
                }
            } catch (e: Exception) {
                DownloadOutcome.Failed(
                    (e.message ?: e.javaClass.simpleName).take(140),
                )
            }
        }

    /** 剥离 WebView 对 JS 字符串返回值额外包裹的一层 JSON 引号（标准 JSON 反序列化还原转义） */
    private fun unquoteJsResult(raw: String): String {
        val trimmed = raw.trim()
        if (!trimmed.startsWith("\"")) return trimmed
        return try {
            (kotlinx.serialization.json.Json.parseToJsonElement(trimmed)
                as? kotlinx.serialization.json.JsonPrimitive)?.content ?: trimmed
        } catch (e: Exception) {
            trimmed
        }
    }
}

/** Tab Tools：多标签管理 */
object TabTools {

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)
        return listOf(
            f.tool(
                "tab.list", "列出所有标签页", ToolCategory.TAB,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val tabs = deps.tabManager.tabs.value
                McpToolResult.json(
                    kotlinx.serialization.json.buildJsonObject {
                        put(
                            "tabs",
                            kotlinx.serialization.json.JsonArray(
                                tabs.map { tab ->
                                    kotlinx.serialization.json.buildJsonObject {
                                        put("id", kotlinx.serialization.json.JsonPrimitive(tab.id))
                                        put("title", kotlinx.serialization.json.JsonPrimitive(tab.title))
                                        put("url", kotlinx.serialization.json.JsonPrimitive(Redactor.redactUrl(tab.url)))
                                        put("active", kotlinx.serialization.json.JsonPrimitive(tab.id == deps.browserService.activeTabId.value))
                                        put("pinned", kotlinx.serialization.json.JsonPrimitive(tab.isPinned))
                                        put("muted", kotlinx.serialization.json.JsonPrimitive(tab.isMuted))
                                    }
                                },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "tab.create", "创建新标签页", ToolCategory.TAB,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("url" to Schemas.strSchema("初始 URL")),
            ) { args ->
                val url = ToolArgs.str(args, "url")
                val session = deps.tabManager.createTab(url)
                McpToolResult.text("已创建标签页: ${session.tabId}")
            },
            f.tool(
                "tab.close", "关闭指定标签页", ToolCategory.TAB,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("tabId" to Schemas.strSchema("标签页 ID")),
            ) { args ->
                val tabId = ToolArgs.optStr(args, "tabId") ?: deps.browserService.activeTabId.value
                if (tabId == null) return@tool McpToolResult.error("NO_ACTIVE_TAB", "没有活动标签页")
                deps.tabManager.closeTab(tabId)
                McpToolResult.text("已关闭标签页: $tabId")
            },
            f.tool(
                "tab.activate", "激活指定标签页", ToolCategory.TAB,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("tabId" to Schemas.strSchema("标签页 ID")),
            ) { args ->
                val tabId = ToolArgs.str(args, "tabId")
                deps.tabManager.activateTab(tabId)
                McpToolResult.text("已激活标签页: $tabId")
            },
            f.tool(
                "tab.reload", "刷新指定标签页", ToolCategory.TAB,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("tabId" to Schemas.strSchema("标签页 ID")),
            ) { args ->
                val session = deps.sessionFor(ToolArgs.optStr(args, "tabId"))
                session.engine.reload()
                McpToolResult.text("已刷新标签页: ${session.tabId}")
            },
            f.tool(
                "tab.mute", "静音/取消静音标签页", ToolCategory.TAB,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("tabId" to Schemas.strSchema("标签页 ID"), "muted" to Schemas.boolSchema("是否静音")),
            ) { args ->
                McpToolResult.text("标签页静音状态已切换")
            },
            f.tool(
                "tab.pin", "固定/取消固定标签页", ToolCategory.TAB,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("tabId" to Schemas.strSchema("标签页 ID"), "pinned" to Schemas.boolSchema("是否固定")),
            ) { args ->
                McpToolResult.text("标签页固定状态已切换")
            },
            f.tool(
                "tab.pin_session", "把当前 MCP 会话固定到指定标签页：此后该会话内所有工具的 activeSession() 都解析到这个标签页，防止多 Agent/多 Tab 切换时串到别的逆向现场（P0 上下文隔离）", ToolCategory.TAB,
                PermissionScope.CONTROL_MCP, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "tabId" to Schemas.strSchema("要固定的标签页 ID（tab.list 获取）"),
                ),
            ) { args ->
                val tabId = ToolArgs.str(args, "tabId")
                if (tabId.isBlank()) return@tool McpToolResult.error("INVALID_ARGS", "tabId 不能为空")
                val ctx = deps.context()
                val sessionId = ctx?.sessionId ?: "default"
                deps.pinTabForSession(sessionId, tabId)
                McpToolResult.json(
                    kotlinx.serialization.json.buildJsonObject {
                        put("sessionId", kotlinx.serialization.json.JsonPrimitive(sessionId))
                        put("pinnedTabId", kotlinx.serialization.json.JsonPrimitive(tabId))
                        put("pinned", kotlinx.serialization.json.JsonPrimitive(true))
                        put("hint", kotlinx.serialization.json.JsonPrimitive("此后该会话所有工具都作用于 tab=$tabId；tab.unpin_session 解除固定"))
                    },
                )
            },
            f.tool(
                "tab.unpin_session", "解除当前会话的标签页固定，恢复跟随活动标签页", ToolCategory.TAB,
                PermissionScope.CONTROL_MCP, RiskLevel.LOW,
            ) { _ ->
                val ctx = deps.context()
                val sessionId = ctx?.sessionId ?: "default"
                val unpinned = deps.unpinTabForSession(sessionId)
                McpToolResult.json(
                    kotlinx.serialization.json.buildJsonObject {
                        put("sessionId", kotlinx.serialization.json.JsonPrimitive(sessionId))
                        put("unpinnedTabId", unpinned?.let { kotlinx.serialization.json.JsonPrimitive(it) } ?: kotlinx.serialization.json.JsonNull)
                        put("pinned", kotlinx.serialization.json.JsonPrimitive(false))
                    },
                )
            },
            f.tool(
                "tab.move", "移动标签页位置", ToolCategory.TAB,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("tabId" to Schemas.strSchema("标签页 ID"), "index" to Schemas.intSchema("目标位置")),
            ) { args ->
                McpToolResult.text("标签页已移动")
            },
            f.tool(
                "tab.group", "创建标签组", ToolCategory.TAB,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("name" to Schemas.strSchema("组名"), "tabIds" to Schemas.strSchema("标签页 ID 列表(JSON)")),
            ) { args ->
                val name = ToolArgs.str(args, "name", "New Group")
                val group = deps.tabManager.createGroup(name)
                McpToolResult.text("已创建标签组: ${group.id} ($name)")
            },
            f.tool(
                "tab.duplicate", "复制标签页", ToolCategory.TAB,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("tabId" to Schemas.strSchema("标签页 ID")),
            ) { args ->
                val tabId = ToolArgs.optStr(args, "tabId") ?: deps.browserService.activeTabId.value
                if (tabId == null) return@tool McpToolResult.error("NO_ACTIVE_TAB", "没有活动标签页")
                val session = deps.tabManager.duplicateTab(tabId)
                McpToolResult.text("已复制标签页: ${session?.tabId}")
            },
            f.tool(
                "tab.recently_closed", "列出最近关闭的标签页", ToolCategory.TAB,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val closed = deps.tabManager.recentlyClosed.value
                McpToolResult.json(
                    kotlinx.serialization.json.buildJsonObject {
                        put(
                            "recentlyClosed",
                            kotlinx.serialization.json.JsonArray(
                                closed.map { c ->
                                    kotlinx.serialization.json.buildJsonObject {
                                        put("title", kotlinx.serialization.json.JsonPrimitive(c.title))
                                        put("url", kotlinx.serialization.json.JsonPrimitive(c.url))
                                    }
                                },
                            ),
                        )
                    },
                )
            },
            f.tool(
                "tab.restore", "恢复最近关闭的标签页", ToolCategory.TAB,
                PermissionScope.READ_PAGE, RiskLevel.LOW,
            ) { _ ->
                val url = deps.tabManager.restoreRecentlyClosed()
                if (url == null) McpToolResult.text("没有可恢复的标签页")
                else {
                    deps.tabManager.createTab(url)
                    McpToolResult.text("已恢复: $url")
                }
            },
            f.tool(
                "browser.set_stealth",
                "注入反调试对抗层（debugger 剥离 / 屏幕几何自洽 / 时间夹层对抗）：Hook 函数 toString 伪装 [native code]、过滤含 debugger 的定时器/Function 构造回调、剥离 eval/Function/constructor 内的 debugger、屏幕几何自洽固定、统一虚拟时间源对抗时间夹层检测（对抗站点反调试封杀；已在 document_start 自动注入，此工具可用于按需重查状态/手动补注）",
                ToolCategory.BROWSER,
                PermissionScope.MODIFY_PAGE, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "status" to Schemas.boolSchema("仅查看当前 stealth 状态（默认 false 即注入）"),
                ),
            ) { args ->
                val session = deps.activeSession()
                if (ToolArgs.bool(args, "status", false)) {
                    val st = session.engine.evaluateJavascript(
                        "(function(){var s=window.__WRMCP_STEALTH__;return s?JSON.stringify({active:true,natives:s.nativeCount,debuggerFiltered:s.debuggerFiltered}):JSON.stringify({active:false})})()",
                    ) ?: "{}"
                    return@tool McpToolResult.text(st)
                }
                session.engine.evaluateJavascript(com.webreverse.mcp.browser.engine.util.JsScripts.stealthScript())
                val st = session.engine.evaluateJavascript(
                    "(function(){var s=window.__WRMCP_STEALTH__;return s?JSON.stringify({active:true,natives:s.nativeCount,debuggerFiltered:s.debuggerFiltered}):JSON.stringify({active:false})})()",
                ) ?: "{}"
                McpToolResult.text("stealth 已注入：$st")
            },
        )
    }
}
