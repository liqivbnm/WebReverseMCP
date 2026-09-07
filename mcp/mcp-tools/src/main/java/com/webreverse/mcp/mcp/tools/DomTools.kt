package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import com.webreverse.mcp.core.common.util.Redactor
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** DOM Tools：元素查询、属性、样式、事件、XPath/Selector、交互 */
object DomTools {

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)
        val json = Json { ignoreUnknownKeys = true }
        return listOf(
            f.tool(
                "dom.query", "查询单个 DOM 元素并返回其属性", ToolCategory.DOM,
                PermissionScope.READ_DOM, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("selector" to Schemas.strSchema("CSS 选择器")),
            ) { args ->
                val selector = ToolArgs.str(args, "selector")
                if (selector.isBlank()) return@tool McpToolResult.error("INVALID_ARGUMENTS", "selector 不能为空")
                val session = deps.activeSession()
                val result = deps.domInspector.querySelector(session.engine, selector)
                result.fold(
                    onSuccess = { node ->
                        McpToolResult.json(
                            buildJsonObject {
                                put("nodeName", JsonPrimitive(node.nodeName))
                                put("localName", JsonPrimitive(node.localName))
                                put("childNodeCount", JsonPrimitive(node.childNodeCount))
                                put("attributes", JsonPrimitive(node.attributes.toString()))
                            },
                        )
                    },
                    onFailure = { McpToolResult.error("ELEMENT_NOT_FOUND", it.message) },
                )
            },
            f.tool(
                "dom.query_all", "查询所有匹配的 DOM 元素", ToolCategory.DOM,
                PermissionScope.READ_DOM, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("selector" to Schemas.strSchema("CSS 选择器"), "limit" to Schemas.intSchema("返回数量上限")),
            ) { args ->
                val selector = ToolArgs.str(args, "selector")
                val limit = ToolArgs.int(args, "limit", 100)
                val session = deps.activeSession()
                val result = deps.domInspector.querySelectorAll(session.engine, selector)
                result.fold(
                    onSuccess = { nodes ->
                        McpToolResult.json(
                            buildJsonObject {
                                put(
                                    "count",
                                    JsonPrimitive(nodes.size),
                                )
                                put(
                                    "elements",
                                    JsonArray(
                                        nodes.take(limit).map { node ->
                                            buildJsonObject {
                                                put("nodeName", JsonPrimitive(node.nodeName))
                                                put("localName", JsonPrimitive(node.localName))
                                                put("attributes", JsonPrimitive(node.attributes.toString()))
                                            }
                                        },
                                    ),
                                )
                            },
                        )
                    },
                    onFailure = { McpToolResult.error("DOM_QUERY_FAILED", it.message) },
                )
            },
            f.tool(
                "dom.get_html", "获取元素 outerHTML / innerHTML", ToolCategory.DOM,
                PermissionScope.READ_DOM, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "selector" to Schemas.strSchema("CSS 选择器"),
                    "inner" to Schemas.boolSchema("true 返回 innerHTML"),
                ),
            ) { args ->
                val selector = ToolArgs.str(args, "selector", "body")
                val inner = ToolArgs.bool(args, "inner")
                val session = deps.activeSession()
                val result = if (inner) {
                    deps.domInspector.getInnerHTML(session.engine, selector)
                } else {
                    deps.domInspector.getOuterHTML(session.engine, selector)
                }
                result.fold(
                    onSuccess = { McpToolResult.text(it.take(100_000)) },
                    onFailure = { McpToolResult.error("DOM_READ_FAILED", it.message) },
                )
            },
            f.tool(
                "dom.get_text", "获取元素 textContent", ToolCategory.DOM,
                PermissionScope.READ_DOM, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("selector" to Schemas.strSchema("CSS 选择器")),
            ) { args ->
                val selector = ToolArgs.str(args, "selector", "body")
                val session = deps.activeSession()
                val result = deps.domInspector.getTextContent(session.engine, selector)
                result.fold(
                    onSuccess = { McpToolResult.text(it.take(50_000)) },
                    onFailure = { McpToolResult.error("DOM_READ_FAILED", it.message) },
                )
            },
            f.tool(
                "dom.get_attribute", "获取元素属性", ToolCategory.DOM,
                PermissionScope.READ_DOM, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "selector" to Schemas.strSchema("CSS 选择器"),
                    "name" to Schemas.strSchema("属性名"),
                ),
            ) { args ->
                val selector = ToolArgs.str(args, "selector")
                val name = ToolArgs.str(args, "name")
                val session = deps.activeSession()
                val result = deps.domInspector.getAttributes(session.engine, selector)
                result.fold(
                    onSuccess = { attrs ->
                        if (name.isBlank()) {
                            McpToolResult.json(buildJsonObject { attrs.forEach { (k, v) -> put(k, JsonPrimitive(Redactor.redactValue(k, v))) } })
                        } else {
                            McpToolResult.text(attrs[name] ?: "")
                        }
                    },
                    onFailure = { McpToolResult.error("DOM_READ_FAILED", it.message) },
                )
            },
            f.tool(
                "dom.set_attribute", "设置元素属性", ToolCategory.DOM,
                PermissionScope.MODIFY_PAGE, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "selector" to Schemas.strSchema("CSS 选择器"),
                    "name" to Schemas.strSchema("属性名"),
                    "value" to Schemas.strSchema("属性值"),
                ),
            ) { args ->
                val selector = ToolArgs.str(args, "selector")
                val name = ToolArgs.str(args, "name")
                val value = ToolArgs.str(args, "value")
                val session = deps.activeSession()
                val result = deps.domInspector.setAttribute(session.engine, selector, name, value)
                result.fold(
                    onSuccess = { McpToolResult.text("已设置 $name=$value") },
                    onFailure = { McpToolResult.error("DOM_MODIFY_FAILED", it.message) },
                )
            },
            f.tool(
                "dom.remove_attribute", "移除元素属性", ToolCategory.DOM,
                PermissionScope.MODIFY_PAGE, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "selector" to Schemas.strSchema("CSS 选择器"),
                    "name" to Schemas.strSchema("属性名"),
                ),
            ) { args ->
                val selector = ToolArgs.str(args, "selector")
                val name = ToolArgs.str(args, "name")
                val session = deps.activeSession()
                val result = deps.domInspector.removeAttribute(session.engine, selector, name)
                result.fold(
                    onSuccess = { McpToolResult.text("已移除属性 $name") },
                    onFailure = { McpToolResult.error("DOM_MODIFY_FAILED", it.message) },
                )
            },
            f.tool(
                "dom.get_style", "获取元素计算样式", ToolCategory.DOM,
                PermissionScope.READ_DOM, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("selector" to Schemas.strSchema("CSS 选择器")),
            ) { args ->
                val selector = ToolArgs.str(args, "selector")
                val session = deps.activeSession()
                val result = deps.domInspector.getComputedStyle(session.engine, selector)
                result.fold(
                    onSuccess = { style ->
                        McpToolResult.json(buildJsonObject { style.properties.forEach { (k, v) -> put(k, JsonPrimitive(v)) } })
                    },
                    onFailure = { McpToolResult.error("DOM_READ_FAILED", it.message) },
                )
            },
            f.tool(
                "dom.set_style", "设置元素 CSS 样式", ToolCategory.DOM,
                PermissionScope.MODIFY_PAGE, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "selector" to Schemas.strSchema("CSS 选择器"),
                    "property" to Schemas.strSchema("CSS 属性"),
                    "value" to Schemas.strSchema("CSS 值"),
                ),
            ) { args ->
                val selector = ToolArgs.str(args, "selector")
                val property = ToolArgs.str(args, "property")
                val value = ToolArgs.str(args, "value")
                val session = deps.activeSession()
                val result = deps.domInspector.setStyle(session.engine, selector, property, value)
                result.fold(
                    onSuccess = { McpToolResult.text("已设置 $property: $value") },
                    onFailure = { McpToolResult.error("DOM_MODIFY_FAILED", it.message) },
                )
            },
            f.tool(
                "dom.get_rect", "获取元素包围盒（BoundingClientRect）", ToolCategory.DOM,
                PermissionScope.READ_DOM, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("selector" to Schemas.strSchema("CSS 选择器")),
            ) { args ->
                val selector = ToolArgs.str(args, "selector")
                val session = deps.activeSession()
                val result = deps.domInspector.getBoundingClientRect(session.engine, selector)
                result.fold(
                    onSuccess = { rect ->
                        McpToolResult.json(buildJsonObject { rect.forEach { (k, v) -> put(k, JsonPrimitive(v)) } })
                    },
                    onFailure = { McpToolResult.error("DOM_READ_FAILED", it.message) },
                )
            },
            f.tool(
                "dom.get_xpath", "获取元素 XPath", ToolCategory.DOM,
                PermissionScope.READ_DOM, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("selector" to Schemas.strSchema("CSS 选择器")),
            ) { args ->
                val selector = ToolArgs.str(args, "selector")
                val session = deps.activeSession()
                val result = deps.domInspector.getXPath(session.engine, selector)
                result.fold(
                    onSuccess = { McpToolResult.text(it) },
                    onFailure = { McpToolResult.error("DOM_READ_FAILED", it.message) },
                )
            },
            f.tool(
                "dom.get_selector", "获取元素唯一 CSS Selector", ToolCategory.DOM,
                PermissionScope.READ_DOM, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("selector" to Schemas.strSchema("CSS 选择器")),
            ) { args ->
                val selector = ToolArgs.str(args, "selector")
                val session = deps.activeSession()
                val result = deps.domInspector.getSelector(session.engine, selector)
                result.fold(
                    onSuccess = { McpToolResult.text(it) },
                    onFailure = { McpToolResult.error("DOM_READ_FAILED", it.message) },
                )
            },
            f.tool(
                "dom.get_events", "获取元素事件监听器", ToolCategory.DOM,
                PermissionScope.READ_DOM, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("selector" to Schemas.strSchema("CSS 选择器")),
            ) { args ->
                val selector = ToolArgs.str(args, "selector")
                val session = deps.activeSession()
                val result = deps.domInspector.getEventListeners(session.engine, selector)
                result.fold(
                    onSuccess = { listeners ->
                        McpToolResult.json(
                            buildJsonObject {
                                put(
                                    "listeners",
                                    JsonArray(
                                        listeners.map { l ->
                                            buildJsonObject {
                                                put("type", JsonPrimitive(l.type))
                                                put("handler", JsonPrimitive(l.handler.take(500)))
                                                put("location", JsonPrimitive(l.location))
                                            }
                                        },
                                    ),
                                )
                            },
                        )
                    },
                    onFailure = { McpToolResult.error("DOM_READ_FAILED", it.message) },
                )
            },
            f.tool(
                "dom.get_box_model", "获取元素盒模型", ToolCategory.DOM,
                PermissionScope.READ_DOM, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("selector" to Schemas.strSchema("CSS 选择器")),
            ) { args ->
                val selector = ToolArgs.str(args, "selector")
                val session = deps.activeSession()
                val result = deps.domInspector.getBoxModel(session.engine, selector)
                result.fold(
                    onSuccess = { box ->
                        McpToolResult.json(
                            buildJsonObject {
                                put("width", JsonPrimitive(box.width))
                                put("height", JsonPrimitive(box.height))
                                put("padding", JsonPrimitive(box.padding.toString()))
                                put("border", JsonPrimitive(box.border.toString()))
                                put("margin", JsonPrimitive(box.margin.toString()))
                            },
                        )
                    },
                    onFailure = { McpToolResult.error("DOM_READ_FAILED", it.message) },
                )
            },
            f.tool(
                "dom.get_css_rules", "获取匹配元素的 CSS 规则", ToolCategory.DOM,
                PermissionScope.READ_DOM, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("selector" to Schemas.strSchema("CSS 选择器")),
            ) { args ->
                val selector = ToolArgs.str(args, "selector")
                val session = deps.activeSession()
                val result = deps.domInspector.getCssRules(session.engine, selector)
                result.fold(
                    onSuccess = { rules ->
                        McpToolResult.json(
                            buildJsonObject {
                                put(
                                    "rules",
                                    JsonArray(
                                        rules.map { r ->
                                            buildJsonObject {
                                                put("selectorText", JsonPrimitive(r.selectorText))
                                                put("style", JsonPrimitive(r.style.toString()))
                                                put("sourceUrl", JsonPrimitive(r.sourceUrl))
                                            }
                                        },
                                    ),
                                )
                            },
                        )
                    },
                    onFailure = { McpToolResult.error("DOM_READ_FAILED", it.message) },
                )
            },
            f.tool(
                "dom.get_accessibility", "获取无障碍树", ToolCategory.DOM,
                PermissionScope.READ_DOM, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("selector" to Schemas.strSchema("CSS 选择器")),
            ) { args ->
                val selector = ToolArgs.optStr(args, "selector")
                val session = deps.activeSession()
                val result = deps.domInspector.getAccessibilityTree(session.engine, selector)
                result.fold(
                    onSuccess = { nodes ->
                        McpToolResult.json(
                            buildJsonObject {
                                put("count", JsonPrimitive(nodes.size))
                                put("nodes", JsonPrimitive(nodes.take(200).toString()))
                            },
                        )
                    },
                    onFailure = { McpToolResult.error("DOM_READ_FAILED", it.message) },
                )
            },
            f.tool(
                "dom.click", "点击元素", ToolCategory.DOM,
                PermissionScope.MODIFY_PAGE, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema("selector" to Schemas.strSchema("CSS 选择器")),
            ) { args ->
                val selector = ToolArgs.str(args, "selector")
                val session = deps.activeSession()
                val result = deps.domInspector.click(session.engine, selector)
                result.fold(
                    onSuccess = { McpToolResult.text("已点击: $selector") },
                    onFailure = { McpToolResult.error("DOM_ACTION_FAILED", it.message) },
                )
            },
            f.tool(
                "dom.focus", "聚焦元素", ToolCategory.DOM,
                PermissionScope.MODIFY_PAGE, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema("selector" to Schemas.strSchema("CSS 选择器")),
            ) { args ->
                val selector = ToolArgs.str(args, "selector")
                val session = deps.activeSession()
                val result = deps.domInspector.focus(session.engine, selector)
                result.fold(
                    onSuccess = { McpToolResult.text("已聚焦: $selector") },
                    onFailure = { McpToolResult.error("DOM_ACTION_FAILED", it.message) },
                )
            },
            f.tool(
                "dom.type", "向元素输入文本", ToolCategory.DOM,
                PermissionScope.MODIFY_PAGE, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema(
                    "selector" to Schemas.strSchema("CSS 选择器"),
                    "text" to Schemas.strSchema("输入文本"),
                ),
            ) { args ->
                val selector = ToolArgs.str(args, "selector")
                val text = ToolArgs.str(args, "text")
                val session = deps.activeSession()
                val result = deps.domInspector.type(session.engine, selector, text)
                result.fold(
                    onSuccess = { McpToolResult.text("已输入文本到: $selector") },
                    onFailure = { McpToolResult.error("DOM_ACTION_FAILED", it.message) },
                )
            },
            f.tool(
                "dom.scroll", "滚动元素", ToolCategory.DOM,
                PermissionScope.MODIFY_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema(
                    "selector" to Schemas.strSchema("CSS 选择器"),
                    "x" to Schemas.intSchema("X 偏移"),
                    "y" to Schemas.intSchema("Y 偏移"),
                ),
            ) { args ->
                val selector = ToolArgs.str(args, "selector", "window")
                val x = ToolArgs.int(args, "x")
                val y = ToolArgs.int(args, "y")
                val session = deps.activeSession()
                val result = deps.domInspector.scroll(session.engine, selector, x, y)
                result.fold(
                    onSuccess = { McpToolResult.text("已滚动") },
                    onFailure = { McpToolResult.error("DOM_ACTION_FAILED", it.message) },
                )
            },
            f.tool(
                "dom.highlight", "高亮元素（调试辅助）", ToolCategory.DOM,
                PermissionScope.MODIFY_PAGE, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("selector" to Schemas.strSchema("CSS 选择器")),
            ) { args ->
                val selector = ToolArgs.str(args, "selector")
                val session = deps.activeSession()
                val result = deps.domInspector.highlight(session.engine, selector)
                result.fold(
                    onSuccess = { McpToolResult.text("已高亮: $selector") },
                    onFailure = { McpToolResult.error("DOM_ACTION_FAILED", it.message) },
                )
            },
            f.tool(
                "dom.modify", "替换元素 outerHTML", ToolCategory.DOM,
                PermissionScope.MODIFY_PAGE, RiskLevel.HIGH,
                inputSchema = Schemas.objectSchema(
                    "selector" to Schemas.strSchema("CSS 选择器"),
                    "html" to Schemas.strSchema("新的 HTML"),
                ),
            ) { args ->
                val selector = ToolArgs.str(args, "selector")
                val html = ToolArgs.str(args, "html")
                val session = deps.activeSession()
                val result = deps.domInspector.modifyElement(session.engine, selector, html)
                result.fold(
                    onSuccess = { McpToolResult.text("已修改元素") },
                    onFailure = { McpToolResult.error("DOM_MODIFY_FAILED", it.message) },
                )
            },
            f.tool(
                "dom.remove", "删除元素", ToolCategory.DOM,
                PermissionScope.MODIFY_PAGE, RiskLevel.HIGH,
                inputSchema = Schemas.objectSchema("selector" to Schemas.strSchema("CSS 选择器")),
            ) { args ->
                val selector = ToolArgs.str(args, "selector")
                val session = deps.activeSession()
                val result = deps.domInspector.removeElement(session.engine, selector)
                result.fold(
                    onSuccess = { McpToolResult.text("已删除元素: $selector") },
                    onFailure = { McpToolResult.error("DOM_MODIFY_FAILED", it.message) },
                )
            },
            f.tool(
                "dom.clone", "克隆元素", ToolCategory.DOM,
                PermissionScope.MODIFY_PAGE, RiskLevel.MEDIUM,
                inputSchema = Schemas.objectSchema("selector" to Schemas.strSchema("CSS 选择器")),
            ) { args ->
                val selector = ToolArgs.str(args, "selector")
                val session = deps.activeSession()
                val result = deps.domInspector.cloneElement(session.engine, selector)
                result.fold(
                    onSuccess = { McpToolResult.text("已克隆元素: $selector") },
                    onFailure = { McpToolResult.error("DOM_MODIFY_FAILED", it.message) },
                )
            },
            f.tool(
                "dom.document", "获取完整 DOM 文档树", ToolCategory.DOM,
                PermissionScope.READ_DOM, RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val result = deps.domInspector.getDocument(session.engine)
                result.fold(
                    onSuccess = { node ->
                        McpToolResult.json(
                            buildJsonObject {
                                put("nodeName", JsonPrimitive(node.nodeName))
                                put("childNodeCount", JsonPrimitive(node.childNodeCount))
                                put("attributes", JsonPrimitive(node.attributes.toString()))
                            },
                        )
                    },
                    onFailure = { McpToolResult.error("DOM_READ_FAILED", it.message) },
                )
            },
            f.tool(
                "dom.search", "在 DOM 中搜索文本", ToolCategory.DOM,
                PermissionScope.READ_DOM, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("text" to Schemas.strSchema("搜索文本")),
            ) { args ->
                val text = ToolArgs.str(args, "text")
                val session = deps.activeSession()
                val result = session.engine.evaluateJavascript(
                    "(function(){var q=${JsQuote(text)};var out=[];var walker=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT);var n;while(n=walker.nextNode()){if(n.nodeValue&&n.nodeValue.indexOf(q)>=0){out.push({tag:n.parentElement?n.parentElement.tagName:'',selector:(n.parentElement&&n.parentElement.id)?'#'+n.parentElement.id:n.parentElement?n.parentElement.className:'',text:n.nodeValue.substring(0,200)})}}return JSON.stringify(out.slice(0,100))})()"
                ) ?: "[]"
                McpToolResult.text(result)
            },
            f.tool(
                "dom.export", "导出 DOM 为 HTML", ToolCategory.DOM,
                PermissionScope.READ_DOM, RiskLevel.LOW,
                inputSchema = Schemas.objectSchema("selector" to Schemas.strSchema("CSS 选择器")),
            ) { args ->
                val selector = ToolArgs.str(args, "selector", "html")
                val session = deps.activeSession()
                val result = deps.domInspector.getOuterHTML(session.engine, selector)
                result.fold(
                    onSuccess = { McpToolResult.text(it) },
                    onFailure = { McpToolResult.error("DOM_READ_FAILED", it.message) },
                )
            },
        )
    }

    private fun JsQuote(s: String): String =
        "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + "\""
}
