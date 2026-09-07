package com.webreverse.mcp.devtools.dom

import com.webreverse.mcp.browser.engine.BrowserEngine
import com.webreverse.mcp.browser.engine.util.JsScripts
import com.webreverse.mcp.core.common.util.AppError
import com.webreverse.mcp.core.common.util.AppResult
import com.webreverse.mcp.devtools.protocol.AccessibilityNode
import com.webreverse.mcp.devtools.protocol.BoxModel
import com.webreverse.mcp.devtools.protocol.ComputedStyle
import com.webreverse.mcp.devtools.protocol.CssRule
import com.webreverse.mcp.devtools.protocol.DomNode
import com.webreverse.mcp.devtools.protocol.EventListenerInfo
import kotlinx.serialization.json.Json

/**
 * DOM 检查器：通过注入 JS 实现 DOM 树 / 属性 / 样式 / 事件监听 / XPath / Selector 分析。
 */
class DomInspector {

    private val json = Json { ignoreUnknownKeys = true }

    suspend fun getDocument(engine: BrowserEngine): AppResult<DomNode> {
        val script = """
            (function(){
              var nextId = 1;
              function serialize(el, depth) {
                if (depth > 500) return null;
                var node = {
                  nodeId: nextId++,
                  nodeType: el.nodeType,
                  nodeName: el.nodeName,
                  localName: el.localName || '',
                  nodeValue: (el.nodeValue || '').substring(0, 200),
                  childNodeCount: el.childElementCount || 0,
                  attributes: {}
                };
                if (el.nodeType === 1) {
                  for (var i=0;i<el.attributes.length;i++){
                    var a = el.attributes[i];
                    node.attributes[a.name] = a.value.substring(0, 500);
                  }
                  node.isClickable = !!(el.onclick || el.getAttribute('onclick'));
                  node.children = [];
                  for (var c=0;c<el.children.length;c++){
                    var child = serialize(el.children[c], depth+1);
                    if (child) node.children.push(child);
                  }
                }
                return node;
              }
              return JSON.stringify(serialize(document.documentElement, 0));
            })()
        """.trimIndent()
        val result = engine.evaluateJavascript(script) ?: return AppResult.failure(AppError.JS_EXECUTION_FAILED)
        return try {
            AppResult.success(json.decodeFromString(DomNode.serializer(), unquote(result)))
        } catch (e: Exception) {
            AppResult.failure(AppError("DOM_PARSE_ERROR", "DOM 解析失败: ${e.message}"))
        }
    }

    suspend fun querySelector(engine: BrowserEngine, selector: String): AppResult<DomNode> {
        val script = """
            (function(){
              var el = document.querySelector(${JsScripts.quote(selector)});
              if (!el) return 'null';
              var node = {nodeId:1, nodeType:1, nodeName:el.nodeName, localName:el.localName||'', nodeValue:'', childNodeCount:el.childElementCount||0, attributes:{}};
              for (var i=0;i<el.attributes.length;i++){ var a=el.attributes[i]; node.attributes[a.name]=a.value.substring(0,500); }
              return JSON.stringify(node);
            })()
        """.trimIndent()
        val result = engine.evaluateJavascript(script) ?: return AppResult.failure(AppError.JS_EXECUTION_FAILED)
        if (result == "null" || result == "\"null\"") {
            return AppResult.failure(AppError("ELEMENT_NOT_FOUND", "未找到元素: $selector"))
        }
        return try {
            AppResult.success(json.decodeFromString(DomNode.serializer(), unquote(result)))
        } catch (e: Exception) {
            AppResult.failure(AppError("DOM_PARSE_ERROR", "DOM 解析失败: ${e.message}"))
        }
    }

    suspend fun querySelectorAll(engine: BrowserEngine, selector: String): AppResult<List<DomNode>> {
        val script = """
            (function(){
              var nodes = [];
              var nextId = 1;
              document.querySelectorAll(${JsScripts.quote(selector)}).forEach(function(el){
                var node = {nodeId:nextId++, nodeType:1, nodeName:el.nodeName, localName:el.localName||'', nodeValue:'', childNodeCount:el.childElementCount||0, attributes:{}};
                for (var i=0;i<el.attributes.length;i++){ var a=el.attributes[i]; node.attributes[a.name]=a.value.substring(0,300); }
                nodes.push(node);
              });
              return JSON.stringify(nodes);
            })()
        """.trimIndent()
        val result = engine.evaluateJavascript(script) ?: return AppResult.failure(AppError.JS_EXECUTION_FAILED)
        return try {
            AppResult.success(json.decodeFromString(kotlinx.serialization.builtins.ListSerializer(DomNode.serializer()), unquote(result)))
        } catch (e: Exception) {
            AppResult.failure(AppError("DOM_PARSE_ERROR", "DOM 解析失败: ${e.message}"))
        }
    }

    suspend fun getOuterHTML(engine: BrowserEngine, selector: String): AppResult<String> {
        val result = engine.evaluateJavascript(
            "(document.querySelector(${JsScripts.quote(selector)})||document.documentElement).outerHTML"
        ) ?: return AppResult.failure(AppError.JS_EXECUTION_FAILED)
        return AppResult.success(unquote(result))
    }

    suspend fun getInnerHTML(engine: BrowserEngine, selector: String): AppResult<String> {
        val result = engine.evaluateJavascript(
            "(document.querySelector(${JsScripts.quote(selector)})||document.body).innerHTML"
        ) ?: return AppResult.failure(AppError.JS_EXECUTION_FAILED)
        return AppResult.success(unquote(result))
    }

    suspend fun getTextContent(engine: BrowserEngine, selector: String): AppResult<String> {
        val result = engine.evaluateJavascript(
            "(document.querySelector(${JsScripts.quote(selector)})||document.body).textContent"
        ) ?: return AppResult.failure(AppError.JS_EXECUTION_FAILED)
        return AppResult.success(unquote(result))
    }

    suspend fun getAttributes(engine: BrowserEngine, selector: String): AppResult<Map<String, String>> {
        val result = engine.evaluateJavascript(
            "(function(){var el=document.querySelector(${JsScripts.quote(selector)});if(!el)return '{}';var o={};for(var i=0;i<el.attributes.length;i++){var a=el.attributes[i];o[a.name]=a.value}return JSON.stringify(o)})()"
        ) ?: return AppResult.failure(AppError.JS_EXECUTION_FAILED)
        return try {
            val element = Json.parseToJsonElement(unquote(result))
            AppResult.success(if (element is kotlinx.serialization.json.JsonObject) element.mapValues { it.value.toString().trim('"') } else emptyMap())
        } catch (e: Exception) {
            AppResult.failure(AppError("DOM_PARSE_ERROR", e.message.orEmpty()))
        }
    }

    suspend fun setAttribute(engine: BrowserEngine, selector: String, name: String, value: String): AppResult<Boolean> {
        engine.evaluateJavascript(
            "(function(){var el=document.querySelector(${JsScripts.quote(selector)});if(!el)return false;el.setAttribute(${JsScripts.quote(name)},${JsScripts.quote(value)});return true})()"
        )
        return AppResult.success(true)
    }

    suspend fun removeAttribute(engine: BrowserEngine, selector: String, name: String): AppResult<Boolean> {
        engine.evaluateJavascript(
            "(function(){var el=document.querySelector(${JsScripts.quote(selector)});if(!el)return false;el.removeAttribute(${JsScripts.quote(name)});return true})()"
        )
        return AppResult.success(true)
    }

    suspend fun getComputedStyle(engine: BrowserEngine, selector: String): AppResult<ComputedStyle> {
        val script = """
            (function(){
              var el = document.querySelector(${JsScripts.quote(selector)});
              if (!el) return '{}';
              var cs = getComputedStyle(el);
              var o = {};
              for (var i=0;i<cs.length;i++){ var p=cs[i]; o[p]=cs.getPropertyValue(p); }
              return JSON.stringify(o);
            })()
        """.trimIndent()
        val result = engine.evaluateJavascript(script) ?: return AppResult.failure(AppError.JS_EXECUTION_FAILED)
        return try {
            val element = Json.parseToJsonElement(unquote(result))
            val props = if (element is kotlinx.serialization.json.JsonObject) element.mapValues { it.value.toString().trim('"') } else emptyMap()
            AppResult.success(ComputedStyle(props))
        } catch (e: Exception) {
            AppResult.failure(AppError("DOM_PARSE_ERROR", e.message.orEmpty()))
        }
    }

    suspend fun getBoundingClientRect(engine: BrowserEngine, selector: String): AppResult<Map<String, Double>> {
        val result = engine.evaluateJavascript(
            "(function(){var el=document.querySelector(${JsScripts.quote(selector)});if(!el)return '{}';var r=el.getBoundingClientRect();return JSON.stringify({x:r.x,y:r.y,width:r.width,height:r.height,top:r.top,left:r.left,right:r.right,bottom:r.bottom})})()"
        ) ?: return AppResult.failure(AppError.JS_EXECUTION_FAILED)
        return try {
            val element = Json.parseToJsonElement(unquote(result))
            val map = if (element is kotlinx.serialization.json.JsonObject) element.mapValues { (it.value as? kotlinx.serialization.json.JsonPrimitive)?.content?.toDoubleOrNull() ?: 0.0 } else emptyMap()
            AppResult.success(map)
        } catch (e: Exception) {
            AppResult.failure(AppError("DOM_PARSE_ERROR", e.message.orEmpty()))
        }
    }

    suspend fun getSelector(engine: BrowserEngine, selector: String): AppResult<String> {
        val result = engine.evaluateJavascript(
            "(function(){var el=document.querySelector(${JsScripts.quote(selector)});if(!el)return '';var s=[];var n=el;while(n&&n.nodeType===1){var id=n.id?'#'+n.id:'';var cls=Array.prototype.slice.call(n.classList).map(function(c){return '.'+c}).join('');var tag=n.tagName.toLowerCase();s.unshift(tag+id+cls);if(n.id)break;n=n.parentElement;}return s.join(' > ')})()"
        ) ?: return AppResult.failure(AppError.JS_EXECUTION_FAILED)
        return AppResult.success(unquote(result))
    }

    suspend fun getXPath(engine: BrowserEngine, selector: String): AppResult<String> {
        val result = engine.evaluateJavascript(
            """
            (function(){
              var el = document.querySelector(${JsScripts.quote(selector)});
              if (!el) return '';
              function getXPath(element){
                if (element.id) return '//*[@id="' + element.id + '"]';
                if (element === document.body) return '/html/body';
                var ix = 0;
                var siblings = element.parentNode.childNodes;
                for (var i=0;i<siblings.length;i++){
                  var sibling = siblings[i];
                  if (sibling === element) return getXPath(element.parentNode) + '/' + element.tagName.toLowerCase() + '[' + (ix+1) + ']';
                  if (sibling.nodeType === 1 && sibling.tagName === element.tagName) ix++;
                }
                return '';
              }
              return getXPath(el);
            })()
            """.trimIndent()
        ) ?: return AppResult.failure(AppError.JS_EXECUTION_FAILED)
        return AppResult.success(unquote(result))
    }

    suspend fun getEventListeners(engine: BrowserEngine, selector: String): AppResult<List<EventListenerInfo>> {
        val script = """
            (function(){
              var el = document.querySelector(${JsScripts.quote(selector)});
              if (!el) return '[]';
              var out = [];
              var events = ['click','dblclick','mousedown','mouseup','mousemove','mouseover','mouseout','keydown','keyup','keypress','focus','blur','change','submit','input','touchstart','touchend','touchmove','scroll','resize','load','error','contextmenu','dragstart','dragend','drop'];
              for (var i=0;i<events.length;i++){
                var ev = events[i];
                var handler = el['on' + ev];
                if (handler) out.push({type:ev, handler:handler.toString().substring(0,500), location:'inline', useCapture:false});
              }
              var attr = el.getAttribute('onclick');
              if (attr) out.push({type:'click', handler:attr, location:'attribute', useCapture:false});
              return JSON.stringify(out);
            })()
        """.trimIndent()
        val result = engine.evaluateJavascript(script) ?: return AppResult.failure(AppError.JS_EXECUTION_FAILED)
        return try {
            AppResult.success(json.decodeFromString(kotlinx.serialization.builtins.ListSerializer(EventListenerInfo.serializer()), unquote(result)))
        } catch (e: Exception) {
            AppResult.failure(AppError("DOM_PARSE_ERROR", e.message.orEmpty()))
        }
    }

    suspend fun getBoxModel(engine: BrowserEngine, selector: String): AppResult<BoxModel> {
        val result = engine.evaluateJavascript(
            "(function(){var el=document.querySelector(${JsScripts.quote(selector)});if(!el)return '{}';var r=el.getBoundingClientRect();var cs=getComputedStyle(el);return JSON.stringify({width:r.width,height:r.height,padding:[parseInt(cs.paddingTop)||0,parseInt(cs.paddingRight)||0,parseInt(cs.paddingBottom)||0,parseInt(cs.paddingLeft)||0],border:[parseInt(cs.borderTopWidth)||0,parseInt(cs.borderRightWidth)||0,parseInt(cs.borderBottomWidth)||0,parseInt(cs.borderLeftWidth)||0],margin:[parseInt(cs.marginTop)||0,parseInt(cs.marginRight)||0,parseInt(cs.marginBottom)||0,parseInt(cs.marginLeft)||0]})})()"
        ) ?: return AppResult.failure(AppError.JS_EXECUTION_FAILED)
        return try {
            AppResult.success(json.decodeFromString(BoxModel.serializer(), unquote(result)))
        } catch (e: Exception) {
            AppResult.failure(AppError("DOM_PARSE_ERROR", e.message.orEmpty()))
        }
    }

    suspend fun getAccessibilityTree(engine: BrowserEngine, selector: String?): AppResult<List<AccessibilityNode>> {
        val script = """
            (function(){
              var root = ${if (selector != null) "document.querySelector(" + JsScripts.quote(selector) + ")" else "document.body"};
              if (!root) return '[]';
              var nextId = 1;
              function walk(el, out){
                var node = {nodeId: nextId++, role: el.getAttribute && el.getAttribute('role') || '', name: el.getAttribute && el.getAttribute('aria-label') || el.textContent || '', value: el.getAttribute && el.getAttribute('aria-valuetext') || '', properties:{}};
                if (el.getAttribute) {
                  ['aria-hidden','aria-expanded','aria-checked','aria-selected','aria-disabled','aria-live','tabindex'].forEach(function(a){
                    var v = el.getAttribute(a);
                    if (v) node.properties[a] = v;
                  });
                }
                node.children = [];
                for (var i=0;i<el.children.length;i++) walk(el.children[i], node.children);
                out.push(node);
              }
              var out = [];
              walk(root, out);
              return JSON.stringify(out);
            })()
        """.trimIndent()
        val result = engine.evaluateJavascript(script) ?: return AppResult.failure(AppError.JS_EXECUTION_FAILED)
        return try {
            AppResult.success(json.decodeFromString(kotlinx.serialization.builtins.ListSerializer(AccessibilityNode.serializer()), unquote(result)))
        } catch (e: Exception) {
            AppResult.failure(AppError("DOM_PARSE_ERROR", e.message.orEmpty()))
        }
    }

    suspend fun getCssRules(engine: BrowserEngine, selector: String): AppResult<List<CssRule>> {
        val script = """
            (function(){
              var el = document.querySelector(${JsScripts.quote(selector)});
              if (!el) return '[]';
              var out = [];
              for (var sheetIdx=0; sheetIdx<document.styleSheets.length; sheetIdx++){
                var sheet = document.styleSheets[sheetIdx];
                try {
                  var rules = sheet.cssRules || [];
                  for (var i=0;i<rules.length;i++){
                    var rule = rules[i];
                    if (rule.selectorText && el.matches(rule.selectorText)){
                      var style = {};
                      for (var j=0;j<rule.style.length;j++){ var p=rule.style[j]; style[p]=rule.style.getPropertyValue(p); }
                      out.push({selectorText:rule.selectorText, style:style, origin:'regular', sourceUrl:sheet.href||'', lineNumber:0});
                    }
                  }
                } catch(e){}
              }
              return JSON.stringify(out);
            })()
        """.trimIndent()
        val result = engine.evaluateJavascript(script) ?: return AppResult.failure(AppError.JS_EXECUTION_FAILED)
        return try {
            AppResult.success(json.decodeFromString(kotlinx.serialization.builtins.ListSerializer(CssRule.serializer()), unquote(result)))
        } catch (e: Exception) {
            AppResult.failure(AppError("DOM_PARSE_ERROR", e.message.orEmpty()))
        }
    }

    suspend fun setStyle(engine: BrowserEngine, selector: String, property: String, value: String): AppResult<Boolean> {
        engine.evaluateJavascript(
            "(function(){var el=document.querySelector(${JsScripts.quote(selector)});if(!el)return false;el.style.setProperty(${JsScripts.quote(property)},${JsScripts.quote(value)});return true})()"
        )
        return AppResult.success(true)
    }

    suspend fun click(engine: BrowserEngine, selector: String): AppResult<Boolean> {
        engine.evaluateJavascript(
            "(function(){var el=document.querySelector(${JsScripts.quote(selector)});if(!el)return false;el.click();return true})()"
        )
        return AppResult.success(true)
    }

    suspend fun focus(engine: BrowserEngine, selector: String): AppResult<Boolean> {
        engine.evaluateJavascript(
            "(function(){var el=document.querySelector(${JsScripts.quote(selector)});if(!el)return false;el.focus();return true})()"
        )
        return AppResult.success(true)
    }

    suspend fun type(engine: BrowserEngine, selector: String, text: String): AppResult<Boolean> {
        engine.evaluateJavascript(
            "(function(){var el=document.querySelector(${JsScripts.quote(selector)});if(!el)return false;el.value=${JsScripts.quote(text)};el.dispatchEvent(new Event('input',{bubbles:true}));el.dispatchEvent(new Event('change',{bubbles:true}));return true})()"
        )
        return AppResult.success(true)
    }

    suspend fun scroll(engine: BrowserEngine, selector: String, x: Int, y: Int): AppResult<Boolean> {
        engine.evaluateJavascript(
            "(function(){var el=document.querySelector(${JsScripts.quote(selector)});if(!el)return false;el.scrollTo($x,$y);return true})()"
        )
        return AppResult.success(true)
    }

    suspend fun highlight(engine: BrowserEngine, selector: String): AppResult<Boolean> {
        engine.evaluateJavascript(
            "(function(){var el=document.querySelector(${JsScripts.quote(selector)});if(!el)return false;el.style.outline='3px solid #ff5722';el.style.outlineOffset='2px';return true})()"
        )
        return AppResult.success(true)
    }

    suspend fun modifyElement(engine: BrowserEngine, selector: String, outerHTML: String): AppResult<Boolean> {
        engine.evaluateJavascript(
            "(function(){var el=document.querySelector(${JsScripts.quote(selector)});if(!el)return false;el.outerHTML=${JsScripts.quote(outerHTML)};return true})()"
        )
        return AppResult.success(true)
    }

    suspend fun removeElement(engine: BrowserEngine, selector: String): AppResult<Boolean> {
        engine.evaluateJavascript(
            "(function(){var el=document.querySelector(${JsScripts.quote(selector)});if(!el)return false;el.remove();return true})()"
        )
        return AppResult.success(true)
    }

    suspend fun cloneElement(engine: BrowserEngine, selector: String): AppResult<Boolean> {
        engine.evaluateJavascript(
            "(function(){var el=document.querySelector(${JsScripts.quote(selector)});if(!el)return false;var c=el.cloneNode(true);el.parentNode.insertBefore(c,el.nextSibling);return true})()"
        )
        return AppResult.success(true)
    }

    private fun unquote(value: String): String {
        if (value.length >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
            return value.substring(1, value.length - 1)
                .replace("\\\"", "\"")
                .replace("\\\\", "\\")
                .replace("\\n", "\n")
                .replace("\\r", "\r")
                .replace("\\t", "\t")
        }
        return value
    }
}
