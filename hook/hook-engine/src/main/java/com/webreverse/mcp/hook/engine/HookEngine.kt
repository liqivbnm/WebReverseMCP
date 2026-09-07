package com.webreverse.mcp.hook.engine

import com.webreverse.mcp.browser.engine.BrowserEngine
import com.webreverse.mcp.browser.engine.bridge.HookActionType
import com.webreverse.mcp.browser.engine.bridge.HookMatchResult
import com.webreverse.mcp.browser.engine.bridge.HookMatcher
import com.webreverse.mcp.core.common.event.EventBus
import com.webreverse.mcp.core.common.event.HookEvent
import com.webreverse.mcp.core.common.model.HookAction
import com.webreverse.mcp.core.common.model.HookRule
import com.webreverse.mcp.core.common.model.HookType
import com.webreverse.mcp.core.common.util.Ids
import com.webreverse.mcp.core.database.entity.HookRuleEntity
import com.webreverse.mcp.core.database.repository.HookRuleRepository
import com.webreverse.mcp.javascript.runtime.JsRuntimeHook
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json

/**
 * Hook 引擎：管理 Hook 规则生命周期（install/enable/disable/remove/reset/export/import），
 * 将规则应用到页面，并作为网络 Hook 匹配器。
 */
class HookEngine(
    private val repository: HookRuleRepository,
    private val eventBus: EventBus,
    private val runtimeHook: JsRuntimeHook = JsRuntimeHook(),
) : HookMatcher {

    private val json = Json { ignoreUnknownKeys = true }
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val _rules = MutableStateFlow<List<HookRule>>(emptyList())
    val rules: StateFlow<List<HookRule>> = _rules.asStateFlow()

    private val _events = MutableStateFlow<List<com.webreverse.mcp.core.common.model.HookEvent>>(emptyList())
    val events: StateFlow<List<com.webreverse.mcp.core.common.model.HookEvent>> = _events.asStateFlow()

    private val installedHooks = mutableMapOf<String, String>() // ruleId -> hookId

    suspend fun loadFromDatabase() {
        val entities = repository.getAll()
        _rules.value = entities.map { it.toDomain() }
    }

    suspend fun createRule(
        name: String,
        type: HookType,
        match: com.webreverse.mcp.core.common.model.HookMatch,
        action: HookAction,
        payload: String = "",
        description: String = "",
    ): HookRule {
        val rule = HookRule(
            id = Ids.uuid(),
            name = name,
            type = type,
            match = match,
            action = action,
            payload = payload,
            description = description,
        )
        _rules.value = _rules.value + rule
        repository.upsert(rule.toEntity())
        return rule
    }

    suspend fun updateRule(rule: HookRule) {
        _rules.value = _rules.value.map { if (it.id == rule.id) rule.copy(updatedAt = System.currentTimeMillis()) else it }
        repository.upsert(rule.copy(updatedAt = System.currentTimeMillis()).toEntity())
    }

    suspend fun deleteRule(ruleId: String) {
        _rules.value = _rules.value.filterNot { it.id == ruleId }
        repository.deleteById(ruleId)
        installedHooks.remove(ruleId)?.let { hookId ->
            // 移除已安装的 hook
        }
    }

    suspend fun setEnabled(ruleId: String, enabled: Boolean) {
        _rules.value = _rules.value.map { if (it.id == ruleId) it.copy(enabled = enabled) else it }
        repository.setEnabled(ruleId, enabled)
    }

    /**
     * 统一 Hook 回调模板。
     * 在原有日志之上追加：
     * 1. 堆栈采集（new Error().stack 前几帧）——命中事件的 stackTrace 字段从此有值
     * 2. 触发本地 recordHookEvent（带 target/args/stack），供 MCP hook.events 查询
     *
     * 反检测升级：数据汇从字符串全局属性 `__WRMCP_HOOK_FIRES__` 改为
     * `Symbol.for('__wrmcp_sink')`——页面脚本枚举 window 属性名时不可见，
     * 反爬代码无法通过属性名扫描发现 hook 痕迹。
     */
    private fun hookCallback(ruleTag: String, captureStack: Boolean = true): String {
        val stackPart = if (captureStack) {
            "try { var _s = (new Error().stack || '').split('\\n').slice(2, 7).join(' <- '); } catch(e){}"
        } else ""
        return """
            try {
              $stackPart
              var _k = Symbol.for('__wrmcp_sink');
              var _arr = globalThis[_k] = globalThis[_k] || [];
              var _rec = { tag: ${'"'}$ruleTag${'"'}, info: info, stack: (_s || ''), ts: Date.now() };
              if (_arr.length < 1000) _arr.push(_rec);
              window.__MCP__ && window.__MCP__.log('hook:$ruleTag ' + JSON.stringify(info).substring(0, 500));
            } catch(e){}
        """.trimIndent()
    }

    /* * ：从 Symbol 汇 drain hook 记录（splice 清空，避免重复读取） */
    suspend fun drainHookFires(engine: BrowserEngine, limit: Int = 200): String {
        val script = """
            (function(){
              try {
                var arr = globalThis[Symbol.for('__wrmcp_sink')];
                if (!arr || !arr.length) return '[]';
                return JSON.stringify(arr.splice(0, Math.min(arr.length, $limit)));
              } catch(e){ return '[]'; }
            })()
        """.trimIndent()
        return engine.evaluateJavascript(script)?.trim()?.removeSurrounding("\"")?.replace("\\\"", "\"")
            ?: "[]"
    }

    /** 安装规则到页面 */
    suspend fun installRule(engine: BrowserEngine, rule: HookRule): Boolean {
        if (!rule.enabled) return false
        return when (rule.type) {
            HookType.FETCH -> simpleHook(engine, rule, "fetch")
            HookType.XHR -> simpleHook(engine, rule, "xhr")
            HookType.WEBSOCKET -> simpleHook(engine, rule, "websocket")
            HookType.STORAGE -> simpleHook(engine, rule, "storage")
            HookType.COOKIE -> simpleHook(engine, rule, "cookie")
            HookType.CONSOLE -> simpleHook(engine, rule, "console")
            HookType.TIMER -> simpleHook(engine, rule, "timer")
            HookType.CRYPTO -> {
                // 细粒度加密库 hook（CryptoJS/JSEncrypt/btoa/TextEncoder）为主，
                // 原生 crypto.getRandomValues 为辅——两者回调相同，key 不同互不冲突
                runtimeHook.installHook(engine, "cryptoLib", "", hookCallback("cryptoLib")) != null &&
                    runtimeHook.installHook(engine, "crypto", "", hookCallback("crypto")) != null
            }
            HookType.HISTORY -> simpleHook(engine, rule, "history")
            HookType.LOCATION -> simpleHook(engine, rule, "location")
            // 新增类型
            HookType.WORKER -> simpleHook(engine, rule, "worker")
            HookType.SUBTLE_CRYPTO -> simpleHook(engine, rule, "subtleCrypto")
            HookType.FINGERPRINT -> simpleHook(engine, rule, "fingerprint")
            HookType.NOTIFICATION -> simpleHook(engine, rule, "notification")
            // 补全的类型（此前返回 false）
            HookType.FUNCTION -> {
                val target = rule.match.target ?: return false
                runtimeHook.installHook(engine, "function", target, hookCallback("function:${target.take(40)}")) != null
            }
            HookType.METHOD -> {
                val target = rule.match.target ?: return false
                runtimeHook.installHook(engine, "method", target, hookCallback("method:${target.take(40)}")) != null
            }
            HookType.PROPERTY -> {
                val target = rule.match.target ?: return false
                runtimeHook.installHook(engine, "property", target, hookCallback("property:${target.take(40)}")) != null
            }
            HookType.EVENT -> {
                // target 形如 "click:#btn" 或 "click"（selector 可选）
                val t = rule.match.target ?: return false
                val (eventType, selector) = if (t.contains(':')) {
                    t.substringBefore(':') to t.substringAfter(':')
                } else t to "*"
                runtimeHook.installEventHook(engine, selector, eventType, hookCallback("event:$t")) != null
            }
            HookType.DOM -> {
                // target 为 CSS selector，观察子树变更
                val selector = rule.match.target ?: return false
                val script = com.webreverse.mcp.browser.engine.util.JsScripts
                    .domBreakpointScript(selector, "all", pause = false)
                engine.evaluateJavascript(script)
                true
            }
            HookType.CANVAS -> {
                // Canvas 指纹观测（toDataURL/toBlob/getImageData）
                val script = """
                    (function(){
                      var _k = Symbol.for('__wrmcp_sink');
                      var fires = globalThis[_k] = globalThis[_k] || [];
                      try {
                        var _tdu = HTMLCanvasElement.prototype.toDataURL;
                        var _tduW = function(){
                          var r = _tdu.apply(this, arguments);
                          if (fires.length < 1000) fires.push({tag:'canvas.toDataURL', info:{len: r.length, prefix: r.substring(0,32)}, ts: Date.now()});
                          window.__MCP__ && window.__MCP__.log('hook:canvas ' + r.substring(0, 40));
                          return r;
                        };
                        _tduW.__original = _tdu;
                        HTMLCanvasElement.prototype.toDataURL = _tduW;
                        var _gid = CanvasRenderingContext2D.prototype.getImageData;
                        var _gidW = function(){
                          var r = _gid.apply(this, arguments);
                          if (fires.length < 1000) fires.push({tag:'canvas.getImageData', info:{w: r.width, h: r.height}, ts: Date.now()});
                          return r;
                        };
                        _gidW.__original = _gid;
                        CanvasRenderingContext2D.prototype.getImageData = _gidW;
                        return true;
                      } catch(e){ return false; }
                    })()
                """.trimIndent()
                engine.evaluateJavascript(script) == "true"
            }
            HookType.CLIPBOARD -> {
                val script = """
                    (function(){
                      try {
                        var _k = Symbol.for('__wrmcp_sink');
                        var fires = globalThis[_k] = globalThis[_k] || [];
                        var _write = navigator.clipboard && navigator.clipboard.writeText;
                        var _read = navigator.clipboard && navigator.clipboard.readText;
                        if (_write) { var _wW = function(t){
                          if (fires.length < 1000) fires.push({tag:'clipboard.writeText', info:{len: String(t).length}, ts: Date.now()});
                          window.__MCP__ && window.__MCP__.log('hook:clipboard.write len=' + String(t).length);
                          return _write.apply(this, arguments);
                        }; _wW.__original = _write; navigator.clipboard.writeText = _wW; }
                        if (_read) { var _rW = function(){
                          if (fires.length < 1000) fires.push({tag:'clipboard.readText', info:{}, ts: Date.now()});
                          window.__MCP__ && window.__MCP__.log('hook:clipboard.read');
                          return _read.apply(this, arguments);
                        }; _rW.__original = _read; navigator.clipboard.readText = _rW; }
                        return true;
                      } catch(e){ return false; }
                    })()
                """.trimIndent()
                engine.evaluateJavascript(script) == "true"
            }
            HookType.CUSTOM -> {
                // CUSTOM：payload 即安装表达式（需返回 hook id 或 true）
                val payload = rule.payload.takeIf { it.isNotBlank() } ?: return false
                runtimeHook.installFramework(engine)
                engine.evaluateJavascript(payload) != null
            }
        }
    }

    /** 无目标参数的内置类型 Hook 安装（fetch/xhr/worker 等） */
    private suspend fun simpleHook(engine: BrowserEngine, rule: HookRule, hookType: String): Boolean =
        runtimeHook.installHook(engine, hookType, "", hookCallback(hookType)) != null

    /** 安装所有启用的规则 */
    suspend fun installAllRules(engine: BrowserEngine): Int {
        var count = 0
        _rules.value.filter { it.enabled }.forEach { rule ->
            if (installRule(engine, rule)) count++
        }
        return count
    }

    /** 网络 Hook 匹配（供 NetworkBridge 使用） */
    override fun match(tabId: String, url: String, method: String, headers: Map<String, String>): HookMatchResult? {
        val rule = _rules.value.firstOrNull { r ->
            r.enabled && matchesRule(r, url, method, headers)
        } ?: return null
        // 网络 Hook 在 WebView 拦截线程回调，这里用协程异步累计命中并持久化
        scope.launch { bumpHit(rule) }
        return when (rule.action) {
            HookAction.BLOCK -> HookMatchResult(HookActionType.BLOCK, rule.name, rule.payload)
            HookAction.REDIRECT -> HookMatchResult(HookActionType.REDIRECT, rule.name, rule.payload)
            HookAction.MOCK -> HookMatchResult(HookActionType.MOCK, rule.name, rule.payload)
            HookAction.DELAY -> HookMatchResult(HookActionType.DELAY, rule.name, rule.payload)
            else -> HookMatchResult(HookActionType.LOG, rule.name, rule.payload)
        }
    }

    private fun matchesRule(rule: HookRule, url: String, method: String, headers: Map<String, String>): Boolean {
        val match = rule.match
        match.urlPattern?.let { if (!url.contains(it)) return false }
        match.hostPattern?.let {
            val host = url.substringAfter("://").substringBefore("/")
            if (!host.contains(it)) return false
        }
        match.pathPattern?.let {
            val path = url.substringAfter("://").substringAfter("/", "")
            if (!path.contains(it)) return false
        }
        match.methodPattern?.let { if (!method.equals(it, ignoreCase = true)) return false }
        match.headerPattern?.let {
            val found = headers.any { (k, v) -> k.contains(it, ignoreCase = true) || v.contains(it, ignoreCase = true) }
            if (!found) return false
        }
        match.regexPattern?.let {
            try {
                val regex = Regex(it)
                if (!regex.containsMatchIn(url)) return false
            } catch (e: Exception) {
                return false
            }
        }
        return true
    }

    private suspend fun bumpHit(rule: HookRule) {
        _rules.value = _rules.value.map {
            if (it.id == rule.id) it.copy(hitCount = it.hitCount + 1, lastTriggeredAt = System.currentTimeMillis()) else it
        }
        repository.bumpHit(rule.id)
        val hookEvent = com.webreverse.mcp.core.common.model.HookEvent(
            id = Ids.uuid(),
            ruleId = rule.id,
            ruleName = rule.name,
            type = rule.type,
            target = rule.match.target ?: rule.match.urlPattern ?: "",
            redacted = true,
        )
        _events.value = _events.value + hookEvent
        eventBus.tryEmit(HookEvent.Triggered(rule.id, rule.name, hookEvent.target, ""))
    }

    fun recordHookEvent(event: com.webreverse.mcp.core.common.model.HookEvent) {
        _events.value = _events.value + event
        eventBus.tryEmit(HookEvent.Triggered(event.ruleId, event.ruleName, event.target, event.arguments))
    }

    suspend fun reset() {
        _rules.value = emptyList()
        _events.value = emptyList()
        installedHooks.clear()
    }

    fun export(): String = json.encodeToString(
        ListSerializer(HookRule.serializer()),
        _rules.value,
    )

    suspend fun import(jsonString: String): Int {
        val rules = json.decodeFromString(
            ListSerializer(HookRule.serializer()),
            jsonString,
        )
        rules.forEach { repository.upsert(it.toEntity()) }
        _rules.value = (_rules.value + rules).distinctBy { it.id }
        return rules.size
    }
}

/** Entity <-> Domain 转换 */
fun HookRuleEntity.toDomain(): HookRule = HookRule(
    id = id,
    name = name,
    type = runCatching { HookType.valueOf(type) }.getOrDefault(HookType.FETCH),
    match = runCatching {
        kotlinx.serialization.json.Json.decodeFromString(
            com.webreverse.mcp.core.common.model.HookMatch.serializer(),
            matchJson,
        )
    }.getOrDefault(com.webreverse.mcp.core.common.model.HookMatch()),
    action = runCatching { HookAction.valueOf(action) }.getOrDefault(HookAction.LOG),
    enabled = enabled,
    payload = payload,
    createdAt = createdAt,
    updatedAt = updatedAt,
    hitCount = hitCount,
    lastTriggeredAt = lastTriggeredAt,
    description = description,
)

fun HookRule.toEntity(): HookRuleEntity = HookRuleEntity(
    id = id,
    name = name,
    type = type.name,
    matchJson = kotlinx.serialization.json.Json.encodeToString(
        com.webreverse.mcp.core.common.model.HookMatch.serializer(),
        match,
    ),
    action = action.name,
    enabled = enabled,
    payload = payload,
    createdAt = createdAt,
    updatedAt = updatedAt,
    hitCount = hitCount,
    lastTriggeredAt = lastTriggeredAt,
    description = description,
)
