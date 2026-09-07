package com.webreverse.mcp.devtools.storage

import com.webreverse.mcp.browser.engine.BrowserEngine
import com.webreverse.mcp.browser.engine.util.JsScripts
import com.webreverse.mcp.core.common.util.AppError
import com.webreverse.mcp.core.common.util.AppResult
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject

/** 存储检查器：Cookies / LocalStorage / SessionStorage / IndexedDB / Cache */
class StorageInspector {

    private val json = Json { ignoreUnknownKeys = true }

    suspend fun getCookies(engine: BrowserEngine): AppResult<List<Map<String, String>>> {
        val cookies = engine.getCookies()
        return AppResult.success(cookies)
    }

    suspend fun getLocalStorage(engine: BrowserEngine): AppResult<Map<String, String>> {
        return AppResult.success(engine.getLocalStorage())
    }

    suspend fun getSessionStorage(engine: BrowserEngine): AppResult<Map<String, String>> {
        return AppResult.success(engine.getSessionStorage())
    }

    suspend fun setLocalStorage(engine: BrowserEngine, key: String, value: String): AppResult<Boolean> {
        engine.setLocalStorage(key, value)
        return AppResult.success(true)
    }

    suspend fun deleteLocalStorage(engine: BrowserEngine, key: String): AppResult<Boolean> {
        engine.evaluateJavascript("localStorage.removeItem(${JsScripts.quote(key)})")
        return AppResult.success(true)
    }

    suspend fun clearLocalStorage(engine: BrowserEngine): AppResult<Boolean> {
        engine.clearLocalStorage()
        return AppResult.success(true)
    }

    suspend fun clearSessionStorage(engine: BrowserEngine): AppResult<Boolean> {
        engine.clearSessionStorage()
        return AppResult.success(true)
    }

    suspend fun getIndexedDB(engine: BrowserEngine): AppResult<List<Map<String, Any>>> {
        val script = """
            (function(){
              return new Promise(function(resolve){
                var out = [];
                if (!window.indexedDB) { resolve('[]'); return; }
                var dbs = [];
                var req = indexedDB.databases ? indexedDB.databases() : null;
                if (req && req.then) {
                  req.then(function(dbList){
                    var remaining = dbList.length;
                    if (remaining === 0) { resolve('[]'); return; }
                    dbList.forEach(function(dbInfo){
                      var openReq = indexedDB.open(dbInfo.name);
                      openReq.onsuccess = function(){
                        var db = openReq.result;
                        var dbObj = {name: db.name, version: db.version, stores: []};
                        Array.prototype.forEach.call(db.objectStoreNames, function(storeName){
                          var store = db.transaction(storeName).objectStore(storeName);
                          var countReq = store.count();
                          countReq.onsuccess = function(){
                            dbObj.stores.push({name: storeName, count: countReq.result});
                            if (dbObj.stores.length === db.objectStoreNames.length) {
                              out.push(dbObj);
                              db.close();
                              remaining--;
                              if (remaining === 0) resolve(JSON.stringify(out));
                            }
                          };
                        });
                      };
                    });
                  }).catch(function(){ resolve('[]'); });
                } else {
                  resolve('[]');
                }
              });
            })()
        """.trimIndent()
        val result = engine.evaluateJavascriptAsync(script)
            ?: return AppResult.failure(AppError.JS_EXECUTION_FAILED)
        return try {
            val element = Json.parseToJsonElement(result)
            val list = if (element is kotlinx.serialization.json.JsonArray) {
                element.map { obj ->
                    val o = obj.jsonObject
                    mapOf(
                        "name" to (o["name"]?.toString()?.trim('"') ?: ""),
                        "version" to (o["version"]?.toString() ?: ""),
                        "stores" to (o["stores"]?.toString() ?: "[]"),
                    )
                }
            } else emptyList()
            AppResult.success(list)
        } catch (e: Exception) {
            AppResult.failure(AppError("STORAGE_PARSE_ERROR", e.message.orEmpty()))
        }
    }

    suspend fun getCacheStorage(engine: BrowserEngine): AppResult<List<Map<String, String>>> {
        val script = """
            (function(){
              return new Promise(function(resolve){
                if (!window.caches) { resolve('[]'); return; }
                caches.keys().then(function(names){
                  var out = [];
                  var remaining = names.length;
                  if (remaining === 0) { resolve('[]'); return; }
                  names.forEach(function(name){
                    caches.open(name).then(function(cache){
                      cache.keys().then(function(requests){
                        out.push({name: name, count: requests.length, urls: requests.slice(0, 50).map(function(r){return r.url;})});
                        remaining--;
                        if (remaining === 0) resolve(JSON.stringify(out));
                      });
                    });
                  });
                }).catch(function(){ resolve('[]'); });
              });
            })()
        """.trimIndent()
        val result = engine.evaluateJavascriptAsync(script)
            ?: return AppResult.failure(AppError.JS_EXECUTION_FAILED)
        return try {
            val element = Json.parseToJsonElement(result)
            val list = if (element is kotlinx.serialization.json.JsonArray) {
                element.map { obj ->
                    val o = obj.jsonObject
                    mapOf(
                        "name" to (o["name"]?.toString()?.trim('"') ?: ""),
                        "count" to (o["count"]?.toString() ?: "0"),
                        "urls" to (o["urls"]?.toString() ?: "[]"),
                    )
                }
            } else emptyList()
            AppResult.success(list)
        } catch (e: Exception) {
            AppResult.failure(AppError("STORAGE_PARSE_ERROR", e.message.orEmpty()))
        }
    }

    suspend fun getServiceWorkers(engine: BrowserEngine): AppResult<List<Map<String, String>>> {
        val script = """
            (function(){
              return new Promise(function(resolve){
                if (!navigator.serviceWorker) { resolve('[]'); return; }
                navigator.serviceWorker.getRegistrations().then(function(regs){
                  var out = regs.map(function(reg){
                    return {scope: reg.scope, active: reg.active ? reg.active.scriptURL : '', installing: reg.installing ? reg.installing.scriptURL : '', waiting: reg.waiting ? reg.waiting.scriptURL : ''};
                  });
                  resolve(JSON.stringify(out));
                }).catch(function(){ resolve('[]'); });
              });
            })()
        """.trimIndent()
        val result = engine.evaluateJavascriptAsync(script)
            ?: return AppResult.failure(AppError.JS_EXECUTION_FAILED)
        return try {
            val element = Json.parseToJsonElement(result)
            val list = if (element is kotlinx.serialization.json.JsonArray) {
                element.map { obj ->
                    val o = obj.jsonObject
                    mapOf(
                        "scope" to (o["scope"]?.toString()?.trim('"') ?: ""),
                        "active" to (o["active"]?.toString()?.trim('"') ?: ""),
                        "installing" to (o["installing"]?.toString()?.trim('"') ?: ""),
                        "waiting" to (o["waiting"]?.toString()?.trim('"') ?: ""),
                    )
                }
            } else emptyList()
            AppResult.success(list)
        } catch (e: Exception) {
            AppResult.failure(AppError("STORAGE_PARSE_ERROR", e.message.orEmpty()))
        }
    }

    suspend fun searchStorage(engine: BrowserEngine, query: String): AppResult<Map<String, Any>> {
        val localStorage = engine.getLocalStorage().filter { (k, v) ->
            k.contains(query, ignoreCase = true) || v.contains(query, ignoreCase = true)
        }
        val sessionStorage = engine.getSessionStorage().filter { (k, v) ->
            k.contains(query, ignoreCase = true) || v.contains(query, ignoreCase = true)
        }
        val cookies = engine.getCookies().filter {
            it["name"]?.contains(query, ignoreCase = true) == true ||
                it["value"]?.contains(query, ignoreCase = true) == true
        }
        return AppResult.success(
            mapOf(
                "localStorage" to localStorage,
                "sessionStorage" to sessionStorage,
                "cookies" to cookies,
            )
        )
    }
}
