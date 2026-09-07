package com.webreverse.mcp.core.security

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.webreverse.mcp.core.common.util.Ids
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map

private val Context.mcpDataStore by preferencesDataStore(name = "mcp_security")

/** Token 管理器：生成 / 轮换 / 校验 API Token */
class TokenManager(private val context: Context) {

    private val tokenKey = stringPreferencesKey("mcp_server_token")

    suspend fun getOrCreateToken(): String {
        val existing = context.mcpDataStore.data.map { it[tokenKey] }.first()
        if (!existing.isNullOrBlank()) return existing
        val token = Ids.token(48)
        context.mcpDataStore.edit { it[tokenKey] = token }
        return token
    }

    suspend fun rotateToken(): String {
        val token = Ids.token(48)
        context.mcpDataStore.edit { it[tokenKey] = token }
        return token
    }

    suspend fun validateToken(token: String): Boolean {
        if (token.isBlank()) return false
        val current = getOrCreateToken()
        return constantTimeEquals(current, token)
    }

    private fun constantTimeEquals(a: String, b: String): Boolean {
        if (a.length != b.length) return false
        var result = 0
        for (i in a.indices) {
            result = result or (a[i].code xor b[i].code)
        }
        return result == 0
    }
}
