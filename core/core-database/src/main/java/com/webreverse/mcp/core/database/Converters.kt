package com.webreverse.mcp.core.database

import androidx.room.TypeConverter
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put

/** Room 类型转换器 */
class Converters {

    @TypeConverter
    fun fromStringMap(value: String?): Map<String, String> =
        if (value.isNullOrBlank()) emptyMap()
        else try {
            Json.parseToJsonElement(value).jsonObject.mapValues { it.value.toString().trim('"') }
        } catch (e: Exception) {
            emptyMap()
        }

    @TypeConverter
    fun toStringMap(value: Map<String, String>?): String =
        value?.let {
            Json.encodeToString(
                JsonObject.serializer(),
                buildJsonObject { value.forEach { (k, v) -> put(k, v) } },
            )
        } ?: "{}"

    @TypeConverter
    fun fromStringList(value: String?): List<String> =
        if (value.isNullOrBlank()) emptyList()
        else try {
            Json.parseToJsonElement(value).jsonArray.map { it.toString().trim('"') }
        } catch (e: Exception) {
            emptyList()
        }

    @TypeConverter
    fun toStringList(value: List<String>?): String =
        value?.let {
            Json.encodeToString(
                JsonArray.serializer(),
                JsonArray(it.map { s -> JsonPrimitive(s) }),
            )
        } ?: "[]"
}
