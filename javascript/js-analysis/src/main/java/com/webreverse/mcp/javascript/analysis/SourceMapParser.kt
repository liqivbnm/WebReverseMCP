package com.webreverse.mcp.javascript.analysis

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.jsonObject

/** Source Map 解析结果 */
@Serializable
data class SourceMapInfo(
    val version: Int = 3,
    val file: String = "",
    val sourceRoot: String = "",
    val sources: List<String> = emptyList(),
    val sourcesContent: List<String?> = emptyList(),
    val names: List<String> = emptyList(),
    val mappings: String = "",
    val parsed: Boolean = false,
)

/** Source Map 解析器：支持 VLQ 解码 */
class SourceMapParser {

    private val base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    fun parse(sourceMapJson: String): SourceMapInfo {
        return try {
            val json = kotlinx.serialization.json.Json.parseToJsonElement(sourceMapJson).jsonObject
            val sources = (json["sources"] as? kotlinx.serialization.json.JsonArray)
                ?.map { it.toString().trim('"') } ?: emptyList()
            val sourcesContent = (json["sourcesContent"] as? kotlinx.serialization.json.JsonArray)
                ?.map { if (it is kotlinx.serialization.json.JsonNull) null else it.toString().trim('"') } ?: emptyList()
            val names = (json["names"] as? kotlinx.serialization.json.JsonArray)
                ?.map { it.toString().trim('"') } ?: emptyList()
            SourceMapInfo(
                version = (json["version"] as? kotlinx.serialization.json.JsonPrimitive)?.content?.toIntOrNull() ?: 3,
                file = (json["file"] as? kotlinx.serialization.json.JsonPrimitive)?.content ?: "",
                sourceRoot = (json["sourceRoot"] as? kotlinx.serialization.json.JsonPrimitive)?.content ?: "",
                sources = sources,
                sourcesContent = sourcesContent,
                names = names,
                mappings = (json["mappings"] as? kotlinx.serialization.json.JsonPrimitive)?.content ?: "",
                parsed = true,
            )
        } catch (e: Exception) {
            SourceMapInfo(parsed = false)
        }
    }

    /** 解码 mappings，返回 (generatedLine, generatedColumn) -> (sourceIndex, sourceLine, sourceColumn) */
    fun decodeMappings(sourceMap: SourceMapInfo): List<MappingEntry> {
        if (!sourceMap.parsed || sourceMap.mappings.isBlank()) return emptyList()
        val entries = mutableListOf<MappingEntry>()
        var sourceIndex = 0
        var sourceLine = 0
        var sourceColumn = 0
        var nameIndex = 0

        sourceMap.mappings.split(';').forEachIndexed { lineIndex, segmentGroup ->
            if (segmentGroup.isBlank()) return@forEachIndexed
            var generatedColumn = 0
            segmentGroup.split(',').forEach { segment ->
                if (segment.isBlank()) return@forEach
                val values = decodeVlqSegment(segment)
                if (values.isEmpty()) return@forEach
                generatedColumn += values[0]
                if (values.size >= 4) {
                    sourceIndex += values[1]
                    sourceLine += values[2]
                    sourceColumn += values[3]
                    val source = sourceMap.sources.getOrNull(sourceIndex) ?: ""
                    entries.add(
                        MappingEntry(
                            generatedLine = lineIndex,
                            generatedColumn = generatedColumn,
                            sourceIndex = sourceIndex,
                            source = source,
                            sourceLine = sourceLine,
                            sourceColumn = sourceColumn,
                            name = if (values.size >= 5) {
                                nameIndex += values[4]
                                sourceMap.names.getOrNull(nameIndex)
                            } else null,
                        )
                    )
                }
            }
        }
        return entries
    }

    /** 定位 minified 位置对应的原始源码位置 */
    fun locateOriginal(sourceMap: SourceMapInfo, generatedLine: Int, generatedColumn: Int): OriginalLocation? {
        val mappings = decodeMappings(sourceMap)
        val candidates = mappings.filter { it.generatedLine == generatedLine && it.generatedColumn <= generatedColumn }
        val best = candidates.maxByOrNull { it.generatedColumn } ?: return null
        return OriginalLocation(
            source = best.source,
            line = best.sourceLine + 1,
            column = best.sourceColumn,
            name = best.name,
        )
    }

    /**
     * 反向定位：原始源码位置 -> generated（bundle）位置。
     * 用于在 minified bundle 上设置"原始源码断点"（DevTools Sources 面板语义）。
     *
     * sourceFile 匹配策略（依序）：
     * 1. 去掉 "./" 前缀后全等
     * 2. sourcemap source 以 "/<sourceFile>" 结尾（如 webpack://app/./src/api/sign.ts）
     * 3. basename 相等（兜底，多个命中时取 generated 最靠前者）
     *
     * 同一 sourceLine 存在多个 generated 映射时，取 generated 行列最靠前者
     * （函数体内第一条可暂停语句）。
     */
    fun reverseLocate(sourceMap: SourceMapInfo, sourceFile: String, sourceLine: Int): GeneratedLocation? {
        if (!sourceMap.parsed) return null
        val mappings = decodeMappings(sourceMap)
        val target = sourceFile.trim().removePrefix("./")
        if (target.isEmpty() || sourceLine <= 0) return null

        fun matches(src: String, exact: Boolean): Boolean {
            val s = src.removePrefix("./")
            return when {
                exact -> s == target || s.substringAfter("://").removePrefix("/") == target
                else -> s.endsWith("/$target") || s.substringAfterLast('/') == target.substringAfterLast('/')
            }
        }

        val candidates = mappings.filter { it.sourceLine == sourceLine - 1 && matches(it.source, exact = true) }
            .ifEmpty { mappings.filter { it.sourceLine == sourceLine - 1 && matches(it.source, exact = false) } }
        val best = candidates.minByOrNull { it.generatedLine * 1_000_000L + it.generatedColumn } ?: return null
        return GeneratedLocation(
            line = best.generatedLine + 1,
            column = best.generatedColumn,
            source = best.source,
        )
    }

    /** 列出 sourcemap 中包含的原始源文件（去重） */
    fun sourcesOf(sourceMap: SourceMapInfo): List<String> =
        if (sourceMap.parsed) sourceMap.sources.distinct() else emptyList()

    private fun decodeVlqSegment(segment: String): List<Int> {
        val values = mutableListOf<Int>()
        var shift = 0
        var value = 0
        for (char in segment) {
            val digit = base64Chars.indexOf(char)
            if (digit < 0) return emptyList()
            val continuation = digit and 32 != 0
            value += (digit and 31) shl shift
            if (continuation) {
                shift += 5
            } else {
                val negate = value and 1 != 0
                value = value ushr 1
                values.add(if (negate) -value else value)
                shift = 0
                value = 0
            }
        }
        return values
    }
}

@Serializable
data class MappingEntry(
    val generatedLine: Int,
    val generatedColumn: Int,
    val sourceIndex: Int,
    val source: String,
    val sourceLine: Int,
    val sourceColumn: Int,
    val name: String? = null,
)

@Serializable
data class OriginalLocation(
    val source: String,
    val line: Int,
    val column: Int,
    val name: String? = null,
)

/** reverseLocate 结果：bundle 中的对应位置（1-based line） */
@Serializable
data class GeneratedLocation(
    val line: Int,
    val column: Int,
    val source: String = "",
)
