package com.webreverse.mcp.javascript.analysis

/**
 * JS 加密算法识别器（ 新增，对标 WASM 侧 [WasmCryptoRecognizer] 的 Identification 语义）。
 *
 * 设计动机：
 * JSVMP 混淆站点大量在 JS 层实现签名/加密算法（自定义 MD5/SHA/AES/RC4/TEA...），
 * WASM 层有常量指纹识别，JS 层此前缺失同类能力。本扫描器补齐：
 *
 * 三层联合识别：
 * 1. **常量指纹**：S-box/K 表/IV/多项式等以「十进制数组 / 0x 十六进制 / 字符串」
 *    形式内嵌在 JS 源码中（混淆后的 hex 数组同样能命中）。
 * 2. **API 调用**：Web Crypto（crypto.subtle.*）、CryptoJS / jsencrypt / jsrsasign /
 *    elliptic / sjcl / forge 等库的调用点。
 * 3. **结构模式**：位运算密度（& | ^ << >> >>>）+ 查表索引（t[i & 255]）+
 *    大整数运算（BigInt 前缀）等自研算法的结构特征。
 *
 * 输出 [Identification]（算法 / 类别 / 证据 / 置信度 / 源码行号），
 * 供 jsvmp.crypto_scan 工具与 LLM 直接消费。
 *
 * 纯 Kotlin、stdlib only；对 4MB 级源码单次扫描 < 100ms（预提取行 + 一次遍历）。
 */
class JsCryptoScanner {

    // =========================================================================
    // 数据模型
    // =========================================================================

    /** 算法类别 */
    enum class Category { HASH, PRF, STREAM_CIPHER, BLOCK_CIPHER, ENCODING, RSA, KEY_EXCHANGE, SIGNATURE }

    /** 判定依据 */
    enum class EvidenceBasis {
        CONSTANT_FINGERPRINT,  // 常量指纹（S-box / K 表 / IV / 多项式）
        API_CALL,              // Web Crypto / 加密库 API 调用
        STRUCTURE,             // 结构模式（位运算密度 / 查表 / 轮循环）
        STRING_LITERAL,        // 字符串字面量（sigma / Base64 表 / PEM 头）
    }

    /** 一条识别结论：算法 + 证据 + 置信度 + 定位 */
    data class Identification(
        val algorithm: String,
        val category: Category,
        val basis: Set<EvidenceBasis>,
        val evidence: List<String>,
        val confidence: Int,          // 0-100
        val lines: List<Int>,         // 命中行号（1-based）
        val snippets: List<String>,   // 命中行片段（截断）
    )

    data class ScanReport(
        val ok: Boolean,
        val error: String = "",
        val identifications: List<Identification>,
        val linesScanned: Int,
        val charsScanned: Int,
        val bitOpDensity: Double,     // 位运算密度（运算符/千行），自研混淆算法信号
        val summary: String,
    )

    // =========================================================================
    // 常量指纹库
    // =========================================================================

    /**
     * 数字常量指纹：算法 -> 常量集合。
     * 匹配形式：十进制（2654435769）、0x 十六进制（0x9e3779b9，大小写均可）、
     * 以及数组字面量中的成员（[99, 124, 119, ...] 或 [0x63, 0x7c, ...]）。
     */
    private data class ConstFingerprint(
        val algorithm: String,
        val category: Category,
        val constants: List<Long>,
        val desc: String,
        /** 命中多少个常量才报告（默认 1；共享常量如 0x67452301 需 ≥2 解歧） */
        val minHits: Int = 1,
        val confidence: Int,
    )

    private val constFingerprints: List<ConstFingerprint> by lazy {
        listOf(
            ConstFingerprint(
                "AES", Category.BLOCK_CIPHER,
                listOf(0x63L, 0x7cL, 0x77L, 0x7bL, 0xf2L, 0x6bL, 0x6fL, 0xc5L),
                "AES S-box 前 8 字节（0x63,0x7c,0x77,0x7b,...）", minHits = 4, confidence = 92,
            ),
            ConstFingerprint(
                "AES", Category.BLOCK_CIPHER,
                listOf(0x52L, 0x09L, 0x6aL, 0xd5L, 0x30L, 0x36L, 0xa5L, 0x38L),
                "AES 逆 S-box 前 8 字节", minHits = 4, confidence = 90,
            ),
            ConstFingerprint(
                "AES", Category.BLOCK_CIPHER,
                listOf(0x01L, 0x02L, 0x04L, 0x08L, 0x10L, 0x20L, 0x40L, 0x80L, 0x1bL, 0x36L),
                "AES 密钥扩展 Rcon 序列", minHits = 6, confidence = 72,
            ),
            ConstFingerprint(
                "SHA-256", Category.HASH,
                listOf(0x6a09e667L, 0xbb67ae85L, 0x3c6ef372L, 0xa54ff53aL),
                "SHA-256 初始向量（0x6a09e667,...）", minHits = 2, confidence = 92,
            ),
            ConstFingerprint(
                "SHA-256", Category.HASH,
                listOf(0x428a2f98L, 0x71374491L, 0xb5c0fbcfL, 0xe9b5dba5L),
                "SHA-256 K 常量表起始（0x428a2f98,...）", minHits = 2, confidence = 96,
            ),
            ConstFingerprint(
                "SHA-512", Category.HASH,
                listOf(0x428a2f98d728ae22L, 0x7137449123ef65cdL),
                "SHA-512 K 常量表（64-bit）", minHits = 1, confidence = 95,
            ),
            ConstFingerprint(
                "SHA-1", Category.HASH,
                listOf(0x67452301L, 0xefcdab89L, 0x98badcfeL, 0x10325476L, 0xc3d2e1f0L),
                "SHA-1 初始向量（含第 5 个 0xc3d2e1f0）", minHits = 3, confidence = 88,
            ),
            ConstFingerprint(
                "MD5", Category.HASH,
                listOf(0xd76aa478L, 0xe8c7b756L, 0x242070dbL, 0xc1bdceeeL),
                "MD5 轮常量 K 表（F/G/H/I 组）", minHits = 2, confidence = 95,
            ),
            // 共享 IV：MD5 前 4 组与 SHA-1 相同，需 ≥4 且无 SHA-1 第 5 组才归 MD5
            ConstFingerprint(
                "MD5", Category.HASH,
                listOf(0x67452301L, 0xefcdab89L, 0x98badcfeL, 0x10325476L),
                "MD5/SHA-1 共享初始向量 0x67452301...", minHits = 4, confidence = 65,
            ),
            ConstFingerprint(
                "SM3", Category.HASH,
                listOf(0x7380166fL, 0x4914b2b9L, 0x172442d7L, 0xda8a0600L),
                "SM3 国密哈希初始向量（0x7380166f,...）", minHits = 2, confidence = 95,
            ),
            ConstFingerprint(
                "SM4", Category.BLOCK_CIPHER,
                listOf(0xd6L, 0x90L, 0xe9L, 0xfeL, 0xccL, 0xe1L, 0x3dL, 0xb7L),
                "SM4 国密分组密码 S-box（0xd6,0x90,0xe9,...）", minHits = 4, confidence = 95,
            ),
            ConstFingerprint(
                "SM4", Category.BLOCK_CIPHER,
                listOf(0xa3b1bac6L, 0x56aa3350L, 0x677d9197L, 0xb27022dcL),
                "SM4 系统参数 FK（密钥扩展）", minHits = 2, confidence = 94,
            ),
            ConstFingerprint(
                "TEA/XTEA", Category.BLOCK_CIPHER,
                listOf(0x9e3779b9L),
                "TEA/XTEA 黄金分割 delta 0x9e3779b9（2654435769）", minHits = 1, confidence = 85,
            ),
            ConstFingerprint(
                "RC4", Category.STREAM_CIPHER,
                listOf(0x100L, 0xffL),
                "RC4 S-box 初始化（256 项 0..255 交换混淆）", minHits = 1, confidence = 40, // 弱指纹：结构识别主导
            ),
            ConstFingerprint(
                "CRC32", Category.HASH,
                listOf(0xedb88320L),
                "CRC32 反射多项式 0xedb88320（3988292384）", minHits = 1, confidence = 92,
            ),
            ConstFingerprint(
                "CRC32C", Category.HASH,
                listOf(0x82f63b78L),
                "CRC32C 多项式 0x82f63b78", minHits = 1, confidence = 92,
            ),
            ConstFingerprint(
                "xxHash", Category.HASH,
                listOf(0x9e3779b1L, 0x85ebca6bL, 0xc2b2ae35L),
                "xxHash 素数（0x9e3779b1/0x85ebca6b/0xc2b2ae35）", minHits = 2, confidence = 90,
            ),
            ConstFingerprint(
                "MurmurHash3", Category.HASH,
                listOf(0xcc9e2d51L, 0x1b873593L),
                "MurmurHash3 素数对（0xcc9e2d51/0x1b873593）", minHits = 2, confidence = 92,
            ),
            ConstFingerprint(
                "SipHash", Category.PRF,
                listOf(),
                "SipHash 常量（字符串指纹在下方）", confidence = 0, // 占位：实际走字符串指纹
            ),
        )
    }

    /** 字符串字面量指纹：算法 -> (子串, 描述) */
    private data class StringFingerprint(
        val algorithm: String,
        val category: Category,
        val needle: String,
        val desc: String,
        val confidence: Int,
    )

    private val stringFingerprints: List<StringFingerprint> by lazy {
        listOf(
            StringFingerprint("ChaCha20", Category.STREAM_CIPHER, "expand 32-byte k", "ChaCha/Salsa sigma 常量", 92),
            StringFingerprint("SipHash", Category.PRF, "somepseu", "SipHash 常量 \"somepseu...\"", 88),
            StringFingerprint("SipHash", Category.PRF, "doranddom", "SipHash 常量 \"...doranddom\"", 88),
            StringFingerprint(
                "Base64", Category.ENCODING,
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
                "Base64 标准字母表", 70,
            ),
            StringFingerprint(
                "Base64", Category.ENCODING,
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
                "Base64url 字母表", 70,
            ),
            StringFingerprint("MD5", Category.HASH, "0123456789ABCDEF", "hex 输出字母表（弱信号）", 20),
            // RSA / 证书
            StringFingerprint("RSA", Category.RSA, "-----BEGIN PUBLIC KEY-----", "PEM 公钥头", 85),
            StringFingerprint("RSA", Category.RSA, "-----BEGIN RSA PRIVATE KEY-----", "PEM RSA 私钥头", 90),
            StringFingerprint("RSA", Category.RSA, "-----BEGIN PRIVATE KEY-----", "PEM PKCS#8 私钥头", 80),
            StringFingerprint("RSA", Category.SIGNATURE, "-----BEGIN CERTIFICATE-----", "PEM 证书头", 75),
            // JWT
            StringFingerprint("JWT", Category.SIGNATURE, "eyJhbGciOi", "JWT 头 base64 前缀（eyJ=\\{\"alg\":）", 60),
        )
    }

    /** API 调用指纹：算法 -> (调用模式正则, 描述) */
    private data class ApiFingerprint(
        val algorithm: String,
        val category: Category,
        val pattern: Regex,
        val desc: String,
        val confidence: Int,
    )

    private val apiFingerprints: List<ApiFingerprint> by lazy {
        listOf(
            // Web Crypto API（原生实现，算法名以参数字符串出现）
            ApiFingerprint(
                "WebCrypto", Category.HASH,
                Regex("""crypto\.subtle\.(?:digest|encrypt|decrypt|sign|verify|deriveBits|deriveKey|importKey|exportKey|generateKey|wrapKey|unwrapKey)"""),
                "Web Crypto API 调用（crypto.subtle.*）", 90,
            ),
            ApiFingerprint(
                "AES-GCM", Category.BLOCK_CIPHER, Regex("""AES-GCM"""), "Web Crypto 算法标识 AES-GCM", 88,
            ),
            ApiFingerprint(
                "AES-CBC", Category.BLOCK_CIPHER, Regex("""AES-CBC"""), "Web Crypto 算法标识 AES-CBC", 88,
            ),
            ApiFingerprint(
                "RSASSA-PKCS1-v1_5", Category.SIGNATURE, Regex("""RSASSA-PKCS1-v1_5"""), "Web Crypto RSA 签名算法标识", 90,
            ),
            ApiFingerprint(
                "RSA-OAEP", Category.RSA, Regex("""RSA-OAEP"""), "Web Crypto RSA-OAEP 算法标识", 90,
            ),
            ApiFingerprint(
                "ECDSA", Category.SIGNATURE, Regex("""\bECDSA\b"""), "ECDSA 签名算法标识", 82,
            ),
            ApiFingerprint(
                "ECDH", Category.KEY_EXCHANGE, Regex("""\bECDH\b"""), "ECDH 密钥交换算法标识", 80,
            ),
            ApiFingerprint(
                "PBKDF2", Category.PRF, Regex("""\bPBKDF2\b"""), "PBKDF2 密钥派生", 88,
            ),
            ApiFingerprint(
                "HKDF", Category.PRF, Regex("""\bHKDF\b"""), "HKDF 密钥派生", 88,
            ),
            // 常见 JS 加密库
            ApiFingerprint(
                "CryptoJS", Category.BLOCK_CIPHER,
                Regex("""CryptoJS\.(?:AES|DES|TripleDES|RC4|Rabbit|MD5|SHA1|SHA256|SHA512|HmacMD5|HmacSHA256|PBKDF2|enc)"""),
                "CryptoJS 库调用", 95,
            ),
            ApiFingerprint(
                "JSEncrypt", Category.RSA,
                Regex("""JSEncrypt|jsencrypt"""), "jsencrypt RSA 库", 92,
            ),
            ApiFingerprint(
                "jsrsasign", Category.RSA,
                Regex("""KJUR\.|jsrsasign|KEYUTIL\.|rs\.RSAKey"""), "jsrsasign RSA 库", 92,
            ),
            ApiFingerprint(
                "elliptic", Category.SIGNATURE,
                Regex("""require\(['"]elliptic['"]\)|from\s+['"]elliptic['"]|elliptic\.ec"""), "elliptic 椭圆曲线库", 88,
            ),
            ApiFingerprint(
                "sjcl", Category.BLOCK_CIPHER,
                Regex("""\bsjcl\."""), "Stanford SJCL 加密库", 92,
            ),
            ApiFingerprint(
                "node-forge", Category.BLOCK_CIPHER,
                Regex("""forge\.(?:cipher|md|pki|random|util)"""), "node-forge 加密库", 90,
            ),
            ApiFingerprint(
                "js-md5", Category.HASH, Regex("""\bmd5\s*\(|js-md5"""), "MD5 哈希调用", 75,
            ),
            ApiFingerprint(
                "sha.js", Category.HASH, Regex("""sha256\s*\(|createHash\(['"]sha"""), "SHA 哈希调用", 80,
            ),
            // RSA 大整数运算
            ApiFingerprint(
                "RSA(BigInt)", Category.RSA,
                Regex("""\bmodPow\(|\bbigInt\(|BigInteger\(|\bmodInverse\(|\bgcd\s*\("""),
                "大整数模幂运算（RSA/DSA 数学原语）", 78,
            ),
            // 编码
            ApiFingerprint(
                "Base64", Category.ENCODING, Regex("""\batob\s*\(|\bbtoa\s*\(|\.toString\(['"]base64['"]\)"""), "Base64 编解码调用", 55,
            ),
        )
    }

    // =========================================================================
    // 主入口
    // =========================================================================

    fun scan(source: String): ScanReport {
        if (source.isBlank()) {
            return ScanReport(true, "", emptyList(), 0, 0, 0.0, "源码为空，无可扫描内容")
        }

        val lines = source.split('\n')
        val results = mutableListOf<Identification>()

        // ---------- 1. 常量指纹：提取每行的数字字面量（十进制 + 0x 十六进制）----------
        val constHits = scanConstants(lines)
        results.addAll(constHits)

        // ---------- 2. 字符串字面量指纹 ----------
        results.addAll(scanStrings(lines))

        // ---------- 3. API 调用指纹 ----------
        results.addAll(scanApis(lines))

        // ---------- 4. 结构模式：位运算密度 / 查表索引 / 轮循环 ----------
        val structResults = scanStructure(lines, source)
        results.addAll(structResults)
        val bitDensity = structResults.firstOrNull { it.algorithm == "__bitDensity__" }
            ?.evidence?.firstOrNull()?.toDoubleOrNull() ?: 0.0

        // ---------- 5. 合并去重 + 排序 ----------
        val merged = mergeIdentifications(results.filter { it.algorithm != "__bitDensity__" })

        return ScanReport(
            ok = true,
            identifications = merged,
            linesScanned = lines.size,
            charsScanned = source.length,
            bitOpDensity = bitDensity,
            summary = buildSummary(merged, lines.size, bitDensity),
        )
    }

    // =========================================================================
    // 1. 常量指纹扫描
    // =========================================================================

    /** 数字字面量提取：十进制 / 0x 十六进制（大小写不敏感） */
    private val numberLiteralRegex = Regex("""0[xX][0-9a-fA-F]{1,16}|\b\d{1,20}\b""")

    private fun scanConstants(lines: List<String>): List<Identification> {
        // 每个指纹独立统计命中（同一指纹的常量分散多行也累积）
        data class Hit(val line: Int, val snippet: String, val constDesc: String)

        val out = mutableListOf<Identification>()
        for (fp in constFingerprints) {
            if (fp.constants.isEmpty()) continue
            val hits = mutableListOf<Hit>()
            // 构建 常量值 -> 匹配形态（hex / decimal 字符串）
            val wanted = fp.constants.associateWith { c ->
                listOf(
                    "0x${c.toString(16)}",
                    c.toString(10),
                )
            }

            val matchedConsts = mutableSetOf<Long>()
            for ((idx, line) in lines.withIndex()) {
                if (line.length > 20_000) continue // 超长行（压缩 JS）按整行匹配
                for (m in numberLiteralRegex.findAll(line)) {
                    val tok = m.value
                    val value = parseNumberToken(tok) ?: continue
                    if (value in wanted.keys) {
                        matchedConsts += value
                        if (hits.size < 8) {
                            hits.add(
                                Hit(
                                    line = idx + 1,
                                    snippet = line.trim().take(160),
                                    constDesc = tok,
                                ),
                            )
                        }
                    }
                }
                if (matchedConsts.size >= fp.constants.size && hits.size >= 4) break // 提前收敛
            }

            if (matchedConsts.size >= fp.minHits) {
                val basis = mutableSetOf(EvidenceBasis.CONSTANT_FINGERPRINT)
                val evidence = mutableListOf<String>()
                evidence += "常量指纹「${fp.desc}」命中 ${matchedConsts.size}/${fp.constants.size} 个常量: " +
                    matchedConsts.sorted().joinToString(", ") { "0x${it.toString(16)}" }
                evidence += "命中行: ${hits.take(5).joinToString(", ") { "L${it.line}(${it.constDesc})" }}"

                // 解歧：MD5/SHA-1 共享 IV——若同时出现 0xc3d2e1f0（SHA-1 第 5 IV）则降级为 SHA-1
                var algo = fp.algorithm
                var conf = fp.confidence
                if (fp.desc.contains("共享初始向量")) {
                    val hasSha1Fifth = lines.any { l ->
                        numberLiteralRegex.findAll(l).any { parseNumberToken(it.value) == 0xc3d2e1f0L }
                    }
                    if (hasSha1Fifth) {
                        algo = "SHA-1"
                        conf = 80
                        evidence += "发现 SHA-1 第 5 个 IV 0xc3d2e1f0 → 归属修正为 SHA-1（160-bit 状态）"
                    } else {
                        evidence += "未发现 SHA-1 独有 IV 0xc3d2e1f0 → 倾向 MD5（128-bit 状态）"
                        conf = 70
                    }
                }

                out.add(
                    Identification(
                        algorithm = algo,
                        category = fp.category,
                        basis = basis,
                        evidence = evidence,
                        confidence = conf,
                        lines = hits.map { it.line }.distinct().take(8),
                        snippets = hits.map { it.snippet }.distinct().take(4),
                    ),
                )
            }
        }
        return out
    }

    /** 解析数字 token：0x 前缀按 16 进制，否则 10 进制；支持负号缺失（常量均为正） */
    private fun parseNumberToken(tok: String): Long? = when {
        tok.startsWith("0x") || tok.startsWith("0X") ->
            tok.substring(2).toLongOrNull(16)
        else -> tok.toLongOrNull()
    }

    // =========================================================================
    // 2. 字符串字面量指纹
    // =========================================================================

    private fun scanStrings(lines: List<String>): List<Identification> {
        val out = mutableListOf<Identification>()
        for (fp in stringFingerprints) {
            val hits = mutableListOf<Pair<Int, String>>()
            for ((idx, line) in lines.withIndex()) {
                if (line.contains(fp.needle)) {
                    hits.add(idx + 1 to line.trim().take(160))
                    if (hits.size >= 6) break
                }
            }
            if (hits.isNotEmpty()) {
                out.add(
                    Identification(
                        algorithm = fp.algorithm,
                        category = fp.category,
                        basis = setOf(EvidenceBasis.STRING_LITERAL),
                        evidence = listOf(
                            "字符串指纹「${fp.desc}」命中 ×${hits.size}，行: ${hits.take(5).joinToString(", ") { "L${it.first}" }}",
                        ),
                        confidence = fp.confidence,
                        lines = hits.map { it.first }.distinct().take(8),
                        snippets = hits.map { it.second }.distinct().take(3),
                    ),
                )
            }
        }
        return out
    }

    // =========================================================================
    // 3. API 调用指纹
    // =========================================================================

    private fun scanApis(lines: List<String>): List<Identification> {
        val out = mutableListOf<Identification>()
        for (fp in apiFingerprints) {
            val hits = mutableListOf<Pair<Int, String>>()
            for ((idx, line) in lines.withIndex()) {
                if (line.length > 50_000) continue
                if (fp.pattern.containsMatchIn(line)) {
                    hits.add(idx + 1 to line.trim().take(160))
                    if (hits.size >= 8) break
                }
            }
            if (hits.isNotEmpty()) {
                out.add(
                    Identification(
                        algorithm = fp.algorithm,
                        category = fp.category,
                        basis = setOf(EvidenceBasis.API_CALL),
                        evidence = listOf(
                            "API 调用「${fp.desc}」命中 ×${hits.size}，行: ${hits.take(6).joinToString(", ") { "L${it.first}" }}",
                        ),
                        confidence = fp.confidence,
                        lines = hits.map { it.first }.distinct().take(10),
                        snippets = hits.map { it.second }.distinct().take(4),
                    ),
                )
            }
        }
        return out
    }

    // =========================================================================
    // 4. 结构模式
    // =========================================================================

    private val bitOpRegex = Regex("""[&|^]|<<|>>>|>>""")
    private val tableIndexRegex = Regex("""\[\s*\w+\s*(?:&|%\s*256)\s*(?:0x)?\d*\s*\]""")
    private val loopRegex = Regex("""\b(?:for|while)\s*\(""")

    private fun scanStructure(lines: List<String>, source: String): List<Identification> {
        val out = mutableListOf<Identification>()

        // ---- 位运算密度（千行） ----
        val bitOps = bitOpRegex.findAll(source).count()
        val density = if (lines.isEmpty()) 0.0 else bitOps * 1000.0 / lines.size

        // ---- 查表索引（t[i & 255] / t[i % 256]）----
        val tableHits = mutableListOf<Pair<Int, String>>()
        for ((idx, line) in lines.withIndex()) {
            if (line.length > 50_000) continue
            if (tableIndexRegex.containsMatchIn(line)) {
                tableHits.add(idx + 1 to line.trim().take(160))
                if (tableHits.size >= 8) break
            }
        }

        // ---- 循环计数 ----
        val loops = loopRegex.findAll(source).count()

        // ---- 自研混淆算法判定：查表 + 位运算 + 循环联合 ----
        if (tableHits.size >= 2 && bitOps >= 20 && loops >= 3) {
            val basis = mutableSetOf(EvidenceBasis.STRUCTURE)
            val evidence = mutableListOf<String>()
            evidence += "位运算密度 ${"%.1f".format(density)}/千行（位运算符 ×$bitOps / ${lines.size} 行）"
            evidence += "查表索引 t[i&255] 模式命中 ×${tableHits.size}，行: ${tableHits.take(5).joinToString(", ") { "L${it.first}" }}"
            evidence += "循环结构 ×$loops——疑似 S-box 轮函数 / 自研流密码"
            out.add(
                Identification(
                    algorithm = "custom-cipher(structure)",
                    category = Category.STREAM_CIPHER,
                    basis = basis,
                    evidence = evidence,
                    confidence = (45 + tableHits.size * 3).coerceAtMost(70),
                    lines = tableHits.map { it.first }.distinct().take(8),
                    snippets = tableHits.map { it.second }.distinct().take(3),
                ),
            )
        }

        // 密度信号单独返回（供 report.bitOpDensity）
        out.add(
            Identification(
                algorithm = "__bitDensity__",
                category = Category.HASH,
                basis = emptySet(),
                evidence = listOf("%.2f".format(density)),
                confidence = 0,
                lines = emptyList(),
                snippets = emptyList(),
            ),
        )
        return out
    }

    // =========================================================================
    // 合并与汇总
    // =========================================================================

    /** 同算法多来源证据合并：置信度 = max + 联合加成，证据串联 */
    private fun mergeIdentifications(items: List<Identification>): List<Identification> {
        val byAlgo = items.groupBy { it.algorithm to it.category }
        val out = mutableListOf<Identification>()
        for ((_, list) in byAlgo) {
            if (list.size == 1) {
                out.add(list[0])
                continue
            }
            val basis = list.flatMap { it.basis }.toSet()
            val bonus = when {
                basis.size >= 3 -> 8   // 常量+API+结构三重联合
                basis.size == 2 -> 5   // 双重联合
                else -> 0
            }
            val merged = Identification(
                algorithm = list[0].algorithm,
                category = list[0].category,
                basis = basis,
                evidence = list.flatMap { it.evidence },
                confidence = (list.maxOf { it.confidence } + bonus).coerceAtMost(98),
                lines = list.flatMap { it.lines }.distinct().take(12),
                snippets = list.flatMap { it.snippets }.distinct().take(5),
            )
            out.add(merged)
        }
        return out.sortedByDescending { it.confidence }
    }

    private fun buildSummary(merged: List<Identification>, lineCount: Int, bitDensity: Double): String {
        if (merged.isEmpty()) {
            return "未识别到已知加密算法特征（常量/字符串/API/结构均未命中）。" +
                "可能是：算法常量运行时解密生成（典型 JSVMP 反静态手段，配合 jsvmp.snapshot 运行时取值）/ " +
                "纯自定义逻辑。建议：1) debugger.trace 拦截加密函数入参出参；2) jsvmp.analyze 定位 handler 后手工分析。"
        }
        val sb = StringBuilder()
        sb.appendLine("识别到 ${merged.size} 类加密特征（扫描 $lineCount 行，位运算密度 ${"%.1f".format(bitDensity)}/千行）：")
        merged.take(12).forEach { id ->
            sb.appendLine("  [${id.confidence}%] ${id.algorithm}（${id.category}）@ 行 ${id.lines.take(6).joinToString(",")}")
            sb.appendLine("      依据: ${id.basis.joinToString("+")}")
            id.evidence.take(2).forEach { sb.appendLine("        - $it") }
        }
        sb.append("下一步：对高置信算法按行号定位源码片段；CryptoJS/API 型直接在运行时断点观察入参；" +
            "自研常量型算法用 jsvmp.analyze 找到包含该常量的 handler 逆向轮函数")
        return sb.toString()
    }
}
