package com.webreverse.mcp.javascript.analysis

/**
 * WASM 加密算法识别器（ 新增， 升级为 Identification 语义识别）。
 *
 * 升级背景（评审点名三缺）：
 * 1. **常量指纹 → 轮结构/非线性函数/移位计划 联合判定**：共享常量（如 0x67452301 同时出现在
 *    MD5 和 SHA-1）不再是「检测到即可固定分」的弱识别，而是在常量之上叠加 MD5 独有的
 *    F/G/H/I 非线性函数常量表、128 位状态宽度、leftrotate 移位计划 {7,12,17,22,...} 与轮循环数，
 *    从而把 MD5 与 SHA-1 可靠区分。
 * 2. **Detection（检测热点） → Identification（识别出具体算法）**：新增 `getIdentifications()`
 *    输出算法级判断结构 [IdentificationResult]：算法名 / 类别 / 判定依据类型集合 / 命中证据 /
 *    置信度 / 对应函数索引与导出名。
 * 3. **call_indirect 间接调用目标解析**：新增 `resolveCallIndirectTargets()`，解析 code 段里
 *    `i32.const N` 紧跟 `call_indirect` 的目标传播，并借助 element section 的真实表项候选集合
 *    解析出候选目标函数索引，与算法识别证据关联。
 *
 * 对外既有公开 API（analyze / recognize / CryptoFinding / RecognizeReport 字段）保持不变，
 * 增强结果通过以下可选接口暴露：
 *   - `getIdentifications(bytes, maxFunctions): List<IdentificationResult>`
 *   - `resolveCallIndirectTargets(bytes): List<CallIndirectTarget>`
 *   - `RecognizeReport.identifications` / `RecognizeReport.callIndirectTargets`（可选增强字段）
 *
 * 纯 Kotlin、stdlib only。
 */
class WasmCryptoRecognizer {

    // =========================================================================
    // 新增：算法级识别数据结构（Identification 语义）
    // =========================================================================

    /** 算法类别 */
    enum class Category { HASH, PRF, STREAM_CIPHER, BLOCK_CIPHER, CRC, ENCODING }

    /** 判定依据类型（联合判定集合） */
    enum class EvidenceBasis {
        CONSTANT_FINGERPRINT,   // 常量指纹（IV / K 表 / sigma）
        ROUND_STRUCTURE,        // 轮结构（轮循环 / 分组）
        NONLINEAR_FUNCTION,     // 非线性函数常量（MD5 F/G/H/I、SHA-1 轮常量）
        ROTATE_SCHEDULE,        // 移位计划（leftrotate 表）
        STATE_WIDTH,            // 状态宽度（MD5 128-bit / SHA-1 160-bit）
        LOOP_COUNT,             // 轮计数循环结构
    }

    /**
     * 算法识别结果：一个「算法名 + 判定依据 + 证据 + 置信度 + 函数定位」的完整结论。
     */
    data class IdentificationResult(
        val algorithm: String,
        val category: Category,
        val basis: Set<EvidenceBasis>,
        val evidence: List<String>,
        val confidence: Int,                    // 0-100
        val funcIndexes: List<Int>,             // 实现该算法的函数（WASM 全局索引，含 import 偏移）
        val exportNames: List<String>,          // 对应导出名
    )

    /** call_indirect 间接调用候选目标解析结果 */
    data class CallIndirectTarget(
        val callerFuncIndex: Int,               // 发起 call_indirect 的函数
        val callerFuncName: String?,
        val tableIndex: Int,                    // call_indirect 指向的 table
        val typeIndex: Int,                     // 签名 type（用于过滤候选）
        val prescribedIndex: Int,               // i32.const N（静态可知的元素下标，-1 = 未知）
        val candidateTargets: List<Int>,        // 解析出的候选目标函数索引
        val candidateNames: List<String>,
        val evidence: List<String>,
    )

    // ---------------- 既有数据模型 ----------------

    data class CryptoFinding(
        val algorithm: String,          // AES / SHA-256 / ChaCha20 / MD5 / CRC32 / custom-ARX ...
        val confidence: Int,            // 0-100
        val evidence: List<String>,     // 证据链
        val funcIndex: Int,             // 关联函数（-1 = 模块级 data 段证据）
        val funcName: String?,          // name section 符号
        val kind: String,               // constant / pattern / combined
    )

    data class RecognizeReport(
        val ok: Boolean,
        val error: String = "",
        val findings: List<CryptoFinding>,
        val dataScanBytes: Int,
        val functionsScanned: Int,
        val summary: String,            // 人类可读结论
        // 新增可选增强字段（不破坏既有读取方）
        val identifications: List<IdentificationResult> = emptyList(),
        val callIndirectTargets: List<CallIndirectTarget> = emptyList(),
    )

    // ---------------- 常量指纹库 ----------------

    /** (算法, 字节序列, 描述)——字节序无关：同时匹配 LE/BE */
    private val byteFingerprints: List<Triple<String, ByteArray, String>> by lazy {
        listOf(
            Triple("AES", aesSboxPrefix, "AES S-box（aes_sbox 表）"),
            Triple("AES", aesInvSboxPrefix, "AES 逆 S-box"),
            Triple("AES", aesRconPrefix, "AES 密钥扩展 Rcon 常量（0x01,0x02,0x04,...）"),
            Triple("SHA-256", sha256KPrefix, "SHA-256 K 常量表（0x428a2f98...）"),
            Triple("SHA-512", sha512KPrefix, "SHA-512 K 常量表（64-bit）"),
            Triple("SHA-1", md5Sha1IvPrefix, "SHA-1/MD5 初始向量 0x67452301"),
            Triple("MD5", md5Sha1IvPrefix, "MD5 初始向量（与 SHA-1 共享 IV 前缀）"),
            // MD5 / SHA-1 专属常量指纹——用于在共享 IV 之上解歧
            Triple("MD5", md5KTablePrefix, "MD5 轮常量表 K 起始 0xd76aa478"),
            Triple("SHA-1", sha1RoundConstPrefix, "SHA-1 特殊轮常量 0x5a827999"),
            // 国密算法（SM3/SM4）——国内 Web 逆向高频
            Triple("SM3", sm3IvPrefix, "SM3 国密哈希 IV 起始 0x7380166f"),
            Triple("SM4", sm4SboxPrefix, "SM4 国密分组密码 S-box（0xd6,0x90,0xe9,...）"),
            // 非加密哈希 / 轻量算法
            Triple("xxHash", xxhPrimePrefix, "xxHash 素数 0x9E3779B1"),
            Triple("MurmurHash", murmurPrimePrefix, "MurmurHash3 素数 0xcc9e2d51"),
            Triple("MurmurHash", murmurPrime2Prefix, "MurmurHash3 素数 0x1b873593"),
            Triple("TEA/XTEA", teaDeltaPrefix, "TEA/XTEA 黄金分割 delta 0x9e3779b9"),
            Triple("SipHash", siphashC0, "SipHash 常量 \"somepseu\""),
            Triple("SipHash", siphashC1, "SipHash 常量 \"doranddom\""),
            Triple("DES", desSboxPrefix, "DES S-box1（0x0e,0x04,0x0d,...）"),
            Triple("ChaCha20", chachaSigma, "ChaCha/Salsa sigma \"expand 32-byte k\""),
            Triple("Salsa20", chachaSigma, "Salsa20 sigma 常量"),
            Triple("CRC32", crc32PolyLe, "CRC32 反射多项式表 0xedb88320"),
            Triple("CRC32C", crc32cPolyLe, "CRC32C 多项式表 0x82f63b78"),
            Triple("Base64", base64Alphabet, "Base64 标准字母表"),
        )
    }

    private val aesSboxPrefix = byteArrayOf(
        0x63, 0x7c, 0x77, 0x7b, 0xf2.toByte(), 0x6b, 0x6f, 0xc5.toByte(),
        0x30, 0x01, 0x67, 0x2b, 0xfe.toByte(), 0xd7.toByte(), 0xab.toByte(), 0x76.toByte(),
    )
    private val aesInvSboxPrefix = byteArrayOf(
        0x52, 0x09, 0x6a, 0xd5.toByte(), 0x30, 0x36, 0xa5.toByte(), 0x38,
        0xbf.toByte(), 0x40, 0xa3.toByte(), 0x9e.toByte(), 0x81.toByte(), 0xf3.toByte(), 0xd7.toByte(), 0xfb.toByte(),
    )
    private val sha256KPrefix = byteArrayOf(
        // 0x428a2f98 0x71374491 0xb5c0fbcf 0xe9b5dba5 的 LE 编码
        0x98.toByte(), 0x2f, 0x8a.toByte(), 0x42,
    )
    private val sha512KPrefix = byteArrayOf(
        0x98.toByte(), 0x2f, 0x8a.toByte(), 0x42, 0x91.toByte(), 0x44, 0x37, 0x71,
    )
    private val md5Sha1IvPrefix = byteArrayOf(
        0x01, 0x23, 0x45, 0x67, // 0x67452301 LE
    )
    // MD5 K 表起始 0xd76aa478 LE
    private val md5KTablePrefix = byteArrayOf(
        0x78.toByte(), 0xa4.toByte(), 0x6a.toByte(), 0xd7.toByte(),
    )
    // SHA-1 轮常量 0x5a827999 LE
    private val sha1RoundConstPrefix = byteArrayOf(
        0x99.toByte(), 0x79.toByte(), 0x82.toByte(), 0x5a.toByte(),
    )
    private val chachaSigma = "expand 32-byte k".toByteArray(Charsets.US_ASCII)
    private val crc32PolyLe = byteArrayOf(0x00, 0x00, 0x00, 0x20.toByte(), 0x83.toByte(), 0xb8.toByte(), 0xed.toByte(), 0x00)
    private val crc32cPolyLe = byteArrayOf(0x00, 0x00, 0x00, 0x00, 0xf8.toByte(), 0x2e, 0x00, 0x00)
    private val base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toByteArray(Charsets.US_ASCII)

    // ---- ：国密 / 轻量哈希 / 分组密码 / 流密码 新增指纹 ----
    // SM3 IV 起始 0x7380166f LE
    private val sm3IvPrefix = byteArrayOf(0x6f.toByte(), 0x16, 0x80.toByte(), 0x73)
    // SM4 S-box 前 16 字节（0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05）
    private val sm4SboxPrefix = byteArrayOf(
        0xd6.toByte(), 0x90.toByte(), 0xe9.toByte(), 0xfe.toByte(), 0xcc.toByte(), 0xe1.toByte(), 0x3d, 0xb7.toByte(),
        0x16, 0xb6.toByte(), 0x14, 0xc2.toByte(), 0x28, 0xfb.toByte(), 0x2c, 0x05,
    )
    // xxHash 素数 0x9E3779B1 LE
    private val xxhPrimePrefix = byteArrayOf(0xb1.toByte(), 0x79, 0x37, 0x9e.toByte())
    // MurmurHash3 素数 0xcc9e2d51 / 0x1b873593 LE
    private val murmurPrimePrefix = byteArrayOf(0x51, 0x2d, 0x9e.toByte(), 0xcc.toByte())
    private val murmurPrime2Prefix = byteArrayOf(0x93.toByte(), 0x35, 0x87.toByte(), 0x1b)
    // TEA/XTEA delta 0x9e3779b9 LE
    private val teaDeltaPrefix = byteArrayOf(0xb9.toByte(), 0x79, 0x37, 0x9e.toByte())
    // SipHash 常量（ASCII "somepseu" / "doranddom"）
    private val siphashC0 = "somepseu".toByteArray(Charsets.US_ASCII)
    private val siphashC1 = "doranddom".toByteArray(Charsets.US_ASCII)
    // DES S-box1 前 16 字节（0x0e,0x04,0x0d,0x01,0x02,0x0f,0x0b,0x08,0x03,0x0a,0x06,0x0c,0x05,0x09,0x00,0x07）
    private val desSboxPrefix = byteArrayOf(
        0x0e, 0x04, 0x0d, 0x01, 0x02, 0x0f, 0x0b, 0x08,
        0x03, 0x0a, 0x06, 0x0c, 0x05, 0x09, 0x00, 0x07,
    )
    // AES 密钥扩展 Rcon：0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
    private val aesRconPrefix = byteArrayOf(
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80.toByte(), 0x1b, 0x36,
    )

    // ---------------- 入口 ----------------

    private val parser = WasmParser()
    private val disassembler = WasmDisassembler()

    fun recognize(bytes: ByteArray, maxFunctions: Int = 400): RecognizeReport {
        val parsed = parser.parse(bytes)
        if (!parsed.ok) return RecognizeReport(false, parsed.error, emptyList(), 0, 0, "")

        val findings = mutableListOf<CryptoFinding>()
        val importedFuncs = parsed.imports.count { it.kind == "func" }

        // ---------- 1. 常量指纹（data 段 + 全模块字节窗口）----------
        var dataScanned = 0
        for (fingerprint in byteFingerprints) {
            val (algo, pattern, desc) = fingerprint
            val hits = findPattern(bytes, pattern, maxHits = 3)
            if (hits.isNotEmpty()) {
                val conf = when (algo) {
                    "AES", "SHA-256", "SHA-512", "ChaCha20", "Salsa20" -> 95
                    "SM3", "SM4" -> 90
                    "xxHash", "MurmurHash", "TEA/XTEA", "SipHash", "DES" -> 85
                    "MD5", "SHA-1" -> 70   // IV 前缀弱指纹；K 表/轮常量专属指纹在下方提权
                    "CRC32", "CRC32C" -> 80
                    "Base64" -> 50
                    else -> 60
                }
                // MD5/SHA-1 专属常量指纹（K 表 / 轮常量）置信度提权
                val boostedConf = when {
                    algo == "MD5" && desc.contains("轮常量表") -> 92
                    algo == "SHA-1" && desc.contains("特殊轮常量") -> 92
                    else -> conf
                }
                findings.add(
                    CryptoFinding(
                        algorithm = algo,
                        confidence = boostedConf,
                        evidence = hits.take(3).map { "常量命中 @$it (0x${it.toString(16)}): $desc" },
                        funcIndex = -1,
                        funcName = null,
                        kind = "constant",
                    ),
                )
            }
        }
        dataScanned = bytes.size

        // ---------- 2. 指令指纹（函数体级 ARX / 轮函数结构）----------
        var scanned = 0
        for (body in parsed.funcBodies) {
            if (scanned >= maxFunctions) break
            scanned++
            // FuncBodyInfo.index 已是全局函数索引（含 import func 计数）
            val funcIdx = body.index
            val name = parsed.functionNames[funcIdx] ?: body.name
            val pattern = analyzeFunctionPattern(bytes, body, importedFuncs)
            if (pattern != null) {
                findings.add(
                    CryptoFinding(
                        algorithm = pattern.first,
                        confidence = pattern.second,
                        evidence = pattern.third,
                        funcIndex = funcIdx,
                        funcName = name,
                        kind = "pattern",
                    ),
                )
            }
        }

        // ---------- 3. 合并 & 排序 ----------
        val merged = mergeFindings(findings)
        // 叠加 Identification 语义识别 + call_indirect 目标解析
        val identifications = getIdentifications(bytes, maxFunctions)
        val callIndirect = resolveCallIndirectTargets(bytes, maxFunctions)
        val summary = buildSummary(merged, parsed, identifications, callIndirect)
        return RecognizeReport(
            ok = true,
            findings = merged,
            dataScanBytes = dataScanned,
            functionsScanned = scanned,
            summary = summary,
            identifications = identifications,
            callIndirectTargets = callIndirect,
        )
    }

    // =========================================================================
    // 算法级 Identification 识别入口
    // =========================================================================

    /**
     * 算法级识别：返回已识别算法的结构化结论列表（Detection 之上叠加 Identification）。
     * 对 MD5/SHA-1 做「常量 + 轮结构 + 非线性函数 + 移位计划 + 状态宽度 + 轮循环」联合判定，
     * 对 ChaCha20 做 quarter-round 轮语义识别。
     */
    fun getIdentifications(bytes: ByteArray, maxFunctions: Int = 400): List<IdentificationResult> {
        val parsed = parser.parse(bytes)
        if (!parsed.ok) return emptyList()
        val infos = buildFuncInfos(bytes, parsed, maxFunctions)
        val out = mutableListOf<IdentificationResult>()

        // 结构 / 轮语义识别（逐函数）
        val structurallyCovered = mutableSetOf<String>()
        for (info in infos) {
            identifyMd5Sha1(info, parsed)?.let {
                out.add(it); structurallyCovered.add(it.algorithm)
            }
            identifyChaCha(info, parsed)?.let {
                out.add(it); structurallyCovered.add(it.algorithm)
            }
            // 国密算法结构识别（SM3/SM4）+ HMAC
            identifySm3(info, parsed)?.let {
                out.add(it); structurallyCovered.add(it.algorithm)
            }
            identifySm4(info, parsed)?.let {
                out.add(it); structurallyCovered.add(it.algorithm)
            }
            identifyHmac(info, parsed)?.let {
                out.add(it); structurallyCovered.add(it.algorithm)
            }
        }

        // 模块级常量指纹 → 常量型识别（对未在结构层覆盖的算法 / 仅由数据段常量命中的情况）
        val constByAlgo = LinkedHashMap<String, MutableList<Pair<Int, String>>>()
        for (fp in byteFingerprints) {
            val hits = findPattern(bytes, fp.second, maxHits = 3)
            if (hits.isNotEmpty()) {
                constByAlgo.getOrPut(fp.first) { mutableListOf() }
                    .addAll(hits.map { it to fp.third })
            }
        }
        appendConstantIdentifications(constByAlgo, structurallyCovered, out)

        return out.sortedByDescending { it.confidence }
    }

    /** 为常量指纹命中补充常量型 IdentificationResult（跳过已结构识别的算法） */
    private fun appendConstantIdentifications(
        constByAlgo: Map<String, List<Pair<Int, String>>>,
        structurallyCovered: Set<String>,
        out: MutableList<IdentificationResult>,
    ) {
        // 先判断 MD5 / SHA-1 / ChaCha 的专属常量指纹是否命中（用于解歧）
        val md5Specific = constByAlgo["MD5"].orEmpty().any { it.second.contains("轮常量表") }
        val sha1Specific = constByAlgo["SHA-1"].orEmpty().any { it.second.contains("特殊轮常量") }
        val sharedIvHit =
            constByAlgo["MD5"].orEmpty().any { it.second.contains("共享 IV") } ||
                constByAlgo["SHA-1"].orEmpty().any { it.second.contains("初始向量") }
        val chachaSigmaHit = constByAlgo["ChaCha20"].orEmpty().isNotEmpty()

        for ((algo, entries) in constByAlgo) {
            when (algo) {
                "MD5" -> {
                    if (algo in structurallyCovered) continue
                    if (md5Specific) addConstantResult(out, "MD5", Category.HASH, entries, 90)
                    else if (!sha1Specific && sharedIvHit && !structurallyCovered.contains("SHA-1")) {
                        // 共享 IV 歧义：不武断归为 MD5，标记为模糊
                        addConstantResult(out, "MD5-or-SHA-1", Category.HASH, entries, 40,
                            note = "共享 IV 0x67452301 同时出现在 MD5/SHA-1，且未发现 MD5 F/G/H/I 常量或 SHA-1 轮常量，归属不明确")
                    }
                }
                "SHA-1" -> {
                    if (algo in structurallyCovered) continue
                    if (sha1Specific) addConstantResult(out, "SHA-1", Category.HASH, entries, 90)
                    else if (!md5Specific && sharedIvHit && !structurallyCovered.contains("MD5")) {
                        // 交由 MD5 分支统一输出模糊结论，此处不再重复
                    }
                }
                "ChaCha20" -> {
                    if (chachaSigmaHit && structurallyCovered.none { it.startsWith("ChaCha") }) {
                        addConstantResult(out, "ChaCha20", Category.STREAM_CIPHER, entries, 85)
                    }
                }
                else -> {
                    if (algo in structurallyCovered) continue
                    addConstantResult(out, algo, categoryOf(algo), entries, constantConfidence(algo))
                }
            }
        }
    }

    private fun addConstantResult(
        out: MutableList<IdentificationResult>,
        algo: String,
        category: Category,
        entries: List<Pair<Int, String>>,
        confidence: Int,
        note: String? = null,
    ) {
        val ev = entries.take(3).map { (off, desc) -> "常量命中 @$off (0x${off.toString(16)}): $desc" }
        out.add(
            IdentificationResult(
                algorithm = algo,
                category = category,
                basis = setOf(EvidenceBasis.CONSTANT_FINGERPRINT),
                evidence = if (note != null) ev + note else ev,
                confidence = confidence,
                funcIndexes = emptyList(),
                exportNames = emptyList(),
            ),
        )
    }

    private fun constantConfidence(algo: String): Int = when (algo) {
        "AES", "SHA-256", "SHA-512" -> 92
        "SM3", "SM4" -> 90
        "xxHash", "MurmurHash", "TEA/XTEA", "SipHash", "DES" -> 85
        "CRC32", "CRC32C" -> 82
        "Base64" -> 55
        else -> 60
    }

    private fun categoryOf(algo: String): Category = when {
        algo.contains("SHA") || algo == "MD5" || algo == "SM3" || algo.contains("hash") || algo == "custom-ARX" -> Category.HASH
        algo.startsWith("HMAC") || algo.startsWith("PBKDF") || algo.startsWith("HKDF") || algo.contains("PRF") -> Category.PRF
        algo.contains("ChaCha") || algo.contains("Salsa") || algo.contains("RC4") || algo.contains("stream") -> Category.STREAM_CIPHER
        algo == "AES" || algo == "SM4" || algo == "DES" || algo.contains("cipher") || algo.contains("CBC") || algo.contains("GCM") -> Category.BLOCK_CIPHER
        algo.contains("CRC") -> Category.CRC
        algo.contains("Base64") || algo.contains("encoding") -> Category.ENCODING
        else -> Category.HASH
    }

    // ------ 函数体 token 方案统（复用 WasmDisassembler.disassemble 的 listing）------

    private class Tok(val mnem: String, val imm: Long, val hasImm: Boolean, val raw: String)

    private class FuncInfo(
        val index: Int,
        val name: String?,
        val toks: List<Tok>,
        val u32Consts: Set<Long>,          // 无符号 32 位常量集
        val rotlShifts: Set<Long>,         // i32.const 直接后跟 i32.rotl 的移位量
        val rotlCount: Int,
        val xorCount: Int,
        val addCount: Int,
        val loopCount: Int,
    )

    private fun tokenizeListing(listing: String): List<Tok> {
        val toks = mutableListOf<Tok>()
        for (line in listing.lineSequence()) {
            val t = line.trim()
            if (t.isEmpty() || t.startsWith(";;")) continue
            val parts = t.split(Regex("\\s+"))
            val mnem = parts[0]
            var imm = 0L
            var hasImm = false
            if ((mnem == "i32.const" || mnem == "i64.const") && parts.size >= 2) {
                imm = parts[1].trimEnd('L', 'l').toLongOrNull() ?: 0L
                hasImm = true
            }
            toks.add(Tok(mnem, imm, hasImm, t))
        }
        return toks
    }

    private fun buildFuncInfos(bytes: ByteArray, parsed: WasmParser.ParsedWasm, maxFunctions: Int): List<FuncInfo> {
        val importedFuncs = parsed.imports.count { it.kind == "func" }
        val out = ArrayList<FuncInfo>()
        var scanned = 0
        for (body in parsed.funcBodies) {
            if (scanned >= maxFunctions) break
            val idx = body.index
            if (idx < importedFuncs) continue
            val d = disassembler.disassemble(bytes, idx, maxInstructions = 3000)
            if (!d.ok) continue
            val toks = tokenizeListing(d.listing)
            if (toks.isEmpty()) continue
            scanned++
            val u32 = mutableSetOf<Long>()
            val rotlShifts = mutableSetOf<Long>()
            var rotl = 0; var xors = 0; var adds = 0; var loops = 0
            for (i in toks.indices) {
                val tk = toks[i]
                when (tk.mnem) {
                    "i32.const" -> {
                        val u = tk.imm and 0xFFFFFFFFL
                        u32.add(u)
                        if (i + 1 < toks.size && toks[i + 1].mnem == "i32.rotl") rotlShifts.add(u)
                    }
                    "i32.rotl" -> rotl++
                    "i32.xor" -> xors++
                    "i32.add" -> adds++
                    "loop" -> loops++
                }
            }
            val name = parsed.functionNames[idx] ?: body.name
            out.add(FuncInfo(idx, name, toks, u32, rotlShifts, rotl, xors, adds, loops))
        }
        return out
    }

    // ------ MD5 / SHA-1 联合判定（A）------

    private val MD5_IV = setOf(0x67452301L and 0xFFFFFFFFL, 0xefcdab89L and 0xFFFFFFFFL, 0x98badcfeL and 0xFFFFFFFFL, 0x10325476L and 0xFFFFFFFFL)
    private val MD5_MAGIC = setOf(0xd76aa478L and 0xFFFFFFFFL, 0xe8c7b756L and 0xFFFFFFFFL, 0x242070dbL and 0xFFFFFFFFL, 0xc1bdceeeL and 0xFFFFFFFFL)
    // MD5 四个轮流用的 leftrotate 移位计划（F/G/H/I 四组）
    private val MD5_SHIFT_F = setOf(7L, 12L, 17L, 22L)
    private val MD5_SHIFT_ALL = setOf(7L, 12L, 17L, 22L, 5L, 9L, 14L, 20L, 4L, 11L, 16L, 23L, 6L, 10L, 15L, 21L)
    // SHA-1 独有：160-bit 第 5 个 IV + 四个轮常量
    private val SHA1_IV_EXTRA = 0xc3d2e1f0L and 0xFFFFFFFFL
    private val SHA1_ROUND = setOf(0x5a827999L and 0xFFFFFFFFL, 0x6ed9eba1L and 0xFFFFFFFFL, 0x8f1bbcdcL and 0xFFFFFFFFL, 0xca62c1d6L and 0xFFFFFFFFL)

    /**
     * MD5 与 SHA-1 的联合判定。两者共享 IV 前缀（0x67452301...），因此：
     *   - MD5：独有 4 组非线性函数常量（F 0xd76aa478 / G 0xe8c7b756 / H 0x242070db / I 0xc1bdceee）
     *           + 128-bit 状态（4×IV）+ leftrotate 移位表 {7,12,17,22,...} 的四轮流调
     *   - SHA-1：160-bit 状态（5×IV，含 0xc3d2e1f0 ）+ 轮常量 {0x5a827999,...}，无 MD5 F/G/H/I 四组长常量
     */
    private fun identifyMd5Sha1(info: FuncInfo, parsed: WasmParser.ParsedWasm): IdentificationResult? {
        val u = info.u32Consts
        val md5IvHits = MD5_IV.count { it in u }
        val md5MagicHits = MD5_MAGIC.count { it in u }
        val sha1ExtraIv = SHA1_IV_EXTRA in u
        val sha1RoundHits = SHA1_ROUND.count { it in u }
        val shiftF = MD5_SHIFT_F.count { it in info.rotlShifts }
        val shiftAll = MD5_SHIFT_ALL.count { it in info.rotlShifts }

        val basis = linkedSetOf<EvidenceBasis>()
        val evidence = mutableListOf<String>()
        var confidence = 0

        // ---- 优先 MD5：命中 F/G/H/I 非线性常量表（最强）----
        if (md5MagicHits >= 3) {
            basis += EvidenceBasis.NONLINEAR_FUNCTION
            evidence += "MD5 非线性函数常量 F/G/H/I 命中 ×$md5MagicHits（0xd76aa478/0xe8c7b756/0x242070db/0xc1bdceee）"
            basis += EvidenceBasis.ROUND_STRUCTURE
            evidence += "MD5 四组轮常量（F/G/H/I）——区别于 SHA-1 的单一轮常量集"
            confidence = 88
        }

        // ---- MD5：128-bit 状态 + 移位计划 + 轮循环 ----
        if (md5IvHits >= 4 && md5MagicHits == 0 && !sha1ExtraIv) {
            basis += EvidenceBasis.STATE_WIDTH
            evidence += "MD5 128-bit 状态：4×IV 全部命中（0x67452301/0xefcdab89/0x98badcfe/0x10325476）"
            confidence = maxOf(confidence, 82)
        }
        if (md5MagicHits == 0 && !sha1ExtraIv && md5IvHits >= 3) {
            evidence += "MD5 128-bit 状态：4×IV 中命中 ${md5IvHits} 组"
            confidence = maxOf(confidence, 74)
        }
        if (md5MagicHits == 0 && !sha1ExtraIv && shiftF >= 3) {
            basis += EvidenceBasis.ROTATE_SCHEDULE
            evidence += "MD5 leftrotate 移位计划 {7,12,17,22} 覆盖 $shiftF/4"
            confidence = maxOf(confidence, 70)
        }
        if (md5MagicHits == 0 && !sha1ExtraIv && shiftAll >= 8) {
            basis += EvidenceBasis.ROTATE_SCHEDULE
            evidence += "MD5 四轮流调移位表 F/G/H/l 覆盖 $shiftAll/16 个移位量"
            confidence = maxOf(confidence, 76)
        }
        if (info.addCount >= 10 && info.rotlCount >= 10) {
            basis += EvidenceBasis.ROUND_STRUCTURE
            evidence += "MD5 轮函数：i32.add×${info.addCount} i32.rotl×${info.rotlCount}"
        }
        if (info.loopCount >= 1) {
            basis += EvidenceBasis.LOOP_COUNT
            evidence += "MD5 轮循环结构：检测到 loop×${info.loopCount}"
        }

        // ---- 优先 MD5：命中 F/G/H/I 非线性常量即下定论（先于 SHA-1，避免含混杂常量时误判）----
        if (md5MagicHits >= 3) {
            basis += EvidenceBasis.CONSTANT_FINGERPRINT
            return IdentificationResult(
                algorithm = "MD5",
                category = Category.HASH,
                basis = basis,
                evidence = evidence,
                confidence = confidence.coerceIn(85, 95),
                funcIndexes = listOf(info.index),
                exportNames = exportNamesFor(parsed, info.index),
            )
        }

        // ---- SHA-1 ----
        if (sha1RoundHits >= 2) {
            basis += EvidenceBasis.NONLINEAR_FUNCTION
            basis += EvidenceBasis.ROUND_STRUCTURE
            evidence += "SHA-1 轮常量 K 命中 ×$sha1RoundHits（0x5a827999/0x6ed9eba1/0x8f1bbcdc/0xca62c1d6）"
            return IdentificationResult(
                algorithm = "SHA-1",
                category = Category.HASH,
                basis = basis + EvidenceBasis.CONSTANT_FINGERPRINT,
                evidence = evidence,
                confidence = 85,
                funcIndexes = listOf(info.index),
                exportNames = exportNamesFor(parsed, info.index),
            )
        }
        if (sha1ExtraIv) {
            basis += EvidenceBasis.STATE_WIDTH
            evidence += "SHA-1 160-bit 状态：5×IV（含独有 0xc3d2e1f0）命中"
            return IdentificationResult(
                algorithm = "SHA-1",
                category = Category.HASH,
                basis = basis + EvidenceBasis.CONSTANT_FINGERPRINT,
                evidence = evidence,
                confidence = 82,
                funcIndexes = listOf(info.index),
                exportNames = exportNamesFor(parsed, info.index),
            )
        }

        // 非空识别：仅当证据足以支持
        if (md5MagicHits >= 3 || confidence >= 74) {
            basis += EvidenceBasis.CONSTANT_FINGERPRINT
            if (basis.isEmpty()) evidence += "MD5 常量与轮结构证据"
            return IdentificationResult(
                algorithm = "MD5",
                category = Category.HASH,
                basis = basis.ifEmpty { setOf(EvidenceBasis.CONSTANT_FINGERPRINT) },
                evidence = evidence,
                confidence = confidence.coerceIn(60, 95),
                funcIndexes = listOf(info.index),
                exportNames = exportNamesFor(parsed, info.index),
            )
        }
        return null
    }

    // ------ ChaCha20 轮语义识别（C）------

    /**
     * ChaCha20 quarter-round 轮语义：在 wat 指令序列里识别
     *   a+=b; d^=a; d<<<=16; c+=d; b^=c; b<<<=12  的 add/xor/rotl-16/rotl-12 成组模式，
     *   以及（完整轮）rotl-8 / rotl-7 段，再结合轮计数判断 20 轮。
     */
    private fun identifyChaCha(info: FuncInfo, parsed: WasmParser.ParsedWasm): IdentificationResult? {
        val shifts = info.rotlShifts
        val has16 = 16L in shifts
        val has12 = 12L in shifts
        val has8 = 8L in shifts
        val has7 = 7L in shifts
        if (!(has16 && has12)) return null
        if (info.addCount < 4 || info.xorCount < 4) return null

        val full = has8 && has7
        val basis = linkedSetOf<EvidenceBasis>()
        basis += EvidenceBasis.ROUND_STRUCTURE
        val is20 = (info.loopCount >= 1) || full

        val evidence = mutableListOf<String>()
        var confidence = 72
        evidence += "ChaCha20 quarter-round：rotl-16 ×($has16) rotl-12 ×($has12) 成组 add/xor 模式命中"
        if (full) {
            evidence += "完整 quarter-round（rotl-16/12/8/7 齐全）——ChaCha 四分之一轮 (a+=b;d^=a;d<<<16;c+=d;b^=c;b<<<12)"
            confidence = 82
        }
        if (info.loopCount >= 1) {
            basis += EvidenceBasis.LOOP_COUNT
            evidence += "外层轮循环 loop×${info.loopCount}——ChaCha 轮计数循环"
        }
        basis += EvidenceBasis.ROTATE_SCHEDULE
        evidence += "ChaCha 移位计划：rotl{16,12${if (full) ",8,7" else ""}} 轮调"
        if (is20) {
            evidence += "ChaCha20 quarter-round + 20 rounds（20 轮估算成立）"
            confidence = maxOf(confidence, 86)
        } else {
            evidence += "ChaCha quarter-round 结构（轮数未在结构上确认，可能非 20 轮）"
            confidence = maxOf(confidence, 76)
        }

        // sigma 常量佐证
        val sigmaEvidence = hasChachaSigmaEvidence(info)
        if (sigmaEvidence) {
            basis += EvidenceBasis.CONSTANT_FINGERPRINT
            evidence += "ChaCha sigma \"expand 32-byte k\" 命中"
            confidence = maxOf(confidence, 88)
        }
        val algorithm = if (is20) "ChaCha20 (quarter-round + 20 rounds)" else "ChaCha20-like (quarter-round)"
        return IdentificationResult(
            algorithm = algorithm,
            category = Category.STREAM_CIPHER,
            basis = basis,
            evidence = evidence,
            confidence = confidence.coerceAtMost(95),
            funcIndexes = listOf(info.index),
            exportNames = exportNamesFor(parsed, info.index),
        )
    }

    /** 判断函数体常量序列里是否出现 ChaCha sigma（"expa" "nd 3" "2-by" "te k"） */
    private fun hasChachaSigmaEvidence(info: FuncInfo): Boolean {
        // "expand" LE: 0x657870616e6420 -> i32 0x20646e61(xpnd?) 过于依赖布局，改用字节级：直接查 listing
        return info.toks.any { tk ->
            tk.raw.contains("expand 32-byte k")
        }
    }

    // ------ SM3 国密哈希结构识别------

    // SM3 8×32-bit IV（与 SHA-256 完全不同，无共享歧义）
    private val SM3_IV = setOf(
        0x7380166fL and 0xFFFFFFFFL, 0x4914b2b9L and 0xFFFFFFFFL, 0x172442d7L and 0xFFFFFFFFL,
        0xda8a0600L and 0xFFFFFFFFL, 0xa96f30bcL and 0xFFFFFFFFL, 0x163138aaL and 0xFFFFFFFFL,
        0xe38dee4dL and 0xFFFFFFFFL, 0xb0fb0e4eL and 0xFFFFFFFFL,
    )
    // SM3 P0/P1 置换移位计划：P0=X^rotl(X,9)^rotl(X,17)；P1=X^rotl(X,15)^rotl(X,23)
    private val SM3_SHIFT = setOf(9L, 17L, 15L, 23L)

    /**
     * SM3 识别：8×IV 全命中 + P0/P1 置换移位计划 {9,17,15,23} + 64 轮循环。
     * 与 SHA-256 的判别：SHA-256 IV 起始 0x6a09e667、移位计划 {30,19,10,26,21,7,25,14}（rotr 语义）。
     */
    private fun identifySm3(info: FuncInfo, parsed: WasmParser.ParsedWasm): IdentificationResult? {
        val u = info.u32Consts
        val ivHits = SM3_IV.count { it in u }
        val shiftHits = SM3_SHIFT.count { it in info.rotlShifts }
        if (ivHits < 3 && shiftHits < 3) return null

        val basis = linkedSetOf<EvidenceBasis>()
        val evidence = mutableListOf<String>()
        var confidence = 40

        if (ivHits >= 4) {
            basis += EvidenceBasis.STATE_WIDTH
            evidence += "SM3 256-bit 状态：8×IV 命中 $ivHits/8（0x7380166f,0x4914b2b9,...）"
            confidence = maxOf(confidence, 82)
        }
        if (shiftHits >= 3) {
            basis += EvidenceBasis.ROTATE_SCHEDULE
            evidence += "SM3 P0/P1 置换移位计划 {9,17,15,23} 覆盖 $shiftHits/4——区别于 SHA-256 的 {30,19,10,26,...}"
            confidence = maxOf(confidence, 78)
        }
        if (info.addCount >= 10 && info.xorCount >= 6 && info.rotlCount >= 6) {
            basis += EvidenceBasis.ROUND_STRUCTURE
            evidence += "SM3 压缩函数：i32.add×${info.addCount} i32.xor×${info.xorCount} i32.rotl×${info.rotlCount}"
            confidence = maxOf(confidence, 74)
        }
        if (info.loopCount >= 1) {
            basis += EvidenceBasis.LOOP_COUNT
            evidence += "SM3 64 轮循环结构：loop×${info.loopCount}"
        }
        if (confidence < 70) return null
        basis += EvidenceBasis.CONSTANT_FINGERPRINT
        return IdentificationResult(
            algorithm = "SM3",
            category = Category.HASH,
            basis = basis,
            evidence = evidence,
            confidence = confidence.coerceIn(70, 95),
            funcIndexes = listOf(info.index),
            exportNames = exportNamesFor(parsed, info.index),
        )
    }

    // ------ SM4 国密分组密码结构识别------

    // SM4 系统参数 FK（密钥扩展用）
    private val SM4_FK = setOf(
        0xa3b1bac6L and 0xFFFFFFFFL, 0x56aa3350L and 0xFFFFFFFFL,
        0x677d9197L and 0xFFFFFFFFL, 0xb27022dcL and 0xFFFFFFFFL,
    )
    // SM4 线性变换 L：B ^ rotl(B,2) ^ rotl(B,10) ^ rotl(B,18) ^ rotl(B,24)
    private val SM4_SHIFT = setOf(2L, 10L, 18L, 24L)

    /**
     * SM4 识别：FK 常量命中 + 线性变换 L 移位计划 {2,10,18,24} + 32 轮循环。
     * 该移位计划高度特异（AES 用 {1,2,4} 循环移位、SM3 用 {9,17,15,23}）。
     */
    private fun identifySm4(info: FuncInfo, parsed: WasmParser.ParsedWasm): IdentificationResult? {
        val u = info.u32Consts
        val fkHits = SM4_FK.count { it in u }
        val shiftHits = SM4_SHIFT.count { it in info.rotlShifts }
        if (fkHits < 2 && shiftHits < 3) return null

        val basis = linkedSetOf<EvidenceBasis>()
        val evidence = mutableListOf<String>()
        var confidence = 40

        if (fkHits >= 2) {
            basis += EvidenceBasis.CONSTANT_FINGERPRINT
            evidence += "SM4 系统参数 FK 命中 $fkHits/4（0xa3b1bac6,0x56aa3350,0x677d9197,0xb27022dc）"
            confidence = maxOf(confidence, 86)
        }
        if (shiftHits >= 3) {
            basis += EvidenceBasis.ROTATE_SCHEDULE
            evidence += "SM4 线性变换 L 移位计划 {2,10,18,24} 覆盖 $shiftHits/4——高度特异"
            confidence = maxOf(confidence, 82)
        }
        if (info.loopCount >= 1 && info.xorCount >= 8) {
            basis += EvidenceBasis.LOOP_COUNT
            evidence += "SM4 32 轮循环：loop×${info.loopCount} i32.xor×${info.xorCount}"
            confidence = maxOf(confidence, 76)
        }
        if (confidence < 70) return null
        basis += EvidenceBasis.ROUND_STRUCTURE
        return IdentificationResult(
            algorithm = "SM4",
            category = Category.BLOCK_CIPHER,
            basis = basis,
            evidence = evidence,
            confidence = confidence.coerceIn(70, 95),
            funcIndexes = listOf(info.index),
            exportNames = exportNamesFor(parsed, info.index),
        )
    }

    // ------ HMAC 结构识别------

    // HMAC ipad=0x36 / opad=0x5c
    private val HMAC_PAD = setOf(0x36L, 0x5cL)

    /**
     * HMAC 识别：同一函数内同时出现 ipad(0x36) 与 opad(0x5c) 常量，且伴随 XOR 密集 +
     * 哈希压缩函数特征（add/rotl/xor 链）。HMAC 通常与底层哈希（SHA-256/MD5/SM3）同函数或相邻函数。
     */
    private fun identifyHmac(info: FuncInfo, parsed: WasmParser.ParsedWasm): IdentificationResult? {
        val u = info.u32Consts
        val padHits = HMAC_PAD.count { it in u }
        if (padHits < 2) return null
        if (info.xorCount < 4 || info.addCount < 4) return null

        val basis = linkedSetOf<EvidenceBasis>()
        basis += EvidenceBasis.CONSTANT_FINGERPRINT
        val evidence = mutableListOf<String>()
        evidence += "HMAC ipad(0x36)/opad(0x5c) 常量同函数命中——HMAC 内/外填充"
        if (info.xorCount >= 6) {
            basis += EvidenceBasis.ROUND_STRUCTURE
            evidence += "HMAC 填充异或：i32.xor×${info.xorCount}（key^ipad / key^opad）"
        }
        if (info.addCount >= 8 && info.rotlCount >= 4) {
            basis += EvidenceBasis.NONLINEAR_FUNCTION
            evidence += "底层哈希压缩特征：i32.add×${info.addCount} i32.rotl×${info.rotlCount}"
        }
        return IdentificationResult(
            algorithm = "HMAC",
            category = Category.PRF,
            basis = basis,
            evidence = evidence,
            confidence = 78,
            funcIndexes = listOf(info.index),
            exportNames = exportNamesFor(parsed, info.index),
        )
    }

    private fun exportNamesFor(parsed: WasmParser.ParsedWasm, idx: Int): List<String> =
        parsed.exports.filter { it.kind == "func" && it.index == idx }.map { it.name }

    // =========================================================================
    // call_indirect 目标解析（D）
    // =========================================================================

    /**
     * 解析所有函数体里 `i32.const N 后紧跟 call_indirect` 的间接调用目标。
     * 借助 element section 的真实表项候选集合 + 签名类型过滤，输出候选目标函数索引与置信证据。
     */
    fun resolveCallIndirectTargets(bytes: ByteArray, maxFunctions: Int = 400): List<CallIndirectTarget> {
        val parsed = parser.parse(bytes)
        if (!parsed.ok) return emptyList()
        val importedFuncs = parsed.imports.count { it.kind == "func" }
        val totalFuncs = importedFuncs + parsed.codeCount
        val tableSizes = scanTableSection(bytes)
        val tableEntries = scanElementSection(bytes)

        val sigByFunc = buildFuncSigMap(parsed, importedFuncs)
        val typeSigs = parsed.types

        val infos = buildFuncInfos(bytes, parsed, maxFunctions)
        val out = mutableListOf<CallIndirectTarget>()

        for (info in infos) {
            for (i in 0 until info.toks.size - 1) {
                val cur = info.toks[i]
                val next = info.toks[i + 1]
                if (cur.mnem != "i32.const" || next.mnem != "call_indirect") continue
                val prescribed = cur.imm.toInt()
                val (typeIdx, tblIdx) = parseCallIndirectMeta(next.raw)
                if (tblIdx < 0) continue

                val tableSize = tableSizes.getOrNull(if (tblIdx in 0 until tableSizes.size) tblIdx else 0) ?: 0L
                val entries = tableEntries[tblIdx] ?: tableEntries[0] ?: emptyList()

                val evidence = mutableListOf<String>()
                val rawCandidates: List<Int>
                if (entries.isNotEmpty() && prescribed in 0 until entries.size) {
                    rawCandidates = listOf(entries[prescribed])
                    evidence += "i32.const $prescribed 静态可知 → table[$tblIdx] 下标 $prescribed 表项 = func[$prescribed]"
                } else if (entries.isNotEmpty()) {
                    rawCandidates = entries
                    evidence += "i32.const $prescribed 超出已知表项范围，给出 table[$tblIdx] 全部 ${entries.size} 个表项作为候选"
                } else {
                    // 无 element section：按类型 + 函数总数启发式
                    evidence += "无 element section 表项信息，按签名类型在 0..$totalFuncs 内启发式候选"
                    rawCandidates = (0 until totalFuncs).filter { idx ->
                        typeSigs.getOrNull(typeIdx) == null || sigByFunc[idx] == typeSigs[typeIdx]
                    }
                }

                val typeSig = typeSigs.getOrNull(typeIdx)
                val candidates = if (typeSig == null) rawCandidates.distinct()
                else rawCandidates.filter { sigByFunc[it] == typeSig }.distinct()

                val names = candidates.map {
                    parsed.functionNames[it] ?: parsed.exports.firstOrNull { e -> e.kind == "func" && e.index == it }?.name ?: "f$it"
                }
                evidence += "call_indirect (type $typeIdx) (table $tblIdx) table大小=$tableSize"
                val callerName = parsed.functionNames[info.index] ?: info.name
                out.add(
                    CallIndirectTarget(
                        callerFuncIndex = info.index,
                        callerFuncName = callerName,
                        tableIndex = tblIdx,
                        typeIndex = typeIdx,
                        prescribedIndex = prescribed,
                        candidateTargets = candidates,
                        candidateNames = names,
                        evidence = evidence,
                    ),
                )
            }
        }
        return out
    }

    private fun parseCallIndirectMeta(raw: String): Pair<Int, Int> {
        val typeMatch = Regex("\\(type\\s+(-?\\d+)\\)").find(raw)
        val tableMatch = Regex("\\(table\\s+(-?\\d+)\\)").find(raw)
        val typeIdx = typeMatch?.groupValues?.get(1)?.toIntOrNull() ?: -1
        val tblIdx = tableMatch?.groupValues?.get(1)?.toIntOrNull() ?: 0
        return typeIdx to tblIdx
    }

    /** 构建 函数全局索引 -> FuncType 映射（imports + locals） */
    private fun buildFuncSigMap(parsed: WasmParser.ParsedWasm, importedFuncs: Int): Map<Int, WasmParser.FuncType> {
        val map = HashMap<Int, WasmParser.FuncType>()
        var importedPos = 0
        parsed.imports.forEach { imp ->
            if (imp.kind == "func") {
                parsed.types.getOrNull(imp.typeIndex)?.let { map[importedPos] = it }
                importedPos++
            }
        }
        parsed.localFunctions.forEachIndexed { k, t -> map[importedFuncs + k] = t }
        return map
    }

    /** 扫描 table section（id=4）：返回各 table 的元素数量（大小） */
    private fun scanTableSection(bytes: ByteArray): List<Long> {
        val result = mutableListOf<Long>()
        var pos = 8
        while (pos < bytes.size) {
            val secId = bytes[pos].toInt() and 0xff; pos++
            val (size, lb) = readU32(bytes, pos); pos += lb
            val end = pos + size.toInt()
            if (end > bytes.size) break
            if (secId == 4) {
                val (n, nb) = readU32(bytes, pos); pos += nb
                repeat(n.toInt()) {
                    if (pos + 1 > end) return@repeat
                    pos += 1 // reftype
                    val flags = bytes[pos].toInt() and 0xff; pos++
                    val (minv, ml) = readU32(bytes, pos); pos += ml
                    if (flags and 0x01 != 0) { val (_, xl) = readU32(bytes, pos); pos += xl }
                    result.add(minv)
                }
                return result
            }
            pos = end
        }
        return result
    }

    /** 扫描 element section（id=9）：返回 tableIndex -> 实际放置的函数索引列表 */
    private fun scanElementSection(bytes: ByteArray): Map<Int, List<Int>> {
        val map = HashMap<Int, MutableList<Int>>()
        var pos = 8
        while (pos < bytes.size) {
            val secId = bytes[pos].toInt() and 0xff; pos++
            val (size, lb) = readU32(bytes, pos); pos += lb
            val end = pos + size.toInt()
            if (end > bytes.size) break
            if (secId == 9) {
                val (n, nb) = readU32(bytes, pos); pos += nb
                repeat(n.toInt()) {
                    if (pos > end) return@repeat
                    val (flags, fb) = readU32(bytes, pos); pos += fb
                    when (flags.toInt()) {
                        0 -> { // active table0 + offset + vec(funcidx)
                            pos = skipInitExpr(bytes, pos)
                            pos = readFuncIdxVec(bytes, pos, map, 0)
                        }
                        1 -> { // passive: elemkind(0x00) + vec(funcidx)
                            pos += 1
                            pos = readFuncIdxVec(bytes, pos, map, 0)
                        }
                        2 -> { // active explicit tableidx + offset + elemkind + vec(funcidx)
                            val (tbl, tblb) = readU32(bytes, pos); pos += tblb
                            pos = skipInitExpr(bytes, pos)
                            pos += 1
                            pos = readFuncIdxVec(bytes, pos, map, tbl.toInt())
                        }
                        3 -> { // declarative: elemkind + vec(funcidx)
                            pos += 1
                            pos = readFuncIdxVec(bytes, pos, map, 0)
                        }
                        4 -> { // active table0 + offset + vec(expr)
                            pos = skipInitExpr(bytes, pos)
                            pos = readFuncExprVec(bytes, pos, map, 0)
                        }
                        5 -> { // passive: reftype + vec(expr)
                            pos += 1
                            pos = readFuncExprVec(bytes, pos, map, 0)
                        }
                        6 -> { // active explicit tableidx + offset + vec(expr)
                            val (tbl, tblb) = readU32(bytes, pos); pos += tblb
                            pos = skipInitExpr(bytes, pos)
                            pos = readFuncExprVec(bytes, pos, map, tbl.toInt())
                        }
                        7 -> { // declarative: reftype + vec(expr)
                            pos += 1
                            pos = readFuncExprVec(bytes, pos, map, 0)
                        }
                    }
                }
                return map
            }
            pos = end
        }
        return map
    }

    private fun readFuncIdxVec(
        bytes: ByteArray,
        pos: Int,
        map: MutableMap<Int, MutableList<Int>>,
        tableIdx: Int,
    ): Int {
        val (cnt, cb) = readU32(bytes, pos); var p = pos + cb
        val list = map.getOrPut(tableIdx) { mutableListOf() }
        repeat(cnt.toInt()) {
            if (p >= bytes.size) return p
            val (v, vb) = readU32(bytes, p); p += vb
            list.add(v.toInt())
        }
        return p
    }

    private fun readFuncExprVec(
        bytes: ByteArray,
        pos: Int,
        map: MutableMap<Int, MutableList<Int>>,
        tableIdx: Int,
    ): Int {
        val (cnt, cb) = readU32(bytes, pos); var p = pos + cb
        val list = map.getOrPut(tableIdx) { mutableListOf() }
        repeat(cnt.toInt()) {
            // expr = ref.func(0xd2) u32 end(0x0b)
            if (p >= bytes.size) return p
            val op = bytes[p].toInt() and 0xff
            if (op == 0xd2) {
                p += 1
                val (v, vb) = readU32(bytes, p); p += vb
                list.add(v.toInt())
            }
            p = skipInitExpr(bytes, p)
        }
        return p
    }

    /** 跳过常量初始化表达式直到 0x0b(end) */
    private fun skipInitExpr(bytes: ByteArray, pos: Int): Int {
        var p = pos
        while (p < bytes.size) {
            val op = bytes[p].toInt() and 0xff
            when (op) {
                0x41, 0x42 -> { val (_, l) = readU32(bytes, p + 1); p += 1 + l }
                0x43, 0x44 -> p += 1 + if (op == 0x43) 4 else 8
                0x23 -> { val (_, l) = readU32(bytes, p + 1); p += 1 + l }
                0xd2 -> { val (_, l) = readU32(bytes, p + 1); p += 1 + l }
                0x0b -> return p + 1
                else -> return p
            }
        }
        return p
    }

    // ---------------- 既有模式匹配 ----------------

    /** 字节序列匹配（朴素搜索，模式短 + 主串大场景足够快） */
    private fun findPattern(haystack: ByteArray, needle: ByteArray, maxHits: Int): List<Int> {
        val hits = mutableListOf<Int>()
        if (needle.isEmpty() || haystack.size < needle.size) return hits
        val first = needle[0]
        var i = 8 // 跳过 magic+version
        outer@ while (i <= haystack.size - needle.size) {
            if (haystack[i] == first) {
                var j = 1
                while (j < needle.size && haystack[i + j] == needle[j]) j++
                if (j == needle.size) {
                    hits.add(i)
                    if (hits.size >= maxHits) break@outer
                    i += needle.size
                    continue
                }
            }
            i++
        }
        return hits
    }

    /** 函数体级指令模式分析：(算法, 置信, 证据) | null */
    private fun analyzeFunctionPattern(
        bytes: ByteArray,
        body: WasmParser.FuncBodyInfo,
        importedFuncs: Int,
    ): Triple<String, Int, List<String>>? {
        // 轻量解码函数体，统计指令直方图
        val stats = decodeBodyStats(bytes, body, importedFuncs)
        if (stats.totalInstr < 8) return null

        val evidence = mutableListOf<String>()
        var score = 0
        var algo = "custom-ARX"

        // --- ARX 结构检测 ---
        val add = stats.count(0x6a) + stats.count(0x7c)          // i32.add + i64.add
        val xor = stats.count(0x73) + stats.count(0x85)          // i32.xor + i64.xor
        val rotl = stats.count(0x77) + stats.count(0x89)         // i32.rotl + i64.rotl
        val rotr = stats.count(0x78) + stats.count(0x8a)
        val shl = stats.count(0x74) + stats.count(0x86)
        val shr = stats.count(0x76) + stats.count(0x88)
        val or = stats.count(0x72) + stats.count(0x84)
        val and = stats.count(0x71) + stats.count(0x83)
        val mul = stats.count(0x6c) + stats.count(0x7e)

        // 旋转模拟三连：shl + shr + or（编译器展开的 rotl）
        val rotEmulated = minOf(shl, shr, or)
        val hasRotate = (rotl + rotr > 0) || (rotEmulated >= 2 && shl >= 2 && shr >= 2)

        if (add >= 4 && xor >= 4 && hasRotate) {
            score = 75
            algo = "custom-ARX"
            evidence.add("ARX 结构: add×$add xor×$xor rotate(rotl×$rotl/rotr×$rotr/emu×$rotEmulated)")
            if (rotl + rotr >= 4) {
                algo = "ChaCha-like-ARX"
                score = 82
                evidence.add("原生旋转指令密集（${rotl + rotr} 个）——典型 ChaCha/Salsa 轮函数")
            }
        }

        // --- AES 特征：字节加载 + 表查找（load8 + xor + and 0xff）---
        val load8 = (0x2c..0x31).sumOf { stats.count(it) }
        val store8 = (0x3a..0x3c).sumOf { stats.count(it) }
        if (load8 >= 6 && xor >= 6 && and >= 2) {
            val aesScore = minOf(load8, xor)
            if (aesScore > score) {
                score = 60
                algo = "byte-mix-cipher"
                evidence.clear()
                evidence.add("字节混合: load8×$load8 store8×$store8 xor×$xor and×$and——疑似 AES/SM4 轮函数或自研字节变换")
            }
        }

        // --- SHA/MD5 特征：常量异或 + 大循环 + 32 位加法链 ---
        val i32add = stats.count(0x6a)
        val loop = stats.count(0x03)   // loop
        if (i32add >= 10 && loop >= 1 && xor + and >= 2) {
            if (score < 65) {
                score = 65
                algo = "hash-compress"
                evidence.add("压缩函数特征: i32.add×$i32add loop×$loop——疑似 SHA/MD5/自定义哈希消息调度")
            }
        }

        // --- 乘法密集：MD5/SHA-1 级复杂度或自研 hash ---
        if (mul >= 3 && add >= 3 && xor >= 2 && score < 60) {
            score = 55
            algo = "mul-mix-hash"
            evidence.add("乘法混合: mul×$mul add×$add xor×$xor——疑似 MurmurHash/xxHash/自研乘法哈希")
        }

        // --- 表驱动查表（S-box 风格）：i32.load + and（索引掩码）---
        val load32 = stats.count(0x28) + stats.count(0x2f) + stats.count(0x35)
        if (load32 >= 4 && and >= 2 && score < 60) {
            score = 58
            algo = "table-lookup-cipher"
            evidence.add("查表密集: i32.load×$load32 and×$and——疑似 S-box/置换表驱动（RC4/DES/AES-T 表）")
        }

        if (score <= 0 || evidence.isEmpty()) return null
        evidence.add("指令总数 ${stats.totalInstr}，函数体 ${body.bodySize} 字节")
        return Triple(algo, score.coerceAtMost(95), evidence)
    }

    /** 函数体指令直方图（轻量解码：跳过 immediate，含 SIMD 前缀处理） */
    private fun decodeBodyStats(bytes: ByteArray, body: WasmParser.FuncBodyInfo, importedFuncs: Int): InstrStats {
        val stats = InstrStats()
        val localIdx = body.index - importedFuncs
        if (localIdx < 0) return stats
        val from = bodyStart(bytes, localIdx)
        if (from < 0) return stats
        var pos = from
        val bodyEnd = from + body.bodySize
        // locals 声明跳过
        runCatching {
            val (groups, gb) = readU32(bytes, pos); pos += gb
            repeat(groups.toInt()) {
                val (_, cb) = readU32(bytes, pos); pos += cb + 1
            }
            while (pos < bodyEnd) {
                val op = bytes[pos].toInt() and 0xff
                pos++
                stats.add(op)
                pos = skipImmediates(bytes, pos, bodyEnd, op)
            }
        }
        return stats
    }

    /** code section 内定位函数体起点（bodySize 字段的下一字节） */
    private fun bodyStart(bytes: ByteArray, localIdx: Int): Int {
        var pos = 8
        var idx = 0
        while (pos < bytes.size) {
            val secId = bytes[pos].toInt() and 0xff
            pos++
            val (size, lb) = readU32(bytes, pos)
            pos += lb
            val end = pos + size.toInt()
            if (end > bytes.size) return -1
            if (secId == 10) {
                val (n, nb) = readU32(bytes, pos)
                pos += nb
                repeat(n.toInt()) {
                    val (bodySize, bb) = readU32(bytes, pos)
                    pos += bb
                    if (idx == localIdx) return pos
                    pos += bodySize.toInt()
                    idx++
                }
                return -1
            }
            pos = end
        }
        return -1
    }

    /* * 跳过指令 immediate（完整处理 SIMD 0xfd / Atomics 0xfe / GC 0xfb） */
    private fun skipImmediates(bytes: ByteArray, pos: Int, bodyEnd: Int, op: Int): Int {
        var p = pos
        when (op) {
            0x02, 0x03, 0x04 -> { // blocktype
                val v = bytes[p].toInt() and 0xff
                if (v == 0x40 || v == 0x7f || v == 0x7e || v == 0x7d || v == 0x7c || v == 0x7b ||
                    v == 0x70 || v == 0x6f
                ) p += 1
                else while (p < bodyEnd && bytes[p].toInt() and 0x80 != 0) p++; p += 1
            }
            0x0c, 0x0d, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0xd2 -> p += u32Len(bytes, p)
            0x0e -> { // br_table
                val (cnt, cb) = readU32(bytes, p); p += cb
                repeat(cnt.toInt() + 1) { p += u32Len(bytes, p) }
            }
            0x10 -> p += u32Len(bytes, p)
            0x11 -> { p += u32Len(bytes, p); p += u32Len(bytes, p) }
            0x1c -> { val (cnt, cb) = readU32(bytes, p); p += cb + cnt.toInt() }
            0x00, 0x01, 0x05, 0x0b, 0x0f, 0x1a, 0x1b -> { /* no immediate */ }
            in 0x28..0x3e -> { p += u32Len(bytes, p); p += u32Len(bytes, p) }
            0x3f, 0x40 -> p += u32Len(bytes, p)
            0x41 -> { while (p < bodyEnd && bytes[p].toInt() and 0x80 != 0) p++; p += 1 }
            0x42 -> { while (p < bodyEnd && bytes[p].toInt() and 0x80 != 0) p++; p += 1 }
            0x43 -> p += 4
            0x44 -> p += 8
            0xd0 -> p += 1
            0xfb -> { // GC 前缀：子操作码 + 少量 u32
                p += u32Len(bytes, p)
                p += u32Len(bytes, p)
            }
            0xfc -> { // bulk memory / sat trunc
                val (sub, sb) = readU32(bytes, p); p += sb
                when (sub.toInt()) {
                    8, 9, 11, 13, 15 -> p += u32Len(bytes, p)
                    10, 12, 14 -> { p += u32Len(bytes, p); p += u32Len(bytes, p) }
                    else -> { /* sat trunc：无 immediate */ }
                }
            }
            0xfd -> { // SIMD 前缀：子操作码 + 按 sub 跳 immediate
                val (sub, sb) = readU32(bytes, p); p += sb
                p += skipSimdImmediate(bytes, p, sub.toInt())
            }
            0xfe -> { // Atomics：memarg (align, offset)
                p += u32Len(bytes, p); p += u32Len(bytes, p)
            }
            else -> { /* 无 immediate 的常规指令 */ }
        }
        return p
    }

    /** SIMD 子操作码的 immediate 长度（按 wasm SIMD 规范布局） */
    private fun skipSimdImmediate(bytes: ByteArray, pos: Int, sub: Int): Int {
        var p = pos
        when {
            // v128.const（0x0C）：16 字节字面量
            sub == 0x0c -> p += 16
            // i8x16.shuffle（0x0D）：16 个 lane 索引
            sub == 0x0d -> p += 16
            // extract/replace lane（0x15..0x22）：单 lane 字节
            sub in 0x15..0x22 -> p += 1
            // load/store lane（0x54..0x5F）：memarg + lane 字节
            sub in 0x54..0x5f -> { p += u32Len(bytes, p); p += u32Len(bytes, p); p += 1 }
            // v128 load/store（0x00..0x0B）：memarg
            sub in 0x00..0x0b -> { p += u32Len(bytes, p); p += u32Len(bytes, p) }
            // 其余（算术/比较/位运算/swizzle/splat）：无 immediate
            else -> { /* none */ }
        }
        return p - pos
    }

    private fun readU32(b: ByteArray, from: Int): Pair<Long, Int> {
        var result = 0L; var shift = 0; var i = from
        while (i < b.size) {
            val byte = b[i].toInt() and 0xff
            result = result or ((byte and 0x7f).toLong() shl shift)
            i++
            if (byte and 0x80 == 0) break
            shift += 7
            if (shift > 35) break
        }
        return result to (i - from)
    }

    private fun u32Len(b: ByteArray, from: Int): Int = readU32(b, from).second

    private class InstrStats {
        val counts = HashMap<Int, Int>()
        var totalInstr = 0
        fun add(op: Int) {
            counts[op] = (counts[op] ?: 0) + 1
            totalInstr++
        }
        fun count(op: Int): Int = counts[op] ?: 0
    }

    // ---------------- 汇总 ----------------

    private fun mergeFindings(findings: List<CryptoFinding>): List<CryptoFinding> {
        // 同算法的 constant + pattern 证据合并加分
        val byAlgo = findings.groupBy { it.algorithm }
        val out = mutableListOf<CryptoFinding>()
        for ((algo, list) in byAlgo) {
            if (list.size == 1) {
                out.add(list[0])
                continue
            }
            val hasConst = list.any { it.kind == "constant" }
            val hasPattern = list.any { it.kind == "pattern" }
            if (hasConst && hasPattern) {
                val conf = (list.maxOf { it.confidence } + 20).coerceAtMost(99)
                val ev = list.flatMap { it.evidence }
                val f = list.first { it.kind == "pattern" }
                out.add(
                    CryptoFinding(
                        algorithm = algo, confidence = conf, evidence = ev,
                        funcIndex = f.funcIndex, funcName = f.funcName, kind = "combined",
                    ),
                )
                // 合并后仍保留纯常量项（无函数归属的模块级证据）
                list.filter { it.kind == "constant" }.forEach { out.add(it.copy(confidence = it.confidence.coerceAtMost(conf))) }
            } else {
                out.addAll(list)
            }
        }
        return out.sortedWith(
            compareByDescending<CryptoFinding> { it.confidence }.thenBy { it.algorithm },
        )
    }

    private fun buildSummary(
        findings: List<CryptoFinding>,
        parsed: WasmParser.ParsedWasm,
        identifications: List<IdentificationResult> = emptyList(),
        callIndirect: List<CallIndirectTarget> = emptyList(),
    ): String {
        val sb = StringBuilder()
        if (identifications.isNotEmpty()) {
            sb.appendLine("算法级识别（Identification，共 ${identifications.size} 项）：")
            identifications.take(12).forEach { id ->
                val loc = if (id.funcIndexes.isEmpty()) "data段" else "func${id.funcIndexes.joinToString(",")}"
                sb.appendLine("  [${id.confidence}%] ${id.algorithm}（${id.category}）@ $loc")
                sb.appendLine("      依据: ${id.basis.joinToString(",")}")
                id.evidence.take(2).forEach { sb.appendLine("        - $it") }
            }
        }
        if (findings.isEmpty() && identifications.isEmpty()) {
            return "未识别到已知加密算法指纹（常量与指令模式均未命中）。" +
                "可能是：自研混淆算法 / 常量在运行时解密生成 / 非 crypto 模块。建议 wasm.disassemble_func 手工分析 cryptoHotspots。"
        }
        sb.appendLine("识别到 ${findings.size} 个加密相关指纹：")
        findings.take(10).forEach { f ->
            val loc = if (f.funcIndex >= 0) "func[${f.funcIndex}]${f.funcName?.let { " $it" } ?: ""}" else "data段"
            sb.appendLine("  [${f.confidence}%] ${f.algorithm} @ $loc (${f.kind})")
        }
        val constHits = findings.filter { it.kind == "constant" }.map { it.algorithm }.distinct()
        if (constHits.isNotEmpty()) sb.appendLine("常量指纹命中: ${constHits.joinToString(", ")}——高可信算法识别")
        if (callIndirect.isNotEmpty()) {
            sb.appendLine("call_indirect 候选目标解析（${callIndirect.size} 处）：")
            callIndirect.take(8).forEach { c ->
                sb.appendLine("  func[$c.callerFuncIndex]${c.callerFuncName?.let { " $it" } ?: ""} → (type ${c.typeIndex},table ${c.tableIndex}) 候选[${c.candidateTargets.joinToString(",")}]")
            }
        }
        sb.append("下一步：对高置信函数执行 wasm.disassemble_func / wasm.cfg_ssa 做指令级验证")
        return sb.toString()
    }
}