package com.webreverse.mcp.javascript.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * WasmDisassembler 单元测试。
 *
 * 手工构造最小合法 .wasm 二进制（无 wabt 依赖），覆盖：
 * - 导出名/索引反汇编、签名与局部变量计数
 * - i32.const/local.get/i32.add 等标准指令名
 * - call 目标符号化（导入名 env.print）
 * - 导入函数报错、索引越界、截断
 */
class WasmDisassemblerTest {

    // ---------------- 测试模块构造 ----------------

    /**
     * 模块 A：导出 add(i32)->i32
     * body: local.get 0; local.get 0; i32.const 5; i32.add; end
     */
    private val moduleA: ByteArray = byteArrayOf(
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic + version
        // type section: 1 type, (i32) -> i32
        0x01, 0x06, 0x01, 0x60, 0x01, 0x7f, 0x01, 0x7f,
        // function section: 1 func, type 0
        0x03, 0x02, 0x01, 0x00,
        // export section: "add" -> func 0
        0x07, 0x07, 0x01, 0x03, 0x61, 0x64, 0x64, 0x00, 0x00,
        // code section: 1 body(size 9): 0 locals, i32.const 5, local.get 0, local.get 0, i32.add, end
        0x0a, 0x0b, 0x01, 0x09, 0x00, 0x41, 0x05, 0x20, 0x00, 0x20, 0x00, 0x6a, 0x0b,
    )

    /**
     * 模块 B：导入 env.print(i32)->i32 + 导出 add 调用它
     * body: local.get 0; call 0; drop; br 0; end
     */
    private val moduleB: ByteArray = byteArrayOf(
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
        // type section: (i32) -> i32
        0x01, 0x06, 0x01, 0x60, 0x01, 0x7f, 0x01, 0x7f,
        // import section: env.print func type 0
        0x02, 0x0d, 0x01, 0x03, 0x65, 0x6e, 0x76, 0x05, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x00, 0x00,
        // function section: 1 local func, type 0
        0x03, 0x02, 0x01, 0x00,
        // export section: "add" -> func 1（导入占 0）
        0x07, 0x07, 0x01, 0x03, 0x61, 0x64, 0x64, 0x00, 0x01,
        // code section: body(9): 0 locals, local.get 0, call 0, drop, br 0, end
        0x0a, 0x0b, 0x01, 0x09, 0x00, 0x20, 0x00, 0x10, 0x00, 0x0a, 0x0c, 0x00, 0x0b,
    )

    // ---------------- 基本反汇编 ----------------

    @Test
    fun `disassembles exported function by name`() {
        val r = WasmDisassembler().disassembleExport(moduleA, "add")
        assertTrue("应成功反汇编，error=${r.error}", r.ok)
        assertEquals("add", r.funcName)
        assertEquals(0, r.funcIndex)
        assertEquals("(param i32) (result i32)", r.signature)
        assertEquals(0, r.localsCount)
        // i32.const 5 + local.get + local.get + i32.add + end = 5 条
        assertEquals("指令数应为 5，实际 ${r.instructionCount}", 5, r.instructionCount)
        assertTrue("应含 i32.const 5", r.listing.contains("i32.const 5"))
        assertTrue("应含 local.get 0", r.listing.contains("local.get 0"))
        assertTrue("应含 i32.add", r.listing.contains("i32.add"))
        assertTrue("应含 end", r.listing.contains("end"))
    }

    @Test
    fun `disassembles by index with import offset`() {
        // 模块 B：导入函数占 index 0，本地 add 是 index 1
        val r = WasmDisassembler().disassemble(moduleB, 1)
        assertTrue("应成功反汇编，error=${r.error}", r.ok)
        assertEquals("add", r.funcName)
        assertEquals(1, r.funcIndex)
        // call 0 应符号化为 env.print
        assertTrue("call 应符号化为 env.print，listing=${r.listing}", r.listing.contains("env.print"))
        // local.get + call + drop + br + end = 5 条
        assertEquals(5, r.instructionCount)
        assertTrue("应含 br 0", r.listing.contains("br 0"))
    }

    @Test
    fun `missing export reports error`() {
        val r = WasmDisassembler().disassembleExport(moduleA, "nonexistent")
        assertFalse(r.ok)
        assertTrue("应提示导出不存在", r.error.contains("nonexistent"))
    }

    @Test
    fun `imported function index rejected`() {
        // 模块 B 的 index 0 是导入函数 env.print
        val r = WasmDisassembler().disassemble(moduleB, 0)
        assertFalse(r.ok)
        assertTrue("应提示导入函数无函数体，error=${r.error}", r.error.contains("导入函数"))
        assertTrue("应给出导入名", r.error.contains("env.print"))
    }

    @Test
    fun `out of range index rejected`() {
        val r = WasmDisassembler().disassemble(moduleA, 5)
        assertFalse(r.ok)
        assertTrue("应提示索引越界，error=${r.error}", r.error.contains("超出范围"))
    }

    @Test
    fun `maxInstructions truncates listing`() {
        val r = WasmDisassembler().disassemble(moduleA, 0, maxInstructions = 2)
        assertTrue(r.ok)
        assertTrue("应标记截断", r.truncated)
        assertEquals("截断时只渲染 2 条，实际 ${r.instructionCount}", 2, r.instructionCount)
    }

    // ---------------- 解析层（WasmParser） ----------------

    @Test
    fun `parses sections and exports`() {
        val p = WasmParser().parse(moduleB)
        assertTrue("模块应解析成功，error=${p.error}", p.ok)
        assertEquals(1, p.types.size)
        assertEquals(1, p.imports.size)
        assertEquals("env", p.imports[0].module)
        assertEquals("print", p.imports[0].name)
        assertEquals("func", p.imports[0].kind)
        assertEquals("导出应指向 func 1", 1, p.exports.first { it.kind == "func" }.index)
    }

    @Test
    fun `non wasm bytes rejected`() {
        val r = WasmDisassembler().disassemble("not wasm".toByteArray(), 0)
        assertFalse(r.ok)
        assertTrue("应报 magic 错误，error=${r.error}", r.error.contains("WASM"))
    }
}
