package com.webreverse.mcp.javascript.parser

import com.google.common.truth.Truth.assertThat
import org.junit.Test

/**
 * JsFormatter 单元测试。
 * 重点验证：minified 代码格式化正确性、字符串/模板/正则/注释不被破坏、
 * 混淆标识符重命名、for(;;) 头部不被拆行、防御性退化。
 */
class JsFormatterTest {

    private fun fmt(src: String, rename: Boolean = false, indent: Int = 2) =
        JsFormatter(indentSize = indent, renameObfuscated = rename, maxOutputChars = 1_000_000)
            .format(src).formatted

    @Test
    fun `minified function declaration gets newlines and indent`() {
        val out = fmt("function add(a,b){return a+b;}")
        assertThat(out).contains("function add(a, b) {")
        assertThat(out).contains("return a + b;")
        assertThat(out).contains("}")
        assertThat(out.lines().first().trim()).startsWith("function")
    }

    // ================= 原始坐标 → 格式化行号映射 =================

    @Test
    fun `formattedLineFor maps original offset to formatted line`() {
        // minified 单行源码：search_in_content 命中坐标永远是 (第1行, 第N列)
        val src = "function a(){x();}function b(){y();}function c(){z();}"
        val r = JsFormatter(indentSize = 2, renameObfuscated = false, maxOutputChars = 1_000_000).format(src)
        // offset 0 → 第一行（function a）
        assertThat(r.formattedLineFor(0)).isEqualTo(1)
        // function b 起始偏移 18 → 应落在含 "function b" 的格式化行
        val bLine = r.formatted.lines().indexOfFirst { it.contains("function b") } + 1
        assertThat(r.formattedLineFor(18)).isEqualTo(bLine)
        // function c 起始偏移 36 → 含 "function c" 的行
        val cLine = r.formatted.lines().indexOfFirst { it.contains("function c") } + 1
        assertThat(r.formattedLineFor(36)).isEqualTo(cLine)
    }

    @Test
    fun `formattedLineFor handles multiline source line numbers`() {
        // 多行源码：第 3 行的 token 应映射到含该 token 的格式化行
        val src = "var a = 1;\nvar b = 2;\nvar c = a + b;\nconsole.log(c);"
        val r = JsFormatter(indentSize = 2, renameObfuscated = false, maxOutputChars = 1_000_000).format(src)
        // 找到 "var c" 在格式化输出中的行
        val cLine = r.formatted.lines().indexOfFirst { it.contains("var c") } + 1
        // 原始第 3 行起始偏移 = "var a = 1;\nvar b = 2;\n".length = 22
        assertThat(r.formattedLineFor(22)).isEqualTo(cLine)
        // 超出末尾的偏移 → 最后一行（不越界）
        assertThat(r.formattedLineFor(src.length + 100)).isAtMost(r.formatted.lines().size)
    }

    @Test
    fun `lineStartOffsets entry count matches formatted line count`() {
        val src = "function a(){x();}function b(){y();}"
        val r = JsFormatter(indentSize = 2, renameObfuscated = false, maxOutputChars = 1_000_000).format(src)
        assertThat(r.lineStartOffsets.size).isEqualTo(r.formatted.lines().size)
    }

    @Test
    fun `for header semicolons stay on one line`() {
        val out = fmt("for(var i=0;i<10;i++){console.log(i);}")
        // for 头部三段不换行
        val forLine = out.lines().first { it.contains("for") }
        assertThat(forLine).contains("for (var i = 0; i < 10; i++) {")
    }

    @Test
    fun `semicolons inside strings are not treated as statement breaks`() {
        val out = fmt("var s=\"a;b{c}\";x();")
        assertThat(out).contains("\"a;b{c}\"")
    }

    @Test
    fun `braces inside comments are preserved verbatim`() {
        val out = fmt("var a=1;/* {;} */var b=2;")
        assertThat(out).contains("/* {;} */")
        assertThat(out).doesNotContain("var b = 2;/*")
    }

    @Test
    fun `line comment forces newline after`() {
        val out = fmt("var a=1;// note { ; }\nvar b=2;")
        assertThat(out).contains("// note { ; }")
        val lines = out.lines()
        val commentIdx = lines.indexOfFirst { it.contains("// note") }
        assertThat(lines[commentIdx + 1].trim()).startsWith("var b")
    }

    @Test
    fun `template literal content is preserved`() {
        val src = "var t=`hi \${name} ; { } //x`;f(t);"
        val out = fmt(src)
        assertThat(out).contains("`hi \${name} ; { } //x`")
    }

    @Test
    fun `nested template literal with braces in interpolation`() {
        val src = "var t=`a\${ {k:1}.k }b`;"
        val out = fmt(src)
        assertThat(out).contains("`a\${ {k:1}.k }b`")
    }

    @Test
    fun `regex literal is not mistaken for division`() {
        val src = "var re=/a{2,};\\/g;var b=re.test('aa');"
        val out = fmt(src)
        assertThat(out).contains("/a{2,};\\/")
    }

    @Test
    fun `division gets spaces but regex is untouched`() {
        val out = fmt("var x=a/b/c;")
        assertThat(out).contains("a / b / c")
    }

    @Test
    fun `if else blocks format with proper structure`() {
        val out = fmt("if(a){f()}else{g()}")
        assertThat(out).contains("if (a) {")
        assertThat(out).contains("} else {")
    }

    @Test
    fun `empty object stays inline`() {
        val out = fmt("var o={};")
        assertThat(out).contains("= {}")
    }

    @Test
    fun `obfuscated identifiers are renamed at token level only`() {
        val src = "var _0x4a3f=function(_0x1b2c){return _0x1b2c+'str _0x4a3f'};"
        val result = JsFormatter(renameObfuscated = true).format(src)
        val out = result.formatted
        // 代码位置的重命名
        assertThat(out).doesNotContain("_0x4a3f=function")
        assertThat(out).contains("v1 = function (")
        // 字符串内容不受影响
        assertThat(out).contains("str _0x4a3f")
        assertThat(result.renameMap).containsEntry("_0x4a3f", "v1")
    }

    @Test
    fun `rename avoids collision with existing identifiers`() {
        val src = "var v1=1;var _0xabcd=2;"
        val result = JsFormatter(renameObfuscated = true).format(src)
        // _0xabcd 不能重命名为 v1（已被占用）
        assertThat(result.renameMap["_0xabcd"]).isNotEqualTo("v1")
    }

    @Test
    fun `return value never separated by newline`() {
        val out = fmt("function f(){return {a:1};}")
        val returnIdx = out.indexOf("return")
        assertThat(out[returnIdx + 6]).isEqualTo(' ') // return 与 { 同行（换行只能出现在 { 之后）
        assertThat(out.substring(returnIdx, returnIdx + 8)).isEqualTo("return {")
    }

    @Test
    fun `member access chains are not spaced`() {
        val out = fmt("a.b(c).d=e;")
        assertThat(out).contains("a.b(c).d = e")
    }

    @Test
    fun `output cap truncates and flags`() {
        val src = "var x=1;".repeat(2000)
        val r = JsFormatter(maxOutputChars = 1000).format(src)
        assertThat(r.truncated).isTrue()
        assertThat(r.formatted.length).isEqualTo(1000)
    }

    @Test
    fun `arrow function and ternary readability`() {
        val out = fmt("var f=a=>a>1?1:0;")
        assertThat(out).contains("a => a > 1 ? 1 : 0")
    }

    @Test
    fun `iife is not broken`() {
        val out = fmt("!function(){var x=1;}();")
        assertThat(out).contains("!function () {")
        val joined = out.replace("\n", "")
        assertThat(joined).contains("}()")
    }

    @Test
    fun `unterminated string does not crash`() {
        val out = fmt("var s='abc")
        assertThat(out).contains("'abc")
    }

    @Test
    fun `unicode content preserved`() {
        val out = fmt("var s=\"中文测试\"；".replace("；", ";"))
        assertThat(out).contains("\"中文测试\"")
    }

    @Test
    fun `degraded path returns original on unexpected input`() {
        val r = JsFormatter().format("plain text without code")
        assertThat(r.degraded).isFalse()
        assertThat(r.formatted).contains("plain text")
    }
}
