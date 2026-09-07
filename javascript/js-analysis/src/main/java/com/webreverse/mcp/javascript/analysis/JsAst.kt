package com.webreverse.mcp.javascript.analysis

/**
 * JS 结构化 AST 模型（面向逆向的轻量级递归下降产物）。
 *
 * 全面升级：按「真实 JS Parser」路线补齐现代 ECMAScript 语法，
 * 覆盖逆向分析（webpack/Vite/Babel/TS 编译产物）高频语法：
 * 函数声明/表达式、var/let/const、if/for/while/switch/return、调用、成员访问、
 * 赋值（含复合/逻辑赋值）、二元/一元运算、数组/对象字面量；
 * **新增**：可选链 `?.`、空值合并 `??`、模板字面量（含 `${}` 插值与标签模板）、
 * 展开运算符 `...`、`new` 表达式、序列（逗号）表达式、await/yield、
 * 类声明/表达式（extends/静态/私有字段/getter/setter）、try/catch/finally、
 * 解构声明、import/export 语句（尽力恢复）。
 * 全部纯 Kotlin、无第三方依赖，供 [JsAstParser]（解析）、[JsCfgBuilder]（控制流图）
 * 与 [JsDfgAnalyzer]（数据流/污点）共用。
 */

/** 源码位置（1 基行/列 + 字符偏移） */
data class SourcePos(val line: Int, val col: Int, val offset: Int) {
    companion object {
        val NONE = SourcePos(0, 0, -1)
    }
}

/** 表达式基类 */
sealed class Expr {
    abstract val pos: SourcePos

    data class Identifier(val name: String, override val pos: SourcePos) : Expr()
    data class Number(val value: String, override val pos: SourcePos) : Expr()
    data class StringLit(val value: String, override val pos: SourcePos) : Expr()
    data class BoolLit(val value: Boolean, override val pos: SourcePos) : Expr()
    data class NullLit(override val pos: SourcePos) : Expr()
    data class UndefinedLit(override val pos: SourcePos) : Expr()
    data class ThisRef(override val pos: SourcePos) : Expr()

    /** 函数表达式：function (name)?(params){body} 或 (params)=>body */
    data class FunctionExpr(
        val name: String?,
        val params: List<String>,
        val body: Stmt.Block,
        val isArrow: Boolean = false,
        override val pos: SourcePos,
        val isAsync: Boolean = false,
        val isGenerator: Boolean = false,
    ) : Expr()

    /** 成员访问：obj.prop / obj[expr]；[optional]=true 表示 obj?.prop / obj?.[expr] */
    data class Member(
        val obj: Expr,
        val property: String?,
        val computed: Expr?,
        override val pos: SourcePos,
        val optional: Boolean = false,
    ) : Expr()

    /** 调用：callee(args)；[optional]=true 表示 callee?.(args)；[spreadIdx] 标记 ... 展开参数 */
    data class Call(
        val callee: Expr,
        val args: List<Expr>,
        override val pos: SourcePos,
        val optional: Boolean = false,
    ) : Expr()

    /** 赋值：target (=|+=|...) value */
    data class Assign(val target: Expr, val op: String, val value: Expr, override val pos: SourcePos) : Expr()

    /** 二元运算 */
    data class Binary(val left: Expr, val op: String, val right: Expr, override val pos: SourcePos) : Expr()

    /** 条件（三元）运算 cond ? a : b */
    data class Conditional(val test: Expr, val consequent: Expr, val alternate: Expr, override val pos: SourcePos) : Expr()

    /** 一元运算 */
    data class Unary(val op: String, val operand: Expr, override val pos: SourcePos) : Expr()

    /** 数组字面量 [a, b, ...rest]（元素可为 [Spread]） */
    data class ArrayLit(val elements: List<Expr>, override val pos: SourcePos) : Expr()

    /** 对象字面量 {k:v, ...spread, method(){}, get k(){}} */
    data class ObjectLit(val props: List<ObjectProperty>, override val pos: SourcePos) : Expr()

    /** 模板字面量：`a${x}b${y}c`；quasis.size == exprs.size + 1 */
    data class TemplateLit(val quasis: List<String>, val exprs: List<Expr>, override val pos: SourcePos) : Expr()

    /** 标签模板：tag`...` */
    data class TaggedTemplate(val tag: Expr, val template: TemplateLit, override val pos: SourcePos) : Expr()

    /** 展开运算符：...expr（数组元素/调用参数/对象属性） */
    data class Spread(val arg: Expr, override val pos: SourcePos) : Expr()

    /** new 表达式：new Callee(args) */
    data class New(val callee: Expr, val args: List<Expr>, override val pos: SourcePos) : Expr()

    /** 序列（逗号）表达式：(a, b, c) */
    data class Sequence(val exprs: List<Expr>, override val pos: SourcePos) : Expr()

    /** await 表达式 */
    data class AwaitExpr(val arg: Expr, override val pos: SourcePos) : Expr()

    /** yield 表达式（[delegate]=true 表示 yield*） */
    data class YieldExpr(val arg: Expr?, val delegate: Boolean, override val pos: SourcePos) : Expr()
}

/** 对象属性 {k: v} / {...spread} / {method(){}} / {get/set k(){}} */
data class ObjectProperty(
    val key: String,
    val value: Expr?,
    val pos: SourcePos,
    val computed: Expr? = null,
    val isSpread: Boolean = false,
    val isMethod: Boolean = false,
    val isAsync: Boolean = false,
    val isGenerator: Boolean = false,
    val isGet: Boolean = false,
    val isSet: Boolean = false,
)

/** 类成员：方法 / 字段 / 构造器 */
data class ClassMember(
    val name: String,
    val params: List<String>,
    val body: Stmt.Block,
    val isStatic: Boolean,
    val kind: String, // method / field / ctor / get / set
    val init: Expr? = null,
    val isAsync: Boolean = false,
    val isGenerator: Boolean = false,
    val pos: SourcePos,
)

/** 语句基类 */
sealed class Stmt {
    abstract val pos: SourcePos

    /** 变量声明 var/let/const name = init */
    data class VarDecl(val kind: String, val name: String, val init: Expr?, override val pos: SourcePos) : Stmt()

    /** 解构声明：const {a, b = 1, ...rest} = obj / [x, y] = arr */
    data class DestructureDecl(
        val kind: String,
        val bindings: List<DestructureBinding>,
        val init: Expr?,
        override val pos: SourcePos,
    ) : Stmt()

    /** 表达式语句 */
    data class ExprStmt(val expr: Expr, override val pos: SourcePos) : Stmt()

    /** if (cond) then [else elseStmt] */
    data class If(val cond: Expr, val thenBody: Stmt, val elseBody: Stmt?, override val pos: SourcePos) : Stmt()

    /** for(init; cond; update) body */
    data class For(
        val init: Stmt?,
        val cond: Expr?,
        val update: Expr?,
        val body: Stmt,
        override val pos: SourcePos,
        val isAwait: Boolean = false,
    ) : Stmt()

    /** for(left in/of obj) body */
    data class ForEach(
        val left: Expr,
        val obj: Expr,
        val body: Stmt,
        val of: Boolean = false,
        override val pos: SourcePos,
        val isAwait: Boolean = false,
    ) : Stmt()

    /** while(cond) body */
    data class While(val cond: Expr, val body: Stmt, override val pos: SourcePos) : Stmt()

    /** do body while(cond); */
    data class DoWhile(val body: Stmt, val cond: Expr, override val pos: SourcePos) : Stmt()

    /** switch(disc){ cases } */
    data class Switch(val disc: Expr, val cases: List<SwitchCase>, override val pos: SourcePos) : Stmt()

    /** return [arg] */
    data class Return(val arg: Expr?, override val pos: SourcePos) : Stmt()

    /** try {} catch (e) {} finally {} */
    data class TryCatch(
        val block: Stmt.Block,
        val catchParam: String?,
        val catchBody: Stmt.Block?,
        val finallyBody: Stmt.Block?,
        override val pos: SourcePos,
    ) : Stmt()

    /** class 声明/语句：class Name extends Base { members } */
    data class ClassDecl(
        val name: String,
        val superClass: String?,
        val members: List<ClassMember>,
        override val pos: SourcePos,
    ) : Stmt()

    /** { stmts } */
    data class Block(val stmts: List<Stmt>, override val pos: SourcePos) : Stmt()

    data class Break(override val pos: SourcePos) : Stmt()
    data class Continue(override val pos: SourcePos) : Stmt()
    data class Throw(val arg: Expr?, override val pos: SourcePos) : Stmt()
    data class EmptyStmt(override val pos: SourcePos) : Stmt()

    /**
     * import 语句（结构化精确解析）。
     * [specifiers] 记录了默认/命名空间/命名导入的分解结果；
     * 仅有模块说明符而 [specifiers] 为空表示副作用导入 `import 'mod'`。
     */
    data class ImportDecl(
        val module: String,
        override val pos: SourcePos,
        val specifiers: List<ImportSpecifier> = emptyList(),
    ) : Stmt()

    /**
     * export 语句（结构化精确解析）。
     * [decl] 承载 `export function/class/var` 等可打包声明；
     * [clause] 承载 `export {a as b}` / `export default expr` / `export ... from 'mod'`;
     * 两者至少其一非空。
     */
    data class ExportDecl(
        val decl: Stmt?,
        override val pos: SourcePos,
        val clause: ExportClause? = null,
    ) : Stmt()
}

/** 解构绑定项 */
data class DestructureBinding(val name: String, val defaultValue: Expr?, val pos: SourcePos)

/** import 说明符类别：命名导入 / 默认导入 / 命名空间导入（import * as ns） */
enum class ImportSpecifierKind { NAMED, DEFAULT, NAMESPACE }

/**
 * import 单个说明符（ 结构化精确解析）。
 * - NAMED：`import { imported as local }`，无别名时 [local] == [imported]。
 * - DEFAULT：`import local from 'm'`，[imported] 恒为 "default"。
 * - NAMESPACE：`import * as local from 'm'`，[imported] 恒为 "*"。
 */
data class ImportSpecifier(
    val local: String,
    val imported: String?,
    val kind: ImportSpecifierKind,
    val pos: SourcePos,
)

/** export 命名说明符：`export { local as exported }`（[exported] 为空表示无别名） */
data class ExportNamedSpecifier(
    val local: String,
    val exported: String? = null,
    val isDefault: Boolean = false, // { default }
    val pos: SourcePos,
)

/**
 * export 子句（ 结构化）：
 * - `export { a, b as c }`：仅 [named]；若带 `from 'm'` 则为再导出，[from] 非空。
 * - `export * from 'm'`：仅 [isAll] + [from]。
 * - `export * as ns from 'm'`：[namespaceAlias] + [from]。
 * - `export default expr`：[isDefault] = true。
 */
data class ExportClause(
    val named: List<ExportNamedSpecifier> = emptyList(),
    val from: String? = null,
    val isAll: Boolean = false,
    val namespaceAlias: String? = null,
    val isDefault: Boolean = false,
    val pos: SourcePos,
)

/** switch 的 case 分支 */
data class SwitchCase(val test: Expr?, val body: List<Stmt>, val pos: SourcePos)

/** 函数（含箭头/异步/生成器） */
data class JsFunction(
    val name: String,
    val params: List<String>,
    val body: Stmt.Block,
    val pos: SourcePos,
    val isArrow: Boolean = false,
    val isAsync: Boolean = false,
    val isGenerator: Boolean = false,
)

/** 顶层基类 */
sealed class TopLevel {
    abstract val pos: SourcePos

    /** 顶层函数声明 */
    data class Function(val fn: JsFunction, override val pos: SourcePos) : TopLevel()

    /** 顶层普通语句 */
    data class Statement(val stmt: Stmt, override val pos: SourcePos) : TopLevel()
}

/** 整个源码程序 */
data class Program(val body: List<TopLevel>, val source: String)

/** 程序辅助工具：以字符串形式渲染表达式/语句（供 CFG/DFG 输出可读标签） */
object AstRender {
    fun expr(e: Expr?): String = when (e) {
        null -> ""
        is Expr.Identifier -> e.name
        is Expr.Number -> e.value
        is Expr.StringLit -> "\"${e.value}\""
        is Expr.BoolLit -> e.value.toString()
        is Expr.NullLit -> "null"
        is Expr.UndefinedLit -> "undefined"
        is Expr.ThisRef -> "this"
        is Expr.FunctionExpr -> (e.name ?: "function") + "()"
        is Expr.Member -> when {
            e.computed != null -> "${expr(e.obj)}${if (e.optional) "?." else ""}[${expr(e.computed)}]"
            else -> "${expr(e.obj)}${if (e.optional) "?." else "."}${e.property ?: "?"}"
        }
        is Expr.Call -> "${expr(e.callee)}${if (e.optional) "?." else ""}(${e.args.joinToString(", ") { expr(it) }})"
        is Expr.Assign -> "${expr(e.target)} ${e.op} ${expr(e.value)}"
        is Expr.Binary -> "${expr(e.left)} ${e.op} ${expr(e.right)}"
        is Expr.Conditional -> "${expr(e.test)} ? ${expr(e.consequent)} : ${expr(e.alternate)}"
        is Expr.Unary -> "${e.op}${expr(e.operand)}"
        is Expr.ArrayLit -> "[${e.elements.joinToString(", ") { expr(it) }}]"
        is Expr.ObjectLit -> "{${e.props.joinToString(", ") {
            when {
                it.isSpread -> "...${expr(it.value)}"
                it.isMethod || it.isGet || it.isSet -> "${it.key}()"
                else -> "${it.key}${if (it.value != null) ":${expr(it.value)}" else ""}"
            }
        }}}"
        is Expr.TemplateLit -> "`${e.quasis.joinToString("${'$'}{…}")}`"
        is Expr.TaggedTemplate -> "${expr(e.tag)}\u0060…\u0060"
        is Expr.Spread -> "...${expr(e.arg)}"
        is Expr.New -> "new ${expr(e.callee)}(${e.args.joinToString(", ") { expr(it) }})"
        is Expr.Sequence -> e.exprs.joinToString(", ") { expr(it) }
        is Expr.AwaitExpr -> "await ${expr(e.arg)}"
        is Expr.YieldExpr -> "yield${if (e.delegate) "*" else " "}${e.arg?.let { expr(it) } ?: ""}"
    }

    fun stmt(s: Stmt?): String = when (s) {
        null -> ""
        is Stmt.VarDecl -> "${s.kind} ${s.name}${if (s.init != null) " = ${expr(s.init)}" else ""}"
        is Stmt.DestructureDecl -> "${s.kind} {${s.bindings.joinToString(", ") { it.name }}}${if (s.init != null) " = ${expr(s.init)}" else ""}"
        is Stmt.ExprStmt -> expr(s.expr)
        is Stmt.If -> "if (${expr(s.cond)})"
        is Stmt.For -> "for (...)"
        is Stmt.ForEach -> "for (${expr(s.left)} ${if (s.of) "of" else "in"} ${expr(s.obj)})"
        is Stmt.While -> "while (${expr(s.cond)})"
        is Stmt.DoWhile -> "do"
        is Stmt.Switch -> "switch (${expr(s.disc)})"
        is Stmt.Return -> if (s.arg != null) "return ${expr(s.arg)}" else "return"
        is Stmt.TryCatch -> "try/catch"
        is Stmt.ClassDecl -> "class ${s.name}${s.superClass?.let { " extends $it" } ?: ""} {${s.members.size} members}"
        is Stmt.Block -> "{...}"
        is Stmt.Break -> "break"
        is Stmt.Continue -> "continue"
        is Stmt.Throw -> "throw ${if (s.arg != null) expr(s.arg) else ""}"
        is Stmt.EmptyStmt -> ";"
        is Stmt.ImportDecl -> {
            if (s.specifiers.isEmpty()) {
                "import '${s.module}'"
            } else {
                val parts = s.specifiers.map { sp ->
                    when (sp.kind) {
                        ImportSpecifierKind.NAMED ->
                            if (sp.imported != null && sp.imported != sp.local) "import {${sp.imported} as ${sp.local}}" else "import {${sp.local}}"
                        ImportSpecifierKind.DEFAULT -> "import ${sp.local} default"
                        ImportSpecifierKind.NAMESPACE -> "import * as ${sp.local}"
                    }
                }
                "import ${parts.joinToString(", ")} from '${s.module}'"
            }
        }
        is Stmt.ExportDecl -> {
            val declPart = s.decl?.let { stmt(it) } ?: ""
            if (s.clause == null) "export $declPart"
            else {
                val c = s.clause
                when {
                    c.named.isNotEmpty() -> {
                        val n = c.named.joinToString(", ") { ns ->
                            if (ns.exported != null && ns.exported != ns.local) "${ns.local} as ${ns.exported}" else ns.local
                        }
                        "export { $n }" + (c.from?.let { " from '$it'" } ?: "")
                    }
                    c.isAll -> "export * from '${c.from ?: ""}'"
                    c.namespaceAlias != null -> "export * as ${c.namespaceAlias} from '${c.from ?: ""}'"
                    c.isDefault -> "export default $declPart"
                    else -> "export $declPart"
                }
            }
        }
    }
}
