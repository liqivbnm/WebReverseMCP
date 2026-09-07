# WebReverse MCP

> AI 驱动的网页调试与逆向分析工作台 —— 让 Claude、GPT、Gemini、Cursor 等 AI Agent 通过 MCP 连接 Android 浏览器

WebReverse MCP 是一个基于 Android 的专业浏览器、网页分析器、JavaScript 调试器、网络分析器和 MCP Server 平台。外部 AI Agent / LLM / IDE Agent 通过 MCP（Model Context Protocol）连接 Android 浏览器，对当前网页执行自动化浏览、DOM 分析、JavaScript 分析、网络分析、调试、断点、运行时观测、Hook、脚本注入等操作。

---

## 目录

- [核心特性](#核心特性)
- [技术栈](#技术栈)
- [架构设计](#架构设计)
- [模块结构](#模块结构)
- [MCP 协议](#mcp-协议)
- [快速开始](#快速开始)
- [AI Agent 连接指南](#ai-agent-连接指南)
- [安全模型](#安全模型)
- [终端与 Host Tools](#终端与-host-tools)
- [开源许可](#开源许可)

---

## 核心特性

### 浏览器模式

- 地址栏、URL 搜索、多标签、标签组
- 页面前进 / 后退 / 刷新 / 停止 / 首页 / 全屏
- Cookie / LocalStorage / SessionStorage / IndexedDB / Cache 管理
- 历史记录、收藏夹、最近关闭
- 页面源码查看

### AI 调试与网络分析（MCP Tools，CDP 直连）

调试与网络能力全部经 MCP Tools 暴露给 AI，由 CDP 复用枢纽承载：同一页面只保持一条后端 CDP 连接，进程内多个 MCP 会话（调试器 / 网络监视器 / 脚本工具）共享接入，断点、暂停与网络事件在会话间广播。CDP 不可用时自动降级为注入式实现（evaluateJavascript + Hook）。

| 能力域 | 覆盖（工具前缀） |
|--------|------|
| DOM | DOM Tree、属性、Computed Style、Box Model、Shadow DOM、XPath、CSS Selector（`dom.*`） |
| Console | evaluate JS（同步/异步）、inspect object、console.log/warn/error/table/dir 捕获（`console.*` / `js.evaluate`） |
| Sources | JS/CSS/HTML/JSON 源码、Pretty Print、SourceMap 还原、Global Search、Diff（`js.*` / `page.*`） |
| Network | HTTP/HTTPS/Fetch/XHR/WebSocket/EventSource 采集、Headers/Cookies/Body/Timing、HAR 导出、Copy as cURL、请求重放/Mock/UA 伪装（`network.*`） |
| Storage | Cookies / LocalStorage / SessionStorage / IndexedDB / Cache Storage / Service Worker（`storage.*`） |
| Debugger | 断点（Line/Function/DOM/Event/XHR/Exception/Logpoint）、单步、调用栈、作用域、局部变量、CPU Profile（`debugger.*`） |
| Performance | Navigation Timing、First Paint / FCP、资源瀑布图、内存快照（`page.performance`） |
| Security | HTTPS/CSP 检查、框架检测、敏感数据脱敏审计（`re.*`） |
| 暂停放行 | 断点命中页面暂停时，浏览器内悬浮"调试器已暂停"提示条一键放行，无需任何调试前端即可恢复执行 |

### JavaScript 分析系统

- AST 解析：基于 ESTree 规范的解析器（JsParser），支持函数 / 字符串 / 标识符 / 调用表达式搜索
- 混淆检测（Obfuscation Score 0-100）：字符串数组编码、控制流平坦化、变量重命名、不可达代码、eval / new Function / setTimeout 动态代码检测、反调试检测
- API Discovery：自动从 HTML/JS/Network 提取 API Endpoint、Method、Headers、Caller
- 框架检测：React / Vue / Angular / Svelte / Next.js / Nuxt / Vite / Webpack / jQuery / Axios / Redux 等
- SourceMap 解析：还原压缩代码到原始源码

### Hook 引擎

- 网络 Hook：URL/Host/Path/Method/Header/Body/Regex 匹配 + Log/Modify/Block/Redirect/Delay/Mock 动作
- Runtime Hook：`hookFunction()` / `hookMethod()` / `hookProperty()` / `hookFetch()` / `hookXHR()` / `hookWebSocket()` / `hookStorage()`
- 生命周期：install / enable / disable / remove / reset / export / import
- 内置类型：Function / Method / Property / Event / Fetch / XHR / WebSocket / Storage / Cookie / Console / Timer / Crypto / Canvas / Clipboard / History / Location

### MCP Server

- 传输方式：Streamable HTTP（`POST /mcp`）
- 协议：JSON-RPC 2.0，兼容 MCP 2025-03-26 规范
- 461 个原始 Tools / 40 个聚合枢纽（开启聚合模式时客户端仅暴露 40 个枢纽，每个含多个 action；全量模式暴露全部原始工具）
- 12 Resources + 2 资源模板：`browser://current-page`、`browser://dom`、`browser://network`、`browser://page/{tabId}` 等
- 13 Prompts：`analyze_page`、`analyze_login_flow`、`trace_function`、`evidence_workflow`（证据驱动工作流）等

### 统一逆向分析内核

- Unified TraceEvent：Hook / Runtime / Network / WASM / Storage / Timer 统一事件模型，支持增量游标、值指纹和异步谱系
- SSA + CallGraph + Taint：从过程内顺序传播升级为 SSA Def-Use、跨函数参数/返回传播与 Source → Transform → Sink 路径分析
- WASM Provenance：静态扫描 memory load/store、函数读写区间、指针型导出与 wasm-bindgen 宿主边界
- JSVMP Micro-IR：将 VM Handler 归一为 Micro-IR，建立跨脚本语义签名库，支持基于样本的算子差分推断
- Validation Loop：候选公式与浏览器真实样本闭环验证，区分"候选 / 全命中 / 已验证"
- Adaptive Investigation：目标驱动的逆向规划器，根据证据与阻塞反馈动态选择静态、动态、Hook、WASM、JSVMP、验证路径

### 证据图谱引擎

- Evidence Store：订阅 EventBus 自动沉淀证据——网络请求 / Hook 命中 / 断点命中 / 控制台异常 / 页面加载全程留痕
- Reverse Graph：端点 / 函数 / 脚本 / 令牌 / 加密操作 / 存储键自动建图，关系含 CALLS / REQUESTS / GENERATES / WRITES / SIGNS 等
- 时间窗关联：加密 Hook 命中与 ±3s 内的网络请求自动建立 SIGNS 边
- Analysis Pipeline：5 条端到端流水线（recon / api_trace / token_trace / crypto_link / snapshot）
- Runtime Snapshot：断点命中现场（调用栈 / 局部变量 / 命中断点）一键沉淀为可查询证据

---

## 技术栈

| 类别 | 技术 |
|------|------|
| 语言 | Kotlin 2.0+ |
| UI | Jetpack Compose + Material 3 |
| 架构 | Clean Architecture + Multi-module |
| 异步 | Coroutines + Flow / StateFlow / SharedFlow |
| 导航 | Navigation Compose（自研响应式路由） |
| 持久化 | Room + DataStore |
| 网络 | OkHttp + Kotlin Serialization |
| 浏览器内核 | Android WebView / androidx.webkit |
| 调试协议 | Chromium DevTools Protocol（unix socket 直连 + 进程内复用枢纽，注入式降级） |
| MCP Server | Ktor（Netty） |
| DI | 手动 DI 容器（AppContainer） |
| 日志 | Timber + 自研分类日志（9 类） |
| 最低支持 | Android 8.0（API 26） |

---

## 架构设计

```
┌─────────────────────────────────────────────────────────────┐
│                        AI Agent                             │
│         Claude / GPT / Gemini / Cursor / IDE Agent          │
└──────────────────────┬──────────────────────────────────────┘
                       │  Wi-Fi / LAN  (JSON-RPC 2.0)
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                    MCP Server (Ktor)                        │
│                Streamable HTTP  POST /mcp                   │
│  ┌──────────────────────────────────────────────────────┐  │
│  │    ToolRegistry (461 raw + 40 hubs)                │  │
│  │  Browser│Tab│DOM│JS│Debugger│Network│Hook│Storage   │  │
│  │  Page│ReverseEngineering│Frame│Worker│Performance   │  │
│  │  Event│Workspace│MCP│System│File System            │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────┐  ┌───────────────┐  ┌────────────────┐  │
│  │ 12 Resources │  │ 13 Prompts    │  │ Auth + Session │  │
│  └──────────────┘  └───────────────┘  └────────────────┘  │
└──────────────────────┬──────────────────────────────────────┘
                       │  ToolDependencies（依赖注入）
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                      领域服务层                              │
│  ┌────────────┐ ┌─────────────┐ ┌────────────────────────┐ │
│  │ Browser    │ │ DevTools    │ │ JavaScript 分析        │ │
│  │ Service    │ │ Inspector   │ │ Parser/Obfuscation/API │ │
│  │ (多 Tab)   │ │ Console     │ │ Discovery/Framework    │ │
│  │            │ │ Debugger    │ │ Workspace              │ │
│  │ Hook       │ │ Network     │ │ Manager                │ │
│  │ Engine     │ │ Storage     │ │ (项目管理)             │ │
│  └────────────┘ │ Performance │ └────────────────────────┘ │
│                 └─────────────┘                             │
└──────────────────────┬──────────────────────────────────────┘
                       │  EventBus（解耦通信）
                       ▼
┌─────────────────────────────────────────────────────────────┐
│              BrowserEngine (WebView 封装)                    │
│   JsBridge (console/network/hook 注入) + NetworkBridge      │
└─────────────────────────────────────────────────────────────┘
```

### 数据流向（Clean Architecture）

```
MCP Tool → UseCase → BrowserService → BrowserEngine → WebView
    ↓                                    ↓
EventBus ←—————— Hook/Console/Network 事件 ——————→ JsBridge
    ↓
Room 持久化 + UI StateFlow 更新
```

---

## 模块结构

```
WebReverseMCP/
├── app/                        # 应用入口 + Compose UI + DI 容器
├── core/
│   ├── core-common/            # 事件总线、领域模型、权限模型、工具类
│   ├── core-logging/           # 统一日志（9 分类 + 环形缓冲）
│   ├── core-security/          # TokenManager + PermissionManager
│   ├── core-network/           # OkHttp 封装、HAR 导出
│   ├── core-database/          # Room（17 张表）+ Repository
│   ├── core-ui/                # 共享 Compose 组件
│   └── core-mcp/               # MCP 协议核心（McpTool/ToolRegistry/JSON-RPC）
├── browser/
│   ├── browser-engine/         # WebView 封装、JsBridge、NetworkBridge
│   ├── browser-tabs/           # TabManager（多标签 + 标签组）
│   ├── browser-history/        # 历史记录
│   ├── browser-bookmarks/      # 收藏夹
│   └── browser-ui/             # 浏览器 UI 组件
├── devtools/
│   ├── devtools-protocol/      # CDP 传输与协议（LocalSocket/TcpWebSocket/CdpHub）
│   ├── devtools-dom/           # DOM Inspector
│   ├── devtools-console/       # Console Manager
│   ├── devtools-debugger/      # Debugger Manager（断点/调用栈）
│   ├── devtools-network/       # Network Inspector（HAR）
│   ├── devtools-storage/       # Storage Inspector
│   └── devtools-performance/   # Performance Analyzer
├── javascript/
│   ├── js-parser/              # JsParser（ESTree AST）
│   ├── js-analysis/            # 混淆检测/API 发现/框架检测/SourceMap/Diff
│   └── js-runtime/             # JsRuntimeHook（运行时 Hook）
├── hook/
│   └── hook-engine/            # HookEngine（规则生命周期）
├── mcp/
│   ├── mcp-server/             # Ktor Server + McpServerManager + 认证守卫
│   ├── mcp-tools/              # 461 Tools（40 命名空间枢纽，含 File System 文件系统）
│   ├── mcp-resources/          # 12 个 browser:// 资源
│   └── mcp-prompts/            # 13 个内置 Prompt
├── workspace/
│   ├── workspace-core/         # WorkspaceManager
│   └── workspace-ui/           # 工作区 UI
```

---

## MCP 协议

### Tool 调用示例

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "js.evaluate",
    "arguments": {
      "expression": "document.title"
    }
  }
}
```

### 核心 Tool 分类

| 分类 | 示例 |
|------|------|
| Browser | `browser.open` `browser.reload` `browser.screenshot` `browser.current_url` |
| Tab | `tab.list` `tab.create` `tab.close` `tab.group` |
| DOM | `dom.query` `dom.get_html` `dom.click` `dom.get_xpath` `dom.set_attribute` |
| JavaScript | `js.evaluate` `js.parse_ast` `js.beautify` `js.detect_obfuscation` `js.extract_strings` |
| Debugger | `debugger.set_breakpoint` `debugger.pause` `debugger.call_stack` `debugger.locals` |
| Network | `network.list` `network.export_har` `network.copy_curl` `network.replay` `network.mock` |
| Hook | `hook.create` `hook.fetch` `hook.websocket` `hook.function` `hook.export` |
| Storage | `storage.cookies` `storage.local` `storage.indexeddb` `storage.clear` |
| Page | `page.inspect` `page.framework_detect` `page.api_list` `page.performance` |
| Reverse Engineering | `re.find_api` `re.find_token` `re.detect_obfuscator` `re.trace_function` `re.generate_report` |
| File System | `file.read` `file.write` `file.search` `file.list` `file.open` `file.share` `file.hash` `file.zip` `file.unzip` |

#### File System 工具

逆向工作流闭环的关键补充：AI 下载 JS/HAR 后可离线阅读与检索（`file.read` / `file.search`），逆向成果可直接落盘为脚本文件（`file.write` / `file.append`），并可通过 `file.open` / `file.share` 把产物交给设备上的其他应用或用户。

| 工具 | 说明 |
|------|------|
| `file.workdir` / `file.set_workdir` | 查看 / 切换工作目录 |
| `file.read` | 读取文件（文本按行分页 offset/limit，超长行按列分段，minified 单行大文件必备；二进制按字节偏移 base64 分页；响应带续读游标） |
| `file.write` / `file.append` | 创建覆盖 / 追加写入（文本或 base64） |
| `file.list` / `file.tree` | 列目录（通配符过滤、递归）/ 树形结构 |
| `file.stat` / `file.exists` | 元信息 / 存在性检查 |
| `file.mkdir` / `file.delete` | 建目录 / 删文件（删除为高风险） |
| `file.copy` / `file.move` | 复制（递归）/ 移动重命名 |
| `file.search` | 本地 grep：文本/正则、目录递归、超长压缩行自动截取匹配点上下文窗口 |
| `file.open` / `file.share` | 唤起系统应用打开 / 系统分享面板 |
| `file.hash` | MD5 / SHA-1 / SHA-256 流式哈希 |
| `file.zip` / `file.unzip` | 打包 / 解压（内置 Zip Slip 防护） |

路径规则：相对路径基于工作目录（`/storage/emulated/0/Download/WebReverseMCP`），绝对路径直接使用；`/proc` `/sys` `/dev` `/system` 等系统目录拒绝访问。`browser.download` 额外支持 `data:` URI 直接落盘。

### Resources

```
browser://current-page    browser://dom          browser://console
browser://network         browser://cookies      browser://local-storage
browser://sources         browser://tabs         browser://debugger
browser://performance     browser://hooks        browser://workspace
browser://page/{tabId}    browser://network/{tabId}
```

### Prompts

```
analyze_page · analyze_javascript · analyze_network · analyze_login_flow
analyze_api · analyze_obfuscation · find_function
trace_function · trace_request · debug_javascript · inspect_dom
analyze_storage · generate_reverse_engineering_report
```

---

## 快速开始

### 环境要求

- Android Studio Ladybug+
- JDK 17
- Android SDK 35

### 构建

```bash
# 克隆项目
git clone <repo-url>
cd WebReverseMCP

# 构建 Debug APK
./gradlew :app:assembleDebug

# 构建 Release APK（未配置签名时自动回退 debug 签名）
./gradlew :app:assembleRelease
```

### 运行

1. 在 Android 设备上安装 APK
2. 确保 Android 与 AI Agent 处于同一局域网
3. 打开 App → MCP Server 页面 → 启动 Server
4. 在 AI Agent 侧配置 MCP 连接

---

## AI Agent 连接指南

### Claude Desktop / Cursor 配置

```json
{
  "mcpServers": {
    "webreverse": {
      "url": "http://<Android-IP>:8787/mcp",
      "headers": {
        "Authorization": "Bearer <Your-Token>"
      }
    }
  }
}
```

### MCP HTTP 连接

MCP 对外仅提供 Streamable HTTP：

```text
http://<Android-IP>:8787/mcp
```

客户端通过 `POST /mcp` 发送 MCP JSON-RPC 请求；服务器不提供其他 MCP Transport。

---

## 安全模型

- 22 个权限作用域（READ_PAGE / EXECUTE_JS / READ_NETWORK / MODIFY_NETWORK / INSTALL_HOOK / READ_FILE / WRITE_FILE 等）
- 4 档授权范围：一次 / 当前网站 / 当前 Tab / 永久
- 敏感数据默认脱敏：`[REDACTED_COOKIE]` / `[REDACTED_TOKEN]` / `[REDACTED_SECRET]`
- 认证：API Token（Authorization Bearer / X-MCP-Token 请求头）+ IP Allowlist + 仅局域网模式；绑定非回环地址时强制要求 Token

---

## 终端与 Host Tools

App 内置终端能力，可为 AI Agent 提供 `terminal.exec` / `run_python` / `run_node` 等工具。其中 Git、Python、Perl 等运行时工具（Host Tools）通过 **Termux 官方软件源**（含中科大、南京大学镜像）在运行时下载预编译 `.deb` 包，解压到应用私有目录后以独立子进程方式执行。

关于 Termux 开源协议的合规说明：

- 本项目**不包含、不复制、不修改** termux-app 与 termux-packages 的任何源代码，所有代码均为自研 Kotlin 实现，因此不构成 GPL-3.0 的衍生作品。
- 应用 APK **不内置** 任何 Termux 二进制文件，仅充当包下载客户端（与 `apt` / `pkg` 的工作方式相同），不构成对软件包的再分发。
- 各软件包保留其上游原始许可证（如 git 为 GPL-2.0、python 为 PSF、perl 为 Artistic/GPL），`.deb` 包内自带的许可证文件在解压时被完整保留。
- 若设备已安装 Termux，应用会以只读方式扫描其可执行文件目录作为命令解析来源之一，不会修改 Termux 的任何文件。

完整第三方组件清单见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

**商标声明**：Termux 是 Termux 团队的商标。本项目与 Termux 团队无任何隶属、赞助或背书关系。

---

## 开源许可

本项目代码遵循 [MIT License](LICENSE) 发布。

第三方组件及其许可情况见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

### 免责声明
本工具仅用于学习研究，请仅对自己拥有或已获得合法授权的网站进行分析。
使用本工具产生的一切法律责任由使用者自行承担。