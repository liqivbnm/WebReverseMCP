# 第三方组件声明

本项目的自研代码遵循项目根目录 `LICENSE` 中规定的 MIT License。

除自研代码外，本项目还使用或引用了以下第三方组件。各第三方组件均按照其各自适用的开源许可证使用。

## Termux 软件包

### 运行时下载，非 APK 随包分发

本项目支持在运行时从 Termux 软件源获取部分命令行工具及运行时软件包，例如 `git`、`perl`、`python`、`python-pip` 等。

软件包来源包括 Termux 官方软件源及其镜像，例如：

- `https://packages.termux.dev`
- 中科大等公开镜像
- 南京大学等公开镜像

相关 `.deb` 软件包由应用在运行时下载，并解压至应用私有目录后作为独立进程运行。

这些软件包并未预置或打包进本项目的 APK；本项目仅提供相应的软件包下载、解压及运行机制，其工作方式类似于包管理器动态获取软件包。

### 许可证

运行时获取的每个软件包均遵循其自身上游项目所适用的许可证。例如：

- Git：GPL-2.0-or-later
- Python：Python Software Foundation License
- Perl：Artistic License / GPL

具体软件包的版权及许可证信息以对应 `.deb` 软件包中包含的许可证文件为准，例如：

`usr/share/doc/*/copyright`

在软件包解压过程中，上述许可证及版权文件会随软件包一并保留，以便用户查阅。

本项目不会因运行时获取某个软件包而改变该软件包自身的许可证。

### Termux 项目

本项目不包含、不复制或修改 Termux App 或 Termux 构建系统的源代码。

本项目所使用的 Termux 软件包通过软件源在运行时获取；相关软件包仍按照各自上游项目适用的许可证进行分发和使用。

Termux 及其相关项目的名称、标识和商标归其相应权利人所有。

**本项目与 Termux 项目及 Termux 团队不存在隶属、授权、赞助或官方背书关系。**

## WABT（WebAssembly Binary Toolkit）

本项目使用 WABT（WebAssembly Binary Toolkit）的相关文件：

- `browser/browser-engine/src/main/assets/wabt/wabt.js`
- `browser/browser-engine/src/main/assets/wabt/wabt.html`

来源：

`https://github.com/WebAssembly/wabt`

WABT 项目采用 Apache License 2.0。

相关文件按照 WABT 及其所包含组件适用的许可证使用。若对应发行文件包含额外的版权声明或许可证文件，则应同时遵循相关声明。

## Android 及其他第三方依赖

本项目使用的 Android 第三方依赖库包括但不限于：

- Android Jetpack
- Kotlin
- OkHttp
- Ktor
- Room
- 以及项目 Gradle 配置中声明的其他第三方依赖

上述依赖均遵循其各自上游项目适用的开源许可证。

具体许可证及版权信息以对应依赖项目的 LICENSE、NOTICE、版权声明及 Maven 发布信息为准。

如相关依赖提供单独的 LICENSE 或 NOTICE 文件，本项目应在发布版本中保留相应文件或按照其许可证要求提供相应声明。

## 商标声明

本声明中出现的 Termux、Git、Python、Perl、WABT、Android、Kotlin、OkHttp、Ktor、Room 等名称及商标均归其各自权利人所有。

除本项目明确声明外，本项目与上述项目、组织或企业不存在官方隶属、授权、赞助或背书关系。
