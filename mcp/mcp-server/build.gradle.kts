plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "com.webreverse.mcp.mcp.server"
    compileSdk = 35
    defaultConfig { minSdk = 26 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    api(project(":core:core-common"))
    api(project(":core:core-mcp"))
    api(project(":core:core-security"))
    api(project(":core:core-logging"))
    api(project(":devtools:devtools-protocol"))
    api(project(":mcp:mcp-tools"))
    api(project(":mcp:mcp-resources"))
    api(project(":mcp:mcp-prompts"))
    api(libs.ktor.server.core)
    // DevTools 代理改用 CIO 引擎：Ktor 3.0.x Netty 的 WebSocket 存在已知稳定性问题
    // （帧处理/连接断开），CIO 为纯协程实现，WS 收发稳定且体积更小。
    // Netty 保留给 MCP 主服务（其 WebSocket 场景少，问题未复现）。
    api(libs.ktor.server.cio)
    api(libs.ktor.server.netty)
    api(libs.ktor.server.websockets)
    api(libs.ktor.server.content.negotiation)
    api(libs.ktor.server.call.logging)
    api(libs.ktor.server.cors)
    api(libs.ktor.server.status.pages)
    api(libs.ktor.serialization.kotlinx.json)
    implementation(libs.kotlinx.coroutines.android)
    testImplementation(libs.junit)
    testImplementation(libs.truth)
    testImplementation(libs.kotlinx.coroutines.test)
}
