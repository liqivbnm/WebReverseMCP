plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "com.webreverse.mcp.mcp.tools"
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
    api(project(":core:core-database"))
    api(project(":browser:browser-engine"))
    api(project(":browser:browser-tabs"))
    api(project(":browser:browser-history"))
    api(project(":browser:browser-bookmarks"))
    api(project(":devtools:devtools-network"))
    api(project(":devtools:devtools-console"))
    api(project(":devtools:devtools-dom"))
    api(project(":devtools:devtools-debugger"))
    api(project(":devtools:devtools-storage"))
    api(project(":devtools:devtools-performance"))
    api(project(":javascript:js-parser"))
    api(project(":javascript:js-analysis"))
    api(project(":javascript:js-runtime"))
    api(project(":hook:hook-engine"))
    api(project(":workspace:workspace-core"))
    implementation(libs.androidx.core.ktx)
    implementation(libs.kotlinx.coroutines.android)
    // Host Tools 安装：纯 Java 解压 tar.xz/.deb，无需系统 tar/xz 命令
    implementation(libs.commons.compress)
    implementation(libs.tukaani.xz)
    testImplementation(libs.junit)
    testImplementation(libs.truth)
    testImplementation(libs.kotlinx.coroutines.test)
}
