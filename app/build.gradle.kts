plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "com.webreverse.mcp"
    compileSdk = 35
    // 构建机只安装 build-tools 35.0.0，显式声明以避免 AGP 默认(34.0.0)
    // 触发 sdkmanager 自动补装（构建机无 cmdline-tools 时会失败）
    buildToolsVersion = "35.0.0"

    defaultConfig {
        applicationId = "com.webreverse.mcp"
        minSdk = 26
        // targetSdk=28：运行在兼容模式，Android 不强制 W^X 限制，
        // 允许从应用私有目录直接执行二进制（Host Tools 的 git/python 等）
        targetSdk = 28
        versionCode = 1
        versionName = "1.0.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables { useSupportLibrary = true }
    }

    signingConfigs {
        create("release") {
            val ksFile = rootProject.file("keystore/release.keystore")
            // 密钥密码不再硬编码于源码。优先环境变量（CI/构建机注入），
            // 其次回退 gradle.properties（本地不提交的私有配置）。
            val props = project.properties
            val storePw = providers.environmentVariable("WRMCP_STORE_PASSWORD")
                .getOrElse(props["wrmcp.storePassword"]?.toString() ?: "")
            val keyPw = providers.environmentVariable("WRMCP_KEY_PASSWORD")
                .getOrElse(props["wrmcp.keyPassword"]?.toString() ?: "")
            val alias = providers.environmentVariable("WRMCP_KEY_ALIAS")
                .getOrElse(props["wrmcp.keyAlias"]?.toString() ?: "webreverse")
            if (ksFile.exists() && storePw.isNotBlank() && keyPw.isNotBlank()) {
                storeFile = ksFile
                storePassword = storePw
                keyAlias = alias
                keyPassword = keyPw
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            // 有密钥且密码齐全则用正式签名，否则回退 debug 签名保证可构建
            // 修复：原判定只看 keystore 文件是否存在——密码缺失时
            // signingConfigs.release 的 storeFile 从未赋值，packageRelease
            // 直接抛 "SigningConfig release is missing storeFile" 构建失败，
            // 注释承诺的 debug 回退从未生效。现改为校验配置完整后才启用。
            val releaseCfg = signingConfigs.getByName("release")
            signingConfig = if (releaseCfg.storeFile?.exists() == true) {
                releaseCfg
            } else {
                signingConfigs.getByName("debug")
            }
        }
        debug {
            isMinifyEnabled = false
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
            excludes += "/META-INF/INDEX.LIST"
            excludes += "/META-INF/io.netty.versions.properties"
        }
    }

    // 内存受限环境：跳过 release 构建 lint 检查
    lint {
        checkReleaseBuilds = false
        abortOnError = false
    }
}

dependencies {
    implementation(project(":core:core-common"))
    implementation(project(":core:core-logging"))
    implementation(project(":core:core-security"))
    implementation(project(":core:core-network"))
    implementation(project(":core:core-database"))
    implementation(project(":core:core-ui"))
    implementation(project(":core:core-mcp"))

    implementation(project(":browser:browser-engine"))
    implementation(project(":browser:browser-tabs"))
    implementation(project(":browser:browser-history"))
    implementation(project(":browser:browser-bookmarks"))
    implementation(project(":browser:browser-ui"))

    implementation(project(":devtools:devtools-protocol"))
    implementation(project(":devtools:devtools-network"))
    implementation(project(":devtools:devtools-console"))
    implementation(project(":devtools:devtools-dom"))
    implementation(project(":devtools:devtools-debugger"))
    implementation(project(":devtools:devtools-storage"))
    implementation(project(":devtools:devtools-performance"))

    implementation(project(":javascript:js-parser"))
    implementation(project(":javascript:js-analysis"))
    implementation(project(":javascript:js-runtime"))

    implementation(project(":hook:hook-engine"))

    implementation(project(":mcp:mcp-server"))
    implementation(project(":mcp:mcp-tools"))
    implementation(project(":mcp:mcp-resources"))
    implementation(project(":mcp:mcp-prompts"))

    implementation(project(":workspace:workspace-core"))
    implementation(project(":workspace:workspace-ui"))

    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.graphics)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.compose.material3)
    implementation(libs.compose.material.icons.extended)
    implementation(libs.compose.foundation)
    implementation(libs.compose.animation)
    implementation(libs.navigation.compose)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.core.ktx)
    implementation(libs.webkit)
    implementation(libs.work.runtime.ktx)
    implementation(libs.paging.runtime.ktx)
    implementation(libs.paging.compose)
    implementation(libs.coil.compose)
    implementation(libs.timber)

    debugImplementation(libs.leakcanary.android)
    debugImplementation(libs.compose.ui.tooling)

    testImplementation(libs.junit)
    testImplementation(libs.truth)
    testImplementation(libs.kotlinx.coroutines.test)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}
