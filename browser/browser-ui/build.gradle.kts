plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "com.webreverse.mcp.browser.ui"
    compileSdk = 35
    defaultConfig { minSdk = 26 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    buildFeatures { compose = true }
}

dependencies {
    api(project(":core:core-common"))
    api(project(":core:core-ui"))
    api(project(":core:core-database"))
    api(project(":browser:browser-engine"))
    api(project(":browser:browser-tabs"))
    api(project(":browser:browser-history"))
    api(project(":browser:browser-bookmarks"))
    api(platform(libs.compose.bom))
    api(libs.compose.material3)
    api(libs.compose.material.icons.extended)
    implementation(libs.kotlinx.coroutines.android)
    testImplementation(libs.junit)
}
