package com.webreverse.mcp.javascript.analysis

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.jsonObject

/** 框架检测结果 */
@Serializable
data class FrameworkDetection(
    val frameworks: List<String> = emptyList(),
    val bundlers: List<String> = emptyList(),
    val obfuscators: List<String> = emptyList(),
    val architecture: List<String> = emptyList(),
    val confidence: Map<String, Double> = emptyMap(),
)

/** 框架检测器 */
class FrameworkDetector {

    fun detectFromJs(source: String): FrameworkDetection {
        val frameworks = mutableListOf<String>()
        val bundlers = mutableListOf<String>()
        val obfuscators = mutableListOf<String>()
        val architecture = mutableListOf<String>()
        val confidence = mutableMapOf<String, Double>()

        // 框架
        if (source.contains("__REACT_DEVTOOLS_GLOBAL_HOOK__") || source.contains("React.createElement") || source.contains("react-dom")) {
            frameworks.add("React"); confidence["React"] = 0.9
        }
        if (source.contains("createApp") && source.contains("vue") || source.contains("Vue.use") || source.contains("vue-router")) {
            frameworks.add("Vue"); confidence["Vue"] = 0.9
        }
        if (source.contains("@angular") || source.contains("ngZone") || source.contains("angular/core")) {
            frameworks.add("Angular"); confidence["Angular"] = 0.9
        }
        if (source.contains("svelte") || source.contains("__SVELTE__")) {
            frameworks.add("Svelte"); confidence["Svelte"] = 0.8
        }
        if (source.contains("jQuery") || source.contains("jquery") || source.contains("$.fn")) {
            frameworks.add("jQuery"); confidence["jQuery"] = 0.9
        }
        if (source.contains("lodash") || source.contains("_.debounce") || source.contains("_.throttle")) {
            frameworks.add("Lodash"); confidence["Lodash"] = 0.8
        }
        if (source.contains("axios") || source.contains("axios/")) {
            frameworks.add("Axios"); confidence["Axios"] = 0.9
        }
        if (source.contains("react-query") || source.contains("useQuery") || source.contains("ReactQuery")) {
            frameworks.add("React Query"); confidence["React Query"] = 0.8
        }
        if (source.contains("redux") || source.contains("createStore") || source.contains("redux-thunk")) {
            frameworks.add("Redux"); confidence["Redux"] = 0.8
        }
        if (source.contains("pinia") || source.contains("defineStore")) {
            frameworks.add("Pinia"); confidence["Pinia"] = 0.8
        }
        if (source.contains("zustand") || source.contains("createStore") && source.contains("zustand")) {
            frameworks.add("Zustand"); confidence["Zustand"] = 0.7
        }

        // 构建工具
        if (source.contains("webpackJsonp") || source.contains("__webpack_require__") || source.contains("webpack")) {
            bundlers.add("Webpack"); confidence["Webpack"] = 0.9
        }
        if (source.contains("vite") || source.contains("import.meta.hot") || source.contains("/@vite/")) {
            bundlers.add("Vite"); confidence["Vite"] = 0.8
        }
        if (source.contains("rollup") || source.contains("System.register") || source.contains("__esModule")) {
            bundlers.add("Rollup"); confidence["Rollup"] = 0.6
        }
        if (source.contains("parcel") || source.contains("parcelRequire")) {
            bundlers.add("Parcel"); confidence["Parcel"] = 0.7
        }
        if (source.contains("next") && source.contains("__NEXT_DATA__")) {
            bundlers.add("Next.js"); confidence["Next.js"] = 0.9
        }
        if (source.contains("nuxt") || source.contains("__NUXT__")) {
            bundlers.add("Nuxt"); confidence["Nuxt"] = 0.9
        }

        // 混淆器
        if (source.contains("javascript-obfuscator") || source.contains("_0x") && source.contains("while(true)")) {
            obfuscators.add("javascript-obfuscator"); confidence["javascript-obfuscator"] = 0.8
        }
        if (source.contains("obfuscator.io")) {
            obfuscators.add("obfuscator.io"); confidence["obfuscator.io"] = 0.9
        }
        if (source.contains("webpack-obfuscator")) {
            obfuscators.add("webpack-obfuscator"); confidence["webpack-obfuscator"] = 0.8
        }

        // 架构
        if (source.contains("__NEXT_DATA__") || source.contains("window.__NUXT__")) {
            architecture.add("SSR")
        }
        if (source.contains("createRoot") || source.contains("createApp") || source.contains("new Vue")) {
            architecture.add("CSR")
        }
        if (source.contains("serviceWorker") || source.contains("navigator.serviceWorker")) {
            architecture.add("PWA")
        }
        if (source.contains("shadowRoot") || source.contains("attachShadow")) {
            architecture.add("Web Components")
            architecture.add("Shadow DOM")
        }

        return FrameworkDetection(
            frameworks = frameworks.distinct(),
            bundlers = bundlers.distinct(),
            obfuscators = obfuscators.distinct(),
            architecture = architecture.distinct(),
            confidence = confidence,
        )
    }

    fun detectFromRuntime(runtimeJson: String): FrameworkDetection {
        val detection = FrameworkDetection()
        if (runtimeJson.isBlank()) return detection
        val frameworks = mutableListOf<String>()
        val architecture = mutableListOf<String>()
        try {
            val obj = kotlinx.serialization.json.Json.parseToJsonElement(runtimeJson).jsonObject
            if (obj["react"]?.toString() == "true") frameworks.add("React")
            if (obj["vue"]?.toString() == "true") frameworks.add("Vue")
            if (obj["angular"]?.toString() == "true") frameworks.add("Angular")
            if (obj["svelte"]?.toString() == "true") frameworks.add("Svelte")
            if (obj["jquery"]?.toString() == "true") frameworks.add("jQuery")
            if (obj["next"]?.toString() == "true") { frameworks.add("Next.js"); architecture.add("SSR") }
            if (obj["nuxt"]?.toString() == "true") { frameworks.add("Nuxt"); architecture.add("SSR") }
            if (obj["webpack"]?.toString() == "true") architecture.add("Webpack")
            if (obj["vite"]?.toString() == "true") architecture.add("Vite")
            if (obj["pwa"]?.toString() == "true") architecture.add("PWA")
            if (obj["spa"]?.toString() == "true") architecture.add("SPA")
            if (obj["shadowDom"]?.toString() == "true") architecture.add("Shadow DOM")
        } catch (e: Exception) {
            // ignore
        }
        return detection.copy(
            frameworks = frameworks.distinct(),
            architecture = architecture.distinct(),
        )
    }
}
