pluginManagement {
    repositories {
        maven {
            setUrl("https://maven.aliyun.com/repository/public")
        }
        maven {
            setUrl("https://maven.aliyun.com/repository/google")
        }
        maven {
            setUrl("https://maven.aliyun.com/repository/jcenter")
        }
        maven {
            setUrl("https://maven.aliyun.com/nexus/content/repositories/releases")
        }
        maven {
            setUrl("https://jitpack.io")
        }
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        maven {
            setUrl("https://maven.aliyun.com/repository/public")
        }
        maven {
            setUrl("https://maven.aliyun.com/repository/google")
        }
        maven {
            setUrl("https://maven.aliyun.com/repository/jcenter")
        }
        maven {
            setUrl("https://maven.aliyun.com/nexus/content/repositories/releases")
        }

        google()
        mavenCentral()
        maven { url = uri("https://jitpack.io") }
    }
}

rootProject.name = "WebReverseMCP"

include(":app")

// core
include(":core:core-common")
include(":core:core-logging")
include(":core:core-security")
include(":core:core-network")
include(":core:core-database")
include(":core:core-ui")
include(":core:core-mcp")

// browser
include(":browser:browser-engine")
include(":browser:browser-tabs")
include(":browser:browser-history")
include(":browser:browser-bookmarks")
include(":browser:browser-ui")

// devtools
include(":devtools:devtools-protocol")
include(":devtools:devtools-network")
include(":devtools:devtools-console")
include(":devtools:devtools-dom")
include(":devtools:devtools-debugger")
include(":devtools:devtools-storage")
include(":devtools:devtools-performance")

// javascript
include(":javascript:js-parser")
include(":javascript:js-analysis")
include(":javascript:js-runtime")

// hook
include(":hook:hook-engine")

// mcp
include(":mcp:mcp-server")
include(":mcp:mcp-tools")
include(":mcp:mcp-resources")
include(":mcp:mcp-prompts")

// workspace
include(":workspace:workspace-core")
include(":workspace:workspace-ui")
