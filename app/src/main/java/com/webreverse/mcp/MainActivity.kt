package com.webreverse.mcp

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.os.PowerManager
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.core.content.ContextCompat
import com.webreverse.mcp.core.common.util.WorkDir
import com.webreverse.mcp.keepalive.KeepAliveService
import com.webreverse.mcp.ui.navigation.WebReverseAppRoot
import com.webreverse.mcp.ui.theme.ThemeMode
import com.webreverse.mcp.ui.theme.WebReverseTheme

class MainActivity : ComponentActivity() {

    /** 权限引导队列：每完成一项（系统设置页/运行时弹窗返回）自动发起下一项 */
    private val permissionSteps = ArrayDeque<() -> Unit>()
    private val settingsLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
            onPermissionStepDone()
        }
    private val runtimePermissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
            onPermissionStepDone()
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)

        // 底部导航栏沉浸：关闭系统对比度强制遮罩。
        // API 29+ 系统会在透明导航栏上自动叠加一层半透明遮罩（浅色主题近白色），
        // 即使应用栏背景已延伸到底部也会被淡化成"白色长条"；关闭后
        // 由应用自己的栏背景直接绘制到手势区后面（与状态栏沉浸同构）
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            window.isStatusBarContrastEnforced = false
            window.isNavigationBarContrastEnforced = false
        }

        val container = (application as WebReverseApp).container

        // 工作目录初始化（所有产出文件的统一存放位置）
        WorkDir.init(this)

        // 保活：开关开启则拉起服务（常驻通知 + 悬浮球）
        if (KeepAliveService.isKeepAliveEnabled(this)) {
            KeepAliveService.start(this)
        }

        // 首次启动：引导申请保活相关权限（悬浮窗 / 所有文件 / 电池优化白名单）
        if (!KeepAliveService.isFirstLaunchDone(this)) {
            KeepAliveService.markFirstLaunchDone(this)
            requestKeepAlivePermissions()
        }

        setContent {
            var themeMode by remember { mutableStateOf(ThemeMode.SYSTEM) }
            var dynamicColor by remember { mutableStateOf(true) }

            WebReverseTheme(
                themeMode = themeMode,
                dynamicColor = dynamicColor,
            ) {
                WebReverseAppRoot(
                    container = container,
                    themeMode = themeMode,
                    onThemeModeChange = { themeMode = it },
                    dynamicColor = dynamicColor,
                    onDynamicColorChange = { dynamicColor = it },
                )
            }
        }
    }

    /** 依次申请保活所需权限：通知 → 悬浮窗 → 所有文件 → 电池优化白名单 */
    fun requestKeepAlivePermissions() {
        permissionSteps.clear()

        // 0. 通知权限（Android 13+，常驻通知显示依赖）
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            permissionSteps.add {
                runtimePermissionLauncher.launch(arrayOf(Manifest.permission.POST_NOTIFICATIONS))
            }
        }

        // 1. 悬浮窗权限（悬浮球依赖）
        if (!Settings.canDrawOverlays(this)) {
            permissionSteps.add {
                settingsLauncher.launch(
                    Intent(
                        Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                        Uri.parse("package:$packageName"),
                    ),
                )
            }
        }

        // 2. 所有文件管理权限（工作目录写入依赖）
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (!Environment.isExternalStorageManager()) {
                permissionSteps.add {
                    settingsLauncher.launch(
                        Intent(
                            Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                            Uri.parse("package:$packageName"),
                        ),
                    )
                }
            }
        } else {
            if (ContextCompat.checkSelfPermission(
                    this,
                    Manifest.permission.WRITE_EXTERNAL_STORAGE,
                ) != PackageManager.PERMISSION_GRANTED
            ) {
                permissionSteps.add {
                    runtimePermissionLauncher.launch(
                        arrayOf(Manifest.permission.WRITE_EXTERNAL_STORAGE),
                    )
                }
            }
        }

        // 3. 电池优化白名单（后台不被冻结）
        val pm = getSystemService(POWER_SERVICE) as PowerManager
        if (!pm.isIgnoringBatteryOptimizations(packageName)) {
            permissionSteps.add {
                try {
                    settingsLauncher.launch(
                        Intent(
                            Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                            Uri.parse("package:$packageName"),
                        ),
                    )
                } catch (e: Exception) {
                    // 部分厂商 ROM 禁止该 intent，直接跳过
                    onPermissionStepDone()
                }
            }
        }

        nextPermissionStep()
    }

    private fun onPermissionStepDone() {
        // 悬浮窗权限授予后立即刷新服务，让悬浮球出现
        KeepAliveService.refresh(this)
        nextPermissionStep()
    }

    private fun nextPermissionStep() {
        if (permissionSteps.isEmpty()) return
        val step = permissionSteps.removeFirstOrNull() ?: return
        step()
    }
}
