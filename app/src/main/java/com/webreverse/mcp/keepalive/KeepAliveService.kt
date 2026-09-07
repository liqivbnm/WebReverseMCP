package com.webreverse.mcp.keepalive

import android.animation.Animator
import android.animation.AnimatorListenerAdapter
import android.animation.ValueAnimator
import android.annotation.SuppressLint
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.graphics.Color
import android.graphics.PixelFormat
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.IBinder
import android.provider.Settings
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.WindowManager
import android.view.animation.DecelerateInterpolator
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.TextView
import com.webreverse.mcp.MainActivity
import com.webreverse.mcp.R

/**
 * 保活服务：
 * - 前台服务 + 常驻通知（降低进程被系统回收的概率）
 * - 悬浮球（应用图标 + "运行中"徽标，可拖动，松手自动吸附到屏幕左右边缘，单击回到应用）
 * - 开机自启（配合 [BootReceiver]）
 */
class KeepAliveService : Service() {

    companion object {
        private const val CHANNEL_ID = "keep_alive_channel"
        private const val NOTIFICATION_ID = 1002
        private const val ACTION_STOP = "com.webreverse.mcp.keepalive.STOP"
        private const val ACTION_REFRESH = "com.webreverse.mcp.keepalive.REFRESH"
        private const val PREFS = "webreverse_prefs"
        private const val KEY_KEEP_ALIVE = "keep_alive_enabled"
        private const val KEY_BALL = "floating_ball_enabled"
        private const val KEY_BALL_X = "floating_ball_x"
        private const val KEY_BALL_Y = "floating_ball_y"
        private const val KEY_FIRST_LAUNCH = "first_launch_done"

        fun prefs(context: Context): SharedPreferences =
            context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

        fun isKeepAliveEnabled(context: Context): Boolean =
            prefs(context).getBoolean(KEY_KEEP_ALIVE, true)

        fun setKeepAliveEnabled(context: Context, enabled: Boolean) {
            prefs(context).edit().putBoolean(KEY_KEEP_ALIVE, enabled).apply()
            if (enabled) start(context) else stop(context)
        }

        fun isBallEnabled(context: Context): Boolean =
            prefs(context).getBoolean(KEY_BALL, true)

        fun setBallEnabled(context: Context, enabled: Boolean) {
            prefs(context).edit().putBoolean(KEY_BALL, enabled).apply()
            refresh(context)
        }

        fun isFirstLaunchDone(context: Context): Boolean =
            prefs(context).getBoolean(KEY_FIRST_LAUNCH, false)

        fun markFirstLaunchDone(context: Context) {
            prefs(context).edit().putBoolean(KEY_FIRST_LAUNCH, true).apply()
        }

        /** 拉起保活服务（常驻通知 + 按需悬浮球） */
        fun start(context: Context) {
            try {
                context.applicationContext.startForegroundService(
                    Intent(context.applicationContext, KeepAliveService::class.java),
                )
            } catch (e: Exception) {
                // 前台服务启动受限（如应用刚被强制停止后立即调用），忽略
            }
        }

        fun stop(context: Context) {
            context.applicationContext.stopService(
                Intent(context.applicationContext, KeepAliveService::class.java),
            )
        }

        /** 通知/悬浮球状态变化后刷新（如悬浮窗权限刚授予） */
        fun refresh(context: Context) {
            if (!isKeepAliveEnabled(context)) return
            try {
                context.applicationContext.startForegroundService(
                    Intent(context.applicationContext, KeepAliveService::class.java)
                        .setAction(ACTION_REFRESH),
                )
            } catch (e: Exception) {
                // 忽略启动失败
            }
        }
    }

    private var windowManager: WindowManager? = null
    private var ballView: View? = null
    private var snapAnimator: ValueAnimator? = null

    private fun dp(v: Int): Int = (v * resources.displayMetrics.density).toInt()

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return START_NOT_STICKY
            }
            else -> {
                startForeground(NOTIFICATION_ID, buildNotification())
                if (isBallEnabled(this) && Settings.canDrawOverlays(this)) {
                    showBall()
                } else {
                    removeBall()
                }
            }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        removeBall()
        super.onDestroy()
    }

    // ---------------- 通知 ----------------

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "保活服务",
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = "常驻通知，降低服务被系统回收的概率"
                setShowBadge(false)
            }
            val manager = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(): Notification {
        val openIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val stopIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, KeepAliveService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        return builder
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle("WebReverse MCP 运行中")
            .setContentText("保活已开启 · 点击返回应用")
            .setContentIntent(openIntent)
            .setOngoing(true)
            .setPriority(Notification.PRIORITY_LOW)
            .setCategory(Notification.CATEGORY_SERVICE)
            .addAction(0, "停止保活", stopIntent)
            .build()
    }

    // ---------------- 悬浮球 ----------------

    @SuppressLint("ClickableViewAccessibility")
    private fun showBall() {
        if (ballView != null) return
        val wm = getSystemService(WINDOW_SERVICE) as WindowManager

        // 圆形深色底 + 应用图标
        val circleBg = GradientDrawable().apply {
            shape = GradientDrawable.OVAL
            setColor(0xF01C1B1F.toInt())
            setStroke(dp(1), 0x66FFFFFF.toInt())
        }
        val icon = ImageView(this).apply {
            setImageResource(R.mipmap.ic_launcher)
            background = circleBg
            setPadding(dp(9), dp(9), dp(9), dp(9))
        }

        // "运行中" 徽标（绿色药丸）
        val badge = TextView(this).apply {
            text = "运行中"
            textSize = 9f
            setTextColor(Color.WHITE)
            typeface = Typeface.DEFAULT_BOLD
            background = GradientDrawable().apply {
                cornerRadius = dp(9).toFloat()
                setColor(0xF034A853.toInt())
            }
            val h = dp(4)
            setPadding(h, dp(2), h, dp(2))
        }

        val content = FrameLayout(this).apply {
            addView(icon, FrameLayout.LayoutParams(dp(46), dp(46)))
            addView(
                badge,
                FrameLayout.LayoutParams(
                    FrameLayout.LayoutParams.WRAP_CONTENT,
                    FrameLayout.LayoutParams.WRAP_CONTENT,
                    Gravity.BOTTOM or Gravity.CENTER_HORIZONTAL,
                ),
            )
        }

        val overlayType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
        } else {
            @Suppress("DEPRECATION")
            WindowManager.LayoutParams.TYPE_PHONE
        }
        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            overlayType,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE
                or WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS,
            PixelFormat.TRANSLUCENT,
        ).apply {
            gravity = Gravity.TOP or Gravity.START
            val screenW = resources.displayMetrics.widthPixels
            val screenH = resources.displayMetrics.heightPixels
            val savedX = prefs(this@KeepAliveService).getInt(KEY_BALL_X, Int.MIN_VALUE)
            val savedY = prefs(this@KeepAliveService).getInt(KEY_BALL_Y, Int.MIN_VALUE)
            if (savedX != Int.MIN_VALUE && savedY != Int.MIN_VALUE) {
                // 恢复上次记忆的位置（旋转/分辨率变化后收敛到合法范围）
                x = savedX.coerceIn(0, (screenW - dp(46)).coerceAtLeast(0))
                y = savedY.coerceIn(0, (screenH - dp(46)).coerceAtLeast(0))
            } else {
                x = screenW - dp(72)
                y = screenH / 3
            }
        }

        // 拖动 + 单击回应用 + 松手自动贴边
        var downRawX = 0f
        var downRawY = 0f
        var startX = 0
        var startY = 0
        var downTime = 0L
        var moved = false
        content.setOnTouchListener { _, ev ->
            when (ev.actionMasked) {
                MotionEvent.ACTION_DOWN -> {
                    snapAnimator?.cancel()
                    downRawX = ev.rawX
                    downRawY = ev.rawY
                    startX = params.x
                    startY = params.y
                    downTime = System.currentTimeMillis()
                    moved = false
                    true
                }
                MotionEvent.ACTION_MOVE -> {
                    val dx = ev.rawX - downRawX
                    val dy = ev.rawY - downRawY
                    if (kotlin.math.abs(dx) > 8 || kotlin.math.abs(dy) > 8) moved = true
                    if (moved) {
                        // 拖动范围始终限制在屏幕内，避免球被拖出边界难以找回
                        val screenW = resources.displayMetrics.widthPixels
                        val screenH = resources.displayMetrics.heightPixels
                        val ballW = if (content.width > 0) content.width else dp(46)
                        val ballH = if (content.height > 0) content.height else dp(46)
                        params.x = (startX + dx.toInt())
                            .coerceIn(0, (screenW - ballW).coerceAtLeast(0))
                        params.y = (startY + dy.toInt())
                            .coerceIn(0, (screenH - ballH).coerceAtLeast(0))
                        try {
                            wm.updateViewLayout(content, params)
                        } catch (e: Exception) {
                            // 窗口已被移除
                        }
                    }
                    true
                }
                MotionEvent.ACTION_UP -> {
                    // 位移小且时间短视为点击 → 回到应用
                    if (!moved && System.currentTimeMillis() - downTime < 500) {
                        openApp()
                    } else if (moved) {
                        // 松手后自动吸附到最近的屏幕边缘（左/右）
                        snapToEdge(wm, content, params)
                    }
                    true
                }
                else -> false
            }
        }

        try {
            wm.addView(content, params)
            ballView = content
            windowManager = wm
        } catch (e: Exception) {
            // 无悬浮窗权限或窗口添加失败，忽略（通知保活仍然生效）
        }
    }

    private fun removeBall() {
        snapAnimator?.cancel()
        snapAnimator = null
        val view = ballView ?: return
        try {
            windowManager?.removeView(view)
        } catch (e: Exception) {
            // 忽略
        }
        ballView = null
        windowManager = null
    }

    // ---------------- 边缘吸附 ----------------

    /**
     * 松手后自动吸附到最近的屏幕边缘：
     * - 球中心在屏幕左半边 → 吸附到左边缘；右半边 → 吸附到右边缘
     * - 使用减速插值动画平滑滑动过去
     * - 吸附完成后记忆位置，下次显示悬浮球时恢复
     */
    private fun snapToEdge(wm: WindowManager, view: View, params: WindowManager.LayoutParams) {
        val screenW = resources.displayMetrics.widthPixels
        val ballW = if (view.width > 0) view.width else dp(46)
        val targetX = if (params.x + ballW / 2f < screenW / 2f) 0 else screenW - ballW
        val fromX = params.x

        snapAnimator?.cancel()
        if (fromX == targetX) {
            saveBallPosition(params)
            return
        }

        snapAnimator = ValueAnimator.ofInt(fromX, targetX).apply {
            duration = 220L
            interpolator = DecelerateInterpolator()
            addUpdateListener { anim ->
                params.x = anim.animatedValue as Int
                try {
                    wm.updateViewLayout(view, params)
                } catch (e: Exception) {
                    // 窗口已被移除
                }
            }
            addListener(object : AnimatorListenerAdapter() {
                private var canceled = false

                override fun onAnimationCancel(animation: Animator) {
                    canceled = true
                }

                override fun onAnimationEnd(animation: Animator) {
                    if (canceled) return
                    params.x = targetX
                    try {
                        wm.updateViewLayout(view, params)
                    } catch (e: Exception) {
                        // 忽略
                    }
                    saveBallPosition(params)
                }
            })
            start()
        }
    }

    /** 持久化悬浮球位置（贴边后调用，重启/重新显示时恢复） */
    private fun saveBallPosition(params: WindowManager.LayoutParams) {
        prefs(this).edit()
            .putInt(KEY_BALL_X, params.x)
            .putInt(KEY_BALL_Y, params.y)
            .apply()
    }

    private fun openApp() {
        try {
            startActivity(
                Intent(this, MainActivity::class.java)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP),
            )
        } catch (e: Exception) {
            // 忽略
        }
    }
}
