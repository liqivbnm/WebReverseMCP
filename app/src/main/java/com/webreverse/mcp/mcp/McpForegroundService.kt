package com.webreverse.mcp.mcp

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.webreverse.mcp.MainActivity
import com.webreverse.mcp.R
import com.webreverse.mcp.WebReverseApp
import com.webreverse.mcp.core.logging.LogCategory
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * MCP Server 前台服务：保持 MCP Server 在后台持续运行。
 * 启动时自动拉起 MCP Server，停止时关闭。
 */
class McpForegroundService : Service() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var started = false

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        if (action == ACTION_STOP) {
            stopServer()
            stopSelf()
            return START_NOT_STICKY
        }

        startForeground(NOTIFICATION_ID, buildNotification("MCP Server 启动中..."))

        if (!started) {
            started = true
            val container = (application as WebReverseApp).container
            serviceScope.launch {
                val ok = container.mcpServerManager.start()
                val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
                if (ok) {
                    notificationManager.notify(
                        NOTIFICATION_ID,
                        buildNotification("MCP Server 运行中: ${container.mcpServerManager.serverAddress()}"),
                    )
                    container.logger.i(LogCategory.MCP, "前台服务已启动 MCP Server")
                } else {
                    notificationManager.notify(
                        NOTIFICATION_ID,
                        buildNotification("MCP Server 启动失败"),
                    )
                }
            }
        }
        return START_STICKY
    }

    private fun stopServer() {
        val container = (application as WebReverseApp).container
        serviceScope.launch {
            container.mcpServerManager.stop()
            container.logger.i(LogCategory.MCP, "前台服务已停止 MCP Server")
        }
    }

    private fun buildNotification(content: String): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val stopIntent = Intent(this, McpForegroundService::class.java).apply {
            action = ACTION_STOP
        }
        val stopPendingIntent = PendingIntent.getService(
            this,
            1,
            stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.mcp_server_running))
            .setContentText(content)
            .setSmallIcon(android.R.drawable.ic_menu_compass)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "停止", stopPendingIntent)
            .build()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "MCP Server",
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = "保持 MCP Server 在后台运行"
                setShowBadge(false)
            }
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }

    override fun onDestroy() {
        serviceScope.cancel()
        super.onDestroy()
    }

    companion object {
        private const val CHANNEL_ID = "mcp_server_channel"
        private const val NOTIFICATION_ID = 1001
        const val ACTION_STOP = "com.webreverse.mcp.action.STOP_MCP"

        fun start(context: Context) {
            val intent = Intent(context, McpForegroundService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            val intent = Intent(context, McpForegroundService::class.java).apply {
                action = ACTION_STOP
            }
            context.startService(intent)
        }
    }
}
