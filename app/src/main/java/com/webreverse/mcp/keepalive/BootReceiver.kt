package com.webreverse.mcp.keepalive

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** 开机自启：保活开关开启时拉起保活服务 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED && KeepAliveService.isKeepAliveEnabled(context)) {
            KeepAliveService.start(context)
        }
    }
}
