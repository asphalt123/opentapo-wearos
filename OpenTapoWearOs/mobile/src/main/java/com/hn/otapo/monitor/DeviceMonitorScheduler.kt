package com.hn.otapo.monitor

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log

/**
 * Arms/cancels the periodic offline check.
 *
 * Uses a one-shot exact-while-idle alarm re-armed on every fire (same
 * pattern as the timers): it survives Doze and stays aligned with the
 * user-chosen interval, unlike setRepeating which drifts and is deferred.
 */
object DeviceMonitorScheduler {

    private const val TAG = "DeviceMonitor"
    const val ACTION_CHECK = "com.hn.otapo.monitor.CHECK"

    fun schedule(context: Context) {
        if (!DeviceMonitorStore.isEnabled(context)) {
            cancel(context)
            return
        }
        val manager = context.getSystemService(Context.ALARM_SERVICE) as AlarmManager
        val at = System.currentTimeMillis() + DeviceMonitorStore.intervalMin(context) * 60_000L
        try {
            manager.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, at, pending(context))
            Log.i(TAG, "next check scheduled in ${DeviceMonitorStore.intervalMin(context)} min")
        } catch (e: Exception) {
            Log.w(TAG, "schedule failed: ${e.message}")
        }
    }

    fun runNow(context: Context) {
        context.sendBroadcast(Intent(ACTION_CHECK).setPackage(context.packageName))
    }

    fun cancel(context: Context) {
        try {
            val manager = context.getSystemService(Context.ALARM_SERVICE) as AlarmManager
            manager.cancel(pending(context))
        } catch (e: Exception) {
            Log.w(TAG, "cancel failed: ${e.message}")
        }
    }

    private fun pending(context: Context): PendingIntent {
        val intent = Intent(ACTION_CHECK).setPackage(context.packageName)
        var flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            // no exact-alarm permission needed: setAndAllowWhileIdle is inexact-safe
        }
        return PendingIntent.getBroadcast(context, 7701, intent, flags)
    }
}
