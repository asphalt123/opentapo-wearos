package com.hn.otapo.monitor

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/** Re-arms the offline monitor (and the persistent notification) after reboot / update. */
class MonitorBootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            Intent.ACTION_BOOT_COMPLETED,
            Intent.ACTION_LOCKED_BOOT_COMPLETED,
            Intent.ACTION_MY_PACKAGE_REPLACED -> {
                Log.i(TAG, "re-arming monitor after ${intent.action}")
                try {
                    DeviceMonitorScheduler.schedule(context.applicationContext)
                    DeviceMonitorReceiver.refreshPersistent(context.applicationContext)
                } catch (e: Exception) {
                    Log.w(TAG, "re-arm failed: ${e.message}")
                }
            }
        }
    }

    companion object {
        private const val TAG = "MonitorBoot"
    }
}
