package com.hn.otapo.geofence

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/** Ré-enregistre les zones après reboot / mise à jour de l'app. */
class GeofenceBootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            Intent.ACTION_BOOT_COMPLETED,
            Intent.ACTION_LOCKED_BOOT_COMPLETED,
            Intent.ACTION_MY_PACKAGE_REPLACED -> {
                Log.i(TAG, "re-registering zones after ${intent.action}")
                try {
                    GeofenceManager.registerAll(context.applicationContext)
                } catch (e: Exception) {
                    Log.w(TAG, "re-register failed: ${e.message}")
                }
            }
        }
    }

    companion object {
        private const val TAG = "GeofenceBoot"
    }
}
