package com.hn.otapo.monitor

import android.content.Context
import android.util.Log
import com.hn.otapo.MainActivity
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json

/**
 * Settings + last-known reachability snapshot for the offline monitor.
 *
 * Snapshot entries are keyed by device id: true = reachable on last check.
 * Comparing the live KLAP probe against this snapshot (and the cached
 * on/off state) is what distinguishes "went offline", "back online" and
 * "unexpected state change" without spamming on every poll.
 */
object DeviceMonitorStore {

    private const val TAG = "DeviceMonitor"
    private const val KEY_ENABLED = "monitor_enabled"
    private const val KEY_PERSISTENT = "monitor_persistent"
    private const val KEY_INTERVAL_MIN = "monitor_interval_min"
    private const val KEY_SNAPSHOT = "monitor_snapshot"

    const val DEFAULT_INTERVAL_MIN = 30

    fun isEnabled(context: Context): Boolean =
        prefs(context).getBoolean(KEY_ENABLED, true)

    fun setEnabled(context: Context, enabled: Boolean) {
        prefs(context).edit().putBoolean(KEY_ENABLED, enabled).apply()
        Log.i(TAG, "monitor enabled=$enabled")
    }

    fun isPersistent(context: Context): Boolean =
        prefs(context).getBoolean(KEY_PERSISTENT, false)

    fun setPersistent(context: Context, persistent: Boolean) {
        prefs(context).edit().putBoolean(KEY_PERSISTENT, persistent).apply()
    }

    fun intervalMin(context: Context): Int =
        prefs(context).getInt(KEY_INTERVAL_MIN, DEFAULT_INTERVAL_MIN).coerceIn(15, 720)

    fun setIntervalMin(context: Context, minutes: Int) {
        prefs(context).edit().putInt(KEY_INTERVAL_MIN, minutes.coerceIn(15, 720)).apply()
    }

    fun loadSnapshot(context: Context): Map<String, Boolean> {
        return try {
            val raw = prefs(context).getString(KEY_SNAPSHOT, "") ?: ""
            if (raw.isBlank()) emptyMap() else Json.decodeFromString(raw)
        } catch (e: Exception) {
            Log.w(TAG, "loadSnapshot failed: ${e.message}")
            emptyMap()
        }
    }

    fun saveSnapshot(context: Context, snapshot: Map<String, Boolean>) {
        try {
            prefs(context).edit()
                .putString(KEY_SNAPSHOT, Json.encodeToString(snapshot))
                .apply()
        } catch (e: Exception) {
            Log.w(TAG, "saveSnapshot failed: ${e.message}")
        }
    }

    private fun prefs(context: Context) =
        context.getSharedPreferences(MainActivity.PREFS, Context.MODE_PRIVATE)
}
