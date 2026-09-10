package com.hn.otapo.complication

import android.content.ComponentName
import android.content.Context
import android.util.Log
import androidx.wear.watchface.complications.datasource.ComplicationDataSourceUpdateRequester
import com.hn.otapo.MainActivity
import com.hn.otapo.view.app_data.DeviceCache
import com.hn.otapo.tapo.device.Device

/**
 * Persists which plug the watch-face complication shows and refreshes it.
 *
 * The complication displays the cached on/off state of the chosen device;
 * tapping it opens [ComplicationToggleActivity] which flips the real state
 * via KLAP and then asks the system for fresh complication data.
 */
object ComplicationHelper {

    private const val TAG = "Complication"
    private const val KEY_DEVICE_ID = "complication_device_id"
    private const val KEY_DEVICE_ALIAS = "complication_device_alias"

    fun selectedDeviceId(context: Context): String? {
        return context.getSharedPreferences(MainActivity.SHARED_PREFS, Context.MODE_PRIVATE)
            .getString(KEY_DEVICE_ID, null)
    }

    fun selectedAlias(context: Context): String? {
        return context.getSharedPreferences(MainActivity.SHARED_PREFS, Context.MODE_PRIVATE)
            .getString(KEY_DEVICE_ALIAS, null)
    }

    fun selectDevice(context: Context, deviceId: String, alias: String) {
        context.getSharedPreferences(MainActivity.SHARED_PREFS, Context.MODE_PRIVATE).edit()
            .putString(KEY_DEVICE_ID, deviceId)
            .putString(KEY_DEVICE_ALIAS, alias)
            .apply()
        Log.d(TAG, "complication device selected: $alias ($deviceId)")
        requestRefresh(context)
    }

    fun findSelected(context: Context): Device? {
        val id = selectedDeviceId(context) ?: return null
        return try {
            val prefs = context.getSharedPreferences(MainActivity.SHARED_PREFS, Context.MODE_PRIVATE)
            val raw = prefs.getString(MainActivity.SHARED_PREFS_CACHED_DEVICES, "") ?: ""
            if (raw.isBlank()) return null
            DeviceCache(raw).devices().firstOrNull { it.id == id }
        } catch (e: Exception) {
            Log.w(TAG, "findSelected failed: ${e.message}")
            null
        }
    }

    /** Returns the selected device, falling back to the first cached one. */
    fun findEffective(context: Context): Device? {
        findSelected(context)?.let { return it }
        return try {
            val prefs = context.getSharedPreferences(MainActivity.SHARED_PREFS, Context.MODE_PRIVATE)
            val raw = prefs.getString(MainActivity.SHARED_PREFS_CACHED_DEVICES, "") ?: ""
            if (raw.isBlank()) null else DeviceCache(raw).devices().firstOrNull()
        } catch (e: Exception) {
            Log.w(TAG, "findEffective failed: ${e.message}")
            null
        }
    }

    fun allCached(context: Context): List<Device> {
        return try {
            val prefs = context.getSharedPreferences(MainActivity.SHARED_PREFS, Context.MODE_PRIVATE)
            val raw = prefs.getString(MainActivity.SHARED_PREFS_CACHED_DEVICES, "") ?: ""
            if (raw.isBlank()) emptyList() else DeviceCache(raw).devices()
        } catch (e: Exception) {
            Log.w(TAG, "allCached failed: ${e.message}")
            emptyList()
        }
    }

    fun requestRefresh(context: Context) {
        try {
            ComplicationDataSourceUpdateRequester.create(
                context,
                ComponentName(context, PlugComplicationService::class.java)
            ).requestUpdateAll()
        } catch (e: Exception) {
            Log.w(TAG, "requestRefresh failed: ${e.message}")
        }
    }
}
