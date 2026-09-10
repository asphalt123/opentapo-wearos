package com.hn.otapo.data

import android.content.Context
import android.util.Log
import com.hn.otapo.DeviceSync
import com.hn.otapo.MainActivity
import com.hn.otapo.tapo.device.Device

/**
 * Reads/writes the cached device list shared with [MainActivity].
 *
 * Background components (widgets, tiles, timers, geofences, voice actions)
 * cannot rely on [MainActivity.devices] being in memory, so they work from
 * this persisted cache. Fresh scans performed by [MainActivity] update it.
 */
object DeviceStore {

    private const val TAG = "DeviceStore"

    fun loadCached(context: Context): List<Device> {
        return try {
            val raw = context.getSharedPreferences(MainActivity.PREFS, Context.MODE_PRIVATE)
                .getString(MainActivity.KEY_CACHED_DEVICES, "") ?: ""
            DeviceSync.devicesFromJson(raw)
        } catch (e: Exception) {
            Log.w(TAG, "loadCached failed: ${e.message}")
            emptyList()
        }
    }

    fun findById(context: Context, deviceId: String): Device? {
        return loadCached(context).firstOrNull { it.id == deviceId }
    }

    fun updateStatus(context: Context, deviceId: String, deviceOn: Boolean) {
        try {
            val devices = loadCached(context)
            val target = devices.firstOrNull { it.id == deviceId } ?: return
            target.status = target.status.copy(deviceOn = deviceOn)
            persist(context, devices)
        } catch (e: Exception) {
            Log.w(TAG, "updateStatus failed: ${e.message}")
        }
    }

    fun persist(context: Context, devices: List<Device>) {
        try {
            context.getSharedPreferences(MainActivity.PREFS, Context.MODE_PRIVATE).edit()
                .putString(MainActivity.KEY_CACHED_DEVICES, DeviceSync.devicesToJson(devices))
                .apply()
        } catch (e: Exception) {
            Log.w(TAG, "persist failed: ${e.message}")
        }
    }
}
