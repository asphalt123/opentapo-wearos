package com.hn.otapo.data

import android.content.Context
import android.util.Log
import com.hn.otapo.tapo.device.Device
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Toggles physical devices from background components (widget, tile, timer,
 * geofence, voice shortcut, group control, monitor).
 *
 * Handles the boring edge cases in one place:
 * - missing credentials -> [ControlResult.NoCredentials]
 * - unknown device id -> [ControlResult.UnknownDevice]
 * - offline / login / KLAP errors -> [ControlResult.Error] (no crash, the
 *   caller decides how to surface it: widget state, notification, toast…)
 *
 * On success the cached device status is updated so the UI, widgets and
 * tiles stay in sync without waiting for the next scan.
 */
object DeviceController {

    private const val TAG = "DeviceController"

    sealed interface ControlResult {
        data class Success(val device: Device, val newState: Boolean) : ControlResult
        object NoCredentials : ControlResult
        data class UnknownDevice(val deviceId: String) : ControlResult
        data class Error(val message: String?) : ControlResult
    }

    suspend fun toggle(context: Context, deviceId: String, newState: Boolean? = null): ControlResult =
        withContext(Dispatchers.IO) {
            val creds = CredentialsProvider.get(context) ?: return@withContext ControlResult.NoCredentials
            val device = DeviceStore.findById(context, deviceId)
                ?: return@withContext ControlResult.UnknownDevice(deviceId)
            try {
                if (!device.authenticated) {
                    device.login(creds.username, creds.password)
                }
                val target = newState ?: !device.status.deviceOn
                // refresh state first when toggling blindly: the cache may be stale
                if (newState == null) {
                    try {
                        device.getDeviceStatus()
                    } catch (e: Exception) {
                        Log.w(TAG, "state refresh failed for ${device.alias}, using cache: ${e.message}")
                    }
                }
                val finalState = newState ?: !device.status.deviceOn
                if (finalState) device.on() else device.off()
                device.status = device.status.copy(deviceOn = finalState)
                DeviceStore.updateStatus(context, deviceId, finalState)
                Log.i(TAG, "${device.alias} -> ${if (finalState) "ON" else "OFF"}")
                ControlResult.Success(device, finalState)
            } catch (e: Exception) {
                Log.e(TAG, "toggle failed for ${device.alias}", e)
                ControlResult.Error(e.message)
            }
        }

    suspend fun setAll(context: Context, deviceIds: List<String>, newState: Boolean): Map<String, ControlResult> {
        val results = mutableMapOf<String, ControlResult>()
        for (id in deviceIds) {
            results[id] = toggle(context, id, newState)
        }
        return results
    }
}
