package com.hn.otapo.complication

import android.app.Activity
import android.content.Context
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import com.hn.otapo.MainActivity
import com.hn.otapo.tapo.device.Device
import com.hn.otapo.view.app_data.DeviceCache
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Invisible tap target of the complication: flips the configured plug and
 * closes immediately. A toast confirms the new state; failures revert
 * silently to a toast so the watch face never shows a stuck UI.
 */
@OptIn(DelicateCoroutinesApi::class)
class ComplicationToggleActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // no UI: toggle in background, then finish
        GlobalScope.launch(Dispatchers.IO) {
            val message = try {
                toggle()
            } catch (e: Exception) {
                Log.e(TAG, "toggle failed", e)
                "Prise injoignable (${e.message})"
            }
            withContext(Dispatchers.Main) {
                Toast.makeText(this@ComplicationToggleActivity, message, Toast.LENGTH_SHORT).show()
            }
            ComplicationHelper.requestRefresh(this@ComplicationToggleActivity)
            finish()
        }
    }

    private suspend fun toggle(): String {
        val device = ComplicationHelper.findEffective(this)
            ?: return "Aucune prise configurée — ouvre OpenTapo"
        val prefs = getSharedPreferences(MainActivity.SHARED_PREFS, Context.MODE_PRIVATE)
        val user = prefs.getString(MainActivity.SHARED_PREFS_USERNAME, "") ?: ""
        val pass = prefs.getString(MainActivity.SHARED_PREFS_PASSWORD, "") ?: ""
        if (user.isEmpty() || pass.isEmpty()) return "Connecte-toi d'abord dans OpenTapo"
        if (!device.authenticated) {
            device.login(user, pass)
        }
        val target = !device.status.deviceOn
        try {
            device.getDeviceStatus()
        } catch (e: Exception) {
            Log.w(TAG, "state refresh failed, using cache: ${e.message}")
        }
        val final = !device.status.deviceOn
        if (final) device.on() else device.off()
        persistState(device.id, final)
        Log.i(TAG, "${device.alias} toggled -> ${if (final) "ON" else "OFF"}")
        return "${device.alias} : ${if (final) "allumée" else "éteinte"}"
    }

    private fun persistState(deviceId: String, on: Boolean) {
        try {
            val prefs = getSharedPreferences(MainActivity.SHARED_PREFS, Context.MODE_PRIVATE)
            val raw = prefs.getString(MainActivity.SHARED_PREFS_CACHED_DEVICES, "") ?: ""
            if (raw.isBlank()) return
            val devices: MutableList<Device> = DeviceCache(raw).devices().toMutableList()
            val idx = devices.indexOfFirst { it.id == deviceId }
            if (idx >= 0) {
                devices[idx].status = devices[idx].status.copy(deviceOn = on)
                prefs.edit()
                    .putString(MainActivity.SHARED_PREFS_CACHED_DEVICES, DeviceCache(devices).serialize())
                    .apply()
            }
        } catch (e: Exception) {
            Log.w(TAG, "persistState failed: ${e.message}")
        }
    }

    companion object {
        private const val TAG = "ComplicationToggle"
    }
}
