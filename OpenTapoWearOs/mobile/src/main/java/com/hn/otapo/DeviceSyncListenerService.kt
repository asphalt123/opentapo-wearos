package com.hn.otapo

import android.content.Intent
import android.util.Log
import com.google.android.gms.wearable.DataEvent
import com.google.android.gms.wearable.DataEventBuffer
import com.google.android.gms.wearable.DataMapItem
import com.google.android.gms.wearable.MessageEvent
import com.google.android.gms.wearable.WearableListenerService

/**
 * Background receiver for the watch-pushed device list (path
 * `/opentapo/devices`). Persists the merged list so it is available on next
 * start, and notifies the foreground [MainActivity] (if any) via broadcast.
 * Foreground handling + immediate pushes live in [MainActivity]; the
 * last-applied dedupe there makes double delivery harmless.
 */
class DeviceSyncListenerService : WearableListenerService() {

    override fun onDataChanged(events: DataEventBuffer) {
        Log.d(TAG, "onDataChanged events=${events.count}")
        for (event in events) {
            if (event.type != DataEvent.TYPE_CHANGED) continue
            if (event.dataItem.uri.path != DeviceSync.DEVICES_PATH) continue
            try {
                val dm = DataMapItem.fromDataItem(event.dataItem).dataMap
                val devicesJson = dm.getString(DeviceSync.KEY_DEVICES_JSON, "")
                if (!devicesJson.isNullOrEmpty()) {
                    onDevicesSynced(devicesJson, "data-background")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error processing devices data item", e)
            }
        }
    }

    override fun onMessageReceived(messageEvent: MessageEvent) {
        if (messageEvent.path != DeviceSync.DEVICES_PATH) return
        Log.d(TAG, "onMessageReceived devices from=${messageEvent.sourceNodeId}")
        try {
            val devicesJson = String(messageEvent.data, Charsets.UTF_8)
            if (devicesJson.isNotEmpty()) {
                onDevicesSynced(devicesJson, "message-background")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error processing devices message", e)
        }
    }

    private fun onDevicesSynced(devicesJson: String, source: String) {
        Log.d(TAG, "onDevicesSynced via $source len=${devicesJson.length}")
        try {
            val prefs = getSharedPreferences(MainActivity.PREFS, MODE_PRIVATE)
            // union-merge with the existing cache (remote wins on id conflict)
            // so nothing is lost while the activity is dead
            val existing = try {
                DeviceSync.devicesFromJson(prefs.getString(MainActivity.KEY_CACHED_DEVICES, "") ?: "")
            } catch (_: Exception) {
                emptyList()
            }
            val remote = DeviceSync.devicesFromJson(devicesJson)
            Log.d(TAG, "onDevicesSynced: ${remote.size} remote, ${existing.size} cached")
            val merged = mutableListOf<com.hn.otapo.tapo.device.Device>()
            val seen = mutableSetOf<String>()
            remote.forEach { merged.add(it); seen.add(it.id) }
            existing.filter { !seen.contains(it.id) }.forEach { merged.add(it); seen.add(it.id) }
            prefs.edit()
                .putString(MainActivity.KEY_CACHED_DEVICES, DeviceSync.devicesToJson(merged))
                .apply()
            // every known device IP stays findable by future scans
            val ips = HashSet(prefs.getStringSet(MainActivity.KEY_MANUAL_IPS, emptySet()) ?: emptySet())
            var changed = false
            merged.forEach { if (ips.add(it.ipAddress)) changed = true }
            if (changed) {
                prefs.edit().putStringSet(MainActivity.KEY_MANUAL_IPS, ips).apply()
            }
            sendBroadcast(
                Intent(ACTION_DEVICES_UPDATED).putExtra(EXTRA_DEVICES_JSON, devicesJson)
            )
        } catch (e: Exception) {
            Log.e(TAG, "onDevicesSynced failed", e)
        }
    }

    companion object {
        private const val TAG = "DeviceSyncListener"
        const val ACTION_DEVICES_UPDATED = "com.hn.otapo.DEVICES_UPDATED"
        const val EXTRA_DEVICES_JSON = "devices_json"
    }
}
