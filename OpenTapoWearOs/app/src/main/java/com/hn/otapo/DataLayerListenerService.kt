package com.hn.otapo

import android.content.Intent
import android.util.Log
import com.google.android.gms.wearable.DataEvent
import com.google.android.gms.wearable.DataEventBuffer
import com.google.android.gms.wearable.DataMapItem
import com.google.android.gms.wearable.MessageEvent
import com.google.android.gms.wearable.WearableListenerService

class DataLayerListenerService : WearableListenerService() {

    companion object {
        private const val TAG = "DataLayerListenerService"
        private const val CREDENTIALS_PATH = "/opentapo/credentials"
        const val ACTION_DEVICES_UPDATED = "com.hn.otapo.DEVICES_UPDATED"
        const val EXTRA_DEVICES_JSON = "devices_json"
    }

    override fun onCreate() {
        Log.d(TAG, "DataLayerListenerService onCreate")
        super.onCreate()
    }

    override fun onDestroy() {
        Log.d(TAG, "DataLayerListenerService onDestroy")
        super.onDestroy()
    }

    override fun onDataChanged(events: DataEventBuffer) {
        Log.d(TAG, "onDataChanged called events=${events.count}")
        for (event in events) {
            Log.d(TAG, "event path=${event.dataItem.uri.path} type=${event.type}")
            if (event.type == DataEvent.TYPE_CHANGED) {
                if (event.dataItem.uri.path == CREDENTIALS_PATH) {
                    try {
                        val dm = DataMapItem.fromDataItem(event.dataItem).dataMap
                        val username = dm.getString("username", "")
                        val password = dm.getString("password", "")
                        val timestamp = dm.getLong("timestamp", 0L)

                        getSharedPreferences("Otapo", MODE_PRIVATE).edit()
                            .putString("username", username)
                            .putString("password", password)
                            .apply()

                        // Force-start MainActivity so auto-login happens even if the activity
                        // was destroyed (e.g. screen off on WearOS). A broadcast alone is lost
                        // because MainActivity's receiver is unregistered in onDestroy().
                        val intent = Intent(this, MainActivity::class.java)
                        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                        startActivity(intent)
                        sendBroadcast(Intent("com.hn.otapo.CREDENTIALS_UPDATED"))
                    } catch (e: Exception) {
                        Log.e(TAG, "Error processing credentials data item", e)
                    }
                } else if (event.dataItem.uri.path == DeviceSync.DEVICES_PATH) {
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
        }
    }

    override fun onMessageReceived(messageEvent: MessageEvent) {
        Log.d(TAG, "onMessageReceived called path=${messageEvent.path} from=${messageEvent.sourceNodeId} dataLen=${messageEvent.data.size}")
        if (messageEvent.path == "/opentapo/credentials") {
            try {
                val payload = String(messageEvent.data, Charsets.UTF_8)
                val parts = payload.split("\n")
                if (parts.size >= 2) {
                    val username = parts[0]
                    val password = parts[1]
                    getSharedPreferences("Otapo", MODE_PRIVATE).edit()
                        .putString("username", username)
                        .putString("password", password)
                        .apply()
                    val intent = Intent(this, MainActivity::class.java)
                    intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                    startActivity(intent)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error processing credentials message", e)
            }
        } else if (messageEvent.path == DeviceSync.DEVICES_PATH) {
            try {
                val devicesJson = String(messageEvent.data, Charsets.UTF_8)
                if (devicesJson.isNotEmpty()) {
                    onDevicesSynced(devicesJson, "message-background")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error processing devices message", e)
            }
        }
    }

    /**
     * Persists a phone-pushed device list to the local cache so it survives
     * restarts, then notifies the foreground MainActivity (if any) to merge
     * it into its in-memory list. MainActivity deduplicates re-deliveries via
     * its last-applied guard, so background + foreground handling is safe.
     */
    private fun onDevicesSynced(devicesJson: String, source: String) {
        Log.d(TAG, "onDevicesSynced via $source len=${devicesJson.length}")
        try {
            val devices = DeviceSync.devicesFromJson(devicesJson)
            Log.d(TAG, "onDevicesSynced: decoded ${devices.size} device(s)")
            getSharedPreferences(MainActivity.SHARED_PREFS, MODE_PRIVATE).edit()
                .putString(
                    MainActivity.SHARED_PREFS_CACHED_DEVICES,
                    com.hn.otapo.view.app_data.DeviceCache(devices).serialize()
                )
                .apply()
            sendBroadcast(Intent(ACTION_DEVICES_UPDATED).putExtra(EXTRA_DEVICES_JSON, devicesJson))
        } catch (e: Exception) {
            Log.e(TAG, "onDevicesSynced failed", e)
        }
    }
}
