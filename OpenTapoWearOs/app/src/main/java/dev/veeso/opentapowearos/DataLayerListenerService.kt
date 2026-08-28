package dev.veeso.opentapowearos

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
    }

    override fun onDataChanged(events: DataEventBuffer) {
        for (event in events) {
            if (event.type == DataEvent.TYPE_CHANGED) {
                if (event.dataItem.uri.path == CREDENTIALS_PATH) {
                    try {
                        val dm = DataMapItem.fromDataItem(event.dataItem).dataMap
                        val username = dm.getString("username", "")
                        val password = dm.getString("password", "")
                        val timestamp = dm.getLong("timestamp", 0L)

                        getSharedPreferences("OpenTapoWearOs", MODE_PRIVATE).edit()
                            .putString("username", username)
                            .putString("password", password)
                            .apply()

                        // Force-start MainActivity so auto-login happens even if the activity
                        // was destroyed (e.g. screen off on WearOS). A broadcast alone is lost
                        // because MainActivity's receiver is unregistered in onDestroy().
                        val intent = Intent(this, MainActivity::class.java)
                        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                        startActivity(intent)
                        sendBroadcast(Intent("dev.veeso.opentapowearos.CREDENTIALS_UPDATED"))
                    } catch (e: Exception) {
                        Log.e(TAG, "Error processing credentials data item", e)
                    }
                }
            }
        }
    }

    override fun onMessageReceived(messageEvent: MessageEvent) {
        if (messageEvent.path == "/opentapo/credentials") {
            try {
                val payload = String(messageEvent.data, Charsets.UTF_8)
                val parts = payload.split("\n")
                if (parts.size >= 2) {
                    val username = parts[0]
                    val password = parts[1]
                    getSharedPreferences("OpenTapoWearOs", MODE_PRIVATE).edit()
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
        }
    }
}
