package dev.veeso.opentapowearos

import android.content.Intent
import android.util.Log
import com.google.android.gms.wearable.DataEvent
import com.google.android.gms.wearable.DataEventBuffer
import com.google.android.gms.wearable.DataMapItem
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

                        sendBroadcast(Intent("dev.veeso.opentapowearos.CREDENTIALS_UPDATED"))
                    } catch (e: Exception) {
                        Log.e(TAG, "Error processing credentials data item", e)
                    }
                }
            }
        }
    }
}
