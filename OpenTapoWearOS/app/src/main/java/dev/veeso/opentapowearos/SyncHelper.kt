package dev.veeso.opentapowearos

import android.content.Context
import android.util.Log
import com.google.android.gms.wearable.PutDataMapRequest
import com.google.android.gms.wearable.Wearable
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

object SyncHelper {

    private const val TAG = "SyncHelper"
    private const val CREDENTIALS_PATH = "/opentapo/credentials"

    fun sendCredentialsToMobile(context: Context, user: String, pass: String) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val req = PutDataMapRequest.create(CREDENTIALS_PATH)
                req.dataMap.putString("username", user)
                req.dataMap.putString("password", pass)
                req.dataMap.putLong("timestamp", System.currentTimeMillis())
                Wearable.getDataClient(context).putDataItem(req.asPutDataRequest().setUrgent())
            } catch (e: Exception) {
                Log.e(TAG, "Failed to send credentials to mobile", e)
            }
        }
    }
}
