package dev.veeso.opentapo.mobile

import android.content.Context
import android.util.Log
import com.google.android.gms.tasks.Tasks
import com.google.android.gms.wearable.PutDataMapRequest
import com.google.android.gms.wearable.Wearable
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

object SyncHelper {

    private const val TAG = "SyncHelper"
    private const val CREDENTIALS_PATH = "/opentapo/credentials"

    fun sendCredentialsToWear(context: Context, user: String, pass: String) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                Log.d(TAG, "sendCredentialsToWear: putDataItem")
                val req = PutDataMapRequest.create(CREDENTIALS_PATH)
                req.dataMap.putString("username", user)
                req.dataMap.putString("password", pass)
                req.dataMap.putLong("timestamp", System.currentTimeMillis())
                Wearable.getDataClient(context).putDataItem(req.asPutDataRequest().setUrgent())
                Log.d(TAG, "sendCredentialsToWear: putDataItem OK")
            } catch (e: Exception) {
                Log.e(TAG, "sendCredentialsToWear FAILED: ${e.message} ${e}", e)
            }
        }
    }

    fun sendCredentialsToWearViaMessage(context: Context, user: String, pass: String) {
        CoroutineScope(Dispatchers.IO).launch {
            Log.d(TAG, "sendCredentialsToWearViaMessage called")
            try {
                val nodeClient = Wearable.getNodeClient(context)
                val nodes = Tasks.await(nodeClient.connectedNodes)
                Log.d(TAG, "Connected nodes count=${nodes.size} ids=${nodes.map{it.id}}")
                val payload = "$user\n$pass".toByteArray(Charsets.UTF_8)
                for (node in nodes) {
                    try {
                        Log.d(TAG, "Sending to node ${node.id}")
                        Wearable.getMessageClient(context).sendMessage(node.id, "/opentapo/credentials", payload)
                        Log.d(TAG, "Sent to node ${node.id} OK")
                    } catch (e: Exception) {
                        Log.e(TAG, "send to ${node.id} FAILED: ${e.message}", e)
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "list nodes FAILED: ${e.message} ${e}", e)
            }
        }
    }
}
