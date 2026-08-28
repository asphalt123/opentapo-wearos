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
                val req = PutDataMapRequest.create(CREDENTIALS_PATH)
                req.dataMap.putString("username", user)
                req.dataMap.putString("password", pass)
                req.dataMap.putLong("timestamp", System.currentTimeMillis())
                Wearable.getDataClient(context).putDataItem(req.asPutDataRequest().setUrgent())
            } catch (e: Exception) {
                Log.e(TAG, "Failed to send credentials to wear", e)
            }
        }
    }

    fun sendCredentialsToWearViaMessage(context: Context, user: String, pass: String) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val nodeClient = Wearable.getNodeClient(context)
                val nodes = Tasks.await(nodeClient.connectedNodes)
                Log.d(TAG, "Connected nodes: ${nodes.size} -> ${nodes.map { it.id }}")
                val payload = "$user\n$pass".toByteArray(Charsets.UTF_8)
                for (node in nodes) {
                    try {
                        Wearable.getMessageClient(context).sendMessage(node.id, "/opentapo/credentials", payload)
                        Log.d(TAG, "Sent credentials to wear node ${node.id}")
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to send message to node ${node.id}", e)
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to list connected nodes", e)
            }
        }
    }
}
