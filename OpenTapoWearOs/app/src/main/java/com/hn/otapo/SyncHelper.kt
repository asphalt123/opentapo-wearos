package com.hn.otapo

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

    /**
     * Pushes the watch device list to the phone, both as a persistent DataItem
     * (so the phone can pull it later) and as an immediate message to
     * connected nodes. [devicesJson] is produced by [DeviceSync.devicesToJson].
     */
    fun sendDevicesToMobile(context: Context, devicesJson: String) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                Log.d(TAG, "sendDevicesToMobile: putDataItem path=${DeviceSync.DEVICES_PATH}")
                val req = PutDataMapRequest.create(DeviceSync.DEVICES_PATH)
                req.dataMap.putString(DeviceSync.KEY_DEVICES_JSON, devicesJson)
                req.dataMap.putLong(DeviceSync.KEY_TIMESTAMP, System.currentTimeMillis())
                val result = Tasks.await(
                    Wearable.getDataClient(context).putDataItem(req.asPutDataRequest().setUrgent())
                )
                Log.d(TAG, "sendDevicesToMobile: putDataItem OK uri=${result?.uri}")
            } catch (e: Exception) {
                Log.e(TAG, "sendDevicesToMobile DataItem FAILED: ${e.message}", e)
            }
            try {
                val nodes = Tasks.await(Wearable.getNodeClient(context).connectedNodes)
                val payload = devicesJson.toByteArray(Charsets.UTF_8)
                for (node in nodes) {
                    try {
                        Tasks.await(
                            Wearable.getMessageClient(context)
                                .sendMessage(node.id, DeviceSync.DEVICES_PATH, payload)
                        )
                        Log.d(TAG, "sendDevicesToMobile: message sent to node ${node.id}")
                    } catch (e: Exception) {
                        Log.e(TAG, "sendDevicesToMobile message to ${node.id} FAILED: ${e.message}", e)
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "sendDevicesToMobile list nodes FAILED: ${e.message}", e)
            }
        }
    }
}
