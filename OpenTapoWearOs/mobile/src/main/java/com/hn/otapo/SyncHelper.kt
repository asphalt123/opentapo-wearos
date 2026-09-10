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

    fun sendCredentialsToWear(context: Context, user: String, pass: String) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                Log.d(TAG, "sendCredentialsToWear: putDataItem path=$CREDENTIALS_PATH")
                val req = PutDataMapRequest.create(CREDENTIALS_PATH)
                req.dataMap.putString("username", user)
                req.dataMap.putString("password", pass)
                req.dataMap.putLong("timestamp", System.currentTimeMillis())
                val result = Tasks.await(
                    Wearable.getDataClient(context).putDataItem(req.asPutDataRequest().setUrgent())
                )
                Log.d(TAG, "sendCredentialsToWear: putDataItem OK uri=${result?.uri}")
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
                if (nodes.isEmpty()) {
                    Log.w(TAG, "No connected nodes; message not sent")
                    return@launch
                }
                val payload = "$user\n$pass".toByteArray(Charsets.UTF_8)
                for (node in nodes) {
                    try {
                        Log.d(TAG, "Sending to node ${node.id}")
                        Tasks.await(
                            Wearable.getMessageClient(context).sendMessage(node.id, "/opentapo/credentials", payload)
                        )
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

    /**
     * Pushes the ACTIVE Tapo account to the watch on its own Data Layer path
     * (`/opentapo/account`, tagged with the account id) so the watch can
     * keep per-account state instead of mixing maison/travail devices.
     * The legacy `/opentapo/credentials` push is kept alongside for the
     * current watch app, which only knows that path.
     */
    fun sendActiveAccountToWear(context: Context) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val account = com.hn.otapo.account.AccountStore.active(context)
                    ?: return@launch
                val creds = com.hn.otapo.account.AccountStore.activeCredentials(context)
                    ?: return@launch
                Log.d(TAG, "sendActiveAccountToWear: account=${account.label} id=${account.id}")
                val req = PutDataMapRequest.create(
                    com.hn.otapo.account.AccountStore.ACCOUNT_PATH
                )
                req.dataMap.putString(
                    com.hn.otapo.account.AccountStore.KEY_ACCOUNT_ID, account.id
                )
                req.dataMap.putString("label", account.label)
                req.dataMap.putString("username", creds.username)
                req.dataMap.putString("password", creds.password)
                req.dataMap.putLong("timestamp", System.currentTimeMillis())
                val result = Tasks.await(
                    Wearable.getDataClient(context).putDataItem(req.asPutDataRequest().setUrgent())
                )
                Log.d(TAG, "sendActiveAccountToWear OK uri=${result?.uri}")
                try {
                    val nodes = Tasks.await(Wearable.getNodeClient(context).connectedNodes)
                    val payload = "${account.id}\n${creds.username}\n${creds.password}"
                        .toByteArray(Charsets.UTF_8)
                    for (node in nodes) {
                        try {
                            Tasks.await(
                                Wearable.getMessageClient(context).sendMessage(
                                    node.id,
                                    com.hn.otapo.account.AccountStore.ACCOUNT_PATH,
                                    payload
                                )
                            )
                        } catch (e: Exception) {
                            Log.e(TAG, "account message to ${node.id} FAILED: ${e.message}", e)
                        }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "account list nodes FAILED: ${e.message}", e)
                }
            } catch (e: Exception) {
                Log.e(TAG, "sendActiveAccountToWear FAILED: ${e.message}", e)
            }
        }
    }

    /**
     * Pushes the phone device list to the watch, both as a persistent DataItem
     * (so the watch can pull it later, even if it was offline) and as an
     * immediate message to connected nodes. [devicesJson] is produced by
     * [DeviceSync.devicesToJson].
     */
    fun sendDevicesToWear(context: Context, devicesJson: String) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                Log.d(TAG, "sendDevicesToWear: putDataItem path=${DeviceSync.DEVICES_PATH}")
                val req = PutDataMapRequest.create(DeviceSync.DEVICES_PATH)
                req.dataMap.putString(DeviceSync.KEY_DEVICES_JSON, devicesJson)
                req.dataMap.putLong(DeviceSync.KEY_TIMESTAMP, System.currentTimeMillis())
                val result = Tasks.await(
                    Wearable.getDataClient(context).putDataItem(req.asPutDataRequest().setUrgent())
                )
                Log.d(TAG, "sendDevicesToWear: putDataItem OK uri=${result?.uri}")
            } catch (e: Exception) {
                Log.e(TAG, "sendDevicesToWear DataItem FAILED: ${e.message} ${e}", e)
            }
            try {
                val nodes = Tasks.await(Wearable.getNodeClient(context).connectedNodes)
                Log.d(TAG, "sendDevicesToWear: connected nodes count=${nodes.size}")
                val payload = devicesJson.toByteArray(Charsets.UTF_8)
                for (node in nodes) {
                    try {
                        Tasks.await(
                            Wearable.getMessageClient(context)
                                .sendMessage(node.id, DeviceSync.DEVICES_PATH, payload)
                        )
                        Log.d(TAG, "sendDevicesToWear: message sent to node ${node.id}")
                    } catch (e: Exception) {
                        Log.e(TAG, "sendDevicesToWear message to ${node.id} FAILED: ${e.message}", e)
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "sendDevicesToWear list nodes FAILED: ${e.message} ${e}", e)
            }
        }
    }
}
