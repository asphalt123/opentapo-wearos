package com.hn.otapo.geofence

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import com.google.android.gms.location.Geofence
import com.google.android.gms.location.GeofencingEvent
import com.hn.otapo.R
import com.hn.otapo.data.DeviceController
import com.hn.otapo.notif.NotifHelper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Applique les actions d'entrée/sortie quand le système déclenche une zone.
 *
 * Chaque zone allume/éteint ses prises via [DeviceController] (qui met à
 * jour le cache, donc widgets/tuiles/monitor suivent) et poste une
 * notification discrète sur le canal monitor.
 */
class GeofenceReceiver : BroadcastReceiver() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != GeofenceManager.ACTION_TRANSITION) return
        val event = try {
            GeofencingEvent.fromIntent(intent)
        } catch (e: Exception) {
            Log.w(TAG, "bad geofence intent: ${e.message}")
            return
        } ?: return
        if (event.hasError()) {
            Log.w(TAG, "geofence error code=${event.errorCode}")
            return
        }
        val transition = event.geofenceTransition
        if (transition != Geofence.GEOFENCE_TRANSITION_ENTER &&
            transition != Geofence.GEOFENCE_TRANSITION_EXIT
        ) {
            return
        }
        val ids = event.triggeringGeofences?.map { it.requestId } ?: emptyList()
        if (ids.isEmpty()) return
        val pending = goAsync()
        scope.launch {
            try {
                applyAll(context.applicationContext, ids, transition)
            } finally {
                pending.finish()
            }
        }
    }

    private suspend fun applyAll(context: Context, ids: List<String>, transition: Int) {
        val entering = transition == Geofence.GEOFENCE_TRANSITION_ENTER
        val zones = GeofenceStore.load(context).filter { it.enabled && ids.contains(it.id) }
        for (zone in zones) {
            val action = if (entering) zone.enterAction else zone.exitAction
            val targetOn = when (action) {
                "ON" -> true
                "OFF" -> false
                else -> {
                    Log.d(TAG, "zone ${zone.label}: no action on ${if (entering) "enter" else "exit"}")
                    continue
                }
            }
            Log.i(TAG, "zone ${zone.label} ${if (entering) "ENTER" else "EXIT"} -> ${if (targetOn) "ON" else "OFF"}")
            val results = withContext(Dispatchers.IO) {
                val out = mutableMapOf<String, DeviceController.ControlResult>()
                for (id in zone.deviceIds) {
                    out[id] = DeviceController.toggle(context, id, targetOn)
                }
                out
            }
            val ok = results.values.count { it is DeviceController.ControlResult.Success }
            NotifHelper.notify(
                context, NotifHelper.CHANNEL_MONITOR, 3000 + (zone.id.hashCode() % 500).let { if (it < 0) -it else it },
                context.getString(
                    if (entering) R.string.geofence_enter_title else R.string.geofence_exit_title,
                    zone.label
                ),
                context.getString(
                    R.string.geofence_applied, zone.label, ok, zone.deviceIds.size,
                    context.getString(if (targetOn) R.string.state_on else R.string.state_off)
                )
            )
        }
    }

    companion object {
        private const val TAG = "Geofence"
    }
}
