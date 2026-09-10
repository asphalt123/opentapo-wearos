package com.hn.otapo.geofence

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.util.Log
import com.google.android.gms.location.Geofence
import com.google.android.gms.location.GeofencingRequest
import com.google.android.gms.location.LocationServices

/**
 * Enregistre/retire les zones auprès du [com.google.android.gms.location.GeofencingClient].
 *
 * L'appelant doit avoir obtenu ACCESS_FINE_LOCATION (et idéalement
 * ACCESS_BACKGROUND_LOCATION sur Android 10+) sinon l'ajout échoue avec
 * une SecurityException tracée ici sans crash.
 */
object GeofenceManager {

    private const val TAG = "Geofence"
    const val ACTION_TRANSITION = "com.hn.otapo.geofence.TRANSITION"

    @SuppressLint("MissingPermission")
    fun registerAll(context: Context) {
        val zones = GeofenceStore.load(context).filter { it.enabled && it.deviceIds.isNotEmpty() }
        val client = LocationServices.getGeofencingClient(context.applicationContext)
        if (zones.isEmpty()) {
            removeAll(context)
            return
        }
        val geofences = zones.map { zone ->
            Geofence.Builder()
                .setRequestId(zone.id)
                .setCircularRegion(zone.latitude, zone.longitude, zone.radiusMeters)
                .setExpirationDuration(Geofence.NEVER_EXPIRE)
                .setTransitionTypes(Geofence.GEOFENCE_TRANSITION_ENTER or Geofence.GEOFENCE_TRANSITION_EXIT)
                .build()
        }
        val request = GeofencingRequest.Builder()
            .setInitialTrigger(GeofencingRequest.INITIAL_TRIGGER_ENTER)
            .addGeofences(geofences)
            .build()
        try {
            client.addGeofences(request, pending(context)).addOnSuccessListener {
                Log.i(TAG, "registered ${zones.size} zone(s)")
            }.addOnFailureListener { e ->
                Log.w(TAG, "register failed: ${e.message}")
            }
        } catch (e: SecurityException) {
            Log.w(TAG, "register denied (location permission?): ${e.message}")
        }
    }

    fun removeAll(context: Context) {
        try {
            LocationServices.getGeofencingClient(context.applicationContext)
                .removeGeofences(pending(context))
        } catch (e: Exception) {
            Log.w(TAG, "removeAll failed: ${e.message}")
        }
    }

    fun refresh(context: Context) {
        removeAll(context)
        registerAll(context)
    }

    private fun pending(context: Context): PendingIntent {
        val intent = Intent(ACTION_TRANSITION).setPackage(context.packageName)
        return PendingIntent.getBroadcast(
            context.applicationContext, 7702, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
    }
}
