package com.hn.otapo.geofence

import android.content.Context
import android.util.Log
import com.hn.otapo.MainActivity
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import java.util.UUID

/**
 * Zones de géorepérage : en entrant dans le périmètre on applique
 * [enterAction], en sortant [exitAction] (ON / OFF / NONE) aux prises cibles.
 *
 * Exemple typique : entrer -> tout allumer, sortir -> tout éteindre.
 */
@kotlinx.serialization.Serializable
data class HomeZone(
    val id: String = UUID.randomUUID().toString(),
    val label: String,
    val latitude: Double,
    val longitude: Double,
    val radiusMeters: Float = 200f,
    val deviceIds: List<String> = emptyList(),
    /** "ON", "OFF" ou "NONE" */
    val enterAction: String = "ON",
    /** "ON", "OFF" ou "NONE" */
    val exitAction: String = "OFF",
    val enabled: Boolean = true
)

object GeofenceStore {

    private const val TAG = "Geofence"
    private const val KEY_ZONES = "geofence_zones"

    fun load(context: Context): MutableList<HomeZone> {
        return try {
            val raw = prefs(context).getString(KEY_ZONES, "") ?: ""
            if (raw.isBlank()) mutableListOf()
            else Json.decodeFromString<List<HomeZone>>(raw).toMutableList()
        } catch (e: Exception) {
            Log.w(TAG, "load failed: ${e.message}")
            mutableListOf()
        }
    }

    fun save(context: Context, zones: List<HomeZone>) {
        try {
            prefs(context).edit()
                .putString(KEY_ZONES, Json.encodeToString(zones))
                .apply()
        } catch (e: Exception) {
            Log.w(TAG, "save failed: ${e.message}")
        }
    }

    fun add(context: Context, zone: HomeZone) {
        val zones = load(context)
        zones.add(zone)
        save(context, zones)
    }

    fun remove(context: Context, id: String) {
        save(context, load(context).filter { it.id != id })
    }

    fun setEnabled(context: Context, id: String, enabled: Boolean) {
        save(context, load(context).map { if (it.id == id) it.copy(enabled = enabled) else it })
    }

    private fun prefs(context: Context) =
        context.getSharedPreferences(MainActivity.PREFS, Context.MODE_PRIVATE)
}
