package com.hn.otapo.energy

import android.content.Context
import android.util.Log
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json

/** One power sample (watts at [timestampMillis]). */
@Serializable
data class PowerSample(val timestampMillis: Long, val watts: Double)

/**
 * Short power history per device (ring buffer, persisted).
 *
 * Feeds the mini bar chart in [EnergyActivity]. Samples older than 24h are
 * dropped; at most [MAX_SAMPLES] are kept so the payload stays tiny.
 */
object EnergyStore {

    private const val TAG = "EnergyStore"
    private const val PREFS = "OpenTapoEnergy"
    private const val MAX_SAMPLES = 96
    private const val RETENTION_MILLIS = 24 * 60 * 60 * 1000L
    private val json = Json { ignoreUnknownKeys = true }

    fun samples(context: Context, deviceId: String): List<PowerSample> {
        return try {
            val raw = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .getString(key(deviceId), "") ?: ""
            if (raw.isBlank()) emptyList()
            else json.decodeFromString<List<PowerSample>>(raw)
                .filter { System.currentTimeMillis() - it.timestampMillis < RETENTION_MILLIS }
        } catch (e: Exception) {
            Log.w(TAG, "samples failed: ${e.message}")
            emptyList()
        }
    }

    fun addSample(context: Context, deviceId: String, watts: Double) {
        try {
            val kept = (samples(context, deviceId) +
                PowerSample(System.currentTimeMillis(), watts)).takeLast(MAX_SAMPLES)
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putString(key(deviceId), json.encodeToString(kept)).apply()
        } catch (e: Exception) {
            Log.w(TAG, "addSample failed: ${e.message}")
        }
    }

    /** Raw JSON (all devices) for backup/export. */
    fun exportAll(context: Context): Map<String, String> {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        return prefs.all.mapNotNull { (k, v) -> (v as? String)?.let { k to it } }.toMap()
    }

    fun importAll(context: Context, entries: Map<String, String>) {
        try {
            val edit = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            entries.forEach { (k, v) -> edit.putString(k, v) }
            edit.apply()
        } catch (e: Exception) {
            Log.w(TAG, "importAll failed: ${e.message}")
        }
    }

    private fun key(deviceId: String) = "energy_" + deviceId.hashCode()
}
