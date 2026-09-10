package com.hn.otapo.group

import android.content.Context
import android.util.Log
import com.hn.otapo.MainActivity
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json

/**
 * Groupes d'appareils côté téléphone (ordonnés).
 *
 * Chaque groupe garde sa liste de device ids dans l'ordre choisi par
 * l'utilisateur (drag & drop). Le contrôle groupé (tout allumer / tout
 * éteindre d'un appui long) passe par [com.hn.otapo.data.DeviceController].
 */
@kotlinx.serialization.Serializable
data class MobileGroup(
    val name: String,
    val deviceIds: List<String> = emptyList()
)

object MobileGroupsStore {

    private const val TAG = "MobileGroups"
    private const val KEY_GROUPS = "mobile_groups"

    fun load(context: Context): MutableList<MobileGroup> {
        return try {
            val raw = prefs(context).getString(KEY_GROUPS, "") ?: ""
            if (raw.isBlank()) mutableListOf()
            else Json.decodeFromString<List<MobileGroup>>(raw).toMutableList()
        } catch (e: Exception) {
            Log.w(TAG, "load failed: ${e.message}")
            mutableListOf()
        }
    }

    fun save(context: Context, groups: List<MobileGroup>) {
        try {
            prefs(context).edit()
                .putString(KEY_GROUPS, Json.encodeToString(groups))
                .apply()
        } catch (e: Exception) {
            Log.w(TAG, "save failed: ${e.message}")
        }
    }

    fun create(context: Context, name: String, deviceIds: List<String>): Boolean {
        val groups = load(context)
        if (groups.any { it.name.equals(name, ignoreCase = true) }) return false
        groups.add(MobileGroup(name.trim(), deviceIds.distinct()))
        save(context, groups)
        return true
    }

    fun delete(context: Context, name: String) {
        save(context, load(context).filter { it.name != name })
    }

    fun rename(context: Context, oldName: String, newName: String): Boolean {
        val groups = load(context)
        if (groups.any { it.name.equals(newName, ignoreCase = true) }) return false
        save(context, groups.map { if (it.name == oldName) it.copy(name = newName.trim()) else it })
        return true
    }

    fun updateMembers(context: Context, name: String, deviceIds: List<String>) {
        save(context, load(context).map { if (it.name == name) it.copy(deviceIds = deviceIds.distinct()) else it })
    }

    private fun prefs(context: Context) =
        context.getSharedPreferences(MainActivity.PREFS, Context.MODE_PRIVATE)
}
