package com.hn.otapo.timer

import android.content.Context
import android.util.Log
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json

/** One-shot countdown: set [deviceId] to [targetOn] at [triggerAtMillis]. */
@Serializable
data class CountdownTimer(
    val id: String,
    val deviceId: String,
    val deviceAlias: String,
    val targetOn: Boolean,
    val triggerAtMillis: Long
)

/**
 * Recurring schedule: set [deviceId] to [targetOn] at [hour]:[minute] on
 * [days] ([Calendar.DAY_OF_WEEK] values; empty = every day).
 */
@Serializable
data class DailySchedule(
    val id: String,
    val deviceId: String,
    val deviceAlias: String,
    val hour: Int,
    val minute: Int,
    val targetOn: Boolean,
    val days: Set<Int> = emptySet(),
    val enabled: Boolean = true
)

@Serializable
private data class TimerStorePayload(
    val countdowns: List<CountdownTimer> = emptyList(),
    val dailies: List<DailySchedule> = emptyList()
)

/** Persisted timers/schedules (SharedPreferences + kotlinx.serialization). */
object TimerStore {

    private const val TAG = "TimerStore"
    private const val PREFS = "OpenTapoTimers"
    private const val KEY = "timers_json"
    private val json = Json { ignoreUnknownKeys = true }

    fun countdowns(context: Context): List<CountdownTimer> = load(context).countdowns

    fun dailies(context: Context): List<DailySchedule> = load(context).dailies

    fun addCountdown(context: Context, timer: CountdownTimer) {
        val current = load(context)
        save(context, current.copy(countdowns = current.countdowns + timer))
    }

    fun removeCountdown(context: Context, id: String) {
        val current = load(context)
        save(context, current.copy(countdowns = current.countdowns.filter { it.id != id }))
    }

    fun addDaily(context: Context, schedule: DailySchedule) {
        val current = load(context)
        save(context, current.copy(dailies = current.dailies + schedule))
    }

    fun removeDaily(context: Context, id: String) {
        val current = load(context)
        save(context, current.copy(dailies = current.dailies.filter { it.id != id }))
    }

    fun setDailyEnabled(context: Context, id: String, enabled: Boolean) {
        val current = load(context)
        save(
            context,
            current.copy(dailies = current.dailies.map {
                if (it.id == id) it.copy(enabled = enabled) else it
            })
        )
    }

    fun prunePastCountdowns(context: Context) {
        val now = System.currentTimeMillis()
        val current = load(context)
        val kept = current.countdowns.filter { it.triggerAtMillis > now }
        if (kept.size != current.countdowns.size) {
            save(context, current.copy(countdowns = kept))
        }
    }

    /** Raw JSON for backup/export. */
    fun exportJson(context: Context): String {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY, "") ?: ""
    }

    fun importJson(context: Context, raw: String) {
        try {
            // validate before storing
            json.decodeFromString<TimerStorePayload>(raw.ifBlank { "{}" })
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putString(KEY, raw).apply()
        } catch (e: Exception) {
            Log.w(TAG, "importJson invalid: ${e.message}")
        }
    }

    private fun load(context: Context): TimerStorePayload {
        return try {
            val raw = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY, "")
            if (raw.isNullOrBlank()) TimerStorePayload()
            else json.decodeFromString(raw)
        } catch (e: Exception) {
            Log.w(TAG, "load failed: ${e.message}")
            TimerStorePayload()
        }
    }

    private fun save(context: Context, payload: TimerStorePayload) {
        try {
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putString(KEY, json.encodeToString(payload)).apply()
        } catch (e: Exception) {
            Log.w(TAG, "save failed: ${e.message}")
        }
    }
}
