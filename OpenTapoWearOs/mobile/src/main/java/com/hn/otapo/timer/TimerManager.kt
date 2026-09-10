package com.hn.otapo.timer

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import java.util.Calendar
import java.util.UUID

/**
 * Schedules/cancels [AlarmManager] alarms for countdowns and daily schedules.
 *
 * - countdowns use an exact alarm (falls back to inexact when the user did
 *   not grant SCHEDULE_EXACT_ALARM on Android 12+)
 * - dailies arm only their next occurrence and re-arm on every fire, which
 *   survives reboots, DST changes and app updates
 */
object TimerManager {

    private const val TAG = "TimerManager"

    fun scheduleCountdown(context: Context, deviceId: String, alias: String, delayMinutes: Int, targetOn: Boolean): CountdownTimer {
        val timer = CountdownTimer(
            id = UUID.randomUUID().toString(),
            deviceId = deviceId,
            deviceAlias = alias,
            targetOn = targetOn,
            triggerAtMillis = System.currentTimeMillis() + delayMinutes * 60_000L
        )
        TimerStore.addCountdown(context, timer)
        armCountdown(context, timer)
        return timer
    }

    fun cancelCountdown(context: Context, id: String) {
        TimerStore.removeCountdown(context, id)
        val intent = TimerReceiver.countdownIntent(context, id)
        pending(context, id.hashCode(), intent, PendingIntent.FLAG_NO_CREATE)?.cancel()
    }

    fun scheduleDaily(
        context: Context,
        deviceId: String,
        alias: String,
        hour: Int,
        minute: Int,
        targetOn: Boolean,
        days: Set<Int>
    ): DailySchedule {
        val schedule = DailySchedule(
            id = UUID.randomUUID().toString(),
            deviceId = deviceId,
            deviceAlias = alias,
            hour = hour,
            minute = minute,
            targetOn = targetOn,
            days = days
        )
        TimerStore.addDaily(context, schedule)
        armDaily(context, schedule)
        return schedule
    }

    fun cancelDaily(context: Context, id: String) {
        TimerStore.removeDaily(context, id)
        val intent = TimerReceiver.dailyIntent(context, id)
        pending(context, id.hashCode(), intent, PendingIntent.FLAG_NO_CREATE)?.cancel()
    }

    fun setDailyEnabled(context: Context, id: String, enabled: Boolean) {
        TimerStore.setDailyEnabled(context, id, enabled)
        val schedule = TimerStore.dailies(context).firstOrNull { it.id == id } ?: return
        if (enabled) armDaily(context, schedule)
        else {
            val intent = TimerReceiver.dailyIntent(context, id)
            pending(context, id.hashCode(), intent, PendingIntent.FLAG_NO_CREATE)?.cancel()
        }
    }

    /** Re-arms everything after a reboot or app update. */
    fun rescheduleAll(context: Context) {
        TimerStore.prunePastCountdowns(context)
        TimerStore.countdowns(context).forEach { armCountdown(context, it) }
        TimerStore.dailies(context).filter { it.enabled }.forEach { armDaily(context, it) }
        Log.i(TAG, "rescheduled all timers")
    }

    fun canScheduleExact(context: Context): Boolean {
        val manager = context.getSystemService(Context.ALARM_SERVICE) as AlarmManager
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            manager.canScheduleExactAlarms()
        } else {
            true
        }
    }

    // -- internals ----------------------------------------------------------

    private fun armCountdown(context: Context, timer: CountdownTimer) {
        val manager = context.getSystemService(Context.ALARM_SERVICE) as AlarmManager
        val pi = pending(context, timer.id.hashCode(), TimerReceiver.countdownIntent(context, timer.id))
            ?: return
        try {
            if (canScheduleExact(context)) {
                manager.setExactAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, timer.triggerAtMillis, pi)
            } else {
                manager.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, timer.triggerAtMillis, pi)
            }
        } catch (e: Exception) {
            Log.w(TAG, "armCountdown failed: ${e.message}")
        }
    }

    internal fun armDaily(context: Context, schedule: DailySchedule) {
        val manager = context.getSystemService(Context.ALARM_SERVICE) as AlarmManager
        val next = nextOccurrence(schedule)
        val pi = pending(context, schedule.id.hashCode(), TimerReceiver.dailyIntent(context, schedule.id))
            ?: return
        try {
            if (canScheduleExact(context)) {
                manager.setExactAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, next, pi)
            } else {
                manager.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, next, pi)
            }
        } catch (e: Exception) {
            Log.w(TAG, "armDaily failed: ${e.message}")
        }
    }

    /** Next epoch millis matching hour/minute (+ day filter). */
    internal fun nextOccurrence(schedule: DailySchedule): Long {
        val now = Calendar.getInstance()
        for (offset in 0..8) {
            val candidate = (now.clone() as Calendar).apply {
                add(Calendar.DAY_OF_YEAR, offset)
                set(Calendar.HOUR_OF_DAY, schedule.hour)
                set(Calendar.MINUTE, schedule.minute)
                set(Calendar.SECOND, 0)
                set(Calendar.MILLISECOND, 0)
            }
            if (candidate.timeInMillis <= now.timeInMillis) continue
            if (schedule.days.isEmpty() || schedule.days.contains(candidate.get(Calendar.DAY_OF_WEEK))) {
                return candidate.timeInMillis
            }
        }
        // fallback: same time tomorrow
        return now.apply {
            add(Calendar.DAY_OF_YEAR, 1)
            set(Calendar.HOUR_OF_DAY, schedule.hour)
            set(Calendar.MINUTE, schedule.minute)
            set(Calendar.SECOND, 0)
            set(Calendar.MILLISECOND, 0)
        }.timeInMillis
    }

    private fun pending(context: Context, requestCode: Int, intent: Intent, extraFlags: Int = 0): PendingIntent? {
        return try {
            PendingIntent.getBroadcast(
                context, requestCode, intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE or extraFlags
            )
        } catch (e: Exception) {
            // FLAG_NO_CREATE returns null when absent by throwing on some OEMs
            Log.d(TAG, "pending unavailable: ${e.message}")
            null
        }
    }
}
