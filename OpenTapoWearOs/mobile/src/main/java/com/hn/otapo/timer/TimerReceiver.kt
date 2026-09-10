package com.hn.otapo.timer

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import com.hn.otapo.R
import com.hn.otapo.data.DeviceController
import com.hn.otapo.notif.NotifHelper
import com.hn.otapo.tile.TileHelper
import com.hn.otapo.widget.DeviceWidgetHelper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import java.util.Calendar

/**
 * Fires countdowns and daily schedules, applies the target state, then
 * notifies the user. Works even if the app was killed: only the persisted
 * [TimerStore] + [AlarmManager] are involved.
 */
class TimerReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val pending = goAsync()
        CoroutineScope(SupervisorJob() + Dispatchers.Main).launch {
            try {
                when (intent.action) {
                    ACTION_COUNTDOWN -> {
                        val id = intent.getStringExtra(EXTRA_ID) ?: return@launch
                        fireCountdown(context, id)
                    }
                    ACTION_DAILY -> {
                        val id = intent.getStringExtra(EXTRA_ID) ?: return@launch
                        fireDaily(context, id)
                    }
                }
            } finally {
                pending.finish()
            }
        }
    }

    private suspend fun fireCountdown(context: Context, id: String) {
        val timer = TimerStore.countdowns(context).firstOrNull { it.id == id } ?: return
        TimerStore.removeCountdown(context, id)
        val result = DeviceController.toggle(context, timer.deviceId, timer.targetOn)
        afterToggle(context)
        val ok = result is DeviceController.ControlResult.Success
        NotifHelper.notify(
            context,
            NotifHelper.CHANNEL_TIMERS,
            id.hashCode(),
            context.getString(R.string.timer_expired_title, timer.deviceAlias),
            if (ok) {
                context.getString(
                    R.string.timer_expired_text,
                    timer.deviceAlias,
                    context.getString(if (timer.targetOn) R.string.state_on else R.string.state_off)
                )
            } else {
                context.getString(R.string.timer_failed_text, timer.deviceAlias)
            }
        )
        Log.i(TAG, "countdown fired for ${timer.deviceAlias} ok=$ok")
    }

    private suspend fun fireDaily(context: Context, id: String) {
        val schedule = TimerStore.dailies(context).firstOrNull { it.id == id } ?: return
        if (!schedule.enabled) return
        // re-arm the next occurrence first so a crash below never loses the schedule
        TimerManager.armDaily(context, schedule)
        val today = Calendar.getInstance().get(Calendar.DAY_OF_WEEK)
        if (schedule.days.isNotEmpty() && !schedule.days.contains(today)) return
        val result = DeviceController.toggle(context, schedule.deviceId, schedule.targetOn)
        afterToggle(context)
        val ok = result is DeviceController.ControlResult.Success
        NotifHelper.notify(
            context,
            NotifHelper.CHANNEL_TIMERS,
            id.hashCode(),
            context.getString(R.string.schedule_fired_title, schedule.deviceAlias),
            if (ok) {
                context.getString(
                    R.string.timer_expired_text,
                    schedule.deviceAlias,
                    context.getString(if (schedule.targetOn) R.string.state_on else R.string.state_off)
                )
            } else {
                context.getString(R.string.timer_failed_text, schedule.deviceAlias)
            }
        )
        Log.i(TAG, "daily fired for ${schedule.deviceAlias} ok=$ok")
    }

    private fun afterToggle(context: Context) {
        DeviceWidgetHelper.updateAll(context)
        TileHelper.requestRefresh(context)
    }

    companion object {
        const val TAG = "TimerReceiver"
        const val ACTION_COUNTDOWN = "com.hn.otapo.timer.COUNTDOWN"
        const val ACTION_DAILY = "com.hn.otapo.timer.DAILY"
        const val EXTRA_ID = "timer_id"

        fun countdownIntent(context: Context, id: String): Intent {
            return Intent(context, TimerReceiver::class.java).apply {
                action = ACTION_COUNTDOWN
                putExtra(EXTRA_ID, id)
            }
        }

        fun dailyIntent(context: Context, id: String): Intent {
            return Intent(context, TimerReceiver::class.java).apply {
                action = ACTION_DAILY
                putExtra(EXTRA_ID, id)
            }
        }
    }
}

/** Re-arms timers after reboot / app update. Extended by later features. */
class TimerBootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action in setOf(
                Intent.ACTION_BOOT_COMPLETED,
                Intent.ACTION_LOCKED_BOOT_COMPLETED,
                Intent.ACTION_MY_PACKAGE_REPLACED
            )
        ) {
            TimerManager.rescheduleAll(context)
        }
    }
}
