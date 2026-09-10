package com.hn.otapo.timer

import android.Manifest
import android.app.AlarmManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.Switch
import android.widget.TextView
import android.widget.TimePicker
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.hn.otapo.R
import com.hn.otapo.common.DevicePickerActivity
import java.util.Calendar
import java.util.concurrent.TimeUnit

/**
 * Minuteries (extinction/allumage dans X minutes) et programmation
 * récurrente (ex: éteindre à 23h tous les jours, jours sélectionnables).
 */
class TimerActivity : AppCompatActivity() {

    private var pickedDeviceId: String? = null
    private var pickedAlias: String? = null
    private val pickedDays = mutableSetOf<Int>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_timer)
        requestNotifPermissionIfNeeded()

        findViewById<Button>(R.id.timer_pick_device).setOnClickListener {
            startActivityForResult(
                Intent(this, DevicePickerActivity::class.java).apply {
                    putExtra(DevicePickerActivity.EXTRA_TITLE_RES, R.string.timer_pick_device)
                },
                REQUEST_DEVICE
            )
        }
        findViewById<Button>(R.id.timer_start_countdown).setOnClickListener { startCountdown() }
        findViewById<Button>(R.id.timer_add_daily).setOnClickListener { addDaily() }
        findViewById<Button>(R.id.timer_exact_alarm).setOnClickListener { openExactAlarmSettings() }

        buildDayChips()
    }

    override fun onResume() {
        super.onResume()
        refreshExactAlarmHint()
        refreshLists()
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_DEVICE && resultCode == RESULT_OK) {
            pickedDeviceId = data?.getStringExtra(DevicePickerActivity.EXTRA_DEVICE_ID)
            pickedAlias = data?.getStringExtra(DevicePickerActivity.EXTRA_DEVICE_ALIAS)
            refreshPickedLabel()
        }
    }

    // -- countdown ----------------------------------------------------------

    private fun startCountdown() {
        val deviceId = pickedDeviceId
        if (deviceId.isNullOrEmpty()) {
            toast(getString(R.string.timer_need_device))
            return
        }
        val minutes = findViewById<EditText>(R.id.timer_minutes).text.toString().toIntOrNull()
        if (minutes == null || minutes < 1 || minutes > 10080) {
            toast(getString(R.string.timer_bad_minutes))
            return
        }
        val targetOn = findViewById<Switch>(R.id.timer_countdown_on).isChecked
        TimerManager.scheduleCountdown(this, deviceId, pickedAlias ?: deviceId, minutes, targetOn)
        findViewById<EditText>(R.id.timer_minutes).text.clear()
        toast(getString(R.string.timer_started, minutes))
        refreshLists()
    }

    // -- daily --------------------------------------------------------------

    private fun addDaily() {
        val deviceId = pickedDeviceId
        if (deviceId.isNullOrEmpty()) {
            toast(getString(R.string.timer_need_device))
            return
        }
        val picker: TimePicker = findViewById(R.id.timer_time)
        val targetOn = findViewById<Switch>(R.id.timer_daily_on).isChecked
        TimerManager.scheduleDaily(
            this, deviceId, pickedAlias ?: deviceId,
            picker.hour, picker.minute, targetOn, pickedDays.toSet()
        )
        toast(getString(R.string.schedule_added))
        refreshLists()
    }

    // -- lists --------------------------------------------------------------

    private fun refreshLists() {
        refreshPickedLabel()
        val countdownBox: LinearLayout = findViewById(R.id.timer_countdown_list)
        countdownBox.removeAllViews()
        val now = System.currentTimeMillis()
        val countdowns = TimerStore.countdowns(this).sortedBy { it.triggerAtMillis }
        findViewById<View>(R.id.timer_countdown_empty).visibility =
            if (countdowns.isEmpty()) View.VISIBLE else View.GONE
        for (timer in countdowns) {
            val remaining = timer.triggerAtMillis - now
            val label = if (remaining > 0) {
                val h = TimeUnit.MILLISECONDS.toHours(remaining)
                val m = TimeUnit.MILLISECONDS.toMinutes(remaining) % 60
                getString(
                    R.string.timer_row,
                    timer.deviceAlias,
                    getString(if (timer.targetOn) R.string.state_on else R.string.state_off),
                    if (h > 0) getString(R.string.timer_remaining_hm, h, m)
                    else getString(R.string.timer_remaining_m, m)
                )
            } else {
                getString(R.string.timer_row_firing, timer.deviceAlias)
            }
            countdownBox.addView(rowView(label) {
                TimerManager.cancelCountdown(this, timer.id)
                refreshLists()
            })
        }

        val dailyBox: LinearLayout = findViewById(R.id.timer_daily_list)
        dailyBox.removeAllViews()
        val dailies = TimerStore.dailies(this).sortedWith(compareBy({ it.hour }, { it.minute }))
        findViewById<View>(R.id.timer_daily_empty).visibility =
            if (dailies.isEmpty()) View.VISIBLE else View.GONE
        for (schedule in dailies) {
            val daysLabel = if (schedule.days.isEmpty()) {
                getString(R.string.schedule_every_day)
            } else {
                schedule.days.sorted().joinToString(" ") { dayShort(it) }
            }
            val label = getString(
                R.string.schedule_row,
                schedule.deviceAlias,
                getString(if (schedule.targetOn) R.string.state_on else R.string.state_off),
                String.format("%02d:%02d", schedule.hour, schedule.minute),
                daysLabel
            )
            val row = rowView(label, onDelete = {
                TimerManager.cancelDaily(this, schedule.id)
                refreshLists()
            })
            val toggle = Switch(this).apply {
                isChecked = schedule.enabled
                setOnCheckedChangeListener { _, checked ->
                    TimerManager.setDailyEnabled(this@TimerActivity, schedule.id, checked)
                }
            }
            row.addView(toggle)
            dailyBox.addView(row)
        }
    }

    private fun rowView(label: String, onDelete: () -> Unit): LinearLayout {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(4, 8, 4, 8)
        }
        val labelView = TextView(this).apply {
            text = label
            setTextColor(ContextCompat.getColor(this@TimerActivity, R.color.op_text_primary))
            textSize = 14f
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        val del = Button(this).apply {
            setText(getString(R.string.delete))
            setOnClickListener { onDelete() }
        }
        row.addView(labelView)
        row.addView(del)
        return row
    }

    // -- misc UI ------------------------------------------------------------

    private fun refreshPickedLabel() {
        findViewById<TextView>(R.id.timer_device).text =
            pickedAlias ?: getString(R.string.timer_no_device)
    }

    private fun buildDayChips() {
        val box: LinearLayout = findViewById(R.id.timer_days)
        box.removeAllViews()
        val order = listOf(
            Calendar.MONDAY, Calendar.TUESDAY, Calendar.WEDNESDAY, Calendar.THURSDAY,
            Calendar.FRIDAY, Calendar.SATURDAY, Calendar.SUNDAY
        )
        for (day in order) {
            val chip = Button(this).apply {
                text = dayShort(day)
                alpha = 0.45f
                setOnClickListener {
                    if (pickedDays.remove(day)) alpha = 0.45f
                    else {
                        pickedDays.add(day)
                        alpha = 1f
                    }
                }
            }
            box.addView(chip)
        }
    }

    private fun dayShort(day: Int): String {
        return when (day) {
            Calendar.MONDAY -> getString(R.string.day_mon)
            Calendar.TUESDAY -> getString(R.string.day_tue)
            Calendar.WEDNESDAY -> getString(R.string.day_wed)
            Calendar.THURSDAY -> getString(R.string.day_thu)
            Calendar.FRIDAY -> getString(R.string.day_fri)
            Calendar.SATURDAY -> getString(R.string.day_sat)
            else -> getString(R.string.day_sun)
        }
    }

    private fun refreshExactAlarmHint() {
        val hint: TextView = findViewById(R.id.timer_exact_hint)
        val btn: Button = findViewById(R.id.timer_exact_alarm)
        if (TimerManager.canScheduleExact(this)) {
            hint.visibility = View.GONE
            btn.visibility = View.GONE
        } else {
            hint.visibility = View.VISIBLE
            btn.visibility = View.VISIBLE
        }
    }

    private fun openExactAlarmSettings() {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                startActivity(Intent(Settings.ACTION_REQUEST_SCHEDULE_EXACT_ALARM))
            }
        } catch (_: Exception) {
        }
    }

    private fun requestNotifPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
            ) {
                ActivityCompat.requestPermissions(
                    this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), 101
                )
            }
        }
    }

    private fun toast(text: String) {
        Toast.makeText(this, text, Toast.LENGTH_SHORT).show()
    }

    companion object {
        const val REQUEST_DEVICE = 51
    }
}
