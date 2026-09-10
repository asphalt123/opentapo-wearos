package com.hn.otapo.monitor

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.hn.otapo.R

/**
 * Surveillance hors-ligne : alerte quand une prise devient injoignable,
 * revient en ligne ou change d'état sans passer par l'app, + notification
 * persistante optionnelle avec le compte des prises allumées.
 */
class MonitorSettingsActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_monitor)

        val enabled: Switch = findViewById(R.id.monitor_enabled)
        val persistent: Switch = findViewById(R.id.monitor_persistent)
        val intervalLabel: TextView = findViewById(R.id.monitor_interval_label)

        enabled.isChecked = DeviceMonitorStore.isEnabled(this)
        persistent.isChecked = DeviceMonitorStore.isPersistent(this)
        intervalLabel.text = intervalText(DeviceMonitorStore.intervalMin(this))

        enabled.setOnCheckedChangeListener { _, checked ->
            DeviceMonitorStore.setEnabled(this, checked)
            if (checked) {
                requestNotifPermissionIfNeeded()
                DeviceMonitorScheduler.schedule(this)
                DeviceMonitorReceiver.refreshPersistent(this)
            } else {
                DeviceMonitorScheduler.cancel(this)
                DeviceMonitorReceiver.refreshPersistent(this)
            }
        }
        persistent.setOnCheckedChangeListener { _, checked ->
            DeviceMonitorStore.setPersistent(this, checked)
            requestNotifPermissionIfNeeded()
            DeviceMonitorReceiver.refreshPersistent(this)
        }
        findViewById<Button>(R.id.monitor_interval_15).setOnClickListener { setInterval(15, intervalLabel) }
        findViewById<Button>(R.id.monitor_interval_30).setOnClickListener { setInterval(30, intervalLabel) }
        findViewById<Button>(R.id.monitor_interval_60).setOnClickListener { setInterval(60, intervalLabel) }
        findViewById<Button>(R.id.monitor_check_now).setOnClickListener {
            requestNotifPermissionIfNeeded()
            Toast.makeText(this, getString(R.string.monitor_checking), Toast.LENGTH_SHORT).show()
            DeviceMonitorScheduler.runNow(this)
        }
    }

    private fun setInterval(minutes: Int, label: TextView) {
        DeviceMonitorStore.setIntervalMin(this, minutes)
        DeviceMonitorScheduler.schedule(this)
        label.text = intervalText(minutes)
        Toast.makeText(this, intervalText(minutes), Toast.LENGTH_SHORT).show()
    }

    private fun intervalText(minutes: Int): String =
        getString(R.string.monitor_interval_value, minutes)

    private fun requestNotifPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
            ) {
                ActivityCompat.requestPermissions(
                    this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), 102
                )
            }
        }
    }
}
