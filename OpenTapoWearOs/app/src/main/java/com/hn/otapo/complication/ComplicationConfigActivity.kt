package com.hn.otapo.complication

import android.app.Activity
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

/**
 * Picks which plug the watch-face complication displays.
 *
 * Launched either from the watch-face editor (with the standard
 * complication-config extras) or directly from [com.hn.otapo.MainActivity].
 * Choosing a plug persists it and asks the system for fresh complication data.
 */
class ComplicationConfigActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(com.hn.otapo.R.layout.activity_complication_config)

        val box: LinearLayout = findViewById(com.hn.otapo.R.id.complication_device_box)
        val empty: TextView = findViewById(com.hn.otapo.R.id.complication_empty)
        val devices = ComplicationHelper.allCached(this)
        val selected = ComplicationHelper.selectedDeviceId(this)

        if (devices.isEmpty()) {
            empty.visibility = View.VISIBLE
            empty.text = getString(com.hn.otapo.R.string.complication_no_device)
        } else {
            empty.visibility = View.GONE
            for (device in devices.sortedBy { it.alias }) {
                val btn = Button(this).apply {
                    val mark = if (device.id == selected) "● " else ""
                    text = mark + device.alias + (if (device.status.deviceOn) " (ON)" else " (OFF)")
                    setOnClickListener { onPick(device.id, device.alias) }
                }
                box.addView(btn)
            }
        }
        Log.d(TAG, "config opened with ${devices.size} device(s)")
    }

    private fun onPick(deviceId: String, alias: String) {
        ComplicationHelper.selectDevice(this, deviceId, alias)
        setResult(RESULT_OK)
        finish()
    }

    companion object {
        private const val TAG = "ComplicationConfig"
    }
}
