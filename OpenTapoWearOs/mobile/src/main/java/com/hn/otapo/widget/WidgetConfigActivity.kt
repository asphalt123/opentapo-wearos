package com.hn.otapo.widget

import android.appwidget.AppWidgetManager
import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.hn.otapo.R
import com.hn.otapo.data.DeviceStore

/**
 * Configuration screen for [DeviceWidgetProvider]: pick which plug/bulb this
 * widget instance controls. Shown automatically when the widget is placed.
 */
class WidgetConfigActivity : AppCompatActivity() {

    private var widgetId: Int = AppWidgetManager.INVALID_APPWIDGET_ID

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_widget_config)

        widgetId = intent?.extras?.getInt(
            AppWidgetManager.EXTRA_APPWIDGET_ID,
            AppWidgetManager.INVALID_APPWIDGET_ID
        ) ?: AppWidgetManager.INVALID_APPWIDGET_ID
        if (widgetId == AppWidgetManager.INVALID_APPWIDGET_ID) {
            finish()
            return
        }
        setResult(RESULT_CANCELED)

        val list: LinearLayout = findViewById(R.id.widget_config_list)
        val empty: TextView = findViewById(R.id.widget_config_empty)
        val devices = DeviceStore.loadCached(this).sortedBy { it.alias }

        if (devices.isEmpty()) {
            empty.visibility = View.VISIBLE
            empty.text = getString(R.string.widget_config_empty)
        } else {
            empty.visibility = View.GONE
            for (device in devices) {
                val btn = Button(this).apply {
                    // dark-theme friendly outlined button look
                    text = "${device.alias}  •  ${device.model}"
                    textAlignment = View.TEXT_ALIGNMENT_VIEW_START
                    setOnClickListener { choose(device.id) }
                }
                list.addView(btn)
            }
        }

        findViewById<Button>(R.id.widget_config_cancel).setOnClickListener { finish() }
    }

    private fun choose(deviceId: String) {
        DeviceWidgetHelper.bind(this, widgetId, deviceId)
        val result = Intent().putExtra(AppWidgetManager.EXTRA_APPWIDGET_ID, widgetId)
        setResult(RESULT_OK, result)
        finish()
    }
}
