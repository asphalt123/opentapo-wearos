package com.hn.otapo.common

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
 * Generic "pick one device" screen.
 *
 * Used by the QS tile favorite picker, the geofence editor, the backup
 * sharer, etc. Returns [EXTRA_DEVICE_ID] (+ [EXTRA_DEVICE_ALIAS]) via
 * `setResult(RESULT_OK)`. Callers pass an optional [EXTRA_TITLE_RES] and can
 * allow an empty choice with [EXTRA_ALLOW_NONE].
 */
class DevicePickerActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_device_picker)

        val titleRes = intent.getIntExtra(EXTRA_TITLE_RES, 0)
        if (titleRes != 0) {
            findViewById<TextView>(R.id.picker_title).setText(titleRes)
        }
        if (intent.getBooleanExtra(EXTRA_ALLOW_NONE, false)) {
            val none: Button = findViewById(R.id.picker_none)
            none.visibility = View.VISIBLE
            none.setOnClickListener {
                setResult(RESULT_OK, Intent().putExtra(EXTRA_DEVICE_ID, ""))
                finish()
            }
        }

        val list: LinearLayout = findViewById(R.id.picker_list)
        val empty: TextView = findViewById(R.id.picker_empty)
        val devices = DeviceStore.loadCached(this).sortedBy { it.alias }
        if (devices.isEmpty()) {
            empty.visibility = View.VISIBLE
        } else {
            empty.visibility = View.GONE
            for (device in devices) {
                val btn = Button(this).apply {
                    text = "${device.alias}  •  ${device.model}"
                    textAlignment = View.TEXT_ALIGNMENT_VIEW_START
                    setOnClickListener {
                        setResult(
                            RESULT_OK,
                            Intent()
                                .putExtra(EXTRA_DEVICE_ID, device.id)
                                .putExtra(EXTRA_DEVICE_ALIAS, device.alias)
                        )
                        finish()
                    }
                }
                list.addView(btn)
            }
        }
        findViewById<Button>(R.id.picker_cancel).setOnClickListener { finish() }
    }

    companion object {
        const val EXTRA_DEVICE_ID = "device_id"
        const val EXTRA_DEVICE_ALIAS = "device_alias"
        const val EXTRA_TITLE_RES = "title_res"
        const val EXTRA_ALLOW_NONE = "allow_none"
    }
}
