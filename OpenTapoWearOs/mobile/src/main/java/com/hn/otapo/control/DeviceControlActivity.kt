package com.hn.otapo.control

import android.os.Bundle
import android.view.View
import android.widget.SeekBar
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.hn.otapo.R
import com.hn.otapo.data.DeviceController
import com.hn.otapo.data.DeviceStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * Per-device control screen, opened by tapping a device card.
 *
 * Shows exactly the controls the detected model supports:
 * - every device: on/off switch
 * - L510/L520/L530/L610/L630: brightness slider (1-100)
 * - L530/L630 (RGB): circular color picker + color-temperature slider
 * - L510/L520/L610: color-temperature slider (white range 2500-6500K)
 * - P110: shortcut to the energy monitor
 *
 * Commands are sent on release (not on every tick) and failures surface as
 * toasts; the cached state is refreshed so lists/widgets/tiles follow.
 */
class DeviceControlActivity : AppCompatActivity() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private var deviceId: String = ""
    private var sending = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_device_control)

        deviceId = intent.getStringExtra(EXTRA_DEVICE_ID) ?: ""
        val device = DeviceStore.findById(this, deviceId)
        if (device == null) {
            toast(getString(R.string.widget_no_device))
            finish()
            return
        }

        findViewById<TextView>(R.id.control_alias).text = device.alias
        findViewById<TextView>(R.id.control_model).text = device.model.toString()

        val power: Switch = findViewById(R.id.control_power)
        power.isChecked = device.status.deviceOn
        power.setOnCheckedChangeListener { _, checked ->
            runOp(
                op = { DeviceController.toggle(this, deviceId, checked) },
                ok = getString(if (checked) R.string.state_on else R.string.state_off)
            )
        }

        val dimmable = DeviceCapabilities.isDimmable(device.model, device.type)
        val rgb = DeviceCapabilities.isRgb(device.model, device.type)

        // -- brightness --
        val brightSection: View = findViewById(R.id.control_brightness_section)
        if (dimmable) {
            brightSection.visibility = View.VISIBLE
            val seek: SeekBar = findViewById(R.id.control_brightness)
            val label: TextView = findViewById(R.id.control_brightness_label)
            val initial = (device.status.brightness ?: 100).coerceIn(1, 100)
            seek.progress = initial
            label.text = getString(R.string.control_brightness_value, initial)
            seek.setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
                override fun onProgressChanged(s: SeekBar, progress: Int, fromUser: Boolean) {
                    if (fromUser) label.text = getString(R.string.control_brightness_value, progress.coerceAtLeast(1))
                }

                override fun onStartTrackingTouch(s: SeekBar) {}
                override fun onStopTrackingTouch(s: SeekBar) {
                    val level = s.progress.coerceAtLeast(1)
                    runOp(
                        op = { LightController.setBrightness(this@DeviceControlActivity, deviceId, level) },
                        ok = getString(R.string.control_brightness_value, level)
                    )
                }
            })
        } else {
            brightSection.visibility = View.GONE
        }

        // -- color wheel (RGB only) --
        val colorSection: View = findViewById(R.id.control_color_section)
        if (rgb) {
            colorSection.visibility = View.VISIBLE
            val wheel: ColorWheelView = findViewById(R.id.control_wheel)
            val hue = device.status.hue
            val sat = device.status.saturation
            if (hue != null && sat != null) wheel.setSelected(hue, sat)
            wheel.onColorChosen = { h, s ->
                runOp(
                    op = { LightController.setColor(this@DeviceControlActivity, deviceId, h, s) },
                    ok = getString(R.string.control_color_value, h, s)
                )
            }
        } else {
            colorSection.visibility = View.GONE
        }

        // -- color temperature (all bulbs) --
        val tempSection: View = findViewById(R.id.control_temp_section)
        if (dimmable) {
            tempSection.visibility = View.VISIBLE
            val seek: SeekBar = findViewById(R.id.control_temp)
            val label: TextView = findViewById(R.id.control_temp_label)
            // map 0..40 -> 2500..6500K
            val initial = ((device.status.colorTemperature ?: 4000) - 2500) / 100
            seek.progress = initial.coerceIn(0, 40)
            label.text = getString(R.string.control_temp_value, seek.progress * 100 + 2500)
            seek.setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
                override fun onProgressChanged(s: SeekBar, progress: Int, fromUser: Boolean) {
                    if (fromUser) label.text = getString(R.string.control_temp_value, progress * 100 + 2500)
                }

                override fun onStartTrackingTouch(s: SeekBar) {}
                override fun onStopTrackingTouch(s: SeekBar) {
                    val kelvin = s.progress * 100 + 2500
                    runOp(
                        op = { LightController.setColorTemp(this@DeviceControlActivity, deviceId, kelvin) },
                        ok = getString(R.string.control_temp_value, kelvin)
                    )
                }
            })
        } else {
            tempSection.visibility = View.GONE
        }

        // -- energy shortcut (P110; EnergyActivity is added by the energy feature) --
        val energyBtn: View = findViewById(R.id.control_energy)
        if (DeviceCapabilities.supportsEnergy(device.model)) {
            energyBtn.visibility = View.VISIBLE
            energyBtn.setOnClickListener {
                val intent = android.content.Intent(ACTION_VIEW_ENERGY).apply {
                    putExtra(EXTRA_DEVICE_ID, deviceId)
                }
                if (intent.resolveActivity(packageManager) != null) {
                    startActivity(intent)
                } else {
                    toast(getString(R.string.error_generic, "energy"))
                }
            }
        } else {
            energyBtn.visibility = View.GONE
        }
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private fun runOp(op: suspend () -> Any, ok: String) {
        setBusy(true)
        scope.launch {
            try {
                when (val result = op()) {
                    is DeviceController.ControlResult.Success -> toast("${result.device.alias} : $ok")
                    is LightController.LightResult.Ok -> toast(ok)
                    is DeviceController.ControlResult.Error -> toast(getString(R.string.error_generic, result.message))
                    is LightController.LightResult.Error -> toast(getString(R.string.error_generic, result.message))
                    else -> toast(getString(R.string.error_generic, ""))
                }
            } finally {
                setBusy(false)
            }
        }
    }

    private fun setBusy(busy: Boolean) {
        sending += if (busy) 1 else -1
        findViewById<View>(R.id.control_progress).visibility =
            if (sending > 0) View.VISIBLE else View.GONE
    }

    private fun toast(text: String) {
        Toast.makeText(this, text, Toast.LENGTH_SHORT).show()
    }

    companion object {
        const val EXTRA_DEVICE_ID = "device_id"
        const val ACTION_VIEW_ENERGY = "com.hn.otapo.energy.VIEW"
    }
}
