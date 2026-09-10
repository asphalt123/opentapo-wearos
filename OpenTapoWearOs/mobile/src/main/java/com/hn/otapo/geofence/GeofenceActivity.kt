package com.hn.otapo.geofence

import android.Manifest
import android.annotation.SuppressLint
import android.app.AlertDialog
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.SeekBar
import android.widget.Spinner
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.google.android.gms.location.LocationServices
import com.hn.otapo.R
import com.hn.otapo.data.DeviceStore

/**
 * Définit les zones GPS : nom, coordonnées (+ bouton "ma position"),
 * rayon (50–1000 m), prises cibles, action à l'entrée / à la sortie.
 */
class GeofenceActivity : AppCompatActivity() {

    private var radiusMeters = 200
    private val pickedDeviceIds = mutableSetOf<String>()
    private lateinit var radiusLabel: TextView
    private lateinit var devicesLabel: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_geofence)

        radiusLabel = findViewById(R.id.geofence_radius_label)
        devicesLabel = findViewById(R.id.geofence_devices_label)
        updateRadiusLabel()
        refreshDevicesLabel()

        val seek: SeekBar = findViewById(R.id.geofence_radius)
        seek.max = 950
        seek.progress = radiusMeters - 50
        seek.setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
            override fun onProgressChanged(s: SeekBar, progress: Int, fromUser: Boolean) {
                radiusMeters = 50 + progress
                if (fromUser) updateRadiusLabel()
            }

            override fun onStartTrackingTouch(s: SeekBar) {}
            override fun onStopTrackingTouch(s: SeekBar) {}
        })

        setupActionSpinner(R.id.geofence_enter, "ON")
        setupActionSpinner(R.id.geofence_exit, "OFF")

        findViewById<Button>(R.id.geofence_here).setOnClickListener { fillCurrentLocation() }
        findViewById<Button>(R.id.geofence_pick_devices).setOnClickListener { pickDevices() }
        findViewById<Button>(R.id.geofence_save).setOnClickListener { saveZone() }

        requestLocationPermission()
    }

    override fun onResume() {
        super.onResume()
        refreshList()
    }

    // -- form ----------------------------------------------------------------

    private fun setupActionSpinner(viewId: Int, default: String) {
        val spinner: Spinner = findViewById(viewId)
        spinner.adapter = ArrayAdapter(
            this, android.R.layout.simple_spinner_dropdown_item,
            listOf(
                getString(R.string.geofence_action_on),
                getString(R.string.geofence_action_off),
                getString(R.string.geofence_action_none)
            )
        )
        spinner.setSelection(
            when (default) {
                "ON" -> 0
                "OFF" -> 1
                else -> 2
            }
        )
    }

    private fun spinnerAction(viewId: Int): String {
        val spinner: Spinner = findViewById(viewId)
        return when (spinner.selectedItemPosition) {
            0 -> "ON"
            1 -> "OFF"
            else -> "NONE"
        }
    }

    private fun updateRadiusLabel() {
        radiusLabel.text = getString(R.string.geofence_radius_value, radiusMeters)
    }

    private fun refreshDevicesLabel() {
        val devices = DeviceStore.loadCached(this).associateBy { it.id }
        devicesLabel.text = if (pickedDeviceIds.isEmpty()) {
            getString(R.string.geofence_no_device)
        } else {
            pickedDeviceIds.mapNotNull { devices[it]?.alias }.sorted().joinToString(", ")
        }
    }

    private fun pickDevices() {
        val devices = DeviceStore.loadCached(this)
        if (devices.isEmpty()) {
            toast(getString(R.string.widget_config_empty))
            return
        }
        val names = devices.map { it.alias }.toTypedArray()
        val checked = devices.map { pickedDeviceIds.contains(it.id) }.toBooleanArray()
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.geofence_pick_devices))
            .setMultiChoiceItems(names, checked) { _, which, isChecked ->
                val id = devices[which].id
                if (isChecked) pickedDeviceIds.add(id) else pickedDeviceIds.remove(id)
            }
            .setPositiveButton(getString(R.string.save)) { _, _ -> refreshDevicesLabel() }
            .setNegativeButton(getString(R.string.cancel), null)
            .show()
    }

    @SuppressLint("MissingPermission")
    private fun fillCurrentLocation() {
        if (!hasFineLocation()) {
            requestLocationPermission()
            toast(getString(R.string.geofence_need_location))
            return
        }
        try {
            LocationServices.getFusedLocationProviderClient(this).lastLocation
                .addOnSuccessListener { loc ->
                    if (loc == null) {
                        toast(getString(R.string.geofence_no_fix))
                        return@addOnSuccessListener
                    }
                    findViewById<EditText>(R.id.geofence_lat).setText(loc.latitude.toString())
                    findViewById<EditText>(R.id.geofence_lng).setText(loc.longitude.toString())
                    toast(getString(R.string.geofence_fix_ok))
                }
                .addOnFailureListener { toast(getString(R.string.error_generic, it.message)) }
        } catch (e: SecurityException) {
            toast(getString(R.string.geofence_need_location))
        }
    }

    private fun saveZone() {
        val label = findViewById<EditText>(R.id.geofence_label).text.toString().trim()
        val lat = findViewById<EditText>(R.id.geofence_lat).text.toString().toDoubleOrNull()
        val lng = findViewById<EditText>(R.id.geofence_lng).text.toString().toDoubleOrNull()
        if (label.isEmpty()) {
            toast(getString(R.string.geofence_need_label))
            return
        }
        if (lat == null || lat !in -90.0..90.0 || lng == null || lng !in -180.0..180.0) {
            toast(getString(R.string.geofence_need_coords))
            return
        }
        if (pickedDeviceIds.isEmpty()) {
            toast(getString(R.string.timer_need_device))
            return
        }
        if (!hasFineLocation()) {
            requestLocationPermission()
            toast(getString(R.string.geofence_need_location))
            return
        }
        GeofenceStore.add(
            this,
            HomeZone(
                label = label,
                latitude = lat,
                longitude = lng,
                radiusMeters = radiusMeters.toFloat(),
                deviceIds = pickedDeviceIds.toList(),
                enterAction = spinnerAction(R.id.geofence_enter),
                exitAction = spinnerAction(R.id.geofence_exit)
            )
        )
        GeofenceManager.refresh(this)
        findViewById<EditText>(R.id.geofence_label).text.clear()
        pickedDeviceIds.clear()
        refreshDevicesLabel()
        toast(getString(R.string.geofence_added, label))
        refreshList()
    }

    // -- list -----------------------------------------------------------------

    private fun refreshList() {
        val box: LinearLayout = findViewById(R.id.geofence_list)
        box.removeAllViews()
        val zones = GeofenceStore.load(this)
        findViewById<View>(R.id.geofence_empty).visibility =
            if (zones.isEmpty()) View.VISIBLE else View.GONE
        val devices = DeviceStore.loadCached(this).associateBy { it.id }
        for (zone in zones) {
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                setPadding(4, 10, 4, 10)
            }
            val info = TextView(this).apply {
                text = describe(zone, devices.mapValues { it.value.alias })
                setTextColor(ContextCompat.getColor(this@GeofenceActivity, R.color.op_text_primary))
                textSize = 14f
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            }
            val toggle = Switch(this).apply {
                isChecked = zone.enabled
                setOnCheckedChangeListener { _, checked ->
                    GeofenceStore.setEnabled(this@GeofenceActivity, zone.id, checked)
                    GeofenceManager.refresh(this@GeofenceActivity)
                }
            }
            val del = Button(this).apply {
                text = getString(R.string.delete)
                setOnClickListener {
                    GeofenceStore.remove(this@GeofenceActivity, zone.id)
                    GeofenceManager.refresh(this@GeofenceActivity)
                    refreshList()
                }
            }
            row.addView(info)
            row.addView(toggle)
            row.addView(del)
            box.addView(row)
        }
    }

    private fun describe(zone: HomeZone, aliases: Map<String, String>): String {
        val names = zone.deviceIds.mapNotNull { aliases[it] }.sorted().joinToString(", ")
        return "${zone.label} • ${zone.radiusMeters.toInt()} m\n" +
            "→ ${actionLabel(zone.enterAction)} / ← ${actionLabel(zone.exitAction)}\n$names"
    }

    private fun actionLabel(action: String): String = when (action) {
        "ON" -> getString(R.string.geofence_action_on)
        "OFF" -> getString(R.string.geofence_action_off)
        else -> getString(R.string.geofence_action_none)
    }

    // -- permissions ------------------------------------------------------------

    private fun hasFineLocation(): Boolean =
        ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) ==
            PackageManager.PERMISSION_GRANTED

    private fun requestLocationPermission() {
        val wanted = mutableListOf(
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            wanted.add(Manifest.permission.ACCESS_BACKGROUND_LOCATION)
        }
        val missing = wanted.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }
        if (missing.isNotEmpty()) {
            ActivityCompat.requestPermissions(this, missing.toTypedArray(), 103)
        }
    }

    private fun toast(text: String) {
        Toast.makeText(this, text, Toast.LENGTH_SHORT).show()
    }
}
