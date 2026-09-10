package com.hn.otapo.tile

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.hn.otapo.R
import com.hn.otapo.common.DevicePickerActivity
import com.hn.otapo.data.DeviceStore

/**
 * Long-press target of the QS tile (and menu entry): choose which plug/bulb
 * the tile controls.
 */
class TileSettingsActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_tile_settings)
        refreshLabel()
        findViewById<Button>(R.id.tile_pick).setOnClickListener {
            val intent = Intent(this, DevicePickerActivity::class.java).apply {
                putExtra(DevicePickerActivity.EXTRA_TITLE_RES, R.string.tile_pick_title)
            }
            startActivityForResult(intent, REQUEST_PICK)
        }
        findViewById<Button>(R.id.tile_clear).setOnClickListener {
            TileHelper.setFavorite(this, null)
            refreshLabel()
        }
        findViewById<Button>(R.id.tile_done).setOnClickListener { finish() }
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_PICK && resultCode == RESULT_OK) {
            val id = data?.getStringExtra(DevicePickerActivity.EXTRA_DEVICE_ID)
            if (!id.isNullOrEmpty()) {
                TileHelper.setFavorite(this, id)
            }
            refreshLabel()
        }
    }

    private fun refreshLabel() {
        val label: TextView = findViewById(R.id.tile_current)
        val id = TileHelper.favoriteDeviceId(this)
        val device = id?.let { DeviceStore.findById(this, it) }
        label.text = if (device != null) {
            getString(R.string.tile_current, device.alias, device.model.toString())
        } else {
            getString(R.string.tile_no_favorite)
        }
        findViewById<View>(R.id.tile_clear).visibility =
            if (device != null) View.VISIBLE else View.GONE
    }

    companion object {
        const val REQUEST_PICK = 41
    }
}
