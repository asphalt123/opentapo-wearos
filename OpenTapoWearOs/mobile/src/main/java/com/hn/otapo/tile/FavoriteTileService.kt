package com.hn.otapo.tile

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.util.Log
import com.hn.otapo.MainActivity
import com.hn.otapo.R
import com.hn.otapo.common.DevicePickerActivity
import com.hn.otapo.data.DeviceController
import com.hn.otapo.data.DeviceStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * Quick Settings tile: toggle the user's favorite plug/bulb straight from
 * the notification shade.
 *
 * - no favorite configured yet -> tap opens the favorite picker
 * - otherwise the tile reflects the cached state (active = on) and tapping
 *   toggles the device via [DeviceController] (offline-safe: the tile flips
 *   to unavailable with a description instead of crashing)
 * - long-press opens the favorite picker (see manifest `ACTION_QS_TILE_PREFERENCES`)
 */
class FavoriteTileService : TileService() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    override fun onStartListening() {
        super.onStartListening()
        refresh()
    }

    override fun onClick() {
        super.onClick()
        val favorite = TileHelper.favoriteDeviceId(this)
        if (favorite == null) {
            openPicker()
            return
        }
        val tile = qsTile ?: return
        tile.state = Tile.STATE_UNAVAILABLE
        tile.updateTile()
        scope.launch {
            val result = DeviceController.toggle(this@FavoriteTileService, favorite)
            if (result !is DeviceController.ControlResult.Success) {
                Log.w(TAG, "tile toggle failed: $result")
            }
            refresh()
        }
    }

    private fun refresh() {
        val tile = qsTile ?: return
        val favorite = TileHelper.favoriteDeviceId(this)
        if (favorite == null) {
            tile.state = Tile.STATE_INACTIVE
            tile.contentDescription = getString(R.string.tile_no_favorite)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                tile.subtitle = getString(R.string.tile_no_favorite)
            }
            tile.updateTile()
            return
        }
        val device = DeviceStore.findById(this, favorite)
        if (device == null) {
            tile.state = Tile.STATE_UNAVAILABLE
            tile.contentDescription = getString(R.string.state_offline)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                tile.subtitle = getString(R.string.state_offline)
            }
            tile.updateTile()
            return
        }
        val isOn = device.status.deviceOn
        tile.state = if (isOn) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.contentDescription = device.alias
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = device.alias
        }
        tile.updateTile()
    }

    private fun openPicker() {
        val intent = Intent(this, DevicePickerActivity::class.java).apply {
            putExtra(DevicePickerActivity.EXTRA_TITLE_RES, R.string.tile_pick_title)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        @Suppress("DEPRECATION")
        startActivityAndCollapse(intent)
    }

    companion object {
        const val TAG = "FavoriteTile"
    }
}

/** Favorite-device preference + tile refresh requests. */
object TileHelper {

    private const val PREFS_TILE = "OpenTapoTile"
    private const val KEY_FAVORITE = "favorite_device_id"

    fun favoriteDeviceId(context: Context): String? {
        return context.getSharedPreferences(PREFS_TILE, Context.MODE_PRIVATE)
            .getString(KEY_FAVORITE, null)
    }

    fun setFavorite(context: Context, deviceId: String?) {
        context.getSharedPreferences(PREFS_TILE, Context.MODE_PRIVATE).edit()
            .putString(KEY_FAVORITE, deviceId)
            .apply()
        requestRefresh(context)
    }

    fun requestRefresh(context: Context) {
        try {
            TileService.requestListeningState(
                context,
                ComponentName(context, FavoriteTileService::class.java)
            )
        } catch (e: Exception) {
            Log.w("FavoriteTile", "requestListeningState failed: ${e.message}")
        }
    }
}
