package com.hn.otapo.voice

import android.content.Context
import android.content.Intent
import android.content.pm.ShortcutInfo
import android.content.pm.ShortcutManager
import android.graphics.drawable.Icon
import android.os.Build
import android.util.Log
import com.hn.otapo.R
import com.hn.otapo.data.DeviceStore

/**
 * Publie un raccourci dynamique par prise ("Salon ON/OFF") : appui long
 * sur l'icône du launcher + exposition à l'Assistant Google via les
 * capabilities déclarées dans shortcuts.xml.
 *
 * Appelé après chaque scan réussi ([com.hn.otapo.MainActivity])
 * et depuis l'écran d'aide vocale.
 */
object VoiceShortcutManager {

    private const val TAG = "VoiceShortcuts"
    private const val MAX_SHORTCUTS = 8

    fun refresh(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N_MR1) return
        try {
            val manager = context.getSystemService(ShortcutManager::class.java) ?: return
            val devices = DeviceStore.loadCached(context).sortedBy { it.alias }.take(MAX_SHORTCUTS)
            val shortcuts = devices.map { device ->
                val intent = Intent(context, VoiceActionActivity::class.java).apply {
                    action = VoiceActionActivity.ACTION_TOGGLE
                    putExtra(VoiceActionActivity.EXTRA_DEVICE_ID, device.id)
                }
                ShortcutInfo.Builder(context, "toggle_${device.id}")
                    .setShortLabel(device.alias)
                    .setLongLabel(
                        context.getString(
                            R.string.voice_shortcut_long,
                            device.alias,
                            context.getString(
                                if (device.status.deviceOn) R.string.state_off else R.string.state_on
                            )
                        )
                    )
                    .setIcon(Icon.createWithResource(context, R.drawable.ic_tile))
                    .setIntent(intent)
                    .build()
            }
            manager.dynamicShortcuts = shortcuts
            Log.i(TAG, "published ${shortcuts.size} dynamic shortcut(s)")
        } catch (e: Exception) {
            Log.w(TAG, "refresh failed: ${e.message}")
        }
    }
}
