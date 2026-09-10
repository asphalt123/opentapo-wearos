package com.hn.otapo.voice

import android.content.Intent
import android.os.Bundle
import android.util.Log
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
import kotlinx.coroutines.withContext

/**
 * Point d'entrée unique des commandes vocales / raccourcis / deep links.
 *
 * Sources gérées :
 * - App Actions `actions.intent.OPEN_APP_FEATURE` : « Ok Google, allume la
 *   prise du salon avec OpenTapo » -> deep link `opentapo://voice?feature=…`
 * - deep links `opentapo://toggle?device=<alias|id>&state=on|off|toggle`
 *   et `https://otapo.hn/toggle?device=…&state=…`
 * - raccourcis launcher (statiques + dynamiques) : toggle / tout ON / tout OFF
 *
 * Le nom d'appareil est apparié en insensible à la casse, avec correspondance
 * partielle (ex : "salon" matche "Prise salon") ; l'état est déduit des mots
 * clés FR/EN ("allume/on" vs "éteins/off"), sinon on bascule.
 */
class VoiceActionActivity : AppCompatActivity() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        scope.launch {
            val message = try {
                handle(intent)
            } catch (e: Exception) {
                Log.e(TAG, "voice action failed", e)
                getString(R.string.error_generic, e.message)
            }
            Toast.makeText(this@VoiceActionActivity, message, Toast.LENGTH_LONG).show()
            finish()
        }
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private suspend fun handle(intent: Intent): String {
        // 1. actions globales (raccourcis statiques "tout allumer/éteindre")
        when (intent.action) {
            ACTION_ALL_ON -> return setAll(true)
            ACTION_ALL_OFF -> return setAll(false)
        }
        // 2. raccourci dynamique / appel explicite par id
        val deviceId = intent.getStringExtra(EXTRA_DEVICE_ID)
        val stateExtra = intent.getStringExtra(EXTRA_STATE)
        if (!deviceId.isNullOrEmpty()) {
            return toggleById(deviceId, parseState(stateExtra))
        }
        // 3. deep link / App Action
        val uri = intent.data
        if (uri != null) {
            val device = uri.getQueryParameter("device") ?: uri.getQueryParameter("feature") ?: ""
            val state = uri.getQueryParameter("state") ?: device
            if (device.isNotEmpty()) {
                return toggleByQuery(device, parseState(state))
            }
        }
        // 4. App Action sans paramètre exploitable
        return getString(R.string.voice_no_match)
    }

    private suspend fun toggleById(deviceId: String, state: Boolean?): String {
        val device = DeviceStore.findById(this, deviceId)
            ?: return getString(R.string.widget_no_device)
        return when (val r = DeviceController.toggle(this, deviceId, state)) {
            is DeviceController.ControlResult.Success ->
                "${device.alias} : " + getString(if (r.newState) R.string.state_on else R.string.state_off)
            is DeviceController.ControlResult.NoCredentials -> getString(R.string.voice_no_match)
            is DeviceController.ControlResult.UnknownDevice -> getString(R.string.widget_no_device)
            is DeviceController.ControlResult.Error -> getString(R.string.error_generic, r.message)
        }
    }

    private suspend fun toggleByQuery(query: String, state: Boolean?): String {
        val devices = DeviceStore.loadCached(this)
        if (devices.isEmpty()) return getString(R.string.voice_no_match)
        val q = query.lowercase()
        val match = devices.firstOrNull { it.alias.equals(query, ignoreCase = true) }
            ?: devices.firstOrNull { it.alias.lowercase().contains(q) || q.contains(it.alias.lowercase()) }
            ?: devices.firstOrNull { it.id.equals(query, ignoreCase = true) }
            ?: return getString(R.string.voice_no_match)
        return toggleById(match.id, state)
    }

    private suspend fun setAll(targetOn: Boolean): String {
        val devices = DeviceStore.loadCached(this)
        if (devices.isEmpty()) return getString(R.string.voice_no_match)
        val results = withContext(Dispatchers.IO) {
            val out = mutableMapOf<String, DeviceController.ControlResult>()
            for (device in devices) {
                out[device.id] = DeviceController.toggle(this@VoiceActionActivity, device.id, targetOn)
            }
            out
        }
        val ok = results.values.count { it is DeviceController.ControlResult.Success }
        return getString(R.string.voice_all_result, ok, devices.size)
    }

    /** on/allume/start -> true, off/éteins/stop -> false, sinon null (bascule). */
    private fun parseState(text: String?): Boolean? {
        val t = text?.lowercase() ?: return null
        return when {
            t.contains("allum") || t.contains("turn on") || t == "on" || t.contains("démarr") || t.contains("start") -> true
            t.contains("étein") || t.contains("etein") || t.contains("turn off") || t == "off" || t.contains("stop") || t.contains("arrêt") || t.contains("arret") -> false
            else -> null
        }
    }

    companion object {
        private const val TAG = "VoiceAction"
        const val ACTION_TOGGLE = "com.hn.otapo.voice.TOGGLE"
        const val ACTION_ALL_ON = "com.hn.otapo.voice.ALL_ON"
        const val ACTION_ALL_OFF = "com.hn.otapo.voice.ALL_OFF"
        const val EXTRA_DEVICE_ID = "device_id"
        const val EXTRA_STATE = "state"
    }
}
