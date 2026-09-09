package dev.veeso.opentapo.mobile.data

import android.content.Context
import dev.veeso.opentapo.mobile.MainActivity
import dev.veeso.opentapo.mobile.view.intent_data.Credentials

/**
 * Single point of access to the Tapo credentials used for local KLAP control.
 *
 * Today this reads the credentials stored by [MainActivity] (single account).
 * The multi-account feature plugs in here: it will return the credentials of
 * the currently active account while keeping the same API, so widgets, tiles,
 * timers, geofences and voice shortcuts keep working unchanged.
 */
object CredentialsProvider {

    fun get(context: Context): Credentials? {
        val prefs = context.getSharedPreferences(MainActivity.PREFS, Context.MODE_PRIVATE)
        val user = prefs.getString(MainActivity.KEY_USER, null) ?: return null
        val pass = prefs.getString(MainActivity.KEY_PASS, null) ?: return null
        if (user.isBlank() || pass.isBlank()) return null
        return Credentials(user, pass)
    }
}
