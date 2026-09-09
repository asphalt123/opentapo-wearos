package dev.veeso.opentapo.mobile.data

import android.content.Context
import dev.veeso.opentapo.mobile.MainActivity
import dev.veeso.opentapo.mobile.view.intent_data.Credentials

/**
 * Single point of access to the Tapo credentials used for local KLAP control.
 *
 * Returns the credentials of the currently active multi-account
 * ([dev.veeso.opentapo.mobile.account.AccountStore]) so widgets, tiles,
 * timers, geofences and voice shortcuts keep working unchanged when the
 * user switches account (maison / travail…).
 */
object CredentialsProvider {

    fun get(context: Context): Credentials? {
        return try {
            dev.veeso.opentapo.mobile.account.AccountStore.activeCredentials(context)
        } catch (_: Exception) {
            val prefs = context.getSharedPreferences(MainActivity.PREFS, Context.MODE_PRIVATE)
            val user = prefs.getString(MainActivity.KEY_USER, null) ?: return null
            val pass = prefs.getString(MainActivity.KEY_PASS, null) ?: return null
            if (user.isBlank() || pass.isBlank()) return null
            Credentials(user, pass)
        }
    }
}
