package com.hn.otapo.data

import android.content.Context
import com.hn.otapo.MainActivity
import com.hn.otapo.view.intent_data.Credentials

/**
 * Single point of access to the Tapo credentials used for local KLAP control.
 *
 * Returns the credentials of the currently active multi-account
 * ([com.hn.otapo.account.AccountStore]) so widgets, tiles,
 * timers, geofences and voice shortcuts keep working unchanged when the
 * user switches account (maison / travail…).
 */
object CredentialsProvider {

    fun get(context: Context): Credentials? {
        return try {
            com.hn.otapo.account.AccountStore.activeCredentials(context)
        } catch (_: Exception) {
            val prefs = context.getSharedPreferences(MainActivity.PREFS, Context.MODE_PRIVATE)
            val user = prefs.getString(MainActivity.KEY_USER, null) ?: return null
            val pass = prefs.getString(MainActivity.KEY_PASS, null) ?: return null
            if (user.isBlank() || pass.isBlank()) return null
            Credentials(user, pass)
        }
    }
}
