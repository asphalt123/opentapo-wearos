package com.hn.otapo.account

import android.content.Context
import android.util.Log
import com.hn.otapo.MainActivity
import com.hn.otapo.view.intent_data.Credentials
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import java.util.UUID

/**
 * Plusieurs comptes Tapo (ex : maison + travail), un seul actif à la fois.
 *
 * - les mots de passe sont chiffrés via [AccountCrypto]
 * - le compte mono-utilisateur historique est migré en compte "Maison"
 * - basculer de compte vide le cache devices (chaque compte a son LAN),
 *   pousse les identifiants du compte actif vers la montre (Data Layer
 *   séparé par compte, voir AccountSync) et relance un scan au retour
 */
@kotlinx.serialization.Serializable
data class TapoAccount(
    val id: String = UUID.randomUUID().toString(),
    val label: String,
    val username: String,
    /** mot de passe chiffré par [AccountCrypto] */
    val secret: String
)

object AccountStore {

    private const val TAG = "Accounts"
    private const val KEY_ACCOUNTS = "tapo_accounts"
    private const val KEY_ACTIVE = "tapo_active_account"

    const val ACCOUNT_PATH = "/opentapo/account"
    const val KEY_ACCOUNT_ID = "account_id"

    fun all(context: Context): MutableList<TapoAccount> {
        ensureMigrated(context)
        return try {
            val raw = prefs(context).getString(KEY_ACCOUNTS, "") ?: ""
            if (raw.isBlank()) mutableListOf()
            else Json.decodeFromString<List<TapoAccount>>(raw).toMutableList()
        } catch (e: Exception) {
            Log.w(TAG, "load failed: ${e.message}")
            mutableListOf()
        }
    }

    fun active(context: Context): TapoAccount? {
        val accounts = all(context)
        if (accounts.isEmpty()) return null
        val id = prefs(context).getString(KEY_ACTIVE, null)
        return accounts.firstOrNull { it.id == id } ?: accounts.first()
    }

    fun activeCredentials(context: Context): Credentials? {
        val account = active(context) ?: return legacy(context)
        return try {
            Credentials(account.username, AccountCrypto.decrypt(account.secret))
        } catch (e: Exception) {
            Log.e(TAG, "decrypt failed for ${account.label}", e)
            null
        }
    }

    fun add(context: Context, label: String, username: String, password: String): TapoAccount {
        val accounts = all(context)
        val account = TapoAccount(label = label.trim(), username = username.trim(), secret = AccountCrypto.encrypt(password))
        accounts.add(account)
        persist(context, accounts)
        if (accounts.size == 1) {
            setActiveId(context, account.id)
        }
        Log.i(TAG, "account added: ${account.label}")
        return account
    }

    fun remove(context: Context, id: String) {
        val accounts = all(context).filter { it.id != id }
        persist(context, accounts)
        if (prefs(context).getString(KEY_ACTIVE, null) == id) {
            prefs(context).edit().remove(KEY_ACTIVE).apply()
        }
    }

    /** Bascule de compte : vide le cache devices et pousse le compte actif vers la montre. */
    fun switch(context: Context, id: String): Boolean {
        val target = all(context).firstOrNull { it.id == id } ?: return false
        setActiveId(context, target.id)
        // chaque compte a son propre LAN : ne jamais mélanger les caches
        prefs(context).edit().remove(MainActivity.KEY_CACHED_DEVICES).apply()
        // Data Layer séparé par compte : la montre sait quel compte est actif…
        com.hn.otapo.SyncHelper.sendActiveAccountToWear(context)
        // …et reçoit aussi les credentials legacy pour compatibilité
        val creds = activeCredentials(context)
        if (creds != null) {
            com.hn.otapo.SyncHelper.sendCredentialsToWear(context, creds.username, creds.password)
            com.hn.otapo.SyncHelper.sendCredentialsToWearViaMessage(context, creds.username, creds.password)
        }
        // legacy single-account keys follow the active account so every
        // background component keeps working unchanged
        if (creds != null) {
            prefs(context).edit()
                .putString(MainActivity.KEY_USER, creds.username)
                .putString(MainActivity.KEY_PASS, creds.password)
                .apply()
        }
        Log.i(TAG, "switched to account: ${target.label}")
        return true
    }

    /** Enregistre (ou met à jour) le compte correspondant à un login réussi. */
    fun upsertLogin(context: Context, username: String, password: String) {
        val accounts = all(context)
        val existing = accounts.firstOrNull { it.username.equals(username, ignoreCase = true) }
        if (existing != null) {
            persist(context, accounts.map {
                if (it.id == existing.id) it.copy(secret = AccountCrypto.encrypt(password)) else it
            })
            setActiveId(context, existing.id)
        } else {
            val label = if (accounts.isEmpty()) "Maison" else username.substringBefore("@")
            val created = add(context, label.ifBlank { username }, username, password)
            setActiveId(context, created.id)
        }
        val creds = activeCredentials(context)
        if (creds != null) {
            prefs(context).edit()
                .putString(MainActivity.KEY_USER, creds.username)
                .putString(MainActivity.KEY_PASS, creds.password)
                .apply()
        }
        com.hn.otapo.SyncHelper.sendActiveAccountToWear(context)
    }

    // -- internals ----------------------------------------------------------

    private fun setActiveId(context: Context, id: String) {
        prefs(context).edit().putString(KEY_ACTIVE, id).apply()
    }

    private fun persist(context: Context, accounts: List<TapoAccount>) {
        try {
            prefs(context).edit()
                .putString(KEY_ACCOUNTS, Json.encodeToString(accounts))
                .apply()
        } catch (e: Exception) {
            Log.w(TAG, "persist failed: ${e.message}")
        }
    }

    private fun legacy(context: Context): Credentials? {
        val user = prefs(context).getString(MainActivity.KEY_USER, null) ?: return null
        val pass = prefs(context).getString(MainActivity.KEY_PASS, null) ?: return null
        if (user.isBlank() || pass.isBlank()) return null
        return Credentials(user, pass)
    }

    /** Migre une fois le compte unique historique vers le store multi-comptes. */
    private fun ensureMigrated(context: Context) {
        try {
            val p = prefs(context)
            if (p.contains(KEY_ACCOUNTS)) return
            val user = p.getString(MainActivity.KEY_USER, null)
            val pass = p.getString(MainActivity.KEY_PASS, null)
            if (!user.isNullOrBlank() && !pass.isNullOrBlank()) {
                val account = TapoAccount(label = "Maison", username = user, secret = AccountCrypto.encrypt(pass))
                p.edit()
                    .putString(KEY_ACCOUNTS, Json.encodeToString(listOf(account)))
                    .putString(KEY_ACTIVE, account.id)
                    .apply()
                Log.i(TAG, "migrated legacy single account to 'Maison'")
            }
        } catch (e: Exception) {
            Log.w(TAG, "migration failed: ${e.message}")
        }
    }

    private fun prefs(context: Context) =
        context.getSharedPreferences(MainActivity.PREFS, Context.MODE_PRIVATE)
}
