package com.hn.otapo.backup

import android.content.Context
import android.util.Log
import com.hn.otapo.MainActivity
import com.hn.otapo.account.AccountCrypto
import com.hn.otapo.account.AccountStore
import com.hn.otapo.timer.TimerStore
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json

/**
 * Export / import de toute la config : comptes (mots de passe re-chiffrés
 * avec la phrase de sauvegarde), appareils connus, groupes, zones GPS,
 * minuteries, tuile favorite et réglages du monitor.
 */
@kotlinx.serialization.Serializable
data class BackupAccount(
    val label: String,
    val username: String,
    /** mot de passe chiffré par [BackupCrypto] */
    val secret: String
)

@kotlinx.serialization.Serializable
data class FullBackup(
    val version: Int = VERSION,
    val exportedAt: Long = System.currentTimeMillis(),
    val activeUsername: String? = null,
    val accounts: List<BackupAccount> = emptyList(),
    val devicesJson: String = "",
    val manualIps: Set<String> = emptySet(),
    val groupsJson: String = "",
    val zonesJson: String = "",
    val timersJson: String = "",
    val tileFavorite: String? = null,
    val monitorEnabled: Boolean = true,
    val monitorPersistent: Boolean = false,
    val monitorIntervalMin: Int = 30
) {
    companion object {
        const val VERSION = 1
    }
}

object BackupManager {

    private const val TAG = "Backup"
    private val json = Json { ignoreUnknownKeys = true; prettyPrint = true }

    fun exportToJson(context: Context, passphrase: String): String {
        val prefs = context.getSharedPreferences(MainActivity.PREFS, Context.MODE_PRIVATE)
        val accounts = AccountStore.all(context).map { account ->
            val plain = try {
                AccountCrypto.decrypt(account.secret)
            } catch (e: Exception) {
                Log.e(TAG, "cannot decrypt ${account.label}, skipped", e)
                return@map null
            }
            BackupAccount(account.label, account.username, BackupCrypto.encrypt(plain, passphrase))
        }.filterNotNull()
        val backup = FullBackup(
            activeUsername = AccountStore.active(context)?.username,
            accounts = accounts,
            devicesJson = prefs.getString(MainActivity.KEY_CACHED_DEVICES, "") ?: "",
            manualIps = prefs.getStringSet(MainActivity.KEY_MANUAL_IPS, emptySet()) ?: emptySet(),
            groupsJson = prefs.getString("mobile_groups", "") ?: "",
            zonesJson = prefs.getString("geofence_zones", "") ?: "",
            timersJson = TimerStore.exportJson(context),
            tileFavorite = context.getSharedPreferences("OpenTapoTile", Context.MODE_PRIVATE)
                .getString("favorite_device_id", null),
            monitorEnabled = prefs.getBoolean("monitor_enabled", true),
            monitorPersistent = prefs.getBoolean("monitor_persistent", false),
            monitorIntervalMin = prefs.getInt("monitor_interval_min", 30)
        )
        return json.encodeToString(backup)
    }

    fun parse(raw: String): FullBackup = json.decodeFromString(raw)

    /**
     * Restaure tout et ré-arme les composants (timers, geofences, monitor,
     * raccourcis, sync montre). Les comptes existants avec le même username
     * sont mis à jour, les autres ajoutés ; les secrets sont re-chiffrés
     * avec le KeyStore local.
     */
    fun restore(context: Context, backup: FullBackup, passphrase: String) {
        // 1. comptes
        for (entry in backup.accounts) {
            val plain = BackupCrypto.decrypt(entry.secret, passphrase)
            val existing = AccountStore.all(context)
                .firstOrNull { it.username.equals(entry.username, ignoreCase = true) }
            if (existing != null) {
                AccountStore.remove(context, existing.id)
            }
            AccountStore.add(context, entry.label, entry.username, plain)
        }
        val activeTarget = AccountStore.all(context)
            .firstOrNull { it.username.equals(backup.activeUsername ?: "", ignoreCase = true) }
            ?: AccountStore.all(context).firstOrNull()
        if (activeTarget != null) {
            // switch() vide le cache devices — on restaure le cache après,
            // donc on ne passe pas par switch() ici
            context.getSharedPreferences(MainActivity.PREFS, Context.MODE_PRIVATE).edit()
                .putString("tapo_active_account", activeTarget.id)
                .apply()
            val creds = AccountStore.activeCredentials(context)
            if (creds != null) {
                context.getSharedPreferences(MainActivity.PREFS, Context.MODE_PRIVATE).edit()
                    .putString(MainActivity.KEY_USER, creds.username)
                    .putString(MainActivity.KEY_PASS, creds.password)
                    .apply()
            }
        }
        // 2. appareils + IPs manuelles
        val prefs = context.getSharedPreferences(MainActivity.PREFS, Context.MODE_PRIVATE)
        prefs.edit()
            .putString(MainActivity.KEY_CACHED_DEVICES, backup.devicesJson)
            .putStringSet(MainActivity.KEY_MANUAL_IPS, backup.manualIps)
            .putString("mobile_groups", backup.groupsJson)
            .putString("geofence_zones", backup.zonesJson)
            .putBoolean("monitor_enabled", backup.monitorEnabled)
            .putBoolean("monitor_persistent", backup.monitorPersistent)
            .putInt("monitor_interval_min", backup.monitorIntervalMin.coerceIn(15, 720))
            .apply()
        // 3. minuteries, tuile
        TimerStore.importJson(context, backup.timersJson)
        context.getSharedPreferences("OpenTapoTile", Context.MODE_PRIVATE).edit()
            .putString("favorite_device_id", backup.tileFavorite)
            .apply()
        // 4. ré-arme tout
        try {
            com.hn.otapo.timer.TimerManager.rescheduleAll(context)
            com.hn.otapo.geofence.GeofenceManager.refresh(context)
            com.hn.otapo.monitor.DeviceMonitorScheduler.schedule(context)
            com.hn.otapo.monitor.DeviceMonitorReceiver.refreshPersistent(context)
            com.hn.otapo.voice.VoiceShortcutManager.refresh(context)
            com.hn.otapo.SyncHelper.sendActiveAccountToWear(context)
            val creds = AccountStore.activeCredentials(context)
            if (creds != null && backup.devicesJson.isNotEmpty()) {
                com.hn.otapo.SyncHelper.sendDevicesToWear(context, backup.devicesJson)
            }
        } catch (e: Exception) {
            Log.w(TAG, "post-restore re-arm failed: ${e.message}")
        }
        Log.i(TAG, "restored backup v${backup.version} (${backup.accounts.size} account(s))")
    }
}
