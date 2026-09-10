package com.hn.otapo.monitor

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import com.hn.otapo.R
import com.hn.otapo.data.CredentialsProvider
import com.hn.otapo.data.DeviceStore
import com.hn.otapo.notif.NotifHelper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Periodic KLAP probe of every cached device.
 *
 * - reachable now but offline in snapshot -> "hors ligne" alert, once
 * - offline in snapshot but reachable now -> "de retour en ligne" info
 * - reachable with an on/off state differing from the cache -> "changement
 *   inattendu" alert (the cache is updated by every app-initiated toggle,
 *   so a drift means someone/something else flipped the plug)
 *
 * Runs off the main thread via goAsync; always re-arms the next check and
 * refreshes the optional persistent status notification.
 */
class DeviceMonitorReceiver : BroadcastReceiver() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != DeviceMonitorScheduler.ACTION_CHECK) return
        val pending = goAsync()
        scope.launch {
            try {
                checkAll(context.applicationContext)
            } finally {
                DeviceMonitorScheduler.schedule(context.applicationContext)
                pending.finish()
            }
        }
    }

    private suspend fun checkAll(context: Context) {
        if (!DeviceMonitorStore.isEnabled(context)) {
            Log.d(TAG, "monitor disabled; skipping")
            return
        }
        val creds = CredentialsProvider.get(context)
        if (creds == null) {
            Log.d(TAG, "no credentials; skipping")
            return
        }
        val devices = DeviceStore.loadCached(context)
        if (devices.isEmpty()) {
            Log.d(TAG, "no cached devices; skipping")
            return
        }
        val snapshot = DeviceMonitorStore.loadSnapshot(context).toMutableMap()
        val firstRun = snapshot.isEmpty()
        val fresh = mutableMapOf<String, Boolean>()
        for (device in devices) {
            val wasReachable = snapshot[device.id] ?: true
            val cachedOn = device.status.deviceOn
            val probe = withContext(Dispatchers.IO) {
                try {
                    if (!device.authenticated) {
                        device.login(creds.username, creds.password)
                    }
                    val live = device.getDeviceStatus()
                    ProbeResult.Reachable(live.deviceOn)
                } catch (e: Exception) {
                    ProbeResult.Offline(e.message)
                }
            }
            when (probe) {
                is ProbeResult.Reachable -> {
                    fresh[device.id] = true
                    if (!wasReachable && !firstRun) {
                        NotifHelper.notify(
                            context, NotifHelper.CHANNEL_MONITOR, idFor(device.id, 0),
                            context.getString(R.string.monitor_back_title, device.alias),
                            context.getString(R.string.monitor_back_text, device.alias)
                        )
                    } else if (probe.on != cachedOn && !firstRun) {
                        NotifHelper.notify(
                            context, NotifHelper.CHANNEL_MONITOR, idFor(device.id, 1),
                            context.getString(R.string.monitor_changed_title, device.alias),
                            context.getString(
                                R.string.monitor_changed_text, device.alias,
                                context.getString(if (probe.on) R.string.state_on else R.string.state_off)
                            )
                        )
                    }
                    if (probe.on != cachedOn) {
                        DeviceStore.updateStatus(context, device.id, probe.on)
                    }
                }
                is ProbeResult.Offline -> {
                    fresh[device.id] = false
                    if (wasReachable && !firstRun) {
                        NotifHelper.notify(
                            context, NotifHelper.CHANNEL_MONITOR, idFor(device.id, 2),
                            context.getString(R.string.monitor_offline_title, device.alias),
                            context.getString(R.string.monitor_offline_text, device.alias)
                        )
                    }
                }
            }
        }
        DeviceMonitorStore.saveSnapshot(context, fresh)
        refreshPersistent(context)
    }

    private sealed interface ProbeResult {
        data class Reachable(val on: Boolean) : ProbeResult
        data class Offline(val message: String?) : ProbeResult
    }

    companion object {
        private const val TAG = "DeviceMonitor"

        fun idFor(deviceId: String, kind: Int): Int =
            2000 + (deviceId.hashCode() % 500).let { if (it < 0) -it else it } * 4 + kind

        /** (Re)draws or hides the optional ongoing status notification. */
        fun refreshPersistent(context: Context) {
            if (!DeviceMonitorStore.isEnabled(context) || !DeviceMonitorStore.isPersistent(context)) {
                NotifHelper.hidePersistent(context)
                return
            }
            val devices = DeviceStore.loadCached(context)
            val snapshot = DeviceMonitorStore.loadSnapshot(context)
            val on = devices.count { it.status.deviceOn }
            val offline = devices.count { snapshot[it.id] == false }
            val text = context.getString(R.string.monitor_persistent_text, on, devices.size, offline)
            NotifHelper.showPersistent(
                context,
                context.getString(R.string.monitor_persistent_title),
                text
            )
        }
    }
}
