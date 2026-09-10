package com.hn.otapo

import android.content.Context
import android.content.Intent
import android.content.BroadcastReceiver
import android.content.IntentFilter
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.DefaultItemAnimator
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout
import com.google.android.gms.tasks.Tasks
import com.google.android.gms.wearable.DataClient
import com.google.android.gms.wearable.DataEvent
import com.google.android.gms.wearable.DataEventBuffer
import com.google.android.gms.wearable.DataMapItem
import com.google.android.gms.wearable.MessageClient
import com.google.android.gms.wearable.MessageEvent
import com.google.android.gms.wearable.Wearable
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.floatingactionbutton.FloatingActionButton
import com.google.android.material.snackbar.Snackbar
import com.hn.otapo.net.DeviceScanner
import com.hn.otapo.net.NetworkUtils
import com.hn.otapo.tapo.device.Device
import com.hn.otapo.view.intent_data.Credentials
import com.hn.otapo.view.main.DeviceAdapter
import com.hn.otapo.widget.DeviceWidgetHelper
import kotlinx.coroutines.*
import java.net.Inet4Address

class MainActivity : AppCompatActivity() {

    private var credentials: Credentials? = null
    private val devices = mutableListOf<Device>()
    private lateinit var adapter: DeviceAdapter
    private lateinit var refreshLayout: SwipeRefreshLayout
    private lateinit var emptyView: TextView
    private lateinit var progress: ProgressBar

    // Device-list sync guards: applyingRemoteDevices suppresses echo pushes
    // while merging a watch-pushed list; last*Json dedupes re-deliveries
    // (background service + foreground listeners often both fire).
    private var applyingRemoteDevices = false
    private var lastPushedDevicesJson: String? = null
    private var lastAppliedDevicesJson: String? = null

    private val devicesReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val devicesJson = intent?.getStringExtra(DeviceSyncListenerService.EXTRA_DEVICES_JSON)
            if (!devicesJson.isNullOrEmpty()) {
                applySyncedDevicesJson(devicesJson, "broadcast")
            }
        }
    }

    private val dataListener = DataClient.OnDataChangedListener { events ->
        onDataChangedWhileForeground(events)
    }
    private val messageListener = MessageClient.OnMessageReceivedListener { event ->
        onMessageWhileForeground(event)
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val toolbar: MaterialToolbar = findViewById(R.id.toolbar)
        toolbar.subtitle = getString(R.string.device_list_subtitle)
        toolbar.setOnMenuItemClickListener { item ->
            when (item.itemId) {
                R.id.action_logout -> {
                    logout()
                    true
                }
                R.id.action_refresh -> {
                    refreshLayout.isRefreshing = true
                    discover()
                    true
                }
                R.id.action_add_ip -> {
                    openAddDevice()
                    true
                }
                R.id.action_tile -> {
                    startActivity(Intent(this, com.hn.otapo.tile.TileSettingsActivity::class.java))
                    true
                }
                R.id.action_timers -> {
                    startActivity(Intent(this, com.hn.otapo.timer.TimerActivity::class.java))
                    true
                }
                R.id.action_energy -> {
                    val pick = Intent(this, com.hn.otapo.common.DevicePickerActivity::class.java)
                    pick.putExtra(
                        com.hn.otapo.common.DevicePickerActivity.EXTRA_TITLE_RES,
                        R.string.menu_energy
                    )
                    startActivityForResult(pick, REQUEST_ENERGY_PICK)
                    true
                }
                R.id.action_monitor -> {
                    startActivity(Intent(this, com.hn.otapo.monitor.MonitorSettingsActivity::class.java))
                    true
                }
                R.id.action_groups -> {
                    startActivity(Intent(this, com.hn.otapo.group.GroupActivity::class.java))
                    true
                }
                R.id.action_geofence -> {
                    startActivity(Intent(this, com.hn.otapo.geofence.GeofenceActivity::class.java))
                    true
                }
                R.id.action_accounts -> {
                    startActivity(Intent(this, com.hn.otapo.account.AccountActivity::class.java))
                    true
                }
                R.id.action_voice -> {
                    startActivity(Intent(this, com.hn.otapo.voice.VoiceHelpActivity::class.java))
                    true
                }
                R.id.action_backup -> {
                    startActivity(Intent(this, com.hn.otapo.backup.BackupActivity::class.java))
                    true
                }
                else -> false
            }
        }

        adapter = DeviceAdapter(devices, { device, newState ->
            toggleDevice(device, newState)
        }, { device ->
            openDeviceControl(device)
        })

        val list: RecyclerView = findViewById(R.id.device_list)
        list.layoutManager = LinearLayoutManager(this)
        list.adapter = adapter
        list.itemAnimator = DefaultItemAnimator().apply {
            addDuration = 220
            changeDuration = 220
            moveDuration = 220
        }

        refreshLayout = findViewById(R.id.swipe_refresh)
        refreshLayout.setColorSchemeColors(
            getColor(R.color.op_accent),
            getColor(R.color.op_primary)
        )
        refreshLayout.setProgressBackgroundColorSchemeColor(getColor(R.color.op_surface_variant))
        refreshLayout.setSize(SwipeRefreshLayout.LARGE)
        refreshLayout.setOnRefreshListener { discover() }

        val fab: FloatingActionButton = findViewById(R.id.fab_add)
        fab.setOnClickListener {
            it.animate().scaleX(0.9f).scaleY(0.9f).setDuration(90)
                .withEndAction { it.animate().scaleX(1f).scaleY(1f).setDuration(120).start() }
                .start()
            openAddDevice()
        }

        emptyView = findViewById(R.id.empty_view)
        progress = findViewById(R.id.progress)

        credentials = readCredentials()
        if (credentials == null) {
            startActivity(Intent(this, LoginActivity::class.java))
            overridePendingTransition(R.anim.fade_in, R.anim.fade_out)
            finish()
        } else {
            Wearable.getDataClient(this).addListener(dataListener)
            Wearable.getMessageClient(this).addListener(messageListener)
            registerReceiver(devicesReceiver, IntentFilter(DeviceSyncListenerService.ACTION_DEVICES_UPDATED))
            // pull a watch-pushed list first (persistent DataItem covers the
            // case where the watch pushed while the phone app was closed)
            pullDevicesFromDataLayer()
            discover()
            com.hn.otapo.voice.VoiceShortcutManager.refresh(this)
            com.hn.otapo.monitor.DeviceMonitorScheduler.schedule(this)
            com.hn.otapo.monitor.DeviceMonitorReceiver.refreshPersistent(this)
        }
    }

    override fun onResume() {
        super.onResume()
        if (credentials != null && devices.isNotEmpty()) {
            discover()
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_ADD_DEVICE && resultCode == RESULT_OK) {
            val ip = data?.getStringExtra(AddDeviceActivity.EXTRA_DEVICE_IP)
            if (ip != null) {
                saveManualIp(ip)
                discover()
            }
        }
        if (requestCode == REQUEST_ENERGY_PICK && resultCode == RESULT_OK) {
            val id = data?.getStringExtra(com.hn.otapo.common.DevicePickerActivity.EXTRA_DEVICE_ID)
            if (!id.isNullOrEmpty()) {
                val energy = Intent(com.hn.otapo.energy.EnergyActivity.ACTION_VIEW)
                energy.putExtra(com.hn.otapo.energy.EnergyActivity.EXTRA_DEVICE_ID, id)
                startActivity(energy)
            }
        }
    }

    /** Manually-added IPs are merged into every future scan result. */
    private fun saveManualIp(ip: String) {
        val prefs = getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val existing = prefs.getStringSet(KEY_MANUAL_IPS, mutableSetOf()) ?: mutableSetOf()
        existing.add(ip)
        prefs.edit().putStringSet(KEY_MANUAL_IPS, existing).apply()
    }

    private fun loadManualIps(): Set<String> {
        return getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getStringSet(KEY_MANUAL_IPS, emptySet()) ?: emptySet()
    }

    override fun onDestroy() {
        scope.cancel()
        try {
            Wearable.getDataClient(this).removeListener(dataListener)
        } catch (_: Exception) {
        }
        try {
            Wearable.getMessageClient(this).removeListener(messageListener)
        } catch (_: Exception) {
        }
        try {
            unregisterReceiver(devicesReceiver)
        } catch (_: Exception) {
        }
        super.onDestroy()
    }

    private fun readCredentials(): Credentials? {
        val prefs = getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val user = prefs.getString(KEY_USER, null) ?: return null
        val pass = prefs.getString(KEY_PASS, null) ?: return null
        return Credentials(user, pass)
    }

    private fun logout() {
        getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().clear().apply()
        startActivity(Intent(this, LoginActivity::class.java))
        overridePendingTransition(R.anim.fade_in, R.anim.fade_out)
        finish()
    }

    private fun openAddDevice() {
        val intent = Intent(this, AddDeviceActivity::class.java)
        intent.putExtra(AddDeviceActivity.EXTRA_CREDENTIALS, credentials)
        startActivityForResult(intent, REQUEST_ADD_DEVICE)
        overridePendingTransition(R.anim.fade_in, R.anim.fade_out)
    }

    /** Opens the per-device screen (brightness/color/energy for supported models). */
    private fun openDeviceControl(device: com.hn.otapo.tapo.device.Device) {
        val intent = Intent(this, com.hn.otapo.control.DeviceControlActivity::class.java)
        intent.putExtra(com.hn.otapo.control.DeviceControlActivity.EXTRA_DEVICE_ID, device.id)
        startActivity(intent)
        overridePendingTransition(R.anim.fade_in, R.anim.fade_out)
    }

    private fun showMessage(text: String, isError: Boolean = false) {
        val root = findViewById<View>(android.R.id.content)
        val bar = Snackbar.make(root, text, if (isError) Snackbar.LENGTH_LONG else Snackbar.LENGTH_SHORT)
        bar.setBackgroundTint(getColor(if (isError) R.color.op_error_container else R.color.op_surface_variant))
        bar.setTextColor(getColor(R.color.op_text_primary))
        bar.setActionTextColor(getColor(R.color.op_accent))
        bar.show()
    }

    private fun discover() {
        val creds = credentials ?: return
        progress.visibility = View.VISIBLE
        emptyView.visibility = View.GONE
        scope.launch {
            try {
                val network = withContext(Dispatchers.IO) { localNetwork() }
                Log.i(TAG, "Scanning subnet: $network")
                if (network == null) {
                    showMessage(
                        "Pas de réseau Wi-Fi détecté — vérifie que le téléphone est en Wi-Fi",
                        isError = true
                    )
                }
                val scanned = withContext(Dispatchers.IO) {
                    val scanner = DeviceScanner(creds.username, creds.password)
                    network?.let { scanner.scanNetwork(it.first, it.second) }
                    // add manually-registered devices that the scan may have missed
                    val manualIps = loadManualIps()
                    val found = scanner.devices.map { it.ipAddress }.toSet()
                    for (ip in manualIps) {
                        if (!found.contains(ip)) {
                            try {
                                val addr = java.net.InetAddress.getByName(ip) as Inet4Address
                                val client = com.hn.otapo.tapo.api.tapo.TapoClient(addr)
                                client.login(creds.username, creds.password)
                                scanner.devices.add(client.queryDevice())
                                Log.i(TAG, "Manual device at $ip reachable again")
                            } catch (e: Exception) {
                                Log.w(TAG, "Manual device at $ip unreachable: ${e.message}")
                            }
                        }
                    }
                    scanner.devices
                }
                Log.i(TAG, "Scan complete: ${scanned.size} device(s) found")
                // merge with the watch-synced cache so devices pushed from the
                // watch appear even if this scan missed them; fresh scan wins
                // on id conflict (its IPs are the most recent)
                val cached = loadCachedDevices()
                val merged = mutableListOf<Device>()
                val seen = mutableSetOf<String>()
                scanned.forEach { merged.add(it); seen.add(it.id) }
                cached.filter { !seen.contains(it.id) }.forEach { merged.add(it); seen.add(it.id) }
                devices.clear()
                devices.addAll(merged.sortedBy { it.alias })
                persistDevices()
                pushDevicesToWear()
                DeviceWidgetHelper.updateAll(this@MainActivity)
                com.hn.otapo.tile.TileHelper.requestRefresh(this@MainActivity)
                adapter.notifyDataSetChanged()
                emptyView.visibility = if (devices.isEmpty()) View.VISIBLE else View.GONE
                if (devices.isEmpty()) {
                    showMessage(
                        "Aucune prise trouvée sur ${network ?: "?"}. " +
                        "Vérifie que la compatibilité tierce est activée dans l'app Tapo " +
                        "(Profil → Paramètres → Compatibilité appareils tiers).",
                        isError = true
                    )
                } else {
                    emptyView.animate().alpha(0f).setDuration(150).start()
                }
            } catch (e: Exception) {
                Log.e(TAG, "Discovery failed", e)
                showMessage(getString(R.string.error_generic, e.message), isError = true)
                emptyView.visibility = View.VISIBLE
            } finally {
                progress.visibility = View.GONE
                refreshLayout.isRefreshing = false
            }
        }
    }

    // -- device-list sync (phone <-> watch) ----------------------------------

    private fun onDataChangedWhileForeground(events: DataEventBuffer) {
        Log.d(TAG, "foreground onDataChanged events=${events.count}")
        for (event in events) {
            if (event.type != DataEvent.TYPE_CHANGED) continue
            if (event.dataItem.uri.path != DeviceSync.DEVICES_PATH) continue
            try {
                val dm = DataMapItem.fromDataItem(event.dataItem).dataMap
                val devicesJson = dm.getString(DeviceSync.KEY_DEVICES_JSON, "")
                if (!devicesJson.isNullOrEmpty()) {
                    applySyncedDevicesJson(devicesJson, "data-foreground")
                }
            } catch (e: Exception) {
                Log.e(TAG, "foreground devices onDataChanged failed", e)
            }
        }
    }

    private fun onMessageWhileForeground(event: MessageEvent) {
        Log.d(TAG, "foreground onMessageReceived path=${event.path}")
        if (event.path != DeviceSync.DEVICES_PATH) return
        val devicesJson = String(event.data, Charsets.UTF_8)
        if (devicesJson.isNotEmpty()) {
            applySyncedDevicesJson(devicesJson, "message-foreground")
        }
    }

    /**
     * Merges a watch-pushed device list into the current list and cache.
     * Remote entries win on id conflict; local-only entries are kept.
     */
    private fun applySyncedDevicesJson(devicesJson: String, source: String) {
        if (devicesJson == lastAppliedDevicesJson) {
            Log.d(TAG, "applySyncedDevices via $source: already applied; skipping")
            return
        }
        val remote = try {
            DeviceSync.devicesFromJson(devicesJson)
        } catch (e: Exception) {
            Log.e(TAG, "applySyncedDevices via $source: decode failed", e)
            return
        }
        if (remote.isEmpty()) {
            Log.d(TAG, "applySyncedDevices via $source: empty list; ignoring")
            return
        }
        Log.d(TAG, "applySyncedDevices via $source: merging ${remote.size} remote device(s)")
        applyingRemoteDevices = true
        try {
            lastAppliedDevicesJson = devicesJson
            // don't echo back what we just received
            lastPushedDevicesJson = devicesJson
            val merged = mutableListOf<Device>()
            val seen = mutableSetOf<String>()
            remote.forEach { merged.add(it); seen.add(it.id) }
            devices.filter { !seen.contains(it.id) }.forEach { merged.add(it); seen.add(it.id) }
            devices.clear()
            devices.addAll(merged.sortedBy { it.alias })
            persistDevices()
            // every known IP stays findable by future scans
            val ips = HashSet(loadManualIps())
            var changed = false
            devices.forEach { if (ips.add(it.ipAddress)) changed = true }
            if (changed) {
                getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                    .edit().putStringSet(KEY_MANUAL_IPS, ips).apply()
            }
            adapter.notifyDataSetChanged()
            emptyView.visibility = if (devices.isEmpty()) View.VISIBLE else View.GONE
        } finally {
            applyingRemoteDevices = false
        }
    }

    /**
     * Pulls an already-synced device list from the Data Layer. Handles the
     * case where the watch pushed while the phone app was closed.
     */
    private fun pullDevicesFromDataLayer() {
        scope.launch {
            try {
                val devicesJson = withContext(Dispatchers.IO) {
                    val client = Wearable.getDataClient(this@MainActivity)
                    val uri = Uri.parse("wear://*" + DeviceSync.DEVICES_PATH)
                    val buffer = Tasks.await(client.getDataItems(uri))
                    try {
                        var found: String? = null
                        for (item in buffer) {
                            if (item.uri.path == DeviceSync.DEVICES_PATH) {
                                val dm = DataMapItem.fromDataItem(item).dataMap
                                val raw = dm.getString(DeviceSync.KEY_DEVICES_JSON, "")
                                if (!raw.isNullOrEmpty()) {
                                    found = raw
                                    break
                                }
                            }
                        }
                        found
                    } finally {
                        buffer.close()
                    }
                }
                if (devicesJson != null) {
                    applySyncedDevicesJson(devicesJson, "data-pull")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to pull devices from Data Layer", e)
            }
        }
    }

    /**
     * Pushes the current list to the watch. No-op while applying a remote
     * list (echo guard), when empty (never wipe the peer's list from an
     * empty state), or when unchanged.
     */
    private fun pushDevicesToWear() {
        if (applyingRemoteDevices) return
        if (devices.isEmpty()) return
        val devicesJson = try {
            DeviceSync.devicesToJson(devices)
        } catch (e: Exception) {
            Log.e(TAG, "pushDevicesToWear: encode failed", e)
            return
        }
        if (devicesJson == lastPushedDevicesJson) return
        lastPushedDevicesJson = devicesJson
        lastAppliedDevicesJson = devicesJson
        Log.d(TAG, "Pushing ${devices.size} device(s) to wear")
        SyncHelper.sendDevicesToWear(this, devicesJson)
    }

    private fun loadCachedDevices(): List<Device> {
        return try {
            val raw = getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .getString(KEY_CACHED_DEVICES, "") ?: ""
            DeviceSync.devicesFromJson(raw)
        } catch (e: Exception) {
            Log.w(TAG, "loadCachedDevices failed: ${e.message}")
            emptyList()
        }
    }

    private fun persistDevices() {
        try {
            getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putString(KEY_CACHED_DEVICES, DeviceSync.devicesToJson(devices))
                .apply()
        } catch (e: Exception) {
            Log.w(TAG, "persistDevices failed: ${e.message}")
        }
    }

    /** Returns (ip, netmask) of the wifi network, or null when unavailable. */    private fun localNetwork(): Pair<String, String>? {
        val cm = getSystemService(CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
        // Prefer the network that actually carries internet over WIFI transport;
        // allNetworks order is arbitrary and the first IPv4 may belong to a VPN
        // or the cellular interface, which would scan the wrong subnet.
        val candidates = mutableListOf<Pair<Int, Pair<String, String>>>()
        for (network in cm.allNetworks) {
            val caps = cm.getNetworkCapabilities(network) ?: continue
            val link = cm.getLinkProperties(network) ?: continue
            var score = 0
            if (caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI)) score += 10
            if (caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET)) score += 5
            for (la in link.linkAddresses) {
                val addr = la.address
                if (addr is Inet4Address && !addr.isLoopbackAddress) {
                    candidates.add(Pair(score, Pair(addr.hostAddress!!, NetworkUtils.cidrToNetmask(la.prefixLength))))
                }
            }
        }
        return candidates.maxByOrNull { it.first }?.second
    }

    private fun toggleDevice(device: Device, newState: Boolean) {
        val creds = credentials ?: return
        scope.launch {
            try {
                withContext(Dispatchers.IO) {
                    if (!device.authenticated) {
                        device.login(creds.username, creds.password)
                    }
                    if (newState) device.on() else device.off()
                }
                device.status = device.status.copy(deviceOn = newState)
                persistDevices()
                DeviceWidgetHelper.updateAll(this@MainActivity)
                com.hn.otapo.tile.TileHelper.requestRefresh(this@MainActivity)
                showMessage(
                    "${device.alias} : " + getString(if (newState) R.string.state_on else R.string.state_off)
                )
            } catch (e: Exception) {
                Log.e(TAG, "Toggle failed", e)
                showMessage(getString(R.string.error_generic, e.message), isError = true)
            } finally {
                adapter.notifyDataSetChanged()
            }
        }
    }

    companion object {
        const val TAG = "MobileMainActivity"
        const val PREFS = "OpenTapo"
        const val KEY_USER = "username"
        const val KEY_PASS = "password"
        const val KEY_MANUAL_IPS = "manual_ips"
        const val KEY_CACHED_DEVICES = "cached_devices"
        const val REQUEST_ADD_DEVICE = 2
        const val REQUEST_ENERGY_PICK = 3
    }
}
