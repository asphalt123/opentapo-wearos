package com.hn.otapo

import android.annotation.SuppressLint
import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.*
import android.os.Build
import android.os.Bundle
import android.os.Parcelable
import android.util.Log
import android.view.View
import android.widget.ImageButton
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.gms.tasks.Tasks
import com.google.android.gms.wearable.DataClient
import com.google.android.gms.wearable.DataEvent
import com.google.android.gms.wearable.DataEventBuffer
import com.google.android.gms.wearable.DataMapItem
import com.google.android.gms.wearable.MessageClient
import com.google.android.gms.wearable.MessageEvent
import com.google.android.gms.wearable.Wearable
import com.hn.otapo.databinding.ActivityMainBinding
import com.hn.otapo.net.DeviceScanner
import com.hn.otapo.net.NetworkUtils
import com.hn.otapo.tapo.api.tplinkcloud.TpLinkCloudClient
import com.hn.otapo.tapo.api.tapo.TapoClient
import com.hn.otapo.tapo.device.Device
import com.hn.otapo.tapo.device.DeviceBuilder
import com.hn.otapo.view.app_data.DeviceCache
import com.hn.otapo.view.app_data.DeviceGroups
import com.hn.otapo.view.intent_data.*
import com.hn.otapo.view.intent_data.Credentials
import com.hn.otapo.view.main_activity.ActivityState
import com.hn.otapo.view.main_activity.DeviceListAdapter
import com.hn.otapo.view.main_activity.GroupListAdapter
import kotlinx.coroutines.*
import java.net.Inet4Address

@OptIn(DelicateCoroutinesApi::class)
class MainActivity : Activity() {

    private lateinit var binding: ActivityMainBinding

    private val credentialsReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val prefs = getSharedPreferences(SHARED_PREFS, Context.MODE_PRIVATE)
            val username = prefs.getString(SHARED_PREFS_USERNAME, "")
            val password = prefs.getString(SHARED_PREFS_PASSWORD, "")
            if (!username.isNullOrEmpty() && !password.isNullOrEmpty()) {
                credentials = Credentials(username, password)
            }
            onCredentials()
        }
    }

    private val devicesReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val devicesJson = intent?.getStringExtra(DataLayerListenerService.EXTRA_DEVICES_JSON)
            if (!devicesJson.isNullOrEmpty()) {
                applySyncedDevicesJson(devicesJson, "broadcast")
            }
        }
    }

    // credentials
    private var credentials: Credentials? = null

    // devices
    private var devices: MutableList<Device> = mutableListOf()
    private var deviceGroups: DeviceGroups = DeviceGroups()

    // Device-list sync guards: applyingRemoteDevices suppresses echo pushes
    // while merging a phone-pushed list; last*Json dedupes re-deliveries
    // (background service + foreground listeners often both fire).
    private var applyingRemoteDevices = false
    private var lastPushedDevicesJson: String? = null
    private var lastAppliedDevicesJson: String? = null

    // network
    private var deviceNetwork: Pair<String, String>? = null

    // Foreground Data Layer listeners (belt & braces alongside
    // DataLayerListenerService, which handles the background case).
    private val dataListener = DataClient.OnDataChangedListener { events ->
        onDataChangedWhileForeground(events)
    }
    private val messageListener = MessageClient.OnMessageReceivedListener { event ->
        onMessageWhileForeground(event)
    }

    // states
    private var state: ActivityState = ActivityState.LOADING_DEVICE_LIST
    private var selectedDevices: MutableList<String> = mutableListOf()
    private var selectedGroups: MutableList<String> = mutableListOf()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        registerReceiver(
            credentialsReceiver,
            IntentFilter("com.hn.otapo.CREDENTIALS_UPDATED")
        )
        registerReceiver(
            devicesReceiver,
            IntentFilter(DataLayerListenerService.ACTION_DEVICES_UPDATED)
        )
    }

    override fun onDestroy() {
        super.onDestroy()
        unregisterReceiver(credentialsReceiver)
        unregisterReceiver(devicesReceiver)
    }

    override fun onResume() {
        super.onResume()
        Log.d(TAG, "onResume")
        Wearable.getDataClient(this).addListener(dataListener)
        Wearable.getMessageClient(this).addListener(messageListener)

        setActivityState(ActivityState.NO_DEVICE_FOUND)

        // get groups
        this.getDeviceGroups()

        // pull device list synced from the phone (persistent DataItem covers
        // the case where the phone pushed while the watch app was closed)
        pullDevicesFromDataLayer()

        // get credentials
        if (this.credentials == null) {
            Log.d(TAG, "Credentials are null; handling null credentials")
            onNullCredentials()
        } else {
            onCredentials()
        }

        // Button listeners
        Log.d(TAG, "Setting up button listeners")
        Log.d(TAG, "Configuring reload icon listener")
        val reloadIcon: ImageButton = findViewById(R.id.activity_main_reload)
        reloadIcon.setOnClickListener {
            onReloadDeviceListClick()
        }
        Log.d(TAG, "Configuring new device icon listener")
        val newDeviceIcon: ImageButton = findViewById(R.id.activity_main_new_device)
        newDeviceIcon.setOnClickListener {
            onNewDeviceClick()
        }
        Log.d(TAG, "Configuring new group icon listener")
        val newGroupIcon: ImageButton = findViewById(R.id.activity_main_new_group)
        newGroupIcon.setOnClickListener {
            if (this.selectedDevices.isNotEmpty()) {
                onCreateNewGroupClick()
            }
        }
        Log.d(TAG, "Configuring delete group icon listener")
        val delGroupIcon: ImageButton = findViewById(R.id.activity_main_del_group)
        delGroupIcon.setOnClickListener {
            if (this.selectedGroups.isNotEmpty()) {
                onDeleteGroupsClick()
            }
        }
    }

    override fun onPause() {
        super.onPause()
        try {
            Wearable.getDataClient(this).removeListener(dataListener)
        } catch (_: Exception) {
        }
        try {
            Wearable.getMessageClient(this).removeListener(messageListener)
        } catch (_: Exception) {
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

        Log.d(
            TAG,
            String.format(
                "OnActivityResult; result code is %d",
                resultCode
            )
        )

        if (resultCode == RESULT_OK && data != null) {
            data.setExtrasClassLoader(javaClass.classLoader)
            val credentials = parcelableExtraCompat(data, LoginActivity.INTENT_OUTPUT, Credentials::class.java)
            if (credentials is Credentials) {
                onLoginActivityResult(credentials)
            }
            val groups = parcelableExtraCompat(data, NewGroupActivity.INTENT_OUTPUT, NewGroupOutput::class.java)
            if (groups is NewGroupOutput) {
                onNewGroupActivityResult(groups)
            }
            val newDevice = parcelableExtraCompat(data, DeviceSetupActivity.INTENT_OUTPUT, DeviceData::class.java)
            if (newDevice is DeviceData) {
                onDeviceSetupActivityResult(newDevice)
            }
        }
    }

    private fun onLoginActivityResult(credentials: Credentials) {
        Log.d(TAG, "Got credentials from login activity")
        if (this.credentials == null) {
            Log.d(TAG, String.format("Set credentials: %s", credentials.username))
            this.credentials = credentials
        }
    }

    private fun onNewGroupActivityResult(newGroup: NewGroupOutput) {
        Log.d(TAG, String.format("Got NewGroup activity result: %s", newGroup))
        this.deviceGroups.add(newGroup.groupName, newGroup.idList)
        // save changes
        commitDeviceGroups()
        populateGroupsList()
        this.selectedGroups.clear()
        toggleDelGroupIcon(visible = false)
        toggleNewGroupIcon(visible = false)
    }

    private fun onDeviceSetupActivityResult(deviceData: DeviceData) {
        Log.d(TAG, String.format("Got DeviceSetup result: %s", deviceData))
        // convert device data to device
        val device = DeviceBuilder.buildDevice(
            alias = deviceData.alias,
            deviceId = deviceData.id,
            model = deviceData.model,
            endpoint = deviceData.endpoint,
            ipAddress = deviceData.ipAddress,
            deviceStatus = deviceData.status,
        )
        // check if device already exists
        if (this.devices.all { it.id != device.id }) {
            this.devices.add(device)
        } else {
            // replace existing entry with fresh state (IP may have changed)
            val idx = this.devices.indexOfFirst { it.id == device.id }
            if (idx >= 0) {
                this.devices[idx] = device
            }
        }
        saveManualIp(device.ipAddress)
        setCachedDeviceList()
        pushDevicesToMobile()
        setActivityState(ActivityState.DEVICE_LIST)
    }

    /** Manually-registered IPs survive failed scans and are re-checked on reload. */
    private fun saveManualIp(ip: String) {
        val sharedPrefs = getSharedPreferences(SHARED_PREFS, Context.MODE_PRIVATE)
        val existing = sharedPrefs.getStringSet(SHARED_PREFS_MANUAL_IPS, mutableSetOf()) ?: mutableSetOf()
        existing.add(ip)
        sharedPrefs.edit().putStringSet(SHARED_PREFS_MANUAL_IPS, existing).apply()
    }

    private fun loadManualIps(): Set<String> {
        return getSharedPreferences(SHARED_PREFS, Context.MODE_PRIVATE)
            .getStringSet(SHARED_PREFS_MANUAL_IPS, emptySet()) ?: emptySet()
    }

    private fun onReloadDeviceListClick() {
        Log.d(TAG, "onReloadDeviceList")
        setActivityState(ActivityState.LOADING_DEVICE_LIST)
        GlobalScope.launch {
            withContext(Dispatchers.IO) {
                discoverDevices()
            }
        }
    }

    private fun onNewDeviceClick() {
        Log.d(TAG, "onNewDeviceClick")
        val newDeviceIntent = Intent(this, DeviceSetupActivity::class.java)
        newDeviceIntent.putExtra(DeviceSetupActivity.INTENT_INPUT, credentials)
        startActivityForResult(newDeviceIntent, 1)
    }

    private fun onCreateNewGroupClick() {
        Log.d(TAG, "onCreateNewGroup")
        val newGroupIntent = Intent(this, NewGroupActivity::class.java)
        val devicesInGroup = this.selectedDevices.toList()
        Log.d(
            TAG,
            String.format("Starting new group activity with devices in group: %s", devicesInGroup)
        )
        newGroupIntent.putExtra(
            NewGroupActivity.INTENT_INPUT, NewGroupInput(
                devicesInGroup,
                this.deviceGroups.getNames()
            )
        )
        this.selectedDevices.clear()
        startActivityForResult(newGroupIntent, 1)
    }

    private fun onDeleteGroupsClick() {
        Log.d(TAG, "onDeleteGroups")
        Log.d(TAG, String.format("Removing groups %s", this.selectedGroups))
        this.selectedGroups.forEach {
            Log.d(TAG, String.format("Removing group %s", it))
            this.deviceGroups.remove(it)
        }
        // commit changes
        this.commitDeviceGroups()
        Log.d(TAG, "Groups removed")
        this.selectedGroups.clear()
        toggleDelGroupIcon(visible = false)
        populateGroupsList()
    }

    private fun onNullCredentials() {
        // try to read from prefs
        readCredentialsFromPrefs()

        // if still NULL; try to pull from Wear Data Layer before falling back to LoginActivity
        if (this.credentials != null) {
            onCredentials()
        } else {
            Log.d(
                TAG,
                "Credentials not in intent and not in preferences. Trying to pull from Wear data layer."
            )
            pullCredentialsFromDataLayer()
        }
    }

    /**
     * Foreground DataClient listener: fires while MainActivity is resumed, even
     * if the background WearableListenerService hasn't been bound yet by GMS.
     */
    private fun onDataChangedWhileForeground(events: DataEventBuffer) {
        Log.d(TAG, "foreground onDataChanged events=${events.count}")
        for (event in events) {
            if (event.type != DataEvent.TYPE_CHANGED) continue
            when (event.dataItem.uri.path) {
                "/opentapo/credentials" -> {
                    try {
                        val dm = DataMapItem.fromDataItem(event.dataItem).dataMap
                        val username = dm.getString("username", "")
                        val password = dm.getString("password", "")
                        if (username.isNotEmpty() && password.isNotEmpty()) {
                            applySyncedCredentials(username, password, "data-foreground")
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "foreground onDataChanged failed: $e")
                    }
                }
                DeviceSync.DEVICES_PATH -> {
                    try {
                        val dm = DataMapItem.fromDataItem(event.dataItem).dataMap
                        val devicesJson = dm.getString(DeviceSync.KEY_DEVICES_JSON, "")
                        if (!devicesJson.isNullOrEmpty()) {
                            applySyncedDevicesJson(devicesJson, "data-foreground")
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "foreground devices onDataChanged failed: $e")
                    }
                }
            }
        }
    }

    /** Foreground MessageClient listener: same path, direct push fallback. */
    private fun onMessageWhileForeground(event: MessageEvent) {
        Log.d(TAG, "foreground onMessageReceived path=${event.path}")
        if (event.path == "/opentapo/credentials") {
            val parts = String(event.data, Charsets.UTF_8).split("\n")
            if (parts.size >= 2 && parts[0].isNotEmpty() && parts[1].isNotEmpty()) {
                applySyncedCredentials(parts[0], parts[1], "message-foreground")
            }
        } else if (event.path == DeviceSync.DEVICES_PATH) {
            val devicesJson = String(event.data, Charsets.UTF_8)
            if (devicesJson.isNotEmpty()) {
                applySyncedDevicesJson(devicesJson, "message-foreground")
            }
        }
    }

    private fun applySyncedCredentials(username: String, password: String, source: String) {
        Log.d(TAG, "applySyncedCredentials via $source user=$username")
        credentials = Credentials(username, password)
        getSharedPreferences(SHARED_PREFS, Context.MODE_PRIVATE).edit()
            .putString(SHARED_PREFS_USERNAME, username)
            .putString(SHARED_PREFS_PASSWORD, password)
            .apply()
        runOnUiThread { onCredentials() }
    }

    /**
     * Pulls credentials directly from the Wear Data Layer by querying for the
     * pre-existing DataItem at path `/opentapo/credentials`.
     *
     * This handles the case where the phone pushed the credentials *before* the
     * watch app was opened. In that scenario the DataItem is already present on
     * the watch node, so `onDataChanged` (driven by `DataLayerListenerService`)
     * never fires — there is no CHANGE to report. By querying `getDataItems()`
     * we retrieve the already-synced item at startup.
     */
    private fun pullCredentialsFromDataLayer() {
        Log.d(TAG, "Pulling credentials from Wear Data Layer")
        GlobalScope.launch(Dispatchers.IO) {
            var found = false
            try {
                val client = Wearable.getDataClient(this@MainActivity)
                val uri = Uri.parse("wear://*/opentapo/credentials")
                val buffer = Tasks.await(client.getDataItems(uri))
                Log.d(TAG, "getDataItems returned count=${buffer.count}")
                try {
                    for (item in buffer) {
                        Log.d(TAG, "pull item path=${item.uri.path}")
                        if (item.uri.path == "/opentapo/credentials") {
                            val dm = DataMapItem.fromDataItem(item).dataMap
                            val username = dm.getString("username")
                            val password = dm.getString("password")
                            if (!username.isNullOrEmpty() && !password.isNullOrEmpty()) {
                                this@MainActivity.credentials = Credentials(username, password)
                                found = true
                                runOnUiThread { onCredentials() }
                                break
                            }
                        }
                    }
                } finally {
                    buffer.close()
                }
                if (!found) {
                    runOnUiThread {
                        Log.d(TAG, "No credentials found in Data Layer; starting LoginActivity")
                        startActivityForResult(
                            Intent(this@MainActivity, LoginActivity::class.java), 1
                        )
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to pull credentials from Wear Data Layer: $e")
                runOnUiThread {
                    startActivityForResult(
                        Intent(this@MainActivity, LoginActivity::class.java), 1
                    )
                }
            }
        }
    }

    // -- device-list sync (phone <-> watch) ----------------------------------

    /**
     * Merges a phone-pushed device list into the in-memory list and cache.
     * Remote entries win on id conflict (the sender just scanned or added
     * them, so its IPs are fresher); local-only entries are kept.
     */
    private fun applySyncedDevicesJson(devicesJson: String, source: String) {
        if (devicesJson == lastAppliedDevicesJson) {
            Log.d(TAG, "applySyncedDevices via $source: already applied; skipping")
            return
        }
        val remote = try {
            DeviceSync.devicesFromJson(devicesJson)
        } catch (e: Exception) {
            Log.e(TAG, "applySyncedDevices via $source: decode failed: $e")
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
            val seenIds = mutableSetOf<String>()
            remote.forEach {
                merged.add(it)
                seenIds.add(it.id)
            }
            devices.filter { !seenIds.contains(it.id) }.forEach {
                merged.add(it)
                seenIds.add(it.id)
            }
            devices.clear()
            devices.addAll(merged)
            setCachedDeviceList()
            if (credentials != null) {
                if (devices.isNotEmpty()) {
                    setActivityState(ActivityState.DEVICE_LIST)
                }
                reloadDeviceState()
            } else {
                Log.d(TAG, "applySyncedDevices: cached ${devices.size} device(s), waiting for credentials")
            }
        } finally {
            applyingRemoteDevices = false
        }
    }

    /**
     * Pulls an already-synced device list from the Data Layer. Handles the
     * case where the phone pushed while the watch app was closed (no change
     * event fires for a pre-existing DataItem).
     */
    private fun pullDevicesFromDataLayer() {
        Log.d(TAG, "Pulling devices from Wear Data Layer")
        GlobalScope.launch(Dispatchers.IO) {
            try {
                val client = Wearable.getDataClient(this@MainActivity)
                val uri = Uri.parse("wear://*" + DeviceSync.DEVICES_PATH)
                val buffer = Tasks.await(client.getDataItems(uri))
                try {
                    for (item in buffer) {
                        if (item.uri.path == DeviceSync.DEVICES_PATH) {
                            val dm = DataMapItem.fromDataItem(item).dataMap
                            val devicesJson = dm.getString(DeviceSync.KEY_DEVICES_JSON, "")
                            if (!devicesJson.isNullOrEmpty()) {
                                runOnUiThread { applySyncedDevicesJson(devicesJson, "data-pull") }
                                break
                            }
                        }
                    }
                } finally {
                    buffer.close()
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to pull devices from Wear Data Layer: $e")
            }
        }
    }

    /**
     * Pushes the current (locally enriched) device list to the phone.
     * No-op while applying a remote list (echo guard), when empty (never wipe
     * the peer's list from a fresh/empty state), or when unchanged.
     */
    private fun pushDevicesToMobile() {
        if (applyingRemoteDevices) return
        if (devices.isEmpty()) return
        val devicesJson = try {
            DeviceSync.devicesToJson(devices)
        } catch (e: Exception) {
            Log.e(TAG, "pushDevicesToMobile: encode failed: $e")
            return
        }
        if (devicesJson == lastPushedDevicesJson) return
        lastPushedDevicesJson = devicesJson
        lastAppliedDevicesJson = devicesJson
        Log.d(TAG, "Pushing ${devices.size} device(s) to mobile")
        SyncHelper.sendDevicesToMobile(this, devicesJson)
    }

    private fun onCredentials() {
        try {
            startPeriodicRefresh()
            if (this.devices.isNotEmpty()) {
                Log.d(TAG, "Credentials are set and devices too; reloading device state...")
                reloadDeviceState()
            } else {
                // Always run discovery when credentials are set and we have no
                // in-memory devices. Previously this only scanned when a cache
                // existed, so a fresh watch (empty cache) stayed on
                // NO_DEVICE_FOUND forever and never scanned the LAN.
                Log.d(TAG, "Credentials are set; discovering devices (cache fallback inside)")
                setActivityState(ActivityState.LOADING_DEVICE_LIST)
                GlobalScope.launch {
                    withContext(Dispatchers.IO) {
                        discoverDevices()
                    }
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
            Log.e(TAG, String.format("Failed to discover devices: %s", e))
            setActivityState(ActivityState.NO_DEVICE_FOUND)
        }
    }

    private fun reloadDeviceState() {
        Log.d(TAG, "Reloading device state...")
        val creds = this.credentials ?: return
        GlobalScope.launch {
            withContext(Dispatchers.IO) {
                devices.map { device ->
                    GlobalScope.async {
                        try {
                            if (!device.authenticated) {
                                Log.d(TAG, String.format("Device %s is not authenticated yet; signin in", device.alias))
                                device.login(creds.username, creds.password)
                            }
                            Log.d(TAG, String.format("Getting device state for %s", device.alias))
                            device.getDeviceStatus()
                        } catch (e: Exception) {
                            Log.e(TAG, String.format("Failed to get device state for %s: %s", device.alias, e))
                        }
                    }
                }.awaitAll()
            }
            if (devices.isNotEmpty()) {
                setActivityState(ActivityState.DEVICE_LIST)
            } else {
                setActivityState(ActivityState.NO_DEVICE_FOUND)
            }
        }
    }

    private suspend fun login(username: String, password: String) {
        Log.d(TAG, String.format("Signing in as %s", username))
        val client = TpLinkCloudClient()
        client.login(username, password)
        this.credentials = Credentials(username, password)
        onCredentials()
    }

    private fun discoverDevices() {
        Log.d(TAG, "discoverDevices")
        GlobalScope.launch {
            withContext(Dispatchers.IO) {
                // keep the current list until a scan produces results; never wipe
                // devices on a failed scan (fixes disappearing devices)
                val previousDevices = devices.toList()
                // Without a resolved network, always go through the Wi-Fi path
                // first (it tries a synchronous lookup, then requests Wi-Fi).
                // Probing discoverDevicesOnLocalNetwork() with a null network
                // would just throw "No link" and never resolve Wi-Fi.
                if (deviceNetwork == null) {
                    // do scan with wifi
                    discoverDevicesOnLocalNetworkWithWifi()
                } else {
                    try {
                        discoverDevicesOnLocalNetwork()
                    } catch (e: Exception) {
                        Log.e(TAG, String.format("Scan failed: %s; keeping %d known devices", e, previousDevices.size))
                        this@MainActivity.devices.clear()
                        this@MainActivity.devices.addAll(previousDevices)
                        if (devices.isNotEmpty()) {
                            setActivityState(ActivityState.DEVICE_LIST)
                            reloadDeviceState()
                        } else {
                            setActivityState(ActivityState.NO_DEVICE_FOUND)
                        }
                    }
                }
            }
        }
    }

    private fun discoverDevicesOnLocalNetwork() {
        Log.d(TAG, "discoverDevicesOnLocalNetwork")
        val previousDevices = this.devices.toList()
        val cachedDeviceList = getCachedDeviceAddressList()
        // Always run a live network scan; use cached/known devices as fallback
        // so nothing disappears when a device is temporarily unreachable or
        // its DHCP lease changed.
        val knownDevices = (previousDevices + (cachedDeviceList ?: emptyList()))
            .distinctBy { it.id }
        Log.d(TAG, String.format("Known devices before scan: %d", knownDevices.size))
        val scanner = DeviceScanner(
            credentials!!.username,
            credentials!!.password
        )
        val network = deviceNetwork
        if (network == null) {
            throw Exception("No link")
        }
        try {
            scanner.scanNetwork(network.first, network.second)
        } catch (e: Exception) {
            Log.e(TAG, String.format("Live scan failed: %s", e))
        }
        val scanned = scanner.devices
        Log.d(TAG, String.format("Scan found %d devices; merging with %d known", scanned.size, knownDevices.size))
        // merge: scanned (fresh state) wins over known entries with same id;
        // keep known devices not found in the scan (offline or IP changed)
        val merged = mutableListOf<Device>()
        val seenIds = mutableSetOf<String>()
        scanned.forEach { scanned_device ->
            merged.add(scanned_device)
            seenIds.add(scanned_device.id)
        }
        knownDevices.forEach { known ->
            if (!seenIds.contains(known.id)) {
                merged.add(known)
                seenIds.add(known.id)
            }
        }
        // re-check manually-registered devices the scan may have missed
        val foundIps = scanned.map { it.ipAddress }.toSet()
        runBlocking {
            for (ip in loadManualIps()) {
                if (!foundIps.contains(ip) && merged.none { it.ipAddress == ip }) {
                    try {
                        val addr = java.net.InetAddress.getByName(ip) as Inet4Address
                        val client = TapoClient(addr)
                        client.login(credentials!!.username, credentials!!.password)
                        merged.add(client.queryDevice())
                        Log.d(TAG, String.format("Manual device at %s reachable again", ip))
                    } catch (e: Exception) {
                        Log.w(TAG, String.format("Manual device at %s unreachable: %s", ip, e.message))
                    }
                }
            }
        }
        this.devices.clear()
        this.devices.addAll(merged)
        Log.d(TAG, String.format("Found %d devices after merge", this.devices.size))
        // cache devices
        setCachedDeviceList()
        // share with the phone (no-op when empty/unchanged/applying remote)
        pushDevicesToMobile()
        // set activity state
        if (devices.isNotEmpty()) {
            setActivityState(ActivityState.DEVICE_LIST)
        } else {
            setActivityState(ActivityState.NO_DEVICE_FOUND)
        }
        // reload device state
        reloadDeviceState()
    }

    private fun discoverDevicesOnLocalNetworkWithWifi() {

        Log.d(TAG, "discoverDevicesOnLocalNetworkWithWifi")

        val connectivityManager: ConnectivityManager =
            getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

        // Fast path: Wi-Fi may already be up; scan it synchronously instead of
        // waiting for a NetworkCallback (which also leaks if never unregistered).
        try {
            deviceNetwork = getDeviceNetworkAddresses()
            discoverDevicesOnLocalNetwork()
            return
        } catch (e: Exception) {
            Log.d(TAG, String.format("No usable network yet, requesting Wi-Fi: %s", e.message))
        }

        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                super.onAvailable(network)
                Log.d(TAG, "Wifi available")
                try {
                    connectivityManager.unregisterNetworkCallback(this)
                } catch (_: Exception) {
                }

                try {
                    deviceNetwork = getDeviceNetworkAddresses()
                } catch (e: Exception) {
                    e.printStackTrace()
                    Log.e(TAG, String.format("Failed to get device network address: %s", e))
                    setActivityState(ActivityState.NO_LINK)
                    return
                }
                discoverDevicesOnLocalNetwork()
            }

            override fun onUnavailable() {
                super.onUnavailable()
                Log.e(TAG, "Wi-Fi network unavailable")
                try {
                    connectivityManager.unregisterNetworkCallback(this)
                } catch (_: Exception) {
                }
                setActivityState(ActivityState.NO_LINK)
            }
        }

        connectivityManager.requestNetwork(
            NetworkRequest.Builder().addTransportType(NetworkCapabilities.TRANSPORT_WIFI).build(),
            callback
        )
    }

    /**
     * Returns (ip, netmask) of the Wi-Fi network.
     *
     * Mirrors the phone's localNetwork(): scores each interface so the Wi-Fi
     * interface carrying internet wins. The previous implementation returned
     * the first IPv4 across allNetworks in arbitrary order — on WearOS that
     * is often the Bluetooth PAN (proxy link to the phone) or loopback,
     * which made the scan probe the wrong subnet and find nothing.
     */
    private fun getDeviceNetworkAddresses(): Pair<String, String> {
        val connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE)

        if (connectivityManager is ConnectivityManager) {
            var best: Pair<String, String>? = null
            var bestScore = Int.MIN_VALUE
            for (network in connectivityManager.allNetworks) {
                val caps = connectivityManager.getNetworkCapabilities(network) ?: continue
                val link = connectivityManager.getLinkProperties(network) ?: continue
                var score = 0
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) score += 10
                if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) score += 5
                for (linkAddress in link.linkAddresses) {
                    val address = linkAddress.address
                    if (address is Inet4Address && !address.isLoopbackAddress) {
                        if (score > bestScore) {
                            bestScore = score
                            best = Pair(
                                address.hostAddress!!,
                                NetworkUtils.cidrToNetmask(linkAddress.prefixLength)
                            )
                        }
                    }
                }
            }
            if (best != null) {
                Log.d(
                    TAG,
                    String.format(
                        "Found local device address %s and netmask %s (score=%d)",
                        best.first,
                        best.second,
                        bestScore
                    )
                )
                return best
            }
        }

        throw Exception("No link")
    }

    private fun setActivityState(state: ActivityState) {
        this.state = state
        when (this.state) {
            ActivityState.DEVICE_LIST -> enterDeviceListState()
            ActivityState.LOADING_DEVICE_LIST -> enterLoadingDeviceListState()
            ActivityState.NO_DEVICE_FOUND -> enterNoDeviceFoundState()
            ActivityState.NO_LINK -> enterNoLinkState()
        }
    }

    private fun enterDeviceListState() {
        Log.d(TAG, "Entering device list state")
        updateHeaderDot(online = true)
        toggleLists(visible = true)
        toggleReloadIcon(visible = true)
        toggleNewDeviceIcon(visible = true)
        toggleNewGroupIcon(visible = false)
        toggleDelGroupIcon(visible = false)
        toggleMessageBox(visible = false)
        toggleLoading(loading = false)
        toggleAlert(visible = false)
    }

    private fun enterLoadingDeviceListState() {
        Log.d(TAG, "Entering loading devices state")
        updateHeaderDot(online = false)
        toggleLists(visible = false)
        toggleNewDeviceIcon(visible = false)
        toggleReloadIcon(visible = false)
        toggleNewGroupIcon(visible = false)
        toggleDelGroupIcon(visible = false)
        toggleMessageBox(visible = true)
        toggleLoading(loading = true)
        toggleAlert(visible = false)
    }

    private fun enterNoDeviceFoundState() {
        Log.d(TAG, "Entering no device found state")
        updateHeaderDot(online = false)
        toggleLists(visible = false)
        toggleReloadIcon(visible = true)
        toggleNewDeviceIcon(visible = true)
        toggleNewGroupIcon(visible = false)
        toggleDelGroupIcon(visible = false)
        toggleMessageBox(visible = true)
        toggleLoading(loading = false)
        toggleAlert(visible = true, R.string.main_activity_not_found, R.drawable.ic_no_devices)
    }

    private fun enterNoLinkState() {
        Log.d(TAG, "Entering no link state")
        updateHeaderDot(online = false)
        toggleLists(visible = false)
        toggleNewDeviceIcon(visible = true)
        toggleReloadIcon(visible = true)
        toggleNewGroupIcon(visible = false)
        toggleDelGroupIcon(visible = false)
        toggleMessageBox(visible = true)
        toggleLoading(loading = false)
        toggleAlert(visible = true, R.string.main_activity_no_network)

    }

    private fun populateDeviceList() {
        runOnUiThread {
            val deviceList: RecyclerView = findViewById(R.id.activity_main_device_list)
            val devicesAdapter = DeviceListAdapter(devices)
            deviceList.adapter = devicesAdapter
            deviceList.layoutManager = LinearLayoutManager(this)

            devicesAdapter.credentials = credentials!!
            devicesAdapter.onItemClick = {
                Log.d(
                    TAG,
                    String.format("Clicked on device %s; starting DeviceActivity", it.alias)
                )
                val intent = Intent(this, DeviceActivity::class.java)
                intent.putExtra(
                    DeviceActivity.DEVICE_DATA_INTENT_NAME, DeviceData(
                        it.alias, it.id, it.model, it.endpoint, it.ipAddress, it.status
                    )
                )
                intent.putExtra(DeviceActivity.CREDENTIALS_INTENT_NAME, credentials)
                startActivity(intent)
            }
            devicesAdapter.onItemLongClick = {
                Log.d(TAG, String.format("onItemLongClick for %s", it.alias))
                if (this.selectedDevices.contains(it.id)) {
                    this.selectedDevices.remove(it.id)
                    if (this.selectedDevices.isEmpty()) {
                        this.toggleNewGroupIcon(visible = false)
                    }
                } else {
                    this.selectedDevices.add(it.id)
                    this.toggleNewGroupIcon(visible = true)
                }
            }
        }
    }

    private fun populateGroupsList() {
        runOnUiThread {
            val groupsList: RecyclerView = findViewById(R.id.activity_main_group_list)
            val groupsLabel: TextView = findViewById(R.id.activity_main_group_list_label)
            if (this.deviceGroups.getNames().isEmpty()) {
                groupsList.visibility = View.GONE
                groupsLabel.visibility = View.GONE
            } else {
                groupsLabel.visibility = View.VISIBLE
                groupsList.visibility = View.VISIBLE
                val groupsAdapter = GroupListAdapter(
                    this.deviceGroups.getNames().map { name ->
                        val deviceIds = this.deviceGroups.getDevices(name)
                        val devices = this.devices.filter { device ->
                            deviceIds.contains(device.id)
                        }
                        Pair(name, devices)
                    }
                )
                groupsList.adapter = groupsAdapter
                groupsList.layoutManager = LinearLayoutManager(this)

                groupsAdapter.credentials = credentials!!
                groupsAdapter.onItemClick = {
                    Log.d(
                        TAG,
                        String.format("Clicked on group %s; starting GroupManagementActivity", it)
                    )
                    val devices: List<Device> = this.deviceGroups.getDevices(it).mapNotNull { id ->
                        this.devices.find { device ->
                            device.id == id
                        }
                    }
                    val intent = Intent(this, GroupManagementActivity::class.java)
                    intent.putExtra(
                        GroupManagementActivity.GROUP_DATA_INTENT_NAME,
                        GroupData(it, devices.map { device ->
                            DeviceData(
                                device.alias,
                                device.id,
                                device.model,
                                device.endpoint,
                                device.ipAddress,
                                device.status
                            )
                        }
                        )
                    )
                    intent.putExtra(GroupManagementActivity.CREDENTIALS_INTENT_NAME, credentials)
                    startActivity(intent)
                }
                groupsAdapter.onItemLongClick = {
                    Log.d(TAG, String.format("On long click for %s", it))
                    if (this.selectedGroups.contains(it)) {
                        this.selectedGroups.remove(it)
                        if (this.selectedGroups.isEmpty()) {
                            this.toggleDelGroupIcon(visible = false)
                        }
                    } else {
                        this.selectedGroups.add(it)
                        this.toggleDelGroupIcon(visible = true)
                    }
                }
            }
        }
    }

    private fun toggleLists(visible: Boolean) {
        runOnUiThread {
            Log.d(TAG, "toggle lists")
            val lists: ScrollView = findViewById(R.id.activity_main_lists)

            if (visible) {
                lists.visibility = View.VISIBLE
                lists.alpha = 0f
                lists.animate().alpha(1f).setDuration(220).start()
                populateDeviceList()
                populateGroupsList()
            } else {
                lists.animate().alpha(0f).setDuration(150).withEndAction {
                    lists.visibility = View.GONE
                    lists.alpha = 1f
                }.start()
            }
        }
    }

    /** Green header dot when a live device list is shown, red otherwise. */
    private fun updateHeaderDot(online: Boolean) {
        runOnUiThread {
            try {
                val dot: View = findViewById(R.id.activity_main_conn_dot)
                dot.setBackgroundResource(if (online) R.drawable.dot_on else R.drawable.dot_off)
            } catch (_: Exception) {
            }
        }
    }

    private fun toggleMessageBox(visible: Boolean) {
        runOnUiThread {
            val messageBox: LinearLayout = findViewById(R.id.activity_main_message_box)
            if (visible) {
                messageBox.visibility = View.VISIBLE
                messageBox.alpha = 0f
                messageBox.animate().alpha(1f).setDuration(220).start()
            } else {
                messageBox.animate().alpha(0f).setDuration(150).withEndAction {
                    messageBox.visibility = View.GONE
                    messageBox.alpha = 1f
                }.start()
            }
        }
    }

    private fun toggleLoading(loading: Boolean) {
        runOnUiThread {
            val alertIcon: ImageView = findViewById(R.id.activity_main_error_icon)
            val progress: ProgressBar = findViewById(R.id.activity_main_progressbar)
            val message: TextView = findViewById(R.id.activity_main_message)

            if (loading) {
                alertIcon.visibility = View.GONE
                progress.visibility = View.VISIBLE
                message.visibility = View.VISIBLE
                message.text = resources.getString(R.string.main_activity_loading)
            } else {
                progress.visibility = View.GONE
            }
        }
    }

    private fun toggleAlert(visible: Boolean, message: Int? = null, alertDrawable: Int = R.drawable.ic_warning) {
        runOnUiThread {
            val alertIcon: ImageView = findViewById(R.id.activity_main_error_icon)

            if (visible) {
                alertIcon.visibility = View.VISIBLE
                alertIcon.setImageResource(alertDrawable)
                val messageView: TextView = findViewById(R.id.activity_main_message)
                if (message != null) {
                    messageView.visibility = View.VISIBLE
                    messageView.text = resources.getString(message)
                } else {
                    messageView.visibility = View.GONE
                }
            } else {
                alertIcon.visibility = View.GONE
            }
        }
    }

    private fun toggleReloadIcon(visible: Boolean) {
        runOnUiThread {
            val reloadIcon: ImageButton = findViewById(R.id.activity_main_reload)
            if (visible) {
                reloadIcon.visibility = View.VISIBLE
            } else {
                reloadIcon.visibility = View.GONE
            }
        }
    }

    private fun toggleNewDeviceIcon(visible: Boolean) {
        runOnUiThread {
            val icon: ImageButton = findViewById(R.id.activity_main_new_device)
            if (visible) {
                icon.visibility = View.VISIBLE
            } else {
                icon.visibility = View.GONE
            }
        }
    }

    private fun toggleNewGroupIcon(visible: Boolean) {
        runOnUiThread {
            val newGroupIcon: ImageButton = findViewById(R.id.activity_main_new_group)
            if (visible) {
                newGroupIcon.visibility = View.VISIBLE
            } else {
                newGroupIcon.visibility = View.GONE
            }
        }
    }

    private fun toggleDelGroupIcon(visible: Boolean) {
        runOnUiThread {
            val delGroupIcon: ImageButton = findViewById(R.id.activity_main_del_group)
            if (visible) {
                delGroupIcon.visibility = View.VISIBLE
            } else {
                delGroupIcon.visibility = View.GONE
            }
        }
    }

    private fun readCredentialsFromPrefs() {
        Log.d(TAG, "Trying to retrieve credentials from shared preferences")
        val sharedPrefs = getSharedPreferences(SHARED_PREFS, Context.MODE_PRIVATE)

        val username = if (sharedPrefs.contains(SHARED_PREFS_USERNAME)) {
            sharedPrefs.getString(SHARED_PREFS_USERNAME, "")
        } else {
            null
        }
        val password = if (sharedPrefs.contains(SHARED_PREFS_PASSWORD)) {
            sharedPrefs.getString(SHARED_PREFS_PASSWORD, "")
        } else {
            null
        }
        if (username != null && password != null) {
            // login and discover devices
            Log.d(TAG, String.format("Found credentials for %s", username))
            val fallbackIntent = Intent(this, LoginActivity::class.java)
            runBlocking {
                withContext(Dispatchers.IO) {
                    try {
                        login(username, password)
                        Log.d(TAG, "Login successful")
                    } catch (e: Exception) {
                        Log.e(TAG, String.format("Login failed: %s; going to login activity", e))
                        runOnUiThread {
                            startActivity(fallbackIntent)
                        }
                    }
                }
            }
        }
    }

    private fun getCachedDeviceAddressList(): List<Device>? {
        Log.d(TAG, "Trying to retrieve cached device list from shared preferences")
        val sharedPrefs = getSharedPreferences(SHARED_PREFS, Context.MODE_PRIVATE)
        if (sharedPrefs.contains(SHARED_PREFS_CACHED_DEVICES)) {
            val cachedDevices = sharedPrefs.getString(SHARED_PREFS_CACHED_DEVICES, "")
            Log.d(TAG, String.format("Found device list: %s", cachedDevices))
            return DeviceCache(cachedDevices!!).devices()
        }
        return null
    }

    private fun setCachedDeviceList() {
        Log.d(TAG, "Writing cached device list to preferences")
        val sharedPrefs = getSharedPreferences(SHARED_PREFS, Context.MODE_PRIVATE)
        val editor = sharedPrefs.edit()
        val payload = DeviceCache(this.devices)
        editor.putString(SHARED_PREFS_CACHED_DEVICES, payload.serialize())
        editor.apply()
        Log.d(TAG, String.format("Device list written as %s", payload))
    }

    @SuppressLint("ApplySharedPref")
    private fun deleteCachedDeviceList() {
        Log.d(TAG, "Deleting cached device list from preferences")
        val sharedPrefs = getSharedPreferences(SHARED_PREFS, Context.MODE_PRIVATE)
        val editor = sharedPrefs.edit()
        editor.remove(SHARED_PREFS_CACHED_DEVICES)
        editor.commit()
        Log.d(TAG, "Device cached list cleared")
    }

    private fun getDeviceGroups() {
        Log.d(TAG, "Trying to retrieve device groups from shared preferences")
        val sharedPrefs = getSharedPreferences(SHARED_PREFS, Context.MODE_PRIVATE)
        if (sharedPrefs.contains(SHARED_PREFS_DEVICE_GROUPS)) {
            val deviceGroups = sharedPrefs.getString(SHARED_PREFS_DEVICE_GROUPS, "")
            Log.d(TAG, String.format("Found device groups: %s", deviceGroups))
            this.deviceGroups = DeviceGroups(deviceGroups!!)
        }
    }

    private fun commitDeviceGroups() {
        Log.d(TAG, "Saving changes to device groups")
        val sharedPrefs = getSharedPreferences(SHARED_PREFS, Context.MODE_PRIVATE)
        val editor = sharedPrefs.edit()
        editor.putString(SHARED_PREFS_DEVICE_GROUPS, deviceGroups.serialize())
        editor.apply()
        Log.d(TAG, "Device groups saved")
    }

    companion object {
        const val TAG = "MainActivity"
        const val DEVICE_STATE_REFRESH_MS = 15000L
        const val SHARED_PREFS = "Otapo"
        const val SHARED_PREFS_USERNAME = "username"
        const val SHARED_PREFS_PASSWORD = "password"
        const val SHARED_PREFS_CACHED_DEVICES = "cachedDeviceList"
        const val SHARED_PREFS_DEVICE_GROUPS = "deviceGroups"
        const val SHARED_PREFS_MANUAL_IPS = "manualIps"
    }

    @Suppress("DEPRECATION")
    private fun <T : Parcelable> parcelableExtraCompat(data: Intent, key: String, clazz: Class<T>): T? {
        return if (Build.VERSION.SDK_INT >= 33) {
            data.getParcelableExtra(key, clazz)
        } else {
            data.getParcelableExtra(key)
        }
    }

    private fun startPeriodicRefresh() {
        GlobalScope.launch {
            while (isActive && credentials != null) {
                delay(DEVICE_STATE_REFRESH_MS)
                if (state == ActivityState.DEVICE_LIST) {
                    Log.d(TAG, "Periodic device state refresh")
                    reloadDeviceState()
                }
            }
        }
    }

}
