package dev.veeso.opentapowearos

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.*
import android.os.Bundle
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
import dev.veeso.opentapowearos.databinding.ActivityMainBinding
import dev.veeso.opentapowearos.net.DeviceScanner
import dev.veeso.opentapowearos.net.NetworkUtils
import dev.veeso.opentapowearos.tapo.api.tplinkcloud.TpLinkCloudClient
import dev.veeso.opentapowearos.tapo.device.Device
import dev.veeso.opentapowearos.tapo.device.DeviceBuilder
import dev.veeso.opentapowearos.view.app_data.DeviceCache
import dev.veeso.opentapowearos.view.app_data.DeviceGroups
import dev.veeso.opentapowearos.view.intent_data.*
import dev.veeso.opentapowearos.view.intent_data.Credentials
import dev.veeso.opentapowearos.view.main_activity.ActivityState
import dev.veeso.opentapowearos.view.main_activity.DeviceListAdapter
import dev.veeso.opentapowearos.view.main_activity.GroupListAdapter
import kotlinx.coroutines.*
import java.net.Inet4Address

@OptIn(DelicateCoroutinesApi::class)
class MainActivity : Activity() {

    private lateinit var binding: ActivityMainBinding

    // credentials
    private var credentials: Credentials? = null

    // devices
    private var devices: MutableList<Device> = mutableListOf()
    private var deviceGroups: DeviceGroups = DeviceGroups()

    // network
    private var deviceNetwork: Pair<String, String>? = null

    // states
    private var state: ActivityState = ActivityState.LOADING_DEVICE_LIST
    private var selectedDevices: MutableList<String> = mutableListOf()
    private var selectedGroups: MutableList<String> = mutableListOf()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

    }

    override fun onResume() {
        super.onResume()
        Log.d(TAG, "onResume")

        setActivityState(ActivityState.NO_DEVICE_FOUND)

        // get groups
        this.getDeviceGroups()

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
            val credentials = data.getParcelableExtra<Credentials>(LoginActivity.INTENT_OUTPUT)
            if (credentials is Credentials) {
                onLoginActivityResult(credentials)
            }
            val groups = data.getParcelableExtra<NewGroupOutput>(NewGroupActivity.INTENT_OUTPUT)
            if (groups is NewGroupOutput) {
                onNewGroupActivityResult(groups)
            }
            val newDevice = data.getParcelableExtra<DeviceData>(DeviceSetupActivity.INTENT_OUTPUT)
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
        Log.d(TAG, String.format("Got DeviceSetup activity result: %s", deviceData))
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
            setCachedDeviceList()
            setActivityState(ActivityState.DEVICE_LIST)
        }
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

        // if still NULL; try to read from intent
        if (this.credentials != null) {
            onCredentials()
        } else {
            Log.d(
                TAG,
                "Credentials not in intent and not in preferences. Starting LoginActivity"
            )
            startActivityForResult(Intent(this, LoginActivity::class.java), 1)
        }
    }

    private fun onCredentials() {
        try {
            startPeriodicRefresh()
            val cachedDevices = getCachedDeviceAddressList()
            if (this.devices.isNotEmpty()) {
                Log.d(TAG, "Credentials are set and devices too; reloading device state...")
                reloadDeviceState()
            } else if (cachedDevices != null && cachedDevices.isNotEmpty()) {
                Log.d(TAG, "Cached devices is NOT empty; discover devices")
                discoverDevices()
            } else {
                // set no device
                setActivityState(ActivityState.NO_DEVICE_FOUND)
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
                val cachedDeviceList = getCachedDeviceAddressList()
                if ((cachedDeviceList == null || cachedDeviceList.isEmpty()) && deviceNetwork == null) {
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
        this.devices.clear()
        this.devices.addAll(merged)
        Log.d(TAG, String.format("Found %d devices after merge", this.devices.size))
        // cache devices
        setCachedDeviceList()
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

        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                super.onAvailable(network)
                Log.d(TAG, "Wifi available")

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
        }

        connectivityManager.requestNetwork(
            NetworkRequest.Builder().addTransportType(NetworkCapabilities.TRANSPORT_WIFI).build(),
            callback
        )
    }

    private fun getDeviceNetworkAddresses(): Pair<String, String> {
        val connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE)

        if (connectivityManager is ConnectivityManager) {
            val networks = connectivityManager.allNetworks
            // pick the first network that has an IPv4 link address (the old code
            // blindly took the last network and address index 1, which crashes
            // or returns the wrong interface depending on device setup)
            for (network in networks) {
                val link = connectivityManager.getLinkProperties(network) ?: continue
                for (linkAddress in link.linkAddresses) {
                    val address = linkAddress.address
                    if (address is Inet4Address) {
                        val netmask = NetworkUtils.cidrToNetmask(linkAddress.prefixLength)
                        Log.d(
                            TAG,
                            String.format(
                                "Found local device address %s and netmask %s",
                                address.hostAddress,
                                netmask
                            )
                        )
                        return Pair(address.hostAddress!!, netmask)
                    }
                }
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
                populateDeviceList()
                populateGroupsList()
            } else {
                lists.visibility = View.GONE
            }
        }
    }

    private fun toggleMessageBox(visible: Boolean) {
        runOnUiThread {
            val messageBox: LinearLayout = findViewById(R.id.activity_main_message_box)
            if (visible) {
                messageBox.visibility = View.VISIBLE
            } else {
                messageBox.visibility = View.GONE
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
        const val SHARED_PREFS = "OpenTapoWearOs"
        const val SHARED_PREFS_USERNAME = "username"
        const val SHARED_PREFS_PASSWORD = "password"
        const val SHARED_PREFS_CACHED_DEVICES = "cachedDeviceList"
        const val SHARED_PREFS_DEVICE_GROUPS = "deviceGroups"
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
