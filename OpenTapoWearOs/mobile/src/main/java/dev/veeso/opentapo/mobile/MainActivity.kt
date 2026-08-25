package dev.veeso.opentapo.mobile

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout
import com.google.android.material.appbar.MaterialToolbar
import dev.veeso.opentapo.mobile.net.DeviceScanner
import dev.veeso.opentapo.mobile.net.NetworkUtils
import dev.veeso.opentapo.mobile.tapo.device.Device
import dev.veeso.opentapo.mobile.view.intent_data.Credentials
import dev.veeso.opentapo.mobile.view.main.DeviceAdapter
import kotlinx.coroutines.*
import java.net.Inet4Address

class MainActivity : AppCompatActivity() {

    private var credentials: Credentials? = null
    private val devices = mutableListOf<Device>()
    private lateinit var adapter: DeviceAdapter
    private lateinit var refreshLayout: SwipeRefreshLayout
    private lateinit var emptyView: TextView
    private lateinit var progress: ProgressBar

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val toolbar: MaterialToolbar = findViewById(R.id.toolbar)
        toolbar.setOnMenuItemClickListener { item ->
            when (item.itemId) {
                R.id.action_logout -> {
                    logout()
                    true
                }
                R.id.action_add_ip -> {
                    val intent = Intent(this, AddDeviceActivity::class.java)
                    intent.putExtra(AddDeviceActivity.EXTRA_CREDENTIALS, credentials)
                    startActivityForResult(intent, REQUEST_ADD_DEVICE)
                    true
                }
                else -> false
            }
        }

        adapter = DeviceAdapter(devices) { device, newState ->
            toggleDevice(device, newState)
        }

        val list: RecyclerView = findViewById(R.id.device_list)
        list.layoutManager = LinearLayoutManager(this)
        list.adapter = adapter

        refreshLayout = findViewById(R.id.swipe_refresh)
        refreshLayout.setColorSchemeColors(getColor(R.color.op_accent))
        refreshLayout.setOnRefreshListener { discover() }

        emptyView = findViewById(R.id.empty_view)
        progress = findViewById(R.id.progress)

        credentials = readCredentials()
        if (credentials == null) {
            startActivity(Intent(this, LoginActivity::class.java))
            finish()
        } else {
            discover()
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
        finish()
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
                    Toast.makeText(this@MainActivity,
                        "Pas de réseau Wi-Fi détecté — vérifie que le téléphone est en Wi-Fi",
                        Toast.LENGTH_LONG).show()
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
                                val client = dev.veeso.opentapo.mobile.tapo.api.tapo.TapoClient(addr)
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
                devices.clear()
                devices.addAll(scanned.sortedBy { it.alias })
                adapter.notifyDataSetChanged()
                emptyView.visibility = if (devices.isEmpty()) View.VISIBLE else View.GONE
                if (devices.isEmpty()) {
                    Toast.makeText(this@MainActivity,
                        "Aucune prise trouvée sur ${network ?: "?"}. " +
                        "Vérifie que la compatibilité tierce est activée dans l'app Tapo " +
                        "(Profil → Paramètres → Compatibilité appareils tiers).",
                        Toast.LENGTH_LONG).show()
                }
            } catch (e: Exception) {
                Log.e(TAG, "Discovery failed", e)
                Toast.makeText(this@MainActivity, getString(R.string.error_generic, e.message), Toast.LENGTH_LONG).show()
                emptyView.visibility = View.VISIBLE
            } finally {
                progress.visibility = View.GONE
                refreshLayout.isRefreshing = false
            }
        }
    }

    /** Returns (ip, netmask) of the wifi network, or null when unavailable. */
    private fun localNetwork(): Pair<String, String>? {
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
            } catch (e: Exception) {
                Log.e(TAG, "Toggle failed", e)
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@MainActivity, getString(R.string.error_generic, e.message), Toast.LENGTH_SHORT).show()
                }
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
        const val REQUEST_ADD_DEVICE = 2
    }
}
