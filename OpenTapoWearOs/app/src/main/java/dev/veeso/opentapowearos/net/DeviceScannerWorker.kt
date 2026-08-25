package dev.veeso.opentapowearos.net

import android.util.Log
import dev.veeso.opentapowearos.tapo.api.tapo.TapoClient
import dev.veeso.opentapowearos.tapo.device.Device
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import java.net.Inet4Address
import java.net.InetSocketAddress
import java.net.Socket

class DeviceScannerWorker(address: Inet4Address, username: String, password: String) : Runnable {

    private val address: Inet4Address
    private val username: String
    private val password: String
    private val tag: String

    var device: Device? = null

    init {
        this.address = address
        this.username = username
        this.password = password
        this.tag = String.format("DeviceScannerWorker[%s]", address.hostAddress!!)
    }

    override fun run() {
        runBlocking {
            withContext(Dispatchers.IO) {
                // ICMP ping (InetAddress.isReachable) is unreliable on Android and
                // usually blocked by Tapo devices; probe TCP port 80 instead.
                if (!isHttpPortOpen()) {
                    Log.d(tag, "Port 80 closed; not a Tapo device")
                    return@withContext
                }
                val client = TapoClient(address)
                try {
                    client.login(username, password)
                    Log.d(
                        tag,
                        "Successfully signed in to device; getting device info..."
                    )
                    device = client.queryDevice()
                } catch (e: Exception) {
                    Log.e(tag, String.format("Discovery failed: %s", e.message))
                }
            }
        }
    }

    /** True when something answers on TCP/80 (all Tapo devices expose their HTTP API there). */
    private fun isHttpPortOpen(): Boolean {
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(address, HTTP_PORT), PORT_TIMEOUT_MS)
                true
            }
        } catch (e: Exception) {
            false
        }
    }

    companion object {
        const val TAG = "DeviceScannerWorker"
        const val HTTP_PORT = 80
        const val PORT_TIMEOUT_MS = 1200
    }

}
