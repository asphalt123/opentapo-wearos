package dev.veeso.opentapo.mobile.net

import android.util.Log
import dev.veeso.opentapo.mobile.tapo.device.Device
import java.net.Inet4Address


class DeviceScanner(username: String, password: String) {

    private val username: String
    private val password: String

    val devices: MutableList<Device>

    init {
        this.username = username
        this.password = password
        this.devices = mutableListOf()
    }

    fun scanNetwork(deviceIp: String, deviceMask: String) {
        doScanNetwork(buildNetworkAddressList(deviceIp, deviceMask))
    }

    private fun doScanNetwork(addressToFetch: List<Inet4Address>) {
        // bounded thread pool: spawning 250+ threads at once can starve a
        // low-power device before the scan completes
        val workers = addressToFetch.map { DeviceScannerWorker(it, username, password) }
        val threads = workers.map {
            Thread(it).also { t ->
                t.priority = Thread.MIN_PRIORITY
                t.start()
            }
        }
        var started = 0
        while (started < threads.size) {
            val batch = threads.subList(started, minOf(started + MAX_CONCURRENT_THREADS, threads.size))
            batch.forEach { it.join() }
            started += batch.size
            Log.d(TAG, String.format("Scan progress: %d/%d addresses probed", started, threads.size))
        }
        // get devices
        workers.forEach {
            if (it.device != null) {
                this.devices.add(it.device!!)
            }
        }
        Log.d(TAG, String.format("Scan terminated; found %d devices", this.devices.size))
    }

    private fun buildNetworkAddressList(deviceIp: String, deviceMask: String): List<Inet4Address> {
        val networkAddress = NetworkUtils.getNetworkAddress(deviceIp, deviceMask)
        Log.d(TAG, String.format("Found network address: %s", networkAddress))
        val broadcastAddress = NetworkUtils.getBroadcastAddress(deviceIp, deviceMask)
        Log.d(TAG, String.format("Found broadcast address: %s", broadcastAddress))
        Log.d(TAG, String.format("Scanning network %s", networkAddress))
        var workingAddress = NetworkUtils.incrementAddress(networkAddress)

        val addressToFetch = mutableListOf<Inet4Address>()

        while (workingAddress != broadcastAddress) {
            addressToFetch.add(workingAddress)
            workingAddress = NetworkUtils.incrementAddress(workingAddress)
        }

        return addressToFetch
    }

    companion object {
        const val TAG = "IpFinder"
        const val MAX_CONCURRENT_THREADS = 32
    }
}
