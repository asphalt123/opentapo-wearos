package com.hn.otapo.net

import android.util.Log
import com.hn.otapo.tapo.device.Device
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
        // Truly bounded scan: start at most MAX_CONCURRENT_THREADS workers,
        // wait for the batch, then start the next one. (Spawning 250+ threads
        // at once starves/kills a low-power wearable process before the scan
        // completes.)
        var offset = 0
        while (offset < addressToFetch.size) {
            val end = minOf(offset + MAX_CONCURRENT_THREADS, addressToFetch.size)
            val batch = addressToFetch.subList(offset, end).map {
                DeviceScannerWorker(it, username, password)
            }
            val threads = batch.map {
                Thread(it).also { t ->
                    t.priority = Thread.MIN_PRIORITY
                    t.start()
                }
            }
            threads.forEach { it.join() }
            offset = end
            // get devices
            batch.forEach {
                if (it.device != null) {
                    this.devices.add(it.device!!)
                }
            }
            Log.d(TAG, String.format("Scan progress: %d/%d addresses probed", offset, addressToFetch.size))
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
