package dev.veeso.opentapo.mobile.tapo.device

import android.util.Log
import dev.veeso.opentapo.mobile.tapo.api.tapo.TapoClient
import dev.veeso.opentapo.mobile.tapo.api.tapo.request.params.SetGenericDeviceInfoParams
import dev.veeso.opentapo.mobile.view.intent_data.Credentials

abstract class Device(
    deviceAlias: String,
    deviceId: String,
    endpoint: String,
    ipAddress: String,
    deviceType: DeviceType,
    deviceModel: DeviceModel,
    deviceStatus: DeviceStatus
) {

    val alias: String
    val id: String
    val model: DeviceModel
    val type: DeviceType
    val endpoint: String
    val ipAddress: String
    var status: DeviceStatus

    private var lastCredentials: Credentials? = null

    val authenticated: Boolean get() = client.authenticated

    protected lateinit var client: TapoClient

    init {
        this.alias = deviceAlias
        this.id = deviceId
        this.model = deviceModel
        this.type = deviceType
        this.endpoint = endpoint
        this.ipAddress = ipAddress
        this.status = deviceStatus
        
        // Parse IP address from ipAddress string to create client with IP constructor
        // This enables KLAP protocol support for device control
        try {
            val ipBytes = ipAddress.split(".").map { it.toInt().toByte() }.toByteArray()
            val inet4Address = java.net.Inet4Address.getByAddress(ipBytes) as java.net.Inet4Address
            this.client = TapoClient(inet4Address)
        } catch (e: Exception) {
            // Fallback to URL-based constructor if IP parsing fails
            Log.w(TAG, "Failed to parse IP address, falling back to URL constructor: ${e.message}")
            this.client = TapoClient(endpoint)
        }
    }

    suspend fun login(username: String, password: String) {
        this.client.login(username, password)
        this.lastCredentials = Credentials(username, password)
    }

    /**
     * Re-authenticates using the credentials stored from the last successful login.
     * Returns true if re-login succeeded.
     */
    suspend fun reauthenticate(): Boolean {
        val cred = lastCredentials ?: return false
        return try {
            this.client.login(cred.username, cred.password)
            true
        } catch (e: Exception) {
            Log.e(TAG, "Re-authentication failed: ${e.message}")
            false
        }
    }

    /**
     * Executes [block], retrying once with a fresh login if the session has expired
     * (error code -1 / session timeout / network error on an authenticated device).
     */
    suspend fun <T> withSessionRetry(block: suspend () -> T): T {
        return try {
            block()
        } catch (e: Exception) {
            Log.w(TAG, "Request failed (${e.message}); attempting re-authentication")
            if (reauthenticate()) {
                block()
            } else {
                throw e
            }
        }
    }

    suspend fun on() = withSessionRetry {
        Log.d(TAG, "Powering device ON")
        this.client.setDeviceInfo(SetGenericDeviceInfoParams(device_on = true))
    }

    suspend fun off() = withSessionRetry {
        Log.d(TAG, "Powering device OFF")
        this.client.setDeviceInfo(SetGenericDeviceInfoParams(device_on = false))
    }

    suspend fun getDeviceStatus(): DeviceStatus = withSessionRetry {
        Log.d(TAG, "Getting device info")
        val deviceInfo = this.client.getDeviceInfo()
        this.status = DeviceStatus(
            deviceOn = deviceInfo.device_on,
            brightness = deviceInfo.brightness,
            hue = deviceInfo.hue,
            saturation = deviceInfo.saturation,
            colorTemperature = deviceInfo.color_temp
        )
        this.status
    }

    companion object {
        const val TAG = "Device"
    }

}

