package com.hn.otapo.control

import android.content.Context
import android.util.Log
import com.hn.otapo.data.CredentialsProvider
import com.hn.otapo.data.DeviceStore
import com.hn.otapo.tapo.api.tapo.TapoClient
import com.hn.otapo.tapo.api.tapo.request.params.SetLightBulbDeviceInfoParams
import com.hn.otapo.tapo.api.tapo.request.params.SetRgbLightBulbDeviceInfoParams
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.Inet4Address

/**
 * Direct light control (brightness / hue+saturation / color temperature)
 * over KLAP, without leaving the control screen.
 *
 * Parameter choice follows the model: plain bulbs get
 * [SetLightBulbDeviceInfoParams], RGB bulbs get [SetRgbLightBulbDeviceInfoParams].
 */
object LightController {

    private const val TAG = "LightController"

    sealed interface LightResult {
        object Ok : LightResult
        object NoCredentials : LightResult
        object UnknownDevice : LightResult
        data class Error(val message: String?) : LightResult
    }

    suspend fun setBrightness(context: Context, deviceId: String, brightness: Int): LightResult =
        withContext(Dispatchers.IO) {
            val device = DeviceStore.findById(context, deviceId) ?: return@withContext LightResult.UnknownDevice
            val creds = CredentialsProvider.get(context) ?: return@withContext LightResult.NoCredentials
            try {
                val client = newClient(device.ipAddress, device.endpoint)
                client.login(creds.username, creds.password)
                val level = brightness.coerceIn(1, 100)
                if (DeviceCapabilities.isRgb(device.model, device.type)) {
                    client.setDeviceInfo(SetRgbLightBulbDeviceInfoParams(brightness = level))
                } else {
                    client.setDeviceInfo(SetLightBulbDeviceInfoParams(brightness = level))
                }
                Log.i(TAG, "${device.alias} brightness=$level")
                LightResult.Ok
            } catch (e: Exception) {
                Log.e(TAG, "setBrightness failed", e)
                LightResult.Error(e.message)
            }
        }

    suspend fun setColor(context: Context, deviceId: String, hue: Int, saturation: Int): LightResult =
        withContext(Dispatchers.IO) {
            val device = DeviceStore.findById(context, deviceId) ?: return@withContext LightResult.UnknownDevice
            val creds = CredentialsProvider.get(context) ?: return@withContext LightResult.NoCredentials
            try {
                val client = newClient(device.ipAddress, device.endpoint)
                client.login(creds.username, creds.password)
                client.setDeviceInfo(
                    SetRgbLightBulbDeviceInfoParams(
                        hue = hue.coerceIn(0, 360),
                        saturation = saturation.coerceIn(0, 100)
                    )
                )
                Log.i(TAG, "${device.alias} hue=$hue sat=$saturation")
                LightResult.Ok
            } catch (e: Exception) {
                Log.e(TAG, "setColor failed", e)
                LightResult.Error(e.message)
            }
        }

    suspend fun setColorTemp(context: Context, deviceId: String, kelvin: Int): LightResult =
        withContext(Dispatchers.IO) {
            val device = DeviceStore.findById(context, deviceId) ?: return@withContext LightResult.UnknownDevice
            val creds = CredentialsProvider.get(context) ?: return@withContext LightResult.NoCredentials
            try {
                val client = newClient(device.ipAddress, device.endpoint)
                client.login(creds.username, creds.password)
                val temp = kelvin.coerceIn(2500, 6500)
                if (DeviceCapabilities.isRgb(device.model, device.type)) {
                    client.setDeviceInfo(SetRgbLightBulbDeviceInfoParams(color_temp = temp))
                } else {
                    client.setDeviceInfo(SetLightBulbDeviceInfoParams(color_temp = temp))
                }
                Log.i(TAG, "${device.alias} color_temp=$temp")
                LightResult.Ok
            } catch (e: Exception) {
                Log.e(TAG, "setColorTemp failed", e)
                LightResult.Error(e.message)
            }
        }

    private fun newClient(ip: String, endpoint: String): TapoClient {
        return try {
            val bytes = ip.split(".").map { it.toInt().toByte() }.toByteArray()
            TapoClient(java.net.Inet4Address.getByAddress(bytes) as Inet4Address)
        } catch (_: Exception) {
            TapoClient(endpoint)
        }
    }
}
