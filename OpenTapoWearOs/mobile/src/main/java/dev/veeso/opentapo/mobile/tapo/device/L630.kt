package dev.veeso.opentapo.mobile.tapo.device

import android.util.Log
import dev.veeso.opentapo.mobile.tapo.api.tapo.request.params.SetLightBulbDeviceInfoParams
import dev.veeso.opentapo.mobile.tapo.api.tapo.request.params.SetRgbLightBulbDeviceInfoParams
import dev.veeso.opentapo.mobile.view.device_activity.Color

class L630(
    deviceAlias: String,
    deviceId: String,
    endpoint: String,
    ipAddress: String,
    deviceStatus: DeviceStatus,
) : Device(
    deviceAlias,
    deviceId,
    endpoint,
    ipAddress,
    DeviceType.RGB_LIGHT_BULB,
    DeviceModel.L630,
    deviceStatus
) {

    suspend fun setBrightness(brightness: Int) {
        Log.d(TAG, String.format("Setting brightness to %d", brightness))
        this.client.setDeviceInfo(SetLightBulbDeviceInfoParams(brightness = brightness))
    }

    suspend fun setColor(color: Color) {
        val colorCfg = color.getConfig()
        val colorTemp = colorCfg.colorTemp ?: 0
        this.client.setDeviceInfo(
            SetRgbLightBulbDeviceInfoParams(
                hue = colorCfg.hue,
                saturation = colorCfg.saturation,
                color_temp = colorTemp
            )
        )
    }

}
