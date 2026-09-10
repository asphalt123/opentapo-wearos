package com.hn.otapo.control

import com.hn.otapo.tapo.device.DeviceModel
import com.hn.otapo.tapo.device.DeviceType

/**
 * Decides which controls a device supports, from its detected model/type.
 *
 * - dimmable: L510/L520/L530/L610/L630 (brightness slider)
 * - RGB: L530/L630 (color wheel + color temperature)
 * - color temperature only: L510/L520/L610 (white range via color_temp)
 * - energy monitoring: P110
 */
object DeviceCapabilities {

    fun isDimmable(model: DeviceModel, type: DeviceType): Boolean {
        return type == DeviceType.LIGHT_BULB || type == DeviceType.RGB_LIGHT_BULB ||
            model in setOf(DeviceModel.L510, DeviceModel.L520, DeviceModel.L530, DeviceModel.L610, DeviceModel.L630)
    }

    fun isRgb(model: DeviceModel, type: DeviceType): Boolean {
        return type == DeviceType.RGB_LIGHT_BULB ||
            model == DeviceModel.L530 || model == DeviceModel.L630
    }

    fun supportsColorTemp(model: DeviceModel, type: DeviceType): Boolean {
        return isDimmable(model, type)
    }

    fun supportsEnergy(model: DeviceModel): Boolean {
        return model == DeviceModel.P110
    }
}
