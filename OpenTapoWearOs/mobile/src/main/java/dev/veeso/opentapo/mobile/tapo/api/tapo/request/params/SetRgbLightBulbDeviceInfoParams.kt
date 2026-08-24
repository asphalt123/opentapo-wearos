package dev.veeso.opentapo.mobile.tapo.api.tapo.request.params

@kotlinx.serialization.Serializable
class SetRgbLightBulbDeviceInfoParams(
    val device_on: Boolean? = null,
    val brightness: Int? = null,
    val hue: Int? = null,
    val saturation: Int? = null,
    val color_temp: Int? = null,
)
