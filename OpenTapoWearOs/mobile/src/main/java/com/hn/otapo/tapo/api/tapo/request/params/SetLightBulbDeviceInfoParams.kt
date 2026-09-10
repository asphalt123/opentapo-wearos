package com.hn.otapo.tapo.api.tapo.request.params

@kotlinx.serialization.Serializable
data class SetLightBulbDeviceInfoParams(
    val device_on: Boolean? = null,
    val brightness: Int? = null,
    val color_temp: Int? = null
)
