package com.hn.otapo.tapo.device

import android.os.Parcel
import android.os.Parcelable

@kotlinx.serialization.Serializable
data class DeviceStatus(
    val deviceOn: Boolean,
    val brightness: Int? = null,
    val hue: Int? = null,
    val saturation: Int? = null,
    val colorTemperature: Int? = null
) : Parcelable {

    constructor(parcel: Parcel) : this(
        deviceOn = parcel.readByte() != 0.toByte(),
        brightness = parcel.readByte().let { if (it == 0.toByte()) null else parcel.readInt() },
        hue = parcel.readByte().let { if (it == 0.toByte()) null else parcel.readInt() },
        saturation = parcel.readByte().let { if (it == 0.toByte()) null else parcel.readInt() },
        colorTemperature = parcel.readByte().let { if (it == 0.toByte()) null else parcel.readInt() }
    )

    override fun writeToParcel(parcel: Parcel, flags: Int) {
        parcel.writeByte(if (deviceOn) 1 else 0)
        if (brightness == null) {
            parcel.writeByte(0)
        } else {
            parcel.writeByte(1)
            parcel.writeInt(brightness)
        }
        if (hue == null) {
            parcel.writeByte(0)
        } else {
            parcel.writeByte(1)
            parcel.writeInt(hue)
        }
        if (saturation == null) {
            parcel.writeByte(0)
        } else {
            parcel.writeByte(1)
            parcel.writeInt(saturation)
        }
        if (colorTemperature == null) {
            parcel.writeByte(0)
        } else {
            parcel.writeByte(1)
            parcel.writeInt(colorTemperature)
        }
    }

    override fun describeContents(): Int {
        return 0
    }

    companion object CREATOR : Parcelable.Creator<DeviceStatus> {
        override fun createFromParcel(parcel: Parcel): DeviceStatus {
            return DeviceStatus(parcel)
        }

        override fun newArray(size: Int): Array<DeviceStatus?> {
            return arrayOfNulls(size)
        }
    }

}
