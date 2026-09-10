package com.hn.otapo.view.intent_data

import android.os.Parcel
import android.os.Parcelable
import com.hn.otapo.tapo.device.DeviceModel
import com.hn.otapo.tapo.device.DeviceStatus

class DeviceData(
    val alias: String,
    val id: String,
    val model: DeviceModel,
    val endpoint: String,
    val ipAddress: String,
    val status: DeviceStatus
) : Parcelable {

    @Suppress("DEPRECATION")
    constructor(parcel: Parcel) : this(
        alias = parcel.readString()!!,
        id = parcel.readString()!!,
        model = DeviceModel.valueOf(parcel.readString()!!),
        endpoint = parcel.readString()!!,
        ipAddress = parcel.readString()!!,
        status = parcel.readParcelable(DeviceStatus::class.java.classLoader)!!
    )

    override fun writeToParcel(parcel: Parcel, flags: Int) {
        parcel.writeString(alias)
        parcel.writeString(id)
        parcel.writeString(model.name)
        parcel.writeString(endpoint)
        parcel.writeString(ipAddress)
        parcel.writeParcelable(status, 0)
    }

    override fun describeContents(): Int {
        return 0
    }

    companion object CREATOR : Parcelable.Creator<DeviceData> {
        override fun createFromParcel(parcel: Parcel): DeviceData {
            return DeviceData(parcel)
        }

        override fun newArray(size: Int): Array<DeviceData?> {
            return arrayOfNulls(size)
        }
    }

}
