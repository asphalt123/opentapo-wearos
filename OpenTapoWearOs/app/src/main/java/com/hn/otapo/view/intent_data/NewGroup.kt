package com.hn.otapo.view.intent_data

import android.os.Parcel
import android.os.Parcelable

class NewGroupInput(
    val idList: List<String>,
    val existingGroups: List<String>,
) : Parcelable {

    constructor(parcel: Parcel) : this(
        idList = parcel.createStringArrayList() ?: emptyList(),
        existingGroups = parcel.createStringArrayList() ?: emptyList()
    )

    override fun writeToParcel(parcel: Parcel, flags: Int) {
        parcel.writeStringList(idList)
        parcel.writeStringList(existingGroups)
    }

    override fun describeContents(): Int {
        return 0
    }

    companion object CREATOR : Parcelable.Creator<NewGroupInput> {
        override fun createFromParcel(parcel: Parcel): NewGroupInput {
            return NewGroupInput(parcel)
        }

        override fun newArray(size: Int): Array<NewGroupInput?> {
            return arrayOfNulls(size)
        }
    }

}

class NewGroupOutput(
    val groupName: String,
    val idList: List<String>,
) : Parcelable {

    constructor(parcel: Parcel) : this(
        groupName = parcel.readString()!!,
        idList = parcel.createStringArrayList() ?: emptyList()
    )

    override fun writeToParcel(parcel: Parcel, flags: Int) {
        parcel.writeString(groupName)
        parcel.writeStringList(idList)
    }

    override fun describeContents(): Int {
        return 0
    }

    companion object CREATOR : Parcelable.Creator<NewGroupOutput> {
        override fun createFromParcel(parcel: Parcel): NewGroupOutput {
            return NewGroupOutput(parcel)
        }

        override fun newArray(size: Int): Array<NewGroupOutput?> {
            return arrayOfNulls(size)
        }
    }

}
