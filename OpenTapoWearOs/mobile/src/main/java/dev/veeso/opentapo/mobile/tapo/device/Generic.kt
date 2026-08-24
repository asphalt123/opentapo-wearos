package dev.veeso.opentapo.mobile.tapo.device

class Generic(
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
    DeviceType.UNKNOWN,
    DeviceModel.GENERIC,
    deviceStatus
)
