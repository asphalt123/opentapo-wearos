package com.hn.otapo

import com.hn.otapo.tapo.device.Device
import com.hn.otapo.tapo.device.DeviceBuilder
import com.hn.otapo.tapo.device.DeviceModel
import com.hn.otapo.tapo.device.DeviceStatus
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json

/**
 * Cross-device device-list sync payload.
 *
 * The watch and the phone each duplicate the `tapo.device` model in their own
 * package, so the sync DTO only carries primitives (the model as its enum
 * name). Both sides encode/decode the exact same JSON shape, making the
 * payload interoperable regardless of which app produced it.
 *
 * Transport reuses the credentials pattern on path [DEVICES_PATH]:
 * - `putDataItem` (persistent: a late-joining side pulls it via getDataItems)
 * - `sendMessage` to connected nodes (immediate push while both are online)
 */
object DeviceSync {

    const val DEVICES_PATH = "/opentapo/devices"
    const val KEY_DEVICES_JSON = "devices_json"
    const val KEY_TIMESTAMP = "timestamp"

    private val json = Json { ignoreUnknownKeys = true }

    fun devicesToJson(devices: List<Device>): String {
        // sorted by id so the encoding is canonical: the same device set
        // always yields the same JSON, which lets both sides dedupe pushes
        // and guarantees the sync converges instead of ping-ponging.
        val payload = devices.sortedBy { it.id }.map {
            SyncedDevice(
                alias = it.alias,
                id = it.id,
                model = it.model.name,
                endpoint = it.endpoint,
                ipAddress = it.ipAddress
            )
        }
        return json.encodeToString(payload)
    }

    fun devicesFromJson(raw: String): List<Device> {
        if (raw.isBlank()) return emptyList()
        val payload: List<SyncedDevice> = json.decodeFromString(raw)
        return payload.mapNotNull {
            try {
                val model = try {
                    DeviceModel.valueOf(it.model)
                } catch (_: IllegalArgumentException) {
                    DeviceModel.GENERIC
                }
                DeviceBuilder.buildDevice(
                    alias = it.alias,
                    deviceId = it.id,
                    model = model,
                    endpoint = it.endpoint,
                    ipAddress = it.ipAddress,
                    // transient state; the receiving side refreshes it via KLAP
                    deviceStatus = DeviceStatus(deviceOn = false)
                )
            } catch (_: Exception) {
                null
            }
        }
    }
}

@kotlinx.serialization.Serializable
data class SyncedDevice(
    val alias: String,
    val id: String,
    val model: String,
    val endpoint: String,
    val ipAddress: String
)
