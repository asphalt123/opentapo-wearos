package com.hn.otapo.tapo.api.tapo.response.result

/**
 * Result of `get_energy_usage` (P110).
 *
 * Units on stock firmware: `current_power` in milliwatts, `today_energy` /
 * `month_energy` in watt-hours. All fields nullable: older firmwares omit
 * some of them, and the energy screen degrades gracefully.
 */
@kotlinx.serialization.Serializable
data class EnergyUsageResult(
    val current_power: Long? = null,
    val today_energy: Long? = null,
    val month_energy: Long? = null,
    val today_runtime: Long? = null,
    val month_runtime: Long? = null
) {
    /** Live power in watts. */
    val watts: Double? get() = current_power?.let { it / 1000.0 }

    /** Today's consumption in kWh. */
    val todayKwh: Double? get() = today_energy?.let { it / 1000.0 }

    /** This month's consumption in kWh. */
    val monthKwh: Double? get() = month_energy?.let { it / 1000.0 }
}
