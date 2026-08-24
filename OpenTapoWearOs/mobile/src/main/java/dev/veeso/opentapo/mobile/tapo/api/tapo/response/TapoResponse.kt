package dev.veeso.opentapo.mobile.tapo.api.tapo.response

@kotlinx.serialization.Serializable
data class TapoResponse<T>(val error_code: Int, val result: T? = null)
