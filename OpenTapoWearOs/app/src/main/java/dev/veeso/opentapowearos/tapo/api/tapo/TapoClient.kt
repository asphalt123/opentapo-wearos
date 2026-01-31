package dev.veeso.opentapowearos.tapo.api.tapo

import android.util.Log
import dev.veeso.opentapowearos.net.DeviceScanner
import dev.veeso.opentapowearos.tapo.api.tapo.crypto.Crypter
import dev.veeso.opentapowearos.tapo.api.tapo.crypto.CryptoUtils
import dev.veeso.opentapowearos.tapo.api.tapo.crypto.KeyPair
import dev.veeso.opentapowearos.tapo.api.tapo.request.*
import dev.veeso.opentapowearos.tapo.api.tapo.request.params.*
import dev.veeso.opentapowearos.tapo.api.tapo.response.TapoResponse
import dev.veeso.opentapowearos.tapo.api.tapo.response.result.HandshakeResult
import dev.veeso.opentapowearos.tapo.api.tapo.response.result.LoginResult
import dev.veeso.opentapowearos.tapo.api.tapo.response.result.PassthroughResult
import dev.veeso.opentapowearos.tapo.api.tapo.response.result.SetDeviceInfoResult
import dev.veeso.opentapowearos.tapo.api.tapo.response.result.get_device_info.GenericDeviceInfoResult
import dev.veeso.opentapowearos.tapo.device.Device
import dev.veeso.opentapowearos.tapo.device.DeviceBuilder
import dev.veeso.opentapowearos.tapo.device.DeviceModel
import dev.veeso.opentapowearos.tapo.device.DeviceStatus
import dev.veeso.opentapowearos.tapo.api.tapo.protocol.KlapProtocol
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.engine.android.*
import io.ktor.client.plugins.*
import io.ktor.client.plugins.cookies.*
import io.ktor.http.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import java.net.Inet4Address
import java.util.Base64

enum class ProtocolType {
    KLAP,
    PASSTHROUGH
}

class TapoClient {

    private var url: String
    private var ipAddress: Inet4Address? = null
    private val terminalUUID: String = "00-00-00-00-00-00"
    private val client: HttpClient = HttpClient(Android) {
        install(HttpCookies)
        install(HttpTimeout)
    }
    private lateinit var crypter: Crypter
    private var klapProtocol: KlapProtocol? = null
    private var currentProtocol: ProtocolType? = null

    private var token: String?

    val authenticated: Boolean get() = token != null || klapProtocol != null

    init {
        this.token = null
    }

    constructor(ipAddress: Inet4Address) {
        this.url = String.format("http://%s/app", ipAddress.hostAddress!!)
        this.ipAddress = ipAddress
    }

    constructor(url: String) {
        this.url = url
    }

    suspend fun login(username: String, password: String) {
        Log.d(TAG, String.format("Performing login as %s", username))
        
        // Try KLAP protocol first (for newer firmware)
        if (ipAddress != null) {
            try {
                Log.d(TAG, "Attempting KLAP protocol")
                klapProtocol = KlapProtocol(client, ipAddress!!)
                klapProtocol!!.handshake(username, password)
                currentProtocol = ProtocolType.KLAP
                Log.d(TAG, "KLAP protocol successful")
                return
            } catch (e: Exception) {
                Log.w(TAG, "KLAP protocol failed, falling back to passthrough: ${e.message}")
                klapProtocol = null
                currentProtocol = null
            }
        }
        
        // Fall back to old passthrough protocol
        Log.d(TAG, "Using passthrough protocol")
        handshake()
        doLogin(username, password)
        currentProtocol = ProtocolType.PASSTHROUGH
    }

    suspend fun queryDevice(): Device {
        Log.d(TAG, "Getting device type")
        val deviceInfo = getDeviceInfo()
        val model = DeviceModel.fromName(deviceInfo.model)
        Log.d(
            DeviceScanner.TAG,
            String.format(
                "Found a device of type %s",
                model
            )
        )
        val alias = String(Base64.getDecoder().decode(deviceInfo.nickname))
        return DeviceBuilder.buildDevice(
            alias,
            deviceInfo.device_id,
            model,
            this.url,
            deviceInfo.ip,
            DeviceStatus(
                deviceOn = deviceInfo.device_on,
                brightness = deviceInfo.brightness,
                hue = deviceInfo.hue,
                saturation = deviceInfo.saturation,
                colorTemperature = deviceInfo.color_temp
            )
        )
    }

    suspend fun getDeviceInfo(): GenericDeviceInfoResult {
        val request = packRequest(GetDeviceInfoParams())
        val response: TapoResponse<GenericDeviceInfoResult> = executeRequest(request)
        validateResponse(response)
        return response.result!!
    }

    suspend fun setDeviceInfo(params: SetGenericDeviceInfoParams) {
        Log.d(TAG, String.format("Setting generic device info params: %s", params))

        val request = packRequest(params)
        val response: TapoResponse<SetDeviceInfoResult> = executeRequest(request)
        validateResponse(response)
        Log.d(TAG, "Device info SET")
    }

    suspend fun setDeviceInfo(params: SetLightBulbDeviceInfoParams) {
        Log.d(TAG, String.format("Setting light bulb device info params: %s", params))

        val request = packRequest(params)
        val response: TapoResponse<SetDeviceInfoResult> = executeRequest(request)
        validateResponse(response)
        Log.d(TAG, "Device info SET")
    }

    suspend fun setDeviceInfo(params: SetRgbLightBulbDeviceInfoParams) {
        Log.d(TAG, String.format("Setting RGB device info params: %s", params))

        val request = packRequest(params)
        val response: TapoResponse<SetDeviceInfoResult> = executeRequest(request)
        validateResponse(response)
        Log.d(TAG, "Device info SET")
    }

    private suspend fun handshake() {
        val keypair = KeyPair()
        val request = packRequest(HandshakeParams(keypair.publicPem()))

        Log.d(
            TAG,
            String.format("Performing handshake; public key is: %s", keypair.publicPem())
        )
        val response: TapoResponse<HandshakeResult> = post(request)
        validateResponse(response)
        Log.d(
            TAG,
            String.format("Handshake OK; got key %s; initializing crypter", response.result!!.key)
        )
        this.crypter = Crypter(response.result.key, keypair)
    }

    private suspend fun doLogin(username: String, password: String) {
        Log.d(TAG, String.format("Will login with username %s", username))
        val usernameDigest = CryptoUtils.shaDigestUsername(username)
        val encodedUsername = String(Base64.getEncoder().encode(usernameDigest.toByteArray()))
        val encodedPassword = String(Base64.getEncoder().encode(password.toByteArray()))
        Log.d(TAG, String.format("Encoded username %s => %s", usernameDigest, encodedUsername))

        val request = packRequest(
            LoginParams(encodedUsername, encodedPassword)
        )
        val response: TapoResponse<LoginResult> = passthroughRequest(request)
        validateResponse(response)
        Log.d(TAG, String.format("Login successful; token: %s", response.result!!.token))
        this.token = response.result.token
        Log.d(TAG, String.format("Session cookie is %s", this.client.cookies(this.url)[0]))
    }

    private suspend inline fun <reified T, reified U> post(request: TapoRequest<T>): U {
        val serializer = Json { encodeDefaults = true }
        val payload = serializer.encodeToString(request)
        Log.d(TAG, String.format("Sending out payload '%s'", payload))
        val response = client.post(getUrl()) {
            contentType(ContentType.Application.Json)
            setBody(payload)
            timeout {
                requestTimeoutMillis = 15000
            }
        }

        Log.d(TAG, String.format("Request status: %d", response.status.value))
        if (response.status.value !in 200..209) {
            throw Exception(
                String.format(
                    "POST failed; expected 200 got %d",
                    response.status.value
                )
            )
        }

        val bodyStr = response.body<String>()
        Log.d(TAG, String.format("Request response: '%s'", bodyStr))

        val deserializer = Json { ignoreUnknownKeys = true }
        return deserializer.decodeFromString(response.body())
    }

    private suspend inline fun <reified T, reified U> executeRequest(request: TapoRequest<T>): U {
        return when (currentProtocol) {
            ProtocolType.KLAP -> klapRequest(request)
            ProtocolType.PASSTHROUGH -> passthroughRequest(request)
            null -> throw IllegalStateException("Not authenticated")
        }
    }

    private suspend inline fun <reified T, reified U> klapRequest(request: TapoRequest<T>): U {
        val serializer = Json { encodeDefaults = false }
        val payload = serializer.encodeToString(request)
        Log.d(TAG, String.format("Sending KLAP request: '%s'", payload))
        
        val responseStr = klapProtocol!!.executeRequest(payload)
        
        val deserializer = Json { ignoreUnknownKeys = true }
        return deserializer.decodeFromString(responseStr)
    }

    private suspend inline fun <reified T, reified U> passthroughRequest(request: TapoRequest<T>): U {
        val serializer = Json { encodeDefaults = false }
        val payload = serializer.encodeToString(request)
        Log.d(TAG, String.format("Sending out payload to encrypt '%s'", payload))
        val encryptedInnerPayload = this.crypter.encrypt(payload)
        Log.d(TAG, String.format("Encrypted inner payload: %s", encryptedInnerPayload))
        val wrappedRequest = packRequest(
            PassthroughParams(encryptedInnerPayload)
        )
        val response: TapoResponse<PassthroughResult> = post(wrappedRequest)
        validateResponse(response)

        Log.d(TAG, "Decrypting response body")
        val plainResponseBody = crypter.decrypt(response.result!!.response)
        Log.d(TAG, String.format("Plain request response: '%s'", plainResponseBody))

        val deserializer = Json { ignoreUnknownKeys = true }
        return deserializer.decodeFromString(plainResponseBody)
    }

    private fun <T> packRequest(params: T): TapoRequest<T> {
        val millis = System.currentTimeMillis().toInt()

        val method = when (params!!::class.java) {
            GetDeviceInfoParams::class.java -> METHOD_GET_DEVICE_INFO
            HandshakeParams::class.java -> METHOD_HANDSHAKE
            LoginParams::class.java -> METHOD_LOGIN
            PassthroughParams::class.java -> METHOD_SECURE_PASSTHROUGH
            SetGenericDeviceInfoParams::class.java -> METHOD_SET_DEVICE_INFO
            SetLightBulbDeviceInfoParams::class.java -> METHOD_SET_DEVICE_INFO
            SetRgbLightBulbDeviceInfoParams::class.java -> METHOD_SET_DEVICE_INFO
            else ->
                throw Exception("Unknown method")
        }
        return TapoRequest(method, millis, terminalUUID, params)
    }

    private fun <T> validateResponse(response: TapoResponse<T>) {
        if (response.error_code != 0) {
            Log.e(TAG, String.format("Expected error code 0; got %d", response.error_code))
            throw Exception(String.format("Expected error code 0; got %d", response.error_code))
        }
    }

    private fun getUrl(): String {
        return if (token != null) {
            String.format("%s?token=%s", url, token)
        } else {
            url
        }
    }

    companion object {
        const val TAG = "TapoClient"
    }

}
