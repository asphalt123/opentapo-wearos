package dev.veeso.opentapowearos.tapo.api.tapo.protocol

import android.util.Log
import dev.veeso.opentapowearos.tapo.api.tapo.crypto.KlapCipher
import dev.veeso.opentapowearos.tapo.api.tapo.crypto.KlapCryptoUtils
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import java.net.Inet4Address

/**
 * KLAP protocol implementation for Tapo device authentication
 */
class KlapProtocol(private val client: HttpClient, private val address: Inet4Address) {
    
    private val baseUrl = "http://${address.hostAddress}/app"
    private var cookie: String? = null
    private var cipher: KlapCipher? = null
    
    /**
     * Perform KLAP handshake and authentication
     */
    suspend fun handshake(username: String, password: String) {
        Log.d(TAG, "Starting KLAP handshake")
        
        // Compute auth hash: SHA256(SHA1(username) + SHA1(password))
        val authHash = KlapCryptoUtils.sha256(
            KlapCryptoUtils.sha1(username.toByteArray()) +
            KlapCryptoUtils.sha1(password.toByteArray())
        )
        
        // Generate random 16-byte local seed
        val localSeed = KlapCryptoUtils.generateRandomBytes(16)
        
        // Perform handshake1
        val remoteSeed = handshake1(localSeed, authHash)
        
        // Perform handshake2
        handshake2(localSeed, remoteSeed, authHash)
        
        // Initialize cipher
        this.cipher = KlapCipher(localSeed, remoteSeed, authHash)
        
        Log.d(TAG, "KLAP handshake completed successfully")
    }
    
    /**
     * Execute an encrypted request
     */
    suspend fun executeRequest(request: String): String {
        val currentCipher = cipher ?: throw IllegalStateException("Not authenticated")
        
        val (encryptedPayload, seq) = currentCipher.encrypt(request)
        
        Log.d(TAG, "Sending KLAP request with seq=$seq")
        
        val response = client.post("$baseUrl/request?seq=$seq") {
            header("Cookie", cookie)
            contentType(ContentType.Application.OctetStream)
            setBody(encryptedPayload)
        }
        
        if (!response.status.isSuccess()) {
            Log.e(TAG, "Request failed with status: ${response.status}")
            throw Exception("KLAP request failed: ${response.status}")
        }
        
        val responseBytes = response.body<ByteArray>()
        val decrypted = currentCipher.decrypt(seq, responseBytes)
        
        Log.d(TAG, "Received KLAP response: $decrypted")
        
        return decrypted
    }
    
    private suspend fun handshake1(localSeed: ByteArray, authHash: ByteArray): ByteArray {
        Log.d(TAG, "Performing handshake1")
        
        val response = client.post("$baseUrl/handshake1") {
            contentType(ContentType.Application.OctetStream)
            setBody(localSeed)
        }
        
        if (response.status == HttpStatusCode.Forbidden) {
            throw Exception(
                "Authentication forbidden. Make sure Third-Party Compatibility is enabled " +
                "in the Tapo app (Me > Third-Party Services)"
            )
        }
        
        if (!response.status.isSuccess()) {
            Log.e(TAG, "Handshake1 failed with status: ${response.status}")
            throw Exception("Handshake1 failed: ${response.status}")
        }
        
        // Extract cookie
        val setCookieHeader = response.headers["Set-Cookie"]
        if (setCookieHeader != null) {
            // Extract TP_SESSIONID from Set-Cookie header
            val sessionId = setCookieHeader.split(";")[0]
            this.cookie = sessionId
            Log.d(TAG, "Got session cookie: $sessionId")
        }
        
        val responseBody = response.body<ByteArray>()
        
        if (responseBody.size < 48) {
            throw Exception("Invalid handshake1 response size: ${responseBody.size}")
        }
        
        // First 16 bytes = remote_seed, next 32 bytes = server_hash
        val remoteSeed = responseBody.copyOfRange(0, 16)
        val serverHash = responseBody.copyOfRange(16, 48)
        
        // Verify server hash
        val localHash = KlapCryptoUtils.sha256(localSeed + remoteSeed + authHash)
        
        if (!localHash.contentEquals(serverHash)) {
            Log.e(TAG, "Server hash mismatch")
            throw Exception(
                "Invalid credentials. Make sure your email and password are correct " +
                "(both are case-sensitive)"
            )
        }
        
        Log.d(TAG, "Handshake1 successful")
        return remoteSeed
    }
    
    private suspend fun handshake2(
        localSeed: ByteArray,
        remoteSeed: ByteArray,
        authHash: ByteArray
    ) {
        Log.d(TAG, "Performing handshake2")
        
        val payload = KlapCryptoUtils.sha256(remoteSeed + localSeed + authHash)
        
        val response = client.post("$baseUrl/handshake2") {
            header("Cookie", cookie)
            contentType(ContentType.Application.OctetStream)
            setBody(payload)
        }
        
        if (!response.status.isSuccess()) {
            Log.e(TAG, "Handshake2 failed with status: ${response.status}")
            throw Exception("Handshake2 failed: ${response.status}")
        }
        
        Log.d(TAG, "Handshake2 successful")
    }
    
    companion object {
        private const val TAG = "KlapProtocol"
    }
}
