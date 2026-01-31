package dev.veeso.opentapowearos.tapo.api.tapo.crypto

import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Cryptographic utility functions for KLAP protocol
 */
object KlapCryptoUtils {
    
    /**
     * Compute SHA-1 hash of input data
     */
    fun sha1(data: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-1")
        return digest.digest(data)
    }
    
    /**
     * Compute SHA-256 hash of input data
     */
    fun sha256(data: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(data)
    }
    
    /**
     * Generate random bytes of specified size
     */
    fun generateRandomBytes(size: Int): ByteArray {
        val random = SecureRandom()
        val bytes = ByteArray(size)
        random.nextBytes(bytes)
        return bytes
    }
}
