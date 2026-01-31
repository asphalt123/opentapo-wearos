package dev.veeso.opentapowearos.tapo.api.tapo.crypto

import android.util.Log
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * KLAP protocol cipher for encryption/decryption
 * Based on the Rust tapo library implementation
 */
class KlapCipher(
    localSeed: ByteArray,
    remoteSeed: ByteArray,
    userHash: ByteArray
) {
    private val key: ByteArray
    private val iv: ByteArray
    private val seq: AtomicInteger
    private val sig: ByteArray
    
    init {
        val localHash = localSeed + remoteSeed + userHash
        
        val (derivedIv, initialSeq) = ivDerive(localHash)
        this.key = keyDerive(localHash)
        this.iv = derivedIv
        this.seq = AtomicInteger(initialSeq)
        this.sig = sigDerive(localHash)
        
        Log.d(TAG, "KlapCipher initialized with seq: $initialSeq")
    }
    
    /**
     * Encrypt data and return (encrypted_bytes, sequence_number)
     */
    fun encrypt(data: String): Pair<ByteArray, Int> {
        val currentSeq = seq.incrementAndGet()
        val ivSeq = ivSeq(currentSeq)
        
        // Encrypt with AES-128-CBC
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        val keySpec = SecretKeySpec(key, "AES")
        val ivSpec = IvParameterSpec(ivSeq)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
        
        val cipherBytes = cipher.doFinal(data.toByteArray(Charsets.UTF_8))
        
        // Create signature
        val seqBytes = ByteBuffer.allocate(4).putInt(currentSeq).array()
        val signatureInput = sig + seqBytes + cipherBytes
        val signature = KlapCryptoUtils.sha256(signatureInput)
        
        // Combine signature + ciphertext
        val result = signature + cipherBytes
        
        return Pair(result, currentSeq)
    }
    
    /**
     * Decrypt response bytes
     */
    fun decrypt(seq: Int, cipherBytes: ByteArray): String {
        val ivSeq = ivSeq(seq)
        
        // Skip first 32 bytes (signature) and decrypt the rest
        val actualCipherBytes = cipherBytes.copyOfRange(32, cipherBytes.size)
        
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        val keySpec = SecretKeySpec(key, "AES")
        val ivSpec = IvParameterSpec(ivSeq)
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
        
        val decryptedBytes = cipher.doFinal(actualCipherBytes)
        return String(decryptedBytes, Charsets.UTF_8)
    }
    
    private fun keyDerive(localHash: ByteArray): ByteArray {
        val input = "lsk".toByteArray() + localHash
        val hash = KlapCryptoUtils.sha256(input)
        return hash.copyOfRange(0, 16) // First 16 bytes
    }
    
    private fun ivDerive(localHash: ByteArray): Pair<ByteArray, Int> {
        val input = "iv".toByteArray() + localHash
        val hash = KlapCryptoUtils.sha256(input)
        val iv = hash.copyOfRange(0, 12) // First 12 bytes
        
        // Last 4 bytes as big-endian int
        val seqBytes = hash.copyOfRange(hash.size - 4, hash.size)
        val seq = ByteBuffer.wrap(seqBytes).int
        
        return Pair(iv, seq)
    }
    
    private fun sigDerive(localHash: ByteArray): ByteArray {
        val input = "ldk".toByteArray() + localHash
        val hash = KlapCryptoUtils.sha256(input)
        return hash.copyOfRange(0, 28) // First 28 bytes
    }
    
    private fun ivSeq(seq: Int): ByteArray {
        val seqBytes = ByteBuffer.allocate(4).putInt(seq).array()
        return iv + seqBytes
    }
    
    companion object {
        private const val TAG = "KlapCipher"
    }
}
