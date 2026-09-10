package com.hn.otapo.backup

import android.util.Base64
import android.util.Log
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Chiffrement portable des sauvegardes (PBKDF2 + AES-256-GCM).
 *
 * Les mots de passe des comptes sont re-chiffrés avec la phrase secrète
 * choisie à l'export : contrairement au KeyStore (lié à l'appareil), ce
 * format se restaure sur un autre téléphone et se partage entre
 * utilisateurs — à condition de transmettre la phrase par un autre canal.
 */
object BackupCrypto {

    private const val TAG = "BackupCrypto"
    private const val ITERATIONS = 65536
    private const val KEY_BITS = 256
    private const val SALT_BYTES = 16
    private const val IV_BYTES = 12

    fun encrypt(plain: String, passphrase: String): String {
        require(passphrase.length >= 4) { "passphrase too short" }
        val salt = ByteArray(SALT_BYTES).also { SecureRandom().nextBytes(it) }
        val key = derive(passphrase, salt)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
        val iv = cipher.iv
        val out = cipher.doFinal(plain.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(salt + iv + out, Base64.NO_WRAP)
    }

    fun decrypt(encoded: String, passphrase: String): String {
        try {
            val raw = Base64.decode(encoded, Base64.NO_WRAP)
            require(raw.size > SALT_BYTES + IV_BYTES) { "truncated backup secret" }
            val salt = raw.copyOfRange(0, SALT_BYTES)
            val iv = raw.copyOfRange(SALT_BYTES, SALT_BYTES + IV_BYTES)
            val cipherText = raw.copyOfRange(SALT_BYTES + IV_BYTES, raw.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(derive(passphrase, salt), "AES"), GCMParameterSpec(128, iv))
            return String(cipher.doFinal(cipherText), Charsets.UTF_8)
        } catch (e: Exception) {
            Log.w(TAG, "decrypt failed: ${e.message}")
            throw IllegalArgumentException("Mot de passe de sauvegarde incorrect ou fichier corrompu")
        }
    }

    private fun derive(passphrase: String, salt: ByteArray): ByteArray {
        val spec = PBEKeySpec(passphrase.toCharArray(), salt, ITERATIONS, KEY_BITS)
        return try {
            SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
        }
    }
}
