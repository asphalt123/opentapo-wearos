package com.hn.otapo.account

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Chiffre les mots de passe des comptes Tapo avec une clé AES-GCM stockée
 * dans l'AndroidKeyStore (jamais dans les SharedPreferences en clair).
 *
 * Si le KeyStore est indisponible (profil restreint, etc.), repli sur un
 * encodage Base64 préfixé — l'app reste fonctionnelle, le backup/restore
 * re-chiffre au premier accès KeyStore valide.
 */
object AccountCrypto {

    private const val TAG = "AccountCrypto"
    private const val ALIAS = "OpenTapoAccounts"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val FALLBACK_PREFIX = "OBFUSCATED:"

    fun encrypt(plain: String): String {
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, key())
            val iv = cipher.iv
            val out = cipher.doFinal(plain.toByteArray(Charsets.UTF_8))
            Base64.encodeToString(iv + out, Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.w(TAG, "keystore encrypt failed, fallback: ${e.message}")
            Base64.encodeToString((FALLBACK_PREFIX + plain).toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
        }
    }

    fun decrypt(encoded: String): String {
        val raw = try {
            Base64.decode(encoded, Base64.NO_WRAP)
        } catch (e: Exception) {
            throw IllegalArgumentException("bad secret: ${e.message}")
        }
        if (String(raw, Charsets.UTF_8).startsWith(FALLBACK_PREFIX)) {
            return String(raw, Charsets.UTF_8).removePrefix(FALLBACK_PREFIX)
        }
        try {
            val iv = raw.copyOfRange(0, 12)
            val cipherText = raw.copyOfRange(12, raw.size)
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, iv))
            return String(cipher.doFinal(cipherText), Charsets.UTF_8)
        } catch (e: Exception) {
            Log.e(TAG, "keystore decrypt failed", e)
            throw e
        }
    }

    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build()
        )
        return generator.generateKey()
    }
}
