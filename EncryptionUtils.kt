package com.lionsecured.app.security

import android.util.Base64
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

object EncryptionUtils {
    private const val PBKDF2_ITERATIONS = 200_000
    private const val KEY_LENGTH = 256
    private const val AES_MODE = "AES/GCM/NoPadding"

    fun deriveKeyFromPin(pin: String, salt: ByteArray): ByteArray {
        val spec = PBEKeySpec(pin.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_LENGTH)
        val skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        return skf.generateSecret(spec).encoded
    }

    fun generateSalt(): ByteArray {
        val sr = SecureRandom()
        val s = ByteArray(16)
        sr.nextBytes(s)
        return s
    }

    fun encrypt(plain: ByteArray, key: ByteArray): String {
        val cipher = Cipher.getInstance(AES_MODE)
        val iv = ByteArray(12)
        SecureRandom().nextBytes(iv)
        val gcm = GCMParameterSpec(128, iv)
        val secretKey = SecretKeySpec(key, "AES")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcm)
        val cipherText = cipher.doFinal(plain)
        val out = ByteArray(iv.size + cipherText.size)
        System.arraycopy(iv, 0, out, 0, iv.size)
        System.arraycopy(cipherText, 0, out, iv.size, cipherText.size)
        return Base64.encodeToString(out, Base64.NO_WRAP)
    }

    fun decrypt(payloadB64: String, key: ByteArray): ByteArray {
        val data = Base64.decode(payloadB64, Base64.NO_WRAP)
        val iv = data.copyOfRange(0, 12)
        val cipherBytes = data.copyOfRange(12, data.size)
        val cipher = Cipher.getInstance(AES_MODE)
        val gcm = GCMParameterSpec(128, iv)
        val secretKey = SecretKeySpec(key, "AES")
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcm)
        return cipher.doFinal(cipherBytes)
    }
}
