package com.lionsecured.app.security

import android.content.Context
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import java.util.concurrent.Executor

class AuthManager(private val ctx: Context) {
    private val prefs = ctx.getSharedPreferences("lion_auth_prefs", Context.MODE_PRIVATE)
    companion object {
        private const val KEY_SALT = "salt"
        private const val KEY_MASTER_ENC = "master_enc"
        private const val KEY_PIN_HASH = "pin_hash"
        private const val KEY_FAILED = "failed"
        private const val KEY_HIDDEN_UNTIL = "hidden_until"
    }

    fun initialize() { }

    fun hasPin(): Boolean = prefs.contains(KEY_PIN_HASH)

    fun setPin(pin: String, masterKeyRaw: ByteArray) {
        val salt = EncryptionUtils.generateSalt()
        val derived = EncryptionUtils.deriveKeyFromPin(pin, salt)
        val encMaster = EncryptionUtils.encrypt(masterKeyRaw, derived)
        prefs.edit().putString(KEY_SALT, Base64.encodeToString(salt, Base64.NO_WRAP))
            .putString(KEY_MASTER_ENC, encMaster)
            .putString(KEY_PIN_HASH, Base64.encodeToString(derived, Base64.NO_WRAP))
            .apply()
    }

    fun verifyPin(pin: String): Boolean {
        val saltB64 = prefs.getString(KEY_SALT, null) ?: return false
        val salt = Base64.decode(saltB64, Base64.NO_WRAP)
        val derived = EncryptionUtils.deriveKeyFromPin(pin, salt)
        val stored = prefs.getString(KEY_PIN_HASH, null) ?: return false
        val storedBytes = Base64.decode(stored, Base64.NO_WRAP)
        if (derived.contentEquals(storedBytes)) {
            prefs.edit().putInt(KEY_FAILED, 0).apply()
            return true
        } else {
            val f = prefs.getInt(KEY_FAILED, 0) + 1
            prefs.edit().putInt(KEY_FAILED, f).apply()
            if (f >= 5) {
                val until = System.currentTimeMillis() + 10L*24*3600*1000
                prefs.edit().putLong(KEY_HIDDEN_UNTIL, until).apply()
                VaultManager(ctx).hideVaultTemporarily()
            }
            return false
        }
    }

    fun getMasterKeyWithPin(pin: String): ByteArray? {
        val saltB64 = prefs.getString(KEY_SALT, null) ?: return null
        val salt = Base64.decode(saltB64, Base64.NO_WRAP)
        val derived = EncryptionUtils.deriveKeyFromPin(pin, salt)
        val encMaster = prefs.getString(KEY_MASTER_ENC, null) ?: return null
        val dec = EncryptionUtils.decrypt(encMaster, derived)
        return dec
    }

    fun isHidden(): Boolean {
        val until = prefs.getLong(KEY_HIDDEN_UNTIL, 0L)
        return if (until==0L) false else System.currentTimeMillis() < until
    }

    fun promptBiometric(title: String, callback: (Boolean)->Unit) {
        val biometricManager = BiometricManager.from(ctx)
        if (biometricManager.canAuthenticate() != BiometricManager.BIOMETRIC_SUCCESS) { callback(false); return }
        val executor: Executor = ContextCompat.getMainExecutor(ctx)
        val prompt = BiometricPrompt(ctx as androidx.fragment.app.FragmentActivity, executor,
            object: BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result); callback(true)
                }
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString); callback(false)
                }
            })
        val info = BiometricPrompt.PromptInfo.Builder().setTitle(title).setNegativeButtonText("Cancel").build()
        prompt.authenticate(info)
    }
}
