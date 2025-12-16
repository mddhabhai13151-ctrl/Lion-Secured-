package com.lionsecured.app.fcm

import android.util.Log
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import android.util.Base64
import com.lionsecured.app.security.VaultManager

class LionFirebaseMessagingService: FirebaseMessagingService() {
    private val HMAC_KEY = "REPLACE_WITH_SERVER_HMAC_SECRET"
    override fun onMessageReceived(message: RemoteMessage) {
        super.onMessageReceived(message)
        val data = message.data
        val cmd = data["cmd"] ?: return
        val ts = data["ts"] ?: return
        val sig = data["sig"] ?: return
        if (verifyHmac(cmd, ts, sig)) handleCommand(cmd) else Log.w("LionFMS","Invalid HMAC")
    }
    private fun verifyHmac(cmd: String, ts: String, sigB64: String): Boolean {
        return try {
            val payload = "$cmd|$ts".toByteArray(Charsets.UTF_8)
            val key = HMAC_KEY.toByteArray(Charsets.UTF_8)
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(key, "HmacSHA256"))
            val digest = mac.doFinal(payload)
            val computed = Base64.encodeToString(digest, Base64.NO_WRAP)
            computed == sigB64
        } catch (e: Exception) { false }
    }
    private fun handleCommand(cmd: String) {
        when (cmd.uppercase()) {
            "LOCK" -> { /* app-level lock */ }
            "WIPE" -> { VaultManager(applicationContext).hideVaultTemporarily() }
            else -> Log.i("LionFMS","Unknown cmd: $cmd")
        }
    }
}
