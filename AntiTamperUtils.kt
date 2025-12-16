package com.lionsecured.app.security

import android.content.Context
import android.content.pm.PackageManager
import android.util.Base64
import android.util.Log
import java.security.MessageDigest

object AntiTamperUtils {
    fun isAppSignatureValid(ctx: Context, expectedSha256B64: String): Boolean {
        return try {
            val pm = ctx.packageManager
            val pkg = ctx.packageName
            val sigs = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES).signingInfo.apkContentsSigners
            val md = MessageDigest.getInstance("SHA-256")
            val digest = md.digest(sigs[0].toByteArray())
            val b64 = Base64.encodeToString(digest, Base64.NO_WRAP)
            b64 == expectedSha256B64
        } catch (e: Exception) {
            Log.e("AntiTamperUtils","failed",e)
            false
        }
    }
    fun isPackageNameValid(ctx: Context, expected: String): Boolean = ctx.packageName == expected
}
