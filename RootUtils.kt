package com.lionsecured.app.security

import android.os.Build
import java.io.File

object RootUtils {
    fun isDeviceRooted(): Boolean {
        val paths = arrayOf("/system/app/Superuser.apk","/sbin/su","/system/bin/su","/system/xbin/su","/data/local/xbin/su","/data/local/bin/su","/system/sd/xbin/su","/su/bin/su")
        try {
            for (p in paths) if (File(p).exists()) return true
        } catch (e: Exception) {}
        return checkTestKeys() || hasDangerousProps() || canExecuteSu()
    }
    private fun checkTestKeys(): Boolean {
        return try { Build.TAGS?.contains("test-keys") == true } catch (e: Exception) { false }
    }
    private fun hasDangerousProps(): Boolean {
        return try {
            val p = Runtime.getRuntime().exec(arrayOf("getprop","ro.build.selinux"))
            p.inputStream.bufferedReader().readText().isNotEmpty()
        } catch (e: Exception) { false }
    }
    private fun canExecuteSu(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("which","su"))
            process.inputStream.bufferedReader().readText().isNotEmpty()
        } catch (e: Exception) { false }
    }
}
