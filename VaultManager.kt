package com.lionsecured.app.security

import android.content.Context
import android.util.Log
import java.io.File

class VaultManager(private val ctx: Context) {
    private val prefs = ctx.getSharedPreferences("lion_vault_prefs", Context.MODE_PRIVATE)
    private val vaultDir: File = File(ctx.filesDir, "vault_files")

    fun initialize() {
        if (!vaultDir.exists()) vaultDir.mkdirs()
    }

    fun addText(name: String, content: String, masterKey: ByteArray) {
        val id = System.currentTimeMillis().toString()
        val enc = EncryptionUtils.encrypt(content.toByteArray(Charsets.UTF_8), masterKey)
        val f = File(vaultDir, "$id.dat")
        f.writeText(enc)
    }

    fun listFiles(): List<File> = vaultDir.listFiles()?.toList() ?: emptyList()

    fun retrieveFileContent(file: File, masterKey: ByteArray): String? {
        return try {
            val enc = file.readText()
            val dec = EncryptionUtils.decrypt(enc, masterKey)
            String(dec, Charsets.UTF_8)
        } catch (e: Exception) {
            Log.e("VaultManager", "decrypt error", e)
            null
        }
    }

    fun hideVaultTemporarily() {
        val hidden = File(ctx.filesDir, "vault_hidden_${System.currentTimeMillis()}")
        vaultDir.renameTo(hidden)
    }
}
