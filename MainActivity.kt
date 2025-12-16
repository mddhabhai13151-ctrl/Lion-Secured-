package com.lionsecured.app

import android.os.Bundle
import android.view.WindowManager
import androidx.appcompat.app.AppCompatActivity
import com.lionsecured.app.security.AuthManager
import com.lionsecured.app.security.VaultManager

class MainActivity : AppCompatActivity() {
    private lateinit var auth: AuthManager
    private lateinit var vault: VaultManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        setContentView(R.layout.activity_main)
        auth = AuthManager(this)
        vault = VaultManager(this)
        auth.initialize()
        vault.initialize()
    }
}
