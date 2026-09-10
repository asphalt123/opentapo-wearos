package com.hn.otapo

import android.content.Context
import android.content.Intent
import android.util.Log
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.snackbar.Snackbar
import com.hn.otapo.tapo.api.tplinkcloud.TpLinkCloudClient
import kotlinx.coroutines.*

class LoginActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "LoginActivity"
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_login)

        val email: EditText = findViewById(R.id.input_email)
        val password: EditText = findViewById(R.id.input_password)
        val button: Button = findViewById(R.id.button_login)
        val progress: android.widget.ProgressBar = findViewById(R.id.login_progress)

        button.setOnClickListener {
            val user = email.text.toString().trim()
            val pass = password.text.toString()
            if (user.isEmpty() || pass.isEmpty()) {
                Snackbar.make(findViewById(android.R.id.content),
                    getString(R.string.error_generic, "Identifiants vides"),
                    Snackbar.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            button.isEnabled = false
            progress.visibility = android.view.View.VISIBLE
            scope.launch {
                try {
                    withContext(Dispatchers.IO) {
                        TpLinkCloudClient().login(user, pass)
                    }
                    getSharedPreferences(MainActivity.PREFS, Context.MODE_PRIVATE).edit()
                        .putString(MainActivity.KEY_USER, user)
                        .putString(MainActivity.KEY_PASS, pass)
                        .apply()
                    com.hn.otapo.account.AccountStore.upsertLogin(this@LoginActivity, user, pass)
                    SyncHelper.sendCredentialsToWear(this@LoginActivity, user, pass)
                    SyncHelper.sendCredentialsToWearViaMessage(this@LoginActivity, user, pass)
                    Log.d(TAG, "SyncHelper calls done after login")
                    startActivity(Intent(this@LoginActivity, MainActivity::class.java))
                    overridePendingTransition(R.anim.fade_in, R.anim.fade_out)
                    finish()
                } catch (e: Exception) {
                    // cloud login may fail for accounts created with the new API;
                    // accept credentials anyway — device login (KLAP/passthrough) is what matters
                    getSharedPreferences(MainActivity.PREFS, Context.MODE_PRIVATE).edit()
                        .putString(MainActivity.KEY_USER, user)
                        .putString(MainActivity.KEY_PASS, pass)
                        .apply()
                    com.hn.otapo.account.AccountStore.upsertLogin(this@LoginActivity, user, pass)
                    SyncHelper.sendCredentialsToWear(this@LoginActivity, user, pass)
                    SyncHelper.sendCredentialsToWearViaMessage(this@LoginActivity, user, pass)
                    Log.d(TAG, "SyncHelper calls done after login")
                    startActivity(Intent(this@LoginActivity, MainActivity::class.java))
                    overridePendingTransition(R.anim.fade_in, R.anim.fade_out)
                    finish()
                }
            }
        }
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }
}
