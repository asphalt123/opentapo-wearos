package dev.veeso.opentapo.mobile

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import dev.veeso.opentapo.mobile.tapo.api.tplinkcloud.TpLinkCloudClient
import kotlinx.coroutines.*

class LoginActivity : AppCompatActivity() {

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
                Toast.makeText(this, R.string.error_generic, Toast.LENGTH_SHORT).show()
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
                    SyncHelper.sendCredentialsToWear(this@LoginActivity, user, pass)
                    startActivity(Intent(this@LoginActivity, MainActivity::class.java))
                    finish()
                } catch (e: Exception) {
                    // cloud login may fail for accounts created with the new API;
                    // accept credentials anyway — device login (KLAP/passthrough) is what matters
                    getSharedPreferences(MainActivity.PREFS, Context.MODE_PRIVATE).edit()
                        .putString(MainActivity.KEY_USER, user)
                        .putString(MainActivity.KEY_PASS, pass)
                        .apply()
                    SyncHelper.sendCredentialsToWear(this@LoginActivity, user, pass)
                    startActivity(Intent(this@LoginActivity, MainActivity::class.java))
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
