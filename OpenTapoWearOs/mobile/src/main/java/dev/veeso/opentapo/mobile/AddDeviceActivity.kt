package dev.veeso.opentapo.mobile

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.ProgressBar
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import dev.veeso.opentapo.mobile.tapo.api.tapo.TapoClient
import dev.veeso.opentapo.mobile.view.intent_data.Credentials
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.Inet4Address

/**
 * Manual device setup by IP address — mirrors DeviceSetupActivity on Wear OS.
 */
class AddDeviceActivity : AppCompatActivity() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private var credentials: Credentials? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_add_device)

        credentials = intent.getParcelableExtra<Credentials>(EXTRA_CREDENTIALS)
        if (credentials == null) {
            finish()
            return
        }

        val ipInput: EditText = findViewById(R.id.input_ip)
        val button: Button = findViewById(R.id.button_add)
        val progress: ProgressBar = findViewById(R.id.add_progress)

        button.setOnClickListener {
            val text = ipInput.text.toString().trim()
            val address = try {
                Inet4Address.getByName(text) as? Inet4Address
            } catch (e: Exception) {
                null
            }
            if (address == null) {
                Toast.makeText(this, getString(R.string.error_generic, "IP invalide"), Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            button.isEnabled = false
            progress.visibility = View.VISIBLE
            scope.launch {
                val result = withContext(Dispatchers.IO) {
                    try {
                        val client = TapoClient(address)
                        client.login(credentials!!.username, credentials!!.password)
                        Pair(client.queryDevice(), null as String?)
                    } catch (e: Exception) {
                        Pair(null, e.message ?: "échec de connexion")
                    }
                }
                button.isEnabled = true
                progress.visibility = View.GONE
                val device = result.first
                if (device != null) {
                    setResult(RESULT_OK, Intent().putExtra(EXTRA_DEVICE_IP, device.ipAddress))
                    finish()
                } else {
                    Toast.makeText(this@AddDeviceActivity,
                        getString(R.string.error_generic, result.second), Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    companion object {
        const val EXTRA_CREDENTIALS = "credentials"
        const val EXTRA_DEVICE_IP = "device_ip"
    }
}
