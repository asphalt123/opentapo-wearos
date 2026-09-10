package com.hn.otapo.energy

import android.content.Context
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.hn.otapo.R
import com.hn.otapo.data.CredentialsProvider
import com.hn.otapo.data.DeviceStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.Inet4Address

/**
 * Energy monitor for P110 plugs: live power (W, polled every 10s while
 * visible), today/month totals (kWh from the device counters) and a simple
 * bar chart of the last 24h of samples.
 *
 * Opened from [com.hn.otapo.control.DeviceControlActivity] via
 * the implicit [ACTION_VIEW] (or the "Consommation" menu entry). Devices
 * without energy support show an explanatory empty state instead of an error.
 */
class EnergyActivity : AppCompatActivity() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private var pollJob: Job? = null
    private var deviceId: String = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_energy)

        deviceId = intent.getStringExtra(EXTRA_DEVICE_ID) ?: ""
        val device = DeviceStore.findById(this, deviceId)
        findViewById<TextView>(R.id.energy_alias).text = device?.alias ?: deviceId

        val chart: EnergyChartView = findViewById(R.id.energy_chart)
        chart.emptyLabel = getString(R.string.energy_no_data)
        chart.samples = EnergyStore.samples(this, deviceId)

        findViewById<Button>(R.id.energy_refresh).setOnClickListener { refresh() }
    }

    override fun onResume() {
        super.onResume()
        refresh()
        pollJob = scope.launch {
            while (isActive) {
                delay(POLL_MILLIS)
                if (isActive) refresh(silent = true)
            }
        }
    }

    override fun onPause() {
        pollJob?.cancel()
        pollJob = null
        super.onPause()
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private fun refresh(silent: Boolean = false) {
        if (!silent) setLoading(true)
        scope.launch {
            val result = withContext(Dispatchers.IO) { query(this@EnergyActivity, deviceId) }
            setLoading(false)
            when (result) {
                is EnergyQuery.Ok -> {
                    findViewById<TextView>(R.id.energy_power).text =
                        getString(R.string.energy_power, result.watts)
                    findViewById<TextView>(R.id.energy_today).text =
                        result.todayKwh?.let { getString(R.string.energy_today, it) }
                            ?: getString(R.string.energy_unavailable)
                    findViewById<TextView>(R.id.energy_month).text =
                        result.monthKwh?.let { getString(R.string.energy_month, it) }
                            ?: getString(R.string.energy_unavailable)
                    findViewById<TextView>(R.id.energy_error).visibility = View.GONE
                    EnergyStore.addSample(this@EnergyActivity, deviceId, result.watts)
                    findViewById<EnergyChartView>(R.id.energy_chart).samples =
                        EnergyStore.samples(this@EnergyActivity, deviceId)
                }
                is EnergyQuery.Failure -> {
                    if (!silent) {
                        findViewById<TextView>(R.id.energy_error).apply {
                            visibility = View.VISIBLE
                            text = getString(R.string.error_generic, result.message)
                        }
                    }
                }
            }
        }
    }

    private fun setLoading(loading: Boolean) {
        findViewById<View>(R.id.energy_progress).visibility =
            if (loading) View.VISIBLE else View.GONE
    }

    sealed interface EnergyQuery {
        data class Ok(val watts: Double, val todayKwh: Double?, val monthKwh: Double?) : EnergyQuery
        data class Failure(val message: String?) : EnergyQuery
    }

    companion object {
        const val EXTRA_DEVICE_ID = "device_id"
        const val ACTION_VIEW = "com.hn.otapo.energy.VIEW"
        private const val POLL_MILLIS = 10_000L

        suspend fun query(context: Context, deviceId: String): EnergyQuery {
            val device = DeviceStore.findById(context, deviceId)
                ?: return EnergyQuery.Failure(null)
            val creds = CredentialsProvider.get(context)
                ?: return EnergyQuery.Failure(null)
            return try {
                val client = try {
                    val bytes = device.ipAddress.split(".").map { it.toInt().toByte() }.toByteArray()
                    com.hn.otapo.tapo.api.tapo.TapoClient(
                        Inet4Address.getByAddress(bytes) as Inet4Address
                    )
                } catch (_: Exception) {
                    com.hn.otapo.tapo.api.tapo.TapoClient(device.endpoint)
                }
                client.login(creds.username, creds.password)
                val usage = client.getEnergyUsage()
                val watts = usage.watts ?: return EnergyQuery.Failure("unsupported")
                EnergyQuery.Ok(watts, usage.todayKwh, usage.monthKwh)
            } catch (e: Exception) {
                EnergyQuery.Failure(e.message)
            }
        }
    }
}
