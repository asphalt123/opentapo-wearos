package dev.veeso.opentapowearos.view.main_activity

import android.graphics.Color
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Switch
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import dev.veeso.opentapowearos.R
import dev.veeso.opentapowearos.tapo.device.Device
import dev.veeso.opentapowearos.view.intent_data.Credentials
import kotlinx.coroutines.*

@OptIn(DelicateCoroutinesApi::class)
internal class DeviceListAdapter(private val devices: List<Device>) :
    RecyclerView.Adapter<DeviceListAdapter.ViewHolder>() {

    var onItemClick: ((Device) -> Unit)? = null
    var onItemLongClick: ((Device) -> Unit)? = null
    var selected: Boolean = false
    lateinit var credentials: Credentials

    private var suppressListener = false
    private val mainHandler = Handler(Looper.getMainLooper())

    internal inner class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val deviceAliasText: TextView = view.findViewById(R.id.device_list_item_alias)
        val deviceModelText: TextView = view.findViewById(R.id.device_list_item_model)
        val devicePowerSwitch: Switch = view.findViewById(R.id.device_list_item_power)

        init {
            itemView.setOnClickListener {
                val position = bindingAdapterPosition
                if (position != RecyclerView.NO_POSITION) {
                    onItemClick?.invoke(devices[position])
                }
            }
            itemView.setOnLongClickListener {
                val position = bindingAdapterPosition
                if (position != RecyclerView.NO_POSITION) {
                    onLongClick(it, position)
                }
                true
            }
            devicePowerSwitch.setOnCheckedChangeListener { _, isChecked ->
                val position = bindingAdapterPosition
                if (position == RecyclerView.NO_POSITION || suppressListener) {
                    return@setOnCheckedChangeListener
                }
                Log.d(
                    TAG,
                    String.format("Changing power state for %s to %s", devices[position].alias, isChecked)
                )
                setPowerState(devices[position], isChecked, this)
            }
        }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val itemView = LayoutInflater.from(parent.context)
            .inflate(R.layout.device_list_item, parent, false)
        return ViewHolder(itemView)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val device = devices[position]
        holder.deviceAliasText.text = device.alias
        holder.deviceModelText.text = device.model.toString()
        // power switch (suppress listener to avoid firing during rebinding)
        suppressListener = true
        holder.devicePowerSwitch.isChecked = device.status.deviceOn
        holder.devicePowerSwitch.alpha = if (device.status.deviceOn) 1f else 0.6f
        suppressListener = false
    }

    override fun getItemCount(): Int {
        return devices.size
    }

    private fun onLongClick(view: View, adapterPosition: Int) {
        Log.d(TAG, "OnLongClick")
        selected = !selected
        val backgroundColor = if (selected) {
            SELECTED_COLOR
        } else {
            UNSELECTED_COLOR
        }
        view.setBackgroundColor(Color.parseColor(backgroundColor))
        onItemLongClick?.invoke(devices[adapterPosition])
    }

    fun setPowerState(device: Device, powerState: Boolean, holder: ViewHolder) {
        GlobalScope.launch {
            withContext(Dispatchers.IO) {
                try {
                    if (!device.authenticated) {
                        Log.d(TAG, String.format("Device %s is not authenticated yet; signing in", device.alias))
                        device.login(credentials.username, credentials.password)
                    }
                    if (powerState) {
                        device.on()
                    } else {
                        device.off()
                    }
                    // confirm optimistic state locally so a rebind keeps it
                    device.status = device.status.copy(deviceOn = powerState)
                } catch (e: Exception) {
                    Log.d(
                        TAG,
                        String.format("Failed to set power state for %s: %s", device.alias, e)
                    )
                    // revert the switch on failure
                    mainHandler.post {
                        suppressListener = true
                        holder.devicePowerSwitch.isChecked = !powerState
                        holder.devicePowerSwitch.alpha = if (!powerState) 1f else 0.6f
                        suppressListener = false
                    }
                }
            }
        }
    }

    companion object {
        const val TAG = "DeviceListAdapter"
        const val SELECTED_COLOR = "#AB2196F3"
        const val UNSELECTED_COLOR = "#00000000"
    }

}
