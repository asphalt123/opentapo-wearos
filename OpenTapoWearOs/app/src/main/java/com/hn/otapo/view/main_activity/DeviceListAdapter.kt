package com.hn.otapo.view.main_activity

import android.graphics.Color
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.animation.DecelerateInterpolator
import android.widget.LinearLayout
import android.widget.Switch
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.hn.otapo.R
import com.hn.otapo.tapo.device.Device
import com.hn.otapo.view.intent_data.Credentials
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
        val card: LinearLayout = view.findViewById(R.id.device_list_item_card)
        val dot: View = view.findViewById(R.id.device_list_item_dot)
        val deviceAliasText: TextView = view.findViewById(R.id.device_list_item_alias)
        val deviceModelText: TextView = view.findViewById(R.id.device_list_item_model)
        val deviceStateText: TextView = view.findViewById(R.id.device_list_item_state)
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
                pulse(card)
                applyVisualState(this, isChecked)
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
        suppressListener = false
        applyVisualState(holder, device.status.deviceOn)
        // entrance fade for small round screens: subtle, cheap
        holder.itemView.alpha = 0f
        holder.itemView.animate()
            .alpha(1f)
            .setDuration(180)
            .setStartDelay((position % 6 * 25).toLong())
            .setInterpolator(DecelerateInterpolator())
            .start()
    }

    override fun getItemCount(): Int {
        return devices.size
    }

    /** Connection + power indicator: green dot + ON label when on, red/grey when off. */
    private fun applyVisualState(holder: ViewHolder, isOn: Boolean) {
        val ctx = holder.itemView.context
        holder.dot.setBackgroundResource(if (isOn) R.drawable.dot_on else R.drawable.dot_off)
        holder.card.setBackgroundResource(
            if (isOn) R.drawable.bg_device_card_on else R.drawable.bg_device_card
        )
        holder.deviceStateText.text = ctx.getString(
            if (isOn) R.string.device_activity_power_on else R.string.device_activity_power_off
        )
        holder.deviceStateText.setTextColor(
            ctx.getColor(if (isOn) R.color.op_on else R.color.op_text_secondary)
        )
        holder.devicePowerSwitch.alpha = if (isOn) 1f else 0.6f
        holder.deviceAliasText.alpha = if (isOn) 1f else 0.85f
    }

    private fun pulse(view: View) {
        view.animate().cancel()
        view.scaleX = 1f
        view.scaleY = 1f
        view.animate()
            .scaleX(0.96f)
            .scaleY(0.96f)
            .setDuration(90)
            .setInterpolator(DecelerateInterpolator())
            .withEndAction {
                view.animate()
                    .scaleX(1f)
                    .scaleY(1f)
                    .setDuration(140)
                    .setInterpolator(DecelerateInterpolator())
                    .start()
            }
            .start()
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
                    // revert the switch + visuals on failure
                    mainHandler.post {
                        suppressListener = true
                        holder.devicePowerSwitch.isChecked = !powerState
                        suppressListener = false
                        applyVisualState(holder, !powerState)
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
