package dev.veeso.opentapo.mobile.view.main

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Switch
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.card.MaterialCardView
import dev.veeso.opentapo.mobile.R
import dev.veeso.opentapo.mobile.tapo.device.Device

class DeviceAdapter(
    private val devices: List<Device>,
    private val onToggle: (Device, Boolean) -> Unit
) : RecyclerView.Adapter<DeviceAdapter.Holder>() {

    private var suppress = false

    class Holder(view: View) : RecyclerView.ViewHolder(view) {
        val card: MaterialCardView = view.findViewById(R.id.device_card)
        val alias: TextView = view.findViewById(R.id.device_alias)
        val model: TextView = view.findViewById(R.id.device_model)
        val state: TextView = view.findViewById(R.id.device_state)
        val power: Switch = view.findViewById(R.id.device_power)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder {
        val v = LayoutInflater.from(parent.context).inflate(R.layout.item_device, parent, false)
        return Holder(v)
    }

    override fun onBindViewHolder(holder: Holder, position: Int) {
        val device = devices[position]
        holder.alias.text = device.alias
        holder.model.text = device.model.toString()
        suppress = true
        holder.power.isChecked = device.status.deviceOn
        suppress = false
        holder.state.setText(if (device.status.deviceOn) R.string.state_on else R.string.state_off)
        holder.state.setTextColor(
            holder.state.context.getColor(
                if (device.status.deviceOn) R.color.op_on else R.color.op_text_secondary
            )
        )
        // re-trigger the state color animation-free binding
        holder.power.setOnCheckedChangeListener(null)
        holder.power.setOnCheckedChangeListener { _, checked ->
            if (!suppress) onToggle(device, checked)
        }
    }

    override fun getItemCount(): Int = devices.size
}
