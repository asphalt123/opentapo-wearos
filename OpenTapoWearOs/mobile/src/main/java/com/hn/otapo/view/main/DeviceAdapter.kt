package com.hn.otapo.view.main

import android.animation.ObjectAnimator
import android.content.res.ColorStateList
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.animation.DecelerateInterpolator
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.card.MaterialCardView
import com.google.android.material.switchmaterial.SwitchMaterial
import com.hn.otapo.R
import com.hn.otapo.tapo.device.Device
import com.hn.otapo.tapo.device.DeviceType

class DeviceAdapter(
    private val devices: List<Device>,
    private val onToggle: (Device, Boolean) -> Unit,
    private val onOpen: (Device) -> Unit = {}
) : RecyclerView.Adapter<DeviceAdapter.Holder>() {

    private var suppress = false
    private var lastAnimatedPosition = -1

    class Holder(view: View) : RecyclerView.ViewHolder(view) {
        val card: MaterialCardView = view.findViewById(R.id.device_card)
        val icon: TextView = view.findViewById(R.id.device_icon)
        val alias: TextView = view.findViewById(R.id.device_alias)
        val model: TextView = view.findViewById(R.id.device_model)
        val state: TextView = view.findViewById(R.id.device_state)
        val dot: View = view.findViewById(R.id.status_dot)
        val power: SwitchMaterial = view.findViewById(R.id.device_power)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder {
        val v = LayoutInflater.from(parent.context).inflate(R.layout.item_device, parent, false)
        return Holder(v)
    }

    override fun onBindViewHolder(holder: Holder, position: Int) {
        val device = devices[position]
        val ctx = holder.itemView.context
        val isOn = device.status.deviceOn

        holder.alias.text = device.alias
        holder.model.text = device.model.toString()
        holder.icon.text = iconFor(device)

        suppress = true
        holder.power.isChecked = isOn
        suppress = false

        holder.state.setText(if (isOn) R.string.state_on else R.string.state_off)
        val pillColor = ContextCompat.getColor(
            ctx, if (isOn) R.color.op_on else R.color.op_text_secondary
        )
        holder.state.setTextColor(pillColor)
        holder.state.backgroundTintList = ColorStateList.valueOf(
            if (isOn) 0x332D7DF6 else 0x22FFFFFF
        )
        holder.dot.setBackgroundResource(if (isOn) R.drawable.dot_on else R.drawable.dot_off)

        // Realtime tint on the icon circle: accent glow when ON.
        holder.icon.alpha = if (isOn) 1f else 0.55f

        holder.power.thumbTintList = ColorStateList.valueOf(
            ContextCompat.getColor(ctx, if (isOn) R.color.op_primary else R.color.op_text_secondary)
        )
        holder.power.setOnCheckedChangeListener(null)
        holder.power.setOnCheckedChangeListener { _, checked ->
            if (!suppress) {
                pulse(holder.card)
                onToggle(device, checked)
            }
        }
        holder.card.setOnClickListener {
            pulse(holder.card)
            onOpen(device)
        }

        // Entrance animation (fade + scale) only for newly revealed rows.
        if (position > lastAnimatedPosition) {
            lastAnimatedPosition = position
            holder.card.alpha = 0f
            holder.card.scaleX = 0.94f
            holder.card.scaleY = 0.94f
            holder.card.animate()
                .alpha(1f)
                .scaleX(1f)
                .scaleY(1f)
                .setDuration(220)
                .setStartDelay((position % 8 * 30).toLong())
                .setInterpolator(DecelerateInterpolator())
                .start()
        }
    }

    override fun getItemCount(): Int = devices.size

    private fun iconFor(device: Device): String {
        return when (device.type) {
            DeviceType.LIGHT_BULB, DeviceType.RGB_LIGHT_BULB -> "💡"
            else -> "🔌"
        }
    }

    private fun pulse(view: View) {
        val scaleX = ObjectAnimator.ofFloat(view, View.SCALE_X, 1f, 0.97f, 1f)
        val scaleY = ObjectAnimator.ofFloat(view, View.SCALE_Y, 1f, 0.97f, 1f)
        scaleX.duration = 160
        scaleY.duration = 160
        scaleX.interpolator = DecelerateInterpolator()
        scaleY.interpolator = DecelerateInterpolator()
        scaleX.start()
        scaleY.start()
    }
}
