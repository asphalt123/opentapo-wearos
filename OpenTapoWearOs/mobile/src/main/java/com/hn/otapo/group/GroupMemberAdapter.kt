package com.hn.otapo.group

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageButton
import android.widget.ImageView
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.hn.otapo.R

/** Lignes membres du groupe : alias + état, drag = réordonner, poubelle = retirer. */
class GroupMemberAdapter(
    val members: MutableList<MemberRow>
) : RecyclerView.Adapter<GroupMemberAdapter.Holder>() {

    data class MemberRow(val deviceId: String, val alias: String, val on: Boolean)

    var onRemove: ((Int) -> Unit)? = null

    class Holder(view: View) : RecyclerView.ViewHolder(view) {
        val alias: TextView = view.findViewById(R.id.item_member_alias)
        val state: TextView = view.findViewById(R.id.item_member_state)
        val handle: ImageView = view.findViewById(R.id.item_member_handle)
        val remove: ImageButton = view.findViewById(R.id.item_member_remove)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_group_member, parent, false)
        return Holder(view)
    }

    override fun getItemCount(): Int = members.size

    override fun onBindViewHolder(holder: Holder, position: Int) {
        val row = members[position]
        holder.alias.text = row.alias
        holder.state.text = holder.itemView.context.getString(
            if (row.on) R.string.state_on else R.string.state_off
        )
        holder.state.setTextColor(
            holder.itemView.context.getColor(
                if (row.on) R.color.op_accent else R.color.op_text_secondary
            )
        )
        holder.remove.setOnClickListener { onRemove?.invoke(holder.bindingAdapterPosition) }
    }

    fun move(from: Int, to: Int) {
        if (from !in members.indices || to !in members.indices) return
        val item = members.removeAt(from)
        members.add(to, item)
        notifyItemMoved(from, to)
    }
}
