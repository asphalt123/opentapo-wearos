package com.hn.otapo.group

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.hn.otapo.R

/**
 * Cartes groupes : nom + résumé (X allumées / N), appui court = éditer,
 * appui long = tout allumer/éteindre, drag = réordonner, swipe = supprimer.
 */
class GroupListAdapter(
    val groups: MutableList<MobileGroup>,
    val summaries: MutableMap<String, String>,
    private val onOpen: (MobileGroup) -> Unit,
    private val onToggleAll: (MobileGroup) -> Unit
) : RecyclerView.Adapter<GroupListAdapter.Holder>() {

    class Holder(view: View) : RecyclerView.ViewHolder(view) {
        val name: TextView = view.findViewById(R.id.item_group_name)
        val summary: TextView = view.findViewById(R.id.item_group_summary)
        val hint: TextView = view.findViewById(R.id.item_group_hint)
        val handle: ImageView = view.findViewById(R.id.item_group_handle)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_group, parent, false)
        return Holder(view)
    }

    override fun getItemCount(): Int = groups.size

    override fun onBindViewHolder(holder: Holder, position: Int) {
        val group = groups[position]
        holder.name.text = group.name
        holder.summary.text = summaries[group.name]
            ?: holder.itemView.context.getString(R.string.group_members, group.deviceIds.size)
        holder.itemView.setOnClickListener { onOpen(group) }
        holder.itemView.setOnLongClickListener {
            onToggleAll(group)
            true
        }
    }

    fun move(from: Int, to: Int) {
        if (from !in groups.indices || to !in groups.indices) return
        val item = groups.removeAt(from)
        groups.add(to, item)
        notifyItemMoved(from, to)
    }

    fun removeAt(position: Int): MobileGroup {
        val item = groups.removeAt(position)
        notifyItemRemoved(position)
        return item
    }
}
