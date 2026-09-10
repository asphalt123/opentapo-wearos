package com.hn.otapo.group

import android.app.AlertDialog
import android.os.Bundle
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.Spinner
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.ItemTouchHelper
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.hn.otapo.R
import com.hn.otapo.data.DeviceStore

/**
 * Crée/édite un groupe : renommer, réordonner les membres par drag & drop,
 * retirer (swipe ou poubelle), ajouter via la liste des prises connues.
 */
class GroupEditActivity : AppCompatActivity() {

    private var groupName: String = ""
    private val members = mutableListOf<GroupMemberAdapter.MemberRow>()
    private lateinit var adapter: GroupMemberAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_group_edit)

        groupName = intent.getStringExtra(EXTRA_GROUP_NAME) ?: ""
        val nameInput: EditText = findViewById(R.id.group_edit_name)
        nameInput.setText(groupName)

        adapter = GroupMemberAdapter(members)
        adapter.onRemove = { position ->
            if (position in members.indices) {
                members.removeAt(position)
                adapter.notifyItemRemoved(position)
            }
        }
        val list: RecyclerView = findViewById(R.id.group_edit_members)
        list.layoutManager = LinearLayoutManager(this)
        list.adapter = adapter
        ItemTouchHelper(
            DragCallback(
                onMove = { from, to -> adapter.move(from, to) },
                onSwiped = { position ->
                    if (position in members.indices) {
                        members.removeAt(position)
                        adapter.notifyItemRemoved(position)
                    }
                },
                swipeDirs = ItemTouchHelper.START or ItemTouchHelper.END
            )
        ).attachToRecyclerView(list)

        findViewById<Button>(R.id.group_edit_add).setOnClickListener { showAddDialog() }
        findViewById<Button>(R.id.group_edit_save).setOnClickListener { save() }
        findViewById<Button>(R.id.group_edit_delete).setOnClickListener { confirmDelete() }

        loadMembers()
    }

    private fun loadMembers() {
        val group = MobileGroupsStore.load(this).firstOrNull { it.name == groupName }
        val devices = DeviceStore.loadCached(this).associateBy { it.id }
        members.clear()
        for (id in group?.deviceIds ?: emptyList()) {
            val device = devices[id] ?: continue
            members.add(
                GroupMemberAdapter.MemberRow(device.id, device.alias, device.status.deviceOn)
            )
        }
        adapter.notifyDataSetChanged()
    }

    private fun showAddDialog() {
        val devices = DeviceStore.loadCached(this).filter { d -> members.none { it.deviceId == d.id } }
        if (devices.isEmpty()) {
            toast(getString(R.string.group_no_more_devices))
            return
        }
        val spinner = Spinner(this).apply {
            adapter = ArrayAdapter(
                this@GroupEditActivity,
                android.R.layout.simple_spinner_dropdown_item,
                devices.map { it.alias }
            )
        }
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.group_add_device))
            .setView(spinner)
            .setPositiveButton(getString(R.string.save)) { _, _ ->
                val device = devices[spinner.selectedItemPosition]
                members.add(
                    GroupMemberAdapter.MemberRow(device.id, device.alias, device.status.deviceOn)
                )
                adapter.notifyItemInserted(members.size - 1)
            }
            .setNegativeButton(getString(R.string.cancel), null)
            .show()
    }

    private fun save() {
        val newName = findViewById<EditText>(R.id.group_edit_name).text.toString().trim()
        if (newName.isEmpty()) {
            toast(getString(R.string.group_name_empty))
            return
        }
        if (!newName.equals(groupName, ignoreCase = true)) {
            if (!MobileGroupsStore.rename(this, groupName, newName)) {
                toast(getString(R.string.group_name_exists))
                return
            }
            groupName = newName
        }
        MobileGroupsStore.updateMembers(this, groupName, members.map { it.deviceId })
        toast(getString(R.string.group_saved, groupName))
        finish()
    }

    private fun confirmDelete() {
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.group_delete_title, groupName))
            .setPositiveButton(getString(R.string.delete)) { _, _ ->
                MobileGroupsStore.delete(this, groupName)
                toast(getString(R.string.group_deleted, groupName))
                finish()
            }
            .setNegativeButton(getString(R.string.cancel), null)
            .show()
    }

    private fun toast(text: String) {
        Toast.makeText(this, text, Toast.LENGTH_SHORT).show()
    }

    companion object {
        const val EXTRA_GROUP_NAME = "group_name"
    }
}
