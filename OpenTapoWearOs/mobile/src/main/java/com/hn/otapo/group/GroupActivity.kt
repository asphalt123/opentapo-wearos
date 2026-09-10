package com.hn.otapo.group

import android.app.AlertDialog
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.ItemTouchHelper
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.hn.otapo.R
import com.hn.otapo.data.DeviceController
import com.hn.otapo.data.DeviceStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Liste des groupes : drag & drop pour réordonner, swipe pour supprimer,
 * appui long sur une carte = tout allumer/éteindre, "+" = créer.
 */
class GroupActivity : AppCompatActivity() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private val groups = mutableListOf<MobileGroup>()
    private val summaries = mutableMapOf<String, String>()
    private lateinit var adapter: GroupListAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_groups)

        adapter = GroupListAdapter(groups, summaries, ::openGroup, ::toggleAll)
        val list: RecyclerView = findViewById(R.id.groups_list)
        list.layoutManager = LinearLayoutManager(this)
        list.adapter = adapter
        ItemTouchHelper(
            DragCallback(
                onMove = { from, to ->
                    adapter.move(from, to)
                    MobileGroupsStore.save(this, groups)
                },
                onSwiped = { position ->
                    val removed = adapter.removeAt(position)
                    MobileGroupsStore.delete(this, removed.name)
                    toast(getString(R.string.group_deleted, removed.name))
                    refresh()
                },
                swipeDirs = ItemTouchHelper.START or ItemTouchHelper.END
            )
        ).attachToRecyclerView(list)

        findViewById<Button>(R.id.groups_create).setOnClickListener { showCreateDialog() }
    }

    override fun onResume() {
        super.onResume()
        refresh()
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private fun refresh() {
        groups.clear()
        groups.addAll(MobileGroupsStore.load(this))
        summaries.clear()
        val devices = DeviceStore.loadCached(this).associateBy { it.id }
        for (group in groups) {
            val members = group.deviceIds.mapNotNull { devices[it] }
            val on = members.count { it.status.deviceOn }
            summaries[group.name] = getString(R.string.group_summary, on, members.size)
        }
        adapter.notifyDataSetChanged()
        findViewById<TextView>(R.id.groups_empty).visibility =
            if (groups.isEmpty()) View.VISIBLE else View.GONE
    }

    private fun openGroup(group: MobileGroup) {
        startActivity(
            android.content.Intent(this, GroupEditActivity::class.java)
                .putExtra(GroupEditActivity.EXTRA_GROUP_NAME, group.name)
        )
    }

    /**
     * Appui long : si au moins une prise est éteinte -> tout allumer,
     * sinon tout éteindre.
     */
    private fun toggleAll(group: MobileGroup) {
        val devices = DeviceStore.loadCached(this).associateBy { it.id }
        val members = group.deviceIds.mapNotNull { devices[it] }
        if (members.isEmpty()) {
            toast(getString(R.string.group_empty))
            return
        }
        val targetOn = members.any { !it.status.deviceOn }
        toast(getString(R.string.group_applying, group.name))
        scope.launch {
            val results = withContext(Dispatchers.IO) {
                // sequential: KLAP sessions are per-device, parallel bursts
                // trigger UDP loss on cheap plugs
                val out = mutableMapOf<String, DeviceController.ControlResult>()
                for (member in members) {
                    out[member.id] = DeviceController.toggle(this@GroupActivity, member.id, targetOn)
                }
                out
            }
            val ok = results.values.count { it is DeviceController.ControlResult.Success }
            toast(getString(R.string.group_applied, group.name, ok, members.size))
            com.hn.otapo.monitor.DeviceMonitorReceiver.refreshPersistent(this@GroupActivity)
            refresh()
        }
    }

    private fun showCreateDialog() {
        val devices = DeviceStore.loadCached(this)
        if (devices.isEmpty()) {
            toast(getString(R.string.widget_config_empty))
            return
        }
        val names = devices.map { it.alias }.toTypedArray()
        val checked = BooleanArray(devices.size)
        val input = EditText(this).apply { hint = getString(R.string.group_name_hint) }
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.group_create_title))
            .setView(input)
            .setMultiChoiceItems(names, checked) { _, which, isChecked -> checked[which] = isChecked }
            .setPositiveButton(getString(R.string.save)) { _, _ ->
                val name = input.text.toString().trim()
                if (name.isEmpty()) {
                    toast(getString(R.string.group_name_empty))
                    return@setPositiveButton
                }
                val ids = devices.filterIndexed { i, _ -> checked[i] }.map { it.id }
                if (!MobileGroupsStore.create(this, name, ids)) {
                    toast(getString(R.string.group_name_exists))
                } else {
                    refresh()
                }
            }
            .setNegativeButton(getString(R.string.cancel), null)
            .show()
    }

    private fun toast(text: String) {
        Toast.makeText(this, text, Toast.LENGTH_SHORT).show()
    }
}
