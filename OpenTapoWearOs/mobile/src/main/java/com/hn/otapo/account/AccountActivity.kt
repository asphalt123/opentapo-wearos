package com.hn.otapo.account

import android.app.AlertDialog
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.hn.otapo.R

/**
 * Gère les comptes Tapo : basculer (maison / travail…), ajouter, supprimer.
 * Basculer vide le cache devices (un LAN par compte) et pousse le compte
 * actif vers la montre ; le retour à l'écran principale relance un scan.
 */
class AccountActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_accounts)

        findViewById<Button>(R.id.accounts_add).setOnClickListener { showAddDialog() }
    }

    override fun onResume() {
        super.onResume()
        refresh()
    }

    private fun refresh() {
        val box: LinearLayout = findViewById(R.id.accounts_list)
        box.removeAllViews()
        val accounts = AccountStore.all(this)
        val activeId = AccountStore.active(this)?.id
        findViewById<TextView>(R.id.accounts_empty).visibility =
            if (accounts.isEmpty()) View.VISIBLE else View.GONE
        for (account in accounts.sortedBy { it.label }) {
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                setPadding(4, 10, 4, 10)
            }
            val isActive = account.id == activeId
            val info = TextView(this).apply {
                text = (if (isActive) "● " else "") + "${account.label}\n${account.username}"
                setTextColor(
                    ContextCompat.getColor(
                        this@AccountActivity,
                        if (isActive) R.color.op_accent else R.color.op_text_primary
                    )
                )
                textSize = 15f
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            }
            info.setOnClickListener {
                if (!isActive && AccountStore.switch(this, account.id)) {
                    toast(getString(R.string.account_switched, account.label))
                    refresh()
                }
            }
            val del = Button(this).apply {
                text = getString(R.string.delete)
                isEnabled = accounts.size > 1
                setOnClickListener { confirmDelete(account.id, account.label) }
            }
            row.addView(info)
            row.addView(del)
            box.addView(row)
        }
    }

    private fun showAddDialog() {
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 24, 48, 0)
        }
        val label = EditText(this).apply { hint = getString(R.string.account_label_hint) }
        val user = EditText(this).apply { hint = getString(R.string.login_email) }
        val pass = EditText(this).apply {
            hint = getString(R.string.login_password)
            inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        layout.addView(label)
        layout.addView(user)
        layout.addView(pass)
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.account_add_title))
            .setView(layout)
            .setPositiveButton(getString(R.string.save)) { _, _ ->
                val l = label.text.toString().trim()
                val u = user.text.toString().trim()
                val p = pass.text.toString()
                if (l.isEmpty() || u.isEmpty() || p.isEmpty()) {
                    toast(getString(R.string.account_need_all))
                    return@setPositiveButton
                }
                AccountStore.add(this, l, u, p)
                toast(getString(R.string.account_added, l))
                refresh()
            }
            .setNegativeButton(getString(R.string.cancel), null)
            .show()
    }

    private fun confirmDelete(id: String, label: String) {
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.account_delete_title, label))
            .setMessage(getString(R.string.account_delete_hint))
            .setPositiveButton(getString(R.string.delete)) { _, _ ->
                AccountStore.remove(this, id)
                toast(getString(R.string.account_deleted, label))
                refresh()
            }
            .setNegativeButton(getString(R.string.cancel), null)
            .show()
    }

    private fun toast(text: String) {
        Toast.makeText(this, text, Toast.LENGTH_SHORT).show()
    }
}
