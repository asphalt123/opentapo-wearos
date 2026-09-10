package com.hn.otapo.backup

import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.FileProvider
import com.hn.otapo.R
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Sauvegarde / restauration : exporte toute la config (appareils, groupes,
 * zones, minuteries, comptes chiffrés) vers un fichier JSON, la restaure et
 * la partage entre utilisateurs.
 *
 * Les mots de passe sont chiffrés avec la phrase saisie ici (jamais en
 * clair) : transmets le fichier et la phrase par deux canaux séparés.
 */
class BackupActivity : AppCompatActivity() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private var lastExported: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_backup)

        findViewById<Button>(R.id.backup_export).setOnClickListener { export() }
        findViewById<Button>(R.id.backup_import).setOnClickListener { pickFile() }
        findViewById<Button>(R.id.backup_share).setOnClickListener { share() }
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private fun passphrase(): String? {
        val p = findViewById<EditText>(R.id.backup_passphrase).text.toString()
        if (p.length < 4) {
            toast(getString(R.string.backup_need_passphrase))
            return null
        }
        return p
    }

    private fun export() {
        val pass = passphrase() ?: return
        scope.launch {
            try {
                val json = withContext(Dispatchers.IO) { BackupManager.exportToJson(this@BackupActivity, pass) }
                lastExported = json
                val name = "opentapo-backup-" +
                    SimpleDateFormat("yyyyMMdd-HHmm", Locale.US).format(Date()) + ".json"
                val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                    addCategory(Intent.CATEGORY_OPENABLE)
                    type = "application/json"
                    putExtra(Intent.EXTRA_TITLE, name)
                }
                startActivityForResult(intent, REQUEST_EXPORT)
            } catch (e: Exception) {
                toast(getString(R.string.error_generic, e.message))
            }
        }
    }

    private fun pickFile() {
        if (passphrase() == null) return
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
            putExtra(Intent.EXTRA_MIME_TYPES, arrayOf("application/json", "text/plain"))
        }
        startActivityForResult(intent, REQUEST_IMPORT)
    }

    private fun share() {
        val json = lastExported
        if (json.isNullOrEmpty()) {
            toast(getString(R.string.backup_export_first))
            return
        }
        try {
            val file = File(cacheDir, "opentapo-backup-share.json")
            file.writeText(json)
            val uri = FileProvider.getUriForFile(this, "$packageName.fileprovider", file)
            val intent = Intent(Intent.ACTION_SEND).apply {
                type = "application/json"
                putExtra(Intent.EXTRA_STREAM, uri)
                putExtra(Intent.EXTRA_SUBJECT, getString(R.string.backup_share_subject))
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            startActivity(Intent.createChooser(intent, getString(R.string.backup_share_subject)))
        } catch (e: Exception) {
            toast(getString(R.string.error_generic, e.message))
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode != RESULT_OK || data?.data == null) return
        val uri = data.data!!
        when (requestCode) {
            REQUEST_EXPORT -> {
                val json = lastExported ?: return
                scope.launch {
                    try {
                        withContext(Dispatchers.IO) {
                            contentResolver.openOutputStream(uri)?.use { it.write(json.toByteArray(Charsets.UTF_8)) }
                                ?: throw IllegalStateException("cannot open $uri")
                        }
                        setStatus(getString(R.string.backup_exported))
                        toast(getString(R.string.backup_exported))
                    } catch (e: Exception) {
                        toast(getString(R.string.error_generic, e.message))
                    }
                }
            }
            REQUEST_IMPORT -> {
                val pass = passphrase() ?: return
                scope.launch {
                    try {
                        val raw = withContext(Dispatchers.IO) {
                            contentResolver.openInputStream(uri)?.use { it.readBytes().toString(Charsets.UTF_8) }
                                ?: throw IllegalStateException("cannot open $uri")
                        }
                        val backup = BackupManager.parse(raw)
                        withContext(Dispatchers.IO) { BackupManager.restore(this@BackupActivity, backup, pass) }
                        setStatus(getString(R.string.backup_imported, backup.accounts.size))
                        toast(getString(R.string.backup_imported, backup.accounts.size))
                    } catch (e: Exception) {
                        toast(getString(R.string.error_generic, e.message))
                    }
                }
            }
        }
    }

    private fun setStatus(text: String) {
        findViewById<TextView>(R.id.backup_status).text = text
    }

    private fun toast(text: String) {
        Toast.makeText(this, text, Toast.LENGTH_LONG).show()
    }

    companion object {
        const val REQUEST_EXPORT = 61
        const val REQUEST_IMPORT = 62
    }
}
