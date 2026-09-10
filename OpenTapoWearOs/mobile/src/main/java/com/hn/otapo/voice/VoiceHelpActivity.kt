package com.hn.otapo.voice

import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.hn.otapo.R

/**
 * Aide "Assistant vocal" : exemples de phrases (« Ok Google, allume la prise
 * du salon avec OpenTapo ») + bouton pour (re)publier les raccourcis
 * dynamiques des prises sur le launcher.
 */
class VoiceHelpActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_voice_help)

        findViewById<TextView>(R.id.voice_examples).text = getString(R.string.voice_examples)
        findViewById<Button>(R.id.voice_publish).setOnClickListener {
            VoiceShortcutManager.refresh(this)
            Toast.makeText(this, getString(R.string.voice_published), Toast.LENGTH_SHORT).show()
        }
    }
}
