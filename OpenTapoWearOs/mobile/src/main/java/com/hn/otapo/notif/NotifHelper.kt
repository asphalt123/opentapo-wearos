package com.hn.otapo.notif

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import com.hn.otapo.MainActivity
import com.hn.otapo.R

/**
 * Central notification helper shared by timers, device monitor, geofences
 * and the optional persistent status notification.
 */
object NotifHelper {

    const val CHANNEL_TIMERS = "opentapo_timers"
    const val CHANNEL_MONITOR = "opentapo_monitor"
    const val CHANNEL_PERSISTENT = "opentapo_persistent"

    const val NOTIF_PERSISTENT_ID = 1001

    fun ensureChannels(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.createNotificationChannel(
            NotificationChannel(
                CHANNEL_TIMERS,
                context.getString(R.string.notif_channel_timers),
                NotificationManager.IMPORTANCE_DEFAULT
            )
        )
        manager.createNotificationChannel(
            NotificationChannel(
                CHANNEL_MONITOR,
                context.getString(R.string.notif_channel_monitor),
                NotificationManager.IMPORTANCE_DEFAULT
            )
        )
        manager.createNotificationChannel(
            NotificationChannel(
                CHANNEL_PERSISTENT,
                context.getString(R.string.notif_channel_persistent),
                NotificationManager.IMPORTANCE_LOW
            )
        )
    }

    fun notify(
        context: Context,
        channel: String,
        id: Int,
        title: String,
        text: String,
        openMain: Boolean = true
    ) {        ensureChannels(context)
        val builder = NotificationCompat.Builder(context, channel)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setAutoCancel(true)
        if (openMain) {
            val intent = Intent(context, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            }
            builder.setContentIntent(
                PendingIntent.getActivity(
                    context, id, intent,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
                )
            )
        }
        try {
            (context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
                .notify(id, builder.build())
        } catch (_: Exception) {
        }
    }

    /** Ongoing status notification (optional): X/Y plugs on, Z offline. */
    fun showPersistent(context: Context, title: String, text: String) {
        ensureChannels(context)
        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val content = PendingIntent.getActivity(
            context, NOTIF_PERSISTENT_ID, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val notif = NotificationCompat.Builder(context, CHANNEL_PERSISTENT)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setOngoing(true)
            .setContentIntent(content)
            .build()
        try {
            (context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
                .notify(NOTIF_PERSISTENT_ID, notif)
        } catch (_: Exception) {
        }
    }

    fun hidePersistent(context: Context) {
        try {
            (context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
                .cancel(NOTIF_PERSISTENT_ID)
        } catch (_: Exception) {
        }
    }
}
