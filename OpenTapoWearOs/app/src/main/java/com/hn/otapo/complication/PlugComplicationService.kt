package com.hn.otapo.complication

import android.app.PendingIntent
import android.content.Intent
import android.util.Log
import androidx.wear.watchface.complications.data.ComplicationData
import androidx.wear.watchface.complications.data.ComplicationType
import androidx.wear.watchface.complications.data.LongTextComplicationData
import androidx.wear.watchface.complications.data.NoDataComplicationData
import androidx.wear.watchface.complications.data.PlainComplicationText
import androidx.wear.watchface.complications.data.ShortTextComplicationData
import androidx.wear.watchface.complications.datasource.ComplicationRequest
import androidx.wear.watchface.complications.datasource.SuspendingComplicationDataSourceService

/**
 * Watch-face complication showing one plug's state.
 *
 * - SHORT_TEXT slot: "ON"/"OFF" (+ plug alias as title)
 * - LONG_TEXT slot: alias as title, "Allumée"/"Éteinte" as body
 * - tap: opens [ComplicationToggleActivity] which toggles the plug via KLAP
 *
 * State comes from the cached device list (refreshed every 5 min and right
 * after each toggle) so complication requests stay instant and offline-safe.
 * Configure the plug with [ComplicationConfigActivity].
 */
class PlugComplicationService : SuspendingComplicationDataSourceService() {

    override suspend fun onComplicationRequest(request: ComplicationRequest): ComplicationData? {
        Log.d(TAG, "onComplicationRequest type=${request.complicationType}")
        val device = ComplicationHelper.findEffective(this)
        if (device == null) {
            Log.d(TAG, "no cached device; returning no-data")
            return NoDataComplicationData()
        }
        val on = device.status.deviceOn
        val tap = tapIntent()
        return when (request.complicationType) {
            ComplicationType.SHORT_TEXT -> ShortTextComplicationData.Builder(
                text = PlainComplicationText.Builder(if (on) "ON" else "OFF").build(),
                contentDescription = PlainComplicationText.Builder(
                    "${device.alias} : ${if (on) "allumée" else "éteinte"}. Toucher pour changer."
                ).build()
            )
                .setTitle(PlainComplicationText.Builder(device.alias).build())
                .setTapAction(tap)
                .build()
            ComplicationType.LONG_TEXT -> LongTextComplicationData.Builder(
                text = PlainComplicationText.Builder(
                    if (on) "Allumée — toucher pour éteindre" else "Éteinte — toucher pour allumer"
                ).build(),
                contentDescription = PlainComplicationText.Builder(
                    "${device.alias} : ${if (on) "allumée" else "éteinte"}"
                ).build()
            )
                .setTitle(PlainComplicationText.Builder(device.alias).build())
                .setTapAction(tap)
                .build()
            else -> {
                Log.d(TAG, "unsupported type ${request.complicationType}; returning no-data")
                NoDataComplicationData()
            }
        }
    }

    override fun getPreviewData(type: ComplicationType): ComplicationData {
        val tap = tapIntent()
        return when (type) {
            ComplicationType.LONG_TEXT -> LongTextComplicationData.Builder(
                text = PlainComplicationText.Builder("Éteinte — toucher pour allumer").build(),
                contentDescription = PlainComplicationText.Builder("Prise salon : éteinte").build()
            )
                .setTitle(PlainComplicationText.Builder("Prise salon").build())
                .setTapAction(tap)
                .build()
            else -> ShortTextComplicationData.Builder(
                text = PlainComplicationText.Builder("OFF").build(),
                contentDescription = PlainComplicationText.Builder("Prise salon : éteinte").build()
            )
                .setTitle(PlainComplicationText.Builder("Salon").build())
                .setTapAction(tap)
                .build()
        }
    }

    private fun tapIntent(): PendingIntent {
        val intent = Intent(this, ComplicationToggleActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        return PendingIntent.getActivity(
            this, REQUEST_TAP, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
    }

    companion object {
        private const val TAG = "PlugComplication"
        private const val REQUEST_TAP = 9001
    }
}
