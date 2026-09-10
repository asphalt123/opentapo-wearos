package com.hn.otapo.widget

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.util.Log
import android.widget.RemoteViews
import com.hn.otapo.MainActivity
import com.hn.otapo.R
import com.hn.otapo.data.DeviceController
import com.hn.otapo.data.DeviceStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * Home-screen widget: shows one plug/bulb and toggles it without opening the app.
 *
 * - each widget instance is bound to a device id chosen in [WidgetConfigActivity]
 * - tap on the button sends [ACTION_TOGGLE]; the toggle runs on IO with
 *   [DeviceController] (handles offline/login errors gracefully)
 * - tap on the label opens the app
 * - [MainActivity] refreshes all widgets after every scan/toggle via
 *   [DeviceWidgetHelper.updateAll]
 */
class DeviceWidgetProvider : AppWidgetProvider() {

    override fun onUpdate(context: Context, manager: AppWidgetManager, widgetIds: IntArray) {
        for (widgetId in widgetIds) {
            render(context, manager, widgetId)
        }
    }

    override fun onDeleted(context: Context, widgetIds: IntArray) {
        DeviceWidgetHelper.forget(context, widgetIds.toList())
    }

    override fun onReceive(context: Context, intent: Intent) {
        super.onReceive(context, intent)
        if (intent.action != ACTION_TOGGLE) return
        val widgetId = intent.getIntExtra(
            AppWidgetManager.EXTRA_APPWIDGET_ID,
            AppWidgetManager.INVALID_APPWIDGET_ID
        )
        if (widgetId == AppWidgetManager.INVALID_APPWIDGET_ID) return
        val pending = goAsync()
        CoroutineScope(SupervisorJob() + Dispatchers.Main).launch {
            try {
                renderLoading(context, widgetId)
                val deviceId = DeviceWidgetHelper.deviceIdFor(context, widgetId)
                if (deviceId == null) {
                    renderUnconfigured(context, widgetId)
                    return@launch
                }
                when (val result = DeviceController.toggle(context, deviceId)) {
                    is DeviceController.ControlResult.Success -> {
                        render(context, AppWidgetManager.getInstance(context), widgetId)
                    }
                    else -> {
                        Log.w(TAG, "widget toggle failed: $result")
                        renderOffline(context, widgetId, result)
                    }
                }
            } finally {
                pending.finish()
            }
        }
    }

    private fun render(context: Context, manager: AppWidgetManager, widgetId: Int) {
        val deviceId = DeviceWidgetHelper.deviceIdFor(context, widgetId)
        if (deviceId == null) {
            renderUnconfigured(context, widgetId)
            return
        }
        val device = DeviceStore.findById(context, deviceId)
        if (device == null) {
            renderOffline(context, widgetId, null)
            return
        }
        val views = baseViews(context, widgetId)
        views.setTextViewText(R.id.widget_alias, device.alias)
        views.setTextViewText(R.id.widget_model, device.model.toString())
        val isOn = device.status.deviceOn
        views.setTextViewText(
            R.id.widget_state,
            context.getString(if (isOn) R.string.state_on else R.string.state_off)
        )
        views.setTextViewText(
            R.id.widget_toggle,
            context.getString(if (isOn) R.string.widget_turn_off else R.string.widget_turn_on)
        )
        try {
            manager.updateAppWidget(widgetId, views)
        } catch (e: Exception) {
            Log.w(TAG, "updateAppWidget failed: ${e.message}")
        }
    }

    private fun baseViews(context: Context, widgetId: Int): RemoteViews {
        val views = RemoteViews(context.packageName, R.layout.widget_device)
        val toggle = Intent(context, DeviceWidgetProvider::class.java).apply {
            action = ACTION_TOGGLE
            putExtra(AppWidgetManager.EXTRA_APPWIDGET_ID, widgetId)
        }
        views.setOnClickPendingIntent(
            R.id.widget_toggle,
            PendingIntent.getBroadcast(
                context, widgetId, toggle,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
        )
        val open = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        views.setOnClickPendingIntent(
            R.id.widget_header,
            PendingIntent.getActivity(
                context, widgetId, open,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
        )
        return views
    }

    private fun renderLoading(context: Context, widgetId: Int) {
        val deviceId = DeviceWidgetHelper.deviceIdFor(context, widgetId) ?: return
        val device = DeviceStore.findById(context, deviceId)
        val views = baseViews(context, widgetId)
        views.setTextViewText(R.id.widget_alias, device?.alias ?: "…")
        views.setTextViewText(R.id.widget_model, device?.model?.toString() ?: "")
        views.setTextViewText(R.id.widget_state, context.getString(R.string.powering))
        views.setTextViewText(R.id.widget_toggle, "…")
        try {
            AppWidgetManager.getInstance(context).updateAppWidget(widgetId, views)
        } catch (_: Exception) {
        }
    }

    private fun renderUnconfigured(context: Context, widgetId: Int) {
        val views = baseViews(context, widgetId)
        views.setTextViewText(R.id.widget_alias, context.getString(R.string.widget_no_device))
        views.setTextViewText(R.id.widget_model, "")
        views.setTextViewText(R.id.widget_state, "")
        views.setTextViewText(R.id.widget_toggle, context.getString(R.string.widget_configure))
        try {
            AppWidgetManager.getInstance(context).updateAppWidget(widgetId, views)
        } catch (_: Exception) {
        }
    }

    private fun renderOffline(context: Context, widgetId: Int, result: DeviceController.ControlResult?) {
        val deviceId = DeviceWidgetHelper.deviceIdFor(context, widgetId)
        val device = deviceId?.let { DeviceStore.findById(context, it) }
        val views = baseViews(context, widgetId)
        views.setTextViewText(R.id.widget_alias, device?.alias ?: context.getString(R.string.widget_no_device))
        views.setTextViewText(R.id.widget_model, device?.model?.toString() ?: "")
        val detail = when (result) {
            is DeviceController.ControlResult.NoCredentials -> context.getString(R.string.login_title)
            is DeviceController.ControlResult.Error -> result.message ?: context.getString(R.string.state_offline)
            else -> context.getString(R.string.state_offline)
        }
        views.setTextViewText(R.id.widget_state, detail)
        views.setTextViewText(R.id.widget_toggle, context.getString(R.string.refresh))
        try {
            AppWidgetManager.getInstance(context).updateAppWidget(widgetId, views)
        } catch (_: Exception) {
        }
    }

    companion object {
        const val TAG = "DeviceWidget"
        const val ACTION_TOGGLE = "com.hn.otapo.widget.TOGGLE"
    }
}

/** Preference mapping (widget instance -> device id) + bulk refresh. */
object DeviceWidgetHelper {

    private const val PREFS_WIDGET = "OpenTapoWidgets"
    private const val KEY_PREFIX = "widget_device_"

    fun deviceIdFor(context: Context, widgetId: Int): String? {
        return context.getSharedPreferences(PREFS_WIDGET, Context.MODE_PRIVATE)
            .getString(KEY_PREFIX + widgetId, null)
    }

    fun bind(context: Context, widgetId: Int, deviceId: String) {
        context.getSharedPreferences(PREFS_WIDGET, Context.MODE_PRIVATE).edit()
            .putString(KEY_PREFIX + widgetId, deviceId)
            .apply()
        val manager = AppWidgetManager.getInstance(context)
        try {
            // render through a throwaway provider instance
            DeviceWidgetProvider().onUpdate(context, manager, intArrayOf(widgetId))
        } catch (_: Exception) {
        }
    }

    fun forget(context: Context, widgetIds: List<Int>) {
        val prefs = context.getSharedPreferences(PREFS_WIDGET, Context.MODE_PRIVATE)
        val edit = prefs.edit()
        widgetIds.forEach { edit.remove(KEY_PREFIX + it) }
        edit.apply()
    }

    fun updateAll(context: Context) {
        try {
            val manager = AppWidgetManager.getInstance(context)
            val ids = manager.getAppWidgetIds(
                ComponentName(context, DeviceWidgetProvider::class.java)
            )
            if (ids.isNotEmpty()) {
                DeviceWidgetProvider().onUpdate(context, manager, ids)
            }
        } catch (e: Exception) {
            Log.w("DeviceWidget", "updateAll failed: ${e.message}")
        }
    }
}
