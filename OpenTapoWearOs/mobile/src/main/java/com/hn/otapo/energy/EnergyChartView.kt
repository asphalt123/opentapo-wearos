package com.hn.otapo.energy

import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.util.AttributeSet
import android.view.View

/**
 * Minimal bar chart of recent power samples (no external dependency).
 * Empty state draws a baseline + label instead of crashing on empty data.
 */
class EnergyChartView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null
) : View(context, attrs) {

    var samples: List<PowerSample> = emptyList()
        set(value) {
            field = value
            invalidate()
        }

    var emptyLabel: String = ""
        set(value) {
            field = value
            invalidate()
        }

    private val barPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = 0xFF4FC3F7.toInt() }
    private val axisPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = 0xFF334155.toInt()
        strokeWidth = 2f
    }
    private val textPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = 0xFF9AA7B4.toInt()
        textSize = 30f
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val w = width.toFloat()
        val h = height.toFloat()
        canvas.drawLine(0f, h - 4f, w, h - 4f, axisPaint)
        if (samples.isEmpty()) {
            canvas.drawText(emptyLabel, 16f, h / 2f, textPaint)
            return
        }
        val max = (samples.maxOf { it.watts }).coerceAtLeast(1.0)
        val gap = 6f
        val barW = ((w - gap * (samples.size + 1)) / samples.size).coerceAtLeast(2f)
        samples.forEachIndexed { i, sample ->
            val barH = ((h - 24f) * (sample.watts / max)).toFloat()
            val left = gap + i * (barW + gap)
            canvas.drawRect(left, h - 4f - barH, left + barW, h - 4f, barPaint)
        }
        canvas.drawText(String.format("%.0f W max", max), 16f, 36f, textPaint)
    }
}
