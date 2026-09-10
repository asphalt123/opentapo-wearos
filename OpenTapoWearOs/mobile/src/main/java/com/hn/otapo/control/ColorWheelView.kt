package com.hn.otapo.control

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.RadialGradient
import android.graphics.Shader
import android.graphics.SweepGradient
import android.util.AttributeSet
import android.view.MotionEvent
import android.view.View
import kotlin.math.atan2
import kotlin.math.min
import kotlin.math.sqrt

/**
 * Circular HSV color picker (no external dependency).
 *
 * Angle = hue (0-360°), distance from center = saturation. Emits
 * [onColorChosen] on finger lift so the caller sends a single KLAP request
 * per gesture instead of flooding the bulb.
 */
class ColorWheelView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null
) : View(context, attrs) {

    var onColorChosen: ((hue: Int, saturation: Int) -> Unit)? = null

    private var selectedHue = 0f
    private var selectedSat = 1f
    private var hasSelection = false

    private val wheelPaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val markerPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = 6f
        color = Color.WHITE
    }
    private val markerFill = Paint(Paint.ANTI_ALIAS_FLAG)

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        val radius = min(w, h) / 2f
        val cx = w / 2f
        val cy = h / 2f
        val sweep = SweepGradient(cx, cy, rainbow(), null)
        // compose hue ring with radial saturation falloff via layering:
        // draw sweep first, then a white->transparent radial overlay is
        // approximated by drawing the sweep with full saturation and letting
        // touches near the center map to low saturation values.
        wheelPaint.shader = sweep
        // subtle dark edge
        wheelPaint.setShadowLayer(radius * 0.06f, 0f, 0f, 0x66000000)
        setLayerType(LAYER_TYPE_SOFTWARE, wheelPaint)
    }

    private fun rainbow(): IntArray {
        return IntArray(13) { i -> Color.HSVToColor(floatArrayOf(i * 30f, 1f, 1f)) }
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val radius = min(width, height) / 2f - padding()
        canvas.drawCircle(width / 2f, height / 2f, radius, wheelPaint)
        // center chip showing the current selection
        if (hasSelection) {
            markerFill.color = Color.HSVToColor(floatArrayOf(selectedHue, selectedSat, 1f))
            canvas.drawCircle(width / 2f, height / 2f, radius * 0.30f, markerFill)
            canvas.drawCircle(width / 2f, height / 2f, radius * 0.30f, markerPaint)
            // marker dot on the wheel
            val angle = Math.toRadians((selectedHue - 90).toDouble())
            val r = radius * selectedSat
            val mx = (width / 2f + r * kotlin.math.cos(angle)).toFloat()
            val my = (height / 2f + r * kotlin.math.sin(angle)).toFloat()
            canvas.drawCircle(mx, my, radius * 0.07f, markerFill)
            canvas.drawCircle(mx, my, radius * 0.07f, markerPaint)
        }
    }

    override fun onTouchEvent(event: MotionEvent): Boolean {
        when (event.action) {
            MotionEvent.ACTION_DOWN, MotionEvent.ACTION_MOVE -> {
                updateFromTouch(event.x, event.y)
                return true
            }
            MotionEvent.ACTION_UP -> {
                if (updateFromTouch(event.x, event.y)) {
                    onColorChosen?.invoke(selectedHue.toInt(), (selectedSat * 100).toInt())
                }
                return true
            }
        }
        return super.onTouchEvent(event)
    }

    private fun updateFromTouch(x: Float, y: Float): Boolean {
        val cx = width / 2f
        val cy = height / 2f
        val radius = min(width, height) / 2f - padding()
        val dx = x - cx
        val dy = y - cy
        if (sqrt(dx * dx + dy * dy) > radius) return false
        var hue = Math.toDegrees(atan2(dx, -dy).toDouble()).toFloat()
        if (hue < 0) hue += 360f
        selectedHue = hue
        selectedSat = (sqrt(dx * dx + dy * dy) / radius).coerceIn(0f, 1f)
        hasSelection = true
        invalidate()
        return true
    }

    /** Pre-select from a known hue/saturation (e.g. polled device state). */
    fun setSelected(hue: Int, saturation: Int) {
        selectedHue = hue.coerceIn(0, 360).toFloat()
        selectedSat = (saturation.coerceIn(0, 100) / 100f)
        hasSelection = true
        invalidate()
    }

    private fun padding(): Float = 12f

    @Suppress("unused")
    private fun radialOverlay(): RadialGradient {
        return RadialGradient(
            0f, 0f, 1f,
            intArrayOf(Color.WHITE, Color.TRANSPARENT),
            floatArrayOf(0f, 1f),
            Shader.TileMode.CLAMP
        )
    }
}
