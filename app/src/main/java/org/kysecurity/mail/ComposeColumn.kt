package org.kysecurity.mail

import android.content.Context
import android.util.AttributeSet
import android.widget.LinearLayout

/** Compose's one column: full width on a phone, capped at [R.dimen.compose_column_max_width] on a
 *  wide window, where its parent's `layout_gravity` centres it. LinearLayout has no maxWidth. */
class ComposeColumn @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
) : LinearLayout(context, attrs) {

    private val maxWidth = resources.getDimensionPixelSize(R.dimen.compose_column_max_width)

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        val capped = if (MeasureSpec.getSize(widthMeasureSpec) > maxWidth) {
            MeasureSpec.makeMeasureSpec(maxWidth, MeasureSpec.EXACTLY)
        } else {
            widthMeasureSpec
        }
        super.onMeasure(capped, heightMeasureSpec)
    }
}
