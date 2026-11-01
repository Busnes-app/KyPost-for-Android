package org.kysecurity.mail

import android.app.Activity
import android.content.Context
import android.view.View
import android.view.ViewGroup

const val RAIL_POSITION_STORAGE_KEY = "kypost-rail-position"

/** Which physical side of a wide window the navigation rail takes. Right is the default. */
enum class RailPosition(val storageValue: String) { RIGHT("right"), LEFT("left") }

internal fun resolveRailPosition(saved: String?): RailPosition =
    RailPosition.values().firstOrNull { it.storageValue == saved } ?: RailPosition.RIGHT

fun getStoredRailPosition(context: Context): RailPosition =
    resolveRailPosition(settings(context).getString(RAIL_POSITION_STORAGE_KEY, null))

fun saveRailPosition(context: Context, position: RailPosition) {
    settings(context).edit().putString(RAIL_POSITION_STORAGE_KEY, position.storageValue).apply()
}

/** Right and Left are physical sides, so a right-to-left locale swaps which layout edge they are. */
internal fun railAtEnd(position: RailPosition, rtl: Boolean): Boolean = (position == RailPosition.RIGHT) != rtl

fun railAtEnd(context: Context): Boolean = railAtEnd(
    getStoredRailPosition(context),
    context.resources.configuration.layoutDirection == View.LAYOUT_DIRECTION_RTL,
)

/** Moves [rail] to the first or last slot of its horizontal parent for the stored side, then pads
 *  it for the bars. Every rail layout declares the rail last, on the end edge. */
fun placeRail(activity: Activity, rail: View) {
    val parent = rail.parent as ViewGroup
    val slot = if (railAtEnd(activity)) parent.childCount - 1 else 0
    if (parent.indexOfChild(rail) != slot) {
        parent.removeView(rail)
        parent.addView(rail, slot)
    }
    applyRailInsets(activity, rail)
}

