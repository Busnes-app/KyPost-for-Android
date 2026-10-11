package org.kysecurity.mail

import android.content.DialogInterface
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import org.kysecurity.mail.security.showSecurely

/** STYLE_GUIDE.md §6: a native AlertDialog in the active palette, shown through [showSecurely].
 *  Colors go on after show(), once the title, message, buttons and list exist; a dialog is its
 *  own window, which the Activity's theme walk never reaches. */
fun AlertDialog.Builder.showThemed(): AlertDialog {
    val dialog = create().showSecurely()
    val palette = getStoredThemePalette(dialog.context)
    val panel = Color.parseColor(palette.panel)
    val ink = Color.parseColor(palette.ink)
    val inkStrong = Color.parseColor(palette.inkStrong)
    val accent = Color.parseColor(palette.accent)
    val density = dialog.context.resources.displayMetrics.density
    dialog.window?.setBackgroundDrawable(
        GradientDrawable().apply {
            setColor(panel)
            cornerRadius = 14 * density
        },
    )
    dialog.findViewById<TextView>(androidx.appcompat.R.id.alertTitle)?.setTextColor(inkStrong)
    dialog.findViewById<TextView>(android.R.id.message)?.setTextColor(ink)
    listOf(DialogInterface.BUTTON_POSITIVE, DialogInterface.BUTTON_NEGATIVE, DialogInterface.BUTTON_NEUTRAL)
        .forEach { dialog.getButton(it)?.setTextColor(accent) }
    dialog.findViewById<View>(androidx.appcompat.R.id.custom)?.let { tintFields(it, inkStrong, ink) }
    // List rows are created as the list lays out, so color them as they arrive.
    dialog.listView?.let { list ->
        tintFields(list, inkStrong, ink)
        list.setOnHierarchyChangeListener(object : ViewGroup.OnHierarchyChangeListener {
            override fun onChildViewAdded(parent: View, child: View) = tintFields(child, inkStrong, ink)
            override fun onChildViewRemoved(parent: View, child: View) = Unit
        })
    }
    return dialog
}

private fun tintFields(view: View, text: Int, hint: Int) {
    if (view is TextView) {
        view.setTextColor(text)
        if (view is EditText) view.setHintTextColor(hint)
    }
    if (view is ViewGroup) for (i in 0 until view.childCount) tintFields(view.getChildAt(i), text, hint)
}
