package org.kysecurity.mail

import android.app.Activity
import android.content.Context
import android.text.InputFilter
import android.text.InputType
import android.widget.EditText
import androidx.appcompat.app.AlertDialog
import org.kysecurity.mail.security.showSecurely

/** The paired account's plain-text signature. Account-scoped: the pairing purge deletes the file. */
internal object MailSignature {
    const val PREFS_NAME = "org.kysecurity.mail.signature"
    private const val KEY = "signature"
    const val MAX_CHARS = 1000

    fun read(context: Context): String =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).getString(KEY, null).orEmpty()

    fun save(context: Context, signature: String) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit()
            .putString(KEY, signature.trim().take(MAX_CHARS))
            .apply()
    }
}

/** Above any quote, after the RFC 3676 "-- " delimiter. [signatureHtml] is already escaped. */
internal fun withSignature(bodyHtml: String, signatureHtml: String): String =
    if (signatureHtml.isBlank()) bodyHtml else "<br><br>-- <br>$signatureHtml$bodyHtml"

fun showSignatureDialog(activity: Activity) {
    val input = EditText(activity).apply {
        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or
            InputType.TYPE_TEXT_FLAG_CAP_SENTENCES
        minLines = 3
        filters = arrayOf(InputFilter.LengthFilter(MailSignature.MAX_CHARS))
        setText(MailSignature.read(activity))
        setHint(R.string.signature_hint)
    }
    val pad = (20 * activity.resources.displayMetrics.density).toInt()
    val frame = android.widget.FrameLayout(activity).apply {
        setPadding(pad, pad / 2, pad, 0)
        addView(input)
    }
    AlertDialog.Builder(activity)
        .setTitle(R.string.settings_signature)
        .setView(frame)
        .setPositiveButton(R.string.save) { _, _ -> MailSignature.save(activity, input.text.toString()) }
        .setNegativeButton(android.R.string.cancel, null)
        .create()
        .showSecurely()
}
