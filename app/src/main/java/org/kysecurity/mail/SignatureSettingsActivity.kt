package org.kysecurity.mail

import android.graphics.Color
import android.os.Bundle
import android.text.InputType
import android.view.View
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.widget.SwitchCompat
import androidx.core.widget.doAfterTextChanged
import org.kysecurity.mail.security.LockedActivity

/** Settings → Signature: this device's own signature ([MailSignature]). Every change is saved as
 *  it is made; text the server's rules refuse is shown with the reason and not saved. */
class SignatureSettingsActivity : LockedActivity() {

    private lateinit var signature: MailSignature

    @androidx.annotation.VisibleForTesting
    internal lateinit var textField: EditText

    @androidx.annotation.VisibleForTesting
    internal lateinit var problemText: TextView

    override fun onCreateUnlocked(savedInstanceState: Bundle?) {
        setTitle(R.string.settings_signature)
        signature = MailSignature.read(this)

        val scrollView = ScrollView(this)
        val page = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dpToPx(16), dpToPx(12), dpToPx(16), dpToPx(20))
        }
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dpToPx(14), dpToPx(12), dpToPx(14), dpToPx(12))
        }
        page.addViewSpaced(container)
        applyTopInsetWithHeader(this, scrollView)

        container.addViewSpaced(
            switch(R.string.signature_enabled, signature.enabled) { signature = signature.copy(enabled = it) },
            bottomDp = 8,
        )
        textField = EditText(this).apply {
            noPersonalizedLearning()
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or
                InputType.TYPE_TEXT_FLAG_CAP_SENTENCES
            minLines = 4
            gravity = android.view.Gravity.TOP or android.view.Gravity.START
            setHint(R.string.signature_hint)
            contentDescription = getString(R.string.settings_signature)
            setText(signature.text)
        }
        container.addViewSpaced(textField, bottomDp = 6)
        problemText = TextView(this).apply {
            textSize = 13f
            visibility = View.GONE
        }
        container.addViewSpaced(problemText, bottomDp = 6)
        container.addViewSpaced(
            TextView(this).apply {
                setText(R.string.signature_device_only_note)
                textSize = 13f
            },
            bottomDp = 16,
        )
        container.addViewSpaced(
            switch(R.string.signature_on_reply, signature.onReply) { signature = signature.copy(onReply = it) },
            bottomDp = 4,
        )
        container.addViewSpaced(
            switch(R.string.signature_on_forward, signature.onForward) { signature = signature.copy(onForward = it) },
        )

        scrollView.addView(page)
        setContentView(scrollView)
        applyThemeToActivity(this)
        // After applyThemeToActivity, which paints every ViewGroup flat `panel` (as Security does).
        val palette = getStoredThemePalette(this)
        scrollView.setBackgroundColor(Color.parseColor(palette.bg))
        page.setBackgroundColor(Color.parseColor(palette.bg))
        applyPanelBackground(this, container)
        problemText.setTextColor(Color.parseColor(palette.danger))

        textField.doAfterTextChanged { onTextChanged(it?.toString().orEmpty()) }
    }

    private fun onTextChanged(text: String) {
        val problem = signatureProblem(text)
        problemText.visibility = if (problem == null) View.GONE else View.VISIBLE
        problemText.text = when (problem) {
            null -> ""
            SignatureProblem.TOO_LONG -> getString(
                R.string.signature_too_long,
                MailSignature.MAX_CHARS,
                text.codePointCount(0, text.length),
            )
            SignatureProblem.CONTROL_CHARACTER -> getString(R.string.signature_control_character)
        }
        if (problem == null) {
            signature = signature.copy(text = text)
            MailSignature.save(this, signature)
        }
    }

    private fun switch(titleRes: Int, checked: Boolean, onChange: (Boolean) -> Unit) = SwitchCompat(this).apply {
        setText(titleRes)
        minHeight = dpToPx(48)
        isChecked = checked
        setOnCheckedChangeListener { _, isChecked ->
            onChange(isChecked)
            MailSignature.save(this@SignatureSettingsActivity, signature)
        }
    }
}
