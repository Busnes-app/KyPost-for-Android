package org.kysecurity.mail.ui

import android.view.View
import androidx.appcompat.widget.SwitchCompat
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.MailSignature
import org.kysecurity.mail.R
import org.kysecurity.mail.SignatureSettingsActivity

@RunWith(AndroidJUnit4::class)
class SignatureSettingsActivityTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Before
    @After
    fun cleanUp() {
        context.deleteSharedPreferences(MailSignature.PREFS_NAME)
    }

    @Test
    fun refusedTextIsExplainedInlineAndNotSaved() {
        MailSignature.save(context, MailSignature(enabled = true, text = "Ada"))
        ActivityScenario.launch(SignatureSettingsActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                activity.textField.setText("Ada‮evil")
                assertEquals(View.VISIBLE, activity.problemText.visibility)
                assertEquals(activity.getString(R.string.signature_control_character), activity.problemText.text.toString())
                activity.textField.setText("a".repeat(MailSignature.MAX_CHARS + 1))
                assertEquals(View.VISIBLE, activity.problemText.visibility)
            }
        }
        assertEquals("Ada", MailSignature.read(context).text)
    }

    @Test
    fun validTextAndTheSwitchesAreSaved() {
        ActivityScenario.launch(SignatureSettingsActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val switches = mutableListOf<SwitchCompat>()
                fun collect(v: View) {
                    if (v is SwitchCompat) switches += v
                    if (v is android.view.ViewGroup) for (i in 0 until v.childCount) collect(v.getChildAt(i))
                }
                collect(activity.findViewById(android.R.id.content))
                assertEquals(listOf(false, true, true), switches.map { it.isChecked })
                switches[0].isChecked = true
                switches[1].isChecked = false
                activity.textField.setText("Ada\nAnalyst")
                assertEquals(View.GONE, activity.problemText.visibility)
            }
        }
        assertEquals(MailSignature(enabled = true, text = "Ada\nAnalyst", onReply = false, onForward = true), MailSignature.read(context))
    }
}
