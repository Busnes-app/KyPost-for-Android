package org.kysecurity.mail.ui

import android.widget.EditText
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.ComposeActivity
import org.kysecurity.mail.ComposeDraftCache
import org.kysecurity.mail.ComposePgpController
import org.kysecurity.mail.pgp.PgpComposeState
import org.kysecurity.mail.R
import org.kysecurity.mail.RecipientInputView
import org.kysecurity.mail.afterSplash
import org.kysecurity.mail.mail.MailRuntime

/** Only chips are recipients. An address typed without a trailing comma used to be dropped by
 *  Send in silence; Send now turns it into a chip first. */
@RunWith(AndroidJUnit4::class)
class ComposeTypedRecipientTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()

    @Before
    @After
    fun reset() {
        ComposeDraftCache.take()
        MailRuntime.invalidate()
        ComposeActivity.pgpControllerForTest = null
        ComposePgpController.resetSessionCache()
    }

    @Test
    fun sendKeepsAnAddressStillBeingTyped() {
        val intent = ComposeActivity.internalIntent(instrumentation.targetContext)
            .putExtra(ComposeActivity.EXTRA_TO, "alice@example.com")
            .putExtra(ComposeActivity.EXTRA_BODY, "hello")
        ActivityScenario.launch<ComposeActivity>(intent).afterSplash().use { scenario ->
            scenario.onActivity {
                it.bodyEmptyForTest = false
                it.applyPgpComposeStateForTest(PgpComposeState(canEncrypt = false, canSign = false, handoffToWebmail = false))
                val cc = it.findViewById<RecipientInputView>(R.id.composeCcInput)
                cc.findViewById<EditText>(R.id.recipientInputField).setText("boss@example.com")
                // No subject: Send stops at the empty-subject prompt, after the recipients are read.
                it.sendForTest()
                assertEquals(listOf("boss@example.com"), cc.recipientEmails())
            }
        }
    }
}
