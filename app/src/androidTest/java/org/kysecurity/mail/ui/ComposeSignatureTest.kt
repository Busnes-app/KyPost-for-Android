package org.kysecurity.mail.ui

import android.content.Intent
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.ComposeActivity
import org.kysecurity.mail.ComposeDraftCache
import org.kysecurity.mail.MailSignature

@RunWith(AndroidJUnit4::class)
class ComposeSignatureTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @After
    fun cleanUp() {
        context.deleteSharedPreferences(MailSignature.PREFS_NAME)
        ComposeDraftCache.take()
    }

    /** The editor renders HTML; a signature is typed text and must never become markup. */
    @Test
    fun aNewMessageCarriesTheEscapedSignature() {
        MailSignature.save(context, "<b>Ada</b> & co")

        ActivityScenario.launch<ComposeActivity>(Intent(context, ComposeActivity::class.java)).use { scenario ->
            scenario.onActivity { activity ->
                assertEquals("<br><br>-- <br>&lt;b&gt;Ada&lt;/b&gt; &amp; co", activity.mirroredBodyHtmlForTest())
            }
        }
    }

    @Test
    fun sharedTextIsNotPrefixedWithTheSignature() {
        MailSignature.save(context, "Ada")
        val share = Intent(context, ComposeActivity::class.java)
            .setAction(Intent.ACTION_SEND)
            .setType("text/plain")
            .putExtra(Intent.EXTRA_TEXT, "look at this")

        ActivityScenario.launch<ComposeActivity>(share).use { scenario ->
            scenario.onActivity { activity ->
                assertTrue(!activity.mirroredBodyHtmlForTest().contains("Ada"))
            }
        }
    }
}
