package org.kysecurity.mail.ui

import android.content.Intent
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.CachedDraft
import org.kysecurity.mail.ComposeActivity
import org.kysecurity.mail.ComposeDraftCache
import org.kysecurity.mail.ComposeKind
import org.kysecurity.mail.MailSignature

@RunWith(AndroidJUnit4::class)
class ComposeSignatureTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val quote = "<br><br><div>bob wrote:</div><blockquote>hi</blockquote>"

    /** An earlier compose test can leave a draft that this launch would restore instead. */
    @Before
    @After
    fun cleanUp() {
        context.deleteSharedPreferences(MailSignature.PREFS_NAME)
        ComposeDraftCache.take()
    }

    private fun openedBody(intent: Intent): String {
        var body = ""
        ActivityScenario.launch<ComposeActivity>(intent).use { scenario ->
            scenario.onActivity { body = it.mirroredBodyHtmlForTest() }
        }
        return body
    }

    private fun quoted(kind: ComposeKind): Intent = ComposeActivity.internalIntent(context)
        .putExtra(ComposeActivity.EXTRA_TO, "bob@example.com")
        .putExtra(ComposeActivity.EXTRA_BODY_HTML, quote)
        .putExtra(ComposeActivity.EXTRA_KIND, kind.name)

    @Test
    fun theSettingsSurviveAReadBack() {
        val saved = MailSignature(enabled = true, text = "Ada\nAnalyst", onReply = false, onForward = true)
        MailSignature.save(context, saved)
        assertEquals(saved, MailSignature.read(context))
        MailSignature.save(context, saved.copy(enabled = false, onReply = true, onForward = false))
        assertEquals(saved.copy(enabled = false, onReply = true, onForward = false), MailSignature.read(context))
    }

    @Test
    fun aNewInstallHasTheSignatureOffAndBothSwitchesOn() {
        assertEquals(MailSignature(enabled = false, text = "", onReply = true, onForward = true), MailSignature.read(context))
    }

    /** The editor renders HTML; a signature is typed text and must never become markup. */
    @Test
    fun aNewMessageCarriesTheEscapedSignature() {
        MailSignature.save(context, MailSignature(enabled = true, text = "<b>Ada</b> & co"))
        assertEquals("<br><br>&lt;b&gt;Ada&lt;/b&gt; &amp; co", openedBody(Intent(context, ComposeActivity::class.java)))
    }

    @Test
    fun turnedOffNothingIsInserted() {
        MailSignature.save(context, MailSignature(enabled = false, text = "Ada"))
        assertEquals("", openedBody(Intent(context, ComposeActivity::class.java)))
        assertEquals(quote, openedBody(quoted(ComposeKind.REPLY)))
    }

    @Test
    fun aReplyAndAForwardCarryItAboveTheQuote() {
        MailSignature.save(context, MailSignature(enabled = true, text = "Ada"))
        assertEquals("<br><br>Ada$quote", openedBody(quoted(ComposeKind.REPLY)))
        assertEquals("<br><br>Ada$quote", openedBody(quoted(ComposeKind.FORWARD)))
    }

    @Test
    fun theSwitchesKeepItOffRepliesAndForwards() {
        MailSignature.save(context, MailSignature(enabled = true, text = "Ada", onReply = false, onForward = false))
        assertEquals(quote, openedBody(quoted(ComposeKind.REPLY)))
        assertEquals(quote, openedBody(quoted(ComposeKind.FORWARD)))
        assertEquals("<br><br>Ada", openedBody(Intent(context, ComposeActivity::class.java)))
    }

    /** The draft already holds whatever its author left, signature or not. */
    @Test
    fun aRestoredDraftGetsNothing() {
        MailSignature.save(context, MailSignature(enabled = true, text = "Ada"))
        ComposeDraftCache.save(CachedDraft("bob@example.com", "", "", "Hi", "typed, signature removed", emptyList()))
        assertEquals("typed, signature removed", openedBody(Intent(context, ComposeActivity::class.java)))
    }

    @Test
    fun sharedTextIsNotPrefixedWithTheSignature() {
        MailSignature.save(context, MailSignature(enabled = true, text = "Ada"))
        val share = Intent(context, ComposeActivity::class.java)
            .setAction(Intent.ACTION_SEND)
            .setType("text/plain")
            .putExtra(Intent.EXTRA_TEXT, "look at this")
        assertFalse(openedBody(share).contains("Ada"))
    }
}
