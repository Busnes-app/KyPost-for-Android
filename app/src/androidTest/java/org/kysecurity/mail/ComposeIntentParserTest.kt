package org.kysecurity.mail

import android.content.Intent
import android.net.Uri
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

/** Instrumented: the parser reads real Uri and Intent, which the JVM unit tests stub out. */
@RunWith(AndroidJUnit4::class)
class ComposeIntentParserTest {

    private fun parse(intent: Intent) = parseComposeIntent(intent, internal = false) { it }

    @Test
    fun mailtoKeepsHeaderRecipients() {
        val prefill = parse(
            Intent(Intent.ACTION_SENDTO, Uri.parse("mailto:a@example.com?to=b@example.com&cc=c@example.com&bcc=d@example.com&subject=Hi")),
        )
        assertEquals("a@example.com, b@example.com", prefill.to)
        assertEquals("c@example.com", prefill.cc)
        assertEquals("d@example.com", prefill.bcc)
        assertEquals("Hi", prefill.subject)
    }

    @Test
    fun mailtoWithOnlyAToHeader() {
        val prefill = parse(Intent(Intent.ACTION_SENDTO, Uri.parse("mailto:?to=support@example.com")))
        assertEquals("support@example.com", prefill.to)
    }

    /** Held across the unlock screen: what comes back parses to the same request, as public. */
    @Test
    fun aRequestHeldAcrossTheLockIsReplayedOnce() {
        val context = androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().targetContext
        PendingExternalCompose.hold(
            Intent(Intent.ACTION_SEND)
                .putExtra(Intent.EXTRA_EMAIL, arrayOf("a@example.com"))
                .putExtra(Intent.EXTRA_SUBJECT, "Notes")
                .putExtra(Intent.EXTRA_TEXT, "hello"),
        )
        val replay = PendingExternalCompose.take(context)!!
        assertEquals(ComposeActivity::class.java.name, replay.component?.className)
        val prefill = parse(replay)
        assertEquals("a@example.com", prefill.to)
        assertEquals("Notes", prefill.subject)
        assertEquals("hello", prefill.bodyHtml)
        assertEquals(null, PendingExternalCompose.take(context))
        assertEquals(false, replay.getBooleanExtra(PendingExternalCompose.EXTRA_FILES_DROPPED, false))

        // Files are not carried, and the replay says so rather than dropping them in silence.
        PendingExternalCompose.hold(
            Intent(Intent.ACTION_SEND).putExtra(Intent.EXTRA_STREAM, Uri.parse("content://example/doc")),
        )
        val withFiles = PendingExternalCompose.take(context)!!
        assertEquals(true, withFiles.getBooleanExtra(PendingExternalCompose.EXTRA_FILES_DROPPED, false))
        assertEquals(null, withFiles.extras?.get(Intent.EXTRA_STREAM))
    }

    @Test
    fun shareKeepsCcAndBcc() {
        val prefill = parse(
            Intent(Intent.ACTION_SEND)
                .putExtra(Intent.EXTRA_EMAIL, arrayOf("a@example.com"))
                .putExtra(Intent.EXTRA_CC, arrayOf("c@example.com", "e@example.com"))
                .putExtra(Intent.EXTRA_BCC, arrayOf("d@example.com")),
        )
        assertEquals("a@example.com", prefill.to)
        assertEquals("c@example.com, e@example.com", prefill.cc)
        assertEquals("d@example.com", prefill.bcc)
    }
}
