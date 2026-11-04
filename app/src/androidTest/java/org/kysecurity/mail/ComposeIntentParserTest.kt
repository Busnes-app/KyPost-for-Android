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
