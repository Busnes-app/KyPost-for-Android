package org.kysecurity.mail.ui

import android.content.Intent
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
import org.kysecurity.mail.mail.MailRuntime
import org.kysecurity.mail.pgp.PgpComposeState
import java.util.concurrent.atomic.AtomicInteger

/** Every way to Send obeys the account's custody, including a confirmation answered after
 *  custody turned out to be webmail-only. */
@RunWith(AndroidJUnit4::class)
class ComposeCustodyGuardTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()

    @Before
    @After
    fun reset() {
        ComposeDraftCache.take()
        MailRuntime.invalidate()
    }

    @Test
    fun custodyResolvedWhileTheSubjectPromptIsOpenStopsTheSend() {
        val sends = AtomicInteger()
        val intent = Intent(instrumentation.targetContext, ComposeActivity::class.java)
            .putExtra(ComposeActivity.EXTRA_TO, "alice@example.com")
            .putExtra(ComposeActivity.EXTRA_BODY, "hello")
        ActivityScenario.launch<ComposeActivity>(intent).use { scenario ->
            scenario.onActivity {
                it.sendObserverForTest = { sends.incrementAndGet() }
                // The editor's own report comes from its page, which CI emulators never finish.
                it.bodyEmptyForTest = false
                // Custody resolves to webmail-only after the prompt was raised...
                it.applyPgpComposeStateForTest(
                    PgpComposeState(canEncrypt = false, canSign = false, handoffToWebmail = true),
                )
                // ...and then the prompt's Send runs its callback.
                it.confirmSendWithoutSubjectForTest()
            }
            instrumentation.waitForIdleSync()

            assertEquals("a webmail-only account went on to send", 0, sends.get())
            scenario.onActivity { it.sendObserverForTest = null }
        }
    }
}
