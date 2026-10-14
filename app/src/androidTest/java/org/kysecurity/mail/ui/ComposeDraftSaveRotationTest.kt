package org.kysecurity.mail.ui

import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.ComposeActivity
import org.kysecurity.mail.ComposeDraftCache
import org.kysecurity.mail.ComposePgpController
import org.kysecurity.mail.ComposeSend
import org.kysecurity.mail.contacts.RecipientPinRetentionTest
import org.kysecurity.mail.mail.MailOutcome
import org.kysecurity.mail.mail.MailRuntime
import org.kysecurity.mail.pgp.EnrollmentSession
import org.kysecurity.mail.pgp.PgpBootstrapClient
import org.kysecurity.mail.pgp.RecipientKeyClient
import org.kysecurity.mail.push.PairingData

/** A rotation mid-save must neither drop the relay's answer nor offer Save draft again. */
@RunWith(AndroidJUnit4::class)
class ComposeDraftSaveRotationTest {

    private val source = FakeMailSource()
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    /** An enrolled client-custody account; the held key means no unlock prompt. */
    @Before
    fun installClientCustodyAccount() {
        reset()
        MailRuntime.sourceForTest = source
        val bootstrap = OkHttpClient.Builder().addInterceptor { chain ->
            Response.Builder().request(chain.request()).protocol(Protocol.HTTP_1_1).code(200).message("OK")
                .body(BOOTSTRAP.toResponseBody("application/json".toMediaType())).build()
        }.build()
        ComposeActivity.pgpControllerForTest = ComposePgpController(
            pairingProvider = {
                PairingData(
                    subscriberId = "sub-1", serverUrl = "https://relay.example.com", registrationUrl = "",
                    pairingToken = "", deviceId = "d", deviceSecret = "s", pairedAtEpochMs = 0L,
                )
            },
            bootstrapClient = PgpBootstrapClient(callFactory = bootstrap),
            recipientKeyClient = RecipientKeyClient(callFactory = bootstrap),
            enrollmentProbe = { true },
        )
        EnrollmentSession.put(RecipientPinRetentionTest.OWN_SECRET_KEY.toCharArray())
    }

    @After
    fun reset() {
        ComposeDraftCache.take()
        ComposeSend.resetForNewSession()
        EnrollmentSession.clear()
        ComposeActivity.pgpControllerForTest = null
        ComposePgpController.resetSessionCache()
        MailRuntime.sourceForTest = null
        MailRuntime.invalidate()
    }

    @Test
    fun aRecreatedComposeAdoptsTheDraftSaveInFlight() {
        val intent = ComposeActivity.internalIntent(context)
            .putExtra(ComposeActivity.EXTRA_TO, "bob@example.com")
            .putExtra(ComposeActivity.EXTRA_SUBJECT, "Plans")
            .putExtra(ComposeActivity.EXTRA_BODY_HTML, "<p>draft</p>")

        ActivityScenario.launch<ComposeActivity>(intent).use { scenario ->
            waitFor("Save draft to be offered") {
                var ready = false
                scenario.onActivity { ready = it.saveDraftOfferedForTest() && it.sendEnabledForTest() == true }
                ready
            }
            scenario.onActivity { it.saveDraftForTest() }
            // The relay now holds the save: FakeMailSource waits for an outcome.
            waitFor("the relay to receive the draft") { source.draftSaves.size == 1 }

            scenario.recreate()
            scenario.onActivity {
                assertTrue("the recreated screen lost the save in flight", it.isSendingForTest())
                assertFalse("Save draft was offered again mid-save", it.sendEnabledForTest() == true)
            }

            source.draftSaveOutcomes.add(MailOutcome.Success(Unit))
            waitFor("the saved draft to close the screen") { scenario.state == Lifecycle.State.DESTROYED }
        }
        assertEquals(1, source.draftSaves.size)
        assertNull(ComposeSend.current())
        assertNull(ComposeDraftCache.take())
    }

    private fun waitFor(what: String, condition: () -> Boolean) {
        val deadline = System.nanoTime() + 20_000_000_000L
        while (!condition()) {
            assertTrue("timed out waiting for $what", System.nanoTime() < deadline)
            InstrumentationRegistry.getInstrumentation().waitForIdleSync()
            Thread.sleep(50)
        }
    }

    private companion object {
        const val BOOTSTRAP =
            """{"hasIdentity":true,"protection":"client","suggestedUserIDs":["me@example.invalid"]}"""
    }
}
