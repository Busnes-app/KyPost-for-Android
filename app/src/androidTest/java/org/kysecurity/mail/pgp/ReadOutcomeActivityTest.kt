package org.kysecurity.mail.pgp

import android.content.Intent
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.EmailDetailActivity
import org.kysecurity.mail.mail.MailRuntime

@RunWith(AndroidJUnit4::class)
class ReadOutcomeActivityTest {
    @After
    fun releaseTheMailGraph() {
        // Scenario closes the Activity, but MailRuntime outlives it. Later wipe tests close
        // its DAO's database; leave them no cached repository pointing at that old handle.
        MailRuntime.invalidate()
    }

    @Test
    fun uncheckedSignaturesKeepAVisibleNoticeWithoutAResolvedSender() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val notice = EmailDetailActivity::class.java.getDeclaredMethod("signatureNoticeFor", PgpSignatureState::class.java)
            .apply { isAccessible = true }
        ActivityScenario.launch<EmailDetailActivity>(
            Intent(context, EmailDetailActivity::class.java).putExtra("email_preview", "body"),
        ).use { scenario ->
            scenario.onActivity { activity ->
                assertFalse("test device must have the app unlocked", activity.isFinishing)
                val outcome = ReadOutcome.Decrypted(
                    DecryptedBody(null, "body", protectedSubject = null), PgpSignatureState.UNCHECKED, "",
                )
                val text = notice.invoke(activity, org.kysecurity.mail.displaySignatureVerdict(outcome)) as String?
                assertTrue("unchecked declarations must not disappear", text?.contains("Signature not checked") == true)
            }
        }
    }

    @Test
    fun acceptedAttachmentsSurviveDeliveryAndAreWipedOnDestroyWhileFinishingRejectsThem() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        for (finishing in listOf(false, true)) {
            val bytes = byteArrayOf(1, 2, 3)
            val outcome = ReadOutcome.Decrypted(
                DecryptedBody(
                    html = null, plain = "body", bodyMode = "plain", protectedSubject = null,
                    attachments = listOf(DecryptedAttachment("file.bin", "application/octet-stream", bytes, null)),
                ),
                PgpSignatureState.UNSIGNED,
                "",
            )
            val render = EmailDetailActivity::class.java.getDeclaredMethod("renderReadOutcome", ReadOutcome::class.java)
                .apply { isAccessible = true }
            ActivityScenario.launch<EmailDetailActivity>(
                Intent(context, EmailDetailActivity::class.java)
                    .putExtra("email_preview", "body")
                    .putExtra("email_body_mode", "plain"),
            ).use { scenario ->
                scenario.onActivity { activity ->
                    assertFalse("test device must have the app unlocked", activity.isFinishing)
                    if (finishing) activity.finish()
                    runBlocking {
                        deliverReadOutcome(Dispatchers.Unconfined, read = { outcome }, render = {
                            (render.invoke(activity, it) as Boolean).also { accepted ->
                                assertTrue(accepted != finishing)
                            }
                        })
                    }
                    assertArrayEquals(if (finishing) ByteArray(3) else byteArrayOf(1, 2, 3), bytes)
                }
            }
            assertArrayEquals("destroy must wipe adopted attachments too", ByteArray(3), bytes)
        }
    }
}
