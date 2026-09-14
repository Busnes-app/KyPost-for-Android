package org.kysecurity.mail.pgp

import android.content.Intent
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.EmailDetailActivity

@RunWith(AndroidJUnit4::class)
class ReadOutcomeActivityTest {
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
