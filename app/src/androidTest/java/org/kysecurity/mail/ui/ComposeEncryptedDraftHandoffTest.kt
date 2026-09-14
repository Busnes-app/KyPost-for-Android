package org.kysecurity.mail.ui

import android.content.Intent
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.runner.lifecycle.ActivityLifecycleCallback
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry
import androidx.test.runner.lifecycle.Stage
import java.util.concurrent.atomic.AtomicReference
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.CachedDraft
import org.kysecurity.mail.ComposeActivity
import org.kysecurity.mail.ComposeDraftCache
import org.kysecurity.mail.mail.MailOutcome
import org.kysecurity.mail.mail.OutgoingAttachment
import org.kysecurity.mail.pgp.DraftSaveOutcome

@RunWith(AndroidJUnit4::class)
class ComposeEncryptedDraftHandoffTest {
    @After fun cleanup() { ComposeDraftCache.take() }

    private fun launch(): ActivityScenario<ComposeActivity> {
        ComposeDraftCache.take()
        ComposeDraftCache.save(CachedDraft(
            "to@example.invalid", "cc@example.invalid", "bcc@example.invalid", "Private subject",
            "<p>Private body</p>", listOf(OutgoingAttachment("note.txt", "text/plain", byteArrayOf(1, 2, 3))),
        ))
        return ActivityScenario.launch(Intent(InstrumentationRegistry.getInstrumentation().targetContext, ComposeActivity::class.java))
    }

    @Test fun initialBodyIsRecoverableBeforeTheFirstAsyncExport() {
        val firstMirror = AtomicReference<String>()
        val callback = ActivityLifecycleCallback { activity, stage ->
            if (activity is ComposeActivity && stage == Stage.RESUMED) {
                firstMirror.compareAndSet(null, activity.mirroredBodyHtmlForTest())
            }
        }
        val monitor = ActivityLifecycleMonitorRegistry.getInstance()
        monitor.addLifecycleCallback(callback)
        try {
            launch().use {
                assertTrue("initial body missing before the queued export", firstMirror.get().orEmpty().contains("Private body"))
            }
        } finally { monitor.removeLifecycleCallback(callback) }
    }

    @Test fun failuresAndMissingBrowserKeepAllComposeFields() {
        launch().use { scenario ->
            scenario.onActivity { activity ->
                for (outcome in listOf(
                    DraftSaveOutcome.Cancelled, DraftSaveOutcome.NotEnrolled, DraftSaveOutcome.EncryptFailed,
                    DraftSaveOutcome.SaveFailed(MailOutcome.UpstreamFailure("offline")),
                )) {
                    activity.completeDraftHandoff(outcome) { error("failure must not open webmail") }
                    assertFalse(activity.isFinishing)
                }
                activity.completeDraftHandoff(DraftSaveOutcome.Saved) { false }
                assertFalse(activity.isFinishing)
                val restored = activity.restoredDraftForTest!!
                assertEquals("to@example.invalid", restored.to)
                assertEquals("cc@example.invalid", restored.cc)
                assertEquals("bcc@example.invalid", restored.bcc)
                assertEquals("Private subject", restored.subject)
                assertTrue(restored.bodyHtml.contains("Private body"))
                assertArrayEquals(byteArrayOf(1, 2, 3), restored.attachments.single().bytes)
            }
            scenario.recreate()
            scenario.onActivity { activity ->
                val restored = activity.restoredDraftForTest!!
                assertEquals("Private subject", restored.subject)
                assertEquals("to@example.invalid", restored.to)
                assertEquals("cc@example.invalid", restored.cc)
                assertEquals("bcc@example.invalid", restored.bcc)
                assertTrue(restored.bodyHtml.contains("Private body"))
                assertArrayEquals(byteArrayOf(1, 2, 3), restored.attachments.single().bytes)
            }
        }
    }

    @Test fun savedAndOpenedDraftKeepsTheOnlyLocalCopy() {
        launch().use { scenario ->
            scenario.onActivity { activity ->
                var opened = false
                activity.completeDraftHandoff(DraftSaveOutcome.Saved) { opened = true; true }
                assertTrue(opened)
                assertFalse(activity.isFinishing)
                assertNotNull(activity.restoredDraftForTest)
                val consent = activity.getString(org.kysecurity.mail.R.string.compose_handoff_encrypted_body)
                assertTrue(consent.contains("From and To"))
                assertTrue(consent.contains("server"))
            }
            scenario.recreate()
            scenario.onActivity { activity ->
                assertEquals("Private subject", activity.restoredDraftForTest!!.subject)
                assertArrayEquals(byteArrayOf(1, 2, 3), activity.restoredDraftForTest!!.attachments.single().bytes)
            }
        }
    }
}
