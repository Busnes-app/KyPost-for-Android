package org.kysecurity.mail.ui

import android.content.ContentValues
import android.net.Uri
import android.provider.MediaStore
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.Job
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.ComposeActivity
import org.kysecurity.mail.MemoryBudget

/** Two picks in flight at once each saw the whole budget, so together they could exceed it. */
@RunWith(AndroidJUnit4::class)
class ComposeAttachmentBudgetTest {

    private val resolver = InstrumentationRegistry.getInstrumentation().targetContext.contentResolver

    private fun download(name: String, size: Int): Uri {
        val uri = resolver.insert(
            MediaStore.Downloads.EXTERNAL_CONTENT_URI,
            ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, name)
                put(MediaStore.Downloads.MIME_TYPE, "application/octet-stream")
            },
        )!!
        resolver.openOutputStream(uri)!!.use { it.write(ByteArray(size)) }
        return uri
    }

    @Test
    fun concurrentPicksCannotTogetherExceedTheBudget() {
        // Each fits alone; the two together do not.
        val size = (MemoryBudget.OUTBOUND_ATTACHMENT_BYTES / 2 + 1024 * 1024).toInt()
        val first = download("kypost-budget-a.bin", size)
        val second = download("kypost-budget-b.bin", size)
        try {
            ActivityScenario.launch(ComposeActivity::class.java).use { scenario ->
                val jobs = mutableListOf<Job>()
                // Both started in one main-thread turn, as two picker results arriving together.
                scenario.onActivity {
                    jobs += it.addAttachmentsForTest(listOf(first))
                    jobs += it.addAttachmentsForTest(listOf(second))
                }
                runBlocking { jobs.joinAll() }

                scenario.onActivity {
                    val held = it.attachmentBytesForTest()
                    assertTrue("held $held bytes", held <= MemoryBudget.OUTBOUND_ATTACHMENT_BYTES)
                    assertEquals(size.toLong(), held)
                }
            }
        } finally {
            resolver.delete(first, null, null)
            resolver.delete(second, null, null)
        }
    }
}
