package org.kysecurity.mail.ui

import android.content.ContentValues
import android.content.Intent
import android.net.Uri
import android.os.StrictMode
import android.provider.MediaStore
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.android.material.chip.Chip
import com.google.android.material.chip.ChipGroup
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.ComposeActivity
import org.kysecurity.mail.R
import org.kysecurity.mail.security.EphemeralAttachmentBytes
import java.io.File

/** Shared streams are processed in order, so the last (accepted) chip means the rest were seen. */
@RunWith(AndroidJUnit4::class)
class ComposeSharedAttachmentTest {

    @Test
    fun sharedStreamsFromThisAppAreRefused() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val privateFile = File(context.filesDir, "shared-attachment-check.txt").apply { writeText("private") }
        val ownProviderUri = EphemeralAttachmentBytes.register(byteArrayOf(1, 2, 3), "text/plain", "own.txt")
        assertNotNull(ownProviderUri)
        val resolver = context.contentResolver
        val foreignUri = resolver.insert(
            MediaStore.Downloads.EXTERNAL_CONTENT_URI,
            ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, FOREIGN_NAME)
                put(MediaStore.Downloads.MIME_TYPE, "text/plain")
            },
        )
        assertNotNull(foreignUri)
        val vmPolicy = StrictMode.getVmPolicy()
        try {
            resolver.openOutputStream(foreignUri!!)!!.use { it.write("public".toByteArray()) }
            // MediaStore may rename on a collision with an earlier run's leftover.
            val foreignName = resolver.query(foreignUri, arrayOf(MediaStore.Downloads.DISPLAY_NAME), null, null, null)!!
                .use { it.moveToFirst(); it.getString(0) }
            // A file: extra would otherwise be refused by StrictMode before it reaches compose.
            StrictMode.setVmPolicy(StrictMode.VmPolicy.Builder().build())
            val intent = Intent(Intent.ACTION_SEND_MULTIPLE).apply {
                type = "text/plain"
                putParcelableArrayListExtra(
                    Intent.EXTRA_STREAM,
                    arrayListOf(Uri.fromFile(privateFile), ownProviderUri, foreignUri),
                )
                setClass(context, ComposeActivity::class.java)
            }

            ActivityScenario.launch<ComposeActivity>(intent).use { scenario ->
                assertEquals(listOf(foreignName), awaitChipNames(scenario, foreignName))
            }
        } finally {
            StrictMode.setVmPolicy(vmPolicy)
            resolver.delete(foreignUri!!, null, null)
            privateFile.delete()
        }
    }

    private fun awaitChipNames(scenario: ActivityScenario<ComposeActivity>, expected: String): List<String> {
        val deadline = System.currentTimeMillis() + TIMEOUT_MS
        var names = emptyList<String>()
        while (System.currentTimeMillis() < deadline) {
            scenario.onActivity { activity ->
                val chips = activity.findViewById<ChipGroup>(R.id.composeAttachmentsCard)
                names = (0 until chips.childCount).map { (chips.getChildAt(it) as Chip).text.toString() }
            }
            if (expected in names) return names
            Thread.sleep(POLL_MS)
        }
        throw AssertionError("the foreign attachment never arrived; chips: $names")
    }

    private companion object {
        const val FOREIGN_NAME = "kypost-shared-attachment-check.txt"
        const val TIMEOUT_MS = 15_000L
        const val POLL_MS = 200L
    }
}
