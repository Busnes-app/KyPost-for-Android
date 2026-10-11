package org.kysecurity.mail.contacts

import android.content.Intent
import android.net.Uri
import android.provider.OpenableColumns
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.security.EphemeralAttachmentBytes

/** Each version choice in the share dialog, delivered through the real ephemeral provider and
 *  read back the way a receiving app would: EXTRA_STREAM, its type, its name and its bytes. */
@RunWith(AndroidJUnit4::class)
class VCardShareTest {
    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()
    private val jane = ContactDto(fn = "Jane Doe", emails = listOf(ContactFieldDto("Work", "jane@acme.example")))

    @After
    fun tearDown() = EphemeralAttachmentBytes.resetForNewSession()

    @Test
    fun eachChoiceDeliversThatVersionAsANamedReadOnlyVcf() {
        val expected = listOf("4.0", "3.0")
        VCARD_SHARE_CHOICES.forEachIndexed { which, _ ->
            val send = requireNotNull(vcardShareIntent(listOf(jane), which, "Jane Doe"))
            assertEquals(Intent.ACTION_SEND, send.action)
            assertEquals(VCARD_MIME_TYPE, send.type)
            assertTrue(send.flags and Intent.FLAG_GRANT_READ_URI_PERMISSION != 0)

            @Suppress("DEPRECATION")
            val uri = requireNotNull(send.getParcelableExtra<Uri>(Intent.EXTRA_STREAM))
            assertEquals(VCARD_MIME_TYPE, context.contentResolver.getType(uri))
            context.contentResolver.query(uri, null, null, null, null)!!.use {
                it.moveToFirst()
                assertEquals("Jane Doe.vcf", it.getString(it.getColumnIndexOrThrow(OpenableColumns.DISPLAY_NAME)))
            }
            val text = context.contentResolver.openInputStream(uri)!!.use { it.readBytes().toString(Charsets.UTF_8) }
            assertTrue(text, text.startsWith("BEGIN:VCARD\r\nVERSION:${expected[which]}\r\nFN:Jane Doe\r\n"))
            assertTrue(text, text.contains("\r\nEMAIL;TYPE=work:jane@acme.example\r\n"))
        }
    }
}
