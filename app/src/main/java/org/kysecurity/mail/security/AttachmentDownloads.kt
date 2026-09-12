package org.kysecurity.mail.security

import android.content.ContentValues
import android.content.Context
import android.os.Environment
import android.provider.MediaStore
import org.kysecurity.mail.safeFileName
import org.kysecurity.mail.safeMimeType
import java.io.OutputStream

private const val TAG = "AttachmentDownloads"

/** Saves a decrypted attachment into shared Downloads, or leaves nothing behind.
 *
 *  Name and type come from the sender's headers, unfiltered by the relay: both are sanitised here.
 *
 *  The row is created PENDING, so no other app can read a half-written file, and it is published
 *  only once the last byte has landed. Every failure after the insert deletes the row: a save that
 *  reported failure used to leave partial decrypted mail in Downloads, reachable by any app with
 *  read access, until some future wipe happened to sweep the ledger. */
internal fun saveAttachmentToDownloads(
    context: Context,
    name: String,
    mimeType: String,
    bytes: ByteArray,
    /** Injectable for the same reason [DownloadedAttachmentLedger.deleteAll]'s `delete` is: no real
     *  provider can be asked to fail halfway through a write on demand, and "the partial file is
     *  cleaned up" must not rest on reading the code. */
    write: (OutputStream, ByteArray) -> Unit = { stream, payload -> stream.write(payload) },
): Boolean {
    val resolver = context.contentResolver
    val safeType = safeMimeType(mimeType, name)
    val values = ContentValues().apply {
        // The name's extension is derived from safeType, not from the sender's filename.
        put(MediaStore.Downloads.DISPLAY_NAME, safeFileName(name, safeType))
        put(MediaStore.Downloads.MIME_TYPE, safeType)
        put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
        // Invisible to every other app until the write completes below.
        put(MediaStore.Downloads.IS_PENDING, 1)
    }
    val uri = runCatching { resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values) }
        .getOrNull() ?: return false
    // Recorded BEFORE a byte is written, and with commit(): this row is the only thing that makes
    // a file outside the sandbox reachable by a later wipe, so it has to be durable before the file
    // exists. Recorded after, a crash in openOutputStream leaves decrypted mail in shared storage
    // that nothing will ever find again.
    DownloadedAttachmentLedger.record(context, uri)
    val outcome = runCatching {
        resolver.openOutputStream(uri)?.use { write(it, bytes) }
            ?: error("The Downloads provider returned no stream for $uri")
        resolver.update(uri, ContentValues().apply { put(MediaStore.Downloads.IS_PENDING, 0) }, null, null)
    }
    if (outcome.isSuccess) return true
    android.util.Log.w(TAG, "Attachment save failed; deleting the row", outcome.exceptionOrNull())
    // The ledger entry stays either way. A row this delete cannot remove must remain findable by
    // the wipe, and one whose row is already gone costs the wipe a single no-op delete.
    runCatching { resolver.delete(uri, null, null) }
        .onFailure { android.util.Log.e(TAG, "Partial attachment left in Downloads: $uri", it) }
    return false
}
