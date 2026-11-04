package org.kysecurity.mail.security

import android.content.Context
import android.net.Uri

/** Downloads rows outlive the sandbox wipe; plain prefs so it survives the database delete. */
object DownloadedAttachmentLedger {
    private const val TAG = "DownloadedAttachments"

    /** Referenced by [SecurityWipe]'s retained-prefs set, so the name cannot drift between the two. */
    internal const val PREFS_NAME = "org.kysecurity.mail.downloaded_attachments"
    private const val KEY_URIS = "uris"

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    /** Call BEFORE writing the file: this row is the only thing that makes an out-of-sandbox copy
     *  reachable by a wipe, so it must be durable before the copy exists, not after.
     *  Synchronized with [deleteAll]: two saves on the reader's two threads each read the set and
     *  wrote back their own copy, so one row was dropped and outlived the next wipe. */
    @Synchronized
    fun record(context: Context, uri: Uri) {
        val store = prefs(context)
        // A fresh set: SharedPreferences returns the *live* set instance from its cache, and
        // mutating that in place is documented as unsupported and does not persist reliably.
        val updated = LinkedHashSet(store.getStringSet(KEY_URIS, emptySet()).orEmpty())
        updated += uri.toString()
        // commit(), like every other security-relevant write in this package — and here for the
        // sharpest reason: an async flush that has not landed when the process dies leaves
        // decrypted mail in shared storage that no later wipe can find, while the wipe reports
        // the device as cleared.
        store.edit().putStringSet(KEY_URIS, updated).commit()
    }

    /** Deletes every recorded row and returns the ones the provider refused, keeping exactly those
     *  in the ledger so a later sweep can retry them.
     *
     *  Returns rather than throws, deliberately. These rows live in shared storage, in another
     *  process, under an ownership model this app does not control — a row it can never delete
     *  must be REPORTED to the user, not turned into a permanently failing wipe step that blocks
     *  the app forever. Sandbox destruction is the terminal kind; this is not. */
    @Synchronized
    fun deleteAll(
        context: Context,
        /** Injectable for the same reason [org.kysecurity.mail.blockExternalResources] takes a
         *  parser: "it fails closed" is exactly the kind of claim that must not rest on reading the
         *  code, and no real provider can be made to return 0-rows-then-throw-on-query on demand.
         *  Returns the row count, or throws exactly as `ContentResolver` would. */
        delete: (Uri) -> Int = { context.applicationContext.contentResolver.delete(it, null, null) },
        /** Likewise: true still there, false provably gone, null unanswerable. */
        resolves: (Uri) -> Boolean? = { stillResolves(context.applicationContext, it) },
    ): List<String> {
        val appContext = context.applicationContext
        val store = prefs(appContext)
        val recorded = store.getStringSet(KEY_URIS, emptySet()).orEmpty()
        val undeleted = LinkedHashSet<String>()
        recorded.forEach { raw ->
            val uri = Uri.parse(raw)
            val deleted = runCatching { delete(uri) }
                .onFailure { android.util.Log.w(TAG, "Could not delete $raw", it) }
                .getOrNull()
            when {
                // A thrown delete is a failure, never a success.
                deleted == null -> undeleted += raw
                deleted > 0 -> Unit
                // Zero rows affected is ambiguous. It is only "already gone" if the row really is
                // gone, so ask the provider rather than assuming the outcome we wanted — and an
                // UNANSWERABLE question is not a yes. `stillResolves` used to swallow its own
                // SecurityException into `false`, dropping a row this app can no longer read from
                // the one ledger that makes it reachable, while the wipe reported Complete.
                resolves(uri) != false -> undeleted += raw
            }
        }
        // commit(), not apply(): a resumed wipe may start in a different process.
        store.edit().putStringSet(KEY_URIS, undeleted).commit()
        if (undeleted.isNotEmpty()) {
            android.util.Log.e(TAG, "Downloads provider refused to delete: $undeleted")
            return undeleted.toList()
        }
        // Delete the ledger only on full success, so a failed sweep keeps the file to retry from.
        appContext.deleteSharedPreferences(PREFS_NAME)
        return emptyList()
    }

    /** True when the row is still readable, false when it is provably gone, NULL when the provider
     *  could not be asked at all — which callers must not round down to "gone". */
    internal fun stillResolves(appContext: Context, uri: Uri): Boolean? = runCatching {
        appContext.contentResolver.query(uri, arrayOf("_id"), null, null, null)
            ?.use { it.moveToFirst() } ?: false
    }.getOrElse {
        android.util.Log.w(TAG, "Could not ask whether $uri still exists", it)
        null
    }

    /** How many rows are recorded, without touching the provider. [SecurityWipe] reads this before
     *  a sweep so a sweep that THROWS can still report a truthful count instead of a placeholder. */
    fun recordedCount(context: Context): Int =
        prefs(context).getStringSet(KEY_URIS, emptySet()).orEmpty().size
}

