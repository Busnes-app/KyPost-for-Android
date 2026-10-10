package org.kysecurity.mail.pgp

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.kysecurity.mail.contacts.toDto
import org.kysecurity.mail.data.AppDatabase
import org.kysecurity.mail.data.ContactEntity
import org.kysecurity.mail.data.DataRuntime
import org.kysecurity.mail.data.RecipientPinEntity

internal class RoomLocalSignerKeys(private val database: () -> AppDatabase) : LocalSignerKeyLookup {
    constructor(context: Context) : this({ DataRuntime.graph(context.applicationContext).database })

    override suspend fun keysFor(address: String): List<LocalSignerKey> {
        val needle = address.trim()
        if (needle.isBlank()) return emptyList()
        return withContext(Dispatchers.IO) {
            val db = database()
            val pins = db.recipientPinDao().forAddress(needle.lowercase())
            // pinnedForEmail, never search: search is capped at five name-ordered rows, which let
            // relay-supplied contacts evict the pin. Exact match in Kotlin, not the SQL LIKE, so a
            // substring cannot admit a lookalike. Skipped when pinned: those keys are not used.
            val contactKeys = if (pins.isNotEmpty()) {
                emptyList()
            } else {
                db.contactDao().pinnedForEmail(needle)
                    .filter { it.hasEmail(needle) }
                    .mapNotNull { it.toLocalSignerKey() }
            }
            authoritativeKeys(pins, contactKeys)
        }
    }
}

/** Keys verified on this device are the only ones accepted for their address; a synced contact
 *  key is consulted only for an address with no pin, which is the behaviour before pins existed. */
internal fun authoritativeKeys(pins: List<RecipientPinEntity>, contactKeys: List<LocalSignerKey>): List<LocalSignerKey> =
    if (pins.isEmpty()) contactKeys else pins.map { LocalSignerKey(publicKey = it.publicKey, confirmed = it.confirmed) }

/** Exact, case-insensitive match against a DECODED address. */
internal fun ContactEntity.hasEmail(address: String): Boolean =
    runCatching { toDto().emails.any { it.value.trim().equals(address, ignoreCase = true) } }
        .getOrDefault(false)

/** Alarms clear `confirmed` but still return the key, so a foreign signature reads KEY_CHANGED. */
internal fun ContactEntity.toLocalSignerKey(): LocalSignerKey? {
    val key = pgpKey?.takeIf { it.isNotBlank() } ?: return null
    if (pgpKeyFingerprint.isNullOrBlank()) return null
    return LocalSignerKey(
        publicKey = key,
        confirmed = !pgpKeyNeedsReverification && !identityNeedsReview,
    )
}
