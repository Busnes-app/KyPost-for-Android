package org.kysecurity.mail.data

import androidx.room.Dao
import androidx.room.Query
import androidx.room.Upsert
import kotlinx.coroutines.flow.Flow

@Dao
interface ContactDao {
    @Query("SELECT * FROM contacts ORDER BY isSelf DESC, fn COLLATE NOCASE")
    fun observeAll(): Flow<List<ContactEntity>>

    @Query("SELECT * FROM contacts WHERE uid = :uid")
    suspend fun getByUid(uid: String): ContactEntity?

    // No getSelf(): the account's own PGP identity lives in pgp.ownFingerprintFromBootstrap.

    @Upsert
    suspend fun upsertAll(contacts: List<ContactEntity>)

    @Query("SELECT uid FROM contacts")
    suspend fun allUids(): List<String>

    @Query("DELETE FROM contacts WHERE uid IN (:uids)")
    suspend fun deleteByUids(uids: List<String>)

    @Query("DELETE FROM contacts")
    suspend fun clearAll()

    // Substring match on raw emailsJson works: the address appears verbatim in the encoded JSON.
    suspend fun search(query: String): List<ContactEntity> = searchEscaped(query.escapeLikePattern())

    /** The PIN lookup, deliberately not [search]. `search` is the autocomplete query — ordered by
     *  name and capped at five rows — and the relay supplies both the contact list and the keys it
     *  serves, so same-address decoys sorting ahead of a pinned contact evicted the pin from its
     *  own lookup and the send fell back to the relay's key. Unbounded and unordered; the caller
     *  still matches the address exactly in Kotlin. */
    suspend fun pinnedForEmail(address: String): List<ContactEntity> =
        pinnedForEmailEscaped(address.escapeLikePattern())

    @Query(
        """
        SELECT * FROM contacts
        WHERE emailsJson LIKE '%' || :query || '%' ESCAPE '\'
        """,
    )
    suspend fun pinnedForEmailEscaped(query: String): List<ContactEntity>

    @Query(
        """
        SELECT * FROM contacts
        WHERE (fn LIKE '%' || :query || '%' ESCAPE '\'
            OR emailsJson LIKE '%' || :query || '%' ESCAPE '\')
          AND emailsJson != '[]'
        ORDER BY fn COLLATE NOCASE
        LIMIT 5
        """,
    )
    suspend fun searchEscaped(query: String): List<ContactEntity>
}

internal fun String.escapeLikePattern(): String =
    replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
