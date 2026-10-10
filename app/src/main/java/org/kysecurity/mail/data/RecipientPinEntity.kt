package org.kysecurity.mail.data

import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Query
import androidx.room.Upsert

/**
 * A recorded key that outlived its contact row. Sync removes contacts on the server's word
 * (tombstones, full snapshots, updates without a key); a key this device recorded must not go
 * with them, so it is kept here and read beside the contacts' own keys. Only a local wipe or
 * unpair clears this table.
 */
@Entity(tableName = "recipient_pins", primaryKeys = ["address", "fingerprint"])
data class RecipientPinEntity(
    /** Lowercased, trimmed. */
    val address: String,
    val fingerprint: String,
    val publicKey: String,
    val confirmed: Boolean,
)

@Dao
interface RecipientPinDao {
    @Query("SELECT * FROM recipient_pins WHERE address = :address")
    suspend fun forAddress(address: String): List<RecipientPinEntity>

    @Upsert
    suspend fun upsertAll(pins: List<RecipientPinEntity>)

    @Query("DELETE FROM recipient_pins")
    suspend fun clearAll()
}
