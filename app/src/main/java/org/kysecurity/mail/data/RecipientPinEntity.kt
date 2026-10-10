package org.kysecurity.mail.data

import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Query
import androidx.room.Upsert

/**
 * A key verified on this device (the PGP QR flow) for one address. While an address has a pin,
 * only its pinned keys are accepted for it; keys that arrive through sync are never pins, so a
 * contact replaced or rewritten by the server cannot change what is accepted. Re-verifying
 * replaces the pin; only a local wipe or unpair clears the table.
 */
@Entity(tableName = "recipient_pins", primaryKeys = ["address", "fingerprint"])
data class RecipientPinEntity(
    /** Lowercased, trimmed. */
    val address: String,
    /** Empty when the key would not fingerprint; the sender refuses such a pin. */
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

    @Query("DELETE FROM recipient_pins WHERE address IN (:addresses)")
    suspend fun deleteForAddresses(addresses: List<String>)

    @Query("DELETE FROM recipient_pins")
    suspend fun clearAll()
}
