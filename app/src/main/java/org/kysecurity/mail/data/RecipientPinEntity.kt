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

/**
 * The pins one pre-migration contact row stands for: the key the earlier lookup trusted for each
 * of its addresses. That lookup required both a key and a fingerprint and matched addresses
 * trimmed and case-insensitively, so the same rules apply here.
 */
internal fun legacyPins(
    emailsJson: String?,
    publicKey: String?,
    fingerprint: String?,
    confirmed: Boolean,
): List<RecipientPinEntity> {
    if (publicKey.isNullOrBlank() || fingerprint.isNullOrBlank()) return emptyList()
    val addresses = runCatching {
        legacyJson.decodeFromString(
            kotlinx.serialization.builtins.ListSerializer(org.kysecurity.mail.contacts.ContactFieldDto.serializer()),
            emailsJson.orEmpty(),
        )
    }.getOrDefault(emptyList())
    return addresses.map { it.value.trim().lowercase() }.filter { it.isNotEmpty() }.distinct()
        .map { RecipientPinEntity(it, fingerprint, publicKey, confirmed) }
}

private val legacyJson = kotlinx.serialization.json.Json { ignoreUnknownKeys = true }
