package org.kysecurity.mail.contacts

import org.kysecurity.mail.data.AppDatabase
import org.kysecurity.mail.data.ContactEntity
import org.kysecurity.mail.data.PendingContactChangeEntity
import org.kysecurity.mail.push.PairingData
import androidx.room.withTransaction
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.util.UUID

sealed class ContactSyncOutcome {
    object Success : ContactSyncOutcome()
    object NotPaired : ContactSyncOutcome()
    object Unauthorized : ContactSyncOutcome()
    data class ServiceUnavailable(val message: String) : ContactSyncOutcome()
    data class Retry(val message: String) : ContactSyncOutcome()
}

sealed class ContactDedupeOutcome {
    data class Success(val report: ContactDedupeReportDto) : ContactDedupeOutcome()
    object NotPaired : ContactDedupeOutcome()
    object Unauthorized : ContactDedupeOutcome()
    data class ServiceUnavailable(val message: String) : ContactDedupeOutcome()
    data class Retry(val message: String) : ContactDedupeOutcome()
}

class ContactSyncRepository(
    private val db: AppDatabase,
    private val client: ContactSyncClient,
    private val cursorStore: ContactCursorStore,
    private val pairingProvider: suspend () -> PairingData?,
) {
    private val json = Json { ignoreUnknownKeys = true }

    /** Guards the contacts table against the other sync writer, `DeviceContactRepository.syncAll`. */
    val syncMutex = Mutex()

    val health = ContactSyncHealth()

    fun observeContacts(): Flow<List<ContactEntity>> = db.contactDao().observeAll()

    fun observeSyncStatus(now: () -> Long = System::currentTimeMillis): Flow<ContactSyncStatus> =
        combine(db.pendingContactChangeDao().observeSummary(), health.failures) { pending, failures ->
            contactSyncStatusOf(pending, failures, now())
        }

    /** Recorded before unlocking, so a waiting caller cannot record ahead of this one. */
    suspend fun sync(): ContactSyncOutcome = syncMutex.withLock { syncLocked().also(health::record) }

    private suspend fun syncLocked(): ContactSyncOutcome = run {
        val pairing = pairingProvider() ?: return@run ContactSyncOutcome.NotPaired
        val deviceId = pairing.deviceId
        val deviceSecret = pairing.deviceSecret
        if (deviceId.isNullOrBlank() || deviceSecret.isNullOrBlank()) return@run ContactSyncOutcome.NotPaired
        val pendingChanges = db.pendingContactChangeDao().getAllPending()
        val cursor = cursorStore.cursor(pairing.subscriberId)

        // Fail closed BEFORE the network call. A row this app cannot encode used to become an
        // empty ContactDto, which the server accepts as a real update and applyDelta then clears
        // from the outbox -- silently replacing the contact with a blank one, original gone.
        val wireChanges = pendingChanges.map { it to it.toWireDtoOrNull(json) }
        val undecodable = wireChanges.mapNotNull { (row, dto) -> row.takeIf { dto == null } }
        if (undecodable.isNotEmpty()) {
            return@run ContactSyncOutcome.Retry(
                "Contact sync stopped: ${undecodable.size} queued change(s) are unreadable " +
                    "(${undecodable.joinToString { it.changeType }}). Nothing was sent or discarded.",
            )
        }

        val result = if (pendingChanges.isEmpty()) {
            client.pull(pairing.serverUrl, deviceId, deviceSecret, cursor)
        } else {
            client.push(
                serverUrl = pairing.serverUrl,
                deviceId = deviceId,
                deviceSecret = deviceSecret,
                baseCursor = cursor,
                changes = wireChanges.mapNotNull { it.second },
            )
        }

        when (result) {
            is ContactSyncResult.Success -> {
                applyDelta(pairing.subscriberId, result.response, pendingChanges)
                ContactSyncOutcome.Success
            }
            is ContactSyncResult.Unauthorized -> ContactSyncOutcome.Unauthorized
            is ContactSyncResult.ServiceUnavailable -> ContactSyncOutcome.ServiceUnavailable(result.message)
            is ContactSyncResult.BadRequest -> ContactSyncOutcome.Retry(result.message)
            is ContactSyncResult.Retryable -> ContactSyncOutcome.Retry(result.message)
        }
    }

    /** Deliberately does not call [sync]; the caller must trigger the follow-up sync itself. */
    suspend fun dedupe(): ContactDedupeOutcome = resolveDedupeOutcome(pairingProvider) { pairing ->
        val deviceId = pairing.deviceId
        val deviceSecret = pairing.deviceSecret
        if (deviceId.isNullOrBlank() || deviceSecret.isNullOrBlank()) {
            ContactDedupeResult.Unauthorized("Device is not registered yet")
        } else {
            client.dedupe(pairing.serverUrl, deviceId, deviceSecret)
        }
    }

    /** The local uid is permanent: the server stores an unknown uid as a create, so a replayed
     *  push lands on the same contact. */
    suspend fun queueCreate(contact: ContactDto): String {
        val localUid = UUID.randomUUID().toString()
        val localCopy = contact.copy(uid = localUid)
        db.withTransaction {
            db.contactDao().upsertAll(listOf(localCopy.toEntity()))
            db.pendingContactChangeDao().enqueue(
                PendingContactChangeEntity(
                    localUid = localUid,
                    rev = 0,
                    changeType = CHANGE_CREATE,
                    payloadJson = json.encodeToString(localCopy),
                    createdAtEpochMs = System.currentTimeMillis(),
                ),
            )
        }
        return localUid
    }

    /** All or nothing, and only into an empty outbox: until the push is batched, a larger push
     *  could pass the server's 500-change cap and wedge the outbox. False means it was not empty. */
    suspend fun queueImport(contacts: List<ContactDto>): Boolean = db.withTransaction {
        if (db.pendingContactChangeDao().getAllPending().isNotEmpty()) return@withTransaction false
        contacts.forEach { queueCreate(it) }
        true
    }

    /** [verifiedInPerson] is set only by the PGP QR flow, after an out-of-band comparison. */
    suspend fun queueUpdate(
        contact: ContactDto,
        identityChanged: Boolean,
        verifiedInPerson: Boolean = false,
    ) {
        db.withTransaction {
            val previous = db.contactDao().getByUid(contact.uid)
            db.contactDao().upsertAll(listOf(contact.toEntity(previous, verifiedInPerson, identityChanged)))
            db.pendingContactChangeDao().enqueue(
                PendingContactChangeEntity(
                    localUid = contact.uid,
                    rev = contact.rev,
                    changeType = CHANGE_UPDATE,
                    payloadJson = json.encodeToString(contact),
                    createdAtEpochMs = System.currentTimeMillis(),
                ),
            )
        }
    }

    suspend fun queueDelete(uid: String, rev: Long) {
        db.withTransaction {
            db.contactDao().deleteByUids(listOf(uid))
            db.pendingContactChangeDao().enqueue(
                PendingContactChangeEntity(
                    localUid = uid,
                    rev = rev,
                    changeType = CHANGE_DELETE,
                    payloadJson = "",
                    createdAtEpochMs = System.currentTimeMillis(),
                ),
            )
        }
    }

    private suspend fun applyDelta(
        subscriberId: String,
        response: ContactSyncPullResponseDto,
        flushedChanges: List<PendingContactChangeEntity>,
    ) {
        if (response.tooOld) {
            // Wire contract: the server applies the pushed changes BEFORE it computes tooOld, so
            // they are already persisted and the outbox rows are cleared. Only the cursor is
            // discarded, which makes the next sync a full since=0 re-pull.
            db.withTransaction {
                cursorStore.resetCursor(subscriberId)
                if (flushedChanges.isNotEmpty()) {
                    db.pendingContactChangeDao().clearFlushed(flushedChanges.map { it.id })
                }
            }
            return
        }

        db.withTransaction {
            val incomingEntities = response.changed.map { dto ->
                dto.toEntity(previous = db.contactDao().getByUid(dto.uid))
            }
            db.contactDao().upsertAll(incomingEntities)
            db.contactDao().deleteByUids(response.deleted.map { it.uid })
            if (flushedChanges.isNotEmpty()) {
                db.pendingContactChangeDao().clearFlushed(flushedChanges.map { it.id })
            }
            cursorStore.advanceCursor(subscriberId, response.cursor)
        }
    }

    companion object {
        const val CHANGE_CREATE = "create"
        const val CHANGE_UPDATE = "update"
        const val CHANGE_DELETE = "delete"
    }
}

/** Null when this outbox row cannot be turned into a wire change -- corrupt payload or a change
 *  type this build does not know. Callers must abandon the sync rather than send a substitute. */
internal fun PendingContactChangeEntity.toWireDtoOrNull(json: Json): ContactDto? = when (changeType) {
    ContactSyncRepository.CHANGE_DELETE -> ContactDto(uid = localUid, rev = rev, deleted = true)
    ContactSyncRepository.CHANGE_CREATE -> decodePayload(json)?.copy(uid = localUid)
    ContactSyncRepository.CHANGE_UPDATE -> decodePayload(json)?.copy(uid = localUid, rev = rev)
    else -> null
}

private fun PendingContactChangeEntity.decodePayload(json: Json): ContactDto? =
    runCatching { json.decodeFromString<ContactDto>(payloadJson) }.getOrNull()

internal suspend fun resolveDedupeOutcome(
    pairingProvider: suspend () -> PairingData?,
    dedupeCall: suspend (PairingData) -> ContactDedupeResult,
): ContactDedupeOutcome {
    val pairing = pairingProvider() ?: return ContactDedupeOutcome.NotPaired
    return contactDedupeOutcomeOf(dedupeCall(pairing))
}

internal fun contactDedupeOutcomeOf(result: ContactDedupeResult): ContactDedupeOutcome = when (result) {
    is ContactDedupeResult.Success -> ContactDedupeOutcome.Success(result.report)
    is ContactDedupeResult.Unauthorized -> ContactDedupeOutcome.Unauthorized
    is ContactDedupeResult.ServiceUnavailable -> ContactDedupeOutcome.ServiceUnavailable(result.message)
    is ContactDedupeResult.BadRequest -> ContactDedupeOutcome.Retry(result.message)
    is ContactDedupeResult.Retryable -> ContactDedupeOutcome.Retry(result.message)
}
