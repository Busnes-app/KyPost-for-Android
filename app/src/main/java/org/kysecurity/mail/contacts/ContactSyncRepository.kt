package org.kysecurity.mail.contacts

import org.kysecurity.mail.data.AppDatabase
import org.kysecurity.mail.data.ContactEntity
import org.kysecurity.mail.data.PendingContactChangeEntity
import org.kysecurity.mail.push.PairingData
import androidx.room.withTransaction
import kotlinx.coroutines.flow.Flow
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

    fun observeContacts(): Flow<List<ContactEntity>> = db.contactDao().observeAll()

    suspend fun sync(): ContactSyncOutcome = syncMutex.withLock {
        val pairing = pairingProvider() ?: return@withLock ContactSyncOutcome.NotPaired
        val deviceId = pairing.deviceId
        val deviceSecret = pairing.deviceSecret
        if (deviceId.isNullOrBlank() || deviceSecret.isNullOrBlank()) return@withLock ContactSyncOutcome.NotPaired
        val pendingChanges = db.pendingContactChangeDao().getAllPending()
        var cursor = cursorStore.cursor(pairing.subscriberId)

        // Fail closed BEFORE the network call. A row this app cannot encode used to become an
        // empty ContactDto, which the server accepts as a real update and applyDelta then clears
        // from the outbox -- silently replacing the contact with a blank one, original gone.
        val wireChanges = pendingChanges.map { it to it.toWireDtoOrNull(json) }
        val undecodable = wireChanges.mapNotNull { (row, dto) -> row.takeIf { dto == null } }
        if (undecodable.isNotEmpty()) {
            return@withLock ContactSyncOutcome.Retry(
                "Contact sync stopped: ${undecodable.size} queued change(s) are unreadable " +
                    "(${undecodable.joinToString { it.changeType }}). Nothing was sent or discarded.",
            )
        }

        // Each batch is atomic server-side and acked here on its own, so a failure keeps the
        // batches before it. A rejected batch (413 over the count cap, 400 over the body cap)
        // is split; a single change still rejected stays queued and the rest go on.
        val sendable = wireChanges.map { (row, dto) -> row to requireNotNull(dto) }
        val batches = ArrayDeque(pushBatches(sendable) { (_, dto) -> wireBytes(dto) })
        val refused = mutableListOf<String>()
        var tooOld = false
        while (batches.isNotEmpty()) {
            val batch = batches.removeFirst()
            val result = client.push(
                serverUrl = pairing.serverUrl,
                deviceId = deviceId,
                deviceSecret = deviceSecret,
                baseCursor = cursor,
                changes = batch.map { it.second },
            )
            if (result is ContactSyncResult.BadRequest) {
                if (batch.size > 1) batches.addAll(0, batch.chunked((batch.size + 1) / 2)) else refused += result.message
                continue
            }
            val response = (result as? ContactSyncResult.Success)?.response ?: return@withLock failureOutcome(result)
            applyDelta(pairing.subscriberId, response, batch.map { it.first })
            // Keep pushing on the stale cursor once tooOld: the server keeps answering tooOld
            // without contact lists, and one full pull below replaces them all.
            tooOld = tooOld || response.tooOld
            if (!tooOld) cursor = response.cursor
        }

        var pullFrom: Long? = if (tooOld) 0L else cursor.takeIf { pendingChanges.isEmpty() }
        while (pullFrom != null) {
            val result = client.pull(pairing.serverUrl, deviceId, deviceSecret, pullFrom)
            val response = (result as? ContactSyncResult.Success)?.response ?: return@withLock failureOutcome(result)
            applyDelta(pairing.subscriberId, response, emptyList())
            pullFrom = if (response.tooOld && pullFrom != 0L) 0L else null
        }

        if (refused.isEmpty()) {
            ContactSyncOutcome.Success
        } else {
            ContactSyncOutcome.Retry(
                "The server refused ${refused.size} queued contact change(s); they stay queued " +
                    "(${refused.first()}).",
            )
        }
    }

    private fun wireBytes(dto: ContactDto): Int =
        json.encodeToString(ContactDto.serializer(), dto).toByteArray(Charsets.UTF_8).size + 1

    private fun failureOutcome(result: ContactSyncResult): ContactSyncOutcome = when (result) {
        is ContactSyncResult.Success -> ContactSyncOutcome.Success
        is ContactSyncResult.Unauthorized -> ContactSyncOutcome.Unauthorized
        is ContactSyncResult.ServiceUnavailable -> ContactSyncOutcome.ServiceUnavailable(result.message)
        is ContactSyncResult.BadRequest -> ContactSyncOutcome.Retry(result.message)
        is ContactSyncResult.Retryable -> ContactSyncOutcome.Retry(result.message)
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

    /** [verifiedInPerson] is set only by the PGP QR flow, after an out-of-band comparison. */
    suspend fun queueUpdate(
        contact: ContactDto,
        identityChanged: Boolean,
        verifiedInPerson: Boolean = false,
    ) {
        db.withTransaction {
            val previous = db.contactDao().getByUid(contact.uid)
            db.contactDao().upsertAll(listOf(contact.toEntity(previous, verifiedInPerson, identityChanged)))
            enqueueCoalesced(
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
            enqueueCoalesced(
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

    /** One pending row per uid. The old rows are replaced, never edited in place: a sync may
     *  already have read them, and its ack clears by row id. */
    private suspend fun enqueueCoalesced(change: PendingContactChangeEntity) {
        val dao = db.pendingContactChangeDao()
        val existing = dao.getByUid(change.localUid)
        if (existing.isNotEmpty()) dao.clearFlushed(existing.map { it.id })
        dao.enqueue(coalescedChange(existing, change))
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

/** kypost-server answers 413 above 500 changes and 400 above a 1 MiB body. */
internal const val MAX_PUSH_CHANGES = 500
internal const val MAX_PUSH_BYTES = 900 * 1024

/** Greedy, order-preserving split under both caps. A change over the byte cap travels alone. */
internal fun <T> pushBatches(items: List<T>, sizeOf: (T) -> Int): List<List<T>> {
    val batches = mutableListOf<MutableList<T>>()
    var bytes = 0
    for (item in items) {
        val size = sizeOf(item)
        val last = batches.lastOrNull()
        if (last == null || last.size == MAX_PUSH_CHANGES || bytes + size > MAX_PUSH_BYTES) {
            batches += mutableListOf(item)
            bytes = size
        } else {
            last += item
            bytes += size
        }
    }
    return batches
}

/** An update to an unsynced create stays a create carrying the new payload. A delete stays a
 *  delete even after an unsynced create: that create may already be on the server from a push
 *  whose reply has not arrived, and the server ignores a delete for a uid it never saw. */
internal fun coalescedChange(
    existing: List<PendingContactChangeEntity>,
    change: PendingContactChangeEntity,
): PendingContactChangeEntity =
    if (change.changeType == ContactSyncRepository.CHANGE_UPDATE &&
        existing.any { it.changeType == ContactSyncRepository.CHANGE_CREATE }
    ) {
        change.copy(changeType = ContactSyncRepository.CHANGE_CREATE)
    } else {
        change
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
