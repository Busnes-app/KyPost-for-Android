package org.kysecurity.mail.contacts

import org.kysecurity.mail.data.PendingContactChangeEntity
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** A row that cannot be encoded must yield null, never a substitute ContactDto: an empty DTO is a
 *  legitimate-looking wipe of the contact, and applyDelta then deletes the outbox row that held
 *  the only copy of the real edit. */
class ContactOutboxEncodingTest {

    private val json = Json { ignoreUnknownKeys = true }

    private fun row(type: String, payload: String, uid: String = "uid-1", rev: Long = 7) =
        PendingContactChangeEntity(
            id = 1,
            localUid = uid,
            rev = rev,
            changeType = type,
            payloadJson = payload,
            createdAtEpochMs = 0L,
        )

    /** The server stores an unknown uid as a create, so a replayed create lands on the same
     *  contact instead of minting a second one. Rows queued by older builds carry a blank payload uid. */
    @Test
    fun create_sendsTheLocalUid() {
        val payload = json.encodeToString(ContactDto.serializer(), ContactDto(uid = "", fn = "Jane"))
        val dto = row(ContactSyncRepository.CHANGE_CREATE, payload).toWireDtoOrNull(json)

        assertEquals("uid-1", dto?.uid)
        assertEquals("Jane", dto?.fn)
    }

    @Test
    fun update_stampsLocalUidAndRev() {
        val payload = json.encodeToString(ContactDto.serializer(), ContactDto(uid = "stale", fn = "Jane"))
        val dto = row(ContactSyncRepository.CHANGE_UPDATE, payload).toWireDtoOrNull(json)

        assertEquals("uid-1", dto?.uid)
        assertEquals(7L, dto?.rev)
        assertEquals("Jane", dto?.fn)
    }

    @Test
    fun delete_ignoresTheEmptyPayload() {
        val dto = row(ContactSyncRepository.CHANGE_DELETE, "").toWireDtoOrNull(json)

        assertEquals("uid-1", dto?.uid)
        assertTrue(dto?.deleted == true)
    }

    @Test
    fun update_withMalformedPayload_isRejected() {
        assertNull(row(ContactSyncRepository.CHANGE_UPDATE, "{not json").toWireDtoOrNull(json))
    }

    @Test
    fun create_withMalformedPayload_isRejected() {
        assertNull(row(ContactSyncRepository.CHANGE_CREATE, "").toWireDtoOrNull(json))
    }

    @Test
    fun update_withTruncatedPayload_doesNotBecomeAnEmptyContact() {
        val dto = row(ContactSyncRepository.CHANGE_UPDATE, """{"fn":""").toWireDtoOrNull(json)

        assertNull("a truncated payload must not encode as a blank contact", dto)
    }

    @Test
    fun unknownChangeType_failsClosed() {
        val payload = json.encodeToString(ContactDto.serializer(), ContactDto(fn = "Jane"))
        assertNull(row("merge", payload).toWireDtoOrNull(json))
    }
}
