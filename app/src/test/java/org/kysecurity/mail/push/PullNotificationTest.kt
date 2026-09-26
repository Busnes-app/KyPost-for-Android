package org.kysecurity.mail.push

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PullNotificationTest {

    @Test
    fun deliveryMode_fromWire_defaultsToPush() {
        assertEquals(DeliveryMode.PULL, DeliveryMode.fromWire("pull"))
        assertEquals(DeliveryMode.PULL, DeliveryMode.fromWire(" PULL "))
        assertEquals(DeliveryMode.PUSH, DeliveryMode.fromWire("push"))
        assertEquals(DeliveryMode.PUSH, DeliveryMode.fromWire(null))
        assertEquals(DeliveryMode.PUSH, DeliveryMode.fromWire("something-else"))
    }

    @Test
    fun resolvePullEndpoint_prefersProvided_elseDerives() {
        assertEquals(
            "https://server.example.com/custom/pull",
            resolvePullEndpoint("https://server.example.com", "https://server.example.com/custom/pull"),
        )
        assertEquals(
            "https://server.example.com/api/notifications/native/pull",
            resolvePullEndpoint("https://server.example.com/", null),
        )
        assertEquals(
            "https://server.example.com/api/notifications/native/pull",
            resolvePullEndpoint("https://server.example.com", "  "),
        )
    }

    @Test
    fun resolvePullEndpoint_rejectsDifferentPortAndUnsafeUrl() {
        assertEquals(
            "https://server.example.com/api/notifications/native/pull",
            resolvePullEndpoint("https://server.example.com", "https://server.example.com:8443/pull"),
        )
        assertEquals(
            "https://server.example.com/api/notifications/native/pull",
            resolvePullEndpoint("https://server.example.com", "http://server.example.com/pull"),
        )
    }

    @Test
    fun toPushPayload_usesTitleAndBody_andFallsBackToData() {
        val n = PullNotification(
            seq = 42,
            title = "Alice",
            body = "Subject line",
            data = mapOf("messageId" to "abc", "url" to "/read"),
            createdAt = "2026-07-05T12:34:56Z",
        )
        val payload = n.toPushPayload(nowEpochMs = 1L)
        assertEquals("abc", payload.messageId)
        assertEquals("Alice", payload.senderName)
        assertEquals("Subject line", payload.emailSubject)
    }

    @Test
    fun toPushPayload_synthesizesMessageIdFromSeq_whenAbsent() {
        val n = PullNotification(seq = 7, title = "T", body = "B", data = null, createdAt = null)
        val payload = n.toPushPayload(nowEpochMs = 99L)
        assertEquals("pull-7", payload.messageId)
        assertEquals(99L, payload.receivedAtEpochMs)
    }

    @Test
    fun toPushPayload_fallsBackToDataSenderSubject_whenTitleBodyBlank() {
        val n = PullNotification(
            seq = 3,
            title = "",
            body = "",
            data = mapOf("sender" to "Bob", "subject" to "Hi"),
        )
        val payload = n.toPushPayload(nowEpochMs = 1L)
        assertEquals("Bob", payload.senderName)
        assertEquals("Hi", payload.emailSubject)
    }

    /** Pull is a second delivery path for the same relay strings, and the relay decides which path
     *  a device is on — so it must bound them to exactly what the push path allows, or the bounds
     *  on the persisted `push_state` history are only as good as the relay's choice. */
    @Test
    fun toPushPayload_boundsRelaySuppliedStrings_identicallyToThePushPath() {
        val n = PullNotification(
            seq = 1,
            title = "s".repeat(10_000),
            body = "j".repeat(10_000),
            data = mapOf("messageId" to "m".repeat(10_000)),
        )
        val pulled = n.toPushPayload(nowEpochMs = 1L)

        assertEquals(PushPayloadParser.MAX_MESSAGE_ID_LENGTH, pulled.messageId.length)
        assertEquals(PushPayloadParser.MAX_HEADER_LENGTH, pulled.senderName.length)
        assertEquals(PushPayloadParser.MAX_HEADER_LENGTH, pulled.emailSubject.length)

        val pushed = requireNotNull(
            PushPayloadParser.parse(
                mapOf(
                    "messageId" to "m".repeat(10_000),
                    "senderName" to "s".repeat(10_000),
                    "emailSubject" to "j".repeat(10_000),
                ),
                nowEpochMs = 1L,
            )
        )
        assertEquals(pushed.messageId, pulled.messageId)
        assertEquals(pushed.senderName, pulled.senderName)
        assertEquals(pushed.emailSubject, pulled.emailSubject)
    }

    /** The `data` fallbacks are relay-supplied too, and the synthesized id must stay non-blank. */
    @Test
    fun toPushPayload_boundsDataFallbacks_andKeepsSynthesizedId() {
        val n = PullNotification(
            seq = 5,
            title = "   ",
            body = "\t",
            data = mapOf("sender" to "a".repeat(9_000), "subject" to "b".repeat(9_000)),
        )
        val payload = n.toPushPayload(nowEpochMs = 1L)

        assertEquals(PushPayloadParser.MAX_HEADER_LENGTH, payload.senderName.length)
        assertEquals(PushPayloadParser.MAX_HEADER_LENGTH, payload.emailSubject.length)
        assertEquals("pull-5", payload.messageId)
        assertTrue(payload.keywords.isEmpty())
    }

    @Test
    fun processor_filtersSeqAtOrBelowCursor_andSortsBySeq() {
        val response = PullNotificationsResponse(
            deliveryMode = "pull",
            cursor = 12,
            notifications = listOf(
                PullNotification(seq = 12, title = "c"),
                PullNotification(seq = 10, title = "a"),
                PullNotification(seq = 11, title = "b"),
                PullNotification(seq = 9, title = "old"), // <= cursor, dropped
            ),
        )
        val prepared = PullNotificationProcessor.prepare(response, currentCursor = 9, nowEpochMs = 1L)
        assertEquals(listOf("pull-10", "pull-11", "pull-12"), prepared.incoming.map { (it as IncomingPush.Mail).payload.messageId })
        assertEquals(12L, prepared.nextCursor)
    }

    @Test
    fun processor_deduplicatesBySeq() {
        val response = PullNotificationsResponse(
            cursor = 5,
            notifications = listOf(
                PullNotification(seq = 5, title = "one"),
                PullNotification(seq = 5, title = "dup"),
            ),
        )
        val prepared = PullNotificationProcessor.prepare(response, currentCursor = 0, nowEpochMs = 1L)
        assertEquals(1, prepared.incoming.size)
    }

    @Test
    fun processor_neverMovesCursorBackwards() {
        // Server reports a lower cursor than we already have (e.g. stale/no new items).
        val response = PullNotificationsResponse(cursor = 3, notifications = emptyList())
        val prepared = PullNotificationProcessor.prepare(response, currentCursor = 20, nowEpochMs = 1L)
        assertTrue(prepared.incoming.isEmpty())
        assertEquals(20L, prepared.nextCursor)
    }

    /** Entries older than the floor are dropped but still advance the cursor; undated ones stay. */
    @Test
    fun processor_dropsEntriesCreatedBeforeTheFloor_andStillAdvancesTheCursor() {
        val response = PullNotificationsResponse(
            cursor = 3,
            notifications = listOf(
                PullNotification(seq = 1, title = "old", createdAt = "2026-07-05T00:00:00Z"),
                PullNotification(seq = 2, title = "fresh", createdAt = "2026-07-05T12:00:00Z"),
                PullNotification(seq = 3, title = "undated"),
            ),
        )
        val floor = java.time.Instant.parse("2026-07-05T06:00:00Z").toEpochMilli()
        val prepared = PullNotificationProcessor.prepare(response, currentCursor = 0, nowEpochMs = 1L, minCreatedAtEpochMs = floor)
        assertEquals(listOf("pull-2", "pull-3"), prepared.incoming.map { (it as IncomingPush.Mail).payload.messageId })
        assertEquals(3L, prepared.nextCursor)
    }

    /** A queued MFA challenge takes the same MFA-first decision as a pushed one. */
    @Test
    fun processor_routesAnMfaChallengeToTheApprovalPath() {
        val response = PullNotificationsResponse(
            cursor = 1,
            notifications = listOf(
                PullNotification(
                    seq = 1,
                    title = "Sign-in request",
                    data = mapOf("type" to "mfa_challenge", "challengeId" to "ch-1", "matchDigits" to "42"),
                ),
            ),
        )
        val prepared = PullNotificationProcessor.prepare(response, currentCursor = 0, nowEpochMs = 1L)
        val routed = prepared.incoming.single() as IncomingPush.Mfa
        assertEquals("ch-1", routed.payload.challengeId)
    }

    @Test
    fun retryAfter_parsesDeltaSeconds_ignoresGarbage() {
        assertEquals(30L, PullNotificationClient.parseRetryAfterSeconds("30"))
        assertNull(PullNotificationClient.parseRetryAfterSeconds("Wed, 21 Oct 2026 07:28:00 GMT"))
        assertNull(PullNotificationClient.parseRetryAfterSeconds(null))
        assertNull(PullNotificationClient.parseRetryAfterSeconds("-5"))
    }
}
