package org.kysecurity.mail.push

import org.kysecurity.mail.HEADER_DEVICE_ID
import org.kysecurity.mail.HEADER_DEVICE_SECRET
import org.kysecurity.mail.testing.FakeCallFactory
import org.kysecurity.mail.testing.response
import org.kysecurity.mail.testing.testTlsHandshake
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import okhttp3.Request
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * New-device approval (KyPost-Server #516, `docs/device-approval.md`): a web-minted pairing token
 * registers as 202 pending, the app polls `pairing-status` until 200 or 410, and a `direct` token
 * still registers at once with 200.
 */
class DeviceApprovalTest {

    private val scanned = PairingData(
        subscriberId = "sub-1",
        serverUrl = "https://relay.example.com",
        registrationUrl = "https://relay.example.com/api/notifications/native/register",
        pairingToken = "tok",
        deviceId = null,
        deviceSecret = null,
        pairedAtEpochMs = 0L,
    )

    private val statusUrl = "https://relay.example.com/api/notifications/native/pairing-status"

    private fun pendingBody(statusEndpoint: String = statusUrl) = """{"ok":false,"synced":false,"status":"pending",
        "error":"approve this device on the web page that showed the pairing code",
        "deviceId":"dev-pending","deviceSecret":"pending-secret","approvalCode":"048213",
        "expiresAt":"2026-11-01T12:05:00Z","statusEndpoint":"$statusEndpoint","pollIntervalSeconds":3}"""

    private val waitingBody = """{"status":"pending","approvalCode":"048213","expiresAt":"2026-11-01T12:05:00Z","pollIntervalSeconds":3}"""
    private val approvedBody = """{"ok":true,"synced":true,"status":"approved","deviceId":"dev-merged","deliveryMode":"pull","pullEndpoint":"https://relay.example.com/api/notifications/native/pull","transport":"fcm"}"""
    private val rejectedBody = """{"status":"rejected","error":"this pairing was denied or has expired; scan a new pairing code"}"""

    /** 12:00:00Z, five minutes before the pending request expires. */
    private val registeredAt = java.time.Instant.parse("2026-11-01T12:00:00Z").toEpochMilli()

    private class Server(val statusAnswers: List<Pair<Int, String>>, val registerAnswer: Pair<Int, String>) {
        val statusRequests = mutableListOf<Request>()
        var registerCalls = 0

        fun answer(req: Request): okhttp3.Response {
            if (req.method == "POST") {
                registerCalls++
                return response(req, registerAnswer.second, registerAnswer.first, tlsHandshake = testTlsHandshake)
            }
            val (code, body) = statusAnswers[minOf(statusRequests.size, statusAnswers.lastIndex)]
            statusRequests += req
            return response(req, body, code)
        }
    }

    private fun coordinator(store: FakePushStore, server: Server) = PushSyncCoordinator(
        repository = store,
        registrationClient = NativeRegistrationClient(callFactory = FakeCallFactory(server::answer)),
        wipeOnIncompletePurge = {},
        wipeOwed = { false },
        fetchRegistrationCredential = { PushRegistrationCredential(token = "fcm-token") },
    )

    private suspend fun register(coordinator: PushSyncCoordinator) =
        coordinator.attemptPairing(scanned) as NativeRegistrationResult.Pending

    @Test
    fun pendingThenApprovedCompletesPairing() = runBlocking {
        val store = FakePushStore()
        val server = Server(listOf(202 to waitingBody, 200 to approvedBody), registerAnswer = 202 to pendingBody())
        val coordinator = coordinator(store, server)

        val pending = register(coordinator)
        assertEquals("048213", pending.approvalCode)
        assertEquals(statusUrl, pending.statusEndpoint)
        // Nothing is stored while the request waits.
        assertEquals(emptyList<String>(), store.events)
        assertNull(store.currentPairing())

        val sleeps = mutableListOf<Long>()
        val result = coordinator.awaitApproval(pending, now = { registeredAt }, sleep = { sleeps += it })

        assertTrue(result is NativeRegistrationResult.Success)
        val paired = store.currentPairing()!!
        // The approved response's id wins: the server may have merged the row.
        assertEquals("dev-merged", paired.deviceId)
        assertEquals("pending-secret", paired.deviceSecret)
        assertEquals(DeliveryMode.PULL, store.currentDeliveryMode())
        // Pinned to the 202's leaf BEFORE the pairing is written, as a 200 pairing is.
        assertEquals(listOf("savePin:relay.example.com", "persist:pending-secret"), store.events)
        assertEquals(listOf(3_000L, 3_000L), sleeps)
        server.statusRequests.forEach {
            assertEquals("GET", it.method)
            assertEquals(statusUrl, it.url.toString())
            assertEquals("dev-pending", it.header(HEADER_DEVICE_ID))
            assertEquals("pending-secret", it.header(HEADER_DEVICE_SECRET))
            // The poll is pinned to the leaf the 202 was served with.
            assertEquals("relay.example.com", it.tag(org.kysecurity.mail.LinkPin::class.java)?.host)
        }
    }

    /** Approved on the web while the app sat locked behind the browser: the approval is held until
     *  the PIN-derived key is back, not refused and wiped. */
    @Test
    fun anApprovalWhileLockedCompletesAfterUnlock() = runBlocking {
        val store = FakePushStore()
        val server = Server(listOf(200 to approvedBody), registerAnswer = 202 to pendingBody())
        val coordinator = coordinator(store, server)
        val pending = register(coordinator)
        store.credentialState = PushRepository.PairingCredentialState.Unavailable

        val sleeps = mutableListOf<Long>()
        val result = coordinator.awaitApproval(pending, now = { registeredAt }, sleep = {
            sleeps += it
            if (sleeps.size == 3) store.credentialState = PushRepository.PairingCredentialState.NotGated
        })

        assertTrue(result is NativeRegistrationResult.Success)
        assertEquals("pending-secret", store.currentPairing()?.deviceSecret)
        assertEquals(listOf(3_000L, 1_000L, 1_000L), sleeps)
    }

    @Test
    fun goneReturnsToTheStartWithNothingStored() = runBlocking {
        val store = FakePushStore()
        val server = Server(listOf(410 to rejectedBody), registerAnswer = 202 to pendingBody())
        val coordinator = coordinator(store, server)
        val pending = register(coordinator)

        val result = coordinator.awaitApproval(pending, now = { registeredAt }, sleep = {})

        assertTrue((result as NativeRegistrationResult.Error).notApproved)
        assertEquals(1, server.statusRequests.size)
        assertNull(pending.deviceSecret)
        assertNull(store.currentPairing())
        assertNull(store.storedPin)
        assertEquals(emptyList<String>(), store.events)
    }

    @Test
    fun cancelStopsPollingAndWipesTheCredentials() = runBlocking {
        val store = FakePushStore()
        val server = Server(listOf(202 to waitingBody), registerAnswer = 202 to pendingBody())
        val coordinator = coordinator(store, server)
        val pending = register(coordinator)

        var sleeps = 0
        val parked = CompletableDeferred<Unit>()
        val poll = launch {
            coordinator.awaitApproval(pending, now = { registeredAt }, sleep = {
                if (++sleeps == 3) {
                    parked.complete(Unit)
                    awaitCancellation()
                }
            })
        }
        parked.await()
        poll.cancelAndJoin()

        assertEquals(2, server.statusRequests.size)
        assertNull(pending.deviceSecret)
        assertNull(store.currentPairing())
        assertEquals(emptyList<String>(), store.events)
    }

    @Test
    fun expiryStopsPollingAndWipes() = runBlocking {
        val store = FakePushStore()
        val server = Server(listOf(202 to waitingBody), registerAnswer = 202 to pendingBody())
        val coordinator = coordinator(store, server)
        val pending = register(coordinator)

        var clock = registeredAt
        val sleeps = mutableListOf<Long>()
        val result = coordinator.awaitApproval(pending, now = { clock }, sleep = { sleeps += it; clock += it })

        assertTrue((result as NativeRegistrationResult.Error).notApproved)
        // 5 minutes at 3 s: the last poll lands exactly on expiresAt, then nothing more.
        assertEquals(100, server.statusRequests.size)
        assertEquals(pending.expiresAtEpochMs, clock)
        assertNull(pending.deviceSecret)
        assertNull(store.currentPairing())
    }

    @Test
    fun failedChecksBackOffAndHonourRetryAfter() = runBlocking {
        val store = FakePushStore()
        val server = Server(
            listOf(503 to "", 503 to "", 429 to "", 202 to waitingBody, 200 to approvedBody),
            registerAnswer = 202 to pendingBody(),
        )
        val factory = FakeCallFactory { req ->
            if (server.statusRequests.size == 2 && req.method == "GET") {
                server.statusRequests += req
                response(req, "", 429, headers = mapOf("Retry-After" to "40"))
            } else {
                server.answer(req)
            }
        }
        val coordinator = PushSyncCoordinator(
            repository = store,
            registrationClient = NativeRegistrationClient(callFactory = factory),
            wipeOnIncompletePurge = {},
            wipeOwed = { false },
            fetchRegistrationCredential = { PushRegistrationCredential(token = "fcm-token") },
        )
        val pending = register(coordinator)

        val sleeps = mutableListOf<Long>()
        val result = coordinator.awaitApproval(pending, now = { registeredAt }, sleep = { sleeps += it })

        assertTrue(result is NativeRegistrationResult.Success)
        // 3 s, then doubling after each failure, Retry-After winning when longer, and back to the
        // server's interval once it answers again.
        assertEquals(listOf(3_000L, 6_000L, 12_000L, 40_000L, 3_000L), sleeps)
    }

    @Test
    fun aDirectRegistrationPairsAtOnceAsBefore() = runBlocking {
        val store = FakePushStore()
        val direct = """{"ok":true,"synced":true,"status":"approved","deviceId":"dev-1","deviceSecret":"secret-1","deliveryMode":"push","transport":"fcm"}"""
        val server = Server(emptyList(), registerAnswer = 200 to direct)
        val coordinator = coordinator(store, server)

        val result = coordinator.attemptPairing(scanned)

        assertTrue(result is NativeRegistrationResult.Success)
        assertEquals(1, server.registerCalls)
        assertEquals(0, server.statusRequests.size)
        assertEquals("secret-1", store.currentPairing()?.deviceSecret)
        assertEquals(listOf("savePin:relay.example.com", "persist:secret-1"), store.events)
    }

    @Test
    fun aCrossOriginStatusEndpointIsIgnored() = runBlocking {
        val server = Server(emptyList(), registerAnswer = 202 to pendingBody("https://evil.example/steal"))
        val pending = register(coordinator(FakePushStore(), server))

        assertEquals(statusUrl, pending.statusEndpoint)
    }

    @Test
    fun aPendingAnswerWithoutACodeIsAnError() = runBlocking {
        val noCode = pendingBody().replace("\"approvalCode\":\"048213\",", "")
        val server = Server(emptyList(), registerAnswer = 202 to noCode)

        val result = coordinator(FakePushStore(), server).attemptPairing(scanned)

        assertTrue(result is NativeRegistrationResult.Error)
    }

    @Test
    fun aUsedCodeIsSaidPlainly() = runBlocking {
        val server = Server(emptyList(), registerAnswer = 409 to """{"error":"pairing token already used"}""")

        val result = coordinator(FakePushStore(), server).attemptPairing(scanned) as NativeRegistrationResult.Error

        assertTrue(result.message, result.message.startsWith("This code was already used."))
    }
}
