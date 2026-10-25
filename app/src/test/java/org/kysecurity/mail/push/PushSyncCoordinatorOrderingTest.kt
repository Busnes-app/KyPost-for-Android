package org.kysecurity.mail.push

import org.kysecurity.mail.testing.FakeCallFactory
import org.kysecurity.mail.testing.response
import org.kysecurity.mail.testing.testTlsHandshake
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import okhttp3.Request
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.BrokenBarrierException
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * The rules that make registration survive being triggered from five places at once.
 *
 * Every successful registration mints a `deviceSecret` and invalidates the previous one, and an
 * account replacement destroys the previous account's data. Both are one-way, so both depend
 * entirely on ORDER — which is what these pin down.
 */
class PushSyncCoordinatorOrderingTest {

    private val existing = PairingData(
        subscriberId = "sub-old",
        serverUrl = "https://old.example.com",
        registrationUrl = "https://old.example.com/api/notifications/native/register",
        pairingToken = "tok-old",
        deviceId = "dev-old",
        deviceSecret = "secret-old",
        pairedAtEpochMs = 0L,
    )

    private val replacement = existing.copy(
        subscriberId = "sub-new",
        serverUrl = "https://new.example.com",
        registrationUrl = "https://new.example.com/api/notifications/native/register",
        pairingToken = "tok-new",
        deviceId = null,
        deviceSecret = null,
    )

    private fun body(secret: String) =
        """{"ok":true,"synced":true,"deviceId":"dev-1","deviceSecret":"$secret"}"""

    private fun coordinator(
        store: FakePushStore,
        responder: (Request) -> okhttp3.Response,
        token: suspend () -> String? = { "fcm-token" },
        // These tests are about registration ordering, not about which transport a build uses;
        // the credential wrapper keeps them expressed in the token they actually care about.
        onWipe: suspend (List<String>) -> Unit = {},
        wipeOwed: () -> Boolean = { false },
    ) = PushSyncCoordinator(
        repository = store,
        registrationClient = NativeRegistrationClient(callFactory = FakeCallFactory(responder)),
        wipeOnIncompletePurge = onWipe,
        wipeOwed = wipeOwed,
        fetchRegistrationCredential = { token()?.let { PushRegistrationCredential(token = it) } },
    )

    /** Two registrations in flight at once used to interleave as register-A, register-B,
     *  persist-B, persist-A, leaving the install holding a secret the relay had already
     *  invalidated. The gate makes each register/persist pair atomic. */
    @Test
    fun registrationsNeverInterleave() = runBlocking {
        val store = FakePushStore(pairing = existing)
        val nth = AtomicInteger(0)
        // Two parties: the barrier trips ONLY if both registrations are in flight together. It is
        // never awaited more than the timeout, so the serialized case simply breaks it and moves on.
        val overlapProbe = CyclicBarrier(2)
        val overlapped = AtomicBoolean(false)

        val coordinator = coordinator(store, { req ->
            val n = nth.incrementAndGet()
            store.events += "register:secret-$n"
            runCatching { overlapProbe.await(500, TimeUnit.MILLISECONDS) }
                .onSuccess { overlapped.set(true) }
                .onFailure { if (it !is BrokenBarrierException && it !is java.util.concurrent.TimeoutException) throw it }
            response(req, body("secret-$n"), 200)
        })

        listOf(
            async(Dispatchers.IO) { coordinator.syncProvidedToken("token-a") },
            async(Dispatchers.IO) { coordinator.syncProvidedToken("token-b") },
        ).awaitAll()

        assertTrue("two registrations were in flight at once", !overlapped.get())
        val events = store.events.toList()
        assertEquals(listOf("register:secret-1", "persist:secret-1", "register:secret-2", "persist:secret-2"), events)
    }

    /** The reviewer's exact scenario: a valid replacement QR confirmed while offline. The old
     *  account used to be deleted before the token fetch that then failed. */
    @Test
    fun aReplacementThatCannotEvenFetchATokenDestroysNothing() = runBlocking {
        val store = FakePushStore(pairing = existing)
        val coordinator = coordinator(store, { req -> response(req, body("secret-new"), 200) }, token = { null })

        val result = coordinator.attemptPairing(replacement)

        assertTrue(result is NativeRegistrationResult.Error)
        assertEquals(emptyList<String>(), store.events)
        assertEquals(existing, store.currentPairing())
    }

    /** Same rule one step later: the network call itself is what fails. */
    @Test
    fun aReplacementThatFailsToRegisterDestroysNothing() = runBlocking {
        val store = FakePushStore(pairing = existing)
        val coordinator = coordinator(store, { req -> response(req, """{"error":"nope"}""", 401) })

        val result = coordinator.attemptPairing(replacement)

        assertTrue(result is NativeRegistrationResult.Error)
        assertEquals(emptyList<String>(), store.events)
        assertEquals(existing, store.currentPairing())
    }

    /** A purge that cannot prove the previous account is gone must not activate the next one:
     *  no table carries a subscriber column, so survivors are readable by whoever pairs next. */
    @Test
    fun anIncompletePurgeRefusesTheNewAccountAndWipes() = runBlocking {
        val store = FakePushStore(pairing = existing, purgeResidue = listOf("database"))
        var wipedWith: List<String>? = null
        val coordinator = coordinator(
            store,
            { req -> response(req, body("secret-new"), 200) },
            onWipe = { wipedWith = it },
        )

        val result = coordinator.attemptPairing(replacement)

        assertTrue(result is NativeRegistrationResult.Error)
        assertEquals(listOf("database"), wipedWith)
        // clearPairing was attempted; nothing of the new account was persisted after it.
        assertEquals(listOf("clearPairing"), store.events)
        assertNull(store.currentPairing()?.deviceSecret?.takeIf { it == "secret-new" })
    }

    /** The successful replacement, in the only safe order. */
    @Test
    fun aProvenReplacementPurgesThenActivates() = runBlocking {
        val store = FakePushStore(pairing = existing)
        val coordinator = coordinator(store, { req -> response(req, body("secret-new"), 200) })

        val result = coordinator.attemptPairing(replacement)

        assertTrue(result is NativeRegistrationResult.Success)
        // No savePin: a fake Call.Factory has no handshake, so there is no chain to pin. The
        // order is the assertion — the purge lands only after the registration succeeded.
        assertEquals(listOf("clearPairing", "persist:secret-new"), store.events)
    }

    /** Not a replacement: same account, so the mailbox is never touched. */
    @Test
    fun rePairingTheSameAccountDoesNotPurge() = runBlocking {
        val store = FakePushStore(pairing = existing)
        val coordinator = coordinator(store, { req -> response(req, body("secret-again"), 200) })

        coordinator.attemptPairing(existing)

        assertTrue("clearPairing" !in store.events)
        assertEquals("secret-again", store.currentPairing()?.deviceSecret)
    }

    /** `reconnectToServer` clears the pairing and deliberately KEEPS the mailbox, so "no pairing"
     *  must not read as "no account here". It used to: the replacement branch was skipped, and a
     *  QR for a different account activated over the previous one's mail, synced address book,
     *  device-contact rows, pending contact changes and sealed PGP vault. */
    @Test
    fun pairingADifferentAccountAfterAReconnectStillPurges() = runBlocking {
        val store = FakePushStore(
            pairing = null,
            reconnectMarker = ReconnectExpectation(existing.subscriberId, existing.serverUrl),
        )
        val coordinator = coordinator(store, { req -> response(req, body("secret-new"), 200) })

        val result = coordinator.attemptPairing(replacement)

        assertTrue(result is NativeRegistrationResult.Success)
        assertEquals(listOf("clearPairing", "persist:secret-new"), store.events)
    }

    /** Either half of the marker is enough: the same subscriber id on a DIFFERENT relay is still a
     *  different account, and the surviving mailbox belongs to neither one by default. */
    @Test
    fun pairingTheSameSubscriberOnAnotherServerAfterAReconnectPurges() = runBlocking {
        val store = FakePushStore(
            pairing = null,
            reconnectMarker = ReconnectExpectation(existing.subscriberId, existing.serverUrl),
        )
        val elsewhere = replacement.copy(subscriberId = existing.subscriberId)
        val coordinator = coordinator(store, { req -> response(req, body("secret-new"), 200) })

        coordinator.attemptPairing(elsewhere)

        assertEquals(listOf("clearPairing", "persist:secret-new"), store.events)
    }

    /** And the escalation reaches that path too, rather than only the still-paired one. */
    @Test
    fun anIncompletePurgeAfterAReconnectAlsoRefusesAndWipes() = runBlocking {
        val store = FakePushStore(
            pairing = null,
            purgeResidue = listOf("database"),
            reconnectMarker = ReconnectExpectation(existing.subscriberId, existing.serverUrl),
        )
        var wipedWith: List<String>? = null
        val coordinator = coordinator(
            store,
            { req -> response(req, body("secret-new"), 200) },
            onWipe = { wipedWith = it },
        )

        val result = coordinator.attemptPairing(replacement)

        assertTrue(result is NativeRegistrationResult.Error)
        assertEquals(listOf("database"), wipedWith)
        assertEquals(listOf("clearPairing"), store.events)
    }

    /** The reconnect's own happy path: the same account comes back, keeps its mail, and spends the
     *  marker, which the restored pairing has made redundant. */
    @Test
    fun reconnectingTheSameAccountKeepsTheMailboxAndSpendsTheMarker() = runBlocking {
        val store = FakePushStore(
            pairing = null,
            reconnectMarker = ReconnectExpectation(existing.subscriberId, existing.serverUrl),
        )
        val coordinator = coordinator(store, { req -> response(req, body("secret-again"), 200) })

        coordinator.attemptPairing(existing)

        assertTrue("clearPairing" !in store.events)
        assertEquals("secret-again", store.currentPairing()?.deviceSecret)
        assertNull(store.reconnectMarker)
    }

    /** An interrupted wipe is owed a resume that erases whatever is paired at the next cold start.
     *  A pairing attempted while one is owed must be refused before anything is registered or
     *  persisted, leaving the existing account untouched (issue #250). */
    @Test
    fun aPairingIsRefusedWhileAWipeIsOwed() = runBlocking {
        val store = FakePushStore(pairing = existing)
        val coordinator = coordinator(
            store,
            { _ -> throw AssertionError("registration must not be attempted while a wipe is owed") },
            wipeOwed = { true },
        )

        val result = coordinator.attemptPairing(replacement)

        assertTrue(result is NativeRegistrationResult.Error)
        assertTrue((result as NativeRegistrationResult.Error).wipeOwed)
        assertEquals(emptyList<String>(), store.events)
        assertEquals(existing, store.currentPairing())
    }

    /** The marker must not be able to strand a fresh install: nothing stored, nothing purged. */
    @Test
    fun aFirstEverPairingPurgesNothing() = runBlocking {
        val store = FakePushStore(pairing = null)
        val coordinator = coordinator(store, { req -> response(req, body("secret-first"), 200) })

        val result = coordinator.attemptPairing(replacement)

        assertTrue(result is NativeRegistrationResult.Success)
        assertEquals(listOf("persist:secret-first"), store.events)
    }

    /** The pin lands BEFORE the pairing it protects. Reversed, a process death between the two
     *  writes leaves a pairing with no pin and no tripwire — which `tlsPinState()` reads as
     *  NeverPaired, the legitimate TOFU window — so every credentialed call goes out on plain
     *  system trust, carrying the device secret, until some later resync happens to repair it. */
    @Test
    fun theTlsPinIsPersistedBeforeThePairingItProtects() = runBlocking {
        val store = FakePushStore(pairing = null)
        val coordinator = coordinator(store, { req ->
            response(req, body("secret-new"), 200, tlsHandshake = testTlsHandshake)
        })

        val result = coordinator.attemptPairing(replacement)

        assertTrue(result is NativeRegistrationResult.Success)
        assertEquals(listOf("savePin:new.example.com", "persist:secret-new"), store.events)
    }
}
