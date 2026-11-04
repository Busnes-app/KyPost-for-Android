package org.kysecurity.mail.push

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [isAccountReplacement] answers one question for two callers: [PushSyncCoordinator.attemptPairing]
 * purges on it, and the pairing confirmation dialog warns on it. That is the point of it being a
 * single function — split, the warning drifts from what actually happens, and the drift is silent
 * because nothing about a string resource fails a build.
 *
 * `PushPairingActivity.confirmAndApplyPairing` used to or-in `isPairedNow()`, which made an
 * ordinary re-pair of the SAME account take the replace branch: the user was told another account's
 * mail and contacts were about to be erased while `attemptPairing` purged nothing. These are the
 * cases that predicate has to get right for both callers.
 */
class PairingReplacementTest {

    private val current = PairingData(
        subscriberId = "sub-1",
        serverUrl = "https://relay.example.com",
        registrationUrl = "https://relay.example.com/api/notifications/native/register",
        pairingToken = "tok-1",
        deviceId = "dev-1",
        deviceSecret = "secret-1",
        pairedAtEpochMs = 0L,
    )

    /** The same account pairing again: a new token and a fresh device secret, nothing else moved. */
    private val sameAccountAgain = current.copy(pairingToken = "tok-2", deviceId = null, deviceSecret = null)

    @Test
    fun rePairingTheSameAccountIsNotAReplacement() {
        assertFalse(isAccountReplacement(sameAccountAgain, current, reconnect = null))
    }

    @Test
    fun aDifferentSubscriberIsAReplacement() {
        assertTrue(isAccountReplacement(current.copy(subscriberId = "sub-2"), current, reconnect = null))
    }

    @Test
    fun aDifferentServerIsAReplacement() {
        val elsewhere = current.copy(
            serverUrl = "https://other.example.com",
            registrationUrl = "https://other.example.com/api/notifications/native/register",
        )
        assertTrue(isAccountReplacement(elsewhere, current, reconnect = null))
    }

    /** Nothing paired and nothing left behind: a first-ever pairing must not purge or warn. */
    @Test
    fun aFirstEverPairingIsNotAReplacement() {
        assertFalse(isAccountReplacement(current, current = null, reconnect = null))
    }

    /** After a reconnect there is no pairing, but the mailbox is still here and the marker names
     *  whose it is — the whole reason the marker outlives the credential. */
    @Test
    fun afterAReconnectTheMarkerDecides() {
        val marker = ReconnectExpectation(current.subscriberId, current.serverUrl)
        assertFalse(isAccountReplacement(sameAccountAgain, current = null, reconnect = marker))
        assertTrue(
            isAccountReplacement(current.copy(subscriberId = "sub-2"), current = null, reconnect = marker),
        )
    }

    /** An install predating the marker has a live pairing and no marker, so the pairing wins and a
     *  stale marker can never contradict the account that is actually active. */
    @Test
    fun aLivePairingOutranksTheMarker() {
        val staleMarker = ReconnectExpectation("sub-stale", "https://stale.example.com")
        assertFalse(isAccountReplacement(sameAccountAgain, current, reconnect = staleMarker))
    }

    /** Owner decision (2026-11-04): a same-account link with a key this device has not pinned is a
     *  re-pin, and the confirm screen must say the certificate changed. */
    @Test
    fun aSameAccountLinkWithANewKeyIsARepin() {
        val stored = TlsPin("relay.example.com", setOf("sha256/old"))
        val renewed = sameAccountAgain.copy(spkiPin = "sha256/new")

        assertTrue(isRepin(renewed, stored, replacesAccount = false))
        assertFalse("same key", isRepin(sameAccountAgain.copy(spkiPin = "sha256/old"), stored, replacesAccount = false))
        assertFalse("no link pin", isRepin(sameAccountAgain, stored, replacesAccount = false))
        assertFalse("nothing pinned yet", isRepin(renewed, storedPin = null, replacesAccount = false))
        assertFalse("a replacement drops the link pin", isRepin(renewed, stored, replacesAccount = true))
    }
}
