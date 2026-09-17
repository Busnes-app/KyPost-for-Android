package org.kysecurity.mail.pgp

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

/** The code's validity window, and the browser's. `deviceEnrollmentCode`'s bucket is
 *  `unixSeconds / 120`; changing this alone strands every honest enrollment. */
private const val BUCKET_SECONDS = 120L

/** How often the phone asks whether the browser has sealed yet. There is no browser-to-device
 *  channel — the publish step is device-to-server POST only — so polling is the only discovery
 *  mechanism this protocol has. */
private const val POLL_INTERVAL_MS = 3_000L

/** One polling window. Bounded: the tail needs a live BiometricPrompt and the user present. */
private const val POLL_WINDOW_MS = 5 * 60 * 1_000L

/** The device-enrollment state machine. No Android imports, and none may be added. */
internal class EnrollmentCeremony(
    private val identity: IdentitySource,
    private val transport: EnrollmentTransport,
    private val keys: EnrollmentKeys,
    private val sealer: VaultSealer,
    private val previousVault: VaultOpener,
    private val mailCache: DecryptedMailCache,
    private val clock: EnrollmentClock,
    private val hostileLocationEnabled: () -> Boolean,
    private val hasSecureLockScreen: () -> Boolean,
    private val onState: (EnrollmentUiState) -> Unit,
) {

    private var deviceId: String? = null
    private var fingerprint: String? = null

    /** Set once a keypair exists, so [teardown] knows whether there is anything to destroy and
     *  cannot report a deletion it never performed. */
    private var keyPairLive = false

    private fun emit(state: EnrollmentUiState) = onState(state)

    /** True whenever no polling window is running; the Activity offers "Check again" on this. */
    var isIdle: Boolean = true
        private set

    suspend fun run() {
        isIdle = false
        try {
            runInner()
        } finally {
            isIdle = true
        }
    }

    private suspend fun runInner() {
        emit(EnrollmentUiState.CheckingIdentity)

        // Local declarations first, and in this order. Hostile Location Protection means the user
        // has just said this network is hostile, so answering it must not require a request to a
        // server on that network.
        if (hostileLocationEnabled()) {
            emit(EnrollmentUiState.Unavailable(UnavailableReason.HOSTILE_LOCATION))
            return
        }
        if (!hasSecureLockScreen()) {
            emit(EnrollmentUiState.Unavailable(UnavailableReason.NO_SECURE_LOCK_SCREEN))
            return
        }

        val id = transport.deviceId()
        if (id.isNullOrBlank()) {
            emit(EnrollmentUiState.Unavailable(UnavailableReason.NOT_PAIRED))
            return
        }
        deviceId = id

        when (val check = identity.check()) {
            is IdentityCheck.ClientProtected -> fingerprint = check.fingerprint
            IdentityCheck.ServerHeld -> {
                emit(EnrollmentUiState.Unavailable(UnavailableReason.SERVER_HELD_KEY))
                return
            }
            IdentityCheck.NoIdentity -> {
                emit(EnrollmentUiState.Unavailable(UnavailableReason.NO_IDENTITY))
                return
            }
            IdentityCheck.CouldNotCheck -> {
                emit(EnrollmentUiState.Unavailable(UnavailableReason.COULD_NOT_CHECK))
                return
            }
        }

        publishAndPoll()
    }

    /** The code currently on screen, so [checkAgain] can resume without re-deriving from a bucket
     *  that has since moved — and so [EnrollmentUiState.WaitingTimedOut] can carry it. */
    private var shownCode: String = ""
    private var shownExpiresAtEpochMs: Long = 0L
    private var shownBucket: Long = Long.MIN_VALUE

    private suspend fun publishAndPoll() {
        emit(EnrollmentUiState.PublishingKey)

        // Mints a FRESH keypair, destroying any previous one. A key that outlives a ceremony is a
        // standing unauthenticated path to every envelope the relay has retained.
        keyPairLive = true
        if (!keys.newKeyPair()) {
            failAndDestroy(FailureReason.NO_DEVICE_KEY)
            return
        }

        val encoded = keys.encodedPublicKey()
        if (encoded == null) {
            failAndDestroy(FailureReason.NO_DEVICE_KEY)
            return
        }

        when (transport.publishKey(encoded)) {
            is EnrollmentCallResult.Ok -> Unit
            is EnrollmentCallResult.Unauthorized -> return failAndDestroy(FailureReason.UNAUTHORIZED)
            is EnrollmentCallResult.RateLimited -> return failAndDestroy(FailureReason.RATE_LIMITED)
            // NotFound (the device row is gone), Failed, and an Envelope this route cannot send.
            // None is retryable, and all leave a minted key that must not survive.
            is EnrollmentCallResult.NotFound,
            is EnrollmentCallResult.Failed,
            is EnrollmentCallResult.Envelope,
            is EnrollmentCallResult.Conflict,
            -> return failAndDestroy(FailureReason.PUBLISH_REJECTED)
        }

        poll()
    }

    /** Reopens a five-minute window against the **same** keypair: rotating would kill the code. */
    suspend fun checkAgain() {
        if (!keyPairLive) return
        isIdle = false
        try {
            poll()
        } finally {
            isIdle = true
        }
    }

    private suspend fun poll() {
        // Every window opens on a freshly derived code: a stale one fires this feature's one alarm.
        shownBucket = Long.MIN_VALUE

        val deadline = clock.elapsedRealtimeMs() + POLL_WINDOW_MS

        while (clock.elapsedRealtimeMs() < deadline) {
            val bucket = clock.epochSeconds() / BUCKET_SECONDS
            if (bucket != shownBucket) {
                // Re-read from the keystore on every recomputation rather than caching the point.
                // The code must describe the key material actually in hand.
                val raw = keys.rawPublicKey()
                if (raw == null) {
                    failAndDestroy(FailureReason.NO_DEVICE_KEY)
                    return
                }
                shownBucket = bucket
                shownCode = deviceEnrollmentCode(raw, requireNotNull(deviceId), bucket)
                shownExpiresAtEpochMs = (bucket + 1) * BUCKET_SECONDS * 1_000L
                emit(EnrollmentUiState.ShowingCode(shownCode, shownExpiresAtEpochMs))
            }

            when (val result = transport.fetchEnvelope()) {
                is EnrollmentCallResult.Envelope -> {
                    openAndSeal(result.envelope)
                    return
                }
                // 401 is the one polling answer that cannot improve: the credential this device
                // holds is not accepted, and no amount of waiting changes that.
                is EnrollmentCallResult.Unauthorized -> return failAndDestroy(FailureReason.UNAUTHORIZED)
                // 404 covers "never sealed" and "expired": keep waiting. 429 and drops are not teardown reasons.
                is EnrollmentCallResult.NotFound,
                is EnrollmentCallResult.RateLimited,
                is EnrollmentCallResult.Failed,
                is EnrollmentCallResult.Ok,
                is EnrollmentCallResult.Conflict,
                -> Unit
            }

            clock.sleep(POLL_INTERVAL_MS)
        }

        // The one exit that KEEPS the keypair — "Check again" resumes against it.
        emit(EnrollmentUiState.WaitingTimedOut(shownCode, shownExpiresAtEpochMs))
    }

    private fun failAndDestroy(reason: FailureReason) {
        teardown()
        emit(EnrollmentUiState.Failed(reason))
    }

    private suspend fun openAndSeal(envelopeJson: String) {
        emit(EnrollmentUiState.Opening)

        // Live enrollment is legacy-only until the server publishes capability, generation and
        // acknowledgement contracts; a v3 envelope is malformed here, not opened under v2.
        val fields = parseDeviceEnvelope(envelopeJson, setOf(ENVELOPE_VERSION_LEGACY))
        if (fields == null) {
            failAndDestroy(FailureReason.ENVELOPE_MALFORMED)
            return
        }

        // The AAD comes from this device's id and the checked fingerprint — never from the envelope.
        val aad = runCatching {
            deviceEnvelopeAad(fields.version, requireNotNull(deviceId), requireNotNull(fingerprint))
        }.getOrNull()
        if (aad == null) {
            failAndDestroy(FailureReason.ENVELOPE_MALFORMED)
            return
        }

        val ownPoint = keys.rawPublicKey()
        if (ownPoint == null) {
            failAndDestroy(FailureReason.NO_DEVICE_KEY)
            return
        }

        val sharedSecret = keys.sharedSecret(fields.epk)
        if (sharedSecret == null) {
            // The ECDH itself failed — a malformed peer point that got past the parse, or a key the
            // Keystore will no longer agree with. Indistinguishable from a hostile envelope from
            // here, and treated the same: no retry.
            failAndDestroy(FailureReason.COULD_NOT_OPEN)
            return
        }

        val plaintext = try {
            // ownPoint is the HKDF salt — this device's own point, not the ephemeral one in the
            // envelope.
            openDeviceEnvelope(sharedSecret, ownPoint, fields, aad)
        } finally {
            sharedSecret.fill(0)
        }
        if (plaintext == null) {
            failAndDestroy(FailureReason.COULD_NOT_OPEN)
            return
        }

        try {
            sealAndReport(plaintext)
        } finally {
            // The armored private key, zeroed in place on every path out — including the throw the
            // sealer is not supposed to produce. It never enters EnrollmentSession: that holder has
            // no reader until the deferred decryption work lands.
            plaintext.fill(0)
        }
    }

    private suspend fun sealAndReport(plaintext: ByteArray) {
        emit(EnrollmentUiState.AwaitingAuth)

        // Re-checked here as well as at the gate: the user can remove the lock screen between the
        // two, and EnrollmentVault.ensureKey() would then fail behind a prompt that never appears.
        if (!hasSecureLockScreen()) {
            failAndDestroy(FailureReason.NO_SECURE_LOCK_SCREEN)
            return
        }

        val hadPrevious = EnrollmentSession.isHeld()
        val openOutcome = if (hadPrevious) OpenOutcome.Opened else try {
            previousVault.open()
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            OpenOutcome.Failed("The existing vault could not be opened")
        }

        val previousExpected = when (openOutcome) {
            OpenOutcome.Opened -> true
            OpenOutcome.NotEnrolled -> false
            OpenOutcome.Cancelled -> {
                emit(EnrollmentUiState.ReadyToFinish)
                return
            }
            is OpenOutcome.Failed -> {
                failAndDestroy(FailureReason.SEAL_FAILED)
                return
            }
            OpenOutcome.NoSecureLockScreen -> {
                failAndDestroy(FailureReason.NO_SECURE_LOCK_SCREEN)
                return
            }
        }

        var toSeal: ByteArray? = null
        try {
            toSeal = if (previousExpected) {
                EnrollmentSession.withLegacyArmor { previous -> mergeSecretKeyRings(plaintext, previous) }
            } else {
                plaintext
            }
            if (toSeal == null) {
                failAndDestroy(FailureReason.SEAL_FAILED)
                return
            }

            // NonCancellable around this call only: a cancel here would zero plaintext mid-read on the sealer.
            when (withContext(NonCancellable) { sealer.seal(toSeal, VaultRecordKind.LEGACY_ARMOR) }) {
                is SealOutcome.Sealed -> {
                    // Sealed and durable by now; zero before cache deletion or report's network round trip.
                    plaintext.fill(0)
                    if (toSeal !== plaintext) toSeal.fill(0)
                    EnrollmentSession.clear()
                    mailCache.clearServerDecryptedBodies()
                    report()
                }
                is SealOutcome.NoSecureLockScreen -> failAndDestroy(FailureReason.NO_SECURE_LOCK_SCREEN)
                is SealOutcome.Failed -> failAndDestroy(FailureReason.SEAL_FAILED)
                is SealOutcome.Cancelled ->
                    // NOT back to the code: it would go stale with no window to refresh it. The envelope waits 7 days.
                    emit(EnrollmentUiState.ReadyToFinish)
            }
        } finally {
            plaintext.fill(0)
            if (toSeal !== plaintext) toSeal?.fill(0)
        }
    }

    /** Tells the server this device is enrolled. A failed report is not a failed enrollment. */
    private suspend fun report() {
        if (transport.report(EnrollmentReport.Legacy) !is EnrollmentCallResult.Ok) {
            transport.enqueueDurableReport()
        }
        teardown()
        emit(EnrollmentUiState.Enrolled)
    }

    /** Destroys the agreement key, whatever state the ceremony was in. Idempotent. */
    fun teardown() {
        if (!keyPairLive) return
        keys.deleteKeyPair()
        keyPairLive = false
    }
}
