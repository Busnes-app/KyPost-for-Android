package org.kysecurity.mail.security

import android.os.SystemClock
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

sealed class UnlockAttemptResult {
    object Success : UnlockAttemptResult()
    data class Rejected(val delayMillis: Long) : UnlockAttemptResult()
    object Wiped : UnlockAttemptResult()

    /** Not a wrong PIN: it must not count toward the wipe threshold. */
    object VerifierUnavailable : UnlockAttemptResult()

    /** The wipe ran but a step failed, so data may remain; the UI must not claim it is gone. */
    data class WipeFailed(val failedSteps: List<String>, val willRetry: Boolean) : UnlockAttemptResult()
}

/** In-process lock state only: "locked" is never persisted. [onWipe] is injected for tests. */
class AppLockManager(
    private val state: AppLockState,
    private val elapsedRealtimeMs: () -> Long = SystemClock::elapsedRealtime,
    // Injected so credential-key derivation is exercisable off-device; the default needs a real
    // AndroidKeyStore. See [CredentialPepper].
    private val pepper: CredentialPepper = KeystoreCredentialPepper,
    // Likewise: [BiometricUnlockVault] is the real one, wired in by [SecurityRuntime].
    private val sealer: BiometricKeySealer = NoBiometricSealer,
    private val onWipe: suspend () -> WipeResult,
) {
    private val _locked = MutableStateFlow(state.isLockEnabled())

    /** A security decision must use [isLockedNow]: this flow only moves when [lockNow] runs. */
    val locked: StateFlow<Boolean> = _locked.asStateFlow()

    @Volatile
    private var credentialKeys: CredentialKeys? = null

    /** Serialises every PIN check. Non-reentrant: code under it must call [verifyLocked]. */
    private val pinGate = Mutex()

    /** Grace-window deadline on elapsedRealtime; zero means no lock is pending. */
    @Volatile
    private var lockDeadlineElapsedMs: Long = 0L

    fun lockNow() {
        lockDeadlineElapsedMs = 0L
        if (state.isLockEnabled()) _locked.value = true
        credentialKeys = null
        // Unconditional, like credentialKeys: gating on isLockEnabled() would keep it alive.
        org.kysecurity.mail.pgp.EnrollmentSession.clear()
    }

    /** elapsedRealtime, unlike the Handler's uptimeMillis, advances during deep sleep. */
    fun scheduleLock(deadlineElapsedMs: Long) {
        lockDeadlineElapsedMs = deadlineElapsedMs
    }

    /** Disarms a pending grace window — the app came back to the foreground inside it. */
    fun cancelScheduledLock() {
        lockDeadlineElapsedMs = 0L
    }

    /** What every gate must call: it resolves an expired-but-unfired grace window. */
    fun isLockedNow(): Boolean {
        if (_locked.value) return true
        val deadline = lockDeadlineElapsedMs
        if (deadline != 0L && elapsedRealtimeMs() >= deadline) {
            lockNow()
            return _locked.value
        }
        return false
    }

    /** Takes a [BiometricProof], never bare keys: only [CredentialEnvelope.open] mints one, and it
     *  only does so from a Cipher a strong biometric has already authorized. Caching mirrors
     *  [attemptPin]. */
    fun unlockWithBiometric(proof: BiometricProof): UnlockAttemptResult {
        // Under the same lockout as every PIN check; a fingerprint must not clear the ladder.
        val remaining = remainingLockoutMillis()
        if (remaining > 0) return UnlockAttemptResult.Rejected(remaining)

        cancelScheduledLock()
        _locked.value = false
        state.resetFailedAttempts()
        if (state.isCredentialPinGateEnabled()) credentialKeys = proof.keys
        return UnlockAttemptResult.Success
    }

    /** On [UnlockAttemptResult.Wiped], [onWipe] has already run by the time this returns. */
    suspend fun attemptPin(pin: CharArray): UnlockAttemptResult = withContext(Dispatchers.Default) {
        pinGate.withLock {
            verifyLocked(pin) {
                // Unlock FIRST: a lost wrapping key must not lock out a correct PIN.
                cancelScheduledLock()
                _locked.value = false
                deriveSealAndCache(pin)
            }
        }
    }

    /** The check-verify-account sequence; every public entry point runs it under [pinGate]. */
    private suspend fun verifyLocked(pin: CharArray, onSuccess: () -> Unit): UnlockAttemptResult {
        val remaining = remainingLockoutMillis()
        if (remaining > 0) return UnlockAttemptResult.Rejected(remaining)

        // The verifier itself may be unevaluable, which is not a wrong PIN and must not be counted
        // as one — the `incrementFailedAttempts()` below is what feeds the wipe threshold.
        val verified = try {
            state.verifyPin(pin)
        } catch (e: PepperUnavailableException) {
            android.util.Log.e("AppLockManager", "PIN verifier is unevaluable; refusing to count an attempt", e)
            return UnlockAttemptResult.VerifierUnavailable
        }

        if (verified) {
            state.resetFailedAttempts()
            onSuccess()
            return UnlockAttemptResult.Success
        }

        val attempts = state.incrementFailedAttempts()
        if (LockoutPolicy.shouldWipe(attempts, state.wipeAfterAttempts())) {
            return when (val wipe = onWipe()) {
                is WipeResult.Complete -> UnlockAttemptResult.Wiped
                is WipeResult.Incomplete -> UnlockAttemptResult.WipeFailed(wipe.failedSteps, wipe.willRetry)
            }
        }
        val delay = LockoutPolicy.delayMillisFor(attempts)
        if (delay > 0) state.setLockout(elapsedRealtimeMs() + delay, delay)
        return UnlockAttemptResult.Rejected(delay)
    }

    /** Clamped to the stored duration: the monotonic clock resets to zero on reboot. */
    fun remainingLockoutMillis(): Long {
        val duration = state.lockoutDurationMs()
        if (duration <= 0L) return 0L
        return (state.lockoutUntilElapsedMs() - elapsedRealtimeMs()).coerceIn(0L, duration)
    }

    /** Null while locked — routed through [isLockedNow], since [lockNow] may not have run yet. */
    fun cachedCredentialKeys(): CredentialKeys? {
        if (isLockedNow()) return null
        return credentialKeys
    }

    /** Private constructor plus an issuer check: `internal` alone would not prove anything. */
    class DecisionToken private constructor(
        private val issuer: AppLockManager,
        internal val keys: CredentialKeys?,
    ) {
        internal companion object {
            fun issue(by: AppLockManager, keys: CredentialKeys?) = DecisionToken(by, keys)
        }

        internal fun issuedBy(manager: AppLockManager): Boolean = issuer === manager
    }

    /** PIN-change path only: without it the old PIN's keys stay sealed and stop unwrapping. */
    suspend fun resealForBiometric(pin: CharArray) = withContext(Dispatchers.Default) {
        // Under pinGate: the salt is minted on first use, so concurrent derivations must not race.
        pinGate.withLock {
            // Error, not info: silently, this is "biometric unlock stopped working and nobody was
            // told". The unseal path can recover on the next PIN unlock, but only if someone knows
            // to look, and INFO on a failing security feature is not telling anyone.
            if (state.isBiometricEnabled()) {
                runCatching { sealer.seal(deriveUsingPersistedSalt(pin)) }
                    .onFailure { android.util.Log.e("AppLockManager", "Could not re-seal after a PIN change", it) }
            }
        }
        Unit
    }

    /** Under [pinGate], so a PIN unlock already running cannot seal again after the switch-off.
     *  Switching on seals nothing: the next PIN entry does. Returns what could not be removed. */
    suspend fun setBiometricEnabled(enabled: Boolean): List<String> = withContext(Dispatchers.Default) {
        pinGate.withLock {
            state.setBiometricEnabled(enabled)
            if (enabled) emptyList() else sealer.destroy()
        }
    }

    /** The one gate on a biometric unlock: null while the user has it switched off. Blocking. */
    fun biometricUnlockOnOffer(): BiometricUnlock? =
        if (state.isBiometricEnabled()) sealer.prepareUnlock() else null

    /** Needed when the credential gate is switched off, or a later pairing re-wraps behind it. */
    fun dropCredentialKeys() {
        credentialKeys = null
    }

    /** Every PIN check must come through here or [attemptPin]; direct verifyPin is unthrottled. */
    suspend fun verifyPinThrottled(pin: CharArray): UnlockAttemptResult = withContext(Dispatchers.Default) {
        pinGate.withLock { verifyLocked(pin) {} }
    }

    /** Deliberately not an unlock: a notification tap must not open the mailbox. */
    suspend fun verifyPinForDecision(
        pin: CharArray,
        deriveKeys: Boolean,
    ): Pair<UnlockAttemptResult, DecisionToken?> = withContext(Dispatchers.Default) {
        pinGate.withLock {
            var token: DecisionToken? = null
            var derivationFailed = false
            val result = verifyLocked(pin) {
                if (!deriveKeys) {
                    token = DecisionToken.issue(this@AppLockManager, null)
                    return@verifyLocked
                }
                val keys = try {
                    deriveUsingPersistedSalt(pin)
                } catch (e: PepperUnavailableException) {
                    android.util.Log.e("AppLockManager", "Credential key derivation is unavailable", e)
                    derivationFailed = true
                    null
                }
                if (keys != null) token = DecisionToken.issue(this@AppLockManager, keys)
            }
            if (result is UnlockAttemptResult.Success && derivationFailed) {
                UnlockAttemptResult.VerifierUnavailable to null
            } else {
                result to token
            }
        }
    }

    /** Keys the token carries, or null when none were needed. Throws if issued elsewhere. */
    fun keysFor(token: DecisionToken): CredentialKeys? {
        require(token.issuedBy(this)) { "DecisionToken was not issued by this AppLockManager" }
        return token.keys
    }

    /** Derives regardless of the gate, but only after [pin] verifies against the stored hash. */
    suspend fun deriveAndCacheCredentialKeys(pin: CharArray): UnlockAttemptResult = withContext(Dispatchers.Default) {
        // Throttled like every other PIN check; the settings screen is a reachable oracle.
        pinGate.withLock {
            // The caller asked for the key, so a failed derivation must be reported.
            var derivationFailed = false
            val result = verifyLocked(pin) {
                credentialKeys = try {
                    deriveUsingPersistedSalt(pin)
                } catch (e: PepperUnavailableException) {
                    android.util.Log.e("AppLockManager", "Credential key derivation is unavailable", e)
                    derivationFailed = true
                    null
                }
            }
            if (result is UnlockAttemptResult.Success && derivationFailed) {
                UnlockAttemptResult.VerifierUnavailable
            } else {
                result
            }
        }
    }

    /** Derives unconditionally and is best-effort: a failure must not fail the unlock. */
    private fun deriveSealAndCache(pin: CharArray) {
        val biometric = state.isBiometricEnabled()
        // Off means nothing sealed, including a blob an earlier build sealed regardless.
        if (!biometric) sealer.destroy()
        val keys = runCatching { deriveUsingPersistedSalt(pin) }
            .onFailure { android.util.Log.e("AppLockManager", "Could not derive credential keys on unlock", it) }
            .getOrNull() ?: return
        // Never fails the unlock: a device with no biometric enrolled has nowhere to seal to, which
        // is not an error, it is that user's normal.
        if (biometric) {
            runCatching { sealer.seal(keys) }
                .onFailure { android.util.Log.i("AppLockManager", "Could not seal keys for biometric unlock", it) }
        }
        if (state.isCredentialPinGateEnabled()) credentialKeys = keys
    }

    private fun deriveUsingPersistedSalt(pin: CharArray): CredentialKeys {
        // Create-on-demand suits the wrapping key, not the verifier; hence separate aliases.
        if (pepper === KeystoreCredentialPepper) KeystoreCredentialPepper.ensureExists()
        // The returned salt is the persisted one, which may be another store's mint rather than
        // this candidate — deriving from the candidate would key the secret to a salt on nobody's disk.
        val salt = state.putCredentialSaltIfAbsent(CredentialCipher.randomSalt())
        return CredentialCipher.deriveKeys(pin, salt, pepper)
    }
}
