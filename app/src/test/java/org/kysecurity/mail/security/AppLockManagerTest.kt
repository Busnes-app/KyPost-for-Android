package org.kysecurity.mail.security

import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.test.assertFailsWith

/** In-memory [AppLockState] test double — lets [AppLockManager] be unit-tested without a real
 *  Context/Keystore, matching how [AppLockStore] backs the real interface. */
private class FakeAppLockState(
    private var lockEnabled: Boolean = true,
    private var pin: CharArray? = "482913".toCharArray(),
    private var credentialSalt: ByteArray? = null,
    /** Simulates the Keystore pepper behind the stored verifier having gone away, which makes
     *  [verifyPin] unevaluable rather than false. See [PepperUnavailableException]. */
    var verifierUnavailable: Boolean = false,
) : AppLockState {
    private var biometricEnabled = false
    private var credentialGateEnabled = false
    var failedAttempts = 0
        private set
    private var lockoutUntilElapsed = 0L
    private var lockoutDuration = 0L

    override fun isLockEnabled() = lockEnabled
    override fun enableLock() { lockEnabled = true }
    override fun isBiometricEnabled() = biometricEnabled
    override fun setBiometricEnabled(enabled: Boolean) { biometricEnabled = enabled }
    override fun isCredentialPinGateEnabled() = credentialGateEnabled
    override fun setCredentialPinGateEnabled(enabled: Boolean) { credentialGateEnabled = enabled }
    override fun setPin(pin: CharArray) { this.pin = pin }
    override fun verifyPin(pin: CharArray): Boolean {
        if (verifierUnavailable) throw PepperUnavailableException("test-alias")
        return this.pin.contentEquals(pin)
    }
    override fun hasPin() = pin != null
    override fun incrementFailedAttempts(): Int { failedAttempts++; return failedAttempts }
    override fun resetFailedAttempts() { failedAttempts = 0; lockoutUntilElapsed = 0L; lockoutDuration = 0L }
    override fun lockoutUntilElapsedMs() = lockoutUntilElapsed
    override fun lockoutDurationMs() = lockoutDuration
    override fun setLockout(untilElapsedMs: Long, durationMs: Long) {
        lockoutUntilElapsed = untilElapsedMs
        lockoutDuration = durationMs
    }
    private var wipeThreshold: Int? = LockoutPolicy.DEFAULT_WIPE_THRESHOLD
    override fun wipeAfterAttempts() = wipeThreshold
    override fun setWipeAfterAttempts(attempts: Int?) { wipeThreshold = attempts }
    override fun credentialSalt() = credentialSalt
    override fun putCredentialSaltIfAbsent(candidate: ByteArray): ByteArray =
        credentialSalt ?: candidate.also { credentialSalt = it }
    override fun reset() {
        lockEnabled = false; pin = null; biometricEnabled = false; credentialGateEnabled = false
        failedAttempts = 0; lockoutUntilElapsed = 0L; lockoutDuration = 0L
    }
}

/** JVM tests have no AndroidKeyStore, so credential-key derivation gets a fixed pepper. */
private object TestPepper : CredentialPepper {
    override fun mix(derived: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec("test-pepper".toByteArray(), "HmacSHA256"))
        return mac.doFinal(derived)
    }
}

/** Stands in for [BiometricUnlockVault], which needs an AndroidKeyStore. Records what a PIN
 *  unlock handed over to be sealed. */
private class FakeSealer : BiometricKeySealer {
    var sealed: CredentialKeys? = null
    override fun seal(keys: CredentialKeys) { sealed = keys }
    override fun prepareUnlock(): BiometricUnlock? =
        sealed?.let { BiometricUnlock(javax.crypto.Cipher.getInstance("AES/GCM/NoPadding"), ByteArray(1)) }
    override fun destroy(): List<String> { sealed = null; return emptyList() }
}

class AppLockManagerTest {
    private lateinit var state: FakeAppLockState
    private var wipeCount = 0
    private var wipeResult: WipeResult = WipeResult.Complete
    private var clock = 1_000L
    private lateinit var sealer: FakeSealer
    private lateinit var manager: AppLockManager

    private fun newManager(withState: FakeAppLockState = state) = AppLockManager(
        state = withState,
        elapsedRealtimeMs = { clock },
        pepper = TestPepper,
        sealer = sealer,
        onWipe = { wipeCount++; wipeResult },
    )

    @Before
    fun setUp() {
        state = FakeAppLockState()
        wipeCount = 0
        wipeResult = WipeResult.Complete
        clock = 1_000L
        sealer = FakeSealer()
        manager = newManager()
    }

    @Test
    fun locked_startsTrue_whenLockEnabled() {
        assertTrue(manager.locked.value)
    }

    @Test
    fun locked_startsFalse_whenLockDisabled() {
        assertFalse(newManager(FakeAppLockState(lockEnabled = false)).locked.value)
    }

    @Test
    fun attemptPin_withCorrectPin_unlocksAndResetsAttempts() = runBlocking {
        assertEquals(UnlockAttemptResult.Success, manager.attemptPin("482913".toCharArray()))
        assertFalse(manager.locked.value)
        assertEquals(0, state.failedAttempts)
    }

    @Test
    fun attemptPin_clearsAnExpiredBackgroundLockDeadline() = runBlocking {
        manager.scheduleLock(clock)

        assertEquals(UnlockAttemptResult.Success, manager.attemptPin("482913".toCharArray()))
        assertFalse(manager.isLockedNow())
    }

    @Test
    fun attemptPin_withWrongPin_staysLockedAndNoDelayFirstTwoTimes() = runBlocking {
        val first = manager.attemptPin("000001".toCharArray())
        assertTrue(first is UnlockAttemptResult.Rejected)
        assertEquals(0L, (first as UnlockAttemptResult.Rejected).delayMillis)
        assertTrue(manager.locked.value)
    }

    @Test
    fun attemptPin_escalatesDelay_fromThirdWrongAttempt() = runBlocking {
        repeat(2) { manager.attemptPin("000001".toCharArray()) }
        val third = manager.attemptPin("000001".toCharArray()) as UnlockAttemptResult.Rejected
        assertEquals(30_000L, third.delayMillis)
    }

    @Test
    fun attemptPin_wipes_atTheConfiguredThreshold() = runBlocking {
        state.setWipeAfterAttempts(10)
        repeat(9) {
            manager.attemptPin("000001".toCharArray())
            // Step past each escalating lockout so the attempts actually land.
            clock += 2 * 60 * 60_000L
        }
        assertEquals(UnlockAttemptResult.Wiped, manager.attemptPin("000001".toCharArray()))
        assertEquals(1, wipeCount)
    }

    @Test
    fun attemptPin_neverWipes_whenTheUserTurnedTheWipeOff() = runBlocking {
        state.setWipeAfterAttempts(null)

        repeat(LockoutPolicy.DEFAULT_WIPE_THRESHOLD * 2) {
            manager.attemptPin("000001".toCharArray())
            clock += 2 * 60 * 60_000L
        }

        assertEquals(0, wipeCount)
        assertTrue(manager.attemptPin("000001".toCharArray()) is UnlockAttemptResult.Rejected)
    }

    @Test
    fun attemptPin_honoursARaisedThreshold() = runBlocking {
        state.setWipeAfterAttempts(20)

        repeat(19) {
            manager.attemptPin("000001".toCharArray())
            clock += 2 * 60 * 60_000L
        }
        assertEquals(0, wipeCount)

        assertEquals(UnlockAttemptResult.Wiped, manager.attemptPin("000001".toCharArray()))
        assertEquals(1, wipeCount)
    }

    @Test
    fun attemptPin_reportsWipeFailed_whenTheWipeDidNotComplete() = runBlocking {
        wipeResult = WipeResult.Incomplete(listOf("database"))
        state.setWipeAfterAttempts(10)
        repeat(9) {
            manager.attemptPin("000001".toCharArray())
            clock += 2 * 60 * 60_000L
        }

        val result = manager.attemptPin("000001".toCharArray())

        assertTrue("expected WipeFailed, got $result", result is UnlockAttemptResult.WipeFailed)
        assertEquals(listOf("database"), (result as UnlockAttemptResult.WipeFailed).failedSteps)
        assertEquals(1, wipeCount)
    }

    @Test
    fun attemptPin_isRejectedWithoutConsumingAnAttempt_whileLockedOut() = runBlocking {
        repeat(3) { manager.attemptPin("000001".toCharArray()) }
        val attemptsAfterLockout = state.failedAttempts

        // No clock advance: the lockout from the third wrong attempt is still active.
        val duringLockout = manager.attemptPin("000001".toCharArray())

        assertTrue(duringLockout is UnlockAttemptResult.Rejected)
        assertTrue((duringLockout as UnlockAttemptResult.Rejected).delayMillis > 0)
        assertEquals(attemptsAfterLockout, state.failedAttempts)
    }

    @Test
    fun attemptPin_refusesTheCorrectPinToo_whileLockedOut() = runBlocking {
        repeat(3) { manager.attemptPin("000001".toCharArray()) }

        assertTrue(manager.attemptPin("482913".toCharArray()) is UnlockAttemptResult.Rejected)
        assertTrue(manager.locked.value)
    }

    @Test
    fun attemptPin_succeedsAgain_onceTheLockoutHasElapsed() = runBlocking {
        repeat(3) { manager.attemptPin("000001".toCharArray()) }
        clock += 30_000L

        assertEquals(UnlockAttemptResult.Success, manager.attemptPin("482913".toCharArray()))
    }

    @Test
    fun remainingLockout_isClampedToTheStoredDuration_afterAMonotonicClockReset() = runBlocking {
        repeat(3) { manager.attemptPin("000001".toCharArray()) }
        assertEquals(30_000L, manager.remainingLockoutMillis())

        // A reboot restarts elapsedRealtime at zero, which naively reads as "the whole previous
        // uptime still to go". Clamping keeps it bounded at the delay that was actually applied.
        clock = 0L
        assertEquals(30_000L, manager.remainingLockoutMillis())
    }

    @Test
    fun remainingLockout_isZero_whenNoLockoutWasEverSet() {
        assertEquals(0L, manager.remainingLockoutMillis())
    }

    @Test
    fun isLockedNow_staysFalse_insideTheGraceWindow() = runBlocking {
        manager.attemptPin("482913".toCharArray())
        assertFalse(manager.isLockedNow())

        manager.scheduleLock(clock + 30_000L)
        clock += 29_999L

        assertFalse("the grace window has not expired yet", manager.isLockedNow())
    }

    @Test
    fun isLockedNow_locksOnceTheGraceWindowExpires_withoutLockNowEverBeingCalled() = runBlocking {
        manager.attemptPin("482913".toCharArray())
        manager.scheduleLock(clock + 30_000L)

        clock += 30_000L

        assertTrue(manager.isLockedNow())
        assertTrue("the observable flow must catch up too", manager.locked.value)
    }

    @Test
    fun isLockedNow_dropsCachedCredentialKeys_whenTheGraceWindowExpires() = runBlocking {
        val salt = CredentialCipher.randomSalt()
        val gated = FakeAppLockState(credentialSalt = salt).apply { setCredentialPinGateEnabled(true) }
        val gatedManager = newManager(gated)
        gatedManager.attemptPin("482913".toCharArray())
        assertTrue(gatedManager.cachedCredentialKeys() != null)

        gatedManager.scheduleLock(clock + 30_000L)
        clock += 30_000L

        assertTrue(gatedManager.cachedCredentialKeys() == null)
    }

    @Test
    fun cancelScheduledLock_disarmsAnExpiredWindow_forAnAppThatCameBack() = runBlocking {
        manager.attemptPin("482913".toCharArray())
        manager.scheduleLock(clock + 30_000L)

        manager.cancelScheduledLock()
        clock += 60_000L

        assertFalse("returning to the foreground inside the window must not lock later", manager.isLockedNow())
    }

    @Test
    fun isLockedNow_ignoresTheDeadline_whenTheLockIsDisabled() {
        val open = newManager(FakeAppLockState(lockEnabled = false))
        open.scheduleLock(clock + 1_000L)
        clock += 1_000L

        assertFalse(open.isLockedNow())
    }

    @Test
    fun attemptPin_withCredentialGateEnabled_cachesDerivedKeys_untilLocked() = runBlocking {
        val salt = CredentialCipher.randomSalt()
        val gated = FakeAppLockState(credentialSalt = salt).apply { setCredentialPinGateEnabled(true) }
        val gatedManager = newManager(gated)

        gatedManager.attemptPin("482913".toCharArray())
        assertTrue(gatedManager.cachedCredentialKeys() != null)

        gatedManager.lockNow()
        assertTrue(gatedManager.cachedCredentialKeys() == null)
    }

    @Test
    fun lockNow_clearsTheOpenedEnrollmentKey() {
        org.kysecurity.mail.pgp.EnrollmentSession.put("-----BEGIN PGP PRIVATE KEY BLOCK-----".toCharArray())

        newManager(FakeAppLockState(lockEnabled = false)).lockNow()

        assertNull(org.kysecurity.mail.pgp.EnrollmentSession.peekForTest())
    }

    @Test
    fun attemptPin_withCredentialGateEnabled_andNoExistingSalt_generatesAndPersistsSalt() = runBlocking {
        val gated = FakeAppLockState().apply { setCredentialPinGateEnabled(true) }
        val gatedManager = newManager(gated)
        assertTrue(gated.credentialSalt() == null)

        gatedManager.attemptPin("482913".toCharArray())

        assertTrue(gatedManager.cachedCredentialKeys() != null)
        assertTrue(gated.credentialSalt() != null)
    }

    @Test
    fun attemptPin_withCredentialGateDisabled_neverCachesKeys() = runBlocking {
        manager.attemptPin("482913".toCharArray())
        assertTrue(manager.cachedCredentialKeys() == null)
    }

    @Test
    fun attemptPin_sealsTheDerivedKeys_evenWithTheGateOff() = runBlocking {
        assertFalse("precondition: this is the default configuration", state.isCredentialPinGateEnabled())
        state.setBiometricEnabled(true)

        manager.attemptPin("482913".toCharArray())

        assertNotNull(sealer.sealed)
    }

    @Test
    fun attemptPin_withWrongPin_sealsNothing() = runBlocking {
        state.setBiometricEnabled(true)
        manager.attemptPin("000001".toCharArray())

        assertNull(sealer.sealed)
    }

    @Test
    fun attemptPin_withBiometricOff_sealsNothing() = runBlocking {
        assertFalse("precondition: biometric unlock is off by default", state.isBiometricEnabled())

        manager.attemptPin("482913".toCharArray())

        assertNull(sealer.sealed)
    }

    @Test
    fun attemptPin_withBiometricOff_removesKeysSealedEarlier() = runBlocking {
        sealer.seal(CredentialCipher.deriveKeys("482913".toCharArray(), CredentialCipher.randomSalt(), TestPepper))

        manager.attemptPin("482913".toCharArray())

        assertNull(sealer.sealed)
    }

    @Test
    fun disableBiometric_removesTheSealedKeysAndTheyStayGone() = runBlocking {
        state.setBiometricEnabled(true)
        manager.attemptPin("482913".toCharArray())
        assertNotNull("precondition: an enabled unlock seals", sealer.sealed)

        manager.disableBiometric()
        assertNull(sealer.sealed)

        manager.lockNow()
        manager.attemptPin("482913".toCharArray())
        manager.resealForBiometric("482913".toCharArray())
        assertNull(sealer.sealed)
        assertFalse(state.isBiometricEnabled())
    }

    @Test
    fun enableBiometric_withTheRightPin_turnsItOnAndSeals() = runBlocking {
        assertEquals(UnlockAttemptResult.Success, manager.enableBiometric("482913".toCharArray()))

        assertTrue(state.isBiometricEnabled())
        assertNotNull(sealer.sealed)
    }

    @Test
    fun enableBiometric_withAWrongPin_changesNothingAndCountsTheAttempt() = runBlocking {
        assertTrue(manager.enableBiometric("000001".toCharArray()) is UnlockAttemptResult.Rejected)

        assertFalse(state.isBiometricEnabled())
        assertNull(sealer.sealed)
        assertEquals(1, state.failedAttempts)
    }

    @Test
    fun biometricUnlockOnOffer_isNullWhileBiometricIsOff_whateverIsSealed() {
        sealer.seal(CredentialCipher.deriveKeys("482913".toCharArray(), CredentialCipher.randomSalt(), TestPepper))

        assertNull(manager.biometricUnlockOnOffer())
        state.setBiometricEnabled(true)
        assertNotNull(manager.biometricUnlockOnOffer())
    }

    @Test
    fun resealForBiometric_withBiometricOff_sealsNothing() = runBlocking {
        state.putCredentialSaltIfAbsent(CredentialCipher.randomSalt())

        manager.resealForBiometric("112233".toCharArray())

        assertNull(sealer.sealed)
    }

    @Test
    fun unlockWithBiometric_unlocksAndResetsAttempts() = runBlocking {
        manager.attemptPin("000001".toCharArray())
        val keys = CredentialCipher.deriveKeys("482913".toCharArray(), CredentialCipher.randomSalt(), TestPepper)

        manager.unlockWithBiometric(BiometricProof.issue(keys))

        assertFalse(manager.locked.value)
        assertEquals(0, state.failedAttempts)
    }

    @Test
    fun unlockWithBiometric_clearsAnExpiredBackgroundLockDeadline() {
        manager.scheduleLock(clock)
        val keys = CredentialCipher.deriveKeys("482913".toCharArray(), CredentialCipher.randomSalt(), TestPepper)

        assertEquals(
            UnlockAttemptResult.Success,
            manager.unlockWithBiometric(BiometricProof.issue(keys)),
        )
        assertFalse(manager.isLockedNow())
    }

    @Test
    fun unlockWithBiometric_makesTheGatedCredentialUsable() = runBlocking {
        val gated = FakeAppLockState(credentialSalt = CredentialCipher.randomSalt())
            .apply { setCredentialPinGateEnabled(true) }
        val gatedManager = newManager(gated)
        val keys = CredentialCipher.deriveKeys("482913".toCharArray(), gated.credentialSalt()!!, TestPepper)

        gatedManager.unlockWithBiometric(BiometricProof.issue(keys))

        assertArrayEquals(keys.current.encoded, gatedManager.cachedCredentialKeys()?.current?.encoded)
    }

    @Test
    fun unlockWithBiometric_isRefused_whileALockoutIsRunning() = runBlocking {
        // Three wrong PINs is the first attempt that arms a delay.
        repeat(3) { manager.attemptPin("000001".toCharArray()) }
        assertTrue("expected a lockout to be running", manager.remainingLockoutMillis() > 0)
        val attemptsBefore = state.failedAttempts

        val keys = CredentialCipher.deriveKeys("482913".toCharArray(), CredentialCipher.randomSalt(), TestPepper)
        val result = manager.unlockWithBiometric(BiometricProof.issue(keys))

        assertTrue("expected Rejected, got $result", result is UnlockAttemptResult.Rejected)
        assertTrue("must stay locked", manager.locked.value)
        assertEquals("must not clear progress toward the wipe threshold", attemptsBefore, state.failedAttempts)
    }

    @Test
    fun unlockWithBiometric_succeeds_onceTheLockoutHasExpired() = runBlocking {
        repeat(3) { manager.attemptPin("000001".toCharArray()) }
        clock += LockoutPolicy.delayMillisFor(3) + 1

        val keys = CredentialCipher.deriveKeys("482913".toCharArray(), CredentialCipher.randomSalt(), TestPepper)

        assertEquals(UnlockAttemptResult.Success, manager.unlockWithBiometric(BiometricProof.issue(keys)))
        assertFalse(manager.locked.value)
    }

    @Test
    fun keysFor_rejectsATokenFromAnotherManager() = runBlocking {
        val gated = FakeAppLockState(credentialSalt = CredentialCipher.randomSalt())
            .apply { setCredentialPinGateEnabled(true) }
        val issuer = newManager(gated)
        val (result, token) = issuer.verifyPinForDecision("482913".toCharArray(), deriveKeys = true)
        assertEquals(UnlockAttemptResult.Success, result)
        assertNotNull(token)

        assertFailsWith<IllegalArgumentException> { newManager(gated).keysFor(token!!) }
        Unit
    }

    @Test
    fun unlockWithBiometric_withTheGateOff_cachesNoKeys() = runBlocking {
        manager.unlockWithBiometric(
            BiometricProof.issue(
                CredentialCipher.deriveKeys("482913".toCharArray(), CredentialCipher.randomSalt(), TestPepper),
            ),
        )

        assertNull(manager.cachedCredentialKeys())
    }

    @Test
    fun resealForBiometric_sealsTheKeysOfTheNewPin() = runBlocking {
        state.setBiometricEnabled(true)
        state.putCredentialSaltIfAbsent(CredentialCipher.randomSalt())

        manager.resealForBiometric("112233".toCharArray())

        val expected = CredentialCipher.deriveKeys("112233".toCharArray(), state.credentialSalt()!!, TestPepper)
        assertArrayEquals(expected.current.encoded, sealer.sealed?.current?.encoded)
    }

    @Test
    fun deriveAndCacheCredentialKeys_refusesAnUnverifiedPin() = runBlocking {
        assertTrue(manager.deriveAndCacheCredentialKeys("000001".toCharArray()) is UnlockAttemptResult.Rejected)
        assertTrue(manager.cachedCredentialKeys() == null)
    }

    @Test
    fun deriveAndCacheCredentialKeys_reportsAWipeRatherThanAPlainRejection() = runBlocking {
        repeat(LockoutPolicy.DEFAULT_WIPE_THRESHOLD - 1) {
            state.setLockout(0L, 0L)
            manager.deriveAndCacheCredentialKeys("000001".toCharArray())
        }
        state.setLockout(0L, 0L)
        assertTrue(manager.deriveAndCacheCredentialKeys("000001".toCharArray()) is UnlockAttemptResult.Wiped)
        assertTrue(wipeCount > 0)
    }

    /** Clock jumps an hour per read, so no lockout applies and no wipe triggers. */
    @Test
    fun concurrentWrongPins_eachAdvanceTheAttemptCounter() = runBlocking {
        val attempts = LockoutPolicy.DEFAULT_WIPE_THRESHOLD - 1
        val racingClock = java.util.concurrent.atomic.AtomicLong(1_000L)
        val racingManager = AppLockManager(
            state = state,
            elapsedRealtimeMs = { racingClock.addAndGet(3_600_000L) },
            pepper = TestPepper,
            onWipe = { wipeCount++; wipeResult },
        )

        coroutineScope {
            repeat(attempts) { launch { racingManager.verifyPinThrottled("000001".toCharArray()) } }
        }

        assertEquals(attempts, state.failedAttempts)
        assertEquals(0, wipeCount)
    }

    @Test
    fun unevaluableVerifier_isNotCountedAsAWrongPin() = runBlocking {
        state.verifierUnavailable = true

        repeat(LockoutPolicy.DEFAULT_WIPE_THRESHOLD * 2) {
            assertEquals(UnlockAttemptResult.VerifierUnavailable, manager.attemptPin("482913".toCharArray()))
        }

        assertEquals(0, state.failedAttempts)
        assertEquals(0, wipeCount)
        assertTrue(manager.locked.value)
    }

    @Test
    fun unevaluableVerifier_isNotCountedByVerifyPinThrottled() = runBlocking {
        state.verifierUnavailable = true

        repeat(LockoutPolicy.DEFAULT_WIPE_THRESHOLD) {
            assertEquals(UnlockAttemptResult.VerifierUnavailable, manager.verifyPinThrottled("482913".toCharArray()))
        }

        assertEquals(0, state.failedAttempts)
        assertEquals(0, wipeCount)
    }

    @Test
    fun credentialDerivationFailure_doesNotFailAnOtherwiseCorrectUnlock() = runBlocking {
        val exploding = object : CredentialPepper {
            override fun mix(derived: ByteArray): ByteArray = throw PepperUnavailableException("credential-alias")
        }
        val gatedState = FakeAppLockState().apply { setCredentialPinGateEnabled(true) }
        val gatedManager = AppLockManager(
            state = gatedState,
            elapsedRealtimeMs = { clock },
            pepper = exploding,
            onWipe = { wipeCount++; wipeResult },
        )

        assertEquals(UnlockAttemptResult.Success, gatedManager.attemptPin("482913".toCharArray()))
        assertFalse(gatedManager.locked.value)
        assertNull(gatedManager.cachedCredentialKeys())
        assertEquals(0, wipeCount)
    }
}
