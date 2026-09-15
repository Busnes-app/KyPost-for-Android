package org.kysecurity.mail.pgp

import android.os.Bundle
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.TextView
import androidx.activity.viewModels
import androidx.annotation.VisibleForTesting
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import org.kysecurity.mail.R
import org.kysecurity.mail.applyGhostButtonTheme
import org.kysecurity.mail.applyPrimaryButtonTheme
import org.kysecurity.mail.applyThemeToActivity
import org.kysecurity.mail.applyTopInsetWithHeader
import org.kysecurity.mail.security.LockedActivity
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import javax.crypto.Cipher
import kotlin.coroutines.resume

/** The ceremony's screen: renders [EnrollmentUiState] and owns the Activity-bound prompt. */
class DeviceEnrollmentActivity : LockedActivity() {

    private val viewModel: DeviceEnrollmentViewModel by viewModels()

    private lateinit var headline: TextView
    private lateinit var detail: TextView
    private lateinit var codeText: TextView
    private lateinit var expiryText: TextView
    private lateinit var checkAgainButton: Button
    private lateinit var closeButton: Button

    private var countdown: Job? = null

    /** True once `onCreate` ran past the lock gate; false only when `onCreate` itself bailed. */
    private var created = false

    /** Where the seal runs: not the main thread, and not `lifecycleScope` — a cancel would hang it. */
    private val sealExecutor = Executors.newSingleThreadExecutor()

    private val vaultOpener = AndroidVaultOpener(this)

    private class LiveSeal(
        val prompt: BiometricPrompt,
        val continuation: CancellableContinuation<SealOutcome>,
    ) {
        /** True once [sealExecutor] owns the write. Only read or written while holding [sealLock]. */
        var committing: Boolean = false
    }

    /** androidx.biometric 1.1.0 will not resolve this across a rotation, so [onDestroy] does it. */
    @Volatile
    private var liveSeal: LiveSeal? = null

    private val sealLock = Any()

    /** Resolves [continuation] exactly once, racing [onDestroy]: whoever clears [liveSeal] wins. */
    private fun resolveSeal(continuation: CancellableContinuation<SealOutcome>, outcome: SealOutcome) {
        val claimed = synchronized(sealLock) {
            if (liveSeal?.continuation === continuation) {
                liveSeal = null
                true
            } else {
                false
            }
        }
        if (claimed && continuation.isActive) continuation.resume(outcome)
    }

    /** An anonymous object because `VaultSealer` is internal and a public class cannot widen it. */
    private val vaultSealer = object : VaultSealer {
        override suspend fun seal(plaintext: ByteArray, kind: VaultRecordKind): SealOutcome {
            val vault = EnrollmentVault(applicationContext)

            // Off main: ensureKey() is a slow Keystore round trip. The prompt itself must stay on main.
            val (ensured, cipher) = withContext(Dispatchers.IO) {
                val ok = vault.ensureKey()
                ok to if (ok) vault.sealCipher() else null
            }
            if (!ensured) {
                // Also false when key generation failed or an existing record's key is unusable, so
                // this is generic rather than "no lock screen".
                return SealOutcome.Failed("The device key could not be prepared")
            }
            if (cipher == null) {
                return SealOutcome.Failed("The vault cipher could not be created")
            }

            return suspendCancellableCoroutine { continuation ->
                // authenticateInternal silently drops a prompt after state save: resolve as a recoverable cancel.
                if (!lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED) ||
                    supportFragmentManager.isStateSaved
                ) {
                    continuation.resume(SealOutcome.Cancelled)
                    return@suspendCancellableCoroutine
                }

                val prompt = BiometricPrompt(
                    this@DeviceEnrollmentActivity,
                    ContextCompat.getMainExecutor(this@DeviceEnrollmentActivity),
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(
                            result: BiometricPrompt.AuthenticationResult,
                        ) {
                            val authenticated = result.cryptoObject?.cipher
                            if (authenticated == null) {
                                resolveSeal(
                                    continuation,
                                    SealOutcome.Failed("No authenticated cipher was returned"),
                                )
                                return
                            }
                            // Marked in the same critical section onDestroy claims liveSeal in, so the two cannot interleave.
                            val handoff = synchronized(sealLock) {
                                val current = liveSeal
                                if (current?.continuation === continuation) {
                                    current.committing = true
                                    true
                                } else {
                                    false
                                }
                            }
                            if (!handoff) return
                            // Post-shutdown the right outcome is a cancel: Failed would tear down the agreement key.
                            try {
                                sealExecutor.execute {
                                    resolveSeal(continuation, commitSeal(vault, authenticated, plaintext, kind))
                                }
                            } catch (e: RejectedExecutionException) {
                                resolveSeal(continuation, SealOutcome.Cancelled)
                            }
                        }

                        /** A configuration-change destroy does **not** land here in androidx.biometric 1.1.0. */
                        override fun onAuthenticationError(
                            errorCode: Int,
                            errString: CharSequence,
                        ) {
                            resolveSeal(continuation, SealOutcome.Cancelled)
                        }

                        // onAuthenticationFailed is a non-matching finger. The prompt stays up and
                        // the user tries again; there is nothing to resume.
                    },
                )

                // With DEVICE_CREDENTIAL in the set, setNegativeButtonText must NOT be called: it throws.
                val info = BiometricPrompt.PromptInfo.Builder()
                    .setTitle(getString(R.string.enrollment_auth_title))
                    .setSubtitle(getString(R.string.enrollment_auth_subtitle))
                    .setAllowedAuthenticators(
                        BiometricManager.Authenticators.BIOMETRIC_STRONG or
                            BiometricManager.Authenticators.DEVICE_CREDENTIAL,
                    )
                    .build()

                // Set before authenticate(), not after: onDestroy must be able to see this the
                // moment there is a live prompt to resolve, with no window where a destroy landing
                // between authenticate() and this assignment would find nothing to cancel.
                liveSeal = LiveSeal(prompt, continuation)

                prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))

                // Registered after authenticate(): an earlier registration could leave an undismissable dialog.
                continuation.invokeOnCancellation {
                    synchronized(sealLock) { if (liveSeal?.continuation === continuation) liveSeal = null }
                    runCatching { prompt.cancelAuthentication() }
                }
            }
        }
    }

    override fun onCreateUnlocked(savedInstanceState: Bundle?) {
        setContentView(R.layout.activity_device_enrollment)
        setTitle(R.string.enrollment_title)
        applyThemeToActivity(this)
        applyTopInsetWithHeader(this, findViewById(R.id.deviceEnrollmentRoot))

        headline = findViewById(R.id.enrollmentHeadline)
        detail = findViewById(R.id.enrollmentDetail)
        codeText = findViewById(R.id.enrollmentCode)
        expiryText = findViewById(R.id.enrollmentExpiry)
        checkAgainButton = findViewById(R.id.btnEnrollmentCheckAgain)
        closeButton = findViewById(R.id.btnEnrollmentClose)

        checkAgainButton.setOnClickListener { viewModel.checkAgain() }
        closeButton.setOnClickListener { finish() }

        // Installed here rather than in onStart: the ceremony may reach the seal at any moment, and
        // a null sealer resolves as a cancel.
        viewModel.installVaultPorts(vaultSealer, vaultOpener)

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                // Captured so the countdown (started from inside render(), below) can be launched
                // on this same STARTED-scoped CoroutineScope rather than the wider lifecycleScope —
                // see startCountdown's KDoc.
                val scope = this
                combine(viewModel.state, viewModel.idle) { state, idle -> state to idle }
                    .collect { (state, idle) -> render(scope, state, idle) }
            }
        }

        created = true
    }

    override fun onResume() {
        super.onResume()
        if (redirectedToUnlock) return
        applyThemeToActivity(this)
        applyPrimaryButtonTheme(this, checkAgainButton)
        applyGhostButtonTheme(this, closeButton)
    }

    override fun onDestroy() {
        // Guarded: touching `viewModel` after ComponentActivity cleared the store would start a new one.
        if (!created) {
            vaultOpener.cancel()
            sealExecutor.shutdown()
            super.onDestroy()
            return
        }

        // The ViewModel coroutine survives rotation, so this Activity must resolve its own prompt.
        vaultOpener.cancel()

        // Skip on a rotation: the new Activity's onCreate already installed its sealer before this runs.
        if (!isChangingConfigurations()) {
            viewModel.installVaultPorts(null, null)
        }

        // Resolve any waiting seal, unless sealExecutor already owns the write (LiveSeal.committing).
        val (seal, shouldResolve) = synchronized(sealLock) {
            val current = liveSeal
            when {
                current == null -> null to false
                current.committing -> current to false
                else -> {
                    liveSeal = null
                    current to true
                }
            }
        }
        // Only on the path that also resolves the wait; the committing path has no live prompt left.
        if (seal != null && shouldResolve) {
            runCatching { seal.prompt.cancelAuthentication() }
            if (seal.continuation.isActive) {
                seal.continuation.resume(SealOutcome.Cancelled)
            }
        }

        sealExecutor.shutdown()
        super.onDestroy()
    }

    @VisibleForTesting
    internal suspend fun openPreviousVaultForTest(): OpenOutcome = vaultOpener.open()

    @VisibleForTesting
    internal suspend fun sealForTest(plaintext: ByteArray): SealOutcome = vaultSealer.seal(plaintext, VaultRecordKind.LEGACY_ARMOR)

    @VisibleForTesting
    internal fun hasPendingVaultPromptForTest(): Boolean = vaultOpener.hasPendingPromptForTest()

    private fun render(scope: CoroutineScope, state: EnrollmentUiState, idle: Boolean) {
        countdown?.cancel()
        countdown = null

        // KEEP_SCREEN_ON wherever the ceremony waits on the user: a sleep starts the lock grace.
        val awaitingTheUser = state is EnrollmentUiState.ShowingCode ||
            state is EnrollmentUiState.WaitingTimedOut ||
            state is EnrollmentUiState.ReadyToFinish

        if (awaitingTheUser) {
            window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        } else {
            window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        }

        val code = when (state) {
            is EnrollmentUiState.ShowingCode -> state.code
            is EnrollmentUiState.WaitingTimedOut -> state.code
            else -> null
        }
        codeText.visibility = if (code == null) View.GONE else View.VISIBLE
        if (code != null) codeText.text = formatEnrollmentCode(code)

        // Only for ShowingCode: in WaitingTimedOut nothing refreshes the expiry, so it would count past 0.
        if (state is EnrollmentUiState.ShowingCode) {
            expiryText.visibility = View.VISIBLE
            startCountdown(scope, state.expiresAtEpochMs)
        } else {
            expiryText.visibility = View.GONE
        }

        headline.setText(headlineFor(state))
        detail.setText(detailFor(state))

        checkAgainButton.visibility =
            if (offersCheckAgain(state, idle)) View.VISIBLE else View.GONE
        closeButton.setText(
            if (state is EnrollmentUiState.Enrolled) R.string.enrollment_done
            else R.string.enrollment_cancel,
        )
    }

    /** Launched on [scope] (the STARTED scope), not `lifecycleScope`, or it ticks while stopped. */
    private fun startCountdown(scope: CoroutineScope, expiresAtEpochMs: Long) {
        countdown = scope.launch {
            while (true) {
                expiryText.text = when (val label = expiryCountdown(expiresAtEpochMs, System.currentTimeMillis())) {
                    is ExpiryCountdown.Counting -> resources.getQuantityString(
                        R.plurals.enrollment_code_expiry,
                        label.remainingSeconds,
                        label.remainingSeconds,
                    )
                    ExpiryCountdown.Now -> getString(R.string.enrollment_code_expiry_now)
                }
                delay(1_000L)
            }
        }
    }

    private fun headlineFor(state: EnrollmentUiState): Int = when (state) {
        EnrollmentUiState.CheckingIdentity -> R.string.enrollment_checking
        EnrollmentUiState.PublishingKey -> R.string.enrollment_publishing
        is EnrollmentUiState.ShowingCode -> R.string.enrollment_waiting
        is EnrollmentUiState.WaitingTimedOut -> R.string.enrollment_waiting_timed_out
        EnrollmentUiState.Opening -> R.string.enrollment_opening
        EnrollmentUiState.AwaitingAuth -> R.string.enrollment_awaiting_auth
        EnrollmentUiState.ReadyToFinish -> R.string.enrollment_ready_to_finish
        EnrollmentUiState.Enrolled -> R.string.enrollment_enrolled
        is EnrollmentUiState.Unavailable -> unavailableCopy(state.reason)
        is EnrollmentUiState.Failed -> failureCopy(state.reason)
    }

    private fun detailFor(state: EnrollmentUiState): Int = when (state) {
        is EnrollmentUiState.ShowingCode -> R.string.enrollment_code_intro
        is EnrollmentUiState.WaitingTimedOut -> R.string.enrollment_timed_out
        EnrollmentUiState.ReadyToFinish -> R.string.enrollment_ready_to_finish_detail
        EnrollmentUiState.Enrolled -> R.string.enrollment_enrolled_detail
        else -> R.string.empty_string
    }

    private fun unavailableCopy(reason: UnavailableReason): Int = when (reason) {
        UnavailableReason.NOT_PAIRED -> R.string.enrollment_unavailable_not_paired
        UnavailableReason.HOSTILE_LOCATION -> R.string.enrollment_unavailable_hostile_location
        UnavailableReason.NO_SECURE_LOCK_SCREEN -> R.string.enrollment_unavailable_no_lock_screen
        UnavailableReason.NO_IDENTITY -> R.string.enrollment_unavailable_no_identity
        UnavailableReason.SERVER_HELD_KEY -> R.string.enrollment_unavailable_server_held
        UnavailableReason.COULD_NOT_CHECK -> R.string.enrollment_unavailable_could_not_check
    }

    private fun failureCopy(reason: FailureReason): Int = when (reason) {
        // The only failure with its own copy — see the string's comment.
        FailureReason.COULD_NOT_OPEN -> R.string.enrollment_failed_could_not_open
        FailureReason.UNAUTHORIZED -> R.string.enrollment_failed_unauthorized
        FailureReason.RATE_LIMITED -> R.string.enrollment_failed_rate_limited
        FailureReason.NO_SECURE_LOCK_SCREEN -> R.string.enrollment_failed_no_lock_screen
        FailureReason.NO_DEVICE_KEY -> R.string.enrollment_failed_no_device_key
        FailureReason.PUBLISH_REJECTED -> R.string.enrollment_failed_generic
        FailureReason.ENVELOPE_MALFORMED -> R.string.enrollment_failed_generic
        FailureReason.SEAL_FAILED -> R.string.enrollment_failed_generic
    }
}

/** The only step that touches storage, after authentication. [SealOutcome.Sealed] means the
 *  record is durable; a write that did not complete reports [SealOutcome.Failed] and leaves the
 *  previous record in place. */
internal fun commitSeal(vault: EnrollmentVault, authenticated: Cipher, plaintext: ByteArray, kind: VaultRecordKind): SealOutcome =
    runCatching {
        val ciphertext = authenticated.doFinal(plaintext)
        if (vault.store(authenticated.iv, ciphertext, kind)) SealOutcome.Sealed
        else SealOutcome.Failed("The sealed key could not be stored")
    }.getOrElse { SealOutcome.Failed(it.message ?: "The seal failed") }
