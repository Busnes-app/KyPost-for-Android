package org.kysecurity.mail.push

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import org.kysecurity.mail.R
import org.kysecurity.mail.noPersonalizedLearning
import org.kysecurity.mail.security.applyOverlayProtection
import org.kysecurity.mail.security.applySecureFlag
import org.kysecurity.mail.security.filterObscuredTouchesRecursively
import org.kysecurity.mail.security.AppLockStore
import org.kysecurity.mail.security.AuthGateKey
import org.kysecurity.mail.security.CredentialEnvelope
import org.kysecurity.mail.security.consumePin
import org.kysecurity.mail.security.usePin
import org.kysecurity.mail.security.SecurityRuntime
import org.kysecurity.mail.security.SecurityWipe
import org.kysecurity.mail.security.resolvePinAttempt
import org.kysecurity.mail.security.showSecurely
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** The only place an MFA challenge can be approved or denied. Tracker check enforced here too. */
class MfaApprovalActivity : AppCompatActivity() {
    private lateinit var denyButton: Button
    private lateinit var contextText: TextView
    private lateinit var matchGroup: View
    private lateinit var matchChoices: LinearLayout
    private lateinit var matchUnavailable: TextView
    /** The whole challenge, not just its id: [MfaResponder] needs it to put the notification back
     *  when a response fails to reach the server. Null before [adoptChallenge] has accepted one. */
    private var payload: MfaChallengePayload? = null
    private val challengeId: String get() = payload?.challengeId.orEmpty()
    private var resolveJob: Job? = null
    private var authenticated = false

    /** A prompt is on screen and unanswered; without it [onStart] stacks a second one. */
    private var authInFlight = false

    /** The app-lock PIN dialog while it is showing. Held so [onStop] can dismiss it — see
     *  [promptAppLockPin]. */
    private var pinDialog: android.app.AlertDialog? = null

    /** Set by [burnChallenge]: this challenge is finished on this device regardless of what the
     *  network says, so [resolve] must not re-offer it. */
    private var burned = false

    /** The digits the server is showing in the browser, or blank when this challenge carries no
     *  usable number match — in which case it can only be denied. */
    private var matchDigits: String = ""

    /** Tile order, shuffled once per challenge and kept across recreation. */
    private var matchOptions: List<String> = emptyList()

    /** Keys from this decision's PIN check: this screen runs locked, where the cache returns null. */
    private var decisionKeys: org.kysecurity.mail.security.CredentialKeys? = null

    /** Set when [onCreate] returned early to wait for the startup wipe verdict: no content view is
     *  set and every `lateinit` view below is unset, yet the activity still starts and resumes, so
     *  every other lifecycle callback must stand down until the recreate lands. */
    private var awaitingStartupVerdict = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.applySecureFlag()
        window.applyOverlayProtection()

        // Outside LockedActivity, so it must carry its own abandoned-wipe block.
        if (SecurityWipe.blockedByAbandonedWipe(applicationContext)) {
            android.util.Log.e("MfaApproval", "Refusing an MFA challenge: a previous wipe was abandoned")
            startActivity(
                Intent(this, org.kysecurity.mail.MainActivity::class.java)
                    .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP),
            )
            finish()
            return
        }

        // And its own startup-wipe gate, for the same reason. `blockedByAbandonedWipe` is FALSE
        // while a wipe is running, so without this a notification tap could open this screen
        // mid-wipe: it reads the pairing store the wipe is deleting, and its PIN prompt feeds the
        // failed-attempt counter that triggers a SECOND wipe. LockedActivity blocks on exactly this
        // and this screen is deliberately outside it.
        if (!SecurityWipe.startupVerdict.isCompleted) {
            awaitingStartupVerdict = true
            lifecycleScope.launch {
                SecurityWipe.startupVerdict.await()
                if (!isFinishing && !isDestroyed) recreate()
            }
            return
        }

        enableEdgeToEdge()
        setContentView(R.layout.activity_mfa_approval)

        denyButton = findViewById(R.id.btnMfaDeny)
        contextText = findViewById(R.id.mfaApprovalContext)
        matchGroup = findViewById(R.id.mfaMatchGroup)
        matchChoices = findViewById(R.id.mfaMatchChoices)
        matchUnavailable = findViewById(R.id.mfaMatchUnavailable)
        denyButton.setOnClickListener { resolve(approve = false) }
        // The whole inflated tree, not just the decorView the window flag covers.
        findViewById<View>(android.R.id.content).filterObscuredTouchesRecursively()

        savedInstanceState?.getStringArray(STATE_MATCH_OPTIONS)?.let { matchOptions = it.toList() }

        if (!adoptChallenge(intent)) return
        requireAuthentication()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putStringArray(STATE_MATCH_OPTIONS, matchOptions.toTypedArray())
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        // The startup gate has not ruled yet; the recreate it is waiting on adopts this intent.
        // Going further would render into unset views and raise a PIN prompt mid-wipe.
        if (awaitingStartupVerdict) return

        // Cancel any in-flight resolve() for the old challenge so it can't finish() this screen.
        resolveJob?.cancel()
        resolveJob = null
        // A different challenge means a different choice set and a fresh verdict; neither the
        // previous one's tile order nor its burn may carry over.
        matchOptions = emptyList()
        burned = false
        payload = null

        if (!adoptChallenge(intent)) return
        // Re-authenticate per challenge: the previous approval's authentication was consent for
        // that decision, not a session that later challenges can ride on.
        authenticated = false
        authInFlight = false
        requireAuthentication()
    }

    /** Returns false (and finishes) if the challenge is malformed or was never delivered by a real
     *  push. Also renders the sign-in's context and sets up number matching. */
    private fun adoptChallenge(source: Intent): Boolean {
        val adopted = PushNotificationDispatcher.payloadFrom(source)
        if (adopted == null || !PushRuntime.graph(this).mfaChallengeTracker.isPending(adopted.challengeId)) {
            // Say why: a challenge can legitimately expire or be evicted, and silence looks like a bug.
            Toast.makeText(this, R.string.mfa_challenge_unavailable, Toast.LENGTH_LONG).show()
            finish()
            return false
        }
        payload = adopted
        renderContext(adopted)
        setUpNumberMatching(adopted)
        setButtonsEnabled(false)
        return true
    }

    /** Shows where the sign-in came from; says "Unknown" explicitly rather than leaving a blank. */
    private fun renderContext(source: MfaChallengePayload) {
        val unknown = getString(R.string.mfa_context_unknown)
        val whenText = if (source.issuedAtEpochMs > 0L) {
            android.text.format.DateFormat.getTimeFormat(this).format(java.util.Date(source.issuedAtEpochMs))
        } else {
            unknown
        }
        contextText.text = listOf(
            getString(R.string.mfa_context_when, whenText),
            getString(R.string.mfa_context_ip, source.ipAddress.ifBlank { unknown }),
            getString(R.string.mfa_context_device, source.userAgent.ifBlank { unknown }),
        ).joinToString("\n")
        org.kysecurity.mail.applyWarningCalloutTheme(this, contextText)
    }

    /** No bare Approve button: an incomplete choice set means this client cannot approve at all. */
    private fun setUpNumberMatching(source: MfaChallengePayload) {
        matchDigits = source.matchDigits
        val decoys = source.decoyDigits
        // Reuse a restored order only if it still contains this challenge's answer.
        val options = matchOptions.takeIf { it.isNotEmpty() && matchDigits in it }
            ?: MfaNumberMatch.optionsFor(matchDigits, decoys).orEmpty()
        matchOptions = options

        matchChoices.removeAllViews()
        if (options.isEmpty()) {
            matchDigits = ""
            matchGroup.visibility = View.GONE
            matchUnavailable.visibility = View.VISIBLE
            org.kysecurity.mail.applyWarningCalloutTheme(this, matchUnavailable)
            return
        }

        matchUnavailable.visibility = View.GONE
        matchGroup.visibility = View.VISIBLE
        options.forEach { value ->
            val button = Button(this).apply {
                text = value
                textSize = 20f
                isEnabled = false
                // Built at runtime, so onCreate's window-level flag never reached it.
                filterTouchesWhenObscured = true
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                    .apply { marginEnd = (8 * resources.displayMetrics.density).toInt() }
                setOnClickListener { onMatchChosen(value) }
            }
            matchChoices.addView(button)
        }
    }

    /** A wrong number burns the challenge before the deny is sent, so the burn holds offline. */
    private fun onMatchChosen(chosen: String) {
        if (!authenticated) return
        if (chosen == matchDigits) {
            resolve(approve = true, chosenDigits = chosen)
            return
        }
        Toast.makeText(this, R.string.mfa_match_wrong, Toast.LENGTH_LONG).show()
        burnChallenge()
        resolve(approve = false)
    }

    /** Makes this challenge unanswerable on this device, whatever the network does next. */
    private fun burnChallenge() {
        PushNotificationDispatcher.cancelMfaChallenge(this, challengeId)
        PushRuntime.graph(this).mfaChallengeTracker.clear(challengeId)
        burned = true
    }

    private fun setButtonsEnabled(enabled: Boolean) {
        denyButton.isEnabled = enabled
        for (i in 0 until matchChoices.childCount) {
            matchChoices.getChildAt(i).isEnabled = enabled
        }
    }

    /** Deny only: the one unauthenticated action allowed, because it can only subtract access. */
    private fun denyOnly() {
        matchDigits = ""
        matchChoices.removeAllViews()
        matchGroup.visibility = View.GONE
        matchUnavailable.visibility = View.VISIBLE
        matchUnavailable.text = getString(R.string.mfa_approve_needs_device_lock)
        org.kysecurity.mail.applyWarningCalloutTheme(this, matchUnavailable)
        denyButton.isEnabled = true
    }

    /** The app-lock flags this screen branches on. Snapshotted once, off Main: reading either one
     *  forces the Keystore-backed EncryptedSharedPreferences open, and every place that used to
     *  read them was a BiometricPrompt callback running on the main thread. Passed down rather
     *  than held in a field so no branch can reach a posture that was never read. */
    private class LockPosture(val lockEnabled: Boolean, val credentialGateEnabled: Boolean)

    /** Gates both buttons behind an authentication that produces the key the decision needs. */
    private fun requireAuthentication() {
        authInFlight = true
        lifecycleScope.launch {
            // Keystore and disk, so never on Main. Null unlock means nothing is sealed on this device.
            val (unlock, posture) = withContext(Dispatchers.IO) {
                val graph = SecurityRuntime.graph(this@MfaApprovalActivity)
                graph.biometricUnlockVault.prepareUnlock() to LockPosture(
                    lockEnabled = graph.appLockStore.isLockEnabled(),
                    credentialGateEnabled = graph.appLockStore.isCredentialPinGateEnabled(),
                )
            }
            // The user left while the vault was being read: leave the decision unmade and let
            // [onStart] start over on the way back.
            if (!canRaisePrompt()) {
                authInFlight = false
                return@launch
            }
            if (unlock != null) {
                authenticateWithSealedKeys(unlock, posture)
            } else {
                authenticateWithoutSealedKeys(posture)
            }
        }
    }

    /** The good path: the fingerprint opens the app's own credential keys. */
    private fun authenticateWithSealedKeys(
        unlock: org.kysecurity.mail.security.BiometricUnlock,
        posture: LockPosture,
    ) {
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(getString(R.string.mfa_auth_title))
            .setSubtitle(getString(R.string.mfa_auth_subtitle))
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setNegativeButtonText(getString(R.string.unlock_use_pin_button))
            .build()

        BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val cipher = result.cryptoObject?.cipher
                    val proof = cipher?.let { CredentialEnvelope.open(unlock.sealed, it) }
                    if (proof == null) {
                        // The blob and the key are out of step; the PIN both authenticates and
                        // re-seals, so route there rather than failing the screen.
                        authenticateWithoutSealedKeys(posture)
                        return
                    }
                    authInFlight = false
                    // Held for this decision only, exactly as the PIN path does — this screen is
                    // deliberately not an unlock, so the keys must not go into the manager's cache.
                    decisionKeys = proof.keys
                    authenticated = true
                    setButtonsEnabled(true)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    // Includes "Use PIN". The app-lock PIN is the one fallback that still produces
                    // the credential, so offer it rather than ending the screen.
                    if (posture.lockEnabled) {
                        promptAppLockPin(posture)
                        return
                    }
                    authInFlight = false
                    Toast.makeText(this@MfaApprovalActivity, R.string.mfa_auth_required, Toast.LENGTH_SHORT).show()
                    finish()
                }
            },
        ).authenticate(promptInfo, BiometricPrompt.CryptoObject(unlock.cipher))
    }

    /** App PIN first when a lock is configured; [AuthGateKey] makes the success callback evidence. */
    private fun authenticateWithoutSealedKeys(posture: LockPosture) {
        if (posture.lockEnabled) {
            promptAppLockPin(posture)
            return
        }

        val authenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL
        if (mfaHasNoAuthenticator(BiometricManager.from(this).canAuthenticate(authenticators))) {
            // Genuinely nothing to authenticate against: no sensor, no credential, no app-lock PIN.
            authInFlight = false
            authenticated = true
            denyOnly()
            return
        }

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(getString(R.string.mfa_auth_title))
            .setSubtitle(getString(R.string.mfa_auth_subtitle))
            .setAllowedAuthenticators(authenticators)
            .build()

        lifecycleScope.launch {
            // Keystore, so never on Main.
            val gate = withContext(Dispatchers.IO) { AuthGateKey.cipher() }
            // The user left while the key was being minted; [onStart] starts over on the way back.
            if (!canRaisePrompt()) {
                authInFlight = false
                return@launch
            }
            if (gate == null) {
                // An authenticator exists but the OS will not bind a key to it. Fail closed: a
                // prompt with nothing to prove it ran is the alert this path was written to answer.
                abandonDecision()
                return@launch
            }

            BiometricPrompt(
                this@MfaApprovalActivity,
                ContextCompat.getMainExecutor(this@MfaApprovalActivity),
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        authInFlight = false
                        val cipher = result.cryptoObject?.cipher
                        if (cipher == null || !AuthGateKey.proves(cipher)) {
                            // Success reported, but the OS did not release the key: a hooked
                            // callback, not a user.
                            abandonDecision()
                            return
                        }
                        authenticated = true
                        setButtonsEnabled(true)
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        // Cancelled or unavailable: leave the decision unmade rather than falling
                        // through to enabled buttons.
                        abandonDecision()
                    }
                },
            ).authenticate(promptInfo, BiometricPrompt.CryptoObject(gate))
        }
    }

    /** Neither a `BiometricPrompt` nor an `AlertDialog` may be raised past a saved state — the first
     *  is silently dropped with no callback ever, the second throws. */
    private fun canRaisePrompt(): Boolean =
        lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED) && !supportFragmentManager.isStateSaved

    /** Ends the screen with the decision unmade. */
    private fun abandonDecision() {
        authInFlight = false
        Toast.makeText(this, R.string.mfa_auth_required, Toast.LENGTH_SHORT).show()
        finish()
    }

    /** The credential gate is on and this process has no PIN-derived key, so only the app-lock PIN
     *  can make this challenge answerable. */
    private fun credentialGateNeedsPin(posture: LockPosture): Boolean {
        if (!posture.lockEnabled || !posture.credentialGateEnabled) return false
        // In-memory only: a volatile field plus a monotonic clock read, safe on Main.
        return SecurityRuntime.graph(this).appLockManager.cachedCredentialKeys() == null
    }

    /** Throttled through AppLockManager; the dialog is held and dismissed in [onStop]. */
    private fun promptAppLockPin(posture: LockPosture) {
        pinDialog?.dismiss()
        val pinField = android.widget.EditText(this).apply {
            noPersonalizedLearning()
            inputType = android.text.InputType.TYPE_CLASS_NUMBER or
                android.text.InputType.TYPE_NUMBER_VARIATION_PASSWORD
            hint = getString(R.string.unlock_pin_hint)
        }
        val gateNeedsPin = credentialGateNeedsPin(posture)
        pinDialog = android.app.AlertDialog.Builder(this)
            .setTitle(R.string.mfa_auth_title)
            .setMessage(if (gateNeedsPin) R.string.mfa_auth_subtitle_pin_required else R.string.mfa_auth_subtitle)
            .setView(pinField)
            .setPositiveButton(android.R.string.ok) { _, _ ->
                lifecycleScope.launch {
                    val manager = SecurityRuntime.graph(this@MfaApprovalActivity).appLockManager
                    // consumePin + usePin: the PIN is a wipeable CharArray and is zeroed the
                    // moment the check returns, never an unzeroable String. See [consumePin].
                    val (attempt, token) = pinField.consumePin().usePin { pin ->
                        // verifyPinForDecision hands keys back only on Success, and does NOT unlock the app.
                        manager.verifyPinForDecision(pin, deriveKeys = gateNeedsPin)
                    }
                    // resolvePinAttempt, not `is Success`: the wipe threshold applies here too.
                    val ok = resolvePinAttempt(attempt)
                    authInFlight = false
                    pinDialog = null
                    if (ok && token != null) {
                        // Captured for the life of this authenticated decision, and dropped in
                        // onStop alongside `authenticated`.
                        decisionKeys = manager.keysFor(token)
                        authenticated = true
                        setButtonsEnabled(true)
                    } else {
                        Toast.makeText(this@MfaApprovalActivity, R.string.mfa_auth_required, Toast.LENGTH_SHORT).show()
                        finish()
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel) { _, _ ->
                authInFlight = false
                pinDialog = null
                finish()
            }
            .setCancelable(false)
            .create()
            .showSecurely()
    }

    /** Authentication is consent for one decision and does not survive leaving the screen. */
    override fun onStop() {
        super.onStop()
        // Nothing was authenticated and no view exists to disable — see [awaitingStartupVerdict].
        if (awaitingStartupVerdict) return
        authenticated = false
        authInFlight = false
        // Dropped with the authentication that produced them: the key is consent for one decision
        // taken on this screen, and it must not outlive the user's presence on it.
        decisionKeys = null
        // Torn down with the authentication it belongs to. Leaving it up while clearing
        // `authInFlight` is what let [onStart] stack a second one on top of it.
        pinDialog?.dismiss()
        pinDialog = null
        setButtonsEnabled(false)
    }

    /** Re-authenticates on the way back; skipped while a resolve is in flight. */
    override fun onStart() {
        super.onStart()
        if (awaitingStartupVerdict) return
        if (authenticated || authInFlight || payload == null || resolveJob?.isActive == true) return
        requireAuthentication()
    }

    /** The server checks [chosenDigits]; the local comparison only decides which request to send. */
    private fun resolve(approve: Boolean, chosenDigits: String = "") {
        if (!authenticated) return
        val current = payload ?: return
        setButtonsEnabled(false)
        resolveJob = lifecycleScope.launch {
            val delivered =
                MfaResponder.respond(applicationContext, current, approve, chosenDigits, decisionKeys)
            if (delivered || burned) {
                // A burned challenge is over on this device whether or not the deny landed; there
                // is nothing left here for the user to do.
                finish()
                return@launch
            }
            // An undelivered approve leaves the challenge open; MfaResponder re-posts for a retry.
            resolveJob = null
            // lifecycleScope cancels on DESTROY, not STOP — don't re-enable tiles on a stopped screen.
            if (authenticated) setButtonsEnabled(true)
        }
    }

    private companion object {
        const val STATE_MATCH_OPTIONS = "matchOptions"
    }
}

/** True only for genuinely terminal statuses; HW_UNAVAILABLE/UNKNOWN/SECURITY_UPDATE are not. */
internal fun mfaHasNoAuthenticator(canAuthenticateStatus: Int): Boolean = when (canAuthenticateStatus) {
    BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE,
    BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED,
    BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED,
    -> true
    else -> false
}
