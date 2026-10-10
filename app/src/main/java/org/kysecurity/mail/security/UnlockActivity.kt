package org.kysecurity.mail.security

import android.content.Intent
import android.os.Bundle
import android.os.CountDownTimer
import android.text.InputFilter
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.activity.addCallback
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import org.kysecurity.mail.MainActivity
import org.kysecurity.mail.R
import org.kysecurity.mail.applyThemeToActivity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class UnlockActivity : AppCompatActivity() {
    private lateinit var pinField: EditText
    private lateinit var errorText: TextView
    private lateinit var submitButton: Button
    private lateinit var appLockManager: AppLockManager
    private var countdown: CountDownTimer? = null

    /** Set when onCreate returned early to wait for the startup wipe verdict: the views and
     *  [appLockManager] are unset, so every other lifecycle callback must stand down too. */
    private var awaitingStartupVerdict = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_unlock)
        applyThemeToActivity(this)
        window.applySecureFlag()
        window.applyOverlayProtection()

        // Outside LockedActivity, which is what normally holds a screen back until the startup
        // wipe has ruled. A PIN attempt taken before then feeds the failed-attempt counter that
        // triggers a wipe, while one may already be running.
        if (!SecurityWipe.startupVerdict.isCompleted) {
            awaitingStartupVerdict = true
            lifecycleScope.launch {
                SecurityWipe.startupVerdict.await()
                if (!isFinishing && !isDestroyed) recreate()
            }
            return
        }

        appLockManager = SecurityRuntime.graph(this).appLockManager

        // Back must never reveal what is behind this screen. Backgrounding the task is the only
        // safe interpretation: the app stays locked and re-gates on the next foreground.
        onBackPressedDispatcher.addCallback(this) { moveTaskToBack(true) }

        pinField = findViewById(R.id.unlockPinField)
        pinField.filters = arrayOf(InputFilter.LengthFilter(PinPolicy.MAX_LENGTH))
        errorText = findViewById(R.id.unlockErrorText)
        submitButton = findViewById(R.id.unlockSubmitButton)
        submitButton.setOnClickListener { attemptUnlock() }

        if (SecurityRuntime.graph(this).appLockStore.isBiometricEnabled()) {
            showBiometricPromptIfAvailable()
        }
    }

    override fun onResume() {
        super.onResume()
        if (awaitingStartupVerdict) return
        applyRemainingLockout()
    }

    override fun onDestroy() {
        super.onDestroy()
        countdown?.cancel()
    }

    private fun attemptUnlock() {
        // consumePin, not text.toString(): the PIN never becomes an unzeroable String, and the
        // field is emptied as it is read. See [consumePin].
        val pin = pinField.consumePin()
        // attemptPin runs PBKDF2 and commit()-backed Keystore writes; the button stays disabled
        // for the duration so a double-tap can't burn two attempts against the wipe counter.
        submitButton.isEnabled = false
        lifecycleScope.launch {
            when (val result = pin.usePin { appLockManager.attemptPin(it) }) {
                is UnlockAttemptResult.Success -> completeUnlock()
                is UnlockAttemptResult.Wiped -> restartToFirstRun()
                is UnlockAttemptResult.WipeFailed -> {
                    // The wipe left its in-progress marker set, so KyPostApp retries it at start.
                    android.util.Log.e("UnlockActivity", "Wipe incomplete: ${result.failedSteps}")
                    restartToFirstRun()
                }
                is UnlockAttemptResult.Rejected -> {
                    errorText.visibility = View.VISIBLE
                    errorText.text = getString(R.string.unlock_wrong_pin)
                    submitButton.isEnabled = true
                    if (result.delayMillis > 0) applyRemainingLockout()
                }
                is UnlockAttemptResult.VerifierUnavailable -> {
                    // No PIN can match again, and this does not advance the wipe threshold.
                    errorText.visibility = View.VISIBLE
                    errorText.text = getString(R.string.security_verifier_unavailable)
                    submitButton.isEnabled = true
                }
            }
        }
    }

    /** Shared by both unlock paths so each runs the rewrap and the enrollment report. */
    private suspend fun completeUnlock() {
        rewrapPairingIfNeeded(this, appLockManager)
        org.kysecurity.mail.pgp.EnrollmentStateWorker.enqueue(this)
        proceedIntoApp()
    }

    private fun proceedIntoApp() {
        startActivity(
            Intent(this, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK),
        )
        finish()
    }

    private fun applyRemainingLockout() {
        val remaining = appLockManager.remainingLockoutMillis()
        countdown?.cancel()
        if (remaining <= 0) {
            submitButton.isEnabled = true
            pinField.isEnabled = true
            return
        }
        submitButton.isEnabled = false
        pinField.isEnabled = false
        countdown = object : CountDownTimer(remaining, 1_000L) {
            override fun onTick(millisUntilFinished: Long) {
                errorText.visibility = View.VISIBLE
                errorText.text = getString(R.string.unlock_locked_out, "${millisUntilFinished / 1_000}s")
            }

            override fun onFinish() {
                submitButton.isEnabled = true
                pinField.isEnabled = true
                errorText.visibility = View.GONE
            }
        }.start()
    }

    /** prepareUnlock() is Keystore and disk work, hence the hop off the main thread. */
    private fun showBiometricPromptIfAvailable() {
        if (BiometricManager.from(this).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) !=
            BiometricManager.BIOMETRIC_SUCCESS
        ) {
            return
        }

        lifecycleScope.launch {
            val unlock = withContext(Dispatchers.IO) {
                SecurityRuntime.graph(this@UnlockActivity).biometricUnlockVault.prepareUnlock()
            } ?: return@launch

            // A prompt requested after the FragmentManager has saved its state is silently dropped
            // by BiometricPrompt with no callback ever — see AndroidVaultOpener, which closes the
            // same race in the same place. Checked here, on Main, immediately before authenticate().
            if (!lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED) || supportFragmentManager.isStateSaved) {
                return@launch
            }
            authenticate(unlock)
        }
    }

    private fun authenticate(unlock: BiometricUnlock) {
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(getString(R.string.unlock_title))
            .setNegativeButtonText(getString(R.string.unlock_use_pin_button))
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()

        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val cipher = result.cryptoObject?.cipher
                    val proof = cipher?.let { CredentialEnvelope.open(unlock.sealed, it) }
                    if (proof == null) {
                        // The blob and the key have gone out of step. Nothing here is recoverable by
                        // trying again, and the PIN both unlocks and re-seals.
                        errorText.visibility = View.VISIBLE
                        errorText.text = getString(R.string.unlock_biometric_unavailable)
                        pinField.requestFocus()
                        return
                    }
                    // Rejected means an earlier lockout is still running; biometrics skip nothing.
                    if (appLockManager.unlockWithBiometric(proof) !is UnlockAttemptResult.Success) {
                        errorText.visibility = View.VISIBLE
                        errorText.text = getString(R.string.unlock_wrong_pin)
                        applyRemainingLockout()
                        return
                    }
                    lifecycleScope.launch { completeUnlock() }
                }
                // Errors and failures need no handling: the PIN field is always the fallback.
            },
        )
        prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(unlock.cipher))
    }

    private fun restartToFirstRun() {
        // SecurityWipe already ran; this only rebuilds the graphs, and the rebuild blocks.
        lifecycleScope.launch { AppRestart.relaunch(this@UnlockActivity) }
    }
}
