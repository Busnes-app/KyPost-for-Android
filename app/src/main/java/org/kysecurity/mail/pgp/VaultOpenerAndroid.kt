package org.kysecurity.mail.pgp

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import org.kysecurity.mail.R
import javax.crypto.Cipher
import kotlin.coroutines.resume
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext

/** Opens via a `CryptoObject`; the plaintext lands in [EnrollmentSession] and is never returned. */
internal class AndroidVaultOpener(private val activity: FragmentActivity) : VaultOpener {

    private class LiveOpen(
        val prompt: BiometricPrompt,
        val continuation: CancellableContinuation<OpenOutcome>,
    )

    @Volatile
    private var liveOpen: LiveOpen? = null

    private val openLock = Any()

    private fun claim(continuation: CancellableContinuation<OpenOutcome>): Boolean =
        synchronized(openLock) {
            if (liveOpen?.continuation === continuation) {
                liveOpen = null
                true
            } else {
                false
            }
        }

    private fun resolve(continuation: CancellableContinuation<OpenOutcome>, outcome: OpenOutcome) {
        if (claim(continuation) && continuation.isActive) continuation.resume(outcome)
    }

    /** Activity teardown owns this resolution; callbacks arriving afterwards cannot claim it. */
    fun cancel() {
        val open = synchronized(openLock) {
            liveOpen.also { liveOpen = null }
        } ?: return
        runCatching { open.prompt.cancelAuthentication() }
        if (open.continuation.isActive) open.continuation.resume(OpenOutcome.Cancelled)
    }

    /** `withContext` is not `inline`, so the IO side's early exits travel out as a value. */
    private sealed class VaultUnlock {
        /** Not a `data class`: `ciphertext` would be compared by identity behind a structural-looking
         *  `equals`. Nothing compares these. */
        class Ready(val cipher: Cipher, val ciphertext: ByteArray) : VaultUnlock()
        data class Blocked(val outcome: OpenOutcome) : VaultUnlock()
    }

    override suspend fun open(): OpenOutcome {
        // Blocking Keystore/disk work; the Main hop is explicit — the caller builds this from IO.
        val unlock = withContext(Dispatchers.IO) {
            val vault = EnrollmentVault(activity)

            // Never ensureKey() here: it mutates and would wipe a still-good envelope.
            if (!hasSecureLockScreen(activity)) {
                return@withContext VaultUnlock.Blocked(OpenOutcome.NoSecureLockScreen)
            }
            val (iv, ciphertext) = vault.stored()
                ?: return@withContext VaultUnlock.Blocked(OpenOutcome.NotEnrolled)
            // A stored blob this key cannot open is Failed, never NotEnrolled — different advice.
            val cipher = vault.openCipher(iv)
                ?: return@withContext VaultUnlock.Blocked(
                    OpenOutcome.Failed(activity.getString(R.string.email_pgp_unseal_failed)),
                )
            VaultUnlock.Ready(cipher, ciphertext)
        }
        val (cipher, ciphertext) = when (unlock) {
            is VaultUnlock.Blocked -> return unlock.outcome
            is VaultUnlock.Ready -> unlock.cipher to unlock.ciphertext
        }

        return withContext(Dispatchers.Main) {
            suspendCancellableCoroutine { cont ->
                // A prompt after state-save is silently dropped; keep this before authenticate().
                if (!activity.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED) ||
                    activity.supportFragmentManager.isStateSaved
                ) {
                    cont.resume(OpenOutcome.Cancelled)
                    return@suspendCancellableCoroutine
                }

                val prompt = BiometricPrompt(
                    activity,
                    ContextCompat.getMainExecutor(activity),
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(
                            result: BiometricPrompt.AuthenticationResult,
                        ) {
                            if (!claim(cont)) return
                            val authenticated = result.cryptoObject?.cipher
                            if (authenticated == null) {
                                if (cont.isActive) cont.resume(
                                    OpenOutcome.Failed(activity.getString(R.string.email_pgp_unseal_failed)),
                                )
                                return
                            }
                            val outcome = runCatching {
                                // GCM tag failure = wrong key for this ciphertext: re-enrol.
                                val plaintext = authenticated.doFinal(ciphertext)
                                try {
                                    // putUtf8: a String copy of the private key could not be zeroed.
                                    EnrollmentSession.putUtf8(plaintext)
                                } finally {
                                    plaintext.fill(0)
                                }
                                OpenOutcome.Opened
                            }.getOrElse {
                                OpenOutcome.Failed(activity.getString(R.string.email_pgp_unseal_failed))
                            }
                            if (cont.isActive) cont.resume(outcome)
                        }

                        /** Every error is [OpenOutcome.Cancelled]: the envelope is not broken. */
                        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                            resolve(cont, OpenOutcome.Cancelled)
                        }

                        // onAuthenticationFailed is a non-matching finger. The prompt stays up and the
                        // user tries again; there is nothing to resume.
                    },
                )

                // DEVICE_CREDENTIAL matches the key spec; setNegativeButtonText must NOT be set.
                val info = BiometricPrompt.PromptInfo.Builder()
                    .setTitle(activity.getString(R.string.email_pgp_unlock_title))
                    .setSubtitle(activity.getString(R.string.email_pgp_unlock_subtitle))
                    .setAllowedAuthenticators(
                        BiometricManager.Authenticators.BIOMETRIC_STRONG or
                            BiometricManager.Authenticators.DEVICE_CREDENTIAL,
                    )
                    .build()

                synchronized(openLock) { liveOpen = LiveOpen(prompt, cont) }

                prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))

                cont.invokeOnCancellation {
                    if (claim(cont)) runCatching { prompt.cancelAuthentication() }
                }
            }
        }
    }
}
