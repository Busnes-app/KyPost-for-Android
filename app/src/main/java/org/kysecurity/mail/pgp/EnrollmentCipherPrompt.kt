package org.kysecurity.mail.pgp

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleDestroyedException
import androidx.lifecycle.withStarted
import javax.crypto.Cipher
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlin.coroutines.resume
import org.kysecurity.mail.R

/** Activity-owned authentication for the temporary X-Wing seed. All state runs on Main. Late
 *  callbacks cannot authenticate a continuation that destruction or cancellation already claimed. */
internal class EnrollmentCipherPrompt(private val activity: FragmentActivity) {
    private var pending: CancellableContinuation<Cipher?>? = null
    private var prompt: BiometricPrompt? = null

    fun cancel() {
        val continuation = pending
        pending = null
        prompt?.cancelAuthentication()
        prompt = null
        if (continuation?.isActive == true) continuation.resume(null)
    }

    suspend fun authenticate(cipher: Cipher): Cipher? = withContext(Dispatchers.Main) {
        if (activity.lifecycle.currentState == Lifecycle.State.DESTROYED) return@withContext null
        try {
            activity.lifecycle.withStarted { }
        } catch (_: LifecycleDestroyedException) {
            return@withContext null
        }
        suspendCancellableCoroutine { continuation ->
            if (!activity.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED) || activity.supportFragmentManager.isStateSaved) {
                continuation.resume(null)
                return@suspendCancellableCoroutine
            }
            check(pending == null)
            fun resolve(authenticated: Cipher?) {
                if (pending !== continuation) return
                pending = null
                prompt = null
                if (continuation.isActive) continuation.resume(authenticated)
            }
            val live = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = resolve(result.cryptoObject?.cipher)
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) = resolve(null)
            })
            pending = continuation
            prompt = live
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle(activity.getString(R.string.enrollment_auth_title))
                .setSubtitle(activity.getString(R.string.enrollment_auth_subtitle))
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL)
                .build()
            try {
                live.authenticate(info, BiometricPrompt.CryptoObject(cipher))
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                resolve(null)
            }
            continuation.invokeOnCancellation {
                // Cancellation can originate off Main; queue the Activity state mutation there.
                ContextCompat.getMainExecutor(activity).execute { if (pending === continuation) cancel() }
            }
        }
    }
}
