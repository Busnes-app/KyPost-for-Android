// See AppLockStore: androidx.security-crypto is deprecated in full with no replacement API.
@file:Suppress("DEPRECATION")

package org.kysecurity.mail.push

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import org.kysecurity.mail.security.CredentialCipher
import org.kysecurity.mail.security.openEncryptedPrefs
import org.kysecurity.mail.security.CredentialKeys
import org.kysecurity.mail.security.WrappedSecret
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext

private const val ENCRYPTED_PREFS_FILE_NAME = "push_pairing_secure"

private const val KEY_SUBSCRIBER_ID = "pair_sub"
private const val KEY_DEVICE_SECRET = "pair_device_secret"
private const val KEY_SERVER_URL = "pair_srv"
private const val KEY_REGISTRATION_URL = "pair_reg"
private const val KEY_PAIRING_TOKEN = "pair_pt"
private const val KEY_DEVICE_ID = "pair_device_id"
private const val KEY_PAIRED_AT = "pair_paired_at"
private const val KEY_DEVICE_SECRET_CIPHERTEXT = "pair_device_secret_ciphertext"
private const val KEY_DEVICE_SECRET_SALT = "pair_device_secret_salt"
private const val KEY_DEVICE_SECRET_IV = "pair_device_secret_iv"
private const val KEY_DEVICE_SECRET_VERSION = "pair_device_secret_version"

/** The staged half of a PIN change; see [SecurePairingStore.stagePendingSecret]. Always written
 *  under the current (peppered) scheme, so it carries no version of its own. */
private const val KEY_DEVICE_SECRET_PENDING_CIPHERTEXT = "pair_device_secret_pending_ciphertext"
private const val KEY_DEVICE_SECRET_PENDING_IV = "pair_device_secret_pending_iv"
/** The account a credential-only reconnect kept data for; see [SecurePairingStore.clearPairing]. */
private const val KEY_RECONNECT_SUB = "reconnect_expect_sub"
private const val KEY_RECONNECT_SRV = "reconnect_expect_srv"

/** Legacy: a single leaf pin. Read-only now — [readTlsPin] carries it forward, nothing writes it. */
private const val KEY_TLS_PIN = "pair_tls_spki_pin"
private const val KEY_TLS_PINS = "pair_tls_spki_pins"
private const val KEY_TLS_PIN_HOST = "pair_tls_spki_pin_host"

/** Absent means the stored set was written under the old whole-chain rule and may contain a public
 *  CA intermediate — see [org.kysecurity.mail.security.SpkiPinner.pinsForChain]. Such a set is
 *  REPLACED, not merged into, on the next capture, or the intermediate would ride the rolling
 *  window forever on any install whose certificate happens not to rotate. */
private const val KEY_TLS_PINS_ARE_LEAVES = "pair_tls_spki_pins_leaf_only"

/** Plain companion file; see [SecurePairingStore.tlsPinState]. */
internal const val TLS_PIN_TRIPWIRE_PREFS = "push_tls_pin_tripwire"
private const val KEY_TLS_PIN_EVER_CAPTURED = "tls_pin_ever_captured"

/** Plain companion file; see [SecurePairingStore.everPaired]. */
internal const val PAIRING_HISTORY_PREFS = "push_pairing_history"
private const val KEY_EVER_PAIRED = "ever_paired"

/** A TOFU certificate pin together with the host it was actually observed on.
 *
 *  [spkiSha256] holds ONE leaf pin for anything written under the current rule. `CertificatePinner`
 *  passes when ANY chain member matches ANY configured pin, so an issuer pin admits every
 *  certificate that issuer signs — see [org.kysecurity.mail.security.SpkiPinner.pinsForChain],
 *  which owns that policy, and [PushSyncCoordinator.narrowLegacyTlsPin], which retires the
 *  whole-chain sets older installs still carry. Renewal with a new key breaks the pin on purpose;
 *  the recovery is [PushHomeViewModel.reconnectToServer], which keeps the mailbox. */
data class TlsPin(val host: String, val spkiSha256: Set<String>) {
    init {
        // An empty pin set is not "unpinned", it is worse: CertificatePinner passes vacuously when
        // no pin is configured for the host, so this must be unrepresentable rather than checked.
        require(spkiSha256.isNotEmpty()) { "A TlsPin with no pins would pin nothing" }
    }
}

/** Why a request is or is not pinned: "never paired" must not be answered like "pin is gone". */
sealed interface TlsPinState {
    /** No pairing has ever completed, so there is nothing to pin against yet. */
    object NeverPaired : TlsPinState
    data class Pinned(val pin: TlsPin) : TlsPinState

    /** A pin was captured once and is no longer readable. Requests must fail rather than downgrade. */
    object Lost : TlsPinState
}

/** What [SecurePairingStore.savePairing] should do with the stored `deviceSecret`. */
sealed interface SecretWrite {
    /** Leave whatever is on disk untouched — the caller is not allowed to persist one right now. */
    object Preserve : SecretWrite

    /** There is no secret; remove any stored one. */
    object Clear : SecretWrite

    /** Wrapped behind the PIN-derived key. Not a `data class`: `toString()` would leak the secret. */
    class Wrapped(val secret: String, val keys: CredentialKeys, val salt: ByteArray) : SecretWrite {
        override fun toString(): String = "SecretWrite.Wrapped(secret=<redacted>)"
    }

    /** Store it as-is; the credential gate is off. */
    data class Plaintext(val secret: String) : SecretWrite {
        /** Redacted: the secret is an unwrapped device credential. Enforced by `SourceRulesTest`. */
        override fun toString(): String = "Plaintext(redacted)"
    }
}

/** Holds pairing proof material in a Keystore-backed EncryptedSharedPreferences file.
 *
 *  CONSTRUCTION IS DISK AND KEYSTORE I/O. It was written `by lazy`, which read as "cheap to
 *  build" — and then [init] below forced it three lines later, so the laziness was decoration and
 *  every construction paid a Tink keyset load, an AndroidKeyStore round trip and an XML parse on
 *  whatever thread got there first. Stated instead of hidden: build this off the main thread. */
class SecurePairingStore(context: Context) {
    private val prefs: SharedPreferences = buildEncryptedPrefs(context.applicationContext)

    private val _pairing = MutableStateFlow<PairingData?>(null)
    val pairing: StateFlow<PairingData?> = _pairing.asStateFlow()

    /** Cached for the request hot path. Only [saveTlsPin] and [clearPairing] may write it. */
    @Volatile
    private var cachedTlsPin: TlsPin? = null

    /** Plain marker that survives the encrypted file being reset — see [tlsPinState]. */
    private val tlsPinTripwire =
        context.applicationContext.getSharedPreferences(TLS_PIN_TRIPWIRE_PREFS, Context.MODE_PRIVATE)

    private val pairingHistory =
        context.applicationContext.getSharedPreferences(PAIRING_HISTORY_PREFS, Context.MODE_PRIVATE)

    private val _everPaired = MutableStateFlow(false)

    /** True once this install has saved any pairing. Unlike [tlsPinState], unpair and reconnect
     *  leave it set: it answers "was this device ever paired", not "is there a pin". */
    val everPaired: StateFlow<Boolean> = _everPaired.asStateFlow()

    init {
        _pairing.value = readPairing(credentialKeys = null)
        cachedTlsPin = readTlsPin()
        _everPaired.value = pairingHistory.getBoolean(KEY_EVER_PAIRED, false)
        // Installs paired before this marker existed: whatever pairing evidence is left counts.
        if (hasStoredPairing() || reconnectExpectation() != null ||
            tlsPinTripwire.getBoolean(KEY_TLS_PIN_EVER_CAPTURED, false)
        ) {
            markEverPaired()
        }
    }

    private fun markEverPaired() {
        if (!pairingHistory.getBoolean(KEY_EVER_PAIRED, false)) {
            pairingHistory.edit().putBoolean(KEY_EVER_PAIRED, true).commit()
        }
        _everPaired.value = true
    }

    /** Writes the pairing, applying [secret] to the stored `deviceSecret`. */
    suspend fun savePairing(pairing: PairingData, secret: SecretWrite) {
        withContext(Dispatchers.IO + NonCancellable) {
            val editor = prefs.edit()
                .putString(KEY_SUBSCRIBER_ID, pairing.subscriberId)
                .putString(KEY_SERVER_URL, pairing.serverUrl)
                .putString(KEY_REGISTRATION_URL, pairing.registrationUrl)
                .putString(KEY_PAIRING_TOKEN, pairing.pairingToken)
                .putLong(KEY_PAIRED_AT, pairing.pairedAtEpochMs)
                // A pairing exists again, so the reconnect marker is spent: the pairing itself now
                // names the account, and a marker that outlives it can only name a stale one.
                .remove(KEY_RECONNECT_SUB)
                .remove(KEY_RECONNECT_SRV)
            if (pairing.deviceId.isNullOrBlank()) editor.remove(KEY_DEVICE_ID) else editor.putString(KEY_DEVICE_ID, pairing.deviceId)

            when (secret) {
                SecretWrite.Preserve -> Unit
                SecretWrite.Clear -> editor.clearWrappedSecret().remove(KEY_DEVICE_SECRET)
                is SecretWrite.Wrapped -> {
                    val wrapped = CredentialCipher.wrap(secret.secret, secret.keys.current)
                    // clearPendingSecret: this write IS the promotion a staged copy was waiting
                    // for, so the staging window closes here. Without it an abandoned PIN change
                    // left the device secret readable under a PIN the user never adopted, on disk,
                    // forever — and SecuritySettingsActivity's PHASE 3 comment claimed otherwise.
                    editor.clearPendingSecret()
                        .remove(KEY_DEVICE_SECRET)
                        .putString(KEY_DEVICE_SECRET_CIPHERTEXT, Base64.encodeToString(wrapped.ciphertext, Base64.NO_WRAP))
                        .putString(KEY_DEVICE_SECRET_SALT, Base64.encodeToString(secret.salt, Base64.NO_WRAP))
                        .putString(KEY_DEVICE_SECRET_IV, Base64.encodeToString(wrapped.iv, Base64.NO_WRAP))
                        .putInt(KEY_DEVICE_SECRET_VERSION, SECRET_VERSION_PEPPERED)
                }
                is SecretWrite.Plaintext ->
                    editor.clearWrappedSecret().putString(KEY_DEVICE_SECRET, secret.secret)
            }
            editor.commit()
            markEverPaired()
        }
        _pairing.value = readPairing(credentialKeys = null)
    }

    /** Writes the pairing's own secret under the STATED gate posture.
     *
     *  [gateEnabled] has no default and is deliberately not inferred from `credentialKeys == null`.
     *  "The gate is off, store it in the clear" and "the gate is on and this caller does not hold
     *  the key" both arrive here as a null key and mean opposite things; inferring collapsed them
     *  into the first, so a caller that merely forgot to pass keys silently downgraded a wrapped
     *  device secret to plaintext on disk. Gate on with no key now PRESERVES what is already
     *  there — the one answer that is safe under either reading. */
    suspend fun savePairing(
        pairing: PairingData,
        gateEnabled: Boolean,
        credentialKeys: CredentialKeys? = null,
        credentialSalt: ByteArray? = null,
    ) {
        val deviceSecret = pairing.deviceSecret
        val secret = when {
            deviceSecret.isNullOrBlank() -> SecretWrite.Clear
            !gateEnabled -> SecretWrite.Plaintext(deviceSecret)
            credentialKeys != null && credentialSalt != null ->
                SecretWrite.Wrapped(deviceSecret, credentialKeys, credentialSalt)
            else -> SecretWrite.Preserve
        }
        savePairing(pairing, secret)
    }

    /** Whether a pairing exists on disk at all, without decrypting anything. */
    fun hasStoredPairing(): Boolean = !prefs.getString(KEY_SUBSCRIBER_ID, null).isNullOrBlank()

    /** The account a reconnect kept data for, or null. Synchronous: the pairing confirmation
     *  dialog reads it on the cold path, where there is no state flow to observe yet. */
    fun reconnectExpectation(): ReconnectExpectation? {
        val sub = prefs.getString(KEY_RECONNECT_SUB, null)?.takeIf { it.isNotBlank() } ?: return null
        val srv = prefs.getString(KEY_RECONNECT_SRV, null)?.takeIf { it.isNotBlank() } ?: return null
        return ReconnectExpectation(subscriberId = sub, serverUrl = srv)
    }

    /** Unwraps `deviceSecret`; null if wrapped and [credentialKeys] is wrong. Never throws. */
    fun pairingSnapshot(credentialKeys: CredentialKeys?): PairingData? = readPairing(credentialKeys)

    /** True when the stored secret is not wrapped under the current scheme while the gate is on.
     *
     *  Scheme only. A secret wrapped under the current scheme but a *different key* is not
     *  re-wrappable — there is no plaintext to re-wrap — so it is [deviceSecretIsStranded]'s
     *  question, not this one. Conflating the two gave a repair loop that silently did nothing. */
    fun needsCredentialRewrap(): Boolean {
        // No pairing means no secret to wrap; cheapest possible check before the rewrap dance.
        if (prefs.getString(KEY_SUBSCRIBER_ID, null).isNullOrBlank()) return false
        if (!prefs.contains(KEY_DEVICE_SECRET_CIPHERTEXT)) return true
        return prefs.getInt(KEY_DEVICE_SECRET_VERSION, SECRET_VERSION_LEGACY) < SECRET_VERSION_PEPPERED
    }

    /** True when a wrapped secret exists and [credentialKeys] cannot open it.
     *
     *  The secret is then unrecoverable: every authenticated call will go out uncredentialed and
     *  the relay will answer 409. Detecting it is what lets the app offer a reconnect instead of
     *  leaving the user to conclude, from a 409, that they must unpair — which deletes the mailbox.
     *  Returns false when the keys are absent, since "locked" is not "stranded". */
    fun deviceSecretIsStranded(credentialKeys: CredentialKeys?): Boolean {
        if (credentialKeys == null) return false
        if (!prefs.contains(KEY_DEVICE_SECRET_CIPHERTEXT)) return false
        return resolveDeviceSecret(credentialKeys).isNullOrBlank()
    }

    /** Persists the TOFU pin with its host; never overwritten except on a fresh pairing. */
    suspend fun saveTlsPin(pin: TlsPin) {
        // ORDER: marker, then pin, then cache — the only ordering that fails closed.
        withContext(Dispatchers.IO + NonCancellable) {
            // The plain marker, so losing the encrypted file cannot look like "never pinned".
            tlsPinTripwire.edit().putBoolean(KEY_TLS_PIN_EVER_CAPTURED, true).commit()
            prefs.edit()
                .putStringSet(KEY_TLS_PINS, pin.spkiSha256)
                // Superseded by the set above; left behind it would win on the next legacy read.
                .remove(KEY_TLS_PIN)
                .putString(KEY_TLS_PIN_HOST, pin.host)
                // Every write from here on is leaf-only; this is what retires the legacy set.
                .putBoolean(KEY_TLS_PINS_ARE_LEAVES, true)
                .commit()
        }
        // Last, and before the suspend returns: a cached pin must never outlive its own durability.
        cachedTlsPin = pin
    }

    /** The currently enforced TLS pin, or null if none was ever captured. */
    fun currentTlsPin(): TlsPin? = cachedTlsPin

    /** False while the stored set still carries whole-chain pins from before the leaf-only rule.
     *  [org.kysecurity.mail.push.PushSyncCoordinator.narrowLegacyTlsPin] acts only on false, so
     *  the narrowing happens exactly once and cannot be undone by a quiet server. */
    fun tlsPinIsLeafOnly(): Boolean = prefs.getBoolean(KEY_TLS_PINS_ARE_LEAVES, false)

    /** The pin, or why there isn't one. "No pin yet" and "the pin is gone" must not be collapsed. */
    fun tlsPinState(): TlsPinState {
        cachedTlsPin?.let { return TlsPinState.Pinned(it) }
        return if (tlsPinTripwire.getBoolean(KEY_TLS_PIN_EVER_CAPTURED, false)) {
            TlsPinState.Lost
        } else {
            TlsPinState.NeverPaired
        }
    }

    private fun readTlsPin(): TlsPin? {
        val host = prefs.getString(KEY_TLS_PIN_HOST, null) ?: return null
        // Copied: SharedPreferences hands back its live cached set, which must not be retained.
        // The legacy single-pin key is the fallback so an upgrade stays connected on its existing
        // leaf; the next successful call re-pins the full chain. See [PushSyncCoordinator].
        val pins = prefs.getStringSet(KEY_TLS_PINS, null)?.let { LinkedHashSet(it) }?.takeIf { it.isNotEmpty() }
            ?: prefs.getString(KEY_TLS_PIN, null)?.let { linkedSetOf(it) }
            ?: return null
        return TlsPin(host = host, spkiSha256 = pins)
    }

    /** Drops pairing proof and the TOFU pin.
     *
     *  [rememberForReconnect] additionally records which account the KEPT account-scoped data
     *  belongs to — see [PushRepository.resetPairingCredential] and [isAccountReplacement]. It is
     *  written in the same commit as the removal it describes: a marker written afterwards can be
     *  lost to process death, and then the next pairing inherits this account's mail in silence.
     *  A second reconnect finds no pairing to name and must leave the first marker standing. */
    suspend fun clearPairing(rememberForReconnect: Boolean = false) {
        val leaving = _pairing.value
        withContext(Dispatchers.IO + NonCancellable) {
            val editor = prefs.edit()
                .remove(KEY_SUBSCRIBER_ID)
                .remove(KEY_DEVICE_SECRET)
                .clearWrappedSecret()
                .remove(KEY_SERVER_URL)
                .remove(KEY_REGISTRATION_URL)
                .remove(KEY_PAIRING_TOKEN)
                .remove(KEY_DEVICE_ID)
                .remove(KEY_PAIRED_AT)
                .remove(KEY_TLS_PIN)
                .remove(KEY_TLS_PINS)
                .remove(KEY_TLS_PIN_HOST)
                .remove(KEY_TLS_PINS_ARE_LEAVES)
            when {
                !rememberForReconnect -> editor.remove(KEY_RECONNECT_SUB).remove(KEY_RECONNECT_SRV)
                leaving != null -> editor
                    .putString(KEY_RECONNECT_SUB, leaving.subscriberId)
                    .putString(KEY_RECONNECT_SRV, leaving.serverUrl)
                else -> Unit
            }
            editor.commit()
            // Deliberate unpair or reconnect: there genuinely is no pin any more, so the marker goes
            // too and the next pairing gets a clean TOFU window rather than being refused as "lost".
            tlsPinTripwire.edit().clear().commit()
        }
        _pairing.value = null
        cachedTlsPin = null
    }

    private fun SharedPreferences.Editor.clearWrappedSecret(): SharedPreferences.Editor =
        remove(KEY_DEVICE_SECRET_CIPHERTEXT)
            .remove(KEY_DEVICE_SECRET_SALT)
            .remove(KEY_DEVICE_SECRET_IV)
            .remove(KEY_DEVICE_SECRET_VERSION)
            .clearPendingSecret()

    private fun SharedPreferences.Editor.clearPendingSecret(): SharedPreferences.Editor =
        remove(KEY_DEVICE_SECRET_PENDING_CIPHERTEXT).remove(KEY_DEVICE_SECRET_PENDING_IV)

    /** Wraps [secret] under [keys] as a SECOND copy, leaving the live one untouched.
     *
     *  A PIN change has to re-wrap the device secret, and the verifier and the wrapping live in
     *  different preference files, so no single `commit()` can swap both. Whichever order they are
     *  written in, a process death between them strands the secret under a key no surviving PIN
     *  derives. Staging removes the window instead of narrowing it: for the duration of the change
     *  BOTH wrappings are on disk, [resolveDeviceSecret] tries each, and so the secret is readable
     *  whether the old or the new PIN ends up authoritative. */
    suspend fun stagePendingSecret(secret: String, keys: CredentialKeys) {
        withContext(Dispatchers.IO + NonCancellable) {
            val wrapped = CredentialCipher.wrap(secret, keys.current)
            prefs.edit()
                .putString(KEY_DEVICE_SECRET_PENDING_CIPHERTEXT, Base64.encodeToString(wrapped.ciphertext, Base64.NO_WRAP))
                .putString(KEY_DEVICE_SECRET_PENDING_IV, Base64.encodeToString(wrapped.iv, Base64.NO_WRAP))
                .commit()
        }
    }

    /** Whether a staged wrapping is still on disk.
     *
     *  A test seam, and a deliberate one: "promoting clears the staged copy" used to be asserted
     *  only through `pairingSnapshot(oldKeys) == null`, which passes whether or not the copy is
     *  actually gone — the staged blob is written under the NEW keys, so the old PIN could never
     *  have opened it either way. The claim is now checkable instead of inferable. */
    internal fun hasPendingSecret(): Boolean = prefs.contains(KEY_DEVICE_SECRET_PENDING_CIPHERTEXT)

    private fun readPairing(credentialKeys: CredentialKeys?): PairingData? {
        val subId = prefs.getString(KEY_SUBSCRIBER_ID, null).orEmpty()
        val serverUrl = prefs.getString(KEY_SERVER_URL, null).orEmpty()
        val registrationUrl = prefs.getString(KEY_REGISTRATION_URL, null).orEmpty()
        val pairingToken = prefs.getString(KEY_PAIRING_TOKEN, null).orEmpty()
        val pairedAt = if (prefs.contains(KEY_PAIRED_AT)) prefs.getLong(KEY_PAIRED_AT, 0L) else null

        if (subId.isBlank() || serverUrl.isBlank() ||
            registrationUrl.isBlank() || pairingToken.isBlank() || pairedAt == null
        ) {
            return null
        }

        return PairingData(
            subscriberId = subId,
            serverUrl = serverUrl,
            registrationUrl = registrationUrl,
            pairingToken = pairingToken,
            deviceId = prefs.getString(KEY_DEVICE_ID, null),
            deviceSecret = resolveDeviceSecret(credentialKeys),
            pairedAtEpochMs = pairedAt,
        )
    }

    private fun resolveDeviceSecret(credentialKeys: CredentialKeys?): String? {
        val wrappedCiphertext = prefs.getString(KEY_DEVICE_SECRET_CIPHERTEXT, null)
            ?: return prefs.getString(KEY_DEVICE_SECRET, null)
        val keys = credentialKeys ?: return null
        // The live wrapping first; the staged one only if that fails. During a PIN change exactly
        // one of them opens under the PIN that is currently authoritative, and which one depends on
        // where the change was interrupted — so trying both is the whole point. See [stagePendingSecret].
        return unwrapLive(wrappedCiphertext, keys) ?: unwrapPending(keys)
    }

    private fun unwrapPending(keys: CredentialKeys): String? {
        val ciphertext = prefs.getString(KEY_DEVICE_SECRET_PENDING_CIPHERTEXT, null) ?: return null
        val iv = prefs.getString(KEY_DEVICE_SECRET_PENDING_IV, null) ?: return null
        return CredentialCipher.unwrap(
            WrappedSecret(Base64.decode(iv, Base64.NO_WRAP), Base64.decode(ciphertext, Base64.NO_WRAP)),
            keys.current,
        )
    }

    private fun unwrapLive(wrappedCiphertext: String, keys: CredentialKeys): String? {
        val iv = prefs.getString(KEY_DEVICE_SECRET_IV, null)?.let { Base64.decode(it, Base64.NO_WRAP) } ?: return null
        val ciphertext = Base64.decode(wrappedCiphertext, Base64.NO_WRAP)
        // The salt (KEY_DEVICE_SECRET_SALT) isn't read here — the keys were already derived from
        // it by the caller (see AppLockManager); it's exposed separately for that derivation.
        val key = when (prefs.getInt(KEY_DEVICE_SECRET_VERSION, SECRET_VERSION_LEGACY)) {
            SECRET_VERSION_PEPPERED -> keys.current
            else -> keys.legacy
        }
        return CredentialCipher.unwrap(WrappedSecret(iv, ciphertext), key)
    }

    /** See [openEncryptedPrefs]. A reset costs the pairing and the TOFU pin — keyset failures only. */
    private fun buildEncryptedPrefs(appContext: Context): SharedPreferences =
        openEncryptedPrefs(appContext, ENCRYPTED_PREFS_FILE_NAME) {
            android.util.Log.e("SecurePairingStore", "Encrypted pairing store keyset is undecryptable", it)
        }

    companion object {
        /** Bare PBKDF2 wrapping key, written by builds before the Keystore pepper existed. Read-only
         *  — [needsCredentialRewrap] reports these so they get migrated on the next PIN unlock. */
        const val SECRET_VERSION_LEGACY = 1

        /** PBKDF2 output mixed with the non-exportable Keystore pepper; see [CredentialCipher]. */
        const val SECRET_VERSION_PEPPERED = 2
    }
}
