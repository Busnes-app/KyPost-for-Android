// androidx.security-crypto is deprecated with no replacement; swapping it is a format migration.
@file:Suppress("DEPRECATION")

package org.kysecurity.mail.security

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.GeneralSecurityException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

private const val TAG = "EncryptedPrefs"

/** Plain, so it survives the reset it reports; not in [SecurityWipe]'s retained set. */
internal const val CREDENTIAL_RESET_PREFS = "org.kysecurity.mail.credential_reset"

/** The ONE AndroidKeyStore alias every encrypted store in this app is sealed under.
 *
 *  Named here rather than left implicit in [createEncryptedPrefs]'s defaulted builder, because
 *  [SecurityWipe] has to destroy it: deleting the prefs FILES without this key leaves a recovered
 *  blob decryptable, which is the same argument the credential peppers already carry. */
internal val ENCRYPTED_PREFS_MASTER_KEY_ALIAS: String = MasterKey.DEFAULT_MASTER_KEY_ALIAS

private const val ANDROID_KEYSTORE = "AndroidKeyStore"

/** Retries before a failure is classified at all. AndroidKeyStore is routinely unavailable for a
 *  few hundred milliseconds around boot, and that window used to be enough to destroy a mailbox. */
private const val OPEN_ATTEMPTS = 3
private const val OPEN_RETRY_BACKOFF_MS = 120L

/** Opening failed and the store is NOT known to be unrecoverable, so nothing was deleted.
 *
 *  Callers must treat this as "unknown", never as "empty". [AppLockStore.tripwireBroken] answers
 *  null on it and [LockedActivity] blocks — because the alternative, which this app shipped, was
 *  reading a transient Keystore fault as a vanished PIN hash and wiping the device over it. */
class EncryptedStoreUnavailableException(fileName: String, cause: Throwable) :
    IllegalStateException("Encrypted store '$fileName' could not be opened", cause)

/**
 * Opens [fileName], resetting it ONLY when the keyset is provably undecryptable.
 *
 * "Provably" is the whole contract. Deleting an encrypted store is destruction of user data and
 * [AppLockStore.tripwireBroken] turns an empty app-lock store into a full device wipe, so the bar
 * for it is positive evidence — the three proofs [isUnrecoverableKeyset] accepts — and never
 * merely "an exception came out of Tink". Everything else throws
 * [EncryptedStoreUnavailableException] and the app blocks until the next launch.
 */
internal fun openEncryptedPrefs(
    context: Context,
    fileName: String,
    onReset: (Throwable) -> Unit = {},
): SharedPreferences {
    val appContext = context.applicationContext
    var last: Throwable? = null
    repeat(OPEN_ATTEMPTS) { attempt ->
        try {
            return createEncryptedPrefs(appContext, fileName)
        } catch (e: GeneralSecurityException) {
            last = e
        } catch (e: java.io.IOException) {
            // Tink reports an unreadable keyset as an IOException too, so neither exception type
            // classifies on its own; [isUnrecoverableKeyset] is the only thing that decides.
            last = e
        }
        if (attempt < OPEN_ATTEMPTS - 1) Thread.sleep(OPEN_RETRY_BACKOFF_MS)
    }

    val cause = last ?: IllegalStateException("Encrypted store '$fileName' would not open")
    if (!isUnrecoverableKeyset(cause)) {
        Log.e(TAG, "Encrypted store '$fileName' could not be opened; NOT resetting it", cause)
        throw EncryptedStoreUnavailableException(fileName, cause)
    }
    return resetUnreadableStore(appContext, fileName, cause, onReset)
}

/** True only on positive evidence that nothing can ever open this store again.
 *
 *  Three proofs are accepted, and no others. A keyset that will not parse is destroyed by
 *  definition; a master key alias the Keystore CONFIRMS is absent can never decrypt one; and a
 *  master key that demonstrably still encrypts and decrypts, under a store that still will not
 *  yield key material, locates the fault in the stored keyset rather than in the Keystore.
 *
 *  A Keystore that merely refuses to answer proves nothing and is not one of them — the version
 *  of this function before the retry loop answered true for every [GeneralSecurityException],
 *  which made it a tautology over the branch that called it. */
internal fun isUnrecoverableKeyset(failure: Throwable): Boolean =
    isUnrecoverableKeyset(failure, masterKeyState())

/** Split from the Keystore lookup only so the whole truth table can be asserted off a device;
 *  there is no AndroidKeyStore on the JVM, and this decision is too load-bearing to leave to
 *  the one row an emulator suite happens to reach. */
internal fun isUnrecoverableKeyset(failure: Throwable, keyState: MasterKeyState): Boolean {
    // Bounded: a cause chain does not legitimately nest this deep, and a cyclic one would hang
    // app startup, since this decides whether LockedActivity can build the security graph at all.
    val chain = generateSequence(failure) { it.cause }.take(MAX_CAUSE_DEPTH).toList()
    if (chain.any { it.isProtobufParseFailure() }) return true
    return when (keyState) {
        MasterKeyState.ABSENT -> true
        // Only a crypto failure. An IOException under a healthy key is the disk — no space, not
        // mounted yet — and the disk comes back; the keyset it could not read is still intact.
        MasterKeyState.WORKING -> chain.any { it is GeneralSecurityException }
        MasterKeyState.UNKNOWN -> false
    }
}

private const val MAX_CAUSE_DEPTH = 16

/** What the Keystore says about the one key every encrypted store in this app is sealed under.
 *  [UNKNOWN] is the answer that destroys nothing, and every uncertainty collapses into it. */
internal enum class MasterKeyState { ABSENT, WORKING, UNKNOWN }

/** Asks the Keystore, rather than inferring from whatever exception Tink chose.
 *
 *  The round trip is the point. Tink hides real corruption behind bare [GeneralSecurityException]s
 *  — a keyset carrying no key material reads as "empty keyset", and a keyset whose ciphertext no
 *  longer verifies reads as an unattributed decrypt failure — and neither is distinguishable from
 *  a Keystore that is briefly unwell, WHICH IS THE FAULT THAT MUST NOT DELETE ANYTHING. Proving
 *  the key itself still works separates them: past this, the bytes on disk are the only suspect. */
private fun masterKeyState(): MasterKeyState = runCatching {
    val keystore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    if (!keystore.containsAlias(ENCRYPTED_PREFS_MASTER_KEY_ALIAS)) return@runCatching MasterKeyState.ABSENT
    val key = keystore.getKey(ENCRYPTED_PREFS_MASTER_KEY_ALIAS, null) as? SecretKey
        ?: return@runCatching MasterKeyState.UNKNOWN
    if (key.roundTripsAProbe()) MasterKeyState.WORKING else MasterKeyState.UNKNOWN
}.getOrElse {
    Log.e(TAG, "Could not establish whether the master key still works", it)
    MasterKeyState.UNKNOWN
}

/** Positive evidence the Keystore is answering: its master key seals and opens a probe. Callers
 *  about to delete something on the strength of a "no such alias" answer need this, because an
 *  unwell Keystore and an absent key look the same from one read. */
internal fun keystoreAnswers(): Boolean = masterKeyState() == MasterKeyState.WORKING

private const val GCM_TAG_BITS = 128

/** The master key's own scheme, AES256_GCM with randomized encryption: no IV may be supplied. */
private fun SecretKey.roundTripsAProbe(): Boolean = runCatching {
    val probe = "keystore round trip".toByteArray()
    val seal = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, this@roundTripsAProbe) }
    val sealed = seal.doFinal(probe)
    val open = Cipher.getInstance("AES/GCM/NoPadding").apply {
        init(Cipher.DECRYPT_MODE, this@roundTripsAProbe, GCMParameterSpec(GCM_TAG_BITS, seal.iv))
    }
    open.doFinal(sealed).contentEquals(probe)
}.getOrElse {
    Log.e(TAG, "The Keystore master key would not complete a round trip", it)
    false
}

/** Walks the hierarchy: subclasses have their own simpleName, and the type is in shaded Tink. */
private fun Throwable.isProtobufParseFailure(): Boolean =
    generateSequence(javaClass as Class<*>?) { it.superclass }
        .any { it.simpleName == "InvalidProtocolBufferException" }

private fun resetUnreadableStore(
    appContext: Context,
    fileName: String,
    cause: Throwable,
    onReset: (Throwable) -> Unit,
): SharedPreferences {
    onReset(cause)
    Log.e(TAG, "Encrypted store '$fileName' keyset is undecryptable; resetting", cause)
    recordCredentialReset(appContext, fileName)
    appContext.deleteSharedPreferences(fileName)
    return createEncryptedPrefs(appContext, fileName)
}

internal fun recordCredentialReset(context: Context, fileName: String) {
    val prefs = context.applicationContext
        .getSharedPreferences(CREDENTIAL_RESET_PREFS, Context.MODE_PRIVATE)
    val existing = prefs.getStringSet(KEY_RESET_STORES, emptySet()).orEmpty()
    prefs.edit().putStringSet(KEY_RESET_STORES, existing + fileName).commit()
}

fun credentialResetsPending(context: Context): Set<String> =
    context.applicationContext
        .getSharedPreferences(CREDENTIAL_RESET_PREFS, Context.MODE_PRIVATE)
        .getStringSet(KEY_RESET_STORES, emptySet()).orEmpty()

fun acknowledgeCredentialResets(context: Context) {
    context.applicationContext
        .getSharedPreferences(CREDENTIAL_RESET_PREFS, Context.MODE_PRIVATE)
        .edit().remove(KEY_RESET_STORES).commit()
}

private const val KEY_RESET_STORES = "reset_stores"

private fun createEncryptedPrefs(appContext: Context, fileName: String): SharedPreferences {
    // Alias named explicitly, not left to the defaulted constructor: SecurityWipe destroys this
    // key by name, and the two must not be able to drift apart.
    val masterKey = MasterKey.Builder(appContext, ENCRYPTED_PREFS_MASTER_KEY_ALIAS)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()
    return EncryptedSharedPreferences.create(
        appContext,
        fileName,
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )
}
