package org.kysecurity.mail.pgp

import androidx.annotation.VisibleForTesting
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.kysecurity.mail.ProcessScopedState
import org.kysecurity.mail.ProcessState

/**
 * Holds the opened material for one unlock session: either the legacy armored collection, as a
 * wipeable [CharArray], or one validated complete [PgpKeyring]. Consumers never see the raw
 * material; they get scoped access to the decryption keys or to the explicit active signer, and
 * the legacy armor only where the legacy merge needs it.
 */
internal object EnrollmentSession : ProcessScopedState {

    init { ProcessState.register(this) }

    private sealed class Held {
        class Legacy(val armor: CharArray) : Held()
        class Keyring(val ring: PgpKeyring) : Held()
    }

    @Volatile
    private var held: Held? = null

    override fun resetForNewSession() = clear()

    /** Clears first, so replacing a key does not strand the previous one in the heap. */
    fun put(armoredKey: CharArray) {
        clear()
        held = Held.Legacy(armoredKey.copyOf())
    }

    /** Decodes UTF-8 [plaintext] straight into the held [CharArray], never building a `String`. */
    fun putUtf8(plaintext: ByteArray) {
        val decoded = Charsets.UTF_8.decode(java.nio.ByteBuffer.wrap(plaintext))
        val chars = CharArray(decoded.remaining()).also { decoded.get(it) }
        try {
            put(chars)
        } finally {
            java.util.Arrays.fill(chars, ' ')
            if (decoded.hasArray()) java.util.Arrays.fill(decoded.array(), ' ')
        }
    }

    /** Takes ownership of a validated ring; [clear] wipes it. */
    fun putKeyring(ring: PgpKeyring) {
        clear()
        held = Held.Keyring(ring)
    }

    /** True while material is held, with no copy minted to answer it. */
    fun isHeld(): Boolean = held != null

    /**
     * Every private key that may decrypt, as a provider so legacy armor is parsed inside the
     * decryptor's own failure handling. A keyring yields all members: history is retained for old
     * mail, and a hidden recipient can only be found by trying them.
     */
    fun <T> withDecryptionKeys(block: (() -> PGPSecretKeyRingCollection) -> T): T? = when (val h = held) {
        null -> null
        is Held.Legacy -> block {
            h.armor.useArmoredStream { PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(it), BcKeyFingerprintCalculator()) }
        }
        is Held.Keyring -> block { PGPSecretKeyRingCollection(h.ring.members.map { it.ring }) }
    }

    /**
     * The one ring that signs and that self-encryption targets: the explicit active member of a
     * keyring, or the first (current) ring of legacy armor. A null argument means no usable
     * signer, which callers must fail on; a historical member is never substituted.
     */
    fun <T> withSigner(block: (PGPSecretKeyRing?) -> T): T? = when (val h = held) {
        null -> null
        is Held.Legacy -> block(runCatching { h.armor.useArmoredStream(::orderedSecretKeyRings)?.firstOrNull() }.getOrNull())
        is Held.Keyring -> block(h.ring.active.ring)
    }

    /** Legacy armor only, for the legacy merge. Null when nothing or a keyring is held, so a
     *  keyring can never be fed to an armor parser. */
    fun <T> withLegacyArmor(block: (CharArray) -> T): T? = (held as? Held.Legacy)?.let { block(it.armor) }

    /** The held keyring only. Null when nothing or legacy armor is held. */
    fun <T> withKeyring(block: (PgpKeyring) -> T): T? = (held as? Held.Keyring)?.let { block(it.ring) }

    /** Test-only view of held legacy armor. Never call this from production code. */
    @VisibleForTesting
    fun peekForTest(): String? = (held as? Held.Legacy)?.let { String(it.armor) }

    fun clear() {
        when (val h = held) {
            is Held.Legacy -> h.armor.fill(' ')
            is Held.Keyring -> h.ring.wipe()
            null -> Unit
        }
        held = null
    }

    @VisibleForTesting
    fun backingArrayForTest(): CharArray = (held as Held.Legacy).armor
}

/** What an opened record becomes. False means the plaintext did not match its declared kind, and
 *  nothing was installed. */
internal fun installOpenedMaterial(kind: VaultRecordKind, plaintext: ByteArray): Boolean = when (kind) {
    VaultRecordKind.LEGACY_ARMOR -> {
        EnrollmentSession.putUtf8(plaintext)
        true
    }
    VaultRecordKind.KEYRING -> {
        val ring = reopenPgpKeyring(plaintext)
        if (ring != null) EnrollmentSession.putKeyring(ring)
        ring != null
    }
}
