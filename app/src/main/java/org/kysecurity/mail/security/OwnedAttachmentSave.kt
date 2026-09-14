package org.kysecurity.mail.security

import java.util.Arrays

/** Owns the one save snapshot allowed to outlive decrypted-message UI state. */
internal class OwnedAttachmentSave {
    private var accepting = false
    private var active: ByteArray? = null
    private var started = false

    @Synchronized
    fun allow() {
        accepting = true
    }

    @Synchronized
    fun stopAccepting() {
        accepting = false
        if (!started) {
            active?.let { Arrays.fill(it, 0) }
            active = null
        }
    }

    /** Copies only after confirmation and refuses both stale lifecycle callbacks and a second save. */
    @Synchronized
    fun admit(source: ByteArray, lifecycleValid: Boolean): ByteArray? {
        if (!accepting || !lifecycleValid || active != null) return null
        return source.copyOf().also {
            active = it
            started = false
        }
    }

    /** Claims a queued snapshot; false means lifecycle cleanup canceled and wiped it first. */
    @Synchronized
    fun begin(snapshot: ByteArray): Boolean {
        if (active !== snapshot) return false
        started = true
        return true
    }

    /** The admitted write owns its snapshot through lock/destroy, then wipes and releases it. */
    @Synchronized
    fun finish(snapshot: ByteArray) {
        if (active !== snapshot) return
        Arrays.fill(snapshot, 0)
        active = null
        started = false
    }
}
