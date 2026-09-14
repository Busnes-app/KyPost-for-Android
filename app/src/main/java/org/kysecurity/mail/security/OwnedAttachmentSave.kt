package org.kysecurity.mail.security

import java.util.Arrays

/** Owns the one save snapshot allowed to outlive decrypted-message UI state. */
internal class OwnedAttachmentSave {
    private var accepting = false
    private var active: ByteArray? = null

    @Synchronized
    fun allow() {
        accepting = true
    }

    @Synchronized
    fun stopAccepting() {
        accepting = false
    }

    /** Copies only after confirmation and refuses both stale lifecycle callbacks and a second save. */
    @Synchronized
    fun admit(source: ByteArray, lifecycleValid: Boolean): ByteArray? {
        if (!accepting || !lifecycleValid || active != null) return null
        return source.copyOf().also { active = it }
    }

    /** The admitted write owns its snapshot through lock/destroy, then wipes and releases it. */
    @Synchronized
    fun finish(snapshot: ByteArray) {
        if (active !== snapshot) return
        Arrays.fill(snapshot, 0)
        active = null
    }
}
