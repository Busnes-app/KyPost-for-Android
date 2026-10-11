package org.kysecurity.mail

import org.kysecurity.mail.mail.OutgoingAttachment

/** Survives [LockedActivity] finishing a compose screen. In-memory only, never on disk. */
object ComposeDraftCache : ProcessScopedState {
    @Volatile
    private var draft: CachedDraft? = null

    /** Sealed on [clear] so a late async `onStop` callback cannot resurrect a wiped draft. */
    @Volatile
    private var sealed: Boolean = false

    init {
        ProcessState.register(this)
    }

    fun save(draft: CachedDraft) {
        if (sealed) return
        this.draft = draft.takeIf { it.hasContent() }
    }

    /** Returns and clears, and unseals: a screen asking for the draft is a live session. */
    fun take(): CachedDraft? {
        val current = draft
        draft = null
        sealed = false
        return current
    }

    fun clear() {
        draft = null
        sealed = true
    }

    /** Zeroes rather than merely dropping — see [ForwardAttachmentHandoff.resetForNewSession].
     *  [clear] deliberately does NOT: an ordinary "draft consumed" drop shares these instances with
     *  a compose screen that may still be alive, and only a session boundary owns them outright. */
    override fun resetForNewSession() {
        draft?.attachments?.forEach { it.wipe() }
        clear()
    }
}

data class CachedDraft(
    val to: String,
    val cc: String,
    val bcc: String,
    val subject: String,
    val bodyHtml: String,
    val attachments: List<OutgoingAttachment>,
    /** Cached so a fold cannot reset Encrypt and send in the clear. Not part of [hasContent]. */
    val encrypt: Boolean = false,
    val sign: Boolean = false,
    /** Kept so a reply restored after the app lock still threads. Not part of [hasContent]. */
    val replyTo: ReplyRef? = null,
) {
    /** An untouched compose screen is not worth restoring, and caching it would silently
     *  resurrect an empty draft over a later Reply's prefilled fields. */
    fun hasContent(): Boolean =
        to.isNotBlank() || cc.isNotBlank() || bcc.isNotBlank() ||
            subject.isNotBlank() || attachments.isNotEmpty() ||
            bodyHtml.isNotBlank()
}
