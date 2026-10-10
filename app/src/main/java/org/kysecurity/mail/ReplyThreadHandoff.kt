package org.kysecurity.mail

import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/** The message a reply answers, by list id and folder (KyPost-Server #352 threads from it). */
data class ReplyRef(val messageId: String, val mailbox: String)

/** Not an Intent extra: ComposeActivity is exported, and an extra any app can set would let it
 *  thread a message it prefilled onto one in this mailbox. The Intent carries only a random token. */
object ReplyThreadHandoff : ProcessScopedState {
    private val pending = ConcurrentHashMap<String, ReplyRef>()

    init {
        ProcessState.register(this)
    }

    override fun resetForNewSession() = pending.clear()

    fun put(ref: ReplyRef): String = UUID.randomUUID().toString().also { pending[it] = ref }

    fun take(token: String?): ReplyRef? = token?.let { pending.remove(it) }
}
