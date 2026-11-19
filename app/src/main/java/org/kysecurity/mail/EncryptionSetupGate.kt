package org.kysecurity.mail

import org.kysecurity.mail.mail.MailOutcome

/** The inbox's "finish encryption setup" state (KyPost-Server #666). Entered on the relay's
 *  `encryption_setup_required` 403, left only by a later successful mailbox call; any other
 *  failure (offline, 502) leaves it as it was. It owns no credentials, keys or drafts, so
 *  entering it can never sign out or drop unsent mail. */
internal class EncryptionSetupGate {
    /** True while mail is withheld: the setup screen shows and polling stays stopped. */
    var blocked = false
        private set

    /** The server's wording, null to use the app's own. */
    var serverMessage: String? = null
        private set

    /** Returns true when [blocked] changed. */
    fun record(outcome: MailOutcome<*>): Boolean {
        val was = blocked
        when (outcome) {
            is MailOutcome.EncryptionSetupRequired -> {
                blocked = true
                serverMessage = outcome.message
            }
            is MailOutcome.Success -> {
                blocked = false
                serverMessage = null
            }
            else -> Unit
        }
        return blocked != was
    }
}
