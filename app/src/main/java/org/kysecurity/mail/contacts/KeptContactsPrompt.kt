package org.kysecurity.mail.contacts

import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.kysecurity.mail.R
import org.kysecurity.mail.push.pairingUrlHost
import org.kysecurity.mail.showThemed

/** "Bring your N contacts into <server>?" (owner decision Q2). Asked after pairing and whenever the
 *  contacts screen opens until answered; nothing uploads before the answer. The message is the
 *  Play prominent disclosure for that upload (#282), so Bring them is the consent. */
object KeptContactsPrompt {
    fun showIfNeeded(activity: AppCompatActivity, onAnswered: () -> Unit = {}) {
        activity.lifecycleScope.launch {
            val graph = ContactsRuntime.graph(activity)
            // Keystore-backed prefs and an AES unwrap: off the main thread.
            val question = withContext(Dispatchers.IO) { graph.repository.keptContactsQuestion() } ?: return@launch
            val count = question.count
            val host = pairingUrlHost(question.account.serverUrl) ?: return@launch
            if (activity.isFinishing || activity.isDestroyed) return@launch
            AlertDialog.Builder(activity)
                .setTitle(activity.resources.getQuantityString(R.plurals.kept_contacts_title, count, count, host))
                .setMessage(activity.getString(R.string.kept_contacts_message, host))
                .setPositiveButton(R.string.kept_contacts_bring) { _, _ ->
                    activity.lifecycleScope.launch {
                        withContext(Dispatchers.IO) { graph.repository.bringKeptContacts(question.account) }
                        graph.coordinator.syncNowAsync()
                        onAnswered()
                    }
                }
                .setNegativeButton(R.string.kept_contacts_remove) { _, _ ->
                    activity.lifecycleScope.launch {
                        withContext(Dispatchers.IO) { graph.repository.removeKeptContacts(question.account) }
                        graph.coordinator.syncNowAsync()
                        onAnswered()
                    }
                }
                .showThemed()
        }
    }
}
