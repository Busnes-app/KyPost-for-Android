package org.kysecurity.mail

import android.content.Intent
import android.os.Bundle
import androidx.lifecycle.lifecycleScope
import org.kysecurity.mail.push.PushNotificationDispatcher
import org.kysecurity.mail.push.PushRuntime
import org.kysecurity.mail.security.LockedActivity
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

/** Routes in [onStart], strictly after [LockedActivity]'s lock check, never in `onCreate`. */
class MainActivity : LockedActivity() {

    private var routed = false

    /** This screen finishes itself as soon as it has routed, so the startup notices belong to
     *  whatever it routes to — claimed here, they would go down with it unseen. */
    override val showsStartupNotices: Boolean = false

    override fun onCreateUnlocked(savedInstanceState: Bundle?) {
        routed = savedInstanceState?.getBoolean(STATE_ROUTED, false) ?: false
    }

    override fun onStartUnlocked() {
        // LockedActivity.onStart finishes us and shows UnlockActivity when the app is locked.
        if (isFinishing || routed) return
        routed = true
        handleIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (redirectedToUnlock) return
        setIntent(intent)
        if (isLocked()) {
            startActivity(Intent(this, org.kysecurity.mail.security.UnlockActivity::class.java))
            finish()
            return
        }
        handleIntent(intent)
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        if (redirectedToUnlock) return
        outState.putBoolean(STATE_ROUTED, routed)
    }

    private fun handleIntent(intent: Intent) {
        lifecycleScope.launch {
            val configured = PushRuntime.graph(this@MainActivity).repository.state.first().pairing != null

            // An "Add account" request the app-lock redirect interrupted resumes where it was going.
            // Process-local state, never read from the (exported) launch intent.
            val targetIntent = if (org.kysecurity.mail.contacts.device.PendingAccountSetup.isPending) {
                Intent(this@MainActivity, org.kysecurity.mail.contacts.ContactsListActivity::class.java)
                    .putExtra(org.kysecurity.mail.contacts.ContactsListActivity.EXTRA_ACCOUNT_SETUP, true)
            } else if (configured) {
                Intent(this@MainActivity, InboxActivity::class.java).apply {
                    notificationExtras(intent)?.let { putExtras(it) }
                }
            } else {
                Intent(this@MainActivity, org.kysecurity.mail.push.PushPairingActivity::class.java)
            }
            startActivity(targetIntent)
            finish()
        }
    }

    /** Exported via LAUNCHER, so extras are attacker-reachable: accept only token-signed ones. */
    private fun notificationExtras(intent: Intent): Bundle? {
        val msgId = intent.getStringExtra(PushNotificationDispatcher.EXTRA_MESSAGE_ID) ?: return null
        if (!org.kysecurity.mail.push.NotificationIntentToken.matches(
                this,
                intent.getStringExtra(PushNotificationDispatcher.EXTRA_INTENT_TOKEN),
            )
        ) {
            android.util.Log.w("MainActivity", "Ignoring notification extras from an unauthenticated intent")
            return null
        }
        return Bundle().apply {
            putString(PushNotificationDispatcher.EXTRA_MESSAGE_ID, msgId)
            putString(PushNotificationDispatcher.EXTRA_SENDER, intent.getStringExtra(PushNotificationDispatcher.EXTRA_SENDER))
            putString(PushNotificationDispatcher.EXTRA_SUBJECT, intent.getStringExtra(PushNotificationDispatcher.EXTRA_SUBJECT))
        }
    }

    private companion object {
        const val STATE_ROUTED = "routed"
    }
}
