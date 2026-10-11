package org.kysecurity.mail

import com.google.android.material.snackbar.BaseTransientBottomBar

/** Row actions held back while the Undo bar shows. Main thread only. There is one bar for all of
 *  them, so they are taken back together and sent together: each runs exactly once, at [flush],
 *  or never if [undoAll] got there first. */
internal class PendingRowActions {

    private class Entry(val emails: List<Email>, val run: () -> Unit)

    private val held = mutableListOf<Entry>()

    fun hold(emails: List<Email>, run: () -> Unit) {
        held += Entry(emails, run)
    }

    /** False when nothing was held, so there was nothing left to take back. */
    fun undoAll(): Boolean {
        val any = held.isNotEmpty()
        held.clear()
        return any
    }

    /** Runs everything still held: the bar timed out, was swiped away, or the screen was left. */
    fun flush() {
        val due = held.toList()
        held.clear()
        due.forEach { it.run() }
    }

    fun heldCount(): Int = held.size

    fun heldEmails(): List<Email> = held.flatMap { it.emails }
}

/** Whether the Undo bar going away commits what it covers. Its timeout follows the system's
 *  accessibility setting, so the bar, not a separate timer, decides when the window closes. A bar
 *  replaced by the next one hands its actions on; one the user acted on was an Undo. */
internal fun commitsOnDismiss(event: Int): Boolean =
    event == BaseTransientBottomBar.BaseCallback.DISMISS_EVENT_TIMEOUT ||
        event == BaseTransientBottomBar.BaseCallback.DISMISS_EVENT_SWIPE
