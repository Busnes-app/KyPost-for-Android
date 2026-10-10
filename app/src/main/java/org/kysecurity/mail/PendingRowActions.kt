package org.kysecurity.mail

/** Row actions held back for the undo window. Main thread only. Each held action runs at most
 *  once: when its timer calls [commit], when [flush] runs, or never if [undo] got there first. */
internal class PendingRowActions {

    class Entry(val emails: List<Email>, internal val run: () -> Unit)

    private val held = mutableListOf<Entry>()

    fun hold(emails: List<Email>, run: () -> Unit): Entry = Entry(emails, run).also { held += it }

    fun commit(entry: Entry) {
        if (held.remove(entry)) entry.run()
    }

    /** False when the action already ran, so there is nothing left to take back. */
    fun undo(entry: Entry): Boolean = held.remove(entry)

    /** Runs everything still held: leaving the screen confirms what the user did there. */
    fun flush() {
        val due = held.toList()
        held.clear()
        due.forEach { it.run() }
    }

    fun heldEmails(): List<Email> = held.flatMap { it.emails }
}
