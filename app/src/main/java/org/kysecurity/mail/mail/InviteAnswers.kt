package org.kysecurity.mail.mail

import android.content.Context
import android.content.SharedPreferences
import java.security.MessageDigest

enum class InviteChange { TIME, PLACE, TITLE }

sealed interface PriorAnswer {
    data object None : PriorAnswer

    /** This revision, or a later one, was answered. */
    data class Same(val answer: Rsvp) : PriorAnswer

    /** A newer revision than the one answered: higher SEQUENCE or, at equal SEQUENCE, a later DTSTAMP. */
    data class Newer(val answer: Rsvp, val changed: List<InviteChange>) : PriorAnswer
}

/** The answered revision of each invite (KyPost-Server docs/NATIVE-RSVP.md "Updates"), as the web
 *  client keeps it: digests only, no title, place, time, address or UID stored readable.
 *  Account-scoped: the pairing purge deletes the file, and nothing is kept under Hostile Location
 *  Protection: its enable path turns protection on and deletes the file inside [withWritesBlocked]. */
class InviteAnswers(private val prefs: SharedPreferences) {
    /** Writes, synchronously, unless [protectionOn]; checked under the same lock as the enable
     *  path, so a late answer can neither outlive the purge nor land after it. Not on the main thread. */
    fun record(event: CalendarEvent, attendee: String, answer: Rsvp, now: Long, protectionOn: () -> Boolean) =
        synchronized(LOCK) {
            if (protectionOn()) return@synchronized
            val key = answerKey(event, attendee)
            val all = prefs.all
            val editor = prefs.edit().putString(key, answerRecord(event, answer, now))
            // Oldest first past the cap; the key being written counts unless it is already there.
            val excess = all.size + (if (key in all) 0 else 1) - MAX_ANSWERS
            all.entries.filter { it.key != key }
                .sortedBy { (it.value as? String)?.substringAfterLast('|')?.toLongOrNull() ?: 0 }
                .take(excess.coerceAtLeast(0))
                .forEach { editor.remove(it.key) }
            editor.commit()
        }

    fun prior(event: CalendarEvent, attendee: String): PriorAnswer =
        priorAnswer(event, prefs.getString(answerKey(event, attendee), null))

    companion object {
        const val PREFS_NAME = "org.kysecurity.mail.invite_answers"
        internal const val MAX_ANSWERS = 200
        private val LOCK = Any()

        /** Runs [block] with every [record] held off; the enable path flips protection and
         *  deletes the file in here. */
        fun <T> withWritesBlocked(block: () -> T): T = synchronized(LOCK, block)

        fun from(context: Context) = InviteAnswers(context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE))
    }
}

private fun digest(value: String): String =
    MessageDigest.getInstance("SHA-256").digest(value.toByteArray()).take(16).joinToString("") { "%02x".format(it) }

internal fun answerKey(event: CalendarEvent, attendee: String): String =
    digest("${attendee.lowercase()}\u0000${event.organizer.lowercase()}\u0000${event.uid}")

private fun whenDigest(e: CalendarEvent) = digest("${e.begin.toEpochMilli()}|${e.end.toEpochMilli()}|${e.allDay}")

/** `seq|stamp|when|title|place|PARTSTAT|at`: every text field is a digest. */
internal fun answerRecord(event: CalendarEvent, answer: Rsvp, now: Long): String =
    listOf(event.sequence, event.stamp, whenDigest(event), digest(event.summary), digest(event.location), answer.name, now)
        .joinToString("|")

internal fun priorAnswer(event: CalendarEvent, stored: String?): PriorAnswer {
    if (!event.canReply) return PriorAnswer.None
    val f = stored?.split('|')?.takeIf { it.size == 7 } ?: return PriorAnswer.None
    val seq = f[0].toIntOrNull() ?: return PriorAnswer.None
    val stamp = f[1].toLongOrNull() ?: return PriorAnswer.None
    val answer = Rsvp.entries.firstOrNull { it.name == f[5] } ?: return PriorAnswer.None
    if (event.sequence < seq || (event.sequence == seq && event.stamp <= stamp)) return PriorAnswer.Same(answer)
    return PriorAnswer.Newer(
        answer,
        listOfNotNull(
            InviteChange.TIME.takeIf { f[2] != whenDigest(event) },
            InviteChange.PLACE.takeIf { f[4] != digest(event.location) },
            InviteChange.TITLE.takeIf { f[3] != digest(event.summary) },
        ),
    )
}
