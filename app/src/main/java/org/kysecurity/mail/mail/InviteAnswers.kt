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
 *  Protection (its enable path deletes the file too). */
class InviteAnswers(private val prefs: SharedPreferences) {
    fun record(event: CalendarEvent, attendee: String, answer: Rsvp, now: Long) {
        val all = prefs.all
        val editor = prefs.edit().putString(answerKey(event, attendee), answerRecord(event, answer, now))
        // Oldest first past the cap; the key being written is already counted.
        all.entries.sortedBy { (it.value as? String)?.substringAfterLast('|')?.toLongOrNull() ?: 0 }
            .take((all.size + 1 - MAX_ANSWERS).coerceAtLeast(0))
            .forEach { editor.remove(it.key) }
        editor.apply()
    }

    fun prior(event: CalendarEvent, attendee: String): PriorAnswer =
        priorAnswer(event, prefs.getString(answerKey(event, attendee), null))

    companion object {
        const val PREFS_NAME = "org.kysecurity.mail.invite_answers"
        internal const val MAX_ANSWERS = 200

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
