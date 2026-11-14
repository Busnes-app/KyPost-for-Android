package org.kysecurity.mail.mail

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update

/** [CONFIRM_MAIL]: KyCalendar said to answer by mail, and the user has not confirmed yet. */
enum class RsvpPhase { PENDING, SENT, UNSURE, CONFIRM_MAIL }

/** A mailed fallback waiting for the user: the [answer] they chose, and why KyCalendar declined. */
data class MailFallback(val answer: Rsvp, val noEvent: Boolean)

data class RsvpState(val phase: RsvpPhase, val fallback: MailFallback? = null)

/** One answerable revision: a raised SEQUENCE, or a later DTSTAMP at the same one, is a new
 *  invite to answer. */
fun rsvpKey(event: CalendarEvent): String =
    listOf(event.uid, event.recurrenceId.orEmpty(), event.sequence.toString(), event.stamp.toString()).joinToString("\u0000")

/** RSVP progress per invite revision, outliving any one screen: an answer finishes on whichever
 *  screen is current, and screens derive their buttons from [phases]. A key with no phase may be
 *  answered. KyCalendar first; [RsvpPhase.CONFIRM_MAIL] hands the mailed fallback to the screen. */
class RsvpTracker {
    private val state = MutableStateFlow<Map<String, RsvpState>>(emptyMap())
    val phases: StateFlow<Map<String, RsvpState>> = state

    /** False when [key] already has an answer pending, sent, unsure, or awaiting confirmation. */
    fun begin(key: String): Boolean {
        var began = false
        state.update { current ->
            began = key !in current
            if (began) current + (key to RsvpState(RsvpPhase.PENDING)) else current
        }
        return began
    }

    /** Releases an answer the user backed out of before it left. */
    fun cancel(key: String) = state.update {
        if (it[key]?.phase == RsvpPhase.PENDING || it[key]?.phase == RsvpPhase.CONFIRM_MAIL) it - key else it
    }

    /** Only a definite refusal frees the key; anything else may already have gone out. */
    fun finish(key: String, result: RsvpResult) = state.update {
        when (result) {
            RsvpResult.SENT -> it + (key to RsvpState(RsvpPhase.SENT))
            RsvpResult.REFUSED -> it - key
            RsvpResult.SENT_AS_PLAIN_MAIL, RsvpResult.MAYBE_SENT -> it + (key to RsvpState(RsvpPhase.UNSURE))
        }
    }

    /** KyCalendar's answer for [chosen]. Nothing was mailed, so every refusal frees the key; a
     *  fallback waits for the user. False, recording nothing, once [session] has ended. */
    fun answered(key: String, answer: CalendarAnswer, chosen: Rsvp, session: Long): Boolean {
        if (!org.kysecurity.mail.ProcessState.isCurrent(session)) return false
        state.update {
            when (answer) {
                CalendarAnswer.Answered -> it + (key to RsvpState(RsvpPhase.SENT))
                is CalendarAnswer.ByMail -> it + (key to RsvpState(RsvpPhase.CONFIRM_MAIL, MailFallback(chosen, answer.noEvent)))
                CalendarAnswer.Conflict, is CalendarAnswer.Failed -> it - key
            }
        }
        return true
    }

    /** Claims the confirmed fallback for sending: true once, so two screens cannot both mail it. */
    fun confirmMail(key: String): Boolean {
        var claimed = false
        state.update {
            claimed = it[key]?.phase == RsvpPhase.CONFIRM_MAIL
            if (claimed) it + (key to RsvpState(RsvpPhase.PENDING)) else it
        }
        return claimed
    }

    /** A fresh open (not a rotation) is the user's deliberate retry of an unsure send. */
    fun opened(key: String, freshOpen: Boolean) =
        state.update { if (freshOpen && it[key]?.phase == RsvpPhase.UNSURE) it - key else it }

    /** [finish] for a send started in [session]; false, recording nothing, once that session has
     *  ended, so a reset tracker is not repopulated and the caller shows no feedback. */
    fun complete(key: String, result: RsvpResult, session: Long): Boolean {
        if (!org.kysecurity.mail.ProcessState.isCurrent(session)) return false
        finish(key, result)
        return true
    }

    fun canAnswer(key: String): Boolean = key !in state.value

    fun clear() = state.update { emptyMap() }
}

/** Sends an RSVP only as the account and session it was confirmed under. Null, with no I/O, once
 *  the session has ended; [send] refuses a replaced pairing before building the request. */
fun sendBoundRsvp(
    draft: MailDraft,
    account: MailAccount,
    session: Long,
    send: (MailDraft, MailAccount?) -> MailOutcome<MailSendOutcome>,
): MailOutcome<MailSendOutcome>? =
    if (org.kysecurity.mail.ProcessState.isCurrent(session)) send(draft, account) else null
