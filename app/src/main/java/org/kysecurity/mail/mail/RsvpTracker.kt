package org.kysecurity.mail.mail

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update

enum class RsvpPhase { PENDING, SENT, UNSURE }

/** One answerable revision: a raised SEQUENCE is a new invite to answer. */
fun rsvpKey(event: CalendarEvent): String =
    listOf(event.uid, event.recurrenceId.orEmpty(), event.sequence.toString()).joinToString("\u0000")

/** RSVP progress per invite revision, outliving any one screen: a send finishes on whichever
 *  screen is current, and screens derive their buttons from [phases]. A key with no phase may be
 *  answered. */
class RsvpTracker {
    private val state = MutableStateFlow<Map<String, RsvpPhase>>(emptyMap())
    val phases: StateFlow<Map<String, RsvpPhase>> = state

    /** False when [key] already has a send pending, sent, or unsure. */
    fun begin(key: String): Boolean {
        var began = false
        state.update { current ->
            began = key !in current
            if (began) current + (key to RsvpPhase.PENDING) else current
        }
        return began
    }

    /** Releases a send the user backed out of before it left. */
    fun cancel(key: String) = state.update { if (it[key] == RsvpPhase.PENDING) it - key else it }

    /** Only a definite refusal frees the key; anything else may already have gone out. */
    fun finish(key: String, result: RsvpResult) = state.update {
        when (result) {
            RsvpResult.SENT -> it + (key to RsvpPhase.SENT)
            RsvpResult.REFUSED -> it - key
            RsvpResult.SENT_AS_PLAIN_MAIL, RsvpResult.MAYBE_SENT -> it + (key to RsvpPhase.UNSURE)
        }
    }

    /** A fresh open (not a rotation) is the user's deliberate retry of an unsure send. */
    fun opened(key: String, freshOpen: Boolean) =
        state.update { if (freshOpen && it[key] == RsvpPhase.UNSURE) it - key else it }

    fun canAnswer(key: String): Boolean = key !in state.value

    fun clear() = state.update { emptyMap() }
}
