package org.kysecurity.mail.mail

import org.junit.Test
import org.kysecurity.mail.testing.MapPrefs
import java.time.ZoneId
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class InviteAnswersTest {

    private fun event(uid: String = "abc@example.com") = assertNotNull(
        parseCalendarInvite(
            listOf(
                "BEGIN:VCALENDAR", "METHOD:REQUEST", "BEGIN:VEVENT", "UID:$uid", "DTSTART:20261112T100000Z",
                "ORGANIZER:mailto:boss@example.com", "END:VEVENT", "END:VCALENDAR",
            ).joinToString("\r\n").toByteArray(),
            ZoneId.of("UTC"),
        ),
    ).primary

    @Test
    fun anAnswerFinishingWhileProtectionIsEnabledLeavesNoHistory() {
        val prefs = MapPrefs()
        val answers = InviteAnswers(prefs)
        val protectionOn = java.util.concurrent.atomic.AtomicBoolean(false)
        val checked = CountDownLatch(1)
        val enabled = CountDownLatch(1)
        // The worst interleaving: the completion reads the flag before it flips, and writes only
        // after the enable path has flipped it and deleted the file.
        val writer = thread {
            answers.record(event(), "me@example.com", Rsvp.ACCEPTED, now = 1) {
                val seen = protectionOn.get()
                checked.countDown()
                enabled.await(5, TimeUnit.SECONDS)
                seen
            }
        }
        // The enable path. Without the lock the writer checks now; with it, it cannot until after.
        InviteAnswers.withWritesBlocked {
            checked.await(500, TimeUnit.MILLISECONDS)
            protectionOn.set(true)
            prefs.edit().clear().commit()
        }
        enabled.countDown()
        writer.join(5_000)
        assertTrue(prefs.all.isEmpty(), "the late answer must not recreate the history")
        assertEquals(PriorAnswer.None, answers.prior(event(), "me@example.com"))
    }

    @Test
    fun anAnswerIsKeptWhileProtectionIsOff() {
        val answers = InviteAnswers(MapPrefs())
        answers.record(event(), "me@example.com", Rsvp.DECLINED, now = 1) { false }
        assertEquals(PriorAnswer.Same(Rsvp.DECLINED), answers.prior(event(), "me@example.com"))
    }

    @Test
    fun theOldestAnswersGoPastTheCap() {
        val prefs = MapPrefs()
        val answers = InviteAnswers(prefs)
        (0..InviteAnswers.MAX_ANSWERS).forEach { answers.record(event("u$it@x"), "me@example.com", Rsvp.ACCEPTED, now = it.toLong()) { false } }
        assertEquals(InviteAnswers.MAX_ANSWERS, prefs.all.size)
        assertEquals(PriorAnswer.None, answers.prior(event("u0@x"), "me@example.com"))
        assertEquals(PriorAnswer.Same(Rsvp.ACCEPTED), answers.prior(event("u${InviteAnswers.MAX_ANSWERS}@x"), "me@example.com"))
        // Re-answering a kept invite does not evict another.
        answers.record(event("u5@x"), "me@example.com", Rsvp.DECLINED, now = 999) { false }
        assertEquals(InviteAnswers.MAX_ANSWERS, prefs.all.size)
        assertEquals(PriorAnswer.Same(Rsvp.ACCEPTED), answers.prior(event("u1@x"), "me@example.com"))
    }
}
