package org.kysecurity.mail

import android.app.Activity
import android.content.Intent
import android.provider.CalendarContract
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import org.kysecurity.mail.mail.CalendarEvent
import org.kysecurity.mail.mail.MAX_DESCRIPTION_CHARS
import org.kysecurity.mail.security.SecurityRuntime
import org.kysecurity.mail.security.showSecurely
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle
import java.util.Locale

/** ACTION_INSERT extras for an invite. The calendar app owns the write, so no permission. */
internal fun calendarInsertExtras(event: CalendarEvent): Map<String, Any> = buildMap {
    put(CalendarContract.Events.TITLE, event.summary)
    put(CalendarContract.EXTRA_EVENT_BEGIN_TIME, event.begin.toEpochMilli())
    put(CalendarContract.EXTRA_EVENT_END_TIME, event.end.toEpochMilli())
    put(CalendarContract.EXTRA_EVENT_ALL_DAY, event.allDay)
    if (event.location.isNotEmpty()) put(CalendarContract.Events.EVENT_LOCATION, event.location)
    if (event.description.isNotEmpty()) put(CalendarContract.Events.DESCRIPTION, event.description)
    if (event.rrule.isNotEmpty()) put(CalendarContract.Events.RRULE, event.rrule)
}

/** "Create event from this email": subject and body only. No date is guessed from the text. */
internal fun emailEventExtras(subject: String, body: String?, bodyMode: String): Map<String, Any> = buildMap {
    put(CalendarContract.Events.TITLE, subject)
    val text = body?.takeIf { it.isNotBlank() }?.let { if (isPlainTextBody(it, bodyMode)) it else htmlToText(it) }
    if (!text.isNullOrBlank()) put(CalendarContract.Events.DESCRIPTION, text.trim().take(MAX_DESCRIPTION_CHARS))
}

private fun htmlToText(html: String): String {
    val document = org.jsoup.Jsoup.parse(html)
    document.select("script, style, head").remove()
    return document.body().wholeText().replace(BLANK_RUN, "\n\n")
}

private val BLANK_RUN = Regex("\\n\\s*\\n(\\s*\\n)+")

/** When the invite happens, in [zone]. All-day ends are exclusive, so the last day is end - 1. */
internal fun inviteWhenText(event: CalendarEvent, zone: ZoneId, locale: Locale): String {
    if (event.allDay) {
        val dates = DateTimeFormatter.ofLocalizedDate(FormatStyle.MEDIUM).withLocale(locale)
        val first = event.begin.atZone(zone).toLocalDate()
        val last = event.end.atZone(zone).toLocalDate().minusDays(1)
        return if (last <= first) dates.format(first) else "${dates.format(first)} – ${dates.format(last)}"
    }
    val start = event.begin.atZone(zone)
    val end = event.end.atZone(zone)
    val dateTime = DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM, FormatStyle.SHORT).withLocale(locale)
    val time = DateTimeFormatter.ofLocalizedTime(FormatStyle.SHORT).withLocale(locale)
    return when {
        end == start -> dateTime.format(start)
        end.toLocalDate() == start.toLocalDate() -> "${dateTime.format(start)} – ${time.format(end)}"
        else -> "${dateTime.format(start)} – ${dateTime.format(end)}"
    }
}

/** Never automatic: only a tap reaches this. Under Hostile Location Protection the event leaves for
 *  a store a wipe cannot reach, so that is said and confirmed first. */
internal fun Activity.handOffToCalendar(extras: Map<String, Any>) {
    val launch = {
        val intent = Intent(Intent.ACTION_INSERT, CalendarContract.Events.CONTENT_URI)
        extras.forEach { (key, value) ->
            when (value) {
                is String -> intent.putExtra(key, value)
                is Long -> intent.putExtra(key, value)
                is Boolean -> intent.putExtra(key, value)
            }
        }
        runCatching { startActivity(intent) }
            .onFailure { Toast.makeText(this, R.string.calendar_no_app, Toast.LENGTH_LONG).show() }
    }
    if (!SecurityRuntime.graph(this).hostileLocationSettings.isEnabled()) {
        launch()
        return
    }
    AlertDialog.Builder(this)
        .setTitle(R.string.calendar_handoff_confirm_title)
        .setMessage(R.string.calendar_handoff_confirm_message)
        .setPositiveButton(R.string.calendar_handoff_confirm_positive) { _, _ -> launch() }
        .setNegativeButton(android.R.string.cancel, null)
        .create()
        .showSecurely()
}
