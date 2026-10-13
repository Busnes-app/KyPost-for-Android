package org.kysecurity.mail

import android.app.Activity
import android.app.DatePickerDialog
import android.app.TimePickerDialog
import android.text.format.DateFormat
import android.widget.Toast
import androidx.annotation.StringRes
import androidx.appcompat.app.AlertDialog
import org.kysecurity.mail.security.showSecurely
import java.time.DayOfWeek
import java.time.Duration
import java.time.Instant
import java.time.LocalDate
import java.time.LocalTime
import java.time.ZoneId
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit
import java.time.temporal.TemporalAdjusters
import java.util.Date

/** The server's window is a year, from any moment after now; the margins absorb clock skew. */
internal fun pickSnoozeTime(activity: Activity, onPicked: (Instant) -> Unit) =
    pickWhen(activity, R.string.snooze_title, Duration.ofMinutes(1), Duration.ofDays(365), onPicked)

/** A named moment [pickWhen] offers. */
internal data class WhenPreset(@StringRes val label: Int, val at: ZonedDateTime)

/** Later today, this evening, tomorrow morning and next Monday morning, kept to those inside
 *  [minAhead]..[maxAhead] from [now]. */
internal fun whenPresets(now: ZonedDateTime, minAhead: Duration, maxAhead: Duration): List<WhenPreset> {
    val later = now.plusHours(3).truncatedTo(ChronoUnit.HOURS)
    val evening = now.with(LocalTime.of(18, 0))
    val morning = LocalTime.of(8, 0)
    return listOfNotNull(
        WhenPreset(R.string.when_later_today, later).takeIf { later.toLocalDate() == now.toLocalDate() },
        // Within the hour it is not "this evening", it is now.
        WhenPreset(R.string.when_this_evening, evening).takeIf { evening.isAfter(now.plusHours(1)) },
        WhenPreset(R.string.when_tomorrow, now.plusDays(1).with(morning)),
        WhenPreset(R.string.when_next_week, now.with(TemporalAdjusters.next(DayOfWeek.MONDAY)).with(morning)),
    ).filter { inWindow(it.at, now, minAhead, maxAhead) }.distinctBy { it.at }
}

internal fun inWindow(at: ZonedDateTime, now: ZonedDateTime, minAhead: Duration, maxAhead: Duration): Boolean =
    !at.isBefore(now.plus(minAhead)) && !at.isAfter(now.plus(maxAhead))

/** Asks when, from presets or a date and time, and calls [onPicked] with a moment inside
 *  [minAhead]..[maxAhead] of when it was picked. */
internal fun pickWhen(
    activity: Activity,
    @StringRes title: Int,
    minAhead: Duration,
    maxAhead: Duration,
    onPicked: (Instant) -> Unit,
) {
    val now = ZonedDateTime.now()
    val presets = whenPresets(now, minAhead, maxAhead)
    val labels = presets.map { activity.getString(it.label, describeWhen(activity, it.at, now)) } +
        activity.getString(R.string.when_custom)
    AlertDialog.Builder(activity)
        .setTitle(title)
        .setItems(labels.toTypedArray()) { _, which ->
            val preset = presets.getOrNull(which)
            when {
                preset == null -> pickDateAndTime(activity, minAhead, maxAhead, onPicked)
                // A dialog left open can outlive its presets.
                inWindow(preset.at, ZonedDateTime.now(), minAhead, maxAhead) -> onPicked(preset.at.toInstant())
                else -> Toast.makeText(activity, R.string.when_out_of_range, Toast.LENGTH_LONG).show()
            }
        }
        .setNegativeButton(android.R.string.cancel, null)
        .showThemed()
}

/** The phone's own 12/24-hour setting, with the weekday once it is not today. */
private fun describeWhen(activity: Activity, at: ZonedDateTime, now: ZonedDateTime): String {
    val time = DateFormat.getTimeFormat(activity).format(Date.from(at.toInstant()))
    return if (at.toLocalDate() == now.toLocalDate()) time else "${at.format(DateTimeFormatter.ofPattern("EEE"))} $time"
}

private fun pickDateAndTime(activity: Activity, minAhead: Duration, maxAhead: Duration, onPicked: (Instant) -> Unit) {
    val now = ZonedDateTime.now()
    DatePickerDialog(activity, { _, year, month, day ->
        pickTime(activity, LocalDate.of(year, month + 1, day), now.plusHours(1).toLocalTime(), minAhead, maxAhead, onPicked)
    }, now.year, now.monthValue - 1, now.dayOfMonth).apply {
        datePicker.minDate = now.toInstant().toEpochMilli()
        datePicker.maxDate = now.plus(maxAhead).toInstant().toEpochMilli()
    }.showSecurely()
}

/** Asks again on a time outside the window, starting from the one picked. */
private fun pickTime(
    activity: Activity,
    date: LocalDate,
    initial: LocalTime,
    minAhead: Duration,
    maxAhead: Duration,
    onPicked: (Instant) -> Unit,
) {
    TimePickerDialog(activity, { _, hour, minute ->
        val at = ZonedDateTime.of(date, LocalTime.of(hour, minute), ZoneId.systemDefault())
        // Checked against the clock now, not when the picker opened.
        if (inWindow(at, ZonedDateTime.now(), minAhead, maxAhead)) {
            onPicked(at.toInstant())
        } else {
            Toast.makeText(activity, R.string.when_out_of_range, Toast.LENGTH_LONG).show()
            pickTime(activity, date, at.toLocalTime(), minAhead, maxAhead, onPicked)
        }
    }, initial.hour, initial.minute, DateFormat.is24HourFormat(activity)).showSecurely()
}
