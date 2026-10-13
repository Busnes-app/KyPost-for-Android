package org.kysecurity.mail

import android.graphics.Color
import android.os.Bundle
import android.util.TypedValue
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.annotation.StringRes
import androidx.appcompat.app.AlertDialog
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import org.kysecurity.mail.mail.MailOutcome
import org.kysecurity.mail.mail.MailRepository
import org.kysecurity.mail.mail.MailRuntime
import org.kysecurity.mail.mail.ScheduledSend
import org.kysecurity.mail.mail.userFacingMessage
import org.kysecurity.mail.pgp.OUTER_PLACEHOLDER_SUBJECT
import org.kysecurity.mail.security.LockedActivity
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/** Mail the relay is holding for later (`GET /api/scheduled`). A waiting one can be canceled,
 *  which returns it to Drafts. */
class ScheduledActivity : LockedActivity() {

    // Reads only. Cancels go to MailBackgroundExecutor, which outlives this screen.
    private val ioExecutor: ExecutorService = Executors.newSingleThreadExecutor()
    private lateinit var repository: MailRepository
    private lateinit var status: TextView
    private val adapter = ScheduledAdapter()

    override fun onCreateUnlocked(savedInstanceState: Bundle?) {
        repository = MailRuntime.graph(this).repository
        setTitle(R.string.scheduled_title)

        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dpToPx(20), dpToPx(20), dpToPx(20), dpToPx(20))
        }
        applyTopInsetWithHeader(this, container)
        status = TextView(this).apply {
            textSize = 14f
            accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE
        }
        container.addViewSpaced(status, bottomDp = 8)
        val list = RecyclerView(this).apply {
            layoutManager = LinearLayoutManager(this@ScheduledActivity)
            adapter = this@ScheduledActivity.adapter
        }
        container.addView(list, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f))
        setContentView(container)
        applyThemeToActivity(this)
        load()
    }

    override fun onDestroy() {
        super.onDestroy()
        ioExecutor.shutdownNow()
    }

    private fun load() {
        status.setText(R.string.scheduled_loading)
        status.visibility = View.VISIBLE
        ioExecutor.execute {
            val outcome = repository.listScheduled()
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                if (outcome !is MailOutcome.Success) {
                    status.text = outcome.userFacingMessage()
                    adapter.submit(emptyList())
                    return@runOnUiThread
                }
                adapter.submit(outcome.value)
                if (outcome.value.isEmpty()) status.setText(R.string.scheduled_empty) else status.visibility = View.GONE
            }
        }
    }

    private fun confirmCancel(send: ScheduledSend) {
        AlertDialog.Builder(this)
            .setTitle(R.string.scheduled_cancel_title)
            .setMessage(getString(R.string.scheduled_cancel_body, sendTime(send)))
            .setPositiveButton(R.string.scheduled_cancel) { _, _ -> cancel(send) }
            .setNegativeButton(R.string.scheduled_keep, null)
            .showThemed()
    }

    private fun cancel(send: ScheduledSend) {
        MailBackgroundExecutor.submitReporting(this, getString(R.string.scheduled_cancel)) {
            repository.cancelScheduled(send.id).also { outcome ->
                runOnUiThread {
                    if (isDestroyed) return@runOnUiThread
                    if (outcome is MailOutcome.Success) {
                        val message = outcome.value.ifBlank { getString(R.string.scheduled_returned) }
                        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
                    }
                    load()
                }
            }
        }
    }

    private fun sendTime(send: ScheduledSend): String =
        send.sendAt?.let(::formatWhen) ?: getString(R.string.scheduled_unknown_time)

    private fun describe(send: ScheduledSend): String {
        // An encrypted message's real subject is inside the ciphertext.
        val subject = send.subject.takeUnless { it.isBlank() || it == OUTER_PLACEHOLDER_SUBJECT }
            ?: getString(R.string.scheduled_no_subject)
        val state = getString(statusLabel(send.status)) + send.reason.takeIf { it.isNotBlank() }?.let { " · $it" }.orEmpty()
        return listOf(subject, send.to.joinToString(", "), sendTime(send), state).filter { it.isNotBlank() }.joinToString("\n")
    }

    private inner class ScheduledAdapter : RecyclerView.Adapter<ScheduledAdapter.Row>() {
        private var sends: List<ScheduledSend> = emptyList()

        @android.annotation.SuppressLint("NotifyDataSetChanged")
        fun submit(next: List<ScheduledSend>) {
            sends = next
            notifyDataSetChanged()
        }

        inner class Row(val text: TextView) : RecyclerView.ViewHolder(text)

        override fun onCreateViewHolder(group: ViewGroup, viewType: Int): Row {
            val context = group.context
            val ripple = TypedValue().also {
                context.theme.resolveAttribute(android.R.attr.selectableItemBackground, it, true)
            }.resourceId
            return Row(
                TextView(context).apply {
                    textSize = 15f
                    setTextColor(Color.parseColor(getStoredThemePalette(context).inkStrong))
                    minHeight = dpToPx(48)
                    setPadding(0, dpToPx(10), 0, dpToPx(10))
                    setBackgroundResource(ripple)
                    layoutParams = RecyclerView.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
                },
            )
        }

        override fun onBindViewHolder(holder: Row, position: Int) {
            val send = sends[position]
            holder.text.text = describe(send)
            // Only a waiting message can still be canceled; the server answers 409 for the rest.
            val cancelable = send.status == "scheduled"
            holder.text.isClickable = cancelable
            holder.text.setOnClickListener(if (cancelable) View.OnClickListener { confirmCancel(send) } else null)
        }

        override fun getItemCount(): Int = sends.size
    }
}

/** The server's statuses (`scheduled_send.go`); an unknown one reads as its own word would. */
@StringRes
internal fun statusLabel(status: String): Int = when (status) {
    "scheduled" -> R.string.scheduled_status_waiting
    "sending" -> R.string.scheduled_status_sending
    "returning" -> R.string.scheduled_status_returning
    "returned" -> R.string.scheduled_status_returned
    "sent", "queued" -> R.string.scheduled_status_sent
    "uncertain" -> R.string.scheduled_status_uncertain
    "failed" -> R.string.scheduled_status_failed
    else -> R.string.scheduled_status_unknown
}
