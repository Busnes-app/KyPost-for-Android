package org.kysecurity.mail

import android.graphics.Color
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import androidx.cardview.widget.CardView
import androidx.core.view.ViewCompat
import androidx.recyclerview.widget.AdapterListUpdateCallback
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListUpdateCallback
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.chip.Chip
import org.kysecurity.mail.pgp.PgpMessageState
import org.kysecurity.mail.pgp.PgpSignatureState
import org.kysecurity.mail.pgp.pgpMessageStateOf
import org.kysecurity.mail.pgp.pgpRowMarker
import org.kysecurity.mail.pgp.pgpSignatureStateOf
import java.time.Instant
import java.time.LocalDate
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle
import java.util.Locale

class EmailAdapter(
    private var emails: List<Email>,
    private val onEmailLongClick: ((Email) -> Unit)? = null,
    private val onEmailClick: ((Email) -> Unit)? = null,
    /** (label, action): the screen-reader stand-ins for the row's swipes. */
    private val rowActions: List<Pair<Int, (Email) -> Unit>> = emptyList(),
) : RecyclerView.Adapter<EmailAdapter.EmailViewHolder>() {

    private var selectedIds: Set<String> = emptySet()

    class EmailViewHolder(
        view: View,
        private val onEmailClick: ((Email) -> Unit)?,
        private val onEmailLongClick: ((Email) -> Unit)?,
        private val rowActions: List<Pair<Int, (Email) -> Unit>>,
    ) : RecyclerView.ViewHolder(view) {
        private val cardView: CardView = view as CardView
        private val contentLayout: LinearLayout = view.findViewById(R.id.emailItemContent)
        private val unreadDot: View = view.findViewById(R.id.unreadDot)
        private val subjectTextView: TextView = view.findViewById(R.id.textViewSubject)
        private val senderTextView: TextView = view.findViewById(R.id.textViewSender)
        private val dateTextView: TextView = view.findViewById(R.id.textViewDate)
        private val snoozedBadge: Chip = view.findViewById(R.id.snoozedBadge)
        private val previewTextView: TextView = view.findViewById(R.id.textViewPreview)

        /** Removed on rebind: a recycled row must not keep acting on the email it showed before. */
        private var actionIds: List<Int> = emptyList()

        fun bind(email: Email, palette: ThemePalette, selected: Boolean) {
            // A message this app can't render is worth knowing before tapping it — otherwise the
            // only signal is opening it and finding nothing there.
            val pgpState = pgpMessageStateOf(email.pgpEncrypted, email.pgpDecryptError, email.hasBody)
            val signatureState =
                pgpSignatureStateOf(email.pgpSigned, email.pgpVerified, email.pgpSignerFingerprint)
            val markers = listOfNotNull(
                pgpRowMarker(pgpState, signatureState),
                if (email.hasAttachments) "📎" else null,
            )
            val context = itemView.context
            subjectTextView.text = if (markers.isEmpty()) {
                email.subject
            } else {
                context.getString(R.string.email_row_subject_marked, markers.joinToString(" "), email.subject)
            }
            // Emoji markers are announced inconsistently by screen readers; spell the state out.
            val spokenSubject = when {
                signatureState == PgpSignatureState.INVALID ->
                    context.getString(R.string.email_row_pgp_bad_signature_description, email.subject)
                // Unreachable today: pgpSignatureStateOf cannot produce KEY_CHANGED.
                signatureState == PgpSignatureState.KEY_CHANGED ->
                    context.getString(R.string.email_row_pgp_key_changed_description, email.subject)
                pgpState == PgpMessageState.CLIENT_PROTECTED ->
                    context.getString(R.string.email_row_pgp_locked_description, email.subject)
                pgpState == PgpMessageState.DECRYPT_FAILED ->
                    context.getString(R.string.email_row_pgp_failed_description, email.subject)
                else -> email.subject
            }
            senderTextView.text = email.sender
            dateTextView.text = inboxRowDate(email.atUtc, ZonedDateTime.now(), Locale.getDefault())
            val woken = email.wokenAt != null
            snoozedBadge.visibility = if (woken) View.VISIBLE else View.GONE
            if (woken) applyStatusBadgeTheme(context, snoozedBadge, StatusTone.NEUTRAL)
            // Plain text into a TextView: the relay already flattened it, and nothing here parses it.
            previewTextView.text = email.preview
            previewTextView.visibility = if (email.preview.isBlank()) View.GONE else View.VISIBLE
            val isUnread = email.status == "unread"
            // The whole row is one focus stop; the unread dot and the 📎 have no voice of their own.
            itemView.contentDescription = listOfNotNull(
                context.getString(R.string.email_row_unread).takeIf { isUnread },
                spokenSubject,
                context.getString(R.string.email_row_from, email.sender),
                email.preview.takeIf { it.isNotBlank() },
                dateTextView.text.toString().takeIf { it.isNotBlank() },
                context.getString(R.string.email_row_snoozed).takeIf { woken },
                context.getString(R.string.email_row_has_attachments).takeIf { email.hasAttachments },
            ).joinToString(", ")
            actionIds.forEach { ViewCompat.removeAccessibilityAction(itemView, it) }
            actionIds = rowActions.map { (label, action) ->
                ViewCompat.addAccessibilityAction(itemView, context.getString(label)) { _, _ ->
                    action(email)
                    true
                }
            }

            val panel = Color.parseColor(palette.panel)
            val background = if (selected) blend(panel, Color.parseColor(palette.accent), 0.3f) else panel
            cardView.setCardBackgroundColor(background)
            contentLayout.setBackgroundColor(background)
            itemView.isActivated = selected
            itemView.stateDescription = if (selected) itemView.context.getString(R.string.selection_selected) else null

            unreadDot.visibility = if (isUnread) View.VISIBLE else View.GONE
            if (isUnread) {
                unreadDot.background = unreadDotDrawable(itemView.context)
            }
            subjectTextView.setBold(isUnread)
            subjectTextView.setTextColor(Color.parseColor(if (isUnread) palette.inkStrong else palette.ink))
            senderTextView.setTextColor(Color.parseColor(palette.ink))
            dateTextView.setTextColor(Color.parseColor(palette.ink))
            // Muted, so a snippet that starts with a name and address does not read as a sender.
            previewTextView.setTextColor(withAlpha(Color.parseColor(palette.ink), 0.72f))

            itemView.setOnClickListener { onEmailClick?.invoke(email) }
            itemView.setOnLongClickListener {
                onEmailLongClick?.invoke(email)
                onEmailLongClick != null
            }
        }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): EmailViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_email, parent, false)
        return EmailViewHolder(view, onEmailClick, onEmailLongClick, rowActions)
    }

    override fun onBindViewHolder(holder: EmailViewHolder, position: Int) {
        val palette = getStoredThemePalette(holder.itemView.context)
        holder.bind(emails[position], palette, emails[position].id in selectedIds)
    }

    override fun getItemCount(): Int = emails.size

    fun getEmailAt(position: Int): Email = emails[position]

    fun currentEmails(): List<Email> = emails
    fun setSelection(ids: Set<String>) {
        val before = selectedIds
        selectedIds = ids.toSet()
        dispatchSelectionUpdate(emails, before, selectedIds, AdapterListUpdateCallback(this))
    }

    /** The day the date labels were formatted for: after midnight "today" shows a time it no longer means. */
    private var labelledDay: LocalDate = LocalDate.now()

    fun updateEmails(newEmails: List<Email>) {
        val previous = emails
        emails = newEmails
        val today = LocalDate.now()
        val dayChanged = today != labelledDay
        labelledDay = today
        dispatchEmailListUpdate(previous, newEmails, AdapterListUpdateCallback(this), dayChanged)
    }
}

/** "Load older mail" after the last row; no item at all while hidden. */
class LoadOlderAdapter(private val onClick: () -> Unit) : RecyclerView.Adapter<RecyclerView.ViewHolder>() {
    var shown = false
        set(value) {
            if (field == value) return
            field = value
            if (value) notifyItemInserted(0) else notifyItemRemoved(0)
        }
    var loading = false
        set(value) {
            field = value
            if (shown) notifyItemChanged(0)
        }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder =
        object : RecyclerView.ViewHolder(
            LayoutInflater.from(parent.context).inflate(R.layout.item_load_older, parent, false),
        ) {}

    override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {
        val button = holder.itemView.findViewById<android.widget.Button>(R.id.loadOlderButton)
        applyGhostButtonTheme(button.context, button)
        button.isEnabled = !loading
        button.setOnClickListener { onClick() }
    }

    override fun getItemCount(): Int = if (shown) 1 else 0
}

/** Time for mail from today, date otherwise, in [now]'s zone. Blank when the relay sent no
 *  parseable `atUtc` (RFC 3339). */
internal fun inboxRowDate(atUtc: String?, now: ZonedDateTime, locale: Locale): String {
    val local = runCatching { Instant.parse(atUtc.orEmpty()) }.getOrNull()?.atZone(now.zone) ?: return ""
    val formatter = if (local.toLocalDate() == now.toLocalDate()) {
        DateTimeFormatter.ofLocalizedTime(FormatStyle.SHORT)
    } else {
        DateTimeFormatter.ofLocalizedDate(FormatStyle.MEDIUM)
    }
    return formatter.withLocale(locale).format(local)
}

/** Only the rows whose selection flipped. A whole-list change per toggle made RecyclerView's
 *  pending-update pass quadratic: 500 toggles before one layout took 80-170s on the CI emulator. */
internal fun dispatchSelectionUpdate(emails: List<Email>, before: Set<String>, after: Set<String>, callback: ListUpdateCallback) {
    emails.forEachIndexed { i, email -> if ((email.id in before) != (email.id in after)) callback.onChanged(i, 1, null) }
}

/** Not notifyDataSetChanged(): NO_POSITION holders strand ItemTouchHelper's swipe animation. */
internal fun dispatchEmailListUpdate(
    old: List<Email>,
    new: List<Email>,
    callback: ListUpdateCallback,
    dayChanged: Boolean = false,
) {
    DiffUtil.calculateDiff(object : DiffUtil.Callback() {
        override fun getOldListSize(): Int = old.size
        override fun getNewListSize(): Int = new.size
        override fun areItemsTheSame(oldPos: Int, newPos: Int): Boolean = old[oldPos].id == new[newPos].id
        override fun areContentsTheSame(oldPos: Int, newPos: Int): Boolean = old[oldPos] == new[newPos]
    }).dispatchUpdatesTo(callback)
    // Rebinds, not a reload: a range change keeps an in-flight swipe's holder.
    if (dayChanged && new.isNotEmpty()) callback.onChanged(0, new.size, null)
}