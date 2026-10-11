package org.kysecurity.mail

import android.graphics.Color
import android.graphics.Typeface
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import androidx.cardview.widget.CardView
import androidx.recyclerview.widget.AdapterListUpdateCallback
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListUpdateCallback
import androidx.recyclerview.widget.RecyclerView
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
) : RecyclerView.Adapter<EmailAdapter.EmailViewHolder>() {

    private var selectedIds: Set<String> = emptySet()

    class EmailViewHolder(
        view: View,
        private val onEmailClick: ((Email) -> Unit)?,
        private val onEmailLongClick: ((Email) -> Unit)?,
    ) : RecyclerView.ViewHolder(view) {
        private val cardView: CardView = view as CardView
        private val contentLayout: LinearLayout = view.findViewById(R.id.emailItemContent)
        private val unreadDot: View = view.findViewById(R.id.unreadDot)
        private val subjectTextView: TextView = view.findViewById(R.id.textViewSubject)
        private val senderTextView: TextView = view.findViewById(R.id.textViewSender)
        private val dateTextView: TextView = view.findViewById(R.id.textViewDate)

        fun bind(email: Email, palette: ThemePalette, selected: Boolean) {
            // A message this app can't render is worth knowing before tapping it — otherwise the
            // only signal is opening it and finding nothing there.
            val pgpState = pgpMessageStateOf(email.pgpEncrypted, email.pgpDecryptError, email.body)
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
            subjectTextView.contentDescription = when {
                signatureState == PgpSignatureState.INVALID ->
                    itemView.context.getString(R.string.email_row_pgp_bad_signature_description, email.subject)
                // Unreachable today: pgpSignatureStateOf cannot produce KEY_CHANGED.
                signatureState == PgpSignatureState.KEY_CHANGED ->
                    itemView.context.getString(R.string.email_row_pgp_key_changed_description, email.subject)
                pgpState == PgpMessageState.CLIENT_PROTECTED ->
                    itemView.context.getString(R.string.email_row_pgp_locked_description, email.subject)
                pgpState == PgpMessageState.DECRYPT_FAILED ->
                    itemView.context.getString(R.string.email_row_pgp_failed_description, email.subject)
                else -> null
            }
            senderTextView.text = email.sender
            dateTextView.text = inboxRowDate(email.atUtc, ZonedDateTime.now(), Locale.getDefault())

            val panel = Color.parseColor(palette.panel)
            val background = if (selected) blend(panel, Color.parseColor(palette.accent), 0.3f) else panel
            cardView.setCardBackgroundColor(background)
            contentLayout.setBackgroundColor(background)
            itemView.isActivated = selected
            itemView.stateDescription = if (selected) itemView.context.getString(R.string.selection_selected) else null

            val isUnread = email.status == "unread"
            unreadDot.visibility = if (isUnread) View.VISIBLE else View.GONE
            if (isUnread) {
                unreadDot.background = unreadDotDrawable(itemView.context)
            }
            subjectTextView.setTypeface(subjectTextView.typeface, if (isUnread) Typeface.BOLD else Typeface.NORMAL)
            subjectTextView.setTextColor(Color.parseColor(if (isUnread) palette.inkStrong else palette.ink))
            senderTextView.setTextColor(Color.parseColor(palette.ink))
            dateTextView.setTextColor(Color.parseColor(palette.ink))

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
        return EmailViewHolder(view, onEmailClick, onEmailLongClick)
    }

    override fun onBindViewHolder(holder: EmailViewHolder, position: Int) {
        val palette = getStoredThemePalette(holder.itemView.context)
        holder.bind(emails[position], palette, emails[position].id in selectedIds)
    }

    override fun getItemCount(): Int = emails.size

    fun getEmailAt(position: Int): Email = emails[position]

    fun currentEmails(): List<Email> = emails
    fun setSelection(ids: Set<String>) {
        selectedIds = ids.toSet()
        notifyItemRangeChanged(0, itemCount)
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