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

class EmailAdapter(
    private var emails: List<Email>,
    private val onEmailLongClick: ((Email, View) -> Unit)? = null,
    private val onEmailClick: ((Email) -> Unit)? = null
) : RecyclerView.Adapter<EmailAdapter.EmailViewHolder>() {

    class EmailViewHolder(
        view: View,
        private val onEmailClick: ((Email) -> Unit)?,
        private val onEmailLongClick: ((Email, View) -> Unit)?,
    ) : RecyclerView.ViewHolder(view) {
        private val cardView: CardView = view as CardView
        private val contentLayout: LinearLayout = view.findViewById(R.id.emailItemContent)
        private val unreadDot: View = view.findViewById(R.id.unreadDot)
        private val subjectTextView: TextView = view.findViewById(R.id.textViewSubject)
        private val senderTextView: TextView = view.findViewById(R.id.textViewSender)
        private val previewTextView: TextView = view.findViewById(R.id.textViewPreview)

        fun bind(email: Email, palette: ThemePalette) {
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
            // Plain text into a TextView: the relay already flattened it, and nothing here parses it.
            previewTextView.text = email.preview
            previewTextView.visibility = if (email.preview.isBlank()) View.GONE else View.VISIBLE

            val panel = Color.parseColor(palette.panel)
            cardView.setCardBackgroundColor(panel)
            contentLayout.setBackgroundColor(panel)

            val isUnread = email.status == "unread"
            unreadDot.visibility = if (isUnread) View.VISIBLE else View.GONE
            if (isUnread) {
                unreadDot.background = unreadDotDrawable(itemView.context)
            }
            subjectTextView.setTypeface(subjectTextView.typeface, if (isUnread) Typeface.BOLD else Typeface.NORMAL)
            subjectTextView.setTextColor(Color.parseColor(if (isUnread) palette.inkStrong else palette.ink))
            senderTextView.setTextColor(Color.parseColor(palette.ink))
            // Muted, so a snippet that starts with a name and address does not read as a sender.
            previewTextView.setTextColor(withAlpha(Color.parseColor(palette.ink), 0.72f))

            itemView.setOnClickListener { onEmailClick?.invoke(email) }
            onEmailLongClick?.let { onLongClick ->
                itemView.setOnLongClickListener { view ->
                    onLongClick(email, view)
                    true
                }
                // Names what the long press does; TalkBack otherwise says only "long press".
                androidx.core.view.ViewCompat.replaceAccessibilityAction(
                    itemView,
                    androidx.core.view.accessibility.AccessibilityNodeInfoCompat.AccessibilityActionCompat.ACTION_LONG_CLICK,
                    context.getString(if (isUnread) R.string.action_mark_read else R.string.action_mark_unread),
                    null,
                )
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
        holder.bind(emails[position], palette)
    }

    override fun getItemCount(): Int = emails.size

    fun getEmailAt(position: Int): Email = emails[position]

    fun currentEmails(): List<Email> = emails

    fun updateEmails(newEmails: List<Email>) {
        val previous = emails
        emails = newEmails
        dispatchEmailListUpdate(previous, newEmails, AdapterListUpdateCallback(this))
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

/** Not notifyDataSetChanged(): NO_POSITION holders strand ItemTouchHelper's swipe animation. */
internal fun dispatchEmailListUpdate(
    old: List<Email>,
    new: List<Email>,
    callback: ListUpdateCallback,
) {
    DiffUtil.calculateDiff(object : DiffUtil.Callback() {
        override fun getOldListSize(): Int = old.size
        override fun getNewListSize(): Int = new.size
        override fun areItemsTheSame(oldPos: Int, newPos: Int): Boolean = old[oldPos].id == new[newPos].id
        override fun areContentsTheSame(oldPos: Int, newPos: Int): Boolean = old[oldPos] == new[newPos]
    }).dispatchUpdatesTo(callback)
}