package org.kysecurity.mail

import android.graphics.Color
import android.graphics.Typeface
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
import org.kysecurity.mail.pgp.PgpMessageState
import org.kysecurity.mail.pgp.PgpSignatureState
import org.kysecurity.mail.pgp.pgpMessageStateOf
import org.kysecurity.mail.pgp.pgpRowMarker
import org.kysecurity.mail.pgp.pgpSignatureStateOf

class EmailAdapter(
    private var emails: List<Email>,
    private val onEmailClick: ((Email) -> Unit)? = null,
    /** (label, action): the screen-reader stand-ins for the row's swipes. */
    private val rowActions: List<Pair<Int, (Email) -> Unit>> = emptyList(),
) : RecyclerView.Adapter<EmailAdapter.EmailViewHolder>() {

    class EmailViewHolder(
        view: View,
        private val onEmailClick: ((Email) -> Unit)?,
        private val rowActions: List<Pair<Int, (Email) -> Unit>>,
    ) : RecyclerView.ViewHolder(view) {
        private val cardView: CardView = view as CardView
        private val contentLayout: LinearLayout = view.findViewById(R.id.emailItemContent)
        private val unreadDot: View = view.findViewById(R.id.unreadDot)
        private val subjectTextView: TextView = view.findViewById(R.id.textViewSubject)
        private val senderTextView: TextView = view.findViewById(R.id.textViewSender)

        // setTypeface(current, NORMAL) keeps a bold current face; derive from the inflated one.
        private val subjectTypeface: Typeface = subjectTextView.typeface

        /** Removed on rebind: a recycled row must not keep acting on the email it showed before. */
        private var actionIds: List<Int> = emptyList()

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
            val isUnread = email.status == "unread"
            // The whole row is one focus stop; the unread dot and the 📎 have no voice of their own.
            itemView.contentDescription = listOfNotNull(
                context.getString(R.string.email_row_unread).takeIf { isUnread },
                spokenSubject,
                context.getString(R.string.email_row_from, email.sender),
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
            cardView.setCardBackgroundColor(panel)
            contentLayout.setBackgroundColor(panel)

            unreadDot.visibility = if (isUnread) View.VISIBLE else View.GONE
            if (isUnread) {
                unreadDot.background = unreadDotDrawable(itemView.context)
            }
            subjectTextView.typeface = Typeface.create(subjectTypeface, if (isUnread) Typeface.BOLD else Typeface.NORMAL)
            subjectTextView.setTextColor(Color.parseColor(if (isUnread) palette.inkStrong else palette.ink))
            senderTextView.setTextColor(Color.parseColor(palette.ink))

            itemView.setOnClickListener { onEmailClick?.invoke(email) }
        }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): EmailViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_email, parent, false)
        return EmailViewHolder(view, onEmailClick, rowActions)
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