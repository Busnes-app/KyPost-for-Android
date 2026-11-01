package org.kysecurity.mail.contacts

import android.graphics.Color
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.cardview.widget.CardView
import androidx.recyclerview.widget.RecyclerView
import android.widget.TextView
import com.google.android.material.chip.Chip
import org.kysecurity.mail.R
import org.kysecurity.mail.ThemePalette
import org.kysecurity.mail.StatusTone
import org.kysecurity.mail.applyStatusBadgeTheme
import org.kysecurity.mail.bindAvatar
import org.kysecurity.mail.data.ContactEntity
import org.kysecurity.mail.getStoredThemePalette

class ContactAdapter(
    private var contacts: List<ContactEntity> = emptyList(),
    private val onContactClick: (ContactEntity) -> Unit,
) : RecyclerView.Adapter<ContactAdapter.ContactViewHolder>() {

    /** The account's PGP identity; unrelated to the self-contact's own editable `pgpKey` field. */
    var selfHasPgpIdentity: Boolean? = null
        set(value) {
            field = value
            notifyDataSetChanged()
        }

    class ContactViewHolder(view: View, private val onContactClick: (ContactEntity) -> Unit) :
        RecyclerView.ViewHolder(view) {
        private val cardView: CardView = view as CardView
        private val avatarView: TextView = view.findViewById(R.id.contactAvatar)
        private val nameView: TextView = view.findViewById(R.id.textViewContactName)
        private val detailView: TextView = view.findViewById(R.id.textViewContactDetail)
        private val statusBadge: Chip = view.findViewById(R.id.contactStatusBadge)

        fun bind(contact: ContactEntity, palette: ThemePalette, selfHasPgpIdentity: Boolean?) {
            nameView.text = contact.fn
            val orgText = contact.org?.takeIf { it.isNotBlank() }
            val selfLabel = if (contact.isSelf) itemView.context.getString(R.string.contact_self_label) else null
            detailView.text = listOfNotNull(selfLabel, orgText).joinToString(" · ")
            detailView.visibility = if (detailView.text.isBlank()) View.GONE else View.VISIBLE
            bindAvatar(itemView.context, avatarView, contact.fn, sizeDp = 34)

            val panel = Color.parseColor(palette.panel)
            cardView.setCardBackgroundColor(panel)
            nameView.setTextColor(Color.parseColor(palette.inkStrong))
            detailView.setTextColor(Color.parseColor(palette.ink))

            val hasKey = contactHasLinkedPgpKey(contact.pgpKey, contact.isSelf, selfHasPgpIdentity)
            val (label, tone) = when {
                hasKey && contact.pgpKeyNeedsReverification -> R.string.contact_status_key_changed to StatusTone.WARNING
                hasKey && contact.identityNeedsReview -> R.string.contact_status_identity_changed to StatusTone.WARNING
                hasKey -> R.string.contact_status_secure_key to StatusTone.SUCCESS
                else -> R.string.contact_status_no_key to StatusTone.NEUTRAL
            }
            statusBadge.setText(label)
            applyStatusBadgeTheme(itemView.context, statusBadge, tone)

            itemView.setOnClickListener { onContactClick(contact) }
        }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ContactViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_contact, parent, false)
        return ContactViewHolder(view, onContactClick)
    }

    override fun onBindViewHolder(holder: ContactViewHolder, position: Int) {
        holder.bind(contacts[position], getStoredThemePalette(holder.itemView.context), selfHasPgpIdentity)
    }

    override fun getItemCount(): Int = contacts.size

    fun updateContacts(newContacts: List<ContactEntity>) {
        contacts = newContacts
        notifyDataSetChanged()
    }
}

/** A null [selfHasPgpIdentity] reads as "no"; it can only ever add a way to show "linked". */
internal fun contactHasLinkedPgpKey(pgpKey: String?, isSelf: Boolean, selfHasPgpIdentity: Boolean?): Boolean =
    !pgpKey.isNullOrBlank() || (isSelf && selfHasPgpIdentity == true)
