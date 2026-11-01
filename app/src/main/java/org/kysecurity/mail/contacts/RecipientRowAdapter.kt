package org.kysecurity.mail.contacts

import android.graphics.Color
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.cardview.widget.CardView
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.chip.Chip
import org.kysecurity.mail.applyCardOutline
import org.kysecurity.mail.R
import org.kysecurity.mail.applyPillChipTheme
import org.kysecurity.mail.applySuccessChipTheme
import org.kysecurity.mail.getStoredThemePalette

/** [onPick] returns whether the pick actually landed (false = duplicate, per
 *  [org.kysecurity.mail.RecipientInputView.addRecipient]) — only a true result flips that row/field to
 *  its checkmark state. */
class RecipientRowAdapter(
    private var candidates: List<RecipientCandidate> = emptyList(),
    private val onPick: (RecipientCandidate, RecipientField) -> Boolean,
) : RecyclerView.Adapter<RecipientRowAdapter.RowViewHolder>() {

    private val added = mutableSetOf<Pair<String, RecipientField>>()

    class RowViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val card: CardView = view as CardView
        val name: TextView = view.findViewById(R.id.recipientRowName)
        val email: TextView = view.findViewById(R.id.recipientRowEmail)
        val department: TextView = view.findViewById(R.id.recipientRowDepartment)
        val toButton: Chip = view.findViewById(R.id.recipientRowToButton)
        val ccButton: Chip = view.findViewById(R.id.recipientRowCcButton)
        val bccButton: Chip = view.findViewById(R.id.recipientRowBccButton)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RowViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_recipient_row, parent, false)
        return RowViewHolder(view)
    }

    override fun onBindViewHolder(holder: RowViewHolder, position: Int) {
        val candidate = candidates[position]
        val palette = getStoredThemePalette(holder.itemView.context)
        holder.card.setCardBackgroundColor(Color.parseColor(palette.panel))
        applyCardOutline(holder.card.context, holder.card)
        holder.name.text = candidate.name
        holder.name.setTextColor(Color.parseColor(palette.inkStrong))
        holder.email.text = candidate.email
        holder.email.setTextColor(Color.parseColor(palette.ink))
        holder.department.text = candidate.department.orEmpty()
        holder.department.visibility = if (candidate.department.isNullOrBlank()) View.GONE else View.VISIBLE
        holder.department.setTextColor(Color.parseColor(palette.ink))

        bindActionButton(holder.toButton, candidate, RecipientField.TO)
        bindActionButton(holder.ccButton, candidate, RecipientField.CC)
        bindActionButton(holder.bccButton, candidate, RecipientField.BCC)
    }

    override fun getItemCount(): Int = candidates.size

    private fun bindActionButton(chip: Chip, candidate: RecipientCandidate, field: RecipientField) {
        if ((candidate.uid to field) in added) {
            applySuccessChipTheme(chip.context, chip)
        } else {
            applyPillChipTheme(chip.context, chip)
        }
        chip.setOnClickListener {
            if (onPick(candidate, field)) {
                added.add(candidate.uid to field)
                // Animate only the tapped chip; a rebind re-applies success via bindActionButton.
                applySuccessChipTheme(chip.context, chip, animate = true)
            }
        }
    }

    fun submitList(newCandidates: List<RecipientCandidate>) {
        candidates = newCandidates
        notifyDataSetChanged()
    }
}
