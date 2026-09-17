package org.kysecurity.mail

import android.content.Context
import android.graphics.Typeface
import android.text.SpannableString
import android.text.style.StyleSpan
import android.util.AttributeSet
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.EditorInfo
import android.widget.AutoCompleteTextView
import android.widget.BaseAdapter
import android.widget.Filter
import android.widget.Filterable
import android.widget.ImageButton
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.core.widget.doAfterTextChanged
import com.google.android.material.chip.Chip
import com.google.android.material.chip.ChipGroup
import org.kysecurity.mail.contacts.RecipientCandidate
import org.kysecurity.mail.contacts.isDuplicateRecipient
import org.kysecurity.mail.contacts.isValidEmailFormat
import org.kysecurity.mail.contacts.matchRanges
import androidx.lifecycle.findViewTreeLifecycleOwner
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** One TO/CC/BCC recipient field; see ContactAutocomplete.md sections 1, 2 and 4. */
class RecipientInputView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
) : LinearLayout(context, attrs) {

    private val labelView: TextView
    private val field: AutoCompleteTextView
    private val bookButton: ImageButton
    private val chipGroup: ChipGroup
    private val recipients = mutableListOf<String>()

    /** Fires once per committed change to [recipientEmails], never per keystroke. */
    var onRecipientsChanged: (() -> Unit)? = null

    /** The in-flight suggestion lookup, cancelled by the next keystroke. See [debounceAndSearch]. */
    private var searchJob: kotlinx.coroutines.Job? = null

    init {
        orientation = VERTICAL
        LayoutInflater.from(context).inflate(R.layout.view_recipient_input, this, true)
        labelView = findViewById(R.id.recipientInputLabel)
        field = findViewById(R.id.recipientInputField)
        bookButton = findViewById(R.id.recipientInputBookButton)
        chipGroup = findViewById(R.id.recipientInputChips)

        field.setOnItemClickListener { _, _, position, _ ->
            (field.adapter as? SuggestionAdapter)?.getCandidateAt(position)?.let {
                addRecipient(it.email, it.name)
            }
        }
        field.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_DONE) {
                commitTypedEmail()
                true
            } else {
                false
            }
        }
        field.doAfterTextChanged { text ->
            if (text != null && (text.endsWith(",") || text.endsWith(" "))) {
                commitTypedEmail()
            }
        }
    }

    fun setLabel(text: CharSequence) {
        labelView.text = text
    }

    /** Pass [onOpenAddressBook] on exactly one instance; the modal covers TO/CC/BCC itself. */
    fun configure(search: suspend (String) -> List<RecipientCandidate>, onOpenAddressBook: (() -> Unit)? = null) {
        val adapter = SuggestionAdapter(context)
        field.setAdapter(adapter)
        field.doAfterTextChanged { editable -> debounceAndSearch(adapter, search, editable?.toString().orEmpty()) }
        if (onOpenAddressBook != null) {
            bookButton.visibility = View.VISIBLE
            bookButton.setOnClickListener { onOpenAddressBook() }
        }
    }

    /** Parses a comma-separated address string (matches [org.kysecurity.mail.mail.MailDraft]'s wire
     *  shape) into chips — used to prefill from ComposeActivity.EXTRA_TO on reply/forward. */
    fun setInitialRecipients(commaSeparated: String) {
        commaSeparated.split(",")
            .map { it.trim() }
            .filter { it.isNotBlank() }
            .forEach { addRecipient(it) }
    }

    /** Adds [email] as a chip; false (plus a duplicate toast) if it is already present. */
    fun addRecipient(email: String, displayName: String? = null): Boolean {
        if (isDuplicateRecipient(recipients, email)) {
            Toast.makeText(context, context.getString(R.string.recipient_duplicate_toast, email), Toast.LENGTH_SHORT).show()
            return false
        }
        recipients.add(email)
        val chip = Chip(context).apply {
            text = displayName?.takeIf { it.isNotBlank() } ?: email
            isCloseIconVisible = true
            setOnCloseIconClickListener {
                recipients.remove(email)
                chipGroup.removeView(this)
                chipGroup.visibility = if (chipGroup.childCount == 0) View.GONE else View.VISIBLE
                onRecipientsChanged?.invoke()
            }
        }
        applyPillChipTheme(context, chip)
        chipGroup.addView(chip)
        chipGroup.visibility = View.VISIBLE
        field.setText("")
        field.dismissDropDown()
        onRecipientsChanged?.invoke()
        return true
    }

    fun recipientEmails(): List<String> = recipients.toList()

    /** Matches [org.kysecurity.mail.mail.MailDraft]'s to/cc/bcc wire shape. */
    fun commaJoinedRecipients(): String = recipients.joinToString(",")

    fun applyTheme() {
        applyIconButtonTheme(context, bookButton)
        for (i in 0 until chipGroup.childCount) {
            (chipGroup.getChildAt(i) as? Chip)?.let { applyPillChipTheme(context, it) }
        }
    }

    private fun commitTypedEmail() {
        val typed = field.text.toString().trim(' ', ',')
        if (typed.isBlank()) return
        if (!isValidEmailFormat(typed)) {
            Toast.makeText(context, R.string.recipient_invalid_email_toast, Toast.LENGTH_SHORT).show()
            return
        }
        addRecipient(typed)
    }

    /** Dropdown adapter only; the search lives in [debounceAndSearch], not in a [Filter]. */
    private inner class SuggestionAdapter(
        context: Context,
    ) : BaseAdapter(), Filterable {

        private var results: List<RecipientCandidate> = emptyList()
        private var lastQuery: String = ""
        private val inflater = LayoutInflater.from(context)

        fun getCandidateAt(position: Int): RecipientCandidate? = results.getOrNull(position)

        override fun getCount(): Int = if (results.isEmpty() && lastQuery.isNotBlank()) 1 else results.size

        override fun getItem(position: Int): Any? = results.getOrNull(position)

        override fun getItemId(position: Int): Long = position.toLong()

        override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
            val view = convertView ?: inflater.inflate(R.layout.item_recipient_suggestion, parent, false)
            val nameView = view.findViewById<TextView>(R.id.recipientSuggestionName)
            val emailView = view.findViewById<TextView>(R.id.recipientSuggestionEmail)
            val candidate = results.getOrNull(position)
            if (candidate == null) {
                nameView.text = context.getString(R.string.recipient_no_contacts_found)
                emailView.text = ""
            } else {
                nameView.text = bolded(candidate.name, lastQuery)
                emailView.text = bolded(candidate.email, lastQuery)
            }
            return view
        }

        private fun bolded(text: String, query: String): CharSequence {
            val span = SpannableString(text)
            matchRanges(text, query).forEach { range ->
                span.setSpan(StyleSpan(Typeface.BOLD), range.first, range.last + 1, SpannableString.SPAN_EXCLUSIVE_EXCLUSIVE)
            }
            return span
        }

        /** Called on the main thread once a debounced search has actually completed. */
        fun submit(query: String, matches: List<RecipientCandidate>) {
            lastQuery = query
            results = matches
            notifyDataSetChanged()
        }

        /** [AutoCompleteTextView] demands a [Filterable]; this only republishes [submit]'s results. */
        override fun getFilter(): Filter = object : Filter() {
            override fun performFiltering(constraint: CharSequence?): FilterResults =
                FilterResults().apply {
                    values = results
                    count = this@SuggestionAdapter.count
                }

            override fun publishResults(constraint: CharSequence?, filterResults: FilterResults?) {
                notifyDataSetChanged()
            }
        }
    }

    /** Real debounce: the next keystroke cancels the job, and so does the view's lifecycle. */
    private fun debounceAndSearch(
        adapter: SuggestionAdapter,
        search: suspend (String) -> List<RecipientCandidate>,
        query: String,
    ) {
        searchJob?.cancel()
        val scope = findViewTreeLifecycleOwner()?.lifecycleScope ?: return
        searchJob = scope.launch {
            delay(DEBOUNCE_MS)
            val matches = if (query.isBlank()) emptyList() else search(query).take(MAX_RESULTS)
            // Still the current text? The delay above already drops most stale queries; this covers
            // a search slower than the next keystroke.
            if (field.text.toString() != query) return@launch
            adapter.submit(query, matches)
            if (matches.isNotEmpty() || query.isNotBlank()) field.showDropDown()
        }
    }

    override fun onDetachedFromWindow() {
        super.onDetachedFromWindow()
        searchJob?.cancel()
        searchJob = null
    }

    private companion object {
        const val DEBOUNCE_MS = 150L
        const val MAX_RESULTS = 5
    }
}
