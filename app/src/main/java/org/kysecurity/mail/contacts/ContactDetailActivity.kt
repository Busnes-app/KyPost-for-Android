package org.kysecurity.mail.contacts

import android.content.ActivityNotFoundException
import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.os.Bundle
import android.view.LayoutInflater
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.lifecycle.lifecycleScope
import com.google.android.material.chip.Chip
import org.kysecurity.mail.R
import org.kysecurity.mail.applyStatusBadgeTheme
import org.kysecurity.mail.applyThemeToActivity
import org.kysecurity.mail.applyThemedTitle
import org.kysecurity.mail.applyTopInsetWithHeader
import org.kysecurity.mail.bindAvatar
import org.kysecurity.mail.data.DataRuntime
import org.kysecurity.mail.getStoredThemePalette
import org.kysecurity.mail.pgp.hasPgpIdentity
import kotlinx.coroutines.launch
import org.kysecurity.mail.security.LockedActivity

class ContactDetailActivity : LockedActivity() {

    private lateinit var avatarView: TextView
    private lateinit var nameView: TextView
    private lateinit var subtitleView: TextView
    private lateinit var selfBadge: Chip
    private lateinit var pgpBadge: Chip
    private lateinit var fieldsContainer: LinearLayout
    private lateinit var detailScrollView: ScrollView

    private var uid: String = ""
    private var pendingScrollY: Int = 0

    override fun onCreateUnlocked(savedInstanceState: Bundle?) {
        pendingScrollY = savedInstanceState?.getInt(STATE_SCROLL_Y, 0) ?: 0
        setContentView(R.layout.activity_contact_detail)
        applyThemeToActivity(this)
        applyTopInsetWithHeader(this, findViewById(R.id.contactDetailRoot))
        applyThemedTitle(this, getString(R.string.contacts_edit_title))
        detailScrollView = findViewById(R.id.contactDetailRoot)

        uid = intent.getStringExtra(EXTRA_UID).orEmpty()
        if (uid.isBlank()) {
            finish()
            return
        }

        avatarView = findViewById(R.id.contactDetailAvatar)
        nameView = findViewById(R.id.contactDetailName)
        subtitleView = findViewById(R.id.contactDetailSubtitle)
        selfBadge = findViewById(R.id.contactDetailSelfBadge)
        pgpBadge = findViewById(R.id.contactDetailPgpBadge)
        fieldsContainer = findViewById(R.id.contactDetailFieldsContainer)
    }

    override fun onResume() {
        super.onResume()
        if (redirectedToUnlock) return
        applyThemeToActivity(this)
        loadContact()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        if (redirectedToUnlock) return
        // A scroll offset. No names, addresses, numbers or PGP keys reach this Bundle.
        outState.putInt(STATE_SCROLL_Y, detailScrollView.scrollY)
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        if (redirectedToUnlock) return false
        menu.add(0, MENU_EDIT, 0, R.string.contacts_detail_edit).apply {
            setIcon(R.drawable.ic_edit)
            setShowAsAction(MenuItem.SHOW_AS_ACTION_ALWAYS)
        }
        menu.add(0, MENU_SHARE, 1, R.string.contacts_share_vcard)
        return super.onCreateOptionsMenu(menu)
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            MENU_EDIT -> {
                startActivity(Intent(this, ContactEditActivity::class.java).putExtra(ContactEditActivity.EXTRA_UID, uid))
                true
            }
            MENU_SHARE -> {
                lifecycleScope.launch {
                    val dto = DataRuntime.graph(this@ContactDetailActivity).database.contactDao().getByUid(uid)?.toDto()
                        ?: return@launch
                    shareContactsAsVCard(this@ContactDetailActivity, listOf(dto), dto.fn)
                }
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    private fun loadContact() {
        lifecycleScope.launch {
            val entity = DataRuntime.graph(this@ContactDetailActivity).database.contactDao().getByUid(uid)
            if (entity == null) {
                Toast.makeText(this@ContactDetailActivity, R.string.contacts_detail_not_found, Toast.LENGTH_SHORT).show()
                finish()
                return@launch
            }
            val dto = entity.toDto()
            // Only the self-contact needs the network identity check; every other badge is pgpKey.
            val selfHasPgpIdentity = if (dto.isSelf) hasPgpIdentity(this@ContactDetailActivity) else null
            render(dto, selfHasPgpIdentity, entity.pgpKeyNeedsReverification, entity.identityNeedsReview)
        }
    }

    private fun render(
        dto: ContactDto,
        selfHasPgpIdentity: Boolean?,
        pgpKeyNeedsReverification: Boolean = false,
        identityNeedsReview: Boolean = false,
    ) {
        applyThemedTitle(this, dto.fn.ifBlank { getString(R.string.contacts_edit_title) })
        bindAvatar(this, avatarView, dto.fn, sizeDp = 64)
        nameView.text = dto.fn
        val palette = getStoredThemePalette(this)
        nameView.setTextColor(Color.parseColor(palette.inkStrong))

        val subtitle = contactSubtitle(dto)
        subtitleView.text = subtitle
        subtitleView.visibility = if (subtitle.isBlank()) View.GONE else View.VISIBLE
        subtitleView.setTextColor(Color.parseColor(palette.ink))

        selfBadge.visibility = if (dto.isSelf) View.VISIBLE else View.GONE
        if (dto.isSelf) {
            selfBadge.text = getString(R.string.contact_self_label)
            applyStatusBadgeTheme(this, selfBadge, active = true)
        }

        val hasKey = contactHasLinkedPgpKey(dto.pgpKey, dto.isSelf, selfHasPgpIdentity)
        pgpBadge.visibility = if (hasKey) View.VISIBLE else View.GONE
        if (hasKey) {
            // Not for an identity rebind: a QR check attests to the key, not to the addresses.
            pgpBadge.text = when {
                pgpKeyNeedsReverification -> getString(R.string.contact_status_key_changed)
                identityNeedsReview -> getString(R.string.contact_status_identity_changed)
                else -> getString(R.string.contacts_pgp_badge_visible)
            }
            applyStatusBadgeTheme(this, pgpBadge, active = true)
        }

        fieldsContainer.removeAllViews()

        if (dto.nickname?.isNotBlank() == true || dto.pronouns?.isNotBlank() == true) {
            addSectionHeader(getString(R.string.contacts_section_name))
            dto.nickname?.takeIf { it.isNotBlank() }?.let { addRow(getString(R.string.contacts_nickname_label).removeOptionalSuffix(), it) }
            dto.pronouns?.takeIf { it.isNotBlank() }?.let { addRow(getString(R.string.contacts_pronouns_label).removeOptionalSuffix(), it) }
        }

        if (dto.department?.isNotBlank() == true) {
            addSectionHeader(getString(R.string.contacts_section_work))
            addRow(getString(R.string.contacts_department_label).removeOptionalSuffix(), dto.department!!)
        }

        if (dto.emails.isNotEmpty()) {
            addSectionHeader(getString(R.string.contacts_detail_email_header))
            dto.emails.forEach { field ->
                addRow(field.label, field.value) { openUri("mailto:${field.value}") }
            }
        }

        if (dto.phones.isNotEmpty()) {
            addSectionHeader(getString(R.string.contacts_detail_phone_header))
            dto.phones.forEach { field ->
                addRow(field.label, field.value) { openUri("tel:${field.value}") }
            }
        }

        if (dto.addresses.isNotEmpty()) {
            addSectionHeader(getString(R.string.contacts_section_addresses))
            dto.addresses.forEach { address ->
                val formatted = formatAddress(address)
                if (formatted.isNotBlank()) {
                    addRow(address.label, formatted) { openUri("geo:0,0?q=${Uri.encode(formatted)}") }
                }
            }
        }

        if (dto.websites.isNotEmpty()) {
            addSectionHeader(getString(R.string.contacts_detail_website_header))
            dto.websites.forEach { url ->
                addRow(url.label, url.value) { openUri(urlWithScheme(url.value)) }
            }
        }

        if (dto.ims.isNotEmpty()) {
            addSectionHeader(getString(R.string.contacts_detail_im_header))
            dto.ims.forEach { im ->
                val label = listOfNotNull(im.service?.takeIf { it.isNotBlank() }, im.label?.takeIf { it.isNotBlank() }).joinToString(" · ")
                addRow(label.ifBlank { null }, im.value)
            }
        }

        dto.birthday?.takeIf { it.isNotBlank() }?.let {
            addSectionHeader(getString(R.string.contacts_detail_birthday_header))
            addRow(null, it)
        }

        if (dto.events.isNotEmpty()) {
            addSectionHeader(getString(R.string.contacts_detail_events_header))
            dto.events.forEach { event -> addRow(event.label, event.date) }
        }

        if (dto.relations.isNotEmpty()) {
            addSectionHeader(getString(R.string.contacts_detail_relations_header))
            dto.relations.forEach { relation -> addRow(relation.label, relation.name) }
        }

        if (dto.notes?.isNotBlank() == true) {
            addSectionHeader(getString(R.string.contacts_section_notes))
            addRow(null, dto.notes!!)
        }

        if (dto.customFields.isNotEmpty()) {
            addSectionHeader(getString(R.string.contacts_section_other))
            dto.customFields.forEach { field -> addRow(field.label, field.value) }
        }

        if (pendingScrollY > 0) {
            val target = pendingScrollY
            pendingScrollY = 0
            detailScrollView.post { detailScrollView.scrollTo(0, target) }
        }
    }

    private fun addSectionHeader(title: String) {
        val header = LayoutInflater.from(this).inflate(R.layout.row_contact_detail_header, fieldsContainer, false) as TextView
        header.text = title
        header.setTextColor(Color.parseColor(getStoredThemePalette(this).inkStrong))
        fieldsContainer.addView(header)
    }

    private fun addRow(label: String?, value: String, onClick: (() -> Unit)? = null) {
        val row = LayoutInflater.from(this).inflate(R.layout.row_contact_detail_row, fieldsContainer, false)
        val labelView = row.findViewById<TextView>(R.id.rowDetailLabel)
        val valueView = row.findViewById<TextView>(R.id.rowDetailValue)
        val palette = getStoredThemePalette(this)
        labelView.setTextColor(Color.parseColor(palette.ink))
        valueView.setTextColor(Color.parseColor(palette.inkStrong))
        if (label.isNullOrBlank()) {
            labelView.visibility = View.GONE
        } else {
            labelView.text = label
        }
        valueView.text = value
        if (onClick != null) {
            row.isClickable = true
            row.isFocusable = true
            row.setOnClickListener { onClick() }
        }
        fieldsContainer.addView(row)
    }

    // Contact fields are untrusted: restrict the scheme, and catch RuntimeException (file:// throws).
    private fun openUri(uri: String) {
        val parsed = Uri.parse(uri)
        if (parsed.scheme?.lowercase() !in ALLOWED_FIELD_SCHEMES) {
            Toast.makeText(this, R.string.contacts_detail_no_app_for_action, Toast.LENGTH_SHORT).show()
            return
        }
        try {
            startActivity(Intent(Intent.ACTION_VIEW, parsed))
        } catch (e: RuntimeException) {
            Toast.makeText(this, R.string.contacts_detail_no_app_for_action, Toast.LENGTH_SHORT).show()
        }
    }

    private fun String.removeOptionalSuffix(): String = removeSuffix(" (optional)")

    companion object {
        /** Schemes a contact field may open: the ones this screen actually builds
         *  (`mailto:`/`tel:`/`geo:`) plus web for the website field. */
        private val ALLOWED_FIELD_SCHEMES = setOf("http", "https", "mailto", "tel", "geo")

        private const val MENU_EDIT = 1
        private const val MENU_SHARE = 2
        const val EXTRA_UID = "contact_uid"

        private const val STATE_SCROLL_Y = "contact_detail_scroll_y"
    }
}

internal fun contactSubtitle(dto: ContactDto): String =
    listOfNotNull(dto.title?.takeIf { it.isNotBlank() }, dto.org?.takeIf { it.isNotBlank() }).joinToString(" · ")

/** Blank components are dropped, and it stays one line because it doubles as the `geo:` query. */
internal fun formatAddress(address: ContactAddressDto): String {
    val cityLine = listOfNotNull(
        address.city?.takeIf { it.isNotBlank() },
        listOfNotNull(address.region?.takeIf { it.isNotBlank() }, address.postalCode?.takeIf { it.isNotBlank() })
            .joinToString(" ").takeIf { it.isNotBlank() },
    ).joinToString(", ")
    return listOfNotNull(
        address.street?.takeIf { it.isNotBlank() },
        cityLine.takeIf { it.isNotBlank() },
        address.country?.takeIf { it.isNotBlank() },
    ).joinToString(", ")
}

/** Prefixes `https://` onto a bare `example.com`; an already-schemed value is left untouched. */
internal fun urlWithScheme(value: String): String {
    val trimmed = value.trim()
    return if (trimmed.contains("://")) trimmed else "https://$trimmed"
}
