package org.kysecurity.mail.contacts

import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.lifecycle.lifecycleScope
import com.google.android.material.chip.Chip
import org.kysecurity.mail.R
import org.kysecurity.mail.applyDangerButtonTheme
import org.kysecurity.mail.applyPrimaryButtonTheme
import org.kysecurity.mail.StatusTone
import org.kysecurity.mail.applyStatusBadgeTheme
import org.kysecurity.mail.applyTextButtonTheme
import org.kysecurity.mail.applyThemeToActivity
import org.kysecurity.mail.applyTopInsetWithHeader
import org.kysecurity.mail.bindAvatar
import org.kysecurity.mail.contacts.device.DeviceContactsRuntime
import org.kysecurity.mail.data.DataRuntime
import org.kysecurity.mail.pgp.hasPgpIdentity
import kotlinx.coroutines.launch
import org.kysecurity.mail.security.LockedActivity
import org.kysecurity.mail.security.showSecurely

/** Covers every contact field except photoRef/groupIDs (no UI) and isSelf/pgpKey (read-only). */
class ContactEditActivity : LockedActivity() {

    private lateinit var avatarView: TextView
    private lateinit var fnField: EditText
    private lateinit var orgField: EditText
    private lateinit var titleField: EditText
    private lateinit var departmentField: EditText
    private lateinit var notesField: EditText
    private lateinit var saveButton: Button
    private lateinit var deleteButton: Button
    private lateinit var givenNameField: EditText
    private lateinit var familyNameField: EditText
    private lateinit var middleNameField: EditText
    private lateinit var prefixField: EditText
    private lateinit var suffixField: EditText
    private lateinit var nicknameField: EditText
    private lateinit var phoneticGivenNameField: EditText
    private lateinit var phoneticFamilyNameField: EditText
    private lateinit var pronounsField: EditText
    private lateinit var selfBadge: Chip
    private lateinit var pgpBadge: Chip
    private lateinit var emailList: RepeatableFieldList<ContactFieldDto>
    private lateinit var phoneList: RepeatableFieldList<ContactFieldDto>
    private lateinit var addressList: RepeatableFieldList<ContactAddressDto>
    private lateinit var websiteList: RepeatableFieldList<ContactUrlDto>
    private lateinit var imList: RepeatableFieldList<ContactImDto>
    private lateinit var birthdayField: EditText
    private var birthdayValue: String? = null
    private lateinit var eventList: RepeatableFieldList<ContactEventDto>
    private lateinit var relationList: RepeatableFieldList<ContactRelationDto>
    private lateinit var customFieldList: RepeatableFieldList<ContactCustomFieldDto>

    private var existingUid: String = ""
    private var existingRev: Long = 0

    /** [save] must `.copy()` off this — the local upsert and the server push both replace the row. */
    private var loadedDto: ContactDto = ContactDto()

    override fun onCreateUnlocked(savedInstanceState: Bundle?) {
        setContentView(R.layout.activity_contact_edit)
        applyThemeToActivity(this)
        val formRoot = findViewById<View>(R.id.contactEditRoot)
        // Keeps this form out of the saved-state Bundle; with this cleared the subtree is skipped.
        formRoot.isSaveFromParentEnabled = false
        applyTopInsetWithHeader(this, formRoot)
        setTitle(R.string.contacts_edit_title)

        avatarView = findViewById(R.id.contactEditAvatar)
        fnField = findViewById(R.id.editContactName)
        orgField = findViewById(R.id.editContactOrg)
        titleField = findViewById(R.id.editContactTitle)
        departmentField = findViewById(R.id.editContactDepartment)
        notesField = findViewById(R.id.editContactNotes)
        givenNameField = findViewById(R.id.editContactGivenName)
        familyNameField = findViewById(R.id.editContactFamilyName)
        middleNameField = findViewById(R.id.editContactMiddleName)
        prefixField = findViewById(R.id.editContactPrefix)
        suffixField = findViewById(R.id.editContactSuffix)
        nicknameField = findViewById(R.id.editContactNickname)
        phoneticGivenNameField = findViewById(R.id.editContactPhoneticGivenName)
        phoneticFamilyNameField = findViewById(R.id.editContactPhoneticFamilyName)
        pronounsField = findViewById(R.id.editContactPronouns)
        selfBadge = findViewById(R.id.contactEditSelfBadge)
        pgpBadge = findViewById(R.id.contactEditPgpBadge)
        findViewById<ExpandableSectionView>(R.id.sectionName).setTitle(getString(R.string.contacts_section_name))
        findViewById<ExpandableSectionView>(R.id.sectionName).setExpanded(true)
        findViewById<ExpandableSectionView>(R.id.sectionWork).setTitle(getString(R.string.contacts_section_work))
        findViewById<ExpandableSectionView>(R.id.sectionContact).setTitle(getString(R.string.contacts_section_contact))
        emailList = RepeatableFieldList(
            container = findViewById(R.id.emailRowsContainer),
            addButton = findViewById(R.id.btnAddEmail),
            rowLayoutRes = R.layout.row_contact_two_field,
            removeButtonId = R.id.rowFieldRemove,
            bind = { rowView, item, onItemChanged ->
                val labelField = rowView.findViewById<EditText>(R.id.rowFieldA)
                val valueField = rowView.findViewById<EditText>(R.id.rowFieldB)
                labelField.hint = getString(R.string.contacts_email_row_label_hint)
                valueField.hint = getString(R.string.contacts_email_row_value_hint)
                valueField.inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS
                labelField.setText(item.label.orEmpty())
                valueField.setText(item.value)
                // Read both fields' live text: a listener closing over the bind-time item drops edits.
                val emit: () -> Unit = {
                    onItemChanged(
                        item.copy(
                            label = labelField.text.toString().trim().ifBlank { null },
                            value = valueField.text.toString().trim(),
                        ),
                    )
                }
                labelField.addTextChangedListener(SimpleTextWatcher(emit))
                valueField.addTextChangedListener(SimpleTextWatcher(emit))
            },
            isBlank = { it.label.isNullOrBlank() && it.value.isBlank() },
            default = { ContactFieldDto() },
            onChanged = { findViewById<ExpandableSectionView>(R.id.sectionContact).setItemCount(emailList.items().size + phoneList.items().size) },
        )
        phoneList = RepeatableFieldList(
            container = findViewById(R.id.phoneRowsContainer),
            addButton = findViewById(R.id.btnAddPhone),
            rowLayoutRes = R.layout.row_contact_two_field,
            removeButtonId = R.id.rowFieldRemove,
            bind = { rowView, item, onItemChanged ->
                val labelField = rowView.findViewById<EditText>(R.id.rowFieldA)
                val valueField = rowView.findViewById<EditText>(R.id.rowFieldB)
                labelField.hint = getString(R.string.contacts_phone_row_label_hint)
                valueField.hint = getString(R.string.contacts_phone_row_value_hint)
                valueField.inputType = android.text.InputType.TYPE_CLASS_PHONE
                labelField.setText(item.label.orEmpty())
                valueField.setText(item.value)
                val emit: () -> Unit = {
                    onItemChanged(
                        item.copy(
                            label = labelField.text.toString().trim().ifBlank { null },
                            value = valueField.text.toString().trim(),
                        ),
                    )
                }
                labelField.addTextChangedListener(SimpleTextWatcher(emit))
                valueField.addTextChangedListener(SimpleTextWatcher(emit))
            },
            isBlank = { it.label.isNullOrBlank() && it.value.isBlank() },
            default = { ContactFieldDto() },
            onChanged = { findViewById<ExpandableSectionView>(R.id.sectionContact).setItemCount(emailList.items().size + phoneList.items().size) },
        )
        findViewById<ExpandableSectionView>(R.id.sectionAddresses).setTitle(getString(R.string.contacts_section_addresses))
        addressList = RepeatableFieldList(
            container = findViewById(R.id.addressRowsContainer),
            addButton = findViewById(R.id.btnAddAddress),
            rowLayoutRes = R.layout.row_contact_address,
            removeButtonId = R.id.rowAddressRemove,
            bind = { rowView, item, onItemChanged ->
                val labelField = rowView.findViewById<EditText>(R.id.rowAddressLabel)
                val streetField = rowView.findViewById<EditText>(R.id.rowAddressStreet)
                val cityField = rowView.findViewById<EditText>(R.id.rowAddressCity)
                val regionField = rowView.findViewById<EditText>(R.id.rowAddressRegion)
                val postalField = rowView.findViewById<EditText>(R.id.rowAddressPostalCode)
                val countryField = rowView.findViewById<EditText>(R.id.rowAddressCountry)
                labelField.setText(item.label.orEmpty())
                streetField.setText(item.street.orEmpty())
                cityField.setText(item.city.orEmpty())
                regionField.setText(item.region.orEmpty())
                postalField.setText(item.postalCode.orEmpty())
                countryField.setText(item.country.orEmpty())
                val emit: () -> Unit = {
                    onItemChanged(
                        item.copy(
                            label = labelField.text.toString().trim().ifBlank { null },
                            street = streetField.text.toString().trim().ifBlank { null },
                            city = cityField.text.toString().trim().ifBlank { null },
                            region = regionField.text.toString().trim().ifBlank { null },
                            postalCode = postalField.text.toString().trim().ifBlank { null },
                            country = countryField.text.toString().trim().ifBlank { null },
                        ),
                    )
                }
                labelField.addTextChangedListener(SimpleTextWatcher(emit))
                streetField.addTextChangedListener(SimpleTextWatcher(emit))
                cityField.addTextChangedListener(SimpleTextWatcher(emit))
                regionField.addTextChangedListener(SimpleTextWatcher(emit))
                postalField.addTextChangedListener(SimpleTextWatcher(emit))
                countryField.addTextChangedListener(SimpleTextWatcher(emit))
            },
            isBlank = { it.label.isNullOrBlank() && it.street.isNullOrBlank() && it.city.isNullOrBlank() && it.region.isNullOrBlank() && it.postalCode.isNullOrBlank() && it.country.isNullOrBlank() },
            default = { ContactAddressDto() },
            onChanged = { findViewById<ExpandableSectionView>(R.id.sectionAddresses).setItemCount(addressList.items().size) },
        )
        findViewById<ExpandableSectionView>(R.id.sectionOnline).setTitle(getString(R.string.contacts_section_online))
        websiteList = RepeatableFieldList(
            container = findViewById(R.id.websiteRowsContainer),
            addButton = findViewById(R.id.btnAddWebsite),
            rowLayoutRes = R.layout.row_contact_two_field,
            removeButtonId = R.id.rowFieldRemove,
            bind = { rowView, item, onItemChanged ->
                val labelField = rowView.findViewById<EditText>(R.id.rowFieldA)
                val valueField = rowView.findViewById<EditText>(R.id.rowFieldB)
                labelField.hint = getString(R.string.contacts_website_row_label_hint)
                valueField.hint = getString(R.string.contacts_website_row_value_hint)
                valueField.inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_URI
                valueField.inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_URI
                labelField.setText(item.label.orEmpty())
                valueField.setText(item.value)
                val emit: () -> Unit = {
                    onItemChanged(
                        item.copy(
                            label = labelField.text.toString().trim().ifBlank { null },
                            value = valueField.text.toString().trim(),
                        ),
                    )
                }
                labelField.addTextChangedListener(SimpleTextWatcher(emit))
                valueField.addTextChangedListener(SimpleTextWatcher(emit))
            },
            isBlank = { it.label.isNullOrBlank() && it.value.isBlank() },
            default = { ContactUrlDto() },
            onChanged = { findViewById<ExpandableSectionView>(R.id.sectionOnline).setItemCount(websiteList.items().size + imList.items().size) },
        )
        imList = RepeatableFieldList(
            container = findViewById(R.id.imRowsContainer),
            addButton = findViewById(R.id.btnAddIm),
            rowLayoutRes = R.layout.row_contact_im,
            removeButtonId = R.id.rowImRemove,
            bind = { rowView, item, onItemChanged ->
                val serviceField = rowView.findViewById<EditText>(R.id.rowImService)
                val labelField = rowView.findViewById<EditText>(R.id.rowImLabel)
                val valueField = rowView.findViewById<EditText>(R.id.rowImValue)
                serviceField.setText(item.service.orEmpty())
                labelField.setText(item.label.orEmpty())
                valueField.setText(item.value)
                val emit: () -> Unit = {
                    onItemChanged(
                        item.copy(
                            service = serviceField.text.toString().trim().ifBlank { null },
                            label = labelField.text.toString().trim().ifBlank { null },
                            value = valueField.text.toString().trim(),
                        ),
                    )
                }
                serviceField.addTextChangedListener(SimpleTextWatcher(emit))
                labelField.addTextChangedListener(SimpleTextWatcher(emit))
                valueField.addTextChangedListener(SimpleTextWatcher(emit))
            },
            isBlank = { it.service.isNullOrBlank() && it.label.isNullOrBlank() && it.value.isBlank() },
            default = { ContactImDto() },
            onChanged = { findViewById<ExpandableSectionView>(R.id.sectionOnline).setItemCount(websiteList.items().size + imList.items().size) },
        )
        findViewById<ExpandableSectionView>(R.id.sectionPersonal).setTitle(getString(R.string.contacts_section_personal))
        birthdayField = findViewById(R.id.editContactBirthday)
        wireDatePicker(birthdayField) { picked -> birthdayValue = picked }
        eventList = RepeatableFieldList(
            container = findViewById(R.id.eventRowsContainer),
            addButton = findViewById(R.id.btnAddEvent),
            rowLayoutRes = R.layout.row_contact_event,
            removeButtonId = R.id.rowEventRemove,
            bind = { rowView, item, onItemChanged ->
                val labelField = rowView.findViewById<EditText>(R.id.rowEventLabel)
                val dateField = rowView.findViewById<EditText>(R.id.rowEventDate)
                labelField.setText(item.label.orEmpty())
                dateField.setText(item.date)
                // wireDatePicker sets the text before this fires, so the live read below is current.
                val emit: () -> Unit = {
                    onItemChanged(
                        item.copy(
                            label = labelField.text.toString().trim().ifBlank { null },
                            date = dateField.text.toString(),
                        ),
                    )
                }
                labelField.addTextChangedListener(SimpleTextWatcher(emit))
                wireDatePicker(dateField) { emit() }
            },
            isBlank = { it.label.isNullOrBlank() && it.date.isBlank() },
            default = { ContactEventDto() },
            onChanged = { findViewById<ExpandableSectionView>(R.id.sectionPersonal).setItemCount(eventList.items().size + relationList.items().size) },
        )
        relationList = RepeatableFieldList(
            container = findViewById(R.id.relationRowsContainer),
            addButton = findViewById(R.id.btnAddRelation),
            rowLayoutRes = R.layout.row_contact_two_field,
            removeButtonId = R.id.rowFieldRemove,
            bind = { rowView, item, onItemChanged ->
                val labelField = rowView.findViewById<EditText>(R.id.rowFieldA)
                val valueField = rowView.findViewById<EditText>(R.id.rowFieldB)
                labelField.hint = getString(R.string.contacts_relation_row_label_hint)
                valueField.hint = getString(R.string.contacts_relation_row_value_hint)
                labelField.setText(item.label.orEmpty())
                valueField.setText(item.name)
                val emit: () -> Unit = {
                    onItemChanged(
                        item.copy(
                            label = labelField.text.toString().trim().ifBlank { null },
                            name = valueField.text.toString().trim(),
                        ),
                    )
                }
                labelField.addTextChangedListener(SimpleTextWatcher(emit))
                valueField.addTextChangedListener(SimpleTextWatcher(emit))
            },
            isBlank = { it.label.isNullOrBlank() && it.name.isBlank() },
            default = { ContactRelationDto() },
            onChanged = { findViewById<ExpandableSectionView>(R.id.sectionPersonal).setItemCount(eventList.items().size + relationList.items().size) },
        )
        findViewById<ExpandableSectionView>(R.id.sectionNotes).setTitle(getString(R.string.contacts_section_notes))
        findViewById<ExpandableSectionView>(R.id.sectionOther).setTitle(getString(R.string.contacts_section_other))
        customFieldList = RepeatableFieldList(
            container = findViewById(R.id.customFieldRowsContainer),
            addButton = findViewById(R.id.btnAddCustomField),
            rowLayoutRes = R.layout.row_contact_two_field,
            removeButtonId = R.id.rowFieldRemove,
            bind = { rowView, item, onItemChanged ->
                val labelField = rowView.findViewById<EditText>(R.id.rowFieldA)
                val valueField = rowView.findViewById<EditText>(R.id.rowFieldB)
                labelField.hint = getString(R.string.contacts_customfield_row_label_hint)
                valueField.hint = getString(R.string.contacts_customfield_row_value_hint)
                labelField.setText(item.label)
                valueField.setText(item.value)
                val emit: () -> Unit = {
                    onItemChanged(
                        item.copy(
                            label = labelField.text.toString().trim(),
                            value = valueField.text.toString().trim(),
                        ),
                    )
                }
                labelField.addTextChangedListener(SimpleTextWatcher(emit))
                valueField.addTextChangedListener(SimpleTextWatcher(emit))
            },
            isBlank = { it.label.isBlank() && it.value.isBlank() },
            default = { ContactCustomFieldDto() },
            onChanged = { findViewById<ExpandableSectionView>(R.id.sectionOther).setItemCount(customFieldList.items().size) },
        )
        saveButton = findViewById(R.id.btnSaveContact)
        deleteButton = findViewById(R.id.btnDeleteContact)

        applyPrimaryButtonTheme(this, saveButton)
        applyDangerButtonTheme(this, deleteButton)
        addButtonIds.forEach { applyTextButtonTheme(this, findViewById(it)) }
        bindAvatar(this, avatarView, fnField.text.toString(), sizeDp = 52)
        fnField.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) = Unit
            override fun afterTextChanged(s: Editable?) {
                bindAvatar(this@ContactEditActivity, avatarView, s?.toString().orEmpty(), sizeDp = 52)
            }
        })

        existingUid = intent.getStringExtra(EXTRA_UID).orEmpty()
        if (existingUid.isBlank()) {
            deleteButton.visibility = View.GONE
        }

        // Restore instead of loading, so the database read cannot land afterwards over the edits.
        val draft = ContactEditDraftCache.take(existingUid)
        when {
            draft != null -> lifecycleScope.launch { populateForm(draft) }
            existingUid.isNotBlank() -> loadExisting(existingUid)
        }

        saveButton.setOnClickListener { save() }
        deleteButton.setOnClickListener { confirmDelete() }
    }

    /** The per-section "Add" actions: secondary to Save, so text buttons, not filled ones. */
    private val addButtonIds = listOf(
        R.id.btnAddEmail, R.id.btnAddPhone, R.id.btnAddAddress, R.id.btnAddWebsite,
        R.id.btnAddIm, R.id.btnAddEvent, R.id.btnAddRelation, R.id.btnAddCustomField,
    )

    override fun onStop() {
        super.onStop()
        // onCreate bailed before assigning any view: there is nothing to stash, and touching the
        // lateinit fields below would throw.
        if (redirectedToUnlock) return
        // A save already wrote to the database and a back-out was deliberate; clearing stops bleed.
        if (isFinishing) {
            ContactEditDraftCache.clear()
            return
        }
        ContactEditDraftCache.save(existingUid, currentFormDto(fnField.text.toString().trim()))
    }

    override fun onResume() {
        super.onResume()
        if (redirectedToUnlock) return
        applyThemeToActivity(this)
        applyPrimaryButtonTheme(this, saveButton)
        applyDangerButtonTheme(this, deleteButton)
        addButtonIds.forEach { applyTextButtonTheme(this, findViewById(it)) }
        bindAvatar(this, avatarView, fnField.text.toString(), sizeDp = 52)
    }

    private fun loadExisting(uid: String) {
        lifecycleScope.launch {
            val entity = DataRuntime.graph(this@ContactEditActivity).database.contactDao().getByUid(uid) ?: return@launch
            populateForm(entity.toDto())
        }
    }

    /** Writes a [ContactDto] into the form. Shared by the database load and the draft restore, so
     *  a restored draft cannot drift from a loaded contact. */
    private suspend fun populateForm(dto: ContactDto) {
        loadedDto = dto
        existingRev = dto.rev
        fnField.setText(dto.fn)
        orgField.setText(dto.org.orEmpty())
        titleField.setText(dto.title.orEmpty())
        departmentField.setText(dto.department.orEmpty())
        notesField.setText(dto.notes.orEmpty())
        givenNameField.setText(dto.givenName.orEmpty())
        familyNameField.setText(dto.familyName.orEmpty())
        middleNameField.setText(dto.middleName.orEmpty())
        prefixField.setText(dto.prefix.orEmpty())
        suffixField.setText(dto.suffix.orEmpty())
        nicknameField.setText(dto.nickname.orEmpty())
        phoneticGivenNameField.setText(dto.phoneticGivenName.orEmpty())
        phoneticFamilyNameField.setText(dto.phoneticFamilyName.orEmpty())
        pronounsField.setText(dto.pronouns.orEmpty())
        selfBadge.visibility = if (dto.isSelf) View.VISIBLE else View.GONE
        if (dto.isSelf) {
            selfBadge.text = getString(R.string.contact_self_label)
            applyStatusBadgeTheme(this@ContactEditActivity, selfBadge, StatusTone.SUCCESS)
        }
        // Only the self-contact needs the extra (network) identity check — every other
        // contact's badge is fully determined by its own pgpKey field.
        val selfHasPgpIdentity = if (dto.isSelf) hasPgpIdentity(this@ContactEditActivity) else null
        val hasKey = contactHasLinkedPgpKey(dto.pgpKey, dto.isSelf, selfHasPgpIdentity)
        pgpBadge.visibility = if (hasKey) View.VISIBLE else View.GONE
        if (hasKey) {
            pgpBadge.text = getString(R.string.contacts_pgp_badge_visible)
            applyStatusBadgeTheme(this@ContactEditActivity, pgpBadge, StatusTone.SUCCESS)
        }
        findViewById<ExpandableSectionView>(R.id.sectionWork).setExpanded(
            dto.org != null || dto.title != null || dto.department != null,
        )
        emailList.setItems(dto.emails)
        phoneList.setItems(dto.phones)
        findViewById<ExpandableSectionView>(R.id.sectionContact).setExpanded(dto.emails.isNotEmpty() || dto.phones.isNotEmpty())
        findViewById<ExpandableSectionView>(R.id.sectionContact).setItemCount(dto.emails.size + dto.phones.size)
        addressList.setItems(dto.addresses)
        findViewById<ExpandableSectionView>(R.id.sectionAddresses).setExpanded(dto.addresses.isNotEmpty())
        findViewById<ExpandableSectionView>(R.id.sectionAddresses).setItemCount(dto.addresses.size)
        websiteList.setItems(dto.websites)
        imList.setItems(dto.ims)
        findViewById<ExpandableSectionView>(R.id.sectionOnline).setExpanded(dto.websites.isNotEmpty() || dto.ims.isNotEmpty())
        findViewById<ExpandableSectionView>(R.id.sectionOnline).setItemCount(dto.websites.size + dto.ims.size)
        birthdayValue = dto.birthday
        birthdayField.setText(dto.birthday.orEmpty())
        eventList.setItems(dto.events)
        relationList.setItems(dto.relations)
        findViewById<ExpandableSectionView>(R.id.sectionNotes).setExpanded(!dto.notes.isNullOrBlank())
        customFieldList.setItems(dto.customFields)
        findViewById<ExpandableSectionView>(R.id.sectionOther).setExpanded(dto.customFields.isNotEmpty())
        findViewById<ExpandableSectionView>(R.id.sectionOther).setItemCount(dto.customFields.size)
        findViewById<ExpandableSectionView>(R.id.sectionPersonal).setExpanded(
            dto.birthday != null || dto.events.isNotEmpty() || dto.relations.isNotEmpty(),
        )
        findViewById<ExpandableSectionView>(R.id.sectionPersonal).setItemCount(dto.events.size + dto.relations.size)
    }

    /** Reads the form into a DTO, merged onto [loadedDto] so unshown fields survive. Shared by the
     *  save path and the draft stash. */
    private fun currentFormDto(fn: String): ContactDto = mergedContactDto(
        loaded = loadedDto,
        uid = existingUid,
        rev = existingRev,
        fn = fn,
        givenName = givenNameField.text.toString().trim().ifBlank { null },
        familyName = familyNameField.text.toString().trim().ifBlank { null },
        middleName = middleNameField.text.toString().trim().ifBlank { null },
        prefix = prefixField.text.toString().trim().ifBlank { null },
        suffix = suffixField.text.toString().trim().ifBlank { null },
        nickname = nicknameField.text.toString().trim().ifBlank { null },
        org = orgField.text.toString().trim().ifBlank { null },
        title = titleField.text.toString().trim().ifBlank { null },
        department = departmentField.text.toString().trim().ifBlank { null },
        notes = notesField.text.toString().trim().ifBlank { null },
        birthday = birthdayValue,
        emails = emailList.items(),
        phones = phoneList.items(),
        addresses = addressList.items(),
        websites = websiteList.items(),
        ims = imList.items(),
        relations = relationList.items(),
        events = eventList.items(),
        phoneticGivenName = phoneticGivenNameField.text.toString().trim().ifBlank { null },
        phoneticFamilyName = phoneticFamilyNameField.text.toString().trim().ifBlank { null },
        customFields = customFieldList.items(),
        pronouns = pronounsField.text.toString().trim().ifBlank { null },
    )

    private fun save() {
        val fn = fnField.text.toString().trim()
        if (fn.isBlank()) {
            Toast.makeText(this, R.string.contacts_name_required, Toast.LENGTH_SHORT).show()
            return
        }
        val dto = currentFormDto(fn)

        lifecycleScope.launch {
            val graph = ContactsRuntime.graph(this@ContactEditActivity)
            if (existingUid.isBlank()) {
                graph.repository.queueCreate(dto)
            } else {
                // The user's own edit, behind the app lock, is not the third-party rebind this catches.
                graph.repository.queueUpdate(dto, identityChanged = false)
            }
            graph.coordinator.syncNowAsync()
            DeviceContactsRuntime.graph(this@ContactEditActivity).coordinator.syncNowAsync()
            Toast.makeText(this@ContactEditActivity, R.string.contacts_saved, Toast.LENGTH_SHORT).show()
            finish()
        }
    }

    private fun confirmDelete() {
        AlertDialog.Builder(this)
            .setTitle(R.string.contacts_delete_confirm_title)
            .setMessage(R.string.contacts_delete_confirm_message)
            .setPositiveButton(R.string.contacts_delete_confirm_positive) { _, _ -> delete() }
            .setNegativeButton(R.string.cancel, null)
            .create()
            .showSecurely()
    }

    private fun delete() {
        lifecycleScope.launch {
            val deviceGraph = DeviceContactsRuntime.graph(this@ContactEditActivity)
            deviceGraph.repository.deleteDeviceRawContact(existingUid)

            val graph = ContactsRuntime.graph(this@ContactEditActivity)
            graph.repository.queueDelete(existingUid, existingRev)
            graph.coordinator.syncNowAsync()
            finish()
        }
    }

    /** [field] must have `focusable="false"` so a tap opens the picker, not the soft keyboard. */
    private fun wireDatePicker(field: EditText, onPicked: (String) -> Unit) {
        field.setOnClickListener {
            val calendar = java.util.Calendar.getInstance()
            val existing = field.text.toString().trim()
            if (existing.isNotBlank()) {
                runCatching {
                    val parts = existing.split("-").map { it.toInt() }
                    calendar.set(parts[0], parts[1] - 1, parts[2])
                }
            }
            android.app.DatePickerDialog(
                this,
                { _, year, month, dayOfMonth ->
                    val formatted = "%04d-%02d-%02d".format(year, month + 1, dayOfMonth)
                    field.setText(formatted)
                    onPicked(formatted)
                },
                calendar.get(java.util.Calendar.YEAR),
                calendar.get(java.util.Calendar.MONTH),
                calendar.get(java.util.Calendar.DAY_OF_MONTH),
            ).show()
        }
    }

    private class SimpleTextWatcher(private val onChanged: () -> Unit) : android.text.TextWatcher {
        override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
        override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) = Unit
        override fun afterTextChanged(s: Editable?) = onChanged()
    }

    @androidx.annotation.VisibleForTesting
    internal fun setNameForTest(name: String) = fnField.setText(name)

    @androidx.annotation.VisibleForTesting
    internal fun nameForTest(): String = fnField.text.toString()

    companion object {
        const val EXTRA_UID = "contact_uid"
    }
}

/** `.copy()`s off [loaded] so photoRef/groupIDs/isSelf/pgpKey survive instead of being wiped. */
internal fun mergedContactDto(
    loaded: ContactDto,
    uid: String,
    rev: Long,
    fn: String,
    givenName: String?,
    familyName: String?,
    middleName: String?,
    prefix: String?,
    suffix: String?,
    nickname: String?,
    org: String?,
    title: String?,
    department: String?,
    notes: String?,
    birthday: String?,
    emails: List<ContactFieldDto>,
    phones: List<ContactFieldDto>,
    addresses: List<ContactAddressDto>,
    ims: List<ContactImDto>,
    websites: List<ContactUrlDto>,
    relations: List<ContactRelationDto>,
    events: List<ContactEventDto>,
    phoneticGivenName: String?,
    phoneticFamilyName: String?,
    customFields: List<ContactCustomFieldDto>,
    pronouns: String?,
): ContactDto = loaded.copy(
    uid = uid,
    rev = rev,
    fn = fn,
    givenName = givenName,
    familyName = familyName,
    middleName = middleName,
    prefix = prefix,
    suffix = suffix,
    nickname = nickname,
    org = org,
    title = title,
    department = department,
    notes = notes,
    birthday = birthday,
    emails = emails,
    phones = phones,
    addresses = addresses,
    ims = ims,
    websites = websites,
    relations = relations,
    events = events,
    phoneticGivenName = phoneticGivenName,
    phoneticFamilyName = phoneticFamilyName,
    customFields = customFields,
    pronouns = pronouns,
)
