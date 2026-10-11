package org.kysecurity.mail.contacts

import android.app.Activity
import android.content.Intent
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import org.kysecurity.mail.R
import org.kysecurity.mail.security.EphemeralAttachmentBytes
import org.kysecurity.mail.security.SecurityRuntime
import org.kysecurity.mail.security.attachmentSaveOffered
import org.kysecurity.mail.security.showSecurely

/** Shares [contacts] as one .vcf through the share sheet. The bytes live only in
 *  [EphemeralAttachmentBytes]; nothing is written to storage. Refused under Hostile Location
 *  Protection, like saving an attachment: the receiving app may write it anywhere. */
fun shareContactsAsVCard(activity: Activity, contacts: List<ContactDto>, fileName: String) {
    val protection = SecurityRuntime.graph(activity).hostileLocationSettings.isEnabled()
    if (!attachmentSaveOffered(protection)) {
        Toast.makeText(activity, R.string.contacts_vcard_blocked_hostile, Toast.LENGTH_LONG).show()
        return
    }
    if (contacts.isEmpty()) {
        Toast.makeText(activity, R.string.contacts_vcard_none, Toast.LENGTH_SHORT).show()
        return
    }
    AlertDialog.Builder(activity)
        .setTitle(R.string.contacts_vcard_version_title)
        .setItems(VCARD_SHARE_CHOICES.map { activity.getString(it.second) }.toTypedArray()) { _, which ->
            launchShare(activity, contacts, which, fileName)
        }
        .setNegativeButton(android.R.string.cancel, null)
        .create()
        .showSecurely()
}

/** The version dialog's items, in order. */
internal val VCARD_SHARE_CHOICES = listOf(
    VCardVersion.V4 to R.string.contacts_vcard_v4,
    VCardVersion.V3 to R.string.contacts_vcard_v3,
)

/** The ACTION_SEND for dialog choice [which]; null when the ephemeral provider is full. */
internal fun vcardShareIntent(contacts: List<ContactDto>, which: Int, fileName: String): Intent? {
    val vcard = writeVCards(contacts, VCARD_SHARE_CHOICES[which].first)
    val uri = EphemeralAttachmentBytes.register(vcard.toByteArray(Charsets.UTF_8), VCARD_MIME_TYPE, fileName)
        ?: return null
    return Intent(Intent.ACTION_SEND)
        .setType(VCARD_MIME_TYPE)
        .putExtra(Intent.EXTRA_STREAM, uri)
        .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
}

private fun launchShare(activity: Activity, contacts: List<ContactDto>, which: Int, fileName: String) {
    val send = vcardShareIntent(contacts, which, fileName) ?: run {
        Toast.makeText(activity, R.string.attachment_too_many_open, Toast.LENGTH_LONG).show()
        return
    }
    val chooser = Intent.createChooser(send, activity.getString(R.string.contacts_vcard_share_title))
        .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    runCatching { activity.startActivity(chooser) }.onFailure {
        @Suppress("DEPRECATION")
        val uri = send.getParcelableExtra<android.net.Uri>(Intent.EXTRA_STREAM)
        EphemeralAttachmentBytes.revoke(uri?.lastPathSegment.orEmpty())
        Toast.makeText(activity, R.string.contacts_vcard_share_failed, Toast.LENGTH_LONG).show()
    }
}
