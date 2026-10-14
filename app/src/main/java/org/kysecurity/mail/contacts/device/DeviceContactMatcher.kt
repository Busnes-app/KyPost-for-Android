package org.kysecurity.mail.contacts.device

import org.kysecurity.mail.contacts.ContactDto

object DeviceContactMatcher {
    fun normalizeEmail(email: String): String {
        return email.trim().lowercase()
    }

    /** Strips non-digits, then drops a leading NANP "1" country code (11 digits, e.g.
     *  "+1 555 123 4567") so it normalizes the same as its 10-digit form ("555-123-4567") —
     *  device contacts and server-synced contacts don't consistently store one or the other. */
    fun normalizePhone(phone: String): String {
        val digits = phone.replace(Regex("[^0-9]"), "")
        return if (digits.length == 11 && digits.startsWith("1")) digits.substring(1) else digits
    }

    /** Values keep their first owner, so [findMatch] returns the lowest-positioned match. */
    class Index private constructor() {
        private data class Match(val uid: String, val ordinal: Int)

        private val byValue = HashMap<String, Match>()
        private var size = 0

        fun findMatch(candidateEmails: List<String>, candidatePhones: List<String>): String? {
            val keys = candidateEmails.mapNotNull { emailKey(it) } + candidatePhones.mapNotNull { phoneKey(it) }
            return keys.mapNotNull { byValue[it] }.minByOrNull { it.ordinal }?.uid
        }

        /** Positioned after every contact already indexed. */
        fun add(contact: ContactDto) {
            val match = Match(contact.uid, size++)
            (contact.emails.mapNotNull { emailKey(it.value) } + contact.phones.mapNotNull { phoneKey(it.value) })
                .forEach { byValue.putIfAbsent(it, match) }
        }

        companion object {
            fun of(existing: List<ContactDto>): Index = Index().apply { existing.forEach(::add) }
        }
    }

    // Emails and phones share one map, so keys are namespaced to keep a phone-shaped email apart.
    private fun emailKey(value: String): String? =
        normalizeEmail(value).takeIf { it.isNotBlank() }?.let { "e:$it" }

    private fun phoneKey(value: String): String? =
        normalizePhone(value).takeIf { it.isNotBlank() }?.let { "p:$it" }

    fun findMatch(
        candidateEmails: List<String>,
        candidatePhones: List<String>,
        existing: List<ContactDto>,
    ): String? = Index.of(existing).findMatch(candidateEmails, candidatePhones)
}
