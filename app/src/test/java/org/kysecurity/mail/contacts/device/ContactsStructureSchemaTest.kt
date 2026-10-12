package org.kysecurity.mail.contacts.device

import org.w3c.dom.Element
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * `res/xml/contacts.xml` against the rules AOSP Contacts' `ExternalAccountType`/`BaseAccountType`
 * enforce. A schema that breaks one is discarded whole and the account is read-only again, with
 * nothing but a log line, so these rules are checked here rather than discovered on a device.
 */
class ContactsStructureSchemaTest {

    private fun repoFile(path: String): File =
        listOf(File(path), File("app/$path")).firstOrNull { it.exists() }
            ?: error("Could not locate $path from ${File(".").absolutePath}")

    private val root: Element by lazy {
        DocumentBuilderFactory.newInstance().newDocumentBuilder()
            .parse(repoFile("src/main/res/xml/contacts.xml")).documentElement
    }

    private fun Element.children(tag: String): List<Element> =
        (0 until childNodes.length).map { childNodes.item(it) }.filterIsInstance<Element>().filter { it.tagName == tag }

    private val kinds: Map<String, Element> by lazy {
        val schema = root.children("EditSchema").single()
        schema.children("DataKind").associateBy { it.getAttribute("kind") }
    }

    @Test
    fun rootAndEditSchema_areWhatAospLooksFor() {
        assertEquals("ContactsAccountType", root.tagName)
        assertEquals(1, root.children("EditSchema").size, "only an EditSchema makes the account writable")
    }

    @Test
    fun nameIsSingleAndSupportsEveryPart() {
        val name = kinds.getValue("name")
        assertEquals("1", name.getAttribute("maxOccurs"))
        for (part in listOf(
            "supportsPrefix", "supportsMiddleName", "supportsSuffix",
            "supportsPhoneticFamilyName", "supportsPhoneticMiddleName", "supportsPhoneticGivenName",
        )) {
            assertEquals("true", name.getAttribute(part), "$part must be true")
        }
        assertTrue("photo" in kinds, "photo must be supported")
    }

    @Test
    fun everyKindIsKnown_singlesAreSingle_andTypesAreValid() {
        for ((kind, element) in kinds) {
            assertTrue(kind in ALL_KINDS, "undefined kind $kind")
            if (kind in SINGLE_KINDS) assertEquals("1", element.getAttribute("maxOccurs"), "$kind must have maxOccurs=1")
            val types = element.children("Type").map { it.getAttribute("type") }
            val allowed = TYPES[kind]
            if (allowed == null) {
                assertTrue(types.isEmpty(), "$kind can't have types")
            } else {
                assertTrue(types.isNotEmpty(), "$kind must have at least one type")
                assertTrue(allowed.containsAll(types), "$kind has an undefined type in $types")
            }
        }
    }

    /** Everything device sync reads back from the phone; editing anything else would stay local. */
    @Test
    fun theKindsDeviceSyncCarries_areEditable() {
        assertTrue(kinds.keys.containsAll(SYNCED_KINDS), "missing ${SYNCED_KINDS - kinds.keys}")
    }

    private companion object {
        val SINGLE_KINDS = setOf("name", "nickname", "organization", "photo", "note", "sip_address", "group_membership")
        val TYPES = mapOf(
            "phone" to setOf(
                "home", "mobile", "work", "fax_work", "fax_home", "pager", "other", "callback", "car",
                "company_main", "isdn", "main", "other_fax", "radio", "telex", "tty_tdd", "work_mobile",
                "work_pager", "assistant", "mms", "custom",
            ),
            "email" to setOf("home", "work", "other", "mobile", "custom"),
            "postal" to setOf("home", "work", "other", "custom"),
            "im" to setOf("aim", "msn", "yahoo", "skype", "qq", "google_talk", "icq", "jabber", "custom"),
            "event" to setOf("birthday", "anniversary", "other", "custom"),
            "relationship" to setOf(
                "assistant", "brother", "child", "domestic_partner", "father", "friend", "manager", "mother",
                "parent", "partner", "referred_by", "relative", "sister", "spouse", "custom",
            ),
        )
        val ALL_KINDS = SINGLE_KINDS + TYPES.keys + setOf("website")
        val SYNCED_KINDS = setOf(
            "name", "phone", "email", "postal", "im", "organization", "note", "website", "event",
            "relationship", "group_membership",
        )
    }
}
