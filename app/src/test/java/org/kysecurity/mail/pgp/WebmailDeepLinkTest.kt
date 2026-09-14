package org.kysecurity.mail.pgp

import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import okhttp3.HttpUrl.Companion.toHttpUrl
import org.junit.Test

class WebmailDeepLinkTest {

    @Test
    fun buildsReadRouteWithMessageParam() {
        assertEquals(
            "https://mail.example.com/read?mailbox=Archive&message=42",
            webmailMessageUrl("https://mail.example.com", "Archive", "42"),
        )
    }

    @Test
    fun toleratesTrailingSlashOnServerUrl() {
        assertEquals(
            "https://mail.example.com/read?mailbox=Archive&message=42",
            webmailMessageUrl("https://mail.example.com/", "Archive", "42"),
        )
    }

    /** The web app's own Inbox link is a bare /read, and ReadPage treats an absent mailbox as the
     *  default — so sending the literal "INBOX" would diverge from every link the server builds. */
    @Test
    fun inboxIsSentAsAnAbsentMailboxParam() {
        assertEquals(
            "https://mail.example.com/read?message=42",
            webmailMessageUrl("https://mail.example.com", "INBOX", "42"),
        )
        assertEquals(
            "https://mail.example.com/read?message=42",
            webmailMessageUrl("https://mail.example.com", "inbox", "42"),
        )
        assertEquals(
            "https://mail.example.com/read?message=42",
            webmailMessageUrl("https://mail.example.com", "", "42"),
        )
    }

    @Test
    fun encodesMailboxNamesWithSpacesAndSlashes() {
        val url = webmailMessageUrl("https://mail.example.com", "Clients/Acme Corp", "7")
        assertTrue(url!!.contains("mailbox=Clients%2FAcme%20Corp"), "unexpected encoding: $url")
    }

    @Test
    fun portAndSubpathAreOnTheServerUrlNotAssumed() {
        assertEquals(
            "https://mail.example.com:8443/read?message=9",
            webmailMessageUrl("https://mail.example.com:8443", "INBOX", "9"),
        )
    }

    /** Null means "render no button" — a dead button is worse than none. */
    @Test
    fun unusableInputsReturnNull() {
        assertNull(webmailMessageUrl("not a url", "INBOX", "42"))
        assertNull(webmailMessageUrl("", "INBOX", "42"))
        assertNull(webmailMessageUrl("https://mail.example.com", "INBOX", ""))
    }

    @Test
    fun handoffUrlContainsOnlyTheDraftsDestination() {
        val url = webmailDraftsUrl("https://relay.example.com")!!
        assertEquals("https://relay.example.com/read?mailbox=Drafts", url)
        assertEquals(setOf("mailbox"), url.toHttpUrl().queryParameterNames)
    }

    @Test
    fun draftsUrl_toleratesATrailingSlash() {
        assertEquals(
            "https://relay.example.com/read?mailbox=Drafts",
            webmailDraftsUrl("https://relay.example.com/"),
        )
    }

    /** Same contract as webmailMessageUrl: an unusable server URL renders as no button rather
     *  than a dead one. */
    @Test
    fun draftsUrl_isNullForAnUnusableServerUrl() {
        assertNull(webmailDraftsUrl("not a url"))
    }

    /** The seam between the builders and [isFirstPartyWebmailUrl]; neither side's tests notice drift. */
    @Test
    fun everyBuiltUrlPassesTheFirstPartyGuard() {
        val serverUrls = listOf(
            "https://mail.example.com",
            "https://mail.example.com/",
            "https://mail.example.com:443",
            "https://mail.example.com:8443",
            "https://mail.example.com/webmail",
            "https://MAIL.EXAMPLE.COM",
        )
        for (serverUrl in serverUrls) {
            val messageUrl = webmailMessageUrl(serverUrl, "Archive", "42")!!
            assertTrue(
                isFirstPartyWebmailUrl(serverUrl, messageUrl),
                "message url rejected by the guard: $serverUrl -> $messageUrl",
            )
            val draftsUrl = webmailDraftsUrl(serverUrl)!!
            assertTrue(
                isFirstPartyWebmailUrl(serverUrl, draftsUrl),
                "drafts url rejected by the guard: $serverUrl -> $draftsUrl",
            )
        }
    }

    /** The Security page's "open webmail" actions target the account, not one message. */
    @Test
    fun webmailHomeUrlIsTheServerRoot() {
        assertEquals("https://relay.example.com/", webmailHomeUrl("https://relay.example.com"))
        assertEquals("https://relay.example.com/", webmailHomeUrl("https://relay.example.com/"))
    }

    /** A path on the stored server URL must not survive into the handoff target. */
    @Test
    fun webmailHomeUrlDropsAnyPath() {
        assertEquals("https://relay.example.com/", webmailHomeUrl("https://relay.example.com/read?message=7"))
    }

    /** Same as the path: a query and a fragment must not survive either, pinned together so a fix
     *  for one cannot silently leave the other in place. */
    @Test
    fun webmailHomeUrlDropsAnyQueryAndFragment() {
        assertEquals(
            "https://relay.example.com/",
            webmailHomeUrl("https://relay.example.com/read?message=7#section2"),
        )
    }

    /** Same failure mode as every other builder here: no button rather than a dead one. */
    @Test
    fun webmailHomeUrlRefusesAnUnusableServerUrl() {
        assertNull(webmailHomeUrl("not a url"))
    }
}
