package org.kysecurity.mail.signon

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class IssuerMatchTest {
    @Test fun trailingSlashDefaultPortAndCaseMatch() {
        assertTrue(sameIssuer("https://Id.Example.com/", "https://id.example.com:443"))
    }

    @Test fun pathSchemePortAndHostDiffer() {
        assertFalse(sameIssuer("https://id.example.com/a", "https://id.example.com"))
        assertFalse(sameIssuer("http://id.example.com", "https://id.example.com"))
        assertFalse(sameIssuer("https://id.example.com:8443", "https://id.example.com"))
        assertFalse(sameIssuer("https://id.example.com", "https://evil.example.com"))
    }

    @Test fun nullNeverEqualsNull() {
        assertFalse(sameIssuer(null, null))
        assertFalse(sameIssuer("not a url", "also not"))
        assertFalse(sameIssuer("https://id.example.com", null))
        assertNull(canonicalOrigin("ftp://x"))
    }

    @Test fun canonicalIncludesPort() {
        assertEquals("https://id.example.com:443/base", canonicalOrigin("https://ID.example.com/base/"))
    }
}
