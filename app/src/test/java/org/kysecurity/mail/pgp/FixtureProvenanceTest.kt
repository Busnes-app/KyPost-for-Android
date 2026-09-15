package org.kysecurity.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Test
import java.security.MessageDigest

/** The shared fixtures are copied, never edited: these are the checksums recorded in
 *  `src/test/resources/kypost-server/PROVENANCE.md` at KyPost-Server `dc2a70eb`. */
class FixtureProvenanceTest {

    @Test
    fun sharedFixturesAreTheServersBytes() {
        assertEquals(
            "0ce8d5ac20ec94bcc35facff6e76fcf78ec0d66f666aabc2dcef1965408e9c3a",
            sha256(SharedFixtures.bytes("device-envelope-v3.json")),
        )
        assertEquals(
            "bba7d8fde4206be91e57a4953b3b56ff915ecb24f9a0f581b7098bdc6dfcb7cc",
            sha256(SharedFixtures.bytes("pgp-keyring-v1.json")),
        )
    }

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
}
