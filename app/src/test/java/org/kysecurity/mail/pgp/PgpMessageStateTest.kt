package org.kysecurity.mail.pgp

import kotlin.test.assertEquals
import kotlin.test.assertNull
import org.junit.Test

class PgpMessageStateTest {

    @Test
    fun noPgpContent_isNone() {
        assertEquals(PgpMessageState.NONE, pgpMessageStateOf(false, "", hasBody = true))
        assertEquals(PgpMessageState.NONE, pgpMessageStateOf(false, "", hasBody = false))
    }

    /** The client-protected shape: the server sets the flag, decrypts nothing, and reports no
     *  error because nothing went wrong — it simply has no key. */
    @Test
    fun encryptedWithNoErrorAndNoBody_isClientProtected() {
        assertEquals(PgpMessageState.CLIENT_PROTECTED, pgpMessageStateOf(true, "", hasBody = false))
        assertEquals(PgpMessageState.CLIENT_PROTECTED, pgpMessageStateOf(true, "   ", hasBody = false))
    }

    @Test
    fun encryptedWithError_isDecryptFailed() {
        assertEquals(PgpMessageState.DECRYPT_FAILED, pgpMessageStateOf(true, "no pgp identity configured", hasBody = false))
    }

    /** Both conditions hold at once for a failed decrypt; the error must win. */
    @Test
    fun errorTakesPrecedenceOverMissingBody() {
        assertEquals(PgpMessageState.DECRYPT_FAILED, pgpMessageStateOf(true, "bad key", hasBody = false))
    }

    @Test
    fun encryptedWithBody_isDecryptedByServer() {
        assertEquals(PgpMessageState.DECRYPTED_BY_SERVER, pgpMessageStateOf(true, "", hasBody = true))
    }

    /** Only the states that yield nothing readable get a row marker — a server-mode mailbox would
     *  otherwise carry a symbol on most rows that the user can do nothing with. */
    @Test
    fun onlyUnreadableStatesGetARowMarker() {
        assertEquals("🔒", pgpRowMarker(PgpMessageState.CLIENT_PROTECTED))
        assertEquals("⚠", pgpRowMarker(PgpMessageState.DECRYPT_FAILED))
        assertNull(pgpRowMarker(PgpMessageState.DECRYPTED_BY_SERVER))
        assertNull(pgpRowMarker(PgpMessageState.NONE))
    }

    @Test
    fun serverVerifiedClaimsNoKeyThisDeviceHolds() {
        // The relay checked against a key this device never pinned, so neither identity nor
        // continuity is ours to claim.
        assertEquals(
            PgpSignatureState.SIGNER_UNKNOWN,
            pgpSignatureStateOf(pgpSigned = true, pgpVerified = true),
        )
    }

    @Test
    fun correctlySignedMailIsNotAnAccusation() {
        // The relay never verifies signed-but-unencrypted mail, so pgpVerified is permanently false.
        // An empty fingerprint means nothing was checked against anything.
        assertEquals(
            PgpSignatureState.SIGNER_UNKNOWN,
            pgpSignatureStateOf(pgpSigned = true, pgpVerified = false, pgpSignerFingerprint = ""),
        )
        assertNull(
            pgpRowMarker(
                PgpMessageState.NONE,
                pgpSignatureStateOf(pgpSigned = true, pgpVerified = false, pgpSignerFingerprint = ""),
            ),
        )
    }

    @Test
    fun aNamedSignerThatIsNotTheSenderIsStillAnAccusation() {
        // A fingerprint means a key produced the signature and it was not the one bound to the
        // sender. That is the case the warning exists for, and it must survive the fix above.
        assertEquals(
            PgpSignatureState.INVALID,
            pgpSignatureStateOf(pgpSigned = true, pgpVerified = false, pgpSignerFingerprint = "ABCDEF01"),
        )
        assertEquals(
            "⚠",
            pgpRowMarker(
                PgpMessageState.NONE,
                pgpSignatureStateOf(pgpSigned = true, pgpVerified = false, pgpSignerFingerprint = "ABCDEF01"),
            ),
        )
    }

    @Test
    fun aChangedKeyMarksTheRow() {
        assertEquals("⚠", pgpRowMarker(PgpMessageState.NONE, PgpSignatureState.KEY_CHANGED))
    }

    @Test
    fun anUnknownSignerDoesNotMarkTheRow() {
        // It is the ordinary state for anyone not yet in the address book. A glyph on most rows
        // carries nothing the user can act on — the same reason DECRYPTED_BY_SERVER is unmarked.
        assertNull(pgpRowMarker(PgpMessageState.NONE, PgpSignatureState.SIGNER_UNKNOWN))
    }

    @Test
    fun unsignedIsNotARowWarning() {
        assertEquals("🔒", pgpRowMarker(PgpMessageState.CLIENT_PROTECTED, PgpSignatureState.UNSIGNED))
        assertNull(pgpRowMarker(PgpMessageState.NONE, PgpSignatureState.UNSIGNED))
    }
}
