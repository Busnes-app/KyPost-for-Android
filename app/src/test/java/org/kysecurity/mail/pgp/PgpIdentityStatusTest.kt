package org.kysecurity.mail.pgp

import org.junit.Assert.assertEquals
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertNull
import org.junit.Test

/** Covers [pgpIdentityFromMintResult] — the pure mapping [hasPgpIdentity] uses to turn a
 *  [PgpQrClient.mintToken] outcome into "does this account have a PGP identity". */
class PgpIdentityStatusTest {

    @Test
    fun success_mapsToTrue() {
        val result = PgpQrTokenResult.Success(PgpQrTokenDto(token = "t", expiresAt = "e", url = "u"))
        assertEquals(true, pgpIdentityFromMintResult(result))
    }

    @Test
    fun noIdentity_mapsToFalse() {
        val result = PgpQrTokenResult.NoIdentity("no pgp identity configured yet")
        assertEquals(false, pgpIdentityFromMintResult(result))
    }

    @Test
    fun unauthorized_mapsToNull_notFalse() {
        val result = PgpQrTokenResult.Unauthorized("bad secret")
        assertEquals(null, pgpIdentityFromMintResult(result))
    }

    @Test
    fun serviceUnavailable_mapsToNull_notFalse() {
        val result = PgpQrTokenResult.ServiceUnavailable("pairing not configured")
        assertEquals(null, pgpIdentityFromMintResult(result))
    }

    @Test
    fun retryable_mapsToNull_notFalse() {
        val result = PgpQrTokenResult.Retryable("network error")
        assertEquals(null, pgpIdentityFromMintResult(result))
    }

    /** The account's fingerprint comes from the bootstrap `publicKey`, not the self-contact column. */
    @Test
    fun bootstrapWithPublicKey_yieldsLocallyComputedFingerprint() {
        val result = PgpBootstrapResult.Success(
            hasIdentity = true,
            protection = "client",
            publicKey = TestPgpKey.ARMORED,
        )

        assertEquals(TestPgpKey.FINGERPRINT, ownFingerprintFromBootstrap(result))
    }

    /** Never render the server's own `fingerprint` string: it is a claim in the same response as
     *  the key, with no cryptographic tie to it. An unparseable key is "unavailable", not a
     *  fingerprint borrowed from elsewhere in the body. */
    @Test
    fun bootstrapWithUnparseableKey_isNull() {
        val result = PgpBootstrapResult.Success(
            hasIdentity = true,
            protection = "client",
            publicKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nnot a key\n-----END PGP PUBLIC KEY BLOCK-----",
        )

        assertNull(ownFingerprintFromBootstrap(result))
    }

    @Test
    fun bootstrapWithoutIdentity_isNull() {
        assertNull(ownFingerprintFromBootstrap(PgpBootstrapResult.Success(false, "", "")))
    }

    @After
    fun clearHeldKey() = EnrollmentSession.clear()

    private val serverReport = PgpBootstrapResult.Success(hasIdentity = true, protection = "client", publicKey = TestPgpKey.ARMORED)

    /** The server reports a different key; the device's own signer is what is shown. */
    @Test
    fun enrolledDevice_showsItsOwnKey_notTheServerReport() = runBlocking {
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
        assertEquals(
            OwnFingerprint.Local("B30A CD64 E04B 8E1B 0379 A320 1D6B DF09 3FAD 1D11"),
            ownFingerprint { serverReport },
        )
    }

    @Test
    fun deviceWithoutSigner_showsTheServerReport_labelledAsSuch() = runBlocking {
        assertEquals(OwnFingerprint.ServerReported(TestPgpKey.FINGERPRINT), ownFingerprint { serverReport })
    }

    @Test
    fun failedBootstrap_isNull() {
        assertNull(ownFingerprintFromBootstrap(PgpBootstrapResult.Failed("no route to host")))
    }
}
