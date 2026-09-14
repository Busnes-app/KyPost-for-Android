package org.kysecurity.mail.pgp

import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** One test per exit-table row in the design spec. */
class EncryptedMessageReaderTest {

    @After fun cleanup() = EnrollmentSession.clear()

    private fun reader(
        opener: FakeVaultOpener = FakeVaultOpener(),
        payloads: FakePayloadSource = FakePayloadSource(successPayload()),
        localKeys: Map<String, List<LocalSignerKey>> = emptyMap(),
    ) = EncryptedMessageReader(
        opener,
        payloads,
        localSignerKeys = { address -> localKeys[address].orEmpty() },
    ) to payloads

    private fun read(
        r: EncryptedMessageReader,
        unlockIfNeeded: Boolean = true,
        sender: String = "bob@example.com",
    ) = runBlocking { r.read("INBOX", "42", sender, unlockIfNeeded) }

    @Test
    fun aHeldKeyDecryptsWithoutPrompting() {
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
        val opener = FakeVaultOpener()
        val (r, _) = reader(opener)

        val outcome = read(r, unlockIfNeeded = false)

        assertTrue("expected Decrypted, got $outcome", outcome is ReadOutcome.Decrypted)
        assertEquals("must not prompt when the key is already held", 0, opener.opened)
    }

    @Test
    fun aColdSessionAsksForAnUnlockRatherThanPrompting() {
        val opener = FakeVaultOpener()
        val (r, payloads) = reader(opener)

        val outcome = read(r, unlockIfNeeded = false)

        assertEquals(ReadOutcome.NeedsUnlock, outcome)
        assertEquals("must not prompt on its own", 0, opener.opened)
        assertEquals("must not spend a fetch it cannot use", 0, payloads.fetched)
    }

    @Test
    fun anExplicitUnlockDecrypts() {
        val (r, _) = reader()

        val outcome = read(r, unlockIfNeeded = true)

        assertTrue("expected Decrypted, got $outcome", outcome is ReadOutcome.Decrypted)
    }

    /** With signing on by default upstream, an encrypted message without one is now worth a
     *  sentence — but never a warning glyph. */
    @Test
    fun anEncryptedUnsignedMessageReportsUnsignedNotNone() {
        val mime = "Content-Type: text/plain; charset=utf-8\r\n\r\nUnsigned encrypted mail.\r\n"
        val encrypted = PgpEncryptor.encrypt(
            plaintext = mime.toByteArray(Charsets.UTF_8),
            recipientPublicKeys = listOf(TestPgpPrivateKey.ARMORED_PUBLIC),
            armoredSigningKey = null,
        ) as EncryptResult.Ok
        val (r, _) = reader(payloads = FakePayloadSource(successPayload(encrypted = encrypted.armored)))

        val outcome = read(r) as ReadOutcome.Decrypted

        assertEquals(PgpSignatureState.UNSIGNED, outcome.signature)
    }

    @Test
    fun anEncryptedDetachedMimeSignatureAtTheRootIsNotUnsigned() {
        assertEncryptedMimeSignatureState(detachedMime(), PgpSignatureState.UNCHECKED)
    }

    @Test
    fun anEncryptedNestedDetachedMimeSignatureIsNotUnsigned() {
        val mime = "Content-Type: multipart/mixed; boundary=outer\r\n\r\n" +
            "--outer\r\n" + detachedMime() + "\r\n--outer--\r\n"
        assertEncryptedMimeSignatureState(mime, PgpSignatureState.UNCHECKED)
    }

    @Test
    fun aMalformedSignatureDeclarationMustNotSilenceTheNotice() {
        val outcome = assertEncryptedMimeSignatureState(detachedMime("not a signature"), PgpSignatureState.UNCHECKED)
        assertTrue("a declared but unchecked signature needs a visible notice", outcome.signature != PgpSignatureState.NONE)
    }

    @Test
    fun aPacketSignatureStillVerifiesAroundADetachedMimeSignature() {
        assertEncryptedMimeSignatureState(
            detachedMime(), PgpSignatureState.VERIFIED_SEEN_BEFORE,
            signingKey = TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray(),
        )
    }

    private fun assertEncryptedMimeSignatureState(
        mime: String,
        expected: PgpSignatureState,
        signingKey: CharArray? = null,
    ): ReadOutcome.Decrypted {
        val encrypted = PgpEncryptor.encrypt(
            mime.toByteArray(Charsets.UTF_8), listOf(TestPgpPrivateKey.ARMORED_PUBLIC), signingKey,
        ) as EncryptResult.Ok
        val (r, _) = reader(payloads = FakePayloadSource(successPayload(
            encrypted = encrypted.armored, signerKeys = listOf(boundKey()),
        )))
        val outcome = read(r) as ReadOutcome.Decrypted
        assertEquals(expected, outcome.signature)
        assertEquals("Signed MIME body.", outcome.body.plain)
        return outcome
    }

    private fun detachedMime(signatureOverride: String? = null): String {
        val signedPart = "Content-Type: text/plain; charset=utf-8\r\n\r\nSigned MIME body."
        val secret = orderedSecretKeyRings(TestPgpPrivateKey.ARMORED_PRIVATE.byteInputStream())!!
            .first().secretKeys.asSequence().first { it.isSigningKey }
        val key = secret.extractPrivateKey(
            org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder(
                org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider(),
            ).build(CharArray(0)),
        )
        val generator = org.bouncycastle.openpgp.PGPSignatureGenerator(
            org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder(
                secret.publicKey.algorithm, org.bouncycastle.bcpg.HashAlgorithmTags.SHA256,
            ), secret.publicKey,
        )
        generator.init(org.bouncycastle.openpgp.PGPSignature.BINARY_DOCUMENT, key)
        generator.update(signedPart.toByteArray(Charsets.UTF_8))
        val buffer = java.io.ByteArrayOutputStream()
        org.bouncycastle.bcpg.ArmoredOutputStream(buffer).use { generator.generate().encode(it) }
        val signature = signatureOverride ?: buffer.toString("UTF-8").also {
            val checked = PgpDecryptor.verifyDetached(
                TestPgpPrivateKey.ARMORED_PUBLIC, signedPart.toByteArray(Charsets.UTF_8), it,
            ) as RawSignature.Checked
            assertTrue("fixture signature must verify over the exact MIME part", checked.verified)
        }
        return "Content-Type: MuLtIpArT/SiGnEd; protocol=\"Application/PGP-Signature\"; boundary=signed\r\n\r\n" +
            "--signed\r\n$signedPart\r\n--signed\r\n" +
            "Content-Type: application/pgp-signature\r\n\r\n$signature\r\n--signed--\r\n"
    }

    @Test
    fun aSignedOnlyMessageWithNothingToCheckStaysNone() {
        val (r, _) = reader(
            payloads = FakePayloadSource(
                detachedSignedPayload(signedPart = ByteArray(0), body = "readable"),
            ),
        )

        val outcome = read(r) as ReadOutcome.Decrypted

        assertEquals(
            "could-not-check is not the same claim as unsigned",
            PgpSignatureState.NONE,
            outcome.signature,
        )
    }

    @Test
    fun aDismissedPromptIsCancelledNotAFailure() {
        val (r, _) = reader(FakeVaultOpener(outcome = OpenOutcome.Cancelled))

        assertEquals(ReadOutcome.Cancelled, read(r))
    }

    @Test
    fun anUnenrolledDeviceSaysSo() {
        val (r, _) = reader(FakeVaultOpener(outcome = OpenOutcome.NotEnrolled))

        assertEquals(ReadOutcome.NotEnrolled, read(r))
    }

    @Test
    fun noSecureLockScreenSaysSo() {
        val (r, _) = reader(FakeVaultOpener(outcome = OpenOutcome.NoSecureLockScreen))

        assertEquals(ReadOutcome.NoSecureLockScreen, read(r))
    }

    @Test
    fun anUnsealFailureIsDistinctFromACancel() {
        val (r, _) = reader(FakeVaultOpener(outcome = OpenOutcome.Failed("key invalidated")))

        assertTrue(read(r) is ReadOutcome.UnsealFailed)
    }

    @Test
    fun aTooLargeMessageSaysSoRatherThanBlamingTheNetwork() {
        val (r, _) = reader(payloads = FakePayloadSource(PgpPayloadResult.TooLarge))
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())

        assertEquals(ReadOutcome.TooLarge, read(r, unlockIfNeeded = false))
    }

    @Test
    fun aFetchFailureIsRetryable() {
        val (r, _) = reader(payloads = FakePayloadSource(PgpPayloadResult.Failed("offline")))
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())

        assertTrue(read(r, unlockIfNeeded = false) is ReadOutcome.FetchFailed)
    }

    @Test
    fun aFailedDecryptDoesNotClearTheHeldKey() {
        // One bad payload says nothing about the key. Clearing would force a fresh biometric
        // prompt for every later message because of one broken message.
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
        val (r, _) = reader(payloads = FakePayloadSource(successPayload(encrypted = "not a pgp message")))

        val outcome = read(r, unlockIfNeeded = false)

        assertTrue("expected DecryptFailed, got $outcome", outcome is ReadOutcome.DecryptFailed)
        assertEquals(TestPgpPrivateKey.ARMORED_PRIVATE, EnrollmentSession.peekForTest())
    }

    @Test
    fun theSignatureVerdictComesFromTheBoundKeyNotTheMessage() {
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
        val (r, _) = reader(payloads = FakePayloadSource(successPayload(signerKeys = emptyList())))

        val outcome = read(r, unlockIfNeeded = false) as ReadOutcome.Decrypted

        assertEquals(PgpSignatureState.SIGNER_UNKNOWN, outcome.signature)
    }

    @Test
    fun aBoundKeyMakesAGenuineSignatureVerifyRatherThanAccusingTheSender() {
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
        val bound = SignerKey(
            addresses = listOf("bob@example.com"),
            // NOT ARMORED_PRIVATE: a secret-key block is rejected where a PGPPublicKeyRing is expected.
            publicKey = TestPgpPrivateKey.ARMORED_PUBLIC,
            verified = false,
            source = "autocrypt",
            conflict = false,
        )
        val (r, _) = reader(payloads = FakePayloadSource(successPayload(signerKeys = listOf(bound))))

        val outcome = read(r, unlockIfNeeded = false) as ReadOutcome.Decrypted

        assertEquals(PgpSignatureState.VERIFIED_SEEN_BEFORE, outcome.signature)
    }

    @Test
    fun aKeyBoundToADifferentSenderIsNeverOfferedToTheSignatureCheck() {
        // Unrelated key material on purpose: ARMORED_PUBLIC would verify whatever .addresses claims.
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
        val otherContact = SignerKey(
            addresses = listOf("eve@evil.example"),
            publicKey = TestPgpKey.ARMORED,
            verified = false,
            source = "autocrypt",
            conflict = false,
        )
        val (r, _) = reader(
            payloads = FakePayloadSource(successPayload(signerKeys = listOf(otherContact))),
        )

        val outcome = read(r, unlockIfNeeded = false, sender = "bob@example.com")
            as ReadOutcome.Decrypted

        assertEquals(PgpSignatureState.SIGNER_UNKNOWN, outcome.signature)
    }

    @Test
    fun aConflictedKeyYieldsKeyChanged() {
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
        val conflicted = SignerKey(
            addresses = listOf("bob@example.com"),
            // "" per SignerKey's own KDoc: a conflicted entry carries no key material.
            publicKey = "",
            verified = false,
            source = "autocrypt",
            conflict = true,
        )
        val (r, _) = reader(
            payloads = FakePayloadSource(successPayload(signerKeys = listOf(conflicted))),
        )

        val outcome = read(r, unlockIfNeeded = false) as ReadOutcome.Decrypted

        assertEquals(PgpSignatureState.KEY_CHANGED, outcome.signature)
    }

    // The detached-signature branch: successPayload() always sets a non-blank encryptedPayload.

    @Test
    fun aDetachedSignatureFromAnUnboundKeyIsUnknownNotUnsigned() {
        // Relies on PGPPublicKeyRingCollection returning empty for empty input rather than throwing.
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
        val (r, _) = reader(payloads = FakePayloadSource(detachedSignedPayload(signerKeys = emptyList())))

        val outcome = read(r, unlockIfNeeded = false) as ReadOutcome.Decrypted

        assertEquals(PgpSignatureState.SIGNER_UNKNOWN, outcome.signature)
    }

    @Test
    fun aDetachedSignatureFromABoundKeyVerifies() {
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
        val bound = SignerKey(
            addresses = listOf("bob@example.com"),
            publicKey = TestPgpPrivateKey.ARMORED_PUBLIC,
            verified = false,
            source = "autocrypt",
            conflict = false,
        )
        val (r, _) = reader(
            payloads = FakePayloadSource(detachedSignedPayload(signerKeys = listOf(bound))),
        )

        val outcome = read(r, unlockIfNeeded = false) as ReadOutcome.Decrypted

        assertEquals(PgpSignatureState.VERIFIED_SEEN_BEFORE, outcome.signature)
    }

    @Test
    fun aDetachedSignatureWithOnlyAConflictedKeyIsKeyChanged() {
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
        val conflicted = SignerKey(
            addresses = listOf("bob@example.com"),
            publicKey = "",
            verified = false,
            source = "autocrypt",
            conflict = true,
        )
        val (r, _) = reader(
            payloads = FakePayloadSource(detachedSignedPayload(signerKeys = listOf(conflicted))),
        )

        val outcome = read(r, unlockIfNeeded = false) as ReadOutcome.Decrypted

        assertEquals(PgpSignatureState.KEY_CHANGED, outcome.signature)
    }

    /** The regression. The server empties `body` whenever it sends `signedPartBase64`, so a client
     *  that reads `body` renders nothing at all — which is how signed-only mail went blank. */
    @Test
    fun aSignedOnlyMessageRendersTheBytesItVerified() {
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
        val (r, _) = reader(payloads = FakePayloadSource(detachedSignedPayload(signerKeys = listOf(boundKey()))))

        val outcome = read(r, unlockIfNeeded = false) as ReadOutcome.Decrypted

        assertEquals(PgpSignatureState.VERIFIED_SEEN_BEFORE, outcome.signature)
        assertEquals(TestPgpPrivateKey.DETACHED_SIGNATURE_BODY, outcome.body.plain)
    }

    /** Byte-exactness, the property the whole `signedPartBase64` round trip exists to preserve. */
    @Test
    fun oneFlippedByteInTheSignedPartIsInvalid() {
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
        val tampered = TestPgpPrivateKey.DETACHED_SIGNATURE_BODY.toByteArray(Charsets.UTF_8)
            .copyOf().also { it[0] = (it[0].toInt() xor 0x01).toByte() }
        val (r, _) = reader(
            payloads = FakePayloadSource(
                detachedSignedPayload(signedPart = tampered, signerKeys = listOf(boundKey())),
            ),
        )

        val outcome = read(r, unlockIfNeeded = false) as ReadOutcome.Decrypted

        assertEquals(PgpSignatureState.INVALID, outcome.signature)
    }

    /** `body` must never reach a signature check. Here it disagrees with the signed part, and the
     *  verdict has to come from the signed part alone — verifying `body` instead would fail, and
     *  rendering it would show one message while vouching for another. */
    @Test
    fun bodyIsNeverTheInputToASignatureCheck() {
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
        val (r, _) = reader(
            payloads = FakePayloadSource(
                detachedSignedPayload(body = "a different message entirely", signerKeys = listOf(boundKey())),
            ),
        )

        val outcome = read(r, unlockIfNeeded = false) as ReadOutcome.Decrypted

        assertEquals(PgpSignatureState.VERIFIED_SEEN_BEFORE, outcome.signature)
        assertEquals(TestPgpPrivateKey.DETACHED_SIGNATURE_BODY, outcome.body.plain)
    }

    /** The server's raw re-fetch failed. A valid response, not an error: show what arrived and
     *  claim nothing. NONE is "could not check", and must not read as an accusation. */
    @Test
    fun anEmptySignedPartShowsTheBodyWithNoVerdict() {
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
        val (r, _) = reader(
            payloads = FakePayloadSource(
                detachedSignedPayload(
                    signedPart = ByteArray(0),
                    body = "the server could not fetch the raw part",
                    signerKeys = listOf(boundKey()),
                ),
            ),
        )

        val outcome = read(r, unlockIfNeeded = false) as ReadOutcome.Decrypted

        assertEquals(PgpSignatureState.NONE, outcome.signature)
        assertEquals("the server could not fetch the raw part", outcome.body.plain)
    }

    /** Undecodable base64 leaves the reader exactly where an empty field does: unable to check,
     *  still able to show. It must not surface as a failure. */
    @Test
    fun anUndecodableSignedPartFallsBackToTheBodyRatherThanFailing() {
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
        val payload = detachedSignedPayload(body = "still readable", signerKeys = listOf(boundKey()))
            .copy(signedPartBase64 = "!!! not base64 !!!")
        val (r, _) = reader(payloads = FakePayloadSource(payload))

        val outcome = read(r, unlockIfNeeded = false) as ReadOutcome.Decrypted

        assertEquals(PgpSignatureState.NONE, outcome.signature)
        assertEquals("still readable", outcome.body.plain)
    }

    @Test
    fun noSignedPartAndNoBodyIsTerminalRatherThanBlank() {
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
        val (r, _) = reader(
            payloads = FakePayloadSource(
                detachedSignedPayload(signedPart = ByteArray(0), body = "", signerKeys = listOf(boundKey())),
            ),
        )

        assertEquals(ReadOutcome.NoReadableContent, read(r, unlockIfNeeded = false))
    }

    /** A signed plain-text body has no blank line, so JavaMail reads the whole thing as headers and
     *  PgpMimeReader answers null — for content that verified perfectly. The raw fallback is what
     *  keeps those messages readable, which is the case the default fixture exercises.
     *
     *  It renders as TEXT: unparsed octets must not reach the WebView as markup. */
    @Test
    fun anUnparseableSignedPartStillRendersAsPlainTextNeverAsMarkup() {
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
        val (r, _) = reader(payloads = FakePayloadSource(detachedSignedPayload(signerKeys = listOf(boundKey()))))

        val outcome = read(r, unlockIfNeeded = false) as ReadOutcome.Decrypted

        assertEquals(null, PgpMimeReader.read(TestPgpPrivateKey.DETACHED_SIGNATURE_BODY.toByteArray(Charsets.UTF_8)))
        assertEquals(TestPgpPrivateKey.DETACHED_SIGNATURE_BODY, outcome.body.plain)
        assertEquals("plain", outcome.body.bodyMode)
        assertTrue(
            org.kysecurity.mail.isPlainTextBody(outcome.body.plain!!, outcome.body.bodyMode),
        )
    }

    /** A real, parseable key that is NOT the signer. Must never pass, and must never accuse either:
     *  nothing was checked, so SIGNER_UNKNOWN, not INVALID. Mirrors the Mac client's
     *  `GopenPGPCryptoTests` row for a wrong key. */
    @Test
    fun aDetachedSignatureOfferedTheWrongKeyIsUnknownNotValidAndNotInvalid() {
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
        val wrongKey = SignerKey(
            addresses = listOf("bob@example.com"),
            publicKey = TestPgpSecondKey.ARMORED_PUBLIC,
            verified = false,
            source = "autocrypt",
            conflict = false,
        )
        val (r, _) = reader(payloads = FakePayloadSource(detachedSignedPayload(signerKeys = listOf(wrongKey))))

        val outcome = read(r, unlockIfNeeded = false) as ReadOutcome.Decrypted

        assertEquals(PgpSignatureState.SIGNER_UNKNOWN, outcome.signature)
    }

    private fun boundKey() = SignerKey(
        addresses = listOf("bob@example.com"),
        publicKey = TestPgpPrivateKey.ARMORED_PUBLIC,
        verified = false,
        source = "autocrypt",
        conflict = false,
    )

    @Test
    fun aClientUnprotectedAccountSaysSo() {
        val (r, _) = reader(payloads = FakePayloadSource(PgpPayloadResult.NotClientProtected))
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())

        assertEquals(ReadOutcome.NotClientProtected, read(r, unlockIfNeeded = false))
    }

    @Test
    fun aMessageWithNoOpenPgpPayloadIsTerminalNotRetryable() {
        val (r, _) = reader(payloads = FakePayloadSource(PgpPayloadResult.NoPayload))
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())

        assertEquals(ReadOutcome.NoEncryptedContent, read(r, unlockIfNeeded = false))
    }

    @Test
    fun aKeyThatVanishesBetweenUnsealAndFetchAsksForAnUnlockAgain() {
        // keyToHold = null: open() reports Opened without leaving a key, as a lock in the gap would.
        val opener = FakeVaultOpener(keyToHold = null)
        val (r, payloads) = reader(opener)

        val outcome = read(r, unlockIfNeeded = true)

        assertEquals(ReadOutcome.NeedsUnlock, outcome)
        assertEquals("the unseal itself must still have run exactly once", 1, opener.opened)
        assertEquals("must not spend a fetch when there is no key to decrypt with", 0, payloads.fetched)
    }

    @Test
    fun aRelaySuppliedVerifiedFlagCannotConfirmASigner() {
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
        val relayKey = SignerKey(
            addresses = listOf("bob@example.com"),
            publicKey = TestPgpPrivateKey.ARMORED_PUBLIC,
            verified = true,
            source = "qr",
            conflict = false,
        )
        val (r, _) = reader(payloads = FakePayloadSource(successPayload(signerKeys = listOf(relayKey))))

        val outcome = read(r, unlockIfNeeded = false)

        assertTrue("expected Decrypted, got $outcome", outcome is ReadOutcome.Decrypted)
        assertEquals(
            "a server-supplied verified flag must be capped at continuity, never identity",
            PgpSignatureState.VERIFIED_SEEN_BEFORE,
            (outcome as ReadOutcome.Decrypted).signature,
        )
    }

    @Test
    fun aLocallyHeldKeyIsResolvedForTheServersResolvedSender() {
        // The lookup key is `resolvedSender`. A relay that names a different sender gets a lookup
        // that misses, which is the fail-safe direction.
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
        var askedFor: String? = null
        val payloads = FakePayloadSource(successPayload(resolvedSender = "bob@example.com"))
        val r = EncryptedMessageReader(
            FakeVaultOpener(),
            payloads,
            localSignerKeys = { address -> askedFor = address; emptyList() },
        )

        read(r, unlockIfNeeded = false)

        assertEquals("bob@example.com", askedFor)
    }

    @Test
    fun aLocalKeyThatDidNotSignOutranksAnyRelayClaim() {
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
        val relayKey = SignerKey(
            addresses = listOf("bob@example.com"),
            publicKey = TestPgpPrivateKey.ARMORED_PUBLIC,
            verified = true,
            source = "qr",
            conflict = false,
        )
        val (r, _) = reader(
            payloads = FakePayloadSource(successPayload(signerKeys = listOf(relayKey))),
            // A real, parseable key that is NOT the one the message was signed with.
            localKeys = mapOf("bob@example.com" to listOf(LocalSignerKey(TestPgpKey.ARMORED, confirmed = true))),
        )

        val outcome = read(r, unlockIfNeeded = false)

        assertTrue("expected Decrypted, got $outcome", outcome is ReadOutcome.Decrypted)
        assertEquals(
            PgpSignatureState.KEY_CHANGED,
            (outcome as ReadOutcome.Decrypted).signature,
        )
    }

    @Test
    fun aLookupFailureDegradesToTheRelayRatherThanFailingTheRead() {
        // Room can throw when a wipe closes the database out from under the lookup.
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
        val r = EncryptedMessageReader(
            FakeVaultOpener(),
            FakePayloadSource(successPayload()),
            localSignerKeys = { error("database is closed") },
        )

        val outcome = read(r, unlockIfNeeded = false)

        assertTrue("expected Decrypted, got $outcome", outcome is ReadOutcome.Decrypted)
    }
}
