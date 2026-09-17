package org.kysecurity.mail.pgp

import org.kysecurity.mail.mail.MailDraft
import org.kysecurity.mail.mail.MailOutcome
import org.kysecurity.mail.mail.MailSendOutcome
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

private const val ACCOUNT = "me@example.invalid"

class ClientEncryptedSenderTest {

    @After
    fun clearHeldKey() = EnrollmentSession.clear()

    private fun sender(
        opener: FakeVaultOpener = FakeVaultOpener(),
        resolver: FakeRecipientKeyResolver = FakeRecipientKeyResolver(),
        transport: FakeClientEncryptedTransport = FakeClientEncryptedTransport(),
        localKeys: FakePinnedKeys = FakePinnedKeys(),
        accountAddress: String = ACCOUNT,
    ) = ClientEncryptedSender(
        opener = opener,
        resolver = resolver,
        transport = transport,
        localKeys = localKeys,
        accountAddress = accountAddress,
    )

    private fun draft(to: String = "alice@example.invalid", cc: String = "", bcc: String = "") =
        MailDraft(to = to, cc = cc, bcc = bcc, subject = "Subject", body = "<p>Body</p>", mode = "html")

    private fun pinnedFor(address: String, confirmed: Boolean) = FakePinnedKeys(
        mapOf(address to listOf(LocalSignerKey(TestPgpPrivateKey.ARMORED_PUBLIC, confirmed))),
    )

    /** A converted account's send is refused unless it names the generation the device holds
     *  (KyPost-Server #210), so the held keyring's generation rides on the message. */
    @Test
    fun aHeldKeyringSendsItsMaterialGeneration() = runBlocking {
        val ring = SharedFixtures.keyring()["ring"]!!.let { kotlinx.serialization.json.Json.encodeToString(kotlinx.serialization.json.JsonElement.serializer(), it) }
        EnrollmentSession.putKeyring(requireNotNull(parsePgpKeyring(ring.toByteArray(Charsets.UTF_8), "5F117951610CAF01500FA059CDE63F0EBEC934A2")))
        val transport = FakeClientEncryptedTransport()

        val result = sender(
            resolver = FakeRecipientKeyResolver(resolvedAll(listOf("alice@example.invalid"), TestPgpPrivateKey.ARMORED_PUBLIC)),
            transport = transport,
        ).send(draft(), sign = false)

        assertTrue("expected Sent, got $result", result is ClientSendOutcome.Sent)
        assertEquals(2L, transport.sent.single().materialGeneration)
    }

    /** Legacy armor has no generation, and a legacy account ignores the field. */
    @Test
    fun legacyArmorSendsNoMaterialGeneration() = runBlocking {
        val transport = FakeClientEncryptedTransport()

        sender(
            resolver = FakeRecipientKeyResolver(resolvedAll(listOf("alice@example.invalid"), TestPgpPrivateKey.ARMORED_PUBLIC)),
            transport = transport,
        ).send(draft(), sign = false)

        assertNull(transport.sent.single().materialGeneration)
    }

    /** One shared ciphertext would put each BCC recipient's key id in a packet everyone can read. */
    @Test
    fun toAndCcShareDeliveryZeroAndEachBccGetsItsOwn() = runBlocking {
        val addresses = listOf("alice@example.invalid", "carol@example.invalid", "dave@example.invalid", "erin@example.invalid")
        val transport = FakeClientEncryptedTransport()
        val result = sender(
            resolver = FakeRecipientKeyResolver(resolvedAll(addresses, TestPgpPrivateKey.ARMORED_PUBLIC)),
            transport = transport,
        ).send(
            draft(to = "alice@example.invalid", cc = "carol@example.invalid", bcc = "dave@example.invalid, erin@example.invalid"),
            sign = false,
        )

        assertTrue("expected Sent, got $result", result is ClientSendOutcome.Sent)
        val message = transport.sent.single()
        assertEquals(3, message.deliveries.size)
        assertEquals(
            listOf("alice@example.invalid", "carol@example.invalid"),
            message.deliveries[0].recipients,
        )
        assertEquals(listOf("dave@example.invalid"), message.deliveries[1].recipients)
        assertEquals(listOf("erin@example.invalid"), message.deliveries[2].recipients)
    }

    /** No delivery may name a BCC recipient in a header — the relay refuses a `Bcc` header outright,
     *  and a BCC address appearing in another delivery's headers defeats the split entirely. */
    @Test
    fun noDeliveryHeaderMentionsABccRecipient() = runBlocking {
        val addresses = listOf("alice@example.invalid", "dave@example.invalid")
        val transport = FakeClientEncryptedTransport()
        sender(
            resolver = FakeRecipientKeyResolver(resolvedAll(addresses, TestPgpPrivateKey.ARMORED_PUBLIC)),
            transport = transport,
        ).send(draft(to = "alice@example.invalid", bcc = "dave@example.invalid"), sign = false)

        transport.sent.single().deliveries.forEach { delivery ->
            val headers = delivery.ciphertext.substringBefore("\r\n\r\n")
            assertFalse("a BCC address must not appear in any delivery header", headers.contains("dave@example.invalid"))
            assertFalse("no Bcc header at all", headers.lineSequence().any { it.startsWith("Bcc:") })
        }
    }

    @Test
    fun aBccDeliveryIsEncryptedOnlyToThatBccKey() = runBlocking {
        val transport = FakeClientEncryptedTransport()
        val resolver = FakeRecipientKeyResolver(
            ResolveResult.Success(
                listOf(
                    ResolvedRecipientKey("alice@example.invalid", TestPgpPrivateKey.ARMORED_PUBLIC, "", "contact-verified", true),
                    ResolvedRecipientKey("dave@example.invalid", TestPgpSecondKey.ARMORED_PUBLIC, "", "contact-verified", true),
                ),
            ),
        )
        sender(resolver = resolver, transport = transport)
            .send(draft(to = "alice@example.invalid", bcc = "dave@example.invalid"), sign = false)

        val bccDelivery = armorOf(transport.sent.single().deliveries[1].ciphertext)

        assertTrue(
            "the BCC recipient must be able to open their own delivery",
            PgpDecryptor.decrypt(TestPgpSecondKey.ARMORED_PRIVATE.toCharArray(), bccDelivery, emptyList()) is DecryptResult.Ok,
        )
        assertTrue(
            "the To recipient must NOT be able to open the BCC delivery",
            PgpDecryptor.decrypt(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray(), bccDelivery, emptyList()) is DecryptResult.Failed,
        )
    }

    /** Key resolution happens before the biometric sheet, so a send that was going to be refused
     *  anyway never interrupts the user to authenticate for it. */
    @Test
    fun resolveRunsBeforeTheBiometricPrompt() = runBlocking {
        val opener = FakeVaultOpener()
        val result = sender(
            opener = opener,
            resolver = FakeRecipientKeyResolver(
                ResolveResult.Success(
                    listOf(ResolvedRecipientKey("alice@example.invalid", "", "", "none", false)),
                ),
            ),
        ).send(draft(), sign = false)

        assertTrue("expected KeysMissing, got $result", result is ClientSendOutcome.KeysMissing)
        assertEquals("the vault must not have been opened", 0, opener.opened)
    }

    @Test
    fun refusesWhenARecipientHasNoUsableKeyAndSendsNothing() = runBlocking {
        val transport = FakeClientEncryptedTransport()
        val result = sender(
            resolver = FakeRecipientKeyResolver(
                ResolveResult.Success(
                    listOf(
                        ResolvedRecipientKey("alice@example.invalid", TestPgpPrivateKey.ARMORED_PUBLIC, "", "contact-verified", true),
                        ResolvedRecipientKey("bob@example.invalid", "", "", "none", false),
                    ),
                ),
            ),
            transport = transport,
        ).send(draft(to = "alice@example.invalid, bob@example.invalid"), sign = false)

        assertEquals(listOf("bob@example.invalid"), (result as ClientSendOutcome.KeysMissing).addresses)
        assertTrue("nothing may be delivered", transport.sent.isEmpty())
    }

    /** `key_changed` means discovery found a key whose fingerprint does not match the pinned one. */
    @Test
    fun aChangedKeyOutranksAMissingKey() = runBlocking {
        val result = sender(
            resolver = FakeRecipientKeyResolver(
                ResolveResult.Success(
                    listOf(
                        ResolvedRecipientKey("alice@example.invalid", "", "", "key_changed", false),
                        ResolvedRecipientKey("bob@example.invalid", "", "", "none", false),
                    ),
                ),
            ),
        ).send(draft(to = "alice@example.invalid, bob@example.invalid"), sign = false)

        assertEquals(listOf("alice@example.invalid"), (result as ClientSendOutcome.KeyChanged).addresses)
    }

    /** The pinned fingerprint was compared in person; `tier` is the relay describing its own
     *  bookkeeping, and a relay that wants to substitute a key simply never sets it. */
    @Test
    fun aRelayKeyThatDoesNotMatchThePinnedOneIsAChangedKey() = runBlocking {
        val transport = FakeClientEncryptedTransport()
        val result = sender(
            resolver = FakeRecipientKeyResolver(
                resolvedAll(listOf("alice@example.invalid"), TestPgpSecondKey.ARMORED_PUBLIC),
            ),
            transport = transport,
            localKeys = pinnedFor("alice@example.invalid", confirmed = true),
        ).send(draft(), sign = false)

        assertEquals(listOf("alice@example.invalid"), (result as ClientSendOutcome.KeyChanged).addresses)
        assertTrue("nothing may be delivered", transport.sent.isEmpty())
    }

    /** A pin this device HOLDS but can no longer verify is a refusal, not an absence.
     *
     *  `ContactMappers.toEntity` stores a relay key verbatim even when `PgpFingerprint.compute`
     *  rejects it, keeping the previous fingerprint — so `keysFor` hands back a pin that will not
     *  fingerprint. Collapsing that into "never pinned" let a relay erase an in-person pin by
     *  serving an unparseable key, then supply any key it liked with no KeyChanged and no warning.
     *  Serving a merely DIFFERENT key was already caught; serving a broken one must be too. */
    @Test
    fun aPinThatWillNotFingerprintIsARefusalNotAnAbsence() = runBlocking {
        val unusablePin = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nnot-a-key\n-----END PGP PUBLIC KEY BLOCK-----"
        assertNull("this test proves nothing unless compute() rejects the pin", PgpFingerprint.compute(unusablePin))
        val transport = FakeClientEncryptedTransport()

        val result = sender(
            resolver = FakeRecipientKeyResolver(
                resolvedAll(listOf("alice@example.invalid"), TestPgpPrivateKey.ARMORED_PUBLIC),
            ),
            transport = transport,
            localKeys = FakePinnedKeys(
                mapOf("alice@example.invalid" to listOf(LocalSignerKey(unusablePin, confirmed = true))),
            ),
        ).send(draft(), sign = false)

        assertTrue("expected KeyChanged, got $result", result is ClientSendOutcome.KeyChanged)
        assertEquals(listOf("alice@example.invalid"), (result as ClientSendOutcome.KeyChanged).addresses)
        assertTrue("nothing may be encrypted to the relay's key", transport.sent.isEmpty())
    }

    /** An unconfirmed pin is still a key this device recorded for that contact, and the read path
     *  already calls a mismatch against one KEY_CHANGED. The write path must not be softer. */
    @Test
    fun anUnconfirmedPinStillOutranksTheRelay() = runBlocking {
        val result = sender(
            resolver = FakeRecipientKeyResolver(
                resolvedAll(listOf("alice@example.invalid"), TestPgpSecondKey.ARMORED_PUBLIC),
            ),
            localKeys = pinnedFor("alice@example.invalid", confirmed = false),
        ).send(draft(), sign = false)

        assertTrue("expected KeyChanged, got $result", result is ClientSendOutcome.KeyChanged)
    }

    /** The relay's blob fingerprints identically to the pin but carries no encryption subkey, so a
     *  delivery the recipient can open can only have been encrypted to the pinned bytes. */
    @Test
    fun aMatchingPinIsTheKeyTheMessageIsEncryptedTo() = runBlocking {
        val relayKey = strippedOfSubkeys(TestPgpPrivateKey.ARMORED_PUBLIC)
        assertEquals(
            "the stripped ring must fingerprint identically, or this test proves nothing",
            PgpFingerprint.compute(TestPgpPrivateKey.ARMORED_PUBLIC),
            PgpFingerprint.compute(relayKey),
        )
        val transport = FakeClientEncryptedTransport()
        val result = sender(
            resolver = FakeRecipientKeyResolver(resolvedAll(listOf("alice@example.invalid"), relayKey)),
            transport = transport,
            localKeys = pinnedFor("alice@example.invalid", confirmed = true),
        ).send(draft(), sign = false)

        assertTrue("expected Sent, got $result", result is ClientSendOutcome.Sent)
        assertTrue(
            "the recipient must be able to open a delivery encrypted to their pinned key",
            PgpDecryptor.decrypt(
                TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray(),
                armorOf(transport.sent.single().deliveries[0].ciphertext),
                emptyList(),
            ) is DecryptResult.Ok,
        )
    }

    /** No pin for this address is the ordinary case: the relay's key is used, tier checks and all. */
    @Test
    fun anAddressWithNoPinStillUsesTheRelaysKey() = runBlocking {
        val transport = FakeClientEncryptedTransport()
        val result = sender(
            resolver = FakeRecipientKeyResolver(
                resolvedAll(listOf("alice@example.invalid"), TestPgpSecondKey.ARMORED_PUBLIC),
            ),
            transport = transport,
            localKeys = pinnedFor("dave@example.invalid", confirmed = true),
        ).send(draft(), sign = false)

        assertTrue("expected Sent, got $result", result is ClientSendOutcome.Sent)
        assertTrue(
            "an unpinned recipient gets the relay's key",
            PgpDecryptor.decrypt(
                TestPgpSecondKey.ARMORED_PRIVATE.toCharArray(),
                armorOf(transport.sent.single().deliveries[0].ciphertext),
                emptyList(),
            ) is DecryptResult.Ok,
        )
    }

    @Test
    fun cancelledUnlockSendsNothing() = runBlocking {
        val transport = FakeClientEncryptedTransport()
        val result = sender(
            opener = FakeVaultOpener(outcome = OpenOutcome.Cancelled),
            resolver = FakeRecipientKeyResolver(
                resolvedAll(listOf("alice@example.invalid"), TestPgpPrivateKey.ARMORED_PUBLIC),
            ),
            transport = transport,
        ).send(draft(), sign = false)

        assertTrue("expected Cancelled, got $result", result is ClientSendOutcome.Cancelled)
        assertTrue(transport.sent.isEmpty())
    }

    @Test
    fun notClientProtectedIsPassedThrough() = runBlocking {
        val result = sender(
            resolver = FakeRecipientKeyResolver(ResolveResult.NotClientProtected),
        ).send(draft(), sign = false)

        assertTrue("expected NotClientProtected, got $result", result is ClientSendOutcome.NotClientProtected)
    }

    /** No mail account configured, so no valid `From` can be built. Refuse locally rather than
     *  build ciphertext the relay will 403. */
    @Test
    fun blankAccountAddressRefusesBeforeResolving() = runBlocking {
        val resolver = FakeRecipientKeyResolver()
        val result = sender(resolver = resolver, accountAddress = "  ").send(draft(), sign = false)

        assertTrue("expected NoAccountAddress, got $result", result is ClientSendOutcome.NoAccountAddress)
        assertEquals("must not even resolve", 0, resolver.calls)
    }

    @Test
    fun everyDeliveryCarriesTheAccountAddressAsFrom() = runBlocking {
        val transport = FakeClientEncryptedTransport()
        sender(
            resolver = FakeRecipientKeyResolver(
                resolvedAll(listOf("alice@example.invalid", "dave@example.invalid"), TestPgpPrivateKey.ARMORED_PUBLIC),
            ),
            transport = transport,
        ).send(draft(to = "alice@example.invalid", bcc = "dave@example.invalid"), sign = false)

        val message = transport.sent.single()
        assertEquals(ACCOUNT, message.from)
        message.deliveries.forEach {
            assertTrue(
                "every delivery's From must equal the authorized account address",
                it.ciphertext.lineSequence().any { line -> line == "From: $ACCOUNT" },
            )
        }
    }

    /** A server handing back "your" public key would otherwise get a readable copy of every send. */
    @Test
    fun theSentCopyIsEncryptedToTheVaultKeyNotAServerSuppliedOne() = runBlocking {
        val transport = FakeClientEncryptedTransport()
        sender(
            // Every recipient resolves to the SECOND key; the vault holds the first.
            resolver = FakeRecipientKeyResolver(
                resolvedAll(listOf("alice@example.invalid"), TestPgpSecondKey.ARMORED_PUBLIC),
            ),
            transport = transport,
        ).send(draft(), sign = false)

        val sentCopy = armorOf(transport.sent.single().sentCopy)

        assertTrue(
            "the sender must be able to read their own Sent copy",
            PgpDecryptor.decrypt(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray(), sentCopy, emptyList()) is DecryptResult.Ok,
        )
        assertTrue(
            "a server-supplied recipient key must not be what the Sent copy was encrypted to",
            PgpDecryptor.decrypt(TestPgpSecondKey.ARMORED_PRIVATE.toCharArray(), sentCopy, emptyList()) is DecryptResult.Failed,
        )
    }

    @Test
    fun signedSendProducesAVerifiableSignature() = runBlocking {
        val transport = FakeClientEncryptedTransport()
        sender(
            resolver = FakeRecipientKeyResolver(
                resolvedAll(listOf("alice@example.invalid"), TestPgpPrivateKey.ARMORED_PUBLIC),
            ),
            transport = transport,
        ).send(draft(), sign = true)

        val decrypted = PgpDecryptor.decrypt(
            TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray(),
            armorOf(transport.sent.single().deliveries[0].ciphertext),
            listOf(TestPgpPrivateKey.ARMORED_PUBLIC),
        ) as DecryptResult.Ok

        assertTrue("the recipient must see a valid signature", decrypted.signature.valid)
    }

    /** The real subject reaches the recipient through the protected header, and never appears in
     *  the delivery's cleartext. */
    @Test
    fun theRecipientRecoversTheRealSubjectAndBody() = runBlocking {
        val transport = FakeClientEncryptedTransport()
        sender(
            resolver = FakeRecipientKeyResolver(
                resolvedAll(listOf("alice@example.invalid"), TestPgpPrivateKey.ARMORED_PUBLIC),
            ),
            transport = transport,
        ).send(draft(), sign = false)

        val delivery = transport.sent.single().deliveries[0].ciphertext
        assertFalse("the real subject must not be in cleartext", delivery.contains("Subject: Subject"))

        val decrypted = PgpDecryptor.decrypt(
            TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray(),
            armorOf(delivery),
            emptyList(),
        ) as DecryptResult.Ok
        val parsed = requireNotNull(PgpMimeReader.read(decrypted.plaintext))
        assertEquals("Subject", parsed.protectedSubject)
        assertEquals("<p>Body</p>", parsed.html?.trim())
    }

    @Test
    fun aTransportFailureIsReportedNotSwallowed() = runBlocking {
        val result = sender(
            resolver = FakeRecipientKeyResolver(
                resolvedAll(listOf("alice@example.invalid"), TestPgpPrivateKey.ARMORED_PUBLIC),
            ),
            transport = FakeClientEncryptedTransport(MailOutcome.UpstreamFailure("failed to send email")),
        ).send(draft(), sign = false)

        assertTrue("expected SendFailed, got $result", result is ClientSendOutcome.SendFailed)
    }

    @Test
    fun successCarriesTheServersWarning() = runBlocking {
        val result = sender(
            resolver = FakeRecipientKeyResolver(
                resolvedAll(listOf("alice@example.invalid"), TestPgpPrivateKey.ARMORED_PUBLIC),
            ),
            transport = FakeClientEncryptedTransport(
                MailOutcome.Success(MailSendOutcome(sentSaved = false, warning = "1 bcc delivery(s) failed")),
            ),
        ).send(draft(), sign = false)

        val sent = result as ClientSendOutcome.Sent
        assertEquals("1 bcc delivery(s) failed", sent.warning)
        assertFalse(sent.sentSaved)
    }
}
