package org.kysecurity.mail.pgp

import kotlinx.coroutines.runBlocking
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters
import org.bouncycastle.openpgp.PGPKeyRingGenerator
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair
import org.kysecurity.mail.mail.MailDraft
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.SecureRandom
import java.util.Date

/** A synced copy may withdraw a pinned key, and only when its revocation verifies against it. */
class PinnedKeyRevocationMergeTest {

    @Test
    fun aVerifiableRevocationOfTheSameKey_isTaken() {
        val merged = withVerifiedRevocation(public(A), revoked(A, signer = A))

        assertTrue(merged != null && isPrimaryRevoked(merged))
        assertEquals(PgpFingerprint.compute(public(A)), PgpFingerprint.compute(merged!!))
    }

    @Test
    fun aRevocationOfADifferentKey_isIgnored() {
        assertNull(withVerifiedRevocation(public(A), revoked(B, signer = B)))
    }

    @Test
    fun aRevocationNotMadeByThePinnedKey_isIgnored() {
        assertNull(withVerifiedRevocation(public(A), revoked(A, signer = B)))
    }

    @Test
    fun noRevocation_nothingTaken() {
        assertNull(withVerifiedRevocation(public(A), public(A)))
        assertFalse(isPrimaryRevoked(public(A)))
    }

    /** No fallback to another key, and no vault prompt for a send that cannot happen. */
    @Test
    fun aRevokedPin_refusesTheSendBeforeTheVault() = runBlocking {
        val opener = FakeVaultOpener()
        val transport = FakeClientEncryptedTransport()
        val revokedPin = withVerifiedRevocation(public(A), revoked(A, signer = A))!!
        val sender = ClientEncryptedSender(
            opener = opener,
            resolver = FakeRecipientKeyResolver(resolvedAll(listOf(ALICE), revoked(A, signer = A))),
            transport = transport,
            localKeys = FakePinnedKeys(mapOf(ALICE to listOf(LocalSignerKey(revokedPin, confirmed = true)))),
            accountAddress = "me@example.invalid",
        )

        val outcome = sender.send(MailDraft(to = ALICE, subject = "s", body = "b", mode = "plain"), sign = false)

        assertEquals(ClientSendOutcome.RecipientKeyRevoked(listOf(ALICE)), outcome)
        assertEquals(0, opener.opened)
        assertTrue(transport.sent.isEmpty())
    }

    /** The relay's view of the key (unusable, or a changed-key tier) must not hide that this
     *  device's own pin was revoked. */
    @Test
    fun aRevokedPin_isReportedEvenWhenTheRelayCallsTheKeyUnusableOrChanged() = runBlocking {
        val revokedPin = withVerifiedRevocation(public(A), revoked(A, signer = A))!!
        for (relayKey in listOf(
            ResolvedRecipientKey(ALICE, revoked(A, signer = A), "", "discovered", usable = false),
            ResolvedRecipientKey(ALICE, public(B), "", "key_changed", usable = true),
        )) {
            val opener = FakeVaultOpener()
            val transport = FakeClientEncryptedTransport()
            val sender = ClientEncryptedSender(
                opener = opener,
                resolver = FakeRecipientKeyResolver(ResolveResult.Success(listOf(relayKey))),
                transport = transport,
                localKeys = FakePinnedKeys(mapOf(ALICE to listOf(LocalSignerKey(revokedPin, confirmed = true)))),
                accountAddress = "me@example.invalid",
            )

            val outcome = sender.send(MailDraft(to = ALICE, subject = "s", body = "b", mode = "plain"), sign = false)

            assertEquals("relay said ${relayKey.tier}/${relayKey.usable}", ClientSendOutcome.RecipientKeyRevoked(listOf(ALICE)), outcome)
            assertEquals(0, opener.opened)
            assertTrue(transport.sent.isEmpty())
        }
    }

    /** The newest encryption subkey of a pinned key is revoked by its owner on the synced copy: the
     *  pin takes that revocation and the next message is encrypted to the remaining subkey. */
    @Test
    fun aVerifiedSubkeyRevocation_isTakenAndNeverEncryptedTo() = runBlocking {
        val pin = public(C)
        val merged = withVerifiedRevocation(pin, subkeyRevoked(C, NEWEST_SUBKEY, signer = C))

        val transport = FakeClientEncryptedTransport()
        ClientEncryptedSender(
            opener = FakeVaultOpener(),
            resolver = FakeRecipientKeyResolver(resolvedAll(listOf(ALICE), pin)),
            transport = transport,
            localKeys = FakePinnedKeys(mapOf(ALICE to listOf(LocalSignerKey(merged ?: pin, confirmed = true)))),
            accountAddress = "me@example.invalid",
        ).send(MailDraft(to = ALICE, subject = "s", body = "b", mode = "plain"), sign = false)

        val targets = recipientKeyIds(armorOf(transport.sent.single().deliveries.single().ciphertext))
        assertTrue("the message went out", targets.isNotEmpty())
        assertFalse("encrypted to the revoked subkey", subkeyId(C, NEWEST_SUBKEY) in targets)
        assertEquals("the pin is still the same key", PgpFingerprint.compute(pin), merged?.let(PgpFingerprint::compute))
    }

    @Test
    fun aSubkeyRevocationNotMadeByThePinnedPrimary_isIgnored() {
        assertNull(withVerifiedRevocation(public(C), subkeyRevoked(C, NEWEST_SUBKEY, signer = B)))
    }

    private companion object {
        const val ALICE = "alice@example.invalid"
        const val NEWEST_SUBKEY = 1
        /** Two encryption subkeys; the newer one is the one a send picks. */
        val C: PGPSecretKeyRing by lazy { generator("C <c@example.invalid>", subkeys = 2).generateSecretKeyRing() }

        fun subkeyId(owner: PGPSecretKeyRing, index: Int): Long =
            owner.publicKeys.asSequence().filter { !it.isMasterKey }.toList()[index].keyID

        /** [owner]'s public ring with subkey [index] revoked by a signature from [signer]'s primary. */
        fun subkeyRevoked(owner: PGPSecretKeyRing, index: Int, signer: PGPSecretKeyRing): String {
            val ring = publicRing(owner)
            val subkey = ring.publicKeys.asSequence().filter { !it.isMasterKey }.toList()[index]
            val privateKey = signer.secretKey.extractPrivateKey(BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(null))
            val generator = PGPSignatureGenerator(BcPGPContentSignerBuilder(signer.secretKey.publicKey.algorithm, HashAlgorithmTags.SHA256))
            generator.init(PGPSignature.SUBKEY_REVOCATION, privateKey)
            val revoked = PGPPublicKey.addCertification(subkey, generator.generateCertification(ring.publicKey, subkey))
            return armored(PGPPublicKeyRing.insertPublicKey(ring, revoked).encoded)
        }

        fun recipientKeyIds(armoredMessage: String): Set<Long> {
            val factory = org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory(
                org.bouncycastle.openpgp.PGPUtil.getDecoderStream(armoredMessage.byteInputStream(Charsets.UTF_8)),
            )
            val list = generateSequence { factory.nextObject() }.filterIsInstance<org.bouncycastle.openpgp.PGPEncryptedDataList>().first()
            return list.encryptedDataObjects.asSequence()
                .filterIsInstance<org.bouncycastle.openpgp.PGPPublicKeyEncryptedData>()
                .map { it.keyID }
                .toSet()
        }
        val A: PGPSecretKeyRing by lazy { generator("A <a@example.invalid>").generateSecretKeyRing() }
        val B: PGPSecretKeyRing by lazy { generator("B <b@example.invalid>").generateSecretKeyRing() }

        fun publicRing(secret: PGPSecretKeyRing) = PGPPublicKeyRing(secret.publicKeys.asSequence().toList())

        fun public(secret: PGPSecretKeyRing) = armored(publicRing(secret).encoded)

        /** [owner]'s public ring carrying a key revocation of its primary, signed by [signer]. */
        fun revoked(owner: PGPSecretKeyRing, signer: PGPSecretKeyRing): String {
            val ring = publicRing(owner)
            val primary = ring.publicKey
            val signingKey = signer.secretKey
            val privateKey = signingKey.extractPrivateKey(BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(null))
            val generator = PGPSignatureGenerator(BcPGPContentSignerBuilder(signingKey.publicKey.algorithm, HashAlgorithmTags.SHA256))
            generator.init(PGPSignature.KEY_REVOCATION, privateKey)
            val withRevocation = PGPPublicKey.addCertification(primary, generator.generateCertification(primary))
            return armored(PGPPublicKeyRing.insertPublicKey(ring, withRevocation).encoded)
        }

        @Suppress("DEPRECATION")
        fun generator(uid: String, subkeys: Int = 1): PGPKeyRingGenerator {
            val rsa = RSAKeyPairGenerator().apply {
                init(RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), SecureRandom(), 2048, 12))
            }
            val now = Date()
            val primary = BcPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, rsa.generateKeyPair(), Date(now.time - subkeys * 60_000L))
            // Each later subkey a minute newer, so "newest" is well defined.
            val subs = (1..subkeys).map { BcPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, rsa.generateKeyPair(), Date(now.time - (subkeys - it) * 60_000L)) }
            return PGPKeyRingGenerator(
                PGPSignature.POSITIVE_CERTIFICATION,
                primary,
                uid,
                BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
                null,
                null,
                BcPGPContentSignerBuilder(primary.publicKey.algorithm, HashAlgorithmTags.SHA256),
                null,
            ).apply { subs.forEach { addSubKey(it) } }
        }

        fun armored(bytes: ByteArray): String {
            val out = ByteArrayOutputStream()
            ArmoredOutputStream(out).use { it.write(bytes) }
            return out.toString(Charsets.UTF_8.name())
        }
    }
}
