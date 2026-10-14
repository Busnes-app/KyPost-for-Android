package org.kysecurity.mail.pgp

import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPCompressedData
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.security.SecureRandom

/** RFC 9580 Intended Recipient Fingerprint: written on every signed send, checked on read. */
class IntendedRecipientTest {

    private val plaintext = "Content-Type: text/plain; charset=utf-8\r\n\r\nFor you only.\r\n".toByteArray()

    @Test
    fun aSignedMessageNamesEveryRecipientPrimaryKey() {
        val armored = signedFor(listOf(TestPgpPrivateKey.ARMORED_PUBLIC, TestPgpSecondKey.ARMORED_PUBLIC))

        val named = hashedIntendedRecipients(armored, TestPgpPrivateKey.ARMORED_PRIVATE).map { it.hex() }.toSet()

        assertEquals(
            setOf(primaryFingerprint(TestPgpPrivateKey.ARMORED_PUBLIC), primaryFingerprint(TestPgpSecondKey.ARMORED_PUBLIC)),
            named,
        )
    }

    @Test
    fun aMessageSignedForThisDeviceStaysVerified() {
        val signature = decryptAsUs(signedFor(listOf(TestPgpPrivateKey.ARMORED_PUBLIC))) as RawSignature.Checked

        assertTrue(signature.verified)
        assertFalse(signature.forAnotherRecipient)
        assertEquals(PgpSignatureState.VERIFIED_SEEN_BEFORE, verdict(signature))
    }

    /** Someone the sender wrote to re-encrypts the signed message to us: the signature still
     *  verifies, but it names the original recipient. */
    @Test
    fun aSignedMessageReEncryptedToThisDeviceIsNeverVerified() {
        val toSomeoneElse = signedFor(listOf(TestPgpSecondKey.ARMORED_PUBLIC))
        val forwarded = reEncrypt(toSomeoneElse, TestPgpSecondKey.ARMORED_PRIVATE, to = TestPgpPrivateKey.ARMORED_PUBLIC)

        val signature = decryptAsUs(forwarded) as RawSignature.Checked

        assertTrue("the signature itself is genuine", signature.verified)
        assertTrue(signature.forAnotherRecipient)
        assertEquals(PgpSignatureState.FOR_ANOTHER_RECIPIENT, verdict(signature))
        assertEquals(
            PgpSignatureState.FOR_ANOTHER_RECIPIENT,
            verdict(signature, LocalSignerKey(TestPgpPrivateKey.ARMORED_PUBLIC, confirmed = true, pinned = true)),
        )
    }

    /** Legacy senders, and every other KyPost client today, emit no subpacket. */
    @Test
    fun aSignatureNamingNoRecipientIsUnchanged() {
        assertTrue(
            "fixture must carry no Intended Recipient Fingerprint",
            hashedIntendedRecipients(TestPgpPrivateKey.ARMORED_MIME_MESSAGE, TestPgpPrivateKey.ARMORED_PRIVATE).isEmpty(),
        )

        val signature = decryptAsUs(TestPgpPrivateKey.ARMORED_MIME_MESSAGE) as RawSignature.Checked

        assertFalse(signature.forAnotherRecipient)
        assertEquals(PgpSignatureState.VERIFIED_SEEN_BEFORE, verdict(signature))
    }

    private fun verdict(
        signature: RawSignature,
        local: LocalSignerKey = LocalSignerKey(TestPgpPrivateKey.ARMORED_PUBLIC, confirmed = false),
    ) = signatureStateFor(signature, serverKeys = emptyList(), localKeys = listOf(local))

    /** Signed by [TestPgpPrivateKey], whose public half the reader below holds. */
    private fun signedFor(recipients: List<String>): String =
        (PgpEncryptor.encrypt(plaintext, recipients, TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray()) as EncryptResult.Ok).armored

    private fun decryptAsUs(armored: String): RawSignature =
        (
            PgpDecryptor.decrypt(
                TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray(),
                armored,
                signerPublicKeys = listOf(TestPgpPrivateKey.ARMORED_PUBLIC),
            ) as DecryptResult.Ok
            ).signature

    /** The decrypted packet stream, exactly as the sender wrote it inside the encryption layer. */
    private fun innerPackets(armored: String, privateKey: String): ByteArray {
        val ring = PGPSecretKeyRing(PGPUtil.getDecoderStream(privateKey.byteInputStream()), BcKeyFingerprintCalculator())
        val list = JcaPGPObjectFactory(PGPUtil.getDecoderStream(armored.byteInputStream())).nextObject() as PGPEncryptedDataList
        val packet = list.encryptedDataObjects.asSequence().filterIsInstance<PGPPublicKeyEncryptedData>()
            .first { ring.getSecretKey(it.keyIdentifier.keyId) != null }
        val privateKeyFor = ring.getSecretKey(packet.keyIdentifier.keyId)
            .extractPrivateKey(BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(CharArray(0)))
        return packet.getDataStream(BcPublicKeyDataDecryptorFactory(privateKeyFor)).readBytes()
    }

    private fun reEncrypt(armored: String, privateKey: String, to: String): String {
        val inner = innerPackets(armored, privateKey)
        val recipient = PGPPublicKeyRing(PGPUtil.getDecoderStream(to.byteInputStream()), BcKeyFingerprintCalculator())
            .publicKeys.asSequence().first { it.isEncryptionKey && !it.isMasterKey }
        val generator = PGPEncryptedDataGenerator(
            BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).setWithIntegrityPacket(true).setSecureRandom(SecureRandom()),
        ).apply { addMethod(BcPublicKeyKeyEncryptionMethodGenerator(recipient)) }
        val out = ByteArrayOutputStream()
        ArmoredOutputStream(out).use { armor -> generator.open(armor, inner.size.toLong()).use { it.write(inner) } }
        return out.toString(Charsets.UTF_8.name())
    }

    private fun hashedIntendedRecipients(armored: String, privateKey: String): List<ByteArray> {
        var factory = JcaPGPObjectFactory(innerPackets(armored, privateKey))
        val found = mutableListOf<ByteArray>()
        generateSequence { factory.nextObject() }.forEach { obj ->
            when (obj) {
                is PGPCompressedData -> factory = JcaPGPObjectFactory(obj.dataStream)
                is PGPLiteralData -> obj.inputStream.readBytes()
                is PGPSignatureList -> obj.forEach { signature ->
                    signature.hashedSubPackets?.intendedRecipientFingerprints?.forEach { found += it.fingerprint }
                }
            }
        }
        return found
    }

    private fun primaryFingerprint(armoredPublic: String): String =
        PGPPublicKeyRing(PGPUtil.getDecoderStream(armoredPublic.byteInputStream()), BcKeyFingerprintCalculator())
            .publicKey.fingerprint.hex()

    private fun ByteArray.hex() = joinToString("") { "%02X".format(it) }
}
