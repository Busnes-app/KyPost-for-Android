package org.kysecurity.mail.pgp

import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPKeyRingGenerator
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.SecureRandom
import java.util.Date

/** Recipient key material comes from the relay, so `encrypt` must validate it locally. */
class PgpEncryptorKeyValidationTest {

    @Test
    fun healthyKeyStillEncrypts() {
        val ring = ringGenerator("Bob <bob@example.invalid>").generatePublicKeyRing()

        val result = PgpEncryptor.encrypt("x".toByteArray(), listOf(armor(ring.encoded)), null as CharArray?)

        assertTrue("a well-formed recipient key must still encrypt: $result", result is EncryptResult.Ok)
    }

    @Test
    fun revokedEncryptionSubkeyIsRefused() {
        val bob = ringGenerator("Bob <bob@example.invalid>")
        val pubRing = bob.generatePublicKeyRing()
        val primaryPub = pubRing.publicKey
        val subPub = pubRing.publicKeys.asSequence().first { !it.isMasterKey }

        val primaryPriv = bob.generateSecretKeyRing().secretKey.extractPrivateKey(
            BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(CharArray(0)),
        )
        val sigGen = PGPSignatureGenerator(
            BcPGPContentSignerBuilder(primaryPub.algorithm, HashAlgorithmTags.SHA256),
            primaryPub,
        )
        sigGen.init(PGPSignature.SUBKEY_REVOCATION, primaryPriv)
        val revokedSub = PGPPublicKey.addCertification(
            subPub,
            sigGen.generateCertification(primaryPub, subPub),
        )
        val revokedRing = PGPPublicKeyRing.insertPublicKey(pubRing, revokedSub)
        assertTrue(
            "precondition: the subkey must read as revoked",
            revokedRing.publicKeys.asSequence().first { !it.isMasterKey }.hasRevocation(),
        )

        val result = PgpEncryptor.encrypt("x".toByteArray(), listOf(armor(revokedRing.encoded)), null as CharArray?)

        // Not "encryption must fail": this fixture's RSA primary is itself encryption-capable and
        // unrevoked, so falling back to it is correct and the recipient can still read the message.
        // The security property is narrower — the retired subkey must not be the one addressed.
        assertTrue("encrypting to a healthy primary must still succeed: $result", result is EncryptResult.Ok)
        assertNotEquals(
            "ciphertext must not be addressed to the revoked subkey",
            subPub.keyID,
            firstPkedKeyId((result as EncryptResult.Ok).armored),
        )
    }

    @Test
    fun ringWhoseOnlyEncryptionKeyIsRevokedIsRefused() {
        // An ed25519-style split: the primary signs only, so once the encryption subkey is revoked
        // there is nothing left to encrypt to and the send must fail rather than silently proceed.
        val bob = ringGenerator("Bob <bob@example.invalid>", signOnlyPrimary = true)
        val pubRing = bob.generatePublicKeyRing()
        val primaryPub = pubRing.publicKey
        val subPub = pubRing.publicKeys.asSequence().first { !it.isMasterKey }

        val primaryPriv = bob.generateSecretKeyRing().secretKey.extractPrivateKey(
            BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(CharArray(0)),
        )
        val sigGen = PGPSignatureGenerator(
            BcPGPContentSignerBuilder(primaryPub.algorithm, HashAlgorithmTags.SHA256),
            primaryPub,
        )
        sigGen.init(PGPSignature.SUBKEY_REVOCATION, primaryPriv)
        val revokedRing = PGPPublicKeyRing.insertPublicKey(
            pubRing,
            PGPPublicKey.addCertification(subPub, sigGen.generateCertification(primaryPub, subPub)),
        )

        val result = PgpEncryptor.encrypt("x".toByteArray(), listOf(armor(revokedRing.encoded)), null as CharArray?)

        assertTrue(
            "no unrevoked encryption key remains, so the send must fail: $result",
            result is EncryptResult.Failed,
        )
    }

    @Test
    fun multipleKeyRingsInOneBlobAreRefused() {
        val bob = ringGenerator("Bob <bob@example.invalid>").generatePublicKeyRing()
        val eve = ringGenerator("Eve <eve@example.invalid>").generatePublicKeyRing()
        val twoRings = armor(bob.encoded + eve.encoded)

        val result = PgpEncryptor.encrypt("x".toByteArray(), listOf(twoRings), null as CharArray?)

        assertTrue(
            "a blob holding more than one key ring is ambiguous and must be refused: $result",
            result is EncryptResult.Failed,
        )
    }

    @Test
    fun foreignBoundSubkeyIsRefused() {
        val bobPub = ringGenerator("Bob <bob@example.invalid>").generatePublicKeyRing()
        val eveSecret = ringGenerator("Eve <eve@example.invalid>").generateSecretKeyRing()
        // Eve's encryption subkey still carries Eve's binding signature over *Eve's* primary, so it
        // is not validly bound to Bob. The primary fingerprint is untouched, which is why a TOFU pin
        // or an out-of-band fingerprint comparison cannot see this.
        val grafted = PGPPublicKeyRing.insertPublicKey(
            bobPub,
            eveSecret.publicKeys.asSequence().first { !it.isMasterKey },
        )

        val result = PgpEncryptor.encrypt("x".toByteArray(), listOf(armor(grafted.encoded)), null as CharArray?)

        assertTrue(
            "a subkey bound by a foreign signature must be refused: $result",
            result is EncryptResult.Failed,
        )
    }

    /** A gpg key with an SSH authentication subkey added later: newest is not "may encrypt". */
    @Test
    fun aNewerAuthenticationSubkeyIsNotEncryptedTo() {
        val gen = RSAKeyPairGenerator()
        gen.init(RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), SecureRandom(), 2048, 12))
        val now = Date()
        fun flags(value: Int) = org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator()
            .apply { setKeyFlags(false, value) }.generate()
        val primary = BcPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, gen.generateKeyPair(), now)
        val encryption = BcPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, gen.generateKeyPair(), now)
        val authentication = BcPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, gen.generateKeyPair(), Date(now.time + 60_000))
        val ring = PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION,
            primary,
            "Bob <bob@example.invalid>",
            BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
            flags(org.bouncycastle.bcpg.sig.KeyFlags.CERTIFY_OTHER or org.bouncycastle.bcpg.sig.KeyFlags.SIGN_DATA),
            null,
            BcPGPContentSignerBuilder(primary.publicKey.algorithm, HashAlgorithmTags.SHA256),
            null,
        ).apply {
            addSubKey(encryption, flags(org.bouncycastle.bcpg.sig.KeyFlags.ENCRYPT_COMMS or org.bouncycastle.bcpg.sig.KeyFlags.ENCRYPT_STORAGE), null)
            addSubKey(authentication, flags(org.bouncycastle.bcpg.sig.KeyFlags.AUTHENTICATION), null)
        }.generatePublicKeyRing()

        val result = PgpEncryptor.encrypt("x".toByteArray(), listOf(armor(ring.encoded)), null as CharArray?)

        assertTrue("$result", result is EncryptResult.Ok)
        org.junit.Assert.assertEquals(encryption.keyID, firstPkedKeyId((result as EncryptResult.Ok).armored))
    }

    /** A subkey once bound for encryption and later rebound for authentication only: the newer
     *  binding is what holds, so encryption goes to the other subkey. */
    @Test
    fun aRebindingForAuthenticationRevokesEncryption() {
        val gen = RSAKeyPairGenerator()
        gen.init(RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), SecureRandom(), 2048, 12))
        val now = Date()
        fun flags(value: Int) = org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator()
            .apply { setKeyFlags(false, value) }.generate()
        val encryptFlags = org.bouncycastle.bcpg.sig.KeyFlags.ENCRYPT_COMMS or org.bouncycastle.bcpg.sig.KeyFlags.ENCRYPT_STORAGE
        val primary = BcPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, gen.generateKeyPair(), now)
        val encryption = BcPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, gen.generateKeyPair(), now)
        val rebound = BcPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, gen.generateKeyPair(), Date(now.time + 60_000))
        val generator = PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION,
            primary,
            "Bob <bob@example.invalid>",
            BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
            flags(org.bouncycastle.bcpg.sig.KeyFlags.CERTIFY_OTHER or org.bouncycastle.bcpg.sig.KeyFlags.SIGN_DATA),
            null,
            BcPGPContentSignerBuilder(primary.publicKey.algorithm, HashAlgorithmTags.SHA256),
            null,
        ).apply {
            addSubKey(encryption, flags(encryptFlags), null)
            addSubKey(rebound, flags(encryptFlags), null)
        }
        val ring = generator.generatePublicKeyRing()
        val primaryPriv = generator.generateSecretKeyRing().secretKey.extractPrivateKey(
            BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(CharArray(0)),
        )
        val reboundPub = ring.getPublicKey(rebound.keyID)
        val sigGen = PGPSignatureGenerator(BcPGPContentSignerBuilder(primary.publicKey.algorithm, HashAlgorithmTags.SHA256), primary.publicKey)
        sigGen.init(PGPSignature.SUBKEY_BINDING, primaryPriv)
        sigGen.setHashedSubpackets(
            org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator().apply {
                setKeyFlags(false, org.bouncycastle.bcpg.sig.KeyFlags.AUTHENTICATION)
                setSignatureCreationTime(false, Date(now.time + 120_000))
            }.generate(),
        )
        val rebinding = sigGen.generateCertification(primary.publicKey, reboundPub)
        val reboundRing = PGPPublicKeyRing.insertPublicKey(ring, PGPPublicKey.addCertification(reboundPub, rebinding))

        val result = PgpEncryptor.encrypt("x".toByteArray(), listOf(armor(reboundRing.encoded)), null as CharArray?)

        assertTrue("$result", result is EncryptResult.Ok)
        org.junit.Assert.assertEquals(encryption.keyID, firstPkedKeyId((result as EncryptResult.Ok).armored))
    }

    /** A later binding that does not verify (here: signed over another key) must not take away
     *  the encryption permission the valid binding grants. */
    @Test
    fun anUnverifiableLaterBindingChangesNothing() {
        val gen = RSAKeyPairGenerator()
        gen.init(RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), SecureRandom(), 2048, 12))
        val now = Date()
        fun flags(value: Int) = org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator()
            .apply { setKeyFlags(false, value) }.generate()
        val primary = BcPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, gen.generateKeyPair(), now)
        val encryption = BcPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, gen.generateKeyPair(), now)
        val other = BcPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, gen.generateKeyPair(), now)
        val generator = PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION,
            primary,
            "Bob <bob@example.invalid>",
            BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
            flags(org.bouncycastle.bcpg.sig.KeyFlags.CERTIFY_OTHER or org.bouncycastle.bcpg.sig.KeyFlags.SIGN_DATA),
            null,
            BcPGPContentSignerBuilder(primary.publicKey.algorithm, HashAlgorithmTags.SHA256),
            null,
        ).apply {
            addSubKey(encryption, flags(org.bouncycastle.bcpg.sig.KeyFlags.ENCRYPT_COMMS or org.bouncycastle.bcpg.sig.KeyFlags.ENCRYPT_STORAGE), null)
        }
        val ring = generator.generatePublicKeyRing()
        val primaryPriv = generator.generateSecretKeyRing().secretKey.extractPrivateKey(
            BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(CharArray(0)),
        )
        val sigGen = PGPSignatureGenerator(BcPGPContentSignerBuilder(primary.publicKey.algorithm, HashAlgorithmTags.SHA256), primary.publicKey)
        sigGen.init(PGPSignature.SUBKEY_BINDING, primaryPriv)
        sigGen.setHashedSubpackets(
            org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator().apply {
                setKeyFlags(false, org.bouncycastle.bcpg.sig.KeyFlags.AUTHENTICATION)
                setSignatureCreationTime(false, Date(now.time + 120_000))
            }.generate(),
        )
        val forged = sigGen.generateCertification(primary.publicKey, other.publicKey)
        val encryptionPub = ring.getPublicKey(encryption.keyID)
        val tampered = PGPPublicKeyRing.insertPublicKey(ring, PGPPublicKey.addCertification(encryptionPub, forged))

        val result = PgpEncryptor.encrypt("x".toByteArray(), listOf(armor(tampered.encoded)), null as CharArray?)

        assertTrue("$result", result is EncryptResult.Ok)
        org.junit.Assert.assertEquals(encryption.keyID, firstPkedKeyId((result as EncryptResult.Ok).armored))
    }

    private fun firstPkedKeyId(armoredMessage: String): Long {
        val factory = JcaPGPObjectFactory(
            PGPUtil.getDecoderStream(armoredMessage.byteInputStream(Charsets.UTF_8)),
        )
        return generateSequence { factory.nextObject() }
            .filterIsInstance<PGPEncryptedDataList>()
            .first()
            .encryptedDataObjects.asSequence()
            .filterIsInstance<PGPPublicKeyEncryptedData>()
            .first()
            .keyIdentifier.keyId
    }

    // RSA_SIGN is deprecated with no replacement, and it is the only way to build the sign-only
    // primary that ringWhoseOnlyEncryptionKeyIsRefused needs; the BcPGPKeyPair constructor below is
    // the deprecated 3-arg form for the same fixture.
    @Suppress("DEPRECATION")
    private fun ringGenerator(uid: String, signOnlyPrimary: Boolean = false): PGPKeyRingGenerator {
        val gen = RSAKeyPairGenerator()
        gen.init(RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), SecureRandom(), 2048, 12))
        val now = Date()
        val primaryAlgorithm =
            if (signOnlyPrimary) PublicKeyAlgorithmTags.RSA_SIGN else PublicKeyAlgorithmTags.RSA_GENERAL
        val primary = BcPGPKeyPair(primaryAlgorithm, gen.generateKeyPair(), now)
        val sub = BcPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, gen.generateKeyPair(), now)
        return PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION,
            primary,
            uid,
            BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
            null,
            null,
            BcPGPContentSignerBuilder(primary.publicKey.algorithm, HashAlgorithmTags.SHA256),
            null,
        ).apply { addSubKey(sub) }
    }

    private fun armor(bytes: ByteArray): String {
        val out = ByteArrayOutputStream()
        ArmoredOutputStream(out).use { it.write(bytes) }
        return out.toString(Charsets.UTF_8.name())
    }
}
