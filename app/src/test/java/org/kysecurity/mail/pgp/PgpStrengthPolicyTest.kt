package org.kysecurity.mail.pgp

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyPacket
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator
import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.PGPKeyRingGenerator
import org.bouncycastle.openpgp.PGPKdfParameters
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPLiteralDataGenerator
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair
import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.util.Date

class PgpStrengthPolicyTest {
    @Test
    fun obsoleteDetachedDigestsRemainPresentButUnchecked() {
        for (hash in obsoleteDigests) {
            val result = PgpDecryptor.verifyDetached(strong.publicArmor, body, detached(strong, hash), emptyList())
            assertTrue("digest $hash", result is RawSignature.Unchecked)
            assertFalse(result.valid)
            assertEquals(PgpSignatureState.UNCHECKED, state(result, strong))
        }
    }

    @Test
    fun obsoleteOnePassDigestsDoNotHideThePlaintextOrGrantTrust() {
        for (hash in obsoleteDigests) {
            val result = open(encrypted(strong, hash), strong)
            assertArrayEquals(body, result.plaintext)
            assertTrue("digest $hash", result.signature is RawSignature.Unchecked)
            assertEquals(PgpSignatureState.UNCHECKED, state(result.signature, strong))
        }
    }

    @Test
    fun strongDigestsStillVerifyInBothFormats() {
        for (hash in strongDigests) {
            val detached = PgpDecryptor.verifyDetached(strong.publicArmor, body, detached(strong, hash), emptyList())
            val inline = open(encrypted(strong, hash), strong)
            assertTrue("detached digest $hash", detached.valid)
            assertTrue("inline digest $hash", inline.signature.valid)
            assertEquals(PgpSignatureState.VERIFIED_CONFIRMED, state(detached, strong))
            assertArrayEquals(body, inline.plaintext)
        }
    }

    @Test
    fun shortRsaRecipientsRefuseTheWholeSend() {
        for (key in weak) {
            val result = PgpEncryptor.encrypt(body, listOf(strong.publicArmor, key.publicArmor), null as PGPSecretKeyRing?)
            assertTrue("RSA-${key.ring.publicKey.bitStrength}", result is EncryptResult.Failed)
        }
    }

    @Test
    fun shortActiveSignersDoNotFallBackToUnsignedMail() {
        for (key in weak) {
            val result = PgpEncryptor.encrypt(body, listOf(strong.publicArmor), key.ring)
            assertTrue("RSA-${key.ring.publicKey.bitStrength}", result is EncryptResult.Failed)
        }
    }

    @Test
    fun shortRsaSignaturesCannotAcquireIdentityTrust() {
        for (key in weak) {
            val detached = PgpDecryptor.verifyDetached(key.publicArmor, body, detached(key, HashAlgorithmTags.SHA256), emptyList())
            val inline = open(encrypted(key, HashAlgorithmTags.SHA256), strong, key)
            assertTrue(detached is RawSignature.Unchecked)
            assertTrue(inline.signature is RawSignature.Unchecked)
            assertEquals(PgpSignatureState.UNCHECKED, state(detached, key))
            assertTrue(signerKeyIdsOf(key.publicArmor).isEmpty())
        }
    }

    @Test
    fun oldShortRecipientCiphertextStillOpensWithoutChangingItsKey() {
        for (key in weak) {
            val privateArmor = key.privateArmor
            val privateBefore = privateArmor.copyOf()
            // Independent BC packet writer represents an already received message.
            val result = PgpDecryptor.decrypt(privateArmor,
                encrypted(strong, HashAlgorithmTags.SHA256, recipient = key), listOf(strong.publicArmor)) as DecryptResult.Ok
            assertArrayEquals(body, result.plaintext)
            assertTrue(result.signature.valid)
            assertArrayEquals(privateBefore, privateArmor)
        }
    }

    @Test
    fun strongOutboundSignAndEncryptStillRoundTrip() {
        val sent = PgpEncryptor.encrypt(body, listOf(strong.publicArmor), strong.ring) as EncryptResult.Ok
        val opened = open(sent.armored, strong)
        assertArrayEquals(body, opened.plaintext)
        assertTrue(opened.signature.valid)
    }

    @Test
    fun aWeakPrimaryCannotAuthorizeAStrongSubkey() {
        val key = rsaFixture(bits = 1024, subkeyBits = 2048, signingOnlyPrimary = true)
        assertTrue(PgpEncryptor.encrypt(body, listOf(key.publicArmor), null as PGPSecretKeyRing?) is EncryptResult.Failed)
        val result = PgpDecryptor.verifyDetached(key.publicArmor, body, detached(key, HashAlgorithmTags.SHA256, subkey = true), emptyList())
        assertTrue(result is RawSignature.Unchecked)
        assertEquals(PgpSignatureState.UNCHECKED, state(result, key))
        assertTrue(signerKeyIdsOf(key.publicArmor).isEmpty())
    }

    @Test
    fun aStrongPrimaryCannotAuthorizeAShortSubkey() {
        val key = rsaFixture(subkeyBits = 1024, signingOnlyPrimary = true)
        assertTrue(PgpEncryptor.encrypt(body, listOf(key.publicArmor), null as PGPSecretKeyRing?) is EncryptResult.Failed)
        val result = PgpDecryptor.verifyDetached(key.publicArmor, body, detached(key, HashAlgorithmTags.SHA256, subkey = true), emptyList())
        assertTrue(result is RawSignature.Unchecked)
        assertEquals(PgpSignatureState.UNCHECKED, state(result, key))
    }

    @Test
    fun shortEllipticKeysAreNotNewRecipientsOrTrustedSigners() {
        val key = ecFixture("secp192r1")
        assertTrue(PgpEncryptor.encrypt(body, listOf(key.publicArmor), null as PGPSecretKeyRing?) is EncryptResult.Failed)
        val signature = PgpDecryptor.verifyDetached(key.publicArmor, body, detached(key, HashAlgorithmTags.SHA256), emptyList())
        assertTrue(signature is RawSignature.Unchecked)
        assertEquals(PgpSignatureState.UNCHECKED, state(signature, key))
    }

    @Test
    fun supportedEllipticKeysStillSignEncryptAndAuthenticate() {
        for (curve in listOf("secp224r1", "secp256r1")) {
            val key = ecFixture(curve)
            val sent = PgpEncryptor.encrypt(body, listOf(key.publicArmor), key.ring) as EncryptResult.Ok
            val result = open(sent.armored, key, key)
            assertArrayEquals(body, result.plaintext)
            assertTrue(result.signature.valid)
            assertEquals(PgpSignatureState.VERIFIED_CONFIRMED, state(result.signature, key))
        }
    }

    @Test
    fun dsaDoesNotAcquireTrustEvenAt2048Bits() {
        val raw = KeyPairGenerator.getInstance("DSA").apply { initialize(2048) }.generateKeyPair()
        val key = keyFixture(JcaPGPKeyPair(PublicKeyPacket.VERSION_4, PublicKeyAlgorithmTags.DSA, raw, Date(0)))
        val signature = PgpDecryptor.verifyDetached(key.publicArmor, body, detached(key, HashAlgorithmTags.SHA256), emptyList())
        assertTrue(signature is RawSignature.Unchecked)
        assertEquals(PgpSignatureState.UNCHECKED, state(signature, key))
        assertTrue(signerKeyIdsOf(key.publicArmor).isEmpty())
    }

    @Test
    fun legacyBindingsKeepTheirArchiveBytesButCannotAuthorizeNewUse() {
        for (hash in obsoleteDigests) {
            val key = rsaFixture(subkeyBits = 2048, certificationHash = hash, signingOnlyPrimary = true)
            val json = key.keyringBytes()
            val retained = requireNotNull(parsePgpKeyring(json, key.fingerprint))
            assertNotNull(PgpFingerprint.compute(key.publicArmor))
            assertTrue(PgpEncryptor.encrypt(body, listOf(key.publicArmor), null as PGPSecretKeyRing?) is EncryptResult.Failed)
            val checked = PgpDecryptor.verifyDetached(key.publicArmor, body, detached(key, HashAlgorithmTags.SHA256, subkey = true), emptyList())
            assertTrue(checked is RawSignature.Unchecked)
            assertEquals(PgpSignatureState.UNCHECKED, state(checked, key))
            assertFalse(key.subkey!!.publicKey.keyID in signerKeyIdsOf(key.publicArmor))
            val opened = open(encrypted(strong, HashAlgorithmTags.SHA256, recipient = key, recipientSubkey = true), key)
            assertArrayEquals(body, opened.plaintext)
            assertArrayEquals(json, retained.original)
            retained.wipe()
        }
    }

    @Test
    fun supportedSubkeyBindingsStillEncryptAndAuthenticate() {
        val key = rsaFixture(subkeyBits = 2048, signingOnlyPrimary = true)
        val sent = PgpEncryptor.encrypt(body, listOf(key.publicArmor), strong.ring) as EncryptResult.Ok
        assertArrayEquals(body, open(sent.armored, key).plaintext)
        val result = PgpDecryptor.verifyDetached(key.publicArmor, body, detached(key, HashAlgorithmTags.SHA256, subkey = true), emptyList())
        assertTrue(result.valid)
        assertEquals(PgpSignatureState.VERIFIED_CONFIRMED, state(result, key))
    }

    @Test
    fun bothOnePassAndTerminalDigestMetadataAreChecked() {
        for ((header, tail) in listOf(
            HashAlgorithmTags.MD5 to HashAlgorithmTags.SHA256,
            HashAlgorithmTags.SHA256 to HashAlgorithmTags.MD5,
        )) {
            val result = open(encrypted(strong, header, tailHash = tail), strong)
            assertTrue(result.signature is RawSignature.Unchecked)
            assertArrayEquals(body, result.plaintext)
        }
        val mismatch = open(encrypted(strong, HashAlgorithmTags.SHA256, tailHash = HashAlgorithmTags.SHA512), strong)
        assertFalse(mismatch.signature.valid)
    }

    @Test
    fun uncheckedSignaturesDoNotSuppressKnownKeyChanges() {
        val raw = RawSignature.Unchecked(strong.ring.publicKey.keyID)
        assertEquals(PgpSignatureState.KEY_CHANGED, state(raw, weak.first()))
        val conflicting = SignerKey(emptyList(), strong.publicArmor, verified = true, source = "relay", conflict = true)
        assertEquals(PgpSignatureState.KEY_CHANGED, signatureStateFor(raw, listOf(conflicting)))
    }

    @Test
    fun detachedReaderFindsTheRetainedSignerAfterAnUnrelatedKey() = runBlocking {
        EnrollmentSession.put(strong.privateArmor)
        try {
            val key = weak.first()
            val payload = PgpPayloadResult.Success(
                encryptedPayload = "", signaturePayload = detached(key, HashAlgorithmTags.SHA256), body = "",
                signedPartBase64 = java.util.Base64.getEncoder().encodeToString(body),
                signerKeys = emptyList(), sender = "fixture@example.invalid", resolvedSender = "fixture@example.invalid",
            )
            val reader = EncryptedMessageReader(FakeVaultOpener(), FakePayloadSource(payload), localSignerKeys = {
                listOf(LocalSignerKey(strong.publicArmor, confirmed = true), LocalSignerKey(key.publicArmor, confirmed = true))
            })
            val result = reader.read("INBOX", "fixture", "fixture@example.invalid", unlockIfNeeded = false) as ReadOutcome.Decrypted
            assertEquals(PgpSignatureState.UNCHECKED, result.signature)
        } finally {
            EnrollmentSession.clear()
        }
    }

    @Test
    fun oldSha1RevocationsStillRemoveTrust() {
        val signature = signer(strong, HashAlgorithmTags.SHA1).apply {
            init(PGPSignature.KEY_REVOCATION, strong.primary.privateKey)
        }.generateCertification(strong.ring.publicKey)
        val revoked = PGPPublicKey.addCertification(strong.ring.publicKey, signature)
        val armor = armor { PGPPublicKeyRing(listOf(revoked)).encode(it) }
        assertTrue(isPrimaryRevoked(armor))
        assertTrue(signerKeyIdsOf(armor).isEmpty())
    }

    @Test
    fun archiveCiphersOpenByDefaultExceptBrokenOnes() {
        for (cipher in strongCiphers + legacyCiphers) {
            val result = PgpDecryptor.decrypt(strong.privateArmor,
                encrypted(strong, HashAlgorithmTags.SHA256, cipher = cipher), listOf(strong.publicArmor))
            assertArrayEquals("cipher $cipher", body, (result as DecryptResult.Ok).plaintext)
        }
        val des = PgpDecryptor.decrypt(strong.privateArmor,
            encrypted(strong, HashAlgorithmTags.SHA256, cipher = SymmetricKeyAlgorithmTags.DES), listOf(strong.publicArmor))
        assertEquals(DecryptResult.Failed(PgpDecryptor.REFUSED_CIPHER), des)
    }

    @Test
    fun refusingLegacyClosesSixtyFourBitCiphersAndKeepsStrongOnes() {
        for (cipher in legacyCiphers) {
            val result = PgpDecryptor.decrypt(strong.privateArmor,
                encrypted(strong, HashAlgorithmTags.SHA256, cipher = cipher), listOf(strong.publicArmor), refuseLegacy = true)
            assertEquals("cipher $cipher", DecryptResult.Failed(PgpDecryptor.REFUSED_CIPHER), result)
        }
        for (cipher in strongCiphers) {
            val result = PgpDecryptor.decrypt(strong.privateArmor,
                encrypted(strong, HashAlgorithmTags.SHA256, cipher = cipher), listOf(strong.publicArmor), refuseLegacy = true)
            assertArrayEquals("cipher $cipher", body, (result as DecryptResult.Ok).plaintext)
        }
    }

    @Test
    fun refusingLegacyClosesShortDecryptionKeysWithoutTouchingThem() {
        for (key in weak) {
            val privateArmor = key.privateArmor
            val privateBefore = privateArmor.copyOf()
            val result = PgpDecryptor.decrypt(privateArmor,
                encrypted(strong, HashAlgorithmTags.SHA256, recipient = key), listOf(strong.publicArmor), refuseLegacy = true)
            assertEquals(DecryptResult.Failed(PgpDecryptor.REFUSED_KEY), result)
            assertArrayEquals(privateBefore, privateArmor)
        }
    }

    /** What every new message is made of, read back with plain Bouncy Castle. */
    @Test
    fun newMessagesUseAes256IntegrityAndSha256() {
        val sent = PgpEncryptor.encrypt(body, listOf(strong.publicArmor), strong.ring) as EncryptResult.Ok
        val list = org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory(
            org.bouncycastle.openpgp.PGPUtil.getDecoderStream(sent.armored.byteInputStream()),
        ).nextObject() as org.bouncycastle.openpgp.PGPEncryptedDataList
        val pked = list.encryptedDataObjects.next() as org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
        val privateKey = strong.ring.secretKey.extractPrivateKey(
            org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(CharArray(0)),
        )
        val factory = org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory(privateKey)
        assertEquals(SymmetricKeyAlgorithmTags.AES_256, pked.getSymmetricAlgorithm(factory))
        assertTrue(pked.isIntegrityProtected)
        val hashes = hashesIn(org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory(pked.getDataStream(factory)))
        assertTrue(pked.verify())
        assertEquals(listOf(HashAlgorithmTags.SHA256, HashAlgorithmTags.SHA256), hashes)
    }

    private fun hashesIn(objects: org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory): List<Int> =
        generateSequence { objects.nextObject() }.flatMap { item ->
            when (item) {
                is org.bouncycastle.openpgp.PGPCompressedData ->
                    hashesIn(org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory(item.dataStream)).asSequence()
                is org.bouncycastle.openpgp.PGPOnePassSignatureList -> sequenceOf(item[0].hashAlgorithm)
                is org.bouncycastle.openpgp.PGPSignatureList -> sequenceOf(item[0].hashAlgorithm)
                is PGPLiteralData -> emptySequence<Int>().also { item.inputStream.readBytes() }
                else -> emptySequence()
            }
        }.toList()

    @Test
    fun archiveCipherPredicate() {
        for (cipher in listOf(SymmetricKeyAlgorithmTags.NULL, SymmetricKeyAlgorithmTags.DES, SymmetricKeyAlgorithmTags.SAFER, 99)) {
            assertFalse("$cipher", PgpStrengthPolicy.archiveCipherAllowed(cipher, strict = false))
        }
        for (cipher in legacyCiphers) {
            assertTrue(PgpStrengthPolicy.archiveCipherAllowed(cipher, strict = false))
            assertFalse(PgpStrengthPolicy.archiveCipherAllowed(cipher, strict = true))
        }
        for (cipher in strongCiphers) assertTrue(PgpStrengthPolicy.archiveCipherAllowed(cipher, strict = true))
    }

    private fun state(raw: RawSignature, key: Fixture): PgpSignatureState =
        signatureStateFor(raw, emptyList(), listOf(LocalSignerKey(key.publicArmor, confirmed = true)))

    private fun open(armor: String, recipient: Fixture, signingKey: Fixture = strong): DecryptResult.Ok =
        PgpDecryptor.decrypt(recipient.privateArmor, armor, listOf(signingKey.publicArmor)) as DecryptResult.Ok

    private fun detached(key: Fixture, hash: Int, subkey: Boolean = false): String = armor { out ->
        signer(key, hash, subkey).apply { update(body) }.generate().encode(out)
    }

    private fun signer(key: Fixture, hash: Int, subkey: Boolean = false): PGPSignatureGenerator {
        val pair = if (subkey) requireNotNull(key.subkey) else key.primary
        return PGPSignatureGenerator(
            BcPGPContentSignerBuilder(pair.publicKey.algorithm, hash), key.ring.getPublicKey(pair.keyID),
        ).apply { init(PGPSignature.BINARY_DOCUMENT, pair.privateKey) }
    }

    private fun encrypted(
        signingKey: Fixture,
        hash: Int,
        recipient: Fixture = strong,
        recipientSubkey: Boolean = false,
        tailHash: Int = hash,
        cipher: Int = SymmetricKeyAlgorithmTags.AES_256,
    ): String = armor { out ->
        val generator = PGPEncryptedDataGenerator(BcPGPDataEncryptorBuilder(cipher)
            .setWithIntegrityPacket(true).setSecureRandom(SecureRandom()))
        val recipientKey = if (recipientSubkey) recipient.ring.getPublicKey(requireNotNull(recipient.subkey).keyID) else recipient.ring.publicKey
        generator.addMethod(BcPublicKeyKeyEncryptionMethodGenerator(recipientKey))
        generator.open(out, ByteArray(4096)).use { encrypted ->
            signer(signingKey, hash).generateOnePassVersion(false).encode(encrypted)
            val literal = PGPLiteralDataGenerator()
            literal.open(encrypted, PGPLiteralData.BINARY, "", body.size.toLong(), Date(0)).use { it.write(body) }
            literal.close()
            signer(signingKey, tailHash).apply { update(body) }.generate().encode(encrypted)
        }
    }

    private data class Fixture(val primary: PGPKeyPair, val subkey: PGPKeyPair?, val ring: PGPSecretKeyRing) {
        val publicArmor: String get() = armor { PGPPublicKeyRing(ring.publicKeys.asSequence().toList()).encode(it) }
        val privateArmor: CharArray get() = armor { ring.encode(it) }.toCharArray()
        val fingerprint: String get() = ring.publicKey.fingerprint.joinToString("") { "%02X".format(it) }
        fun keyringBytes(): ByteArray = buildJsonObject {
            put("format", "kypost-pgp-keyring-v1")
            put("materialGeneration", 1)
            put("activeFingerprint", fingerprint)
            put("keyFingerprints", JsonArray(ring.publicKeys.asSequence().map { key ->
                JsonPrimitive(key.fingerprint.joinToString("") { "%02X".format(it) })
            }.toList()))
            put("keys", JsonArray(listOf(buildJsonObject {
                put("fingerprint", fingerprint)
                put("privateKey", privateArmor.concatToString())
            })))
        }.toString().toByteArray()
    }

    companion object {
        private val body = "Public OpenPGP policy fixture".toByteArray()
        private val obsoleteDigests = listOf(HashAlgorithmTags.MD5, HashAlgorithmTags.SHA1, HashAlgorithmTags.RIPEMD160)
        private val strongDigests = listOf(HashAlgorithmTags.SHA256, HashAlgorithmTags.SHA384, HashAlgorithmTags.SHA512, HashAlgorithmTags.SHA3_256, HashAlgorithmTags.SHA3_512)
        private val strongCiphers = listOf(SymmetricKeyAlgorithmTags.AES_128, SymmetricKeyAlgorithmTags.AES_192,
            SymmetricKeyAlgorithmTags.AES_256, SymmetricKeyAlgorithmTags.TWOFISH, SymmetricKeyAlgorithmTags.CAMELLIA_128,
            SymmetricKeyAlgorithmTags.CAMELLIA_192, SymmetricKeyAlgorithmTags.CAMELLIA_256)
        private val legacyCiphers = listOf(SymmetricKeyAlgorithmTags.IDEA, SymmetricKeyAlgorithmTags.TRIPLE_DES,
            SymmetricKeyAlgorithmTags.CAST5, SymmetricKeyAlgorithmTags.BLOWFISH)
        private val strong by lazy { rsaFixture() }
        private val weak by lazy { listOf(rsaFixture(1024), rsaFixture(2047)) }

        // RSA_SIGN is a legacy role tag used only to build rejected/retained compatibility inputs.
        @Suppress("DEPRECATION")
        private fun rsaFixture(
            bits: Int = 2048,
            subkeyBits: Int? = null,
            certificationHash: Int = HashAlgorithmTags.SHA256,
            signingOnlyPrimary: Boolean = false,
        ): Fixture {
            fun pair(bits: Int, algorithm: Int): PGPKeyPair {
                val raw = KeyPairGenerator.getInstance("RSA").apply { initialize(bits) }.generateKeyPair()
                return JcaPGPKeyPair(PublicKeyPacket.VERSION_4, algorithm, raw, Date(0))
            }
            val primary = pair(bits, if (signingOnlyPrimary) PublicKeyAlgorithmTags.RSA_SIGN else PublicKeyAlgorithmTags.RSA_GENERAL)
            val subkey = subkeyBits?.let { pair(it, PublicKeyAlgorithmTags.RSA_GENERAL) }
            return keyFixture(primary, subkey, certificationHash)
        }

        private fun ecFixture(curve: String): Fixture {
            fun pair(algorithm: Int): PGPKeyPair {
                val raw = KeyPairGenerator.getInstance("EC", BouncyCastleProvider()).apply {
                    initialize(ECNamedCurveGenParameterSpec(curve))
                }.generateKeyPair()
                return if (algorithm == PublicKeyAlgorithmTags.ECDH) {
                    JcaPGPKeyPair(PublicKeyPacket.VERSION_4, algorithm,
                        PGPKdfParameters(HashAlgorithmTags.SHA256, SymmetricKeyAlgorithmTags.AES_128), raw, Date(0))
                } else JcaPGPKeyPair(PublicKeyPacket.VERSION_4, algorithm, raw, Date(0))
            }
            return keyFixture(pair(PublicKeyAlgorithmTags.ECDSA), pair(PublicKeyAlgorithmTags.ECDH))
        }

        private fun keyFixture(
            primary: PGPKeyPair,
            subkey: PGPKeyPair? = null,
            certificationHash: Int = HashAlgorithmTags.SHA256,
        ): Fixture {
            val generator = PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, primary, "fixture@example.invalid",
                BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1), null, null,
                BcPGPContentSignerBuilder(primary.publicKey.algorithm, certificationHash), null)
            if (subkey != null) generator.addSubKey(subkey, PGPSignatureSubpacketGenerator().apply {
                setKeyFlags(false, KeyFlags.SIGN_DATA or KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE)
            }.generate(), null)
            return Fixture(primary, subkey, generator.generateSecretKeyRing())
        }

        private fun armor(encode: (ArmoredOutputStream) -> Unit): String {
            val out = ByteArrayOutputStream()
            ArmoredOutputStream(out).use(encode)
            return out.toString(Charsets.UTF_8.name())
        }
    }
}
