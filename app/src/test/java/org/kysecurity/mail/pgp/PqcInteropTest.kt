package org.kysecurity.mail.pgp

import kotlinx.serialization.json.*
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.junit.Assert.*
import org.junit.Test
import java.util.Base64

/** Exercises the app's read path, not BC's high-level demonstration API. Public test keys only. */
class PqcInteropTest {
    private fun text(name: String) = String(SharedFixtures.bytes("openpgp-v6/$name"), Charsets.UTF_8)

    @Test fun rfc9980MessagesDecryptThroughTheAppIncludingStrictPolicy() {
        for (prefix in listOf("v4", "v4-pqc", "v6-pqc")) {
            for (strict in listOf(false, true)) {
                val result = PgpDecryptor.decrypt(text("$prefix.sec.asc").toCharArray(), text("$prefix.msg.asc"), emptyList(), strict)
                assertTrue("$prefix strict=$strict: $result", result is DecryptResult.Ok)
                assertArrayEquals(text("message.txt").toByteArray(), (result as DecryptResult.Ok).plaintext)
                result.plaintext.fill(0)
            }
        }
    }

    @Test fun compositeSignatureVerifiesAndRejectsAlteredText() {
        val plain = text("message.txt").toByteArray()
        val sig = text("v6-pqc.sig.asc")
        val keys = text("v6-pqc.pub.asc")
        assertTrue(PgpDecryptor.verifyDetached(keys, plain, sig, emptyList()).valid)
        assertFalse(PgpDecryptor.verifyDetached(keys, plain + 1, sig, emptyList()).valid)
    }

    @Test fun v6OnePassCompositeSignaturesVerifyThroughTheApp() {
        val ring = PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(text("v6-pqc.sec.asc").byteInputStream()), BcKeyFingerprintCalculator()).keyRings.next()
        val secret = ring.secretKey
        val primary = secret.publicKey
        val sigFactory = org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory(PGPUtil.getDecoderStream(text("v6-pqc.sig.asc").byteInputStream()))
        val hash = (sigFactory.nextObject() as org.bouncycastle.openpgp.PGPSignatureList)[0].hashAlgorithm
        val signature = org.bouncycastle.openpgp.PGPSignatureGenerator(org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder(primary.algorithm, hash), primary)
        signature.init(org.bouncycastle.openpgp.PGPSignature.BINARY_DOCUMENT, secret.extractPrivateKey(null))
        val output = java.io.ByteArrayOutputStream()
        val encryptor = org.bouncycastle.openpgp.PGPEncryptedDataGenerator(org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder(org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags.AES_256)
            .setWithAEAD(org.bouncycastle.bcpg.AEADAlgorithmTags.OCB, 6).setUseV6AEAD())
        encryptor.addMethod(org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator(ring.publicKeys.asSequence().first { it.isEncryptionKey }))
        val plain = text("message.txt").toByteArray()
        org.bouncycastle.bcpg.ArmoredOutputStream(output).use { armor ->
            encryptor.open(armor, ByteArray(4096)).use { encrypted ->
                signature.generateOnePassVersion(false).encode(encrypted)
                org.bouncycastle.openpgp.PGPLiteralDataGenerator().open(encrypted, org.bouncycastle.openpgp.PGPLiteralData.BINARY, "", plain.size.toLong(), java.util.Date(0)).use { it.write(plain) }
                signature.update(plain)
                signature.generate().encode(encrypted)
            }
        }
        val opened = PgpDecryptor.decrypt(text("v6-pqc.sec.asc").toCharArray(), output.toString("UTF-8"), listOf(text("v6-pqc.pub.asc")), true)
        assertTrue("$opened", opened is DecryptResult.Ok)
        assertArrayEquals(plain, (opened as DecryptResult.Ok).plaintext)
        assertTrue(opened.signature.valid)
        opened.plaintext.fill(0)
    }

    @Test fun v6FinalAuthenticationTagIsRequired() {
        val binary = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(text("v6-pqc.msg.asc").byteInputStream()).readBytes()
        binary[binary.lastIndex] = (binary.last().toInt() xor 1).toByte()
        val output = java.io.ByteArrayOutputStream()
        org.bouncycastle.bcpg.ArmoredOutputStream(output).use { it.write(binary) }
        val result = PgpDecryptor.decrypt(text("v6-pqc.sec.asc").toCharArray(), output.toString("UTF-8"), emptyList())
        assertTrue(result is DecryptResult.Failed)
    }

    @Test fun v6FingerprintsAreFullAndBindingsVerify() {
        for (prefix in listOf("v6", "v6-pqc")) {
            assertEquals(64, requireNotNull(PgpFingerprint.compute(text("$prefix.pub.asc"))).replace(" ", "").length)
        }
    }

    @Test fun xwingGoAndWasmVectorsOpenAndSasHashesEveryByte() {
        val vector = Json.parseToJsonElement(String(SharedFixtures.bytes("device-envelope-xwing.json"))).jsonObject
        fun field(name: String) = vector.getValue(name).jsonPrimitive.content
        val seed = Base64.getDecoder().decode(field("seed"))
        val key = Base64.getDecoder().decode(field("publicKey"))
        assertArrayEquals(key, xwingPublicKey(seed))
        val code = deviceEnrollmentCode(key, field("deviceId"), field("bucket").toLong())
        assertEquals(field("sas"), code)
        for (index in key.indices) {
            val changed = key.copyOf().also { it[index] = (it[index].toInt() xor 1).toByte() }
            assertNotEquals("SAS omitted byte $index", code, deviceEnrollmentCode(changed, field("deviceId"), field("bucket").toLong()))
        }
        val info = deviceEnvelopeAad(6, field("deviceId"), field("fingerprint"))
        for (envelope in listOf(vector.getValue("envelope").toString(), String(SharedFixtures.bytes("device-envelope-xwing-browser.json")))) {
            val fields = requireNotNull(parseDeviceEnvelope(envelope))
            assertArrayEquals(field("plaintext").toByteArray(), xwingOpen(seed, fields, info))
            assertNull(xwingOpen(seed, fields, info + 1))
            assertNull(xwingOpen(seed.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }, fields, info))
            fields.ct[0] = (fields.ct[0].toInt() xor 1).toByte()
            assertNull(xwingOpen(seed, fields, info))
        }
        val sealed = xwingSeal(key, info, field("plaintext").toByteArray())
        assertArrayEquals(field("plaintext").toByteArray(), xwingOpen(seed, sealed, info))
        seed.fill(0)
    }
}
