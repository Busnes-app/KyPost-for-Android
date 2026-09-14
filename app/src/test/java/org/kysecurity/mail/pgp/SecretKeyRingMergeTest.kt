package org.kysecurity.mail.pgp

import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.kysecurity.mail.MemoryBudget
import java.io.ByteArrayOutputStream

class SecretKeyRingMergeTest {
    private val current = TestPgpSecondKey.ARMORED_PRIVATE.toByteArray(Charsets.UTF_8)
    private val previous = TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray()

    @Test
    fun keepsCurrentFirstAndEveryPreviousRing() {
        val merged = mergeSecretKeyRings(current, previous)!!
        val fingerprints = rings(merged).map { it.publicKey.fingerprint }

        assertEquals(2, fingerprints.size)
        assertArrayEquals(rings(current).single().publicKey.fingerprint, fingerprints.first())
        assertArrayEquals(rings(previous.bytes()).single().publicKey.fingerprint, fingerprints.last())
    }

    @Test
    fun isIdempotent() {
        val once = mergeSecretKeyRings(current, previous)!!
        val twice = mergeSecretKeyRings(once, previous)!!

        assertEquals(rings(once).map(::keyFingerprints), rings(twice).map(::keyFingerprints))
    }

    @Test
    fun stillDecryptsMailToTheRetiredKey() {
        val result = PgpDecryptor.decrypt(
            mergeSecretKeyRings(current, previous)!!.chars(),
            TestPgpPrivateKey.ARMORED_MESSAGE,
            emptyList(),
        )

        assertTrue("expected Ok, got $result", result is DecryptResult.Ok)
        assertEquals(
            TestPgpPrivateKey.EXPECTED_PLAINTEXT,
            String((result as DecryptResult.Ok).plaintext, Charsets.UTF_8),
        )
    }

    @Test
    fun signsWithTheCurrentKey() {
        val merged = mergeSecretKeyRings(current, previous)!!.chars()
        val encrypted = PgpEncryptor.encrypt(
            "signed".toByteArray(),
            listOf(TestPgpSecondKey.ARMORED_PUBLIC),
            merged,
        ) as EncryptResult.Ok

        val againstCurrent = PgpDecryptor.decrypt(
            merged,
            encrypted.armored,
            listOf(TestPgpSecondKey.ARMORED_PUBLIC),
        ) as DecryptResult.Ok
        val againstPrevious = PgpDecryptor.decrypt(
            merged,
            encrypted.armored,
            listOf(TestPgpPrivateKey.ARMORED_PUBLIC),
        ) as DecryptResult.Ok

        assertTrue(againstCurrent.signature.valid)
        assertFalse(againstPrevious.signature.valid)
    }

    @Test
    fun derivesOwnPublicKeyFromTheCurrentRing() {
        val own = PgpEncryptor.ownPublicKey(mergeSecretKeyRings(current, previous)!!.chars())!!
        val fingerprint = PGPPublicKeyRingCollection(
            PGPUtil.getDecoderStream(own.byteInputStream()),
            BcKeyFingerprintCalculator(),
        ).keyRings.next().publicKey.fingerprint

        assertArrayEquals(rings(current).single().publicKey.fingerprint, fingerprint)
    }

    @Test
    fun samePrimaryKeepsHistoricalSubkeys() {
        val full = rings(TestPgpPrivateKey.ARMORED_PRIVATE.toByteArray()).single()
        val historicalSubkey = full.secretKeys.asSequence().drop(1).single()
        val withoutSubkey = PGPSecretKeyRing.removeSecretKey(full, historicalSubkey)

        val merged = mergeSecretKeyRings(armor(withoutSubkey), previous)!!

        assertEquals(keyFingerprints(full), keyFingerprints(rings(merged).single()))
    }

    @Test
    fun refusesConcatenatedOrTrailingArmoredMaterial() {
        val concatenated = TestPgpSecondKey.ARMORED_PRIVATE + "\n" + TestPgpPrivateKey.ARMORED_PRIVATE

        assertNull(mergeSecretKeyRings(current, concatenated.toCharArray()))
        assertNull(mergeSecretKeyRings(current, (TestPgpPrivateKey.ARMORED_PRIVATE + "\ninvalid").toCharArray()))
        assertNull(mergeSecretKeyRings(concatenated.toByteArray(), previous))
    }

    @Test
    fun refusesEveryEarlyDashTerminatorBeforeTheExpectedFooter() {
        listOf("", "  ", "\t", "\u000c", "\u000b").forEach { indent ->
            listOf("\n", "\r").forEach { newline ->
                val malformed = TestPgpPrivateKey.ARMORED_PRIVATE.replace(
                    "-----END PGP PRIVATE KEY BLOCK-----",
                    "$indent-early-end${newline}invalid unconsumed material$newline" +
                        "-----END PGP PRIVATE KEY BLOCK-----",
                )

                assertNull("previous: indent=${indent.length}, newline=${newline.codePointAt(0)}", mergeSecretKeyRings(current, malformed.toCharArray()))
                assertNull("current: indent=${indent.length}, newline=${newline.codePointAt(0)}", mergeSecretKeyRings(malformed.toByteArray(), previous))
            }
        }
    }

    @Test
    fun restoresUsableHistoricalSecretBehindAnEmptyCurrentStub() {
        val full = rings(TestPgpPrivateKey.ARMORED_PRIVATE.toByteArray()).single()
        val historicalSubkey = full.secretKeys.asSequence().drop(1).single()
        val currentPublic = historicalSubkey.publicKey
        val stub = PGPSecretKey(
            PGPPrivateKey(currentPublic.keyID, currentPublic.publicKeyPacket, null),
            currentPublic,
            null,
            false,
            null,
        )
        val currentWithStub = PGPSecretKeyRing.insertSecretKey(full, stub)

        val merged = mergeSecretKeyRings(armor(currentWithStub), previous)!!
        val restored = rings(merged).single().getSecretKey(currentPublic.fingerprint)
        val decrypted = PgpDecryptor.decrypt(merged.chars(), TestPgpPrivateKey.ARMORED_MESSAGE, emptyList())

        assertFalse(restored.isPrivateKeyEmpty)
        assertArrayEquals(currentPublic.encoded, restored.publicKey.encoded)
        assertTrue("expected old-key decrypt after restoration, got $decrypted", decrypted is DecryptResult.Ok)
        assertEquals(
            TestPgpPrivateKey.EXPECTED_PLAINTEXT,
            String((decrypted as DecryptResult.Ok).plaintext, Charsets.UTF_8),
        )
    }

    @Test
    fun rejectsInvalidOrEmptyMaterialWithoutFallback() {
        assertNull(mergeSecretKeyRings("garbage".toByteArray(), previous))
        assertNull(mergeSecretKeyRings(current, "garbage".toCharArray()))
        assertNull(mergeSecretKeyRings(ByteArray(0), previous))
        assertNull(mergeSecretKeyRings(current, CharArray(0)))
    }

    @Test
    fun rejectsInputsOverTheirCaps() {
        assertNull(mergeSecretKeyRings(ByteArray(MemoryBudget.PGP_SECRET_KEY_INPUT_BYTES + 1), previous))
        assertNull(mergeSecretKeyRings(current, CharArray(MemoryBudget.PGP_SECRET_KEY_PREVIOUS_INPUT_BYTES + 1) { 'a' }))
        assertNull(mergeSecretKeyRings(current, charArrayOf('\u0080')))
    }

    @Test
    fun rejectsTooManyRingsAndAnOversizedSerializedResult() {
        val ring = rings(current).single()

        assertNull(
            mergeParsedSecretKeyRings(
                List(MemoryBudget.PGP_SECRET_KEY_RING_COUNT + 1) { ring },
                listOf(ring),
            ),
        )
        assertNull(
            serializeSecretKeyRings(
                List(3 * MemoryBudget.PGP_SECRET_KEY_OUTPUT_BYTES / current.size + 2) { ring },
            ),
        )
    }

    private fun rings(armored: ByteArray) = orderedSecretKeyRings(armored.inputStream())!!

    private fun keyFingerprints(ring: PGPSecretKeyRing) =
        ring.secretKeys.asSequence().map { it.publicKey.fingerprint.toList() }.toList()

    private fun armor(ring: PGPSecretKeyRing): ByteArray = ByteArrayOutputStream().use { output ->
        ArmoredOutputStream(output).use { ring.encode(it) }
        output.toByteArray()
    }

    private fun CharArray.bytes() = concatToString().toByteArray(Charsets.UTF_8)

    private fun ByteArray.chars(): CharArray {
        val decoded = Charsets.UTF_8.decode(java.nio.ByteBuffer.wrap(this))
        return CharArray(decoded.remaining()).also { decoded.get(it) }
    }
}
