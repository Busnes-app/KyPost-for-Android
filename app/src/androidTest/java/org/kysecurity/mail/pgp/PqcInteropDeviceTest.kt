package org.kysecurity.mail.pgp

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.Base64

/** The real Android runtime must agree with the JVM on BC's RFC 9980 and X-Wing paths. */
@RunWith(AndroidJUnit4::class)
class PqcInteropDeviceTest {
    private fun bytes(name: String) = requireNotNull(javaClass.classLoader!!.getResourceAsStream("kypost-server/pqc/$name")).use { it.readBytes() }
    private fun text(name: String) = String(bytes(name), Charsets.UTF_8)

    @Test fun rfc9980DecryptsAndVerifiesWithoutTheAndroidJceProvider() {
        val result = PgpDecryptor.decrypt(text("v6-pqc.sec.asc").toCharArray(), text("v6-pqc.msg.asc"), emptyList(), true)
        assertTrue("$result", result is DecryptResult.Ok)
        assertArrayEquals(bytes("message.txt"), (result as DecryptResult.Ok).plaintext)
        result.plaintext.fill(0)
        val key = text("v6-pqc.pub.asc")
        assertEquals(64, requireNotNull(PgpFingerprint.compute(key)).replace(" ", "").length)
        assertTrue(PgpDecryptor.verifyDetached(key, bytes("message.txt"), text("v6-pqc.sig.asc"), emptyList()).valid)
        assertFalse(PgpDecryptor.verifyDetached(key, bytes("message.txt") + 1, text("v6-pqc.sig.asc"), emptyList()).valid)
    }

    @Test fun xwingGoEnvelopeAndSasMatchOnAndroid() {
        val vector = Json.parseToJsonElement(text("device-envelope-xwing.json")).jsonObject
        fun field(name: String) = vector.getValue(name).jsonPrimitive.content
        val seed = Base64.getDecoder().decode(field("seed"))
        try {
            val publicKey = xwingPublicKey(seed)
            assertArrayEquals(Base64.getDecoder().decode(field("publicKey")), publicKey)
            assertEquals(field("sas"), deviceEnrollmentCode(publicKey, field("deviceId"), field("bucket").toLong()))
            val fields = requireNotNull(parseDeviceEnvelope(vector.getValue("envelope").toString()))
            assertArrayEquals(field("plaintext").toByteArray(), xwingOpen(seed, fields, deviceEnvelopeAad(6, field("deviceId"), field("fingerprint"))))
        } finally { seed.fill(0) }
    }
}
