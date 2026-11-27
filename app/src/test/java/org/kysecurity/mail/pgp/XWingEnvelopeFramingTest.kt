package org.kysecurity.mail.pgp

import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test
import java.util.Base64

class XWingEnvelopeFramingTest {
    private val vector = Json.parseToJsonElement(String(SharedFixtures.bytes("device-envelope-xwing.json"))).jsonObject
    private val envelope = vector.getValue("envelope").jsonObject
    private fun changed(name: String, value: JsonElement) = JsonObject(envelope + (name to value)).toString()

    @Test fun exactVersionSuiteAndEncLengthAreMandatory() {
        assertNotNull(parseDeviceEnvelope(envelope.toString()))
        for (version in listOf(JsonPrimitive("6"), JsonPrimitive(6.0), JsonPrimitive(5), JsonPrimitive(7))) {
            assertNull(parseDeviceEnvelope(changed("v", version)))
        }
        for (length in listOf(65, 1119, 1121)) {
            assertNull(parseDeviceEnvelope(changed("enc", JsonPrimitive(Base64.getEncoder().encodeToString(ByteArray(length))))))
        }
        assertNull(parseDeviceEnvelope(changed("alg", JsonPrimitive("HPKE-Base-P256-SHA256-A256GCM"))))
        assertNull(parseDeviceEnvelope(JsonObject(envelope + ("extra" to JsonPrimitive(true))).toString()))
        assertNull(parseDeviceEnvelope(envelope.toString().replace("\"v\":6", "\"v\":6,\"v\":6")))
        assertNull(parseDeviceEnvelope(changed("enc", JsonPrimitive(envelope.getValue("enc").jsonPrimitive.content.trimEnd('=')))))
        assertNull(parseDeviceEnvelope(changed("ct", JsonPrimitive(Base64.getEncoder().encodeToString(ByteArray(15))))))
        assertNotNull(parseDeviceEnvelope(changed("ct", JsonPrimitive(Base64.getEncoder().encodeToString(ByteArray(16))))))
    }

    @Test fun v6SerializationCapIsInBytesAndNoTrailingPayloadIsAccepted() {
        val json = envelope.toString()
        val cap = org.kysecurity.mail.MemoryBudget.PGP_DEVICE_ENVELOPE_V6_BYTES
        val atCap = json.dropLast(1) + " ".repeat(cap - json.length) + "}"
        assertNotNull(parseDeviceEnvelope(atCap))
        assertNull(parseDeviceEnvelope("$atCap "))
        assertNull(parseDeviceEnvelope("$json {}"))
    }
}
