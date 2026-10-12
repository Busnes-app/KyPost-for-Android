package org.kysecurity.mail.mail

import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RelayModelsSerializationTest {
    private val json = Json { ignoreUnknownKeys = true }

    @Test
    fun relayMailRequestDto_toCcBcc_serializeAsPlainStrings_notArrays() {
        val dto = RelayMailRequestDto(
            to = "a@example.com, b@example.com",
            cc = "c@example.com",
            subject = "Hi",
            body = "Body",
        )

        val encoded = json.encodeToString(dto)

        assertTrue(encoded.contains("\"to\":\"a@example.com, b@example.com\""))
        assertFalse(encoded.contains("\"to\":["))
        assertFalse(encoded.contains("\"cc\":["))
    }

    @Test
    fun relayInboxResponseDto_decodesByTabMap() {
        val jsonText = """
            {
              "tabs": ["Work", "Personal"],
              "byTab": {
                "Work": [{"messageId": "m1", "sender": "a@example.com", "subject": "S", "body": "B", "label": "Work", "status": "unread"}],
                "Personal": []
              }
            }
        """.trimIndent()

        val parsed = json.decodeFromString<RelayInboxResponseDto>(jsonText)

        assertEquals(listOf("Work", "Personal"), parsed.tabs)
        assertEquals(1, parsed.byTab["Work"]?.size)
        assertEquals("m1", parsed.byTab["Work"]?.first()?.messageId)
        assertFalse(parsed.delta)
        assertEquals("", parsed.cursor)
        assertTrue(parsed.removed.isEmpty())
    }

    @Test
    fun relayInboxResponseDto_decodesKeywordsArray() {
        val jsonText = """
            {
              "tabs": ["Work"],
              "byTab": {
                "Work": [{"messageId": "m1", "sender": "a@example.com", "subject": "S", "label": "Work",
                          "keywords": ["Work", "${'$'}Phishing"], "status": "unread"}]
              }
            }
        """.trimIndent()

        val parsed = json.decodeFromString<RelayInboxResponseDto>(jsonText)

        assertEquals(listOf("Work", "${'$'}Phishing"), parsed.byTab["Work"]?.first()?.keywords)
    }

    @Test
    // omitempty server-side, so an absent key must decode to an empty list
    // rather than failing the whole response.
    fun relayInboxResponseDto_absentKeywordsDecodesEmpty() {
        val jsonText = """
            {"tabs": ["Work"], "byTab": {"Work": [{"messageId": "m1", "subject": "S", "status": "unread"}]}}
        """.trimIndent()

        val parsed = json.decodeFromString<RelayInboxResponseDto>(jsonText)

        assertTrue(parsed.byTab["Work"]?.first()?.keywords?.isEmpty() == true)
    }

    /** An older server never sends `wokenAt`; absent must decode to null, not fail the response. */
    @Test
    fun relayInboxResponseDto_decodesWokenAtWhenPresentAndNullWhenAbsent() {
        val jsonText = """
            {"tabs": ["Work"], "byTab": {"Work": [
              {"messageId": "m1", "subject": "S", "atUtc": "2026-10-01T08:00:00Z", "wokenAt": "2026-10-12T09:00:00Z"},
              {"messageId": "m2", "subject": "S", "atUtc": "2026-10-02T08:00:00Z"}
            ]}}
        """.trimIndent()

        val rows = json.decodeFromString<RelayInboxResponseDto>(jsonText).byTab.getValue("Work")

        assertEquals("2026-10-12T09:00:00Z", rows[0].wokenAt)
        assertEquals("2026-10-01T08:00:00Z", rows[0].atUtc)
        assertEquals(null, rows[1].wokenAt)
    }

    @Test
    fun relayInboxResponseDto_decodesDeltaShape_newUpdatedAndRemoved() {
        val jsonText = """
            {
              "tabs": ["Work"],
              "byTab": {
                "Work": [
                  {"messageId": "m1", "sender": "a@example.com", "subject": "New", "body": "Full body", "label": "Work", "status": "unread", "changeType": "new"},
                  {"messageId": "m2", "sender": "b@example.com", "subject": "Updated", "label": "Work", "status": "read", "changeType": "updated"}
                ]
              },
              "cursor": "cursor-123",
              "delta": true,
              "removed": ["m3"]
            }
        """.trimIndent()

        val parsed = json.decodeFromString<RelayInboxResponseDto>(jsonText)

        assertTrue(parsed.delta)
        assertEquals("cursor-123", parsed.cursor)
        assertEquals(listOf("m3"), parsed.removed)
        val messages = parsed.byTab.getValue("Work")
        assertEquals("new", messages[0].changeType)
        assertEquals("Full body", messages[0].body)
        assertEquals("updated", messages[1].changeType)
        assertEquals(null, messages[1].body)
    }

    @Test
    fun relayInboxResponseDto_decodesNumericCursor_asString() {
        val jsonText = """{"tabs": [], "byTab": {}, "cursor": 12345, "delta": true, "removed": []}"""

        val parsed = json.decodeFromString<RelayInboxResponseDto>(jsonText)

        assertEquals("12345", parsed.cursor)
    }
}
