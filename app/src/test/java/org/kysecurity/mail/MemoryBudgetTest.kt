package org.kysecurity.mail

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The comment in [MemoryBudget] said the total "must fit a 128 MB heap" and nothing checked it,
 *  so it drifted the moment a term was added — and one term was never there at all. This is that
 *  sentence as a test: raise any constant past the ceiling and the build says so. */
class MemoryBudgetTest {

    @Test
    fun readScenarioLeavesFourMiBOfHeadroom() {
        assertTrue(
            "Reading peaks at ${MemoryBudget.READ_SCENARIO_PEAK_BYTES}; leave at least 4 MiB " +
                "below the ${MemoryBudget.ASSUMED_HEAP_BYTES} byte heap. Lower a ceiling, do not raise this.",
            MemoryBudget.READ_SCENARIO_PEAK_BYTES <= MemoryBudget.ASSUMED_HEAP_BYTES - 4L * 1024 * 1024,
        )
    }

    /** Sending does NOT fit today — see [MemoryBudget.SEND_SCENARIO_PEAK_BYTES], which says why and
     *  what the two fixes are. A ratchet rather than a pass/fail: the number may come down freely
     *  and cannot go up without someone editing the pin, which is the point. */
    @Test
    fun sendScenarioDoesNotGrow() {
        assertTrue(
            "Sending now peaks at ${MemoryBudget.SEND_SCENARIO_PEAK_BYTES}, above the pinned " +
                "${MemoryBudget.SEND_SCENARIO_RATCHET_BYTES}. This path is already over the heap " +
                "assumption; making it worse needs a deliberate decision, not a passing build.",
            MemoryBudget.SEND_SCENARIO_PEAK_BYTES <= MemoryBudget.SEND_SCENARIO_RATCHET_BYTES,
        )
    }

    /** The ratchet is only meaningful while it is snug. If a fix lands and this fails, lower
     *  [MemoryBudget.SEND_SCENARIO_RATCHET_BYTES] to the new value in the same commit. */
    @Test
    fun sendScenarioRatchetIsStillSnug() {
        val slack = MemoryBudget.SEND_SCENARIO_RATCHET_BYTES - MemoryBudget.SEND_SCENARIO_PEAK_BYTES
        assertTrue(
            "The send ratchet has ${slack / 1024 / 1024} MB of slack; re-pin it to the real value.",
            slack in 0..(2L * 1024 * 1024),
        )
    }

    /** Guards the omission itself, not just the arithmetic: a new retention that is bounded but
     *  never summed reintroduces exactly the bug this file exists to stop. */
    @Test
    fun readScenarioSumsEveryTerm() {
        assertEquals(
            MemoryBudget.PENDING_ATTACHMENT_BYTES +
                MemoryBudget.FORWARD_ATTACHMENT_PEAK_BYTES +
                MemoryBudget.LARGEST_READ_IN_FLIGHT_BYTES +
                MemoryBudget.PGP_PLAINTEXT_PEAK_BYTES +
                MemoryBudget.DECRYPTED_ATTACHMENT_BYTES +
                MemoryBudget.DECRYPTED_ATTACHMENT_DECODE_GROWTH_BYTES +
                MemoryBudget.DECRYPTED_SAVE_SNAPSHOT_BYTES +
                MemoryBudget.DECRYPTED_OPEN_SNAPSHOT_BYTES +
                MemoryBudget.INLINE_IMAGE_HTML_PEAK_BYTES,
            MemoryBudget.READ_SCENARIO_PEAK_BYTES,
        )
    }

    /** Twelve conservative base64/UTF-16 copies include retained variants and render scratch. */
    @Test
    fun inlineImageHtmlPeakCountsRetainedAndTransientCopies() {
        assertEquals(12L * 3L * MemoryBudget.INLINE_IMAGE_BYTES, MemoryBudget.INLINE_IMAGE_HTML_PEAK_BYTES)
    }

    /** The in-flight term takes a max over the three network paths. Naming one of them by hand is
     *  how a later cap increase stops being counted, so assert it really is the largest. */
    @Test
    fun largestInFlightTermCoversEveryNetworkPath() {
        listOf(
            MemoryBudget.ATTACHMENT_DOWNLOAD_BYTES,
            MemoryBudget.JSON_DECODED_PEAK_BYTES,
            MemoryBudget.PGP_PAYLOAD_DECODED_PEAK_BYTES,
        ).forEach {
            assertTrue(
                "$it is not covered by LARGEST_READ_IN_FLIGHT_BYTES=${MemoryBudget.LARGEST_READ_IN_FLIGHT_BYTES}",
                it <= MemoryBudget.LARGEST_READ_IN_FLIGHT_BYTES,
            )
        }
    }

    /** A wire cap is not a heap cap. Both JSON terms decode into `String` fields at two bytes per
     *  character, so the decoded term must exceed the transfer it came from. */
    @Test
    fun decodedTermsExceedTheirWireCaps() {
        assertTrue(MemoryBudget.JSON_DECODED_PEAK_BYTES > MemoryBudget.JSON_RESPONSE_BYTES)
        assertTrue(MemoryBudget.PGP_PAYLOAD_DECODED_PEAK_BYTES > MemoryBudget.PGP_PAYLOAD_BYTES)
    }

    /** Retention is 1x now that `OutgoingAttachment` holds decoded bytes rather than base64 in a
     *  `String`. If that ever regresses, the retained term has to grow with it. */
    @Test
    fun retainedForwardAttachmentsAreHeldDecoded() {
        assertEquals(MemoryBudget.FORWARD_ATTACHMENT_BYTES, MemoryBudget.FORWARD_ATTACHMENT_PEAK_BYTES)
    }

    /** The v3 import is its own term, beside the legacy one rather than replacing it, so legacy
     *  enrollment capacity cannot shrink by accident. Both fit the heap together. */
    @Test
    fun keyringImportCountsEveryTermAndFitsBesideLegacyEnrollment() {
        assertEquals(
            3L * MemoryBudget.PGP_DEVICE_ENVELOPE_V3_BYTES + 9L * MemoryBudget.PGP_KEYRING_JSON_BYTES,
            MemoryBudget.PGP_KEYRING_IMPORT_PEAK_BYTES.toLong(),
        )
        assertTrue(MemoryBudget.PGP_KEYRING_IMPORT_PEAK_BYTES + MemoryBudget.PGP_ENROLLMENT_PEAK_BYTES <= MemoryBudget.ASSUMED_HEAP_BYTES)
        assertEquals(128 * 1024, MemoryBudget.PGP_DEVICE_ENVELOPE_V3_BYTES)
        assertEquals(128 * 1024, MemoryBudget.PGP_KEYRING_JSON_BYTES)
        assertTrue(
            "a legacy envelope holding the largest admitted key must still parse",
            MemoryBudget.PGP_DEVICE_ENVELOPE_LEGACY_BYTES > (MemoryBudget.PGP_SECRET_KEY_INPUT_BYTES + 16) * 4 / 3,
        )
    }

    @Test
    fun enrollmentScenarioFitsTheAssumedHeapAndCountsEveryTerm() {
        assertEquals(
            3L * MemoryBudget.PGP_SECRET_KEY_INPUT_BYTES +
                6L * MemoryBudget.PGP_SECRET_KEY_PREVIOUS_INPUT_BYTES +
                2L * MemoryBudget.PGP_SECRET_KEY_OUTPUT_BYTES +
                MemoryBudget.PGP_SECRET_KEY_STREAM_BUFFER_BYTES,
            MemoryBudget.PGP_ENROLLMENT_PEAK_BYTES.toLong(),
        )
        assertTrue(MemoryBudget.PGP_ENROLLMENT_PEAK_BYTES <= MemoryBudget.ASSUMED_HEAP_BYTES)
        assertTrue(MemoryBudget.PGP_SECRET_KEY_PREVIOUS_INPUT_BYTES >= MemoryBudget.PGP_SECRET_KEY_OUTPUT_BYTES)
    }
}
