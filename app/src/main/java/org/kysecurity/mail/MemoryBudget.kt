package org.kysecurity.mail

/** Every ceiling on attacker-influenced heap, in one place; the sum is the number that matters.
 *
 *  A term belongs here if a remote party chooses its size. "The relay would never send that many"
 *  is not a ceiling — the relay is in this app's threat model everywhere else — and a budget that
 *  omits a term is worse than no budget, because the file reads as a completeness claim.
 *  `MemoryBudgetTest` asserts the total rather than leaving it to this comment.
 *
 *  Two rules learned the hard way, both of which had a term wrong by a factor of two or three:
 *   - a `String` costs TWO bytes per character on ART, which has no compact-string representation;
 *   - a bound on the wire is not a bound on the heap, because what is decoded from those bytes
 *     outlives them. Count the decoded form, not the transfer. */
internal object MemoryBudget {

    /** A JSON reply, on the wire. Every route uses this except the two named below, which raise it
     *  per-request via `BodyLimit`. It used to be one 32 MB constant covering attachment downloads
     *  too, so every small JSON endpoint inherited an attachment-sized ceiling. */
    const val JSON_RESPONSE_BYTES = 8L * 1024 * 1024

    /** What that JSON costs once decoded: the DTO graph is mostly `String` fields holding the same
     *  characters, at two bytes each. The intermediate `String` that `.string()` used to make on
     *  top of this is gone — see `executeDecoding`. */
    const val JSON_DECODED_PEAK_BYTES = 2L * JSON_RESPONSE_BYTES

    /** One attachment download. 1x since `readBounded` allocates the result once at the declared
     *  length and reads into it; it previously filled an okio Buffer and then copied that into a
     *  second array of the same size, so the true peak was double this and the budget said 32 MB. */
    const val ATTACHMENT_DOWNLOAD_BYTES = 25L * 1024 * 1024

    /** One armored OpenPGP payload, on the wire. Its own ceiling because base64 armor inside JSON
     *  is the one reply that legitimately dwarfs [JSON_RESPONSE_BYTES]. */
    const val PGP_PAYLOAD_BYTES = 12L * 1024 * 1024

    /** The armored ciphertext, decoded into a `String` field: two bytes per character. */
    const val PGP_PAYLOAD_DECODED_PEAK_BYTES = 2L * PGP_PAYLOAD_BYTES

    /** One decrypted OpenPGP message; bound by the relay's 25 MB cap (~18 MB decoded). */
    const val PGP_PLAINTEXT_BYTES = 24 * 1024 * 1024

    /** 1.5x: `readAllWithLimit` grows one array in place and holds the old and the new only during
     *  a doubling. It used to accumulate a chunk list and then join it into a full-size result,
     *  which held both in full — a guaranteed 2x on every message. */
    const val PGP_PLAINTEXT_PEAK_BYTES = 3L * PGP_PLAINTEXT_BYTES / 2L

    /** One armored secret-key collection admitted during enrollment. Secret keys are normally a
     *  few KiB; raise this only with a streaming parser/serializer upgrade. */
    const val PGP_SECRET_KEY_INPUT_BYTES = 256 * 1024

    /** A previously merged vault must remain admissible on the next rotation. */
    const val PGP_SECRET_KEY_PREVIOUS_INPUT_BYTES = 384 * 1024

    /** The accumulated armored collection after rotation. This is a refusal limit: historical
     *  keys are never dropped to fit it. */
    const val PGP_SECRET_KEY_OUTPUT_BYTES = 384 * 1024

    /** A collection may contain this many primary identities before enrollment refuses it. */
    const val PGP_SECRET_KEY_RING_COUNT = 32

    /** Wiped scratch used while a secret-key stream is copied into its bounded parser input. */
    const val PGP_SECRET_KEY_STREAM_BUFFER_BYTES = 8 * 1024

    /** Enrollment is separate from reading. At peak it holds both caller inputs, the UTF-8
     *  encoder's two temporary copies, parsed packet storage conservatively charged at both input
     *  caps, and the bounded output backing plus its final copy. */
    const val PGP_ENROLLMENT_PEAK_BYTES =
        3 * PGP_SECRET_KEY_INPUT_BYTES +
            2 * PGP_SECRET_KEY_PREVIOUS_INPUT_BYTES +
            2 * PGP_SECRET_KEY_PREVIOUS_INPUT_BYTES +
            2 * PGP_SECRET_KEY_PREVIOUS_INPUT_BYTES +
            2 * PGP_SECRET_KEY_OUTPUT_BYTES +
            PGP_SECRET_KEY_STREAM_BUFFER_BYTES

    /** Attachment parts kept out of one decrypted message, decoded, for the life of the detail
     *  screen. Bounded by [PgpMimeReader], which drops parts past this rather than truncating one. */
    const val DECRYPTED_ATTACHMENT_BYTES = 4L * 1024 * 1024

    /** `readAllWithLimit` can briefly hold old + doubled arrays while earlier parts remain kept. */
    const val DECRYPTED_ATTACHMENT_DECODE_GROWTH_BYTES = DECRYPTED_ATTACHMENT_BYTES / 2L

    /** One admitted Downloads save owns a copy while the retained source remains available. */
    const val DECRYPTED_SAVE_SNAPSHOT_BYTES = DECRYPTED_ATTACHMENT_BYTES

    /** Tap-to-open copies before provider admission, so even a rejected registration costs this. */
    const val DECRYPTED_OPEN_SNAPSHOT_BYTES = DECRYPTED_ATTACHMENT_BYTES

    /** The subset of those that are `cid:` images inlined into the rendered HTML. */
    const val INLINE_IMAGE_BYTES = 3L * 1024 * 1024

    /** What inlining costs: base64 (4/3) inside a UTF-16 String (2x) is 8/3; rounded up to 3x. */
    const val INLINE_IMAGE_HTML_PEAK_BYTES = 3L * INLINE_IMAGE_BYTES

    /** Decrypted attachments awaiting a viewer: retained until read or swept. */
    const val PENDING_ATTACHMENT_BYTES = 32L * 1024 * 1024

    /** Attachment bytes retained for Reply/Forward and in an interrupted compose draft.
     *
     *  1x since `OutgoingAttachment` holds decoded bytes; it used to hold base64 in a `String`,
     *  which cost ~2.67x this (4/3 for the encoding, 2x again for UTF-16) and was retained for the
     *  whole life of the screen. Nothing bounded it at all before that: the real limit was "as
     *  many attachments as the relay claims the message has", times 25 MB each, live at once in
     *  `EmailDetailActivity.downloadedAttachments`. */
    const val FORWARD_ATTACHMENT_BYTES = 12L * 1024 * 1024

    /** Retained as-is now that it is a `ByteArray`. Kept as its own name because the RETAINED and
     *  the PEAK cost of a term are different questions, and collapsing them is how the base64
     *  version went uncounted. */
    const val FORWARD_ATTACHMENT_PEAK_BYTES = FORWARD_ATTACHMENT_BYTES

    /** The total attachment payload one send may carry; `ComposeActivity` enforces it. */
    const val OUTBOUND_ATTACHMENT_BYTES = 25L * 1024 * 1024

    /** What building that request costs, as a multiple of the attachment bytes. At the peak, inside
     *  `Json.encodeToString`, three copies are live at once:
     *    1.00x  the retained decoded bytes, still held by the compose screen
     *    2.67x  base64 of them in the DTO (4/3 for the encoding, 2x again for UTF-16)
     *    2.67x  the request-body String being built around that
     *  = 19/3. */
    const val OUTBOUND_SEND_MULTIPLIER_NUMERATOR = 19L
    const val OUTBOUND_SEND_MULTIPLIER_DENOMINATOR = 3L

    /** The largest single INBOUND network operation. These are alternatives, not addends: one
     *  request is in flight per call, and taking the max rather than the sum is the one place this
     *  budget relies on an exclusivity argument — stated so it can be checked rather than assumed.
     *
     *  Computed, not named: raising any one of them has to move this on its own, or the next cap
     *  change quietly stops being counted. */
    val LARGEST_READ_IN_FLIGHT_BYTES = maxOf(
        ATTACHMENT_DOWNLOAD_BYTES,
        JSON_DECODED_PEAK_BYTES,
        PGP_PAYLOAD_DECODED_PEAK_BYTES,
    )

    /** Reading a message: everything retained across operations, plus one inbound request, plus a
     *  decrypt. All three can be live together on the message-detail screen. */
    val READ_SCENARIO_PEAK_BYTES =
        PENDING_ATTACHMENT_BYTES +
            FORWARD_ATTACHMENT_PEAK_BYTES +
            LARGEST_READ_IN_FLIGHT_BYTES +
            PGP_PLAINTEXT_PEAK_BYTES +
            DECRYPTED_ATTACHMENT_BYTES +
            DECRYPTED_ATTACHMENT_DECODE_GROWTH_BYTES +
            DECRYPTED_SAVE_SNAPSHOT_BYTES +
            DECRYPTED_OPEN_SNAPSHOT_BYTES +
            INLINE_IMAGE_HTML_PEAK_BYTES

    /** Sending a message. A different screen and a different operation from [READ_SCENARIO_PEAK_BYTES],
     *  so the two are alternatives rather than addends — summing every term in the app at once
     *  would be conservative to the point of being useless.
     *
     *  **This exceeds [ASSUMED_HEAP_BYTES] today, and always has.** The outbound path was simply
     *  never in this file; counting it is what made that visible. It is stated rather than
     *  asserted-away because the two ways to fix it are both decisions, not numbers:
     *   - lower [OUTBOUND_ATTACHMENT_BYTES], which is a visible capability cut (the relay itself
     *     accepts 25 MB, so the app would refuse what the server would take); or
     *   - write the request body to the socket rather than building it as a `String`
     *     (`Json.encodeToStream` into a custom `RequestBody`), the mirror of what
     *     `executeDecoding` already does for responses. That removes the 2.67x body term and
     *     brings this to ~92 MB — but a streamed body has no `Content-Length` and switches the
     *     request to chunked transfer encoding, which is a wire-format change that needs verifying
     *     against a real relay first.
     *
     *  `MemoryBudgetTest` ratchets it: it may not grow without a deliberate edit here. */
    val SEND_SCENARIO_PEAK_BYTES =
        OUTBOUND_ATTACHMENT_BYTES * OUTBOUND_SEND_MULTIPLIER_NUMERATOR / OUTBOUND_SEND_MULTIPLIER_DENOMINATOR

    /** Today's [SEND_SCENARIO_PEAK_BYTES], pinned so it can only ever come down. Lower it whenever
     *  the real number drops; raising it is the deliberate act this exists to make visible. */
    const val SEND_SCENARIO_RATCHET_BYTES = 159L * 1024 * 1024

    /** The smallest heap this app is expected to run in. Android guarantees a process far less
     *  than the device's RAM, and `largeHeap` is deliberately not set. */
    const val ASSUMED_HEAP_BYTES = 128L * 1024 * 1024
}
