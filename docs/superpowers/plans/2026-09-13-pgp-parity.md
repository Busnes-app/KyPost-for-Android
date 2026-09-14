# Android PGP Parity With the Server Punch List — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring the Android client level with the six server-side PGP changes: attachments inside the ciphertext, encrypted drafts, signed-only mail, the inbox cache change, key retirement, and the new resolver tiers.

**Architecture:** Every unit that touches decrypted bytes stays pure JVM under `app/src/main/java/org/kysecurity/mail/pgp/` and is tested without Android. `PgpMimeReader` grows attachment parts behind hard caps; `EmailDetailActivity` hands those parts to the existing `EphemeralAttachmentBytes` provider and inlines `cid:` images as `data:` URIs before the existing sanitiser. Key retirement is handled by merging the previous secret key ring into the new envelope at re-enrolment, so the vault stays one blob and `PgpDecryptor`'s existing key-ID selection does the rest. Tiers and signer sources are already plain strings; the work there is tests that prove it.

**Tech Stack:** Kotlin/Android, BouncyCastle `bcpg-jdk18on`, `org.eclipse.angus:jakarta.mail`, jsoup, OkHttp, kotlinx.serialization, JUnit4. No mocking framework; hand-written fakes.

**Spec:** myslop board folder `kypost-android-pgp-parity` (post 592 by linnet, 2026-09-13). Server-side order and reasons: `kypost-server/docs/superpowers/plans/2026-09-13-pgp-punch-list.md`. Durable copy of the client contract: `kypost-server/docs/superpowers/handoffs/2026-09-13-pgp-native-client-handoffs.md`.

## Global Constraints

- **The decrypted body and decrypted attachments never reach Room, `fetchedBodyHtml`, or `downloadedAttachments`.** The last one feeds Forward, and Forward is blocked for `CLIENT_PROTECTED` by `mayReplyOrForward` (`EmailDetailActivity.kt:1348`). Keep it that way.
- **Every new class holding decrypted bytes is a plain class, not a data class, and overrides `toString()` to redact.** `SourceRulesTest` enforces both (`SENSITIVE_PROPERTY_NAMES` at `SourceRulesTest.kt:262`).
- **Files under `pgp/` that decrypt or parse have zero Android imports.** `java.util.Base64`, never `android.util.Base64`. Bc* operators, never Jce*.
- **Every attacker-sized allocation has a ceiling in `MemoryBudget`, and `MemoryBudgetTest.readScenarioSumsEveryTerm` must be updated in the same commit** that adds a term. `READ_SCENARIO_PEAK_BYTES` must stay ≤ `ASSUMED_HEAP_BYTES` (128 MiB). Today it is 105 MiB.
- **Release gate after every task that touches jakarta.mail.** The R8 incident (`docs/superpowers/plans/2026-08-24-android-encrypted-read-incident.md`) is why. Find the exact task name once with `./gradlew :app:tasks --all | grep checkRuntimeMatchedClassNames` (flavors are `play`, `github`, `fdroid`, so it is `checkRuntimeMatchedClassNames<Flavor>Release`), then run it. Green output prints nothing; red names the class.
- **`isReturnDefaultValues = true` is set project-wide.** Every new test is proven by deliberate break: invert the assertion, watch it fail, restore it.
- **Top-level test fakes are `internal`, never `private`.**
- **Tests:** `./gradlew :app:testFdroidDebugUnitTest --tests "<pattern>"`. Full suite before any PR: `./gradlew :app:testFdroidDebugUnitTest lintFdroidDebug`.
- **Commit per task, on a branch off `main`.** Suggested branch: `feature/pgp-parity`.

---

## File Structure

| File | Responsibility |
|---|---|
| `app/src/main/java/org/kysecurity/mail/MemoryBudget.kt` | Modify: add `DECRYPTED_ATTACHMENT_BYTES`, `INLINE_IMAGE_BYTES`, `INLINE_IMAGE_HTML_PEAK_BYTES`; sum them into `READ_SCENARIO_PEAK_BYTES` |
| `app/src/main/java/org/kysecurity/mail/pgp/PgpMimeReader.kt` | Modify: `DecryptedAttachment` class; `DecryptedBody.attachments` + `attachmentsOmitted`; walk collects attachment parts under caps |
| `app/src/main/java/org/kysecurity/mail/pgp/InlineImages.kt` | Create: `inlineCidImages(html, attachments)` — pure jsoup rewrite of `cid:` to `data:` |
| `app/src/main/java/org/kysecurity/mail/EmailDetailActivity.kt` | Modify: `blockExternalResources` keeps `data:image/*` on `img`; Decrypted branch inlines images and renders decrypted attachment chips; zeroing on lock/destroy |
| `app/src/main/java/org/kysecurity/mail/pgp/PgpMessageState.kt` | Modify: `PgpSignatureState.UNSIGNED` |
| `app/src/main/java/org/kysecurity/mail/pgp/EncryptedMessageReader.kt` | Modify: encrypted-and-unsigned maps to `UNSIGNED` |
| `app/src/main/java/org/kysecurity/mail/pgp/SecretKeyRingMerge.kt` | Create: `mergeSecretKeyRings(current, previous)` |
| `app/src/main/java/org/kysecurity/mail/pgp/EnrollmentCeremony.kt` | Modify: open the previous vault, merge before seal, clear `EnrollmentSession` after seal |
| `app/src/main/java/org/kysecurity/mail/pgp/DeviceEnrollmentViewModel.kt` (or wherever the ceremony is constructed) | Modify: pass `AndroidVaultOpener` as `previousVault` |
| `app/src/main/res/values/strings.xml` | Modify: three strings |
| Tests | `PgpMimeReaderTest`, `InlineImagesTest` (new), `EmailDetailActivityTest`, `MemoryBudgetTest`, `PgpMessageStateTest`, `EncryptedMessageReaderTest`, `SecretKeyRingMergeTest` (new), `EnrollmentCeremony*Test`, `RecipientResolveClientTest`, `PgpPayloadClientTest`, `RelayMailSourceTest` |

---

## Tier 1 — Attachments inside the ciphertext

### Task 1: Budget the new retention

**Files:**
- Modify: `app/src/main/java/org/kysecurity/mail/MemoryBudget.kt`
- Test: `app/src/test/java/org/kysecurity/mail/MemoryBudgetTest.kt`

**Interfaces:**
- Produces: `MemoryBudget.DECRYPTED_ATTACHMENT_BYTES: Long` (8 MiB), `MemoryBudget.INLINE_IMAGE_BYTES: Long` (3 MiB), `MemoryBudget.INLINE_IMAGE_HTML_PEAK_BYTES: Long` (3× the previous).

- [ ] **Step 1: Write the failing test**

In `MemoryBudgetTest.readScenarioSumsEveryTerm`, extend the expected sum:

```kotlin
    @Test
    fun readScenarioSumsEveryTerm() {
        assertEquals(
            MemoryBudget.PENDING_ATTACHMENT_BYTES +
                MemoryBudget.FORWARD_ATTACHMENT_PEAK_BYTES +
                MemoryBudget.LARGEST_READ_IN_FLIGHT_BYTES +
                MemoryBudget.PGP_PLAINTEXT_PEAK_BYTES +
                MemoryBudget.DECRYPTED_ATTACHMENT_BYTES +
                MemoryBudget.INLINE_IMAGE_HTML_PEAK_BYTES,
            MemoryBudget.READ_SCENARIO_PEAK_BYTES,
        )
    }

    /** Base64 in a UTF-16 String is 8/3 of the bytes; 3x is the round-up the budget carries. */
    @Test
    fun inlineImageHtmlPeakIsThreeTimesTheInlineBytes() {
        assertEquals(3L * MemoryBudget.INLINE_IMAGE_BYTES, MemoryBudget.INLINE_IMAGE_HTML_PEAK_BYTES)
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `./gradlew :app:testFdroidDebugUnitTest --tests "org.kysecurity.mail.MemoryBudgetTest"`
Expected: compile failure, unresolved `DECRYPTED_ATTACHMENT_BYTES`.

- [ ] **Step 3: Add the terms**

In `MemoryBudget.kt`, after `PGP_PLAINTEXT_PEAK_BYTES`:

```kotlin
    /** Attachment parts kept out of one decrypted message, decoded, for the life of the detail
     *  screen. Bounded by [PgpMimeReader], which drops parts past this rather than truncating one. */
    const val DECRYPTED_ATTACHMENT_BYTES = 8L * 1024 * 1024

    /** The subset of those that are `cid:` images inlined into the rendered HTML. */
    const val INLINE_IMAGE_BYTES = 3L * 1024 * 1024

    /** What inlining costs: base64 (4/3) inside a UTF-16 String (2x) is 8/3; rounded up to 3x. */
    const val INLINE_IMAGE_HTML_PEAK_BYTES = 3L * INLINE_IMAGE_BYTES
```

And extend `READ_SCENARIO_PEAK_BYTES`:

```kotlin
    val READ_SCENARIO_PEAK_BYTES =
        PENDING_ATTACHMENT_BYTES +
            FORWARD_ATTACHMENT_PEAK_BYTES +
            LARGEST_READ_IN_FLIGHT_BYTES +
            PGP_PLAINTEXT_PEAK_BYTES +
            DECRYPTED_ATTACHMENT_BYTES +
            INLINE_IMAGE_HTML_PEAK_BYTES
```

- [ ] **Step 4: Run to verify it passes**

Run: `./gradlew :app:testFdroidDebugUnitTest --tests "org.kysecurity.mail.MemoryBudgetTest"`
Expected: PASS. The heap test still passes: 105 + 8 + 9 = 122 MiB ≤ 128 MiB. If it fails, the numbers above are wrong; lower `DECRYPTED_ATTACHMENT_BYTES`, do not raise `ASSUMED_HEAP_BYTES`.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/org/kysecurity/mail/MemoryBudget.kt app/src/test/java/org/kysecurity/mail/MemoryBudgetTest.kt
git commit -m "budget: count decrypted attachments and inlined images"
```

### Task 2: `PgpMimeReader` returns attachment parts under caps

**Files:**
- Modify: `app/src/main/java/org/kysecurity/mail/pgp/PgpMimeReader.kt`
- Test: `app/src/test/java/org/kysecurity/mail/pgp/PgpMimeReaderTest.kt`

**Interfaces:**
- Consumes: `MemoryBudget.DECRYPTED_ATTACHMENT_BYTES`, `PgpDecryptor.readAllWithLimit(InputStream, Int): ByteArray?` (already `internal`, `PgpDecryptor.kt:194`).
- Produces:
  ```kotlin
  internal class DecryptedAttachment(val name: String, val mimeType: String, val bytes: ByteArray, val contentId: String?)
  // DecryptedBody gains:
  val attachments: List<DecryptedAttachment> = emptyList()
  val attachmentsOmitted: Boolean = false
  ```

- [ ] **Step 1: Write the failing tests**

Append to `PgpMimeReaderTest`:

```kotlin
    private val pngBase64 = java.util.Base64.getEncoder().encodeToString(byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47))

    @Test
    fun collectsAnAttachmentPartBesideTheBody() {
        val body = read(
            """
            Content-Type: multipart/mixed; boundary="b1"

            --b1
            Content-Type: text/plain; charset=utf-8

            see attached
            --b1
            Content-Type: application/pdf; name="report.pdf"
            Content-Disposition: attachment; filename="report.pdf"
            Content-Transfer-Encoding: base64

            JVBERi0xLjQK
            --b1--
            """.trimIndent(),
        )

        assertEquals("see attached", body?.plain?.trim())
        val attachment = body!!.attachments.single()
        assertEquals("report.pdf", attachment.name)
        assertEquals("application/pdf", attachment.mimeType)
        assertEquals("%PDF-1.4\n", String(attachment.bytes, Charsets.ISO_8859_1))
        assertNull(attachment.contentId)
        assertTrue(!body.attachmentsOmitted)
    }

    @Test
    fun aTextPartWithAnAttachmentDispositionIsAnAttachmentNotTheBody() {
        val body = read(
            """
            Content-Type: multipart/mixed; boundary="b1"

            --b1
            Content-Type: text/plain; charset=utf-8

            the body
            --b1
            Content-Type: text/plain; charset=utf-8; name="notes.txt"
            Content-Disposition: attachment; filename="notes.txt"

            not the body
            --b1--
            """.trimIndent(),
        )

        assertEquals("the body", body?.plain?.trim())
        assertEquals("notes.txt", body?.attachments?.single()?.name)
    }

    @Test
    fun anInlineImageCarriesItsContentIdWithoutTheAngleBrackets() {
        val body = read(
            """
            Content-Type: multipart/related; boundary="b1"

            --b1
            Content-Type: text/html; charset=utf-8

            <img src="cid:logo@kypost">
            --b1
            Content-Type: image/png; name="logo.png"
            Content-Disposition: inline; filename="logo.png"
            Content-ID: <logo@kypost>
            Content-Transfer-Encoding: base64

            $pngBase64
            --b1--
            """.trimIndent(),
        )

        assertEquals("logo@kypost", body?.attachments?.single()?.contentId)
        assertEquals("image/png", body?.attachments?.single()?.mimeType)
    }

    @Test
    fun attachmentsPastTheByteCapAreDroppedWholeAndReported() {
        val big = "A".repeat(PgpMimeReader.attachmentByteCap.toInt() + 1)
        val body = read(
            """
            Content-Type: multipart/mixed; boundary="b1"

            --b1
            Content-Type: text/plain; charset=utf-8

            body
            --b1
            Content-Type: application/octet-stream; name="huge.bin"
            Content-Disposition: attachment; filename="huge.bin"

            $big
            --b1
            Content-Type: application/octet-stream; name="small.bin"
            Content-Disposition: attachment; filename="small.bin"

            tiny
            --b1--
            """.trimIndent(),
        )

        // The oversize part is gone entirely: a truncated file is worse than a missing one.
        assertEquals(listOf("small.bin"), body?.attachments?.map { it.name })
        assertTrue("the reader must say a part was dropped", body!!.attachmentsOmitted)
    }

    @Test
    fun attachmentsPastThePartCapAreDroppedAndReported() {
        val parts = (1..PgpMimeReader.MAX_ATTACHMENT_PARTS + 1).joinToString("\n") { i ->
            """
            --b1
            Content-Type: application/octet-stream; name="f$i.bin"
            Content-Disposition: attachment; filename="f$i.bin"

            x
            """.trimIndent()
        }
        val body = read("Content-Type: multipart/mixed; boundary=\"b1\"\n\n$parts\n--b1--")

        assertEquals(PgpMimeReader.MAX_ATTACHMENT_PARTS, body?.attachments?.size)
        assertTrue(body!!.attachmentsOmitted)
    }

    @Test
    fun anAttachmentOnlyMessageStillReadsAsAMessage() {
        // No body part at all. Today read() returns null when html and plain are both null; an
        // attachment is content, so it must not.
        val body = read(
            """
            Content-Type: multipart/mixed; boundary="b1"

            --b1
            Content-Type: application/pdf; name="only.pdf"
            Content-Disposition: attachment; filename="only.pdf"

            x
            --b1--
            """.trimIndent(),
        )

        assertEquals("only.pdf", body?.attachments?.single()?.name)
        assertEquals("plain", body?.bodyMode)
        assertEquals("", body?.plain)
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `./gradlew :app:testFdroidDebugUnitTest --tests "org.kysecurity.mail.pgp.PgpMimeReaderTest"`
Expected: compile failure on `attachments`, `attachmentsOmitted`, `attachmentByteCap`, `MAX_ATTACHMENT_PARTS`.

- [ ] **Step 3: Implement**

Replace `PgpMimeReader.kt` wholesale with:

```kotlin
package org.kysecurity.mail.pgp

import jakarta.mail.Part
import jakarta.mail.Session
import jakarta.mail.internet.MimeMessage
import jakarta.mail.internet.MimeMultipart
import java.io.ByteArrayInputStream
import java.util.Properties

/** One attachment part out of a decrypted message. Not a data class: identity equals over [bytes],
 *  and [toString] is redacted. Enforced by `SourceRulesTest`. */
internal class DecryptedAttachment(
    val name: String,
    val mimeType: String,
    val bytes: ByteArray,
    /** The `Content-ID` without its angle brackets, for `cid:` references in the html part. */
    val contentId: String?,
) {
    override fun toString(): String = "DecryptedAttachment(redacted)"
}

/** Both kept: a message with only a plain part must not render as an empty page. */
internal data class DecryptedBody(
    val html: String?,
    val plain: String?,
    /** MIME mode paired with the selected body; never infer this from its characters. */
    val bodyMode: String = "",
    /** The real subject from the encrypted part's protected headers, when the sender used them.
     *  The outer envelope subject is a placeholder for KyPost-to-KyPost mail. */
    val protectedSubject: String?,
    val attachments: List<DecryptedAttachment> = emptyList(),
    /** True when a part was dropped for size or count. The screen says so; silence would show a
     *  message that appears to have fewer files than it does. */
    val attachmentsOmitted: Boolean = false,
) {
    /** Redacted: every field is a decrypted message. Enforced by `SourceRulesTest`. */
    override fun toString(): String = "DecryptedBody(redacted)"
}

/** Returns null rather than throwing; unparsed bytes never reach a WebView. */
internal object PgpMimeReader {

    /** A sender chooses the part count; fifty is past any real message and cheap to hold. */
    const val MAX_ATTACHMENT_PARTS = 50

    /** Total decoded attachment bytes retained from one message. */
    val attachmentByteCap: Long = org.kysecurity.mail.MemoryBudget.DECRYPTED_ATTACHMENT_BYTES

    fun read(mime: ByteArray): DecryptedBody? = runCatching {
        val session = Session.getInstance(Properties())
        val message = MimeMessage(session, ByteArrayInputStream(mime))

        var html: String? = null
        var plain: String? = null
        val attachments = ArrayList<DecryptedAttachment>()
        var omitted = false
        var retained = 0L

        fun collect(part: Part) {
            if (attachments.size >= MAX_ATTACHMENT_PARTS) { omitted = true; return }
            val remaining = (attachmentByteCap - retained).coerceAtLeast(0L)
            // Bounded read; null means the part alone would cross the ceiling, and it is dropped
            // whole rather than truncated. A partial file is worse than a missing one.
            val bytes = runCatching {
                PgpDecryptor.readAllWithLimit(part.inputStream, remaining.coerceAtMost(Int.MAX_VALUE.toLong()).toInt())
            }.getOrNull()
            if (bytes == null) { omitted = true; return }
            retained += bytes.size
            val name = runCatching { part.fileName }.getOrNull()?.takeIf { it.isNotBlank() } ?: "attachment"
            val mimeType = runCatching { part.contentType }.getOrNull()
                ?.substringBefore(';')?.trim()?.lowercase()?.takeIf { it.isNotBlank() }
                ?: "application/octet-stream"
            val contentId = runCatching { part.getHeader("Content-ID") }.getOrNull()
                ?.firstOrNull()?.trim()?.removePrefix("<")?.removeSuffix(">")?.takeIf { it.isNotBlank() }
            attachments += DecryptedAttachment(name, mimeType, bytes, contentId)
        }

        /** Disposition first: a `text/plain` part named `notes.txt` is a file, not the body. */
        fun isAttachment(part: Part): Boolean {
            val disposition = runCatching { part.disposition }.getOrNull()?.lowercase()
            if (disposition == Part.ATTACHMENT) return true
            if (part.isMimeType("multipart/*")) return false
            val hasName = runCatching { part.fileName }.getOrNull()?.isNotBlank() == true
            val hasContentId = runCatching { part.getHeader("Content-ID") }.getOrNull()?.isNotEmpty() == true
            return hasName || hasContentId || !(part.isMimeType("text/html") || part.isMimeType("text/plain"))
        }

        fun walk(content: Any?) {
            if (content !is MimeMultipart) return
            for (i in 0 until content.count) {
                val part = content.getBodyPart(i)
                if (isAttachment(part)) { collect(part); continue }
                val body = runCatching { part.content }.getOrNull()
                when {
                    part.isMimeType("text/html") -> {
                        val s = body as? String
                        // A blank part is real content, but a later non-blank sibling must win.
                        if (s != null && (html == null || html!!.isBlank())) html = s
                    }
                    part.isMimeType("text/plain") -> {
                        val s = body as? String
                        if (s != null && (plain == null || plain!!.isBlank())) plain = s
                    }
                    body is MimeMultipart -> walk(body)
                }
            }
        }

        val hadContentTypeHeader = message.getHeader("Content-Type", null) != null
        val content = message.content
        when {
            message.isMimeType("text/html") -> html = (content as? String)
                ?.let { if (hadContentTypeHeader) it else it.takeIf(String::isNotBlank) }
            message.isMimeType("text/plain") -> plain = (content as? String)
                ?.let { if (hadContentTypeHeader) it else it.takeIf(String::isNotBlank) }
            else -> walk(content)
        }

        // An attachment is content: a files-only message renders an empty body and its chips.
        if (html == null && plain == null) {
            if (attachments.isEmpty()) return null
            plain = ""
        }
        DecryptedBody(
            html = html,
            plain = plain,
            bodyMode = if (html != null) "html" else "plain",
            protectedSubject = message.subject?.takeIf { it.isNotBlank() },
            attachments = attachments,
            attachmentsOmitted = omitted,
        )
    }.getOrNull()
}
```

Note `isAttachment` treats a non-text, non-multipart leaf (e.g. `application/pgp-keys` without a filename) as an attachment. That is deliberate: before this change such a part was silently dropped.

- [ ] **Step 4: Run to verify they pass, and that the existing reader tests still pass**

Run: `./gradlew :app:testFdroidDebugUnitTest --tests "org.kysecurity.mail.pgp.PgpMimeReaderTest" --tests "org.kysecurity.mail.pgp.EncryptedMessageReaderTest" --tests "org.kysecurity.mail.SourceRulesTest"`
Expected: PASS. If `SourceRulesTest` names `DecryptedAttachment`, it is because `bytes` was added to `SENSITIVE_PROPERTY_NAMES`; the class already overrides `toString`, so fix the test's expectation, not the class.

- [ ] **Step 5: Prove the byte-cap test by deliberate break**

Change `if (bytes == null) { omitted = true; return }` to `if (bytes == null) return`, run `PgpMimeReaderTest`, confirm `attachmentsPastTheByteCapAreDroppedWholeAndReported` fails, restore.

- [ ] **Step 6: Release gate**

Run: `./gradlew :app:tasks --all | grep checkRuntimeMatchedClassNames` then the `...Release` task it prints for one flavor, e.g. `./gradlew :app:checkRuntimeMatchedClassNamesFdroidRelease`.
Expected: BUILD SUCCESSFUL, no class named. `part.inputStream` reaches the base64/quoted-printable decoders through bytecode, not mailcap, so no new keep rule is expected. If the gate goes red, add the named class to both `runtimeMatchedClassNames` and `proguard-rules.pro` and update `MimeContentHandlersTest.kept`.

- [ ] **Step 7: Commit**

```bash
git add app/src/main/java/org/kysecurity/mail/pgp/PgpMimeReader.kt app/src/test/java/org/kysecurity/mail/pgp/PgpMimeReaderTest.kt
git commit -m "pgp: return attachment parts from the decrypted MIME under a byte and part cap"
```

### Task 3: Inline `cid:` images as `data:` URIs

**Files:**
- Create: `app/src/main/java/org/kysecurity/mail/pgp/InlineImages.kt`
- Modify: `app/src/main/java/org/kysecurity/mail/EmailDetailActivity.kt:1177-1183` (`blockExternalResources`)
- Test: `app/src/test/java/org/kysecurity/mail/pgp/InlineImagesTest.kt` (new), `app/src/test/java/org/kysecurity/mail/EmailDetailActivityTest.kt`

**Interfaces:**
- Consumes: `DecryptedAttachment` from Task 2; `MemoryBudget.INLINE_IMAGE_BYTES`.
- Produces: `internal fun inlineCidImages(html: String, attachments: List<DecryptedAttachment>): String`.

- [ ] **Step 1: Write the failing tests**

`InlineImagesTest.kt`:

```kotlin
package org.kysecurity.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class InlineImagesTest {

    private val png = byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47)
    private fun logo(id: String = "logo@kypost", type: String = "image/png", bytes: ByteArray = png) =
        DecryptedAttachment("logo.png", type, bytes, id)

    @Test
    fun rewritesAMatchingCidToADataUri() {
        val out = inlineCidImages("""<p>hi</p><img src="cid:logo@kypost">""", listOf(logo()))

        assertTrue(out, out.contains("src=\"data:image/png;base64,iVBORw==\""))
        assertTrue(out, !out.contains("cid:"))
    }

    @Test
    fun matchesCaseInsensitivelyOnTheSchemeOnly() {
        val out = inlineCidImages("""<img src="CID:logo@kypost">""", listOf(logo()))
        assertTrue(out, out.contains("data:image/png;base64,"))

        val miss = inlineCidImages("""<img src="cid:LOGO@kypost">""", listOf(logo()))
        assertTrue("Content-ID is case-sensitive", miss.contains("cid:LOGO@kypost"))
    }

    @Test
    fun leavesAnUnresolvedCidForTheSanitiserToStrip() {
        val out = inlineCidImages("""<img src="cid:missing">""", listOf(logo()))
        assertTrue(out, out.contains("cid:missing"))
    }

    @Test
    fun refusesTypesThatAreNotRasterImages() {
        // SVG can carry script and event handlers; it is never inlined even with JS off.
        val out = inlineCidImages("""<img src="cid:logo@kypost">""", listOf(logo(type = "image/svg+xml")))
        assertTrue(out, out.contains("cid:logo@kypost"))
    }

    @Test
    fun stopsInliningAtTheByteBudget() {
        val half = ByteArray((org.kysecurity.mail.MemoryBudget.INLINE_IMAGE_BYTES / 2 + 1).toInt())
        val out = inlineCidImages(
            """<img src="cid:a"><img src="cid:b">""",
            listOf(logo("a", bytes = half), logo("b", bytes = half)),
        )

        assertEquals(1, Regex("data:image/png").findAll(out).count())
        assertTrue("the second image stays a cid: and gets stripped downstream", out.contains("cid:b"))
    }

    @Test
    fun anUnparseableFragmentComesBackUntouched() {
        assertEquals("", inlineCidImages("", listOf(logo())))
    }
}
```

Append to `EmailDetailActivityTest`:

```kotlin
    @Test
    fun blockExternalResources_keepsInlineRasterDataImages() {
        val blocked = blockExternalResources("""<img src="data:image/png;base64,iVBORw=="><img src="https://x/y.png">""")

        assertTrue(blocked, blocked.contains("data:image/png;base64,iVBORw=="))
        assertTrue(blocked, !blocked.contains("https://x/y.png"))
    }

    @Test
    fun blockExternalResources_stillStripsDataSvgAndNonImageData() {
        val blocked = blockExternalResources("""<img src="data:image/svg+xml;base64,PHN2Zz4="><img src="data:text/html;base64,PGI+">""")

        assertTrue(blocked, !blocked.contains("data:"))
    }

    @Test
    fun blockExternalResources_inlineDataImagesDoNotCountAsRemote() {
        val html = """<img src="data:image/png;base64,iVBORw==">"""
        assertEquals(blockExternalResources(html), blockExternalResources(html, keepImages = true))
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `./gradlew :app:testFdroidDebugUnitTest --tests "org.kysecurity.mail.pgp.InlineImagesTest" --tests "org.kysecurity.mail.EmailDetailActivityTest"`
Expected: `InlineImagesTest` fails to compile; the three new `EmailDetailActivityTest` cases fail because `src` is removed from every `img`.

- [ ] **Step 3: Implement `InlineImages.kt`**

```kotlin
package org.kysecurity.mail.pgp

import org.jsoup.Jsoup

/** Raster only. SVG is a document with script and event handlers; not worth a JS-off argument. */
private val INLINEABLE_IMAGE_TYPES = setOf("image/png", "image/jpeg", "image/gif", "image/webp")

/** `src` prefixes [org.kysecurity.mail.blockExternalResources] leaves alone on an `img`. */
internal val INLINE_DATA_IMAGE_PREFIXES = INLINEABLE_IMAGE_TYPES.map { "data:$it;base64," }

/** Rewrites `<img src="cid:...">` to a `data:` URI from the matching inline part.
 *
 *  Runs BEFORE the sanitiser: an unresolved `cid:` stays in place and the sanitiser strips it like
 *  any other image source. Stops at [org.kysecurity.mail.MemoryBudget.INLINE_IMAGE_BYTES]: a
 *  base64 image in a UTF-16 String costs 8/3 of its bytes, and the sender chooses the size. */
internal fun inlineCidImages(html: String, attachments: List<DecryptedAttachment>): String {
    if (html.isEmpty() || attachments.none { it.contentId != null }) return html
    val byId = attachments.filter { it.contentId != null && it.mimeType in INLINEABLE_IMAGE_TYPES }
        .associateBy { it.contentId!! }
    val document = runCatching { Jsoup.parseBodyFragment(html) }.getOrNull() ?: return html
    var budget = org.kysecurity.mail.MemoryBudget.INLINE_IMAGE_BYTES
    for (img in document.select("img[src]")) {
        val src = img.attr("src")
        if (!src.regionMatches(0, "cid:", 0, 4, ignoreCase = true)) continue
        val part = byId[src.substring(4)] ?: continue
        if (part.bytes.size > budget) continue
        budget -= part.bytes.size
        img.attr("src", "data:${part.mimeType};base64," + java.util.Base64.getEncoder().encodeToString(part.bytes))
    }
    document.outputSettings().prettyPrint(false)
    return document.body().html()
}
```

- [ ] **Step 4: Teach `blockExternalResources` to keep inline raster images**

In `EmailDetailActivity.kt` replace the loop at lines 1178-1183:

```kotlin
    document.select(resourceTags).forEach { element ->
        // A data: raster image is bytes already in hand, not a fetch; every other src goes.
        val keepsSrc = element.tagName() == "img" &&
            org.kysecurity.mail.pgp.INLINE_DATA_IMAGE_PREFIXES.any { element.attr("src").startsWith(it) }
        if (!keepsSrc) element.removeAttr("src")
        element.removeAttr("srcset")
        element.removeAttr("poster")
        element.removeAttr("data")
    }
```

- [ ] **Step 5: Run to verify they pass**

Run: `./gradlew :app:testFdroidDebugUnitTest --tests "org.kysecurity.mail.pgp.InlineImagesTest" --tests "org.kysecurity.mail.EmailDetailActivityTest"`
Expected: PASS, including every pre-existing `blockExternalResources_*` case.

- [ ] **Step 6: Deliberate break**

Remove `"image/svg+xml"` refusal by adding it to `INLINEABLE_IMAGE_TYPES`; confirm `refusesTypesThatAreNotRasterImages` and `blockExternalResources_stillStripsDataSvgAndNonImageData` both fail; restore.

- [ ] **Step 7: Commit**

```bash
git add app/src/main/java/org/kysecurity/mail/pgp/InlineImages.kt app/src/test/java/org/kysecurity/mail/pgp/InlineImagesTest.kt app/src/main/java/org/kysecurity/mail/EmailDetailActivity.kt app/src/test/java/org/kysecurity/mail/EmailDetailActivityTest.kt
git commit -m "pgp: inline cid images from the decrypted message as raster data URIs"
```

### Task 4: Show, open and save decrypted attachments

**Files:**
- Modify: `app/src/main/java/org/kysecurity/mail/EmailDetailActivity.kt` (Decrypted branch at 613-655, `showLocked` at 689, `onDestroy` at 959, and `renderAttachments` at 734)
- Modify: `app/src/main/res/values/strings.xml`
- Test: `app/src/test/java/org/kysecurity/mail/EmailDetailActivityTest.kt`

**Interfaces:**
- Consumes: `DecryptedBody.attachments`, `DecryptedBody.attachmentsOmitted`, `inlineCidImages`, existing `viewAttachmentEphemerally(DownloadedAttachment)`, `saveAttachmentToDownloads`, `attachmentSaveOffered`.
- Produces: a pure helper for the test: `internal fun decryptedAttachmentNotice(omitted: Boolean): Int?` returning a string resource id or null.

- [ ] **Step 1: Add strings**

```xml
    <string name="email_pgp_attachments_omitted">Some attachments in this message are too large to show on this device. Open it in webmail to get them.</string>
    <string name="email_pgp_attachments_label">Decrypted attachments — tap to open</string>
    <string name="email_pgp_attachments_label_hold_to_save">Decrypted attachments — tap to open, hold to save</string>
```

- [ ] **Step 2: Write the failing test**

```kotlin
    @Test
    fun decryptedAttachmentNotice_onlyWhenSomethingWasDropped() {
        assertNull(decryptedAttachmentNotice(omitted = false))
        assertEquals(R.string.email_pgp_attachments_omitted, decryptedAttachmentNotice(omitted = true))
    }
```

Run: `./gradlew :app:testFdroidDebugUnitTest --tests "org.kysecurity.mail.EmailDetailActivityTest"`. Expected: compile failure.

- [ ] **Step 3: Implement**

Top-level, next to `displaySignatureVerdict` (~line 1344):

```kotlin
/** A dropped part is said out loud; a complete list needs no sentence. */
internal fun decryptedAttachmentNotice(omitted: Boolean): Int? =
    if (omitted) R.string.email_pgp_attachments_omitted else null
```

Add a field beside `downloadedAttachments` (line 92):

```kotlin
    /** Parts of the decrypted message, retained for the chips; zeroed on lock and destroy. Never
     *  copied into [downloadedAttachments]: Forward is blocked for CLIENT_PROTECTED and must stay so. */
    private var decryptedAttachments: List<org.kysecurity.mail.pgp.DecryptedAttachment> = emptyList()

    private fun dropDecryptedAttachments() {
        decryptedAttachments.forEach { java.util.Arrays.fill(it.bytes, 0) }
        decryptedAttachments = emptyList()
    }
```

In the `Decrypted` branch, change the `rawHtml` computation to inline images, and render chips after the signature notice:

```kotlin
                val rawHtml = org.kysecurity.mail.pgp.inlineCidImages(
                    emailBodyToHtml(outcome.body.html ?: plainText.orEmpty(), outcome.body.bodyMode),
                    outcome.body.attachments,
                )
                // ...existing render...
                dropDecryptedAttachments()
                decryptedAttachments = outcome.body.attachments
                renderDecryptedAttachments(outcome.body.attachmentsOmitted)
```

Where the notice is assembled (the `notice`/`pgpBar` block), prepend the omission sentence:

```kotlin
                val omission = decryptedAttachmentNotice(outcome.body.attachmentsOmitted)
                    ?.let { getString(it) }
                val notice = listOfNotNull(signatureNoticeFor(verdict), omission).joinToString("\n\n").ifBlank { null }
```

New private function, modelled on `renderAttachments`:

```kotlin
    /** Chips for parts that came out of the ciphertext. Tap opens through the ephemeral provider;
     *  hold saves after the same confirmation the server-listed chips use. */
    private fun renderDecryptedAttachments(omitted: Boolean) {
        val label = findViewById<TextView>(R.id.emailAttachmentsLabel)
        val chips = findViewById<ChipGroup>(R.id.emailAttachmentChips)
        chips.removeAllViews()
        if (decryptedAttachments.isEmpty()) {
            label.visibility = View.GONE
            chips.visibility = View.GONE
            return
        }
        label.visibility = View.VISIBLE
        chips.visibility = View.VISIBLE
        val protectionEnabled = org.kysecurity.mail.security.SecurityRuntime
            .graph(this).hostileLocationSettings.isEnabled()
        val saveOffered = org.kysecurity.mail.security.attachmentSaveOffered(protectionEnabled)
        decryptedAttachments.forEach { part ->
            val chip = Chip(this).apply {
                text = getString(R.string.attachment_chip_label, part.name)
                setOnClickListener {
                    // register() takes ownership and zeroes; the chip must survive a second tap.
                    viewAttachmentEphemerally(
                        org.kysecurity.mail.mail.DownloadedAttachment(part.name, part.mimeType, part.bytes.copyOf()),
                    )
                }
                if (saveOffered) {
                    setOnLongClickListener {
                        androidx.appcompat.app.AlertDialog.Builder(this@EmailDetailActivity)
                            .setTitle(R.string.attachment_save_confirm_title)
                            .setMessage(getString(R.string.attachment_save_confirm_message, part.name))
                            .setPositiveButton(R.string.attachment_save_confirm_positive) { _, _ ->
                                ioExecutor.execute {
                                    val saved = org.kysecurity.mail.security.saveAttachmentToDownloads(
                                        this@EmailDetailActivity, part.name, part.mimeType, part.bytes,
                                    )
                                    runOnUiThread {
                                        if (isFinishing || isDestroyed) return@runOnUiThread
                                        val id = if (saved) R.string.attachment_saved else R.string.attachment_save_failed
                                        Toast.makeText(this@EmailDetailActivity, getString(id, part.name), Toast.LENGTH_LONG).show()
                                    }
                                }
                            }
                            .setNegativeButton(android.R.string.cancel, null)
                            .create()
                            .showSecurely()
                        true
                    }
                }
            }
            applyPillChipTheme(this, chip)
            chips.addView(chip)
        }
        label.text = getString(
            if (saveOffered) R.string.email_pgp_attachments_label_hold_to_save
            else R.string.email_pgp_attachments_label,
        )
    }
```

`showLocked` gains, before `lockedPlaceholder.visibility = View.VISIBLE`:

```kotlin
        dropDecryptedAttachments()
        findViewById<ChipGroup>(R.id.emailAttachmentChips).removeAllViews()
```

`onDestroy` gains `dropDecryptedAttachments()` after `super.onDestroy()`.

- [ ] **Step 4: Run tests and lint**

Run: `./gradlew :app:testFdroidDebugUnitTest --tests "org.kysecurity.mail.EmailDetailActivityTest" lintFdroidDebug`
Expected: PASS, lint clean.

- [ ] **Step 5: Verify on device (this is the artifact; the unit tests are not)**

Install a **release** build on a device enrolled against a relay that already produces `multipart/mixed` inside the ciphertext. Open one such message. Check, and record the result in the commit message body:
1. A chip per attachment appears after Decrypt; a tap opens the chooser; the opened file is intact.
2. An HTML body with an inline image shows the image with the "images blocked" bar hidden.
3. Lock the app, reopen the message: the chips are gone until the next Decrypt.
4. `adb logcat` shows no `PgpMimeReader` or `DecryptFailed` line for that message.

If no such relay is reachable, say so in the commit body: "device check not run".

- [ ] **Step 6: Commit**

```bash
git add app/src/main/java/org/kysecurity/mail/EmailDetailActivity.kt app/src/main/res/values/strings.xml app/src/test/java/org/kysecurity/mail/EmailDetailActivityTest.kt
git commit -m "pgp: open and save attachments from the decrypted message"
```

---

## Tier 2 — Encrypted drafts

### Task 5: Decision gate, no code

The server has not decided whether `POST /api/mail/draft` keeps accepting plaintext from native clients. The client already refuses to draft, reply or forward a `CLIENT_PROTECTED` message (`mayReplyOrForward`, `EmailDetailActivity.kt:1348`), and the compose hand-off is behind a consent dialog (`ComposeActivity.kt:803-869`).

- [ ] **Step 1: Confirm the block still holds**

Run: `./gradlew :app:testFdroidDebugUnitTest --tests "org.kysecurity.mail.EmailDetailActivityTest" --tests "org.kysecurity.mail.ComposePgpControllerTest"`
Expected: PASS.

- [ ] **Step 2: Read the Drafts folder through the normal path**

Encrypted draft rows arrive with `pgpEncrypted=true` and no body, exactly like an encrypted inbox row, and read through `/api/mail/pgp-payload`. No client change is expected. On a relay that writes encrypted drafts, open the Drafts folder in the app and open one row: it must show the Decrypt button, not `BODY_UNAVAILABLE`. Record the outcome on the board.

- [ ] **Step 3: Post the question to the board**

Post to `kypost-pgp-punch-list`: "Android: does `/api/mail/draft` keep accepting plaintext from native clients? If it refuses, the compose hand-off needs an encrypted save; if it keeps them, nothing changes here." Set nothing on that folder's status; it is the server's.

Do not build the encrypted draft save until the answer is "refuses". If it is, the shape is: `PgpEncryptor.encrypt(mimeBytes, listOf(ownPublicKey), signingKey)` to the user's own key, posted as the draft body with a `kypostEncryptedDraft` flag the server defines. That is a separate plan.

---

## Tier 3 — Signed-only mail

### Task 6: An encrypted-but-unsigned message says so

Signing defaults on server-side, so an unsigned encrypted message becomes the odd one. Today `NONE` covers "not signed" and "nothing checked" alike.

**Files:**
- Modify: `app/src/main/java/org/kysecurity/mail/pgp/PgpMessageState.kt`
- Modify: `app/src/main/java/org/kysecurity/mail/pgp/EncryptedMessageReader.kt:206-210`
- Modify: `app/src/main/java/org/kysecurity/mail/EmailDetailActivity.kt:559-566` (`signatureNoticeFor`)
- Modify: `app/src/main/res/values/strings.xml`
- Test: `EncryptedMessageReaderTest`, `PgpMessageStateTest`

**Interfaces:**
- Produces: `PgpSignatureState.UNSIGNED`.

- [ ] **Step 1: Write the failing tests**

`EncryptedMessageReaderTest`:

```kotlin
    /** ARMORED_MIME_MESSAGE is encrypted and not signed. With signing on by default upstream, that
     *  is now worth a sentence — but never a warning glyph. */
    @Test
    fun anEncryptedUnsignedMessageReportsUnsignedNotNone() {
        val (r, _) = reader()

        val outcome = read(r) as ReadOutcome.Decrypted

        assertEquals(PgpSignatureState.UNSIGNED, outcome.signature)
    }

    @Test
    fun aSignedOnlyMessageWithNothingToCheckStaysNone() {
        val (r, _) = reader(payloads = FakePayloadSource(detachedSignedPayload(signedPart = ByteArray(0), body = "readable")))

        val outcome = read(r) as ReadOutcome.Decrypted

        assertEquals("could-not-check is not the same claim as unsigned", PgpSignatureState.NONE, outcome.signature)
    }
```

`PgpMessageStateTest`:

```kotlin
    @Test
    fun unsignedIsNotARowWarning() {
        assertEquals("🔒", pgpRowMarker(PgpMessageState.CLIENT_PROTECTED, PgpSignatureState.UNSIGNED))
        assertNull(pgpRowMarker(PgpMessageState.NONE, PgpSignatureState.UNSIGNED))
    }
```

Run both classes. Expected: compile failure on `UNSIGNED`.

- [ ] **Step 2: Implement**

`PgpMessageState.kt`, inside `PgpSignatureState` after `NONE`:

```kotlin
    /** Decrypted, and the ciphertext carried no signature at all. A statement about the message,
     *  never about the sender: no glyph stronger than "nothing to say". Only [EncryptedMessageReader]
     *  produces it; the inbox flags cannot tell it from [NONE]. */
    UNSIGNED,
```

`EncryptedMessageReader.kt`, the final return:

```kotlin
        val verdict = signatureStateFor(decrypted.signature, payload.signerKeys, localKeys)
        return ReadOutcome.Decrypted(
            body,
            // Only here, where the bytes were decrypted: a signed-only message with nothing to check
            // stays NONE because "could not check" and "not signed" are different claims.
            if (decrypted.signature is RawSignature.Absent) PgpSignatureState.UNSIGNED else verdict,
            payload.resolvedSender,
        )
```

`signatureNoticeFor`:

```kotlin
        PgpSignatureState.UNSIGNED -> "⬜ " + getString(R.string.email_pgp_signature_unsigned)
```

`strings.xml`:

```xml
    <string name="email_pgp_signature_unsigned">Encrypted, not signed</string>
```

`pgpRowMarker` needs no change: its `else` routes `UNSIGNED` to the readability marker.

- [ ] **Step 3: Run**

Run: `./gradlew :app:testFdroidDebugUnitTest --tests "org.kysecurity.mail.pgp.*" --tests "org.kysecurity.mail.EmailDetailActivityTest"`
Expected: PASS. If a `when` over `PgpSignatureState` elsewhere fails to compile, add the `UNSIGNED` arm there mirroring `NONE`.

- [ ] **Step 4: Commit**

```bash
git add app/src/main/java/org/kysecurity/mail/pgp/PgpMessageState.kt app/src/main/java/org/kysecurity/mail/pgp/EncryptedMessageReader.kt app/src/main/java/org/kysecurity/mail/EmailDetailActivity.kt app/src/main/res/values/strings.xml app/src/test/java/org/kysecurity/mail/pgp/EncryptedMessageReaderTest.kt app/src/test/java/org/kysecurity/mail/pgp/PgpMessageStateTest.kt
git commit -m "pgp: say when an encrypted message carried no signature"
```

---

## Tier 4 — Inbox cache change

### Task 7: Delta-sync regression, scripted and then real

The server change is that encrypted rows stop making the mailbox cold. `since`, `changeType` and `removed` are meant to be unchanged. One gap in the existing tests: no delta case carries an encrypted row.

**Files:**
- Test: `app/src/test/java/org/kysecurity/mail/mail/RelayMailSourceTest.kt`

- [ ] **Step 1: Write the test** (after `deltaPoll_parsesNewUpdatedAndRemoved`, reusing its helpers)

```kotlin
    /** The cache change: an encrypted row arrives in a delta with no body. It must keep its flags
     *  and be `updated`, never a bodyless `new` that MailRepository would store as unreadable. */
    @Test
    fun deltaPoll_keepsAnEncryptedRowsFlagsWithoutABody() {
        val cursorProvider = FakeMailCursorProvider(storedCursor = "cursor-1")
        val body = """
            {
              "tabs": ["Work"],
              "byTab": {"Work": [
                {"messageId": "e1", "sender": "a@example.com", "subject": "…", "label": "Work",
                 "status": "unread", "changeType": "new", "pgpEncrypted": true, "pgpSigned": true}
              ]},
              "cursor": "cursor-2", "delta": true, "removed": []
            }
        """.trimIndent()
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = cursorProvider,
            callFactory = FakeCallFactory { request -> jsonResponse(request, body) },
        )

        val result = (source.fetchInbox("INBOX", 50) as MailOutcome.Success).value

        val row = result.messages.single()
        assertTrue(row.pgpEncrypted)
        assertTrue(row.pgpSigned)
        assertNull(row.body)
        assertEquals(emptySet<String>(), result.updatedMessageIds)
    }
```

If `UiEmail` names the flags differently, use its names; do not add fields.

- [ ] **Step 2: Run the whole sync surface**

Run: `./gradlew :app:testFdroidDebugUnitTest --tests "org.kysecurity.mail.mail.RelayMailSourceTest" --tests "org.kysecurity.mail.mail.MailRepositoryTest" --tests "org.kysecurity.mail.mail.RelayModelsSerializationTest"`
Expected: PASS.

- [ ] **Step 3: Real relay**

Against a relay running the cache change, with the app's cursor already persisted: receive one encrypted message, pull to refresh, open it. Expect the Decrypt button (`CLIENT_PROTECTED`), not the `email_pgp_body_unavailable` sentence. Then delete it in webmail, refresh, confirm the row is gone (`removed` path). Record both on the board; if no relay is reachable, record "not run".

- [ ] **Step 4: Commit**

```bash
git add app/src/test/java/org/kysecurity/mail/mail/RelayMailSourceTest.kt
git commit -m "sync: an encrypted delta row keeps its flags without a body"
```

---

## Tier 5 — Key retirement

The server seals the current key plus every historical key the account still holds into the one envelope. `PgpDecryptor.decrypt` already walks the whole `PGPSecretKeyRingCollection` by key ID (`PgpDecryptor.kt:88-100`), and `PgpEncryptor` signs with the first signing key in ring order (`PgpEncryptor.kt:136-141`). So the client's job is: never lose a ring the device once held, and keep the current key first. That is a merge at re-enrolment, not a second vault. Nothing in this app uploads private material (`grep -rn "armoredPrivateKey\|withKey" app/src/main --include=*.kt` shows only decrypt and sign call sites), so "never seal a retired key back to the server" is already true.

### Task 8: `mergeSecretKeyRings`

**Files:**
- Create: `app/src/main/java/org/kysecurity/mail/pgp/SecretKeyRingMerge.kt`
- Test: `app/src/test/java/org/kysecurity/mail/pgp/SecretKeyRingMergeTest.kt`

**Interfaces:**
- Consumes: `CharArray.useArmoredStream` (`ArmoredKeyStream.kt:9`), test fixtures `TestPgpPrivateKey.ARMORED_PRIVATE` / `ARMORED_MESSAGE` / `ARMORED_PUBLIC`, `TestPgpSecondKey.ARMORED_PRIVATE` / `ARMORED_PUBLIC`.
- Produces: `internal fun mergeSecretKeyRings(current: ByteArray, previous: CharArray): ByteArray?` — armored UTF-8 bytes, current rings first, then previous rings whose primary fingerprint is absent from current. Null when `current` does not parse; an unparseable `previous` is ignored (nothing to keep).

- [ ] **Step 1: Write the failing tests**

```kotlin
package org.kysecurity.mail.pgp

import org.bouncycastle.openpgp.PGPSecretKeyRingCollection
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SecretKeyRingMergeTest {

    private fun rings(armored: ByteArray) = PGPSecretKeyRingCollection(
        PGPUtil.getDecoderStream(armored.inputStream()), BcKeyFingerprintCalculator(),
    ).keyRings.asSequence().toList()

    private val newKey = TestPgpSecondKey.ARMORED_PRIVATE.toByteArray(Charsets.UTF_8)
    private val oldKey = TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray()

    @Test
    fun keepsTheNewRingFirstAndAppendsTheOldOne() {
        val merged = mergeSecretKeyRings(newKey, oldKey)!!

        val fps = rings(merged).map { it.publicKey.fingerprint.toHexString() }
        assertEquals(2, fps.size)
        assertEquals(rings(newKey).single().publicKey.fingerprint.toHexString(), fps[0])
    }

    @Test
    fun doesNotDuplicateARingAlreadyInTheNewEnvelope() {
        val merged = mergeSecretKeyRings(TestPgpPrivateKey.ARMORED_PRIVATE.toByteArray(Charsets.UTF_8), oldKey)!!
        assertEquals(1, rings(merged).size)
    }

    @Test
    fun theMergedBlobStillDecryptsMailToTheRetiredKey() {
        val merged = mergeSecretKeyRings(newKey, oldKey)!!

        val result = PgpDecryptor.decrypt(String(merged, Charsets.UTF_8).toCharArray(), TestPgpPrivateKey.ARMORED_MESSAGE, emptyList())

        assertTrue("expected Ok, got $result", result is DecryptResult.Ok)
        assertEquals(TestPgpPrivateKey.EXPECTED_PLAINTEXT, String((result as DecryptResult.Ok).plaintext, Charsets.UTF_8))
    }

    @Test
    fun theMergedBlobSignsWithTheCurrentKeyNotTheRetiredOne() {
        val merged = mergeSecretKeyRings(newKey, oldKey)!!

        val encrypted = PgpEncryptor.encrypt(
            "signed".toByteArray(), listOf(TestPgpSecondKey.ARMORED_PUBLIC),
            String(merged, Charsets.UTF_8).toCharArray(),
        ) as EncryptResult.Ok
        val verified = PgpDecryptor.decrypt(
            String(merged, Charsets.UTF_8).toCharArray(), encrypted.armored, listOf(TestPgpSecondKey.ARMORED_PUBLIC),
        ) as DecryptResult.Ok

        assertTrue("must verify against the NEW public key", verified.signature.valid)
        val againstOld = PgpDecryptor.decrypt(
            String(merged, Charsets.UTF_8).toCharArray(), encrypted.armored, listOf(TestPgpPrivateKey.ARMORED_PUBLIC),
        ) as DecryptResult.Ok
        assertTrue("must NOT verify against the retired key", !againstOld.signature.valid)
    }

    @Test
    fun anUnparseableNewEnvelopeIsRefused() {
        assertNull(mergeSecretKeyRings("garbage".toByteArray(), oldKey))
    }

    @Test
    fun anUnparseablePreviousKeyIsIgnored() {
        val merged = mergeSecretKeyRings(newKey, "garbage".toCharArray())!!
        assertEquals(1, rings(merged).size)
    }
}

private fun ByteArray.toHexString() = joinToString("") { "%02X".format(it) }
```

- [ ] **Step 2: Run to verify they fail**

Run: `./gradlew :app:testFdroidDebugUnitTest --tests "org.kysecurity.mail.pgp.SecretKeyRingMergeTest"`
Expected: compile failure on `mergeSecretKeyRings`.

- [ ] **Step 3: Implement**

```kotlin
package org.kysecurity.mail.pgp

import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import java.io.ByteArrayOutputStream

/** The envelope the server just sealed, plus every ring this device already held that it lacks.
 *
 *  Current rings come first, so [PgpEncryptor]'s first-signing-key rule keeps signing with the
 *  current key. [PgpDecryptor] selects by key ID across the whole collection, so a message to a
 *  retired key still opens. One blob, one unseal: a second vault would cost a second biometric
 *  prompt on every read for the rare message this covers. */
internal fun mergeSecretKeyRings(current: ByteArray, previous: CharArray): ByteArray? {
    val currentRings = runCatching { ringsOf(current.inputStream()) }.getOrNull() ?: return null
    val previousRings = runCatching { previous.useArmoredStream(::ringsOf) }.getOrDefault(emptyList())
    val known = currentRings.map { it.publicKey.fingerprint.toList() }.toHashSet()
    val retired = previousRings.filter { it.publicKey.fingerprint.toList() !in known }

    val out = ByteArrayOutputStream()
    ArmoredOutputStream(out).use { armored ->
        (currentRings + retired).forEach { it.encode(armored) }
    }
    return out.toByteArray()
}

private fun ringsOf(input: java.io.InputStream): List<PGPSecretKeyRing> =
    PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(input), BcKeyFingerprintCalculator())
        .keyRings.asSequence().toList()
```

- [ ] **Step 4: Run to verify they pass**

Run: `./gradlew :app:testFdroidDebugUnitTest --tests "org.kysecurity.mail.pgp.SecretKeyRingMergeTest"`
Expected: PASS.

- [ ] **Step 5: Deliberate break**

Swap `(currentRings + retired)` to `(retired + currentRings)`; `theMergedBlobSignsWithTheCurrentKeyNotTheRetiredOne` and `keepsTheNewRingFirstAndAppendsTheOldOne` must fail. Restore.

- [ ] **Step 6: Commit**

```bash
git add app/src/main/java/org/kysecurity/mail/pgp/SecretKeyRingMerge.kt app/src/test/java/org/kysecurity/mail/pgp/SecretKeyRingMergeTest.kt
git commit -m "pgp: merge the previous secret key ring into a new envelope, current key first"
```

### Task 9: The ceremony merges before it seals, and never drops a held key

**Files:**
- Modify: `app/src/main/java/org/kysecurity/mail/pgp/EnrollmentCeremony.kt` (constructor at 19-29; `sealAndReport` at 248-273)
- Modify: `app/src/main/java/org/kysecurity/mail/pgp/DeviceEnrollmentViewModel.kt:24-45` (proxy the opener the same way `activitySealer` is proxied)
- Modify: `app/src/main/java/org/kysecurity/mail/pgp/DeviceEnrollmentActivity.kt` (install an `AndroidVaultOpener(this)` beside the sealer)
- Test: `app/src/test/java/org/kysecurity/mail/pgp/FakeEnrollmentPorts.kt`, new `app/src/test/java/org/kysecurity/mail/pgp/EnrollmentCeremonyMergeTest.kt`

**Interfaces:**
- Consumes: `VaultOpener` (`VaultOpener.kt`), `EnrollmentSession.isHeld()/withKey/clear()`, `mergeSecretKeyRings` (Task 8), `FakeVaultOpener` (`FakeReaderPorts.kt`, same test package), `FakePorts`/`FakeVaultSealer.received`/`sealEnvelope` (`FakeEnrollmentPorts.kt`).
- Produces: constructor parameter `previousVault: VaultOpener`; `sealEnvelope(..., plaintext: String = FAKE_PLAINTEXT)`; `FakePorts(previousVault: VaultOpener = FakeVaultOpener(outcome = OpenOutcome.NotEnrolled), ...)`.

- [ ] **Step 1: Extend the fixtures**

In `FakeEnrollmentPorts.kt`, give `sealEnvelope` a plaintext parameter and use it in place of `FAKE_PLAINTEXT` at the `doFinal` line:

```kotlin
internal fun sealEnvelope(
    keys: FakeEnrollmentKeys,
    deviceId: String = "dev-1",
    aadFingerprint: String = FAKE_FINGERPRINT,
    plaintext: String = FAKE_PLAINTEXT,
): String {
    // ...unchanged...
    val ct = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
```

Give `FakePorts` a `previousVault` and pass it through `ceremony()`:

```kotlin
internal class FakePorts(
    // ...existing parameters...
    val previousVault: VaultOpener = FakeVaultOpener(outcome = OpenOutcome.NotEnrolled),
) {
    // ...
    fun ceremony(): EnrollmentCeremony = EnrollmentCeremony(
        identity = identity,
        transport = transport,
        keys = keys,
        sealer = sealer,
        previousVault = previousVault,
        mailCache = mailCache,
        clock = clock,
        hostileLocationEnabled = { hostileLocation },
        hasSecureLockScreen = { secureLockScreen },
        onState = { states += it },
    )
}
```

Add at the bottom of the file:

```kotlin
internal fun ringCount(armored: ByteArray): Int = org.bouncycastle.openpgp.PGPSecretKeyRingCollection(
    org.bouncycastle.openpgp.PGPUtil.getDecoderStream(armored.inputStream()),
    org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator(),
).keyRings.asSequence().count()
```

- [ ] **Step 2: Write the failing tests**

`EnrollmentCeremonyMergeTest.kt`:

```kotlin
package org.kysecurity.mail.pgp

import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Re-enrolment after a key retirement: the envelope carries the new key, the vault holds the old
 *  one, and the seal must carry both. One vault, one unseal per read. */
class EnrollmentCeremonyMergeTest {

    @After fun clearSession() = EnrollmentSession.clear()

    private fun ports(previousVault: VaultOpener): FakePorts {
        val probe = FakeEnrollmentKeys()
        val envelope = sealEnvelope(probe, plaintext = TestPgpSecondKey.ARMORED_PRIVATE)
        return FakePorts(
            fetchResults = mutableListOf(EnrollmentCallResult.Envelope(envelope)),
            previousVault = previousVault,
        )
    }

    @Test
    fun reEnrolmentSealsTheMergedRingNotJustTheNewOne() = runBlocking {
        val previous = FakeVaultOpener(keyToHold = TestPgpPrivateKey.ARMORED_PRIVATE)
        val ports = ports(previous)

        ports.ceremony().run()

        assertEquals(EnrollmentUiState.Enrolled, ports.states.last())
        assertEquals(1, previous.opened)
        assertEquals(2, ringCount(ports.sealer.received.single()))
    }

    @Test
    fun aHeldSessionKeyIsMergedWithoutAPrompt() = runBlocking {
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
        val previous = FakeVaultOpener()
        val ports = ports(previous)

        ports.ceremony().run()

        assertEquals("the held key IS the previous key; no prompt", 0, previous.opened)
        assertEquals(2, ringCount(ports.sealer.received.single()))
    }

    @Test
    fun aFirstEnrolmentHasNothingToMerge() = runBlocking {
        val ports = ports(FakeVaultOpener(outcome = OpenOutcome.NotEnrolled))

        ports.ceremony().run()

        assertEquals(1, ringCount(ports.sealer.received.single()))
    }

    @Test
    fun cancellingThePreviousUnlockSealsNothingOverTheOldVault() = runBlocking {
        val ports = ports(FakeVaultOpener(outcome = OpenOutcome.Cancelled))

        ports.ceremony().run()

        assertTrue("nothing may be sealed over a vault the user declined to open", ports.sealer.received.isEmpty())
        assertTrue(ports.states.last() is EnrollmentUiState.ReadyToFinish)
    }

    @Test
    fun anUnopenableOldVaultIsReplacedRatherThanBlockingEnrolment() = runBlocking {
        val ports = ports(FakeVaultOpener(outcome = OpenOutcome.Failed("keystore invalidated")))

        ports.ceremony().run()

        assertEquals(EnrollmentUiState.Enrolled, ports.states.last())
        assertEquals(1, ringCount(ports.sealer.received.single()))
    }

    @Test
    fun theSessionIsClearedAfterASealSoTheNextReadUnsealsTheMergedBlob() = runBlocking {
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
        val ports = ports(FakeVaultOpener())

        ports.ceremony().run()

        assertTrue(!EnrollmentSession.isHeld())
    }

    @Test
    fun theMergedPlaintextIsZeroedAfterTheSeal() = runBlocking {
        val ports = ports(FakeVaultOpener(keyToHold = TestPgpPrivateKey.ARMORED_PRIVATE))

        ports.ceremony().run()

        ports.sealer.handedArrays.forEach { handed -> assertTrue(handed.all { it == 0.toByte() }) }
    }
}
```

- [ ] **Step 3: Run to verify they fail**

Run: `./gradlew :app:testFdroidDebugUnitTest --tests "org.kysecurity.mail.pgp.EnrollmentCeremonyMergeTest"`
Expected: compile failure on `previousVault`.

- [ ] **Step 4: Implement the ceremony change**

Constructor gains, after `sealer`:

```kotlin
    /** Opens the vault this device already holds so its rings survive the re-seal. */
    private val previousVault: VaultOpener,
```

`sealAndReport` becomes:

```kotlin
    private suspend fun sealAndReport(plaintext: ByteArray) {
        emit(EnrollmentUiState.AwaitingAuth)

        if (!hasSecureLockScreen()) {
            failAndDestroy(FailureReason.NO_SECURE_LOCK_SCREEN)
            return
        }

        // A retired key still opens old mail. Merge it in now, while both plaintexts are in hand,
        // rather than keeping a second vault that would cost a second prompt on every read.
        if (!EnrollmentSession.isHeld()) {
            when (previousVault.open()) {
                OpenOutcome.Opened, OpenOutcome.NotEnrolled -> Unit
                // The user declined to open what they already hold; sealing over it would lose it.
                OpenOutcome.Cancelled -> { emit(EnrollmentUiState.ReadyToFinish); return }
                OpenOutcome.NoSecureLockScreen -> { failAndDestroy(FailureReason.NO_SECURE_LOCK_SCREEN); return }
                // Exists and cannot be opened: a Keystore key the OS invalidated. Nothing recoverable
                // is being lost, so the new envelope replaces it.
                is OpenOutcome.Failed -> Unit
            }
        }
        // Null from withKey means no previous key; null from the merge means the NEW envelope did
        // not parse, which the sealer and the server will judge as before. Both seal the plaintext.
        val toSeal = EnrollmentSession.withKey { previous -> mergeSecretKeyRings(plaintext, previous) } ?: plaintext

        try {
            when (withContext(NonCancellable) { sealer.seal(toSeal) }) {
                is SealOutcome.Sealed -> {
                    // The held key is now stale relative to the vault; the next read re-unseals.
                    EnrollmentSession.clear()
                    mailCache.clearServerDecryptedBodies()
                    report()
                }
                is SealOutcome.NoSecureLockScreen -> failAndDestroy(FailureReason.NO_SECURE_LOCK_SCREEN)
                is SealOutcome.Failed -> failAndDestroy(FailureReason.SEAL_FAILED)
                // NOT back to the code: it would go stale with no window to refresh it. The envelope waits 7 days.
                is SealOutcome.Cancelled -> emit(EnrollmentUiState.ReadyToFinish)
            }
        } finally {
            // Sealed and durable by now, or abandoned: either way neither copy may outlive this.
            plaintext.fill(0)
            if (toSeal !== plaintext) toSeal.fill(0)
        }
    }
```

The old code zeroed `plaintext` right after `Sealed` and before `report()`; the `finally` keeps that ordering property (zero before anything else runs after the seal) only if `report()` is moved out. Keep it simple: zero both arrays immediately after the `Sealed` branch's first line, and leave the `finally` as the safety net:

```kotlin
                is SealOutcome.Sealed -> {
                    plaintext.fill(0)
                    if (toSeal !== plaintext) toSeal.fill(0)
                    EnrollmentSession.clear()
                    mailCache.clearServerDecryptedBodies()
                    report()
                }
```

- [ ] **Step 5: Wire the Android opener**

`DeviceEnrollmentViewModel.kt`: beside `activitySealer`, add

```kotlin
    /** The live Activity's opener, or null between destroy and the next install. */
    @Volatile
    private var activityOpener: VaultOpener? = null
```

and pass to the ceremony

```kotlin
        previousVault = object : VaultOpener {
            override suspend fun open(): OpenOutcome = activityOpener?.open() ?: OpenOutcome.Cancelled
        },
```

Wherever the ViewModel installs and clears `activitySealer` (grep `activitySealer =`), install and clear `activityOpener = AndroidVaultOpener(activity)` in the same two places.

- [ ] **Step 6: Run**

Run: `./gradlew :app:testFdroidDebugUnitTest --tests "org.kysecurity.mail.pgp.*" lintFdroidDebug`
Expected: PASS, including every pre-existing ceremony test (they get a `NotEnrolled` opener by default and behave as before). If `EnrollmentCeremonyExitTest.expectedCleanup` enumerates terminal states, the new `ReadyToFinish` exit on a cancelled unlock is one it already knows.

- [ ] **Step 7: Deliberate break**

Change `OpenOutcome.Cancelled -> { emit(EnrollmentUiState.ReadyToFinish); return }` to `OpenOutcome.Cancelled -> Unit`; `cancellingThePreviousUnlockSealsNothingOverTheOldVault` must fail. Restore.

- [ ] **Step 8: Device check**

On an enrolled release build: retire the key in webmail, re-enrol the phone. Expect two prompts (unlock, then seal) unless the app was already unlocked. Afterwards open one message encrypted to the OLD key and one to the NEW key; both must decrypt. Send one message; verify in webmail that it is signed by the NEW key. Record all three on the board; if not run, say so.

- [ ] **Step 9: Commit**

```bash
git add app/src/main/java/org/kysecurity/mail/pgp/EnrollmentCeremony.kt app/src/main/java/org/kysecurity/mail/pgp/DeviceEnrollmentViewModel.kt app/src/main/java/org/kysecurity/mail/pgp/DeviceEnrollmentActivity.kt app/src/test/java/org/kysecurity/mail/pgp/FakeEnrollmentPorts.kt app/src/test/java/org/kysecurity/mail/pgp/EnrollmentCeremonyMergeTest.kt
git commit -m "pgp: re-enrolment keeps every ring the device already held"
```

---

## Tier 6 — New resolver tiers

`tier` (`RecipientResolveClient.kt:19-25`) and `SignerKey.source` (`SignerBinding.kt:14`) are plain strings; `usable` governs, and `signatureStateFor` never reads `source`. `RecipientKeyClient` declares `revoked`/`expired` as unused booleans. The tolerance exists; what is missing is a test that pins it, so a future "make it an enum" refactor fails loudly.

### Task 10: Pin unknown-value tolerance

**Files:**
- Test: `RecipientResolveClientTest.kt`, `PgpPayloadClientTest.kt`

- [ ] **Step 1: Write the tests**

`RecipientResolveClientTest`:

```kotlin
    /** `expired` and `revoked` join the tier set server-side, and more may follow. The client must
     *  carry any tier verbatim and let `usable` decide; a decoder that enumerates tiers would turn
     *  the next server release into a compose-screen outage. */
    @Test
    fun unknownTiersParseAndUsableStillGoverns() = runBlocking {
        val body = """{"results":[
            {"address":"a@example.invalid","publicKey":"K","fingerprint":"AA","tier":"expired","usable":false},
            {"address":"b@example.invalid","publicKey":"K","fingerprint":"BB","tier":"revoked","usable":false},
            {"address":"c@example.invalid","publicKey":"K","fingerprint":"CC","tier":"tier-from-the-future","usable":true}
        ]}"""
        val client = RecipientResolveClient(callFactory = FakeCallFactory { request -> response(request, body, 200) })

        val results = (client.resolve("https://relay.example.com/", "d", "s", listOf("a@example.invalid", "b@example.invalid", "c@example.invalid")) as ResolveResult.Success).results

        assertEquals(listOf("expired", "revoked", "tier-from-the-future"), results.map { it.tier })
        assertEquals(listOf(false, false, true), results.map { it.usable })
    }
```

`PgpPayloadClientTest`:

```kotlin
    @Test
    fun anUnknownSignerKeySourceParses() {
        val result = fetchWith(
            200,
            """{"encryptedPayload":"X","signaturePayload":"","body":"",
                "signerKeys":[{"addresses":["bob@example.com"],"publicKey":"KEY","source":"expired"},
                              {"addresses":["bob@example.com"],"publicKey":"KEY2","source":"source-from-the-future","conflict":true}]}""",
        )

        val ok = result as PgpPayloadResult.Success
        assertEquals(listOf("expired", "source-from-the-future"), ok.signerKeys.map { it.source })
        assertTrue(ok.signerKeys[1].conflict)
    }
```

- [ ] **Step 2: Run**

Run: `./gradlew :app:testFdroidDebugUnitTest --tests "org.kysecurity.mail.pgp.RecipientResolveClientTest" --tests "org.kysecurity.mail.pgp.PgpPayloadClientTest"`
Expected: PASS on first run. Prove them by break: temporarily change `tier: String = ""` in `ResolvedKeyDto` to an enum with two values, confirm the first test fails to decode, restore.

- [ ] **Step 3: Commit**

```bash
git add app/src/test/java/org/kysecurity/mail/pgp/RecipientResolveClientTest.kt app/src/test/java/org/kysecurity/mail/pgp/PgpPayloadClientTest.kt
git commit -m "pgp: pin that unknown resolver tiers and signer sources decode"
```

---

## Finish

- [ ] Full suite and lint: `./gradlew :app:testFdroidDebugUnitTest lintFdroidDebug`, then the release gate for every flavor printed by `./gradlew :app:tasks --all | grep checkRuntimeMatchedClassNames`.
- [ ] `./gradlew :app:assembleFdroidRelease` (or whichever flavor the device uses) and the device checks in Tasks 4, 7 and 9, recorded honestly.
- [ ] Open the PR with the `pull-request` skill. Post the hand-off to `kypost-android-pgp-parity` with the `myslop-handoff` skill: what shipped, which device checks ran, and the Task 5 decision still owed by the server.
