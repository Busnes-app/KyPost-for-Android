package org.kysecurity.mail

import org.kysecurity.mail.mail.MailMessageBody
import org.kysecurity.mail.mail.MailOutcome
import org.kysecurity.mail.pgp.DecryptedBody
import org.kysecurity.mail.pgp.PgpMessageState
import org.kysecurity.mail.pgp.PgpSignatureState
import org.kysecurity.mail.pgp.ReadOutcome
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class EmailDetailActivityTest {

    /** The inbox is fetched with bodies=0, so the body arrives over the network when the message is
     *  opened and the fetch can now fail — before that it took a missing cache row and effectively
     *  never happened. What it leaves behind is `emailPreview`, and rendering that is
     *  indistinguishable from a short message that arrived intact. */
    @Test
    fun aFailedBodyFetch_doesNotLetThePreviewStandInForTheMessage() {
        val outcome: MailOutcome<MailMessageBody> = MailOutcome.UpstreamFailure("imap down")

        assertFalse(mayFallBackToPreview(outcome))
    }

    /** The server answering with an empty body IS the case the preview fallback exists for. */
    @Test
    fun anEmptyBodyFromTheServer_stillFallsBackToThePreview() {
        val outcome: MailOutcome<MailMessageBody> = MailOutcome.Success(
            MailMessageBody(html = "", bodyMode = "", toAddresses = emptyList(), ccAddresses = emptyList()),
        )

        assertTrue(mayFallBackToPreview(outcome))
    }

    /** "No message body available." is only true when the server answered and had nothing. A
     *  failure is a different fact and the only one the user can act on. */
    @Test
    fun aFailedBodyFetch_isReportedInsteadOfClaimingTheMessageHasNoBody() {
        val outcome: MailOutcome<MailMessageBody> = MailOutcome.UpstreamFailure("imap down")

        val notice = bodyFetchFailureNotice(outcome)

        assertNotNull(notice)
        assertTrue(notice!!.contains("imap down"))
    }

    @Test
    fun aSuccessfulBodyFetch_reportsNoFailure() {
        val outcome: MailOutcome<MailMessageBody> = MailOutcome.Success(
            MailMessageBody(html = "hi", bodyMode = "plain", toAddresses = emptyList(), ccAddresses = emptyList()),
        )

        assertNull(bodyFetchFailureNotice(outcome))
    }

    /** A signature notice must not swallow the fetch failure: they are independent facts, and the
     *  one about the message not loading is the one the user can act on. */
    @Test
    fun aSignedMessageWhoseBodyFailedToLoad_saysBoth() {
        val notice = emptyBodyNotice(
            signatureNotice = "Signed by an unknown key",
            fetchFailure = "Couldn't reach the mail server",
            noContent = "No message body available.",
            nothingToRender = true,
        )

        assertNotNull(notice)
        assertTrue(notice!!.contains("Signed by an unknown key"))
        assertTrue(notice.contains("Couldn't reach the mail server"))
    }

    /** "No message body available." claims the server answered and had nothing. A failed fetch has
     *  not established that, so the two must never both appear. */
    @Test
    fun aFailedFetch_neverAlsoClaimsTheMessageHasNoBody() {
        val notice = emptyBodyNotice(
            signatureNotice = null,
            fetchFailure = "Couldn't reach the mail server",
            noContent = "No message body available.",
            nothingToRender = true,
        )

        assertEquals("Couldn't reach the mail server", notice)
    }

    @Test
    fun anEmptyMessageTheServerAnsweredFor_saysSoWhenNothingIsOnScreen() {
        val notice = emptyBodyNotice(
            signatureNotice = null,
            fetchFailure = null,
            noContent = "No message body available.",
            nothingToRender = true,
        )

        assertEquals("No message body available.", notice)
    }

    /** Nothing to say when the message rendered fine. */
    @Test
    fun aMessageThatRendered_getsNoNotice() {
        val notice = emptyBodyNotice(
            signatureNotice = null,
            fetchFailure = null,
            noContent = "No message body available.",
            nothingToRender = false,
        )

        assertNull(notice)
    }

    @Test
    fun emailBodyToHtml_preservesPlainTextWhitespaceAndEscapesMarkup() {
        val html = emailBodyToHtml("one\t two\nthree < four", "plain")

        assertTrue(html.startsWith("<div class=\"kypost-plain-text\">") )
        assertTrue(html.contains("one\t two\nthree &lt; four"))
    }

    @Test
    fun emailBodyToHtml_respectsExplicitHtmlMode() {
        assertEquals("<p>hello</p>", emailBodyToHtml("<p>hello</p>", "html"))
    }

    @Test
    fun emailBodyToHtml_fallbackRecognizesEmailHtmlTags() {
        assertEquals("<center><p>hello</p></center>", emailBodyToHtml("<center><p>hello</p></center>", ""))
    }

    @Test
    fun isPlainTextBody_usesHtmlDetectionWhenModeIsMissing() {
        assertTrue(isPlainTextBody("a very wide line", ""))
        assertFalse(isPlainTextBody("<p>hello</p>", ""))
        assertTrue(isPlainTextBody("<user@example.com>", ""))
        assertTrue(isPlainTextBody("# Security Policy\nSee https://example.com", "html"))
        assertFalse(isPlainTextBody("<img src=\"cid:image\">", "html"))
        assertTrue(isPlainTextBody("# Security Policy\nSee the [advisory](https://example.com)", "html"))
    }

    @Test
    fun softWrapPlainText_addsInvisibleBreaksOnlyToLongTokens() {
        val wrapped = softWrapPlainText("short ${"a".repeat(40)}")

        assertEquals("short aaaaaaaaaaaaaaaa\u200Baaaaaaaaaaaaaaaa\u200Baaaaaaaa", wrapped)
        assertEquals("short text", softWrapPlainText("short text"))
    }

    @Test
    fun blockExternalResources_removesImageAndStyleResourceUrls() {
        val blocked = blockExternalResources(
            "<img src=\"https://example.com/a.png\"><div style=\"background:url(https://example.com/b.png)\">Hi</div>",
        )

        assertFalse(blocked.contains("https://example.com"))
        assertTrue(blocked.contains("Hi"))
    }

    /** `[style]` is an ATTRIBUTE selector and matches `<div style=...>`, never `<style>`, so a
     *  `<style>` block was never inspected at all. With "Show images" pressed — which clears
     *  `blockNetworkLoads` wholesale — that is a read receipt with the reader's IP on it. */
    @Test
    fun blockExternalResources_stripsResourceUrlsInsideStyleElements() {
        val blocked = blockExternalResources(
            "<style>body{background-image:url(https://tracker.example/beacon?u=victim)}</style><p>Hi</p>",
        )

        assertFalse("a <style> beacon must not survive", blocked.contains("tracker.example"))
        assertTrue(blocked.contains("Hi"))
    }

    @Test
    fun blockExternalResources_stripsAtImportInBothForms() {
        val urlForm = blockExternalResources("<style>@import url(https://tracker.example/x.css);</style>")
        val stringForm = blockExternalResources("<style>@import \"https://tracker.example/y.css\";</style>")

        assertFalse(urlForm.contains("tracker.example"))
        // `@import` takes a bare string too, which no url() pattern can see.
        assertFalse(stringForm.contains("tracker.example"))
    }

    @Test
    fun blockExternalResources_stripsImageSetAndCrossFade() {
        val blocked = blockExternalResources(
            "<div style=\"background:image-set(url(https://tracker.example/a.png) 1x)\">Hi</div>",
        )

        assertFalse(blocked.contains("tracker.example"))
    }

    /** A CSS escape can spell the function name: `\75 rl(...)` is a `url()` token to a CSS parser
     *  and was not one to the regex. [stripImportantFromCss] already had to learn this lesson. */
    @Test
    fun blockExternalResources_seesResourceUrlsHiddenBehindCssEscapes() {
        val blocked = blockExternalResources(
            "<style>body{background:\\75 rl(https://tracker.example/beacon)}</style>",
        )

        assertFalse(blocked.contains("tracker.example"))
    }

    /** Only when an escape was HIDING something: decoding unconditionally would rewrite legitimate
     *  escapes in content strings for no benefit. */
    @Test
    fun blockExternalResources_leavesInnocentCssEscapesAlone() {
        val blocked = blockExternalResources("<div style=\"content:'\\201C'\">Hi</div>")

        assertTrue("an escape that hides nothing must survive", blocked.contains("201C"))
    }

    /** A CSS comment is transparent between any two tokens, including inside a declaration. */
    @Test
    fun blockExternalResources_stripsResourceUrlsAroundCssComments() {
        val blocked = blockExternalResources(
            "<style>body{background:/*x*/url(https://tracker.example/beacon)}</style>",
        )

        assertFalse(blocked.contains("tracker.example"))
    }

    /** Fails CLOSED, like QuotedHtmlSanitizer. Returning unparseable markup unchanged handed a
     *  sender who can break jsoup every beacon this function exists to strip. */
    /** THE SIZE CLIFF. Both render paths gated `blockExternalResources` on a regex named
     *  `hasRemoteImages`, and one of them skipped the scan entirely past 512 KB — so a large enough
     *  body reached `loadDataWithBaseURL` with every resource URL intact, defended only by the
     *  WebView's `blockNetworkLoads`, which the "Show images" button exists to clear. */
    @Test
    fun renderableBody_stripsABodyFarPastTheOldScanCeiling() {
        val padding = "<p>x</p>".repeat(80_000)
        val body = padding + "<img src=\"https://tracker.example/beacon.png\">"
        assertTrue("the fixture must exceed the old 512 KB ceiling", body.length > 512 * 1024)

        val rendered = renderableBody(body, darkPalette, "", isDark = true)

        assertFalse(rendered.stripped.contains("tracker.example"))
        assertTrue("and the images bar must still offer it", rendered.hasRemoteImages)
    }

    /** A `<style>` beacon — which the old regex could not see at all — is stripped from BOTH
     *  variants, and the images bar stays hidden.
     *
     *  Both halves are deliberate. `blockExternalResources` scrubs `<style>` regardless of
     *  `keepImages`, so there is nothing "Show images" could restore here: offering the bar would
     *  promise pictures that do not exist and clear `blockNetworkLoads` for nothing. The flag
     *  answers "is there an image to show", and the beacon's safety does not depend on it —
     *  which is the whole reason stripping is no longer gated on the flag. */
    @Test
    fun renderableBody_stripsAStyleOnlyBeaconFromBothVariantsAndOffersNoBar() {
        val body = "<style>div{background:url(https://tracker.example/b.png)}</style><div>Hi</div>"

        val rendered = renderableBody(body, darkPalette, "", isDark = true)

        assertFalse(rendered.stripped.contains("tracker.example"))
        assertFalse("not even behind Show images", rendered.withImages.contains("tracker.example"))
        assertFalse(rendered.hasRemoteImages)
    }

    /** And when a message carries both, pressing "Show images" restores the picture WITHOUT
     *  reviving the stylesheet beacon riding along with it. */
    @Test
    fun renderableBody_showImagesDoesNotReviveAStyleBeacon() {
        val body = "<style>div{background:url(https://tracker.example/b.png)}</style>" +
            "<img src=\"https://pictures.example/i.png\">"

        val rendered = renderableBody(body, darkPalette, "", isDark = true)

        assertTrue(rendered.hasRemoteImages)
        assertTrue(rendered.withImages.contains("pictures.example"))
        assertFalse(rendered.withImages.contains("tracker.example"))
    }

    @Test
    fun renderableBody_reportsNoRemoteImagesForAPlainBody() {
        val rendered = renderableBody("<p>Just words.</p>", darkPalette, "", isDark = true)

        assertFalse(rendered.hasRemoteImages)
        assertEquals(rendered.stripped, rendered.withImages)
    }

    /** "Show images" means images, and only images: every other remote resource stays stripped. */
    @Test
    fun renderableBody_keepsOnlyImagesInTheShowImagesVariant() {
        val body = "<img src=\"https://a.example/i.png\"><iframe src=\"https://b.example/f\"></iframe>"

        val rendered = renderableBody(body, darkPalette, "", isDark = true)

        assertTrue(rendered.withImages.contains("a.example"))
        assertFalse("the iframe must stay stripped", rendered.withImages.contains("b.example"))
        assertFalse(rendered.stripped.contains("a.example"))
    }

    /** `srcdoc` is a whole inline document, not a URL: removing `src` never touched it, so the
     *  frame kept its beacons and fired them the moment "Show images" cleared blockNetworkLoads.
     *  The frame goes entirely, as the composer's Safelist already does with it. */
    @Test
    fun renderableBody_dropsAnIframeSrcdocPayloadFromBothVariants() {
        val body = "<iframe srcdoc=\"&lt;img src=https://tracker.example/b.png&gt;\"></iframe><p>Hi</p>"

        val rendered = renderableBody(body, darkPalette, "", isDark = true)

        assertFalse(rendered.stripped.contains("tracker.example"))
        assertFalse("the frame itself must be gone", rendered.stripped.contains("iframe", ignoreCase = true))
        assertFalse("not even behind Show images", rendered.withImages.contains("tracker.example"))
        assertFalse(rendered.withImages.contains("srcdoc", ignoreCase = true))
        assertFalse("nothing here is an image the user asked for", rendered.hasRemoteImages)
    }

    /** And pressing "Show images" on a message carrying both restores the picture without
     *  reviving the frame riding along with it. */
    @Test
    fun renderableBody_showImagesDoesNotReviveAnIframeSrcdoc() {
        val body = "<img src=\"https://pictures.example/i.png\">" +
            "<iframe srcdoc=\"&lt;link rel=stylesheet href=https://tracker.example/b.css&gt;\"></iframe>"

        val rendered = renderableBody(body, darkPalette, "", isDark = true)

        assertTrue(rendered.hasRemoteImages)
        assertTrue(rendered.withImages.contains("pictures.example"))
        assertFalse(rendered.withImages.contains("tracker.example"))
        assertFalse(rendered.withImages.contains("iframe", ignoreCase = true))
    }

    /** `[^)]*` stops at the FIRST `)`, which in a quoted CSS url is not the closing one: the old
     *  regex replaced `url("http://x/a)` and left `b")` — the tail of the URL it meant to remove. */
    @Test
    fun blockExternalResources_stripsAUrlContainingAQuotedParenthesis() {
        val blocked = blockExternalResources(
            "<div style=\"background:url('https://tracker.example/a)b.png')\">Hi</div>",
        )

        assertFalse(blocked.contains("tracker.example"))
        assertFalse("no fragment of the URL may survive", blocked.contains("b.png"))
    }

    @Test
    fun blockExternalResources_stripsNestedResourceFunctions() {
        val blocked = blockExternalResources(
            "<div style=\"background:image-set(url(https://a.example/1x.png) 1x, url(https://a.example/2x.png) 2x)\">Hi</div>",
        )

        assertFalse(blocked.contains("a.example"))
    }

    /** `image-set()` takes a bare string as a URL, with no `url()` for the scan to find inside. */
    @Test
    fun blockExternalResources_stripsABareStringInsideImageSet() {
        val blocked = blockExternalResources(
            "<div style=\"background:image-set('https://tracker.example/x.png' 1x)\">Hi</div>",
        )

        assertFalse(blocked.contains("tracker.example"))
    }

    /** An unbalanced call consumes to the end of the declaration rather than being skipped: a
     *  strip that cannot find the end of what it is removing must not leave the remainder. */
    @Test
    fun blockExternalResources_failsClosedOnAnUnterminatedUrl() {
        val blocked = blockExternalResources(
            "<style>div{background:url(https://tracker.example/x.png</style>",
        )

        assertFalse(blocked.contains("tracker.example"))
    }

    /** The identifier boundary: only a real function call is a call. */
    @Test
    fun blockExternalResources_doesNotMatchUrlInsideALongerIdentifier() {
        val blocked = blockExternalResources("<div style=\"color:#fff;--my-url:red\">Hi</div>")

        assertTrue(blocked.contains("--my-url"))
    }

    @Test
    fun blockExternalResources_failsClosedWhenTheMarkupCannotBeParsed() {
        val hostile = "<img src=\"https://tracker.example/beacon\">"

        val blocked = blockExternalResources(hostile) { throw StackOverflowError("nested too deep") }

        assertFalse("a parse failure must not pass the markup through", blocked.contains("<img"))
        assertTrue("the reader keeps their context as escaped text", blocked.contains("&lt;img"))
    }

    private val darkPalette = ThemePalette(
        bg = "#1a1a1e",
        panel = "#252530",
        ink = "#d4c5e2",
        inkStrong = "#e8ddf5",
        accent = "#c29a72",
        line = "#404050",
        avatarGradientStart = "#c29a72",
        avatarGradientEnd = "#9a7450",
        avatarBorder = "#8f6b4a",
    )

    private val lightPalette = ThemePalette(
        bg = "#f5efe5",
        panel = "#fff8ee",
        ink = "#4c3d32",
        inkStrong = "#2d1f15",
        accent = "#c29a72",
        line = "#c5b29d",
        avatarGradientStart = "#c29a72",
        avatarGradientEnd = "#9a7450",
        avatarBorder = "#8f6b4a",
    )

    /** An email that only sets its own text color (the "black text on the app's default dark
     *  background" half of the reported bug) — the wildcard `!important` override must still win. */
    private val emailWithOwnTextColorOnly =
        """<div style="color:#000000">Hello, this text sets its own black color.</div>"""

    /** An email that sets both its own background and text color (the "black text on white,
     *  ignoring the app's theme" half of the reported bug). */
    private val emailWithOwnBackgroundAndTextColor =
        """<table bgcolor="#ffffff"><tr><td style="color:#000000">Hi</td></tr></table>"""

    @Test
    fun darkPalette_forcesTextAndBackgroundColorsWithImportant_overridingAnyEmailStyle() {
        val html = buildEmailBodyHtml(emailWithOwnTextColorOnly, darkPalette, monoFontFace = "", isDark = true)

        assertTrue(html.contains("body * {"))
        assertTrue(html.contains("color: ${darkPalette.inkStrong} !important;"))
        assertTrue(html.contains("background-color: transparent !important;"))
        assertTrue(html.contains("background-color: ${darkPalette.bg} !important;"))
        assertTrue(html.contains(emailWithOwnTextColorOnly))
    }

    @Test
    fun darkPalette_keepsLinksOnAccentColor_afterTheWildcardOverride() {
        val html = buildEmailBodyHtml(emailWithOwnBackgroundAndTextColor, darkPalette, monoFontFace = "", isDark = true)

        val wildcardIndex = html.indexOf("body * {")
        val linkRuleIndex = html.indexOf("body a, body a * {")
        assertTrue("link color override must come after the wildcard rule to win the cascade", linkRuleIndex > wildcardIndex)
        assertTrue(html.contains("color: ${darkPalette.accent} !important;"))
    }

    @Test
    fun lightPalette_doesNotForceOverridesAtAll() {
        val html = buildEmailBodyHtml(emailWithOwnBackgroundAndTextColor, lightPalette, monoFontFace = "", isDark = false)

        assertFalse(html.contains("body * {"))
        assertFalse(html.contains("!important"))
        assertTrue(html.contains("color: ${lightPalette.inkStrong};"))
        assertTrue(html.contains("background-color: ${lightPalette.bg};"))
    }

    @Test
    fun plainTextBody_wrapsLongLinesWithoutHorizontalOverflow() {
        val html = buildEmailBodyHtml(
            emailBodyToHtml("a".repeat(500), "plain"),
            lightPalette,
            monoFontFace = "",
            isDark = false,
        )

        assertTrue(html.contains("overflow-x: hidden;"))
        assertTrue(html.contains("min-width: 0;"))
        assertTrue(html.contains("max-width: 100%;"))
        assertTrue(html.contains("width: 100%;"))
        assertTrue(html.contains("word-wrap: break-word;"))
        assertTrue(html.contains("word-break: break-all;"))
    }

    @Test
    fun darkPalette_stripsImportantFromAnEmailThatDefendsItsOwnWhiteBackground() {
        val email = """<table style="background-color:#ffffff !important; color:#000000!important"><tr><td>Hi</td></tr></table>"""

        val html = buildEmailBodyHtml(email, darkPalette, monoFontFace = "", isDark = true)

        val emailPortion = html.substringAfter("<table")
        assertFalse(emailPortion.contains("important", ignoreCase = true))
        assertTrue(emailPortion.contains("#ffffff"))
        assertTrue(emailPortion.contains("#000000"))
    }

    @Test
    fun lightPalette_leavesImportantInTheEmailUntouched() {
        val email = """<table style="background-color:#ffffff !important"><tr><td>Hi</td></tr></table>"""

        val html = buildEmailBodyHtml(email, lightPalette, monoFontFace = "", isDark = false)

        assertTrue(html.contains(email))
    }

    @Test
    fun stripImportantFromCss_removesLowercaseImportant() {
        assertEquals("color:#000000", stripImportantFromCss("color:#000000 !important"))
    }

    @Test
    fun stripImportantFromCss_isCaseInsensitive() {
        assertEquals("color:#000000", stripImportantFromCss("color:#000000 !IMPORTANT"))
    }

    @Test
    fun stripImportantFromCss_toleratesNoSpaceBeforeImportant() {
        assertEquals("color:#000000", stripImportantFromCss("color:#000000!important"))
    }

    @Test
    fun stripImportantFromCss_consumesLeadingWhitespace() {
        assertEquals("color:#000000", stripImportantFromCss("color:#000000    !important"))
    }

    @Test
    fun stripImportantFromCss_removesCommentSplitImportant() {
        assertEquals("color:#000000", stripImportantFromCss("color:#000000!/**/important"))
        assertEquals("color:#000000", stripImportantFromCss("color:#000000 !/*x*/important"))
    }

    @Test
    fun stripImportantFromCss_removesEscapeSplitImportant() {
        // \49 is the CSS escape for code point 0x49 ("I"), so this decodes to "!Important".
        assertEquals("color:#000000", stripImportantFromCss("""color:#000000!\49 mportant"""))
    }

    @Test
    fun stripImportantFromCss_survivesEscapesAboveTheUnicodeCodespace() {
        // CSS_ESCAPE accepts six hex digits (0xFFFFFF); Character.toChars throws above 0x10FFFF.
        for (hex in listOf("110000", "ffffff", "FFFFFF", "7FFFFF")) {
            val input = """color:red !\$hex mportant"""
            assertEquals(input, stripImportantFromCss(input))
        }
    }

    @Test
    fun stripImportantFromCss_stillDecodesTheHighestValidCodePoint() {
        // 0x10FFFF is the last valid code point — the boundary the guard must not over-reject.
        val input = """color:red !\10FFFF mportant"""
        assertEquals(input, stripImportantFromCss(input))
    }

    @Test
    fun stripImportant_removesEveryOccurrenceInStyleAttributesAndStyleBlocks() {
        val input = """<div style="color:#000 !important; background:#fff !important"><style>.x{color:red!important}</style></div>"""
        assertFalse(stripImportant(input).contains("important", ignoreCase = true))
    }

    @Test
    fun stripImportant_leavesEverythingElseUnchanged() {
        val input = """<div style="color:#000000">plain text, no important here</div>"""
        assertEquals(input, stripImportant(input))
    }

    @Test
    fun stripImportant_doesNotRewriteBodyText() {
        val input = "<p>Great job! Hope you're well. This is !important to me.</p>"
        assertEquals(input, stripImportant(input))
    }

    @Test
    fun stripImportant_terminatesQuicklyOnHostileBodies() {
        val hostile = listOf(
            "/*" + "a".repeat(200_000),
            " ".repeat(200_000),
            " ".repeat(200_000) + "!",
            "<p>" + "x".repeat(600_000) + "</p>",
        )
        hostile.forEach { body ->
            val elapsed = kotlin.system.measureTimeMillis { stripImportant(body) }
            assertTrue("stripImportant took ${elapsed}ms", elapsed < 2_000)
        }
    }

    @Test
    fun stripImportant_stillCleansLargeBodies() {
        val huge = """<div style="color:#000 !important">""" + "x".repeat(600_000) + "</div>"
        assertFalse(stripImportant(huge).contains("important", ignoreCase = true))
    }

    @Test
    fun safeFileName_stripsPathsAndControlCharacters() {
        assertEquals("invoice", safeFileName("../../etc/invoice.pdf"))
        assertEquals("invoice", safeFileName("""C:\windows\invoice.pdf"""))
        assertEquals("attachment", safeFileName(""))
        assertEquals("attachment", safeFileName("///"))
        assertEquals("hidden", safeFileName(".hidden"))
        assertEquals(120, safeFileName("a".repeat(500)).length)
    }

    @Test
    fun safeFileName_takesItsExtensionFromTheDeclaredTypeNotTheSenderName() {
        assertEquals("invoice.pdf", safeFileName("invoice.pdf", "application/pdf"))
        assertEquals("invoice.pdf", safeFileName("invoice.exe", "application/pdf"))
        assertEquals("invoice", safeFileName("invoice.pdf\u0000.apk", "application/octet-stream"))
        assertEquals("photo.jpg", safeFileName("photo.jpeg", "image/jpeg"))
        assertEquals("payload", safeFileName("payload.apk", "application/vnd.android.package-archive"))
        // Ordinary dotted names keep their text: only short alphanumeric trailing segments count
        // as extensions.
        assertEquals("minutes.2026 Q1 final", safeFileName("minutes.2026 Q1 final", ""))
    }

    @Test
    fun safeMimeType_downgradesAnythingNotOnTheAllowlist() {
        assertEquals("application/pdf", safeMimeType("application/pdf"))
        assertEquals("application/pdf", safeMimeType("Application/PDF; charset=utf-8"))
        // A type only the sender's own app claims would otherwise make it the sole resolver.
        assertEquals("application/octet-stream", safeMimeType("application/vnd.attacker-x"))
        assertEquals("application/octet-stream", safeMimeType(""))
    }

    /** Mailers that label every file application/octet-stream cost the user the extension: a PDF
     *  saved as "invoice" with no type opened nowhere. */
    @Test
    fun safeMimeType_fallsBackToTheSenderExtensionWhenTheDeclaredTypeIsOpaque() {
        assertEquals("application/pdf", safeMimeType("application/octet-stream", "invoice.pdf"))
        assertEquals("application/pdf", safeMimeType("application/x-pdf", "Invoice.PDF"))
        assertEquals("image/jpeg", safeMimeType("", "photo.jpeg"))
        assertEquals("invoice.pdf", safeFileName("invoice.pdf", safeMimeType("application/octet-stream", "invoice.pdf")))
        // Only the final extension counts, and only benign ones; the declared type wins when known.
        assertEquals("application/octet-stream", safeMimeType("application/octet-stream", "invoice.pdf.apk"))
        assertEquals("application/octet-stream", safeMimeType("application/octet-stream", "payload.apk"))
        assertEquals("image/jpeg", safeMimeType("image/jpeg", "photo.pdf"))
    }

    @Test
    fun downloadsResolveOpaqueTypeBeforeSanitisingTheRawName() {
        val metadata = org.kysecurity.mail.security.attachmentDownloadMetadata(
            "invoice.pdf",
            "application/octet-stream",
        )

        assertEquals("application/pdf", metadata.mimeType)
        assertEquals("invoice.pdf", metadata.displayName)
    }

    /** The ephemeral sink handed the sender's filename to the chooser verbatim while the Downloads
     *  sink sanitised it; the display name is what a viewer persists the file under. */
    @Test
    fun ephemeralDisplayName_getsTheSameSanitisationAsTheDownloadsName() {
        val hostile = org.kysecurity.mail.security.PendingAttachment(
            bytes = ByteArray(0),
            mimeType = "application/pdf",
            displayName = "../../etc/invoice.pdf.apk",
        )
        assertEquals("invoice.pdf", hostile.displayName)

        val long = org.kysecurity.mail.security.PendingAttachment(ByteArray(0), "", "a".repeat(500))
        assertEquals(120, long.displayName.length)
    }

    // isDarkPalette() needs android.graphics.Color, so it is not covered here; isDark is passed in.

    private val nonRetryableOutcomes = listOf(
        ReadOutcome.Decrypted(
            body = DecryptedBody(html = "<p>hi</p>", plain = null, protectedSubject = null),
            signature = PgpSignatureState.NONE,
            resolvedSender = "bob@example.com",
        ),
        ReadOutcome.NeedsUnlock,
        ReadOutcome.Cancelled,
        ReadOutcome.NotEnrolled,
        ReadOutcome.NoSecureLockScreen,
        ReadOutcome.TooLarge,
        ReadOutcome.NotClientProtected,
        ReadOutcome.UnsealFailed("could not open"),
        ReadOutcome.NoEncryptedContent,
        ReadOutcome.DecryptFailed("bad padding"),
    )

    @Test
    fun showsRetryButton_isTrueOnlyForFetchFailed() {
        assertTrue(showsRetryButton(ReadOutcome.FetchFailed("network error")))
    }

    @Test
    fun showsRetryButton_isFalseForEveryOtherExitTableRow() {
        nonRetryableOutcomes.forEach { outcome ->
            assertFalse("expected no Retry for $outcome", showsRetryButton(outcome))
        }
    }

    @Test
    fun showsRetryButton_isFalseForNoEncryptedContent() {
        assertFalse(showsRetryButton(ReadOutcome.NoEncryptedContent))
    }

    /** Every row of the exit table that leaves the message unread. */
    private val failureOutcomes = listOf(
        ReadOutcome.NotEnrolled,
        ReadOutcome.NoSecureLockScreen,
        ReadOutcome.TooLarge,
        ReadOutcome.NotClientProtected,
        ReadOutcome.NoEncryptedContent,
        ReadOutcome.UnsealFailed("could not open"),
        ReadOutcome.FetchFailed("network error"),
        ReadOutcome.DecryptFailed("bad padding"),
    )

    @Test
    fun readFailureNotice_namesEveryFailureRowOfTheExitTable() {
        failureOutcomes.forEach { outcome ->
            assertNotNull("no notice for $outcome", readFailureNotice(outcome))
        }
    }

    /** The regression this pins: all eight rendered as one wordless padlock, so a decrypt that
     *  failed on THIS device was indistinguishable from one the server had refused. */
    @Test
    fun readFailureNotice_givesEveryFailureItsOwnSentence() {
        val ids = failureOutcomes.map { readFailureNotice(it)?.first }
        assertEquals(failureOutcomes.size, ids.toSet().size)
    }

    /** The detail is the whole point on this row: "bad padding" and "not encrypted to a key on
     *  this device" are different bugs behind the same padlock. */
    @Test
    fun readFailureNotice_carriesTheDetailOfAnOnDeviceDecryptFailure() {
        val notice = readFailureNotice(ReadOutcome.DecryptFailed("bad padding"))
        assertEquals(R.string.email_pgp_decrypt_here_failed, notice?.first)
        assertEquals("bad padding", notice?.second)
    }

    @Test
    fun readFailureNotice_isNullWhereTheScreenStillOffersDecrypt() {
        assertNull(readFailureNotice(ReadOutcome.NeedsUnlock))
        assertNull(readFailureNotice(ReadOutcome.Cancelled))
    }

    @Test
    fun readFailureNotice_isNullForASuccessfulRead() {
        val decrypted = ReadOutcome.Decrypted(
            body = decryptedBody,
            signature = PgpSignatureState.NONE,
            resolvedSender = "bob@example.com",
        )
        assertNull(readFailureNotice(decrypted))
    }

    private val decryptedBody = DecryptedBody(html = "<p>hi</p>", plain = null, protectedSubject = null)

    @Test
    fun displaySignatureVerdict_passesThroughASignatureWithAResolvedSender() {
        val outcome = ReadOutcome.Decrypted(
            body = decryptedBody,
            signature = PgpSignatureState.VERIFIED_CONFIRMED,
            resolvedSender = "bob@example.com",
        )
        assertEquals(PgpSignatureState.VERIFIED_CONFIRMED, displaySignatureVerdict(outcome))
    }

    @Test
    fun displaySignatureVerdict_suppressesASignatureWithNoResolvedSender() {
        val outcome = ReadOutcome.Decrypted(
            body = decryptedBody,
            signature = PgpSignatureState.SIGNER_UNKNOWN,
            resolvedSender = "",
        )
        assertEquals(PgpSignatureState.NONE, displaySignatureVerdict(outcome))
    }

    @Test
    fun displaySignatureVerdict_passesThroughUnsignedWithNoResolvedSender() {
        val outcome = ReadOutcome.Decrypted(
            body = decryptedBody,
            signature = PgpSignatureState.UNSIGNED,
            resolvedSender = "",
        )
        assertEquals(PgpSignatureState.UNSIGNED, displaySignatureVerdict(outcome))
    }

    @Test
    fun displaySignatureVerdict_isNoneWhenTheReadOutcomeItselfIsNone() {
        val outcome = ReadOutcome.Decrypted(
            body = decryptedBody,
            signature = PgpSignatureState.NONE,
            resolvedSender = "bob@example.com",
        )
        assertEquals(PgpSignatureState.NONE, displaySignatureVerdict(outcome))
    }

    @Test
    fun mayReplyOrForward_isFalseForClientProtected() {
        assertFalse(mayReplyOrForward(PgpMessageState.CLIENT_PROTECTED))
    }

    @Test
    fun mayReplyOrForward_isTrueForEveryOtherState() {
        PgpMessageState.entries.filter { it != PgpMessageState.CLIENT_PROTECTED }.forEach { state ->
            assertTrue("expected $state to allow reply/forward", mayReplyOrForward(state))
        }
    }

    @Test
    fun initialReplyForwardState_failsClosedWhenEncrypted() {
        val state = initialReplyForwardState(pgpEncrypted = true)
        assertEquals(PgpMessageState.CLIENT_PROTECTED, state)
        assertFalse(mayReplyOrForward(state))
    }

    @Test
    fun initialReplyForwardState_isNoneWhenNotEncrypted() {
        assertEquals(PgpMessageState.NONE, initialReplyForwardState(pgpEncrypted = false))
    }

    @Test
    fun blockExternalResources_keepsInlineRasterDataImages() {
        val blocked = blockExternalResources(
            """<img src="data:image/png;base64,iVBORw=="><img src="https://x/y.png">""",
            keepInlineDataImages = true,
        )

        assertTrue(blocked, blocked.contains("data:image/png;base64,iVBORw=="))
        assertTrue(blocked, !blocked.contains("https://x/y.png"))
    }

    @Test
    fun blockExternalResources_stillStripsDataSvgAndNonImageData() {
        val blocked = blockExternalResources(
            """<img src="data:image/svg+xml;base64,PHN2Zz4="><img src="data:text/html;base64,PGI+">""",
            keepInlineDataImages = true,
        )

        assertTrue(blocked, !blocked.contains("data:"))
    }

    @Test
    fun blockExternalResources_inlineDataImagesDoNotCountAsRemote() {
        val html = """<img src="data:image/png;base64,iVBORw==">"""
        assertEquals(
            blockExternalResources(html, keepInlineDataImages = true),
            blockExternalResources(html, keepImages = true, keepInlineDataImages = true),
        )
    }

    @Test
    fun blockExternalResources_stripsInlineDataImagesByDefault() {
        val blocked = blockExternalResources("""<img src="data:image/png;base64,iVBORw==">""")

        assertTrue(blocked, !blocked.contains("data:image/png;base64,iVBORw=="))
    }

    @Test
    fun blockExternalResources_keptInlineImageStillLosesSrcset() {
        val blocked = blockExternalResources(
            """<img src="data:image/png;base64,iVBORw==" srcset="https://tracker/x.png 2x">""",
            keepInlineDataImages = true,
        )

        assertTrue(blocked, blocked.contains("data:image/png;base64,iVBORw=="))
        assertTrue(blocked, !blocked.contains("srcset"))
        assertTrue(blocked, !blocked.contains("tracker"))
    }

    @Test
    fun decryptedAttachmentNotice_onlyWhenSomethingWasDropped() {
        assertNull(decryptedAttachmentNotice(omitted = false))
        assertEquals(R.string.email_pgp_attachments_omitted, decryptedAttachmentNotice(omitted = true))
    }
}
