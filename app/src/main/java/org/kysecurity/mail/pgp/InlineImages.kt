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
