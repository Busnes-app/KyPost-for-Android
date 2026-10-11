package org.kysecurity.mail

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** A view added to `layout/` but not `layout-w600dp/` passes every phone test and crashes
 *  `findViewById` on a tablet. */
class LayoutVariantIdsTest {

    @Test
    fun everyBaseLayoutIdExistsInItsVariants() {
        val res = listOf(File("src/main/res"), File("app/src/main/res")).first { it.isDirectory }
        val variants = res.listFiles { f -> f.isDirectory && f.name.startsWith("layout-") }.orEmpty()
            .flatMap { it.listFiles { f -> f.extension == "xml" }.orEmpty().toList() }
        assertTrue("No layout variants found under $res", variants.isNotEmpty())
        val missing = variants.flatMap { variant ->
            val base = File(res, "layout/${variant.name}")
            (ids(base) - ids(variant)).map { "${variant.parentFile?.name}/${variant.name}: $it" }
        }
        assertEquals(emptyList<String>(), missing)
    }

    private fun ids(file: File): Set<String> =
        Regex("""@\+id/(\w+)""").findAll(file.readText()).map { it.groupValues[1] }.toSet()
}
