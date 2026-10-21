package org.kysecurity.mail

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** A view added to a phone layout but not to the rail layout a `values-*` alias swaps in passes
 *  every phone test and crashes `findViewById` on a tablet or a Fold cover screen. */
class LayoutVariantIdsTest {

    @Test
    fun everyBaseLayoutIdExistsInItsVariants() {
        val res = listOf(File("src/main/res"), File("app/src/main/res")).first { it.isDirectory }
        val aliases = res.listFiles { f -> f.isDirectory && f.name.startsWith("values-") }.orEmpty()
            .mapNotNull { File(it, "layouts.xml").takeIf(File::isFile) }
            .flatMap { file ->
                ALIAS.findAll(file.readText()).map { "${file.parentFile?.name}: ${it.groupValues[1]} -> ${it.groupValues[2]}" to it }
            }
        assertTrue("No layout aliases found under $res", aliases.isNotEmpty())
        val missing = aliases.flatMap { (label, match) ->
            val base = ids(res, match.groupValues[1])
            val variant = ids(res, match.groupValues[2])
            (base - variant).map { "$label: $it" }
        }
        assertEquals(emptyList<String>(), missing)
    }

    /** Ids in `layout/<name>.xml`, following `<include>` so a shared body counts once. */
    private fun ids(res: File, name: String): Set<String> {
        val text = File(res, "layout/$name.xml").readText()
        val own = Regex("""@\+id/(\w+)""").findAll(text).map { it.groupValues[1] }.toSet()
        val included = Regex("""<include[^>]*layout="@layout/(\w+)"""").findAll(text)
            .flatMap { ids(res, it.groupValues[1]) }
        return own + included
    }

    private companion object {
        val ALIAS = Regex("""<item name="(\w+)" type="layout">@layout/(\w+)</item>""")
    }
}
