package org.kysecurity.mail

import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File

/** STYLE_GUIDE.md §6: dialogs are native but wear the active palette. A dialog is its own window,
 *  so the Activity's theme walk misses it; these sites must go through `showThemed()`. */
class ThemedDialogsTest {

    @Test
    fun theseDialogsUseTheActivePalette() {
        val root = listOf(File("src/main/java"), File("app/src/main/java")).first { it.isDirectory }
        val offenders = SITES.filterNot { (file, function) ->
            val source = File(root, "org/kysecurity/mail/$file").readText()
            val body = source.substringAfter("fun $function(", missingDelimiterValue = "")
                .let { rest -> NEXT_FUNCTION.find(rest)?.let { rest.substring(0, it.range.first) } ?: rest }
            "showThemed()" in body && ".showSecurely()" !in body
        }
        assertEquals(emptyList<Pair<String, String>>(), offenders)
    }

    private companion object {
        val NEXT_FUNCTION = Regex("""\n\s*(private |internal )?fun """)
        val SITES = listOf(
            "MoveToFolder.kt" to "pickMoveTarget",
            "MailSignature.kt" to "showSignatureDialog",
        )
    }
}
