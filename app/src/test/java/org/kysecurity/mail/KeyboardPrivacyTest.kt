package org.kysecurity.mail

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** Every text field asks the keyboard not to learn what is typed: recipients, subjects, searches,
 *  PINs, server addresses and contacts all leave this app through a keyboard's personal
 *  dictionary otherwise. The compose body is a `final` library WebView and cannot be reached. */
class KeyboardPrivacyTest {

    private fun dir(path: String) = listOf(File(path), File("app/$path")).first { it.isDirectory }

    @Test
    fun everyLayoutTextFieldOptsOutOfLearning() {
        val res = dir("src/main/res")
        val fields = res.listFiles { f -> f.isDirectory && f.name.startsWith("layout") }.orEmpty()
            .flatMap { it.listFiles { f -> f.extension == "xml" }.orEmpty().toList() }
            .flatMap { file -> XML_FIELD.findAll(file.readText()).map { "${file.parentFile?.name}/${file.name}" to it.value } }
        assertTrue("no text fields found under $res", fields.isNotEmpty())
        val offenders = fields.filterNot { (_, tag) -> "flagNoPersonalizedLearning" in tag }.map { it.first }
        assertEquals(emptyList<String>(), offenders)
    }

    @Test
    fun everyFieldBuiltInCodeOptsOutOfLearning() {
        val sources = dir("src/main/java").walkTopDown().filter { it.extension == "kt" }.toList()
        val offenders = sources.flatMap { file ->
            val lines = file.readLines()
            lines.withIndex()
                .filter { (_, line) -> CODE_FIELD.containsMatchIn(line) && !line.trimStart().startsWith("import ") }
                .filterNot { (i, _) -> lines.drop(i).take(3).any { OPT_OUT.containsMatchIn(it) } }
                .map { (i, line) -> "${file.name}:${i + 1}: ${line.trim()}" }
        }
        assertEquals(emptyList<String>(), offenders)
    }

    private companion object {
        val XML_FIELD = Regex(
            """<(EditText|AutoCompleteTextView|MultiAutoCompleteTextView|com\.google\.android\.material\.textfield\.TextInputEditText)\b[^>]*>""",
        )
        val CODE_FIELD = Regex("""\b(EditText|AutoCompleteTextView|SearchView)\((this|activity|context)""")
        val OPT_OUT = Regex("""noPersonalizedLearning\(\)|IME_FLAG_NO_PERSONALIZED_LEARNING""")
    }
}
