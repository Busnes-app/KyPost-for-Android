package org.kysecurity.mail.security

import org.junit.Test
import org.w3c.dom.Element
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** PIN length is [PinPolicy]'s to decide; a layout limit can silently disagree with it. */
class PinLayoutLengthTest {

    @Test
    fun noNumericPasswordFieldInALayoutHardcodesMaxLength() {
        val dir = listOf(File(LAYOUT_ROOT), File("app/$LAYOUT_ROOT")).first { it.isDirectory }
        val pinFields = dir.listFiles { f -> f.extension == "xml" }!!.flatMap { file ->
            val root = DocumentBuilderFactory.newInstance().apply { isNamespaceAware = true }
                .newDocumentBuilder().parse(file).documentElement
            val nodes = root.getElementsByTagName("*")
            ((0 until nodes.length).map { nodes.item(it) as Element } + root)
                .filter { it.getAttributeNS(ANDROID, "inputType").contains("numberPassword") }
                .map { file.name to it }
        }
        assertTrue(pinFields.any { it.first == "activity_unlock.xml" }, "unlock PIN field not found")
        val offenders = pinFields.filter { it.second.hasAttributeNS(ANDROID, "maxLength") }.map { it.first }
        assertEquals(emptyList(), offenders, "Cap PIN fields in code with PinPolicy.MAX_LENGTH.")
    }

    private companion object {
        const val LAYOUT_ROOT = "src/main/res/layout"
        const val ANDROID = "http://schemas.android.com/apk/res/android"
    }
}
