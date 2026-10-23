package org.kysecurity.mail.signon

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory

class AuthenticatorPinTest {
    private val pinned = AuthenticatorPin.PINS.first()
    private val kyauth = "org.kysecurity.authenticator"

    @Test
    fun decide_acceptsKyAuthWithPinnedCert() {
        assertTrue(AuthenticatorPin.decide(listOf(kyauth), { setOf(pinned) }, null))
    }

    @Test
    fun decide_acceptsProductionPlaySignersAndRotationHistory() {
        val play = "d419c37003033b87630a67f0f27f2295546ebd134956d3f37b20282964317f41"
        val classical = "c3b2a095228c2b80d4646b162dc3478542ff36c692619c0da6a8aa49f8fb11e5"
        val hybrid = "293d7cd424179eed61003a2d4e1f21f1fb9e41faafc666837c5bf1fab330bc7f"
        for (history in listOf(setOf(play), setOf(classical), setOf(hybrid), setOf(play, classical, hybrid))) {
            assertTrue("Genuine Play KyAuth signing history must be trusted: $history",
                AuthenticatorPin.decide(listOf(kyauth), { history }, null))
            assertFalse(AuthenticatorPin.decide(listOf(kyauth), { history + "00".repeat(32) }, null))
        }
    }

    @Test
    fun decide_refusesWrongPackageOrCert() {
        assertFalse(AuthenticatorPin.decide(listOf("com.evil"), { setOf(pinned) }, null))
        assertFalse(AuthenticatorPin.decide(listOf(kyauth), { setOf("00".repeat(32)) }, null))
        assertFalse(AuthenticatorPin.decide(listOf(kyauth), { emptySet() }, null))
    }

    @Test
    fun decide_refusesAnyUnpinnedCertInHistory() {
        assertFalse(AuthenticatorPin.decide(listOf(kyauth), { setOf(pinned, "00".repeat(32)) }, null))
    }

    @Test
    fun decide_refusesMultiple() {
        assertFalse(AuthenticatorPin.decide(listOf(kyauth, "com.evil"), { setOf(pinned) }, null))
        assertFalse(AuthenticatorPin.decide(listOf(kyauth, kyauth), { setOf(pinned) }, null))
        assertFalse(AuthenticatorPin.decide(emptyList(), { setOf(pinned) }, null))
    }

    @Test
    fun decide_debugDigestOnlyWhenSupplied() {
        val debug = "ab".repeat(32)
        assertFalse(AuthenticatorPin.decide(listOf(kyauth), { setOf(debug) }, null))
        assertTrue(AuthenticatorPin.decide(listOf(kyauth), { setOf(debug) }, debug))
    }

    @Test
    fun pins_areRealDigests() {
        assertTrue(AuthenticatorPin.PINS.isNotEmpty())
        assertTrue(AuthenticatorPin.PINS.all { Regex("[0-9a-f]{64}").matches(it) })
    }

    @Test
    fun manifest_declaresKyAuthUnderQueries() {
        var dir: File? = File("").absoluteFile
        while (dir != null && !File(dir, "src/main/AndroidManifest.xml").isFile) {
            dir = File(dir, "app").takeIf { File(it, "src/main/AndroidManifest.xml").isFile } ?: dir.parentFile
        }
        val manifest = File(dir ?: error("AndroidManifest.xml not found"), "src/main/AndroidManifest.xml")
        val doc = DocumentBuilderFactory.newInstance().apply { isNamespaceAware = true }
            .newDocumentBuilder().parse(manifest)
        val names = (0 until doc.getElementsByTagName("queries").length).flatMap { q ->
            val pkgs = doc.getElementsByTagName("queries").item(q).childNodes
            (0 until pkgs.length).map { pkgs.item(it) }.filter { it.nodeName == "package" }
                .map { it.attributes.getNamedItem("android:name")?.nodeValue }
        }
        assertTrue(names.contains(AuthenticatorPin.KYAUTH_PACKAGE))
    }
}
