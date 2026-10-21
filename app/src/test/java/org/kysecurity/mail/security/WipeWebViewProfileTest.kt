package org.kysecurity.mail.security

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/** The `webViewState` wipe step. A resumed wipe failed it on every launch, because clearing
 *  WebView through its statics loads Chromium, which recreates the profile under the delete. */
class WipeWebViewProfileTest {
    @get:Rule val temp = TemporaryFolder()

    private fun plantedProfile(): File = temp.newFolder("app_webview").also {
        File(it, "Default").mkdirs()
        File(it, "Default/Cookies").writeText("host-level record")
    }

    @Test
    fun aColdStartDeletesTheProfileWithoutTouchingWebView() = runBlocking {
        val profile = plantedProfile()
        SecurityWipe.clearWebViewProfile(profile, clearLiveWebView = null)
        assertFalse(profile.exists())
    }

    @Test
    fun aLiveWebViewIsClearedBeforeItsProfileIsDeleted() = runBlocking {
        val profile = plantedProfile()
        val order = mutableListOf<String>()
        SecurityWipe.clearWebViewProfile(profile) { order += if (profile.exists()) "live-before-delete" else "late" }
        assertEquals(listOf("live-before-delete"), order)
        assertFalse(profile.exists())
    }
}
