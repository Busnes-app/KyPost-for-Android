package org.kysecurity.mail.ui

import android.app.Activity
import android.graphics.Color
import android.graphics.drawable.ColorDrawable
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.FOLLOW_SYSTEM_THEME
import org.kysecurity.mail.ThemesActivity
import org.kysecurity.mail.getStoredThemeName
import org.kysecurity.mail.saveThemeName
import org.kysecurity.mail.signon.KyIdentitySignOnActivity
import org.kysecurity.mail.themePaletteFor

/** "Follow system" repaints when the system night mode flips, with no app restart. */
@RunWith(AndroidJUnit4::class)
class FollowSystemThemeTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()

    private fun shell(command: String): String =
        ParcelFileDescriptor.AutoCloseInputStream(instrumentation.uiAutomation.executeShellCommand(command))
            .bufferedReader().use { it.readText() }

    private fun nightMode(mode: String) {
        shell("cmd uimode night $mode")
        instrumentation.waitForIdleSync()
    }

    /** A recreated screen. */
    @Test
    fun themesScreenFollowsTheSystem() = assertFollowsSystem(ThemesActivity::class.java)

    /** Declares uiMode in configChanges, so it repaints in onConfigurationChanged instead. */
    @Test
    fun kyIdentitySignOnFollowsTheSystem() = assertFollowsSystem(KyIdentitySignOnActivity::class.java)

    private fun <A : Activity> assertFollowsSystem(screen: Class<A>) {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val previousTheme = getStoredThemeName(context)
        // "Night mode: yes|no|auto|custom"
        val previousMode = shell("cmd uimode night").substringAfter(':').trim()
        saveThemeName(context, FOLLOW_SYSTEM_THEME)
        try {
            nightMode("no")
            ActivityScenario.launch(screen).use { scenario ->
                assertEquals(bg(systemDark = false), awaitDecorColor(scenario, bg(systemDark = false)))
                nightMode("yes")
                assertEquals(bg(systemDark = true), awaitDecorColor(scenario, bg(systemDark = true)))
            }
        } finally {
            nightMode(previousMode)
            saveThemeName(context, previousTheme)
        }
    }

    private fun bg(systemDark: Boolean) = Color.parseColor(themePaletteFor(FOLLOW_SYSTEM_THEME, systemDark).bg)

    /** The night-mode change is posted by the system, so idle sync alone does not cover it. */
    private fun <A : Activity> awaitDecorColor(scenario: ActivityScenario<A>, expected: Int): Int {
        val deadline = SystemClock.uptimeMillis() + 10_000
        var color = decorColor(scenario)
        while (color != expected && SystemClock.uptimeMillis() < deadline) {
            SystemClock.sleep(100)
            color = decorColor(scenario)
        }
        return color
    }

    private fun <A : Activity> decorColor(scenario: ActivityScenario<A>): Int {
        var color = 0
        scenario.onActivity { color = (it.window.decorView.background as? ColorDrawable)?.color ?: 0 }
        return color
    }
}
