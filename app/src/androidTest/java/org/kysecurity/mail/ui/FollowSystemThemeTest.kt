package org.kysecurity.mail.ui

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
import org.kysecurity.mail.themePaletteFor

/** "Follow system" repaints when the system night mode flips, with no app restart. */
@RunWith(AndroidJUnit4::class)
class FollowSystemThemeTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()

    private fun shell(command: String): String =
        ParcelFileDescriptor.AutoCloseInputStream(instrumentation.uiAutomation.executeShellCommand(command))
            .bufferedReader().use { it.readText() }

    private fun nightMode(on: Boolean) {
        shell("cmd uimode night " + if (on) "yes" else "no")
        instrumentation.waitForIdleSync()
    }

    @Test
    fun followSystemSwitchesBetweenBusnesLightAndDark() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val previousTheme = getStoredThemeName(context)
        val wasNight = shell("cmd uimode night").contains("yes")
        saveThemeName(context, FOLLOW_SYSTEM_THEME)
        try {
            nightMode(false)
            ActivityScenario.launch(ThemesActivity::class.java).use { scenario ->
                assertEquals(bg(systemDark = false), decorColor(scenario))
                nightMode(true)
                assertEquals(bg(systemDark = true), awaitDecorColor(scenario, bg(systemDark = true)))
            }
        } finally {
            nightMode(wasNight)
            saveThemeName(context, previousTheme)
        }
    }

    private fun bg(systemDark: Boolean) = Color.parseColor(themePaletteFor(FOLLOW_SYSTEM_THEME, systemDark).bg)

    /** The night-mode recreate is posted by the system, so idle sync alone does not cover it. */
    private fun awaitDecorColor(scenario: ActivityScenario<ThemesActivity>, expected: Int): Int {
        val deadline = SystemClock.uptimeMillis() + 10_000
        var color = decorColor(scenario)
        while (color != expected && SystemClock.uptimeMillis() < deadline) {
            SystemClock.sleep(100)
            color = decorColor(scenario)
        }
        return color
    }

    private fun decorColor(scenario: ActivityScenario<ThemesActivity>): Int {
        var color = 0
        scenario.onActivity { color = (it.window.decorView.background as ColorDrawable).color }
        return color
    }
}
