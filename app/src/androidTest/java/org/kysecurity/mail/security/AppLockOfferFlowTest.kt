package org.kysecurity.mail.security

import android.graphics.Color
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withId
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.R
import org.kysecurity.mail.SettingsActivity
import org.kysecurity.mail.getStoredThemePalette

/** The offer is made once per install, never repeated, and answered "Not now" for good. Runs on
 *  the CI device, which has no app lock (every Activity test requires an unlocked app). */
@RunWith(AndroidJUnit4::class)
class AppLockOfferFlowTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Before
    @After
    fun forgetTheOffer() {
        context.deleteSharedPreferences("org.kysecurity.mail.app_lock_offer")
    }

    @Test
    fun declinedOnceItIsNotAskedAgainAfterRecreation() {
        ActivityScenario.launch(SettingsActivity::class.java).use { scenario ->
            scenario.onActivity { assertTrue(AppLockOffer.showIfDue(it)) }
            onView(withText(R.string.app_lock_offer_title)).inRoot(isDialog()).check(matches(isDisplayed()))
            onView(withText(R.string.app_lock_offer_decline)).inRoot(isDialog()).perform(click())
            InstrumentationRegistry.getInstrumentation().waitForIdleSync()

            scenario.recreate()
            // Asked of the offer, not of a window root: on API 31 a recreated Activity can take
            // a while to regain focus, and Espresso's root lookup times out on that, not on us.
            scenario.onActivity { assertFalse(AppLockOffer.showIfDue(it)) }
        }
    }

    @Test
    fun theOfferUsesTheActivePalette() {
        ActivityScenario.launch(SettingsActivity::class.java).use { scenario ->
            scenario.onActivity { AppLockOffer.showIfDue(it) }
            onView(withId(androidx.appcompat.R.id.alertTitle)).inRoot(isDialog()).check { view, _ ->
                val expected = Color.parseColor(getStoredThemePalette(view.context).inkStrong)
                assertEquals(expected, (view as TextView).currentTextColor)
            }
            onView(withText(R.string.app_lock_offer_decline)).inRoot(isDialog()).perform(click())
        }
    }
}
