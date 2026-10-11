package org.kysecurity.mail.ui

import android.app.Instrumentation
import android.content.Intent
import android.graphics.Color
import android.text.Spanned
import android.text.style.TypefaceSpan
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.withId
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.EmailDetailActivity
import org.kysecurity.mail.R
import org.kysecurity.mail.getStoredThemePalette
import org.kysecurity.mail.mail.MailRuntime

/** A tapped web link leaves the app only after the user confirmed the host it really goes to,
 *  and then exactly that parsed address. */
@RunWith(AndroidJUnit4::class)
class EmailDetailLinkConfirmTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()

    /** Records outgoing VIEW intents and blocks them, so no browser starts. */
    private class ViewIntents : Instrumentation.ActivityMonitor() {
        val started = mutableListOf<Intent>()
        override fun onStartActivity(intent: Intent): Instrumentation.ActivityResult? {
            if (intent.action != Intent.ACTION_VIEW) return null
            started += intent
            return Instrumentation.ActivityResult(0, null)
        }
    }

    private val views = ViewIntents()

    @Before
    fun watch() {
        instrumentation.addMonitor(views)
    }

    @After
    fun release() {
        instrumentation.removeMonitor(views)
        MailRuntime.invalidate()
    }

    private fun launch(suspicious: Boolean = false): ActivityScenario<EmailDetailActivity> =
        ActivityScenario.launch(
            Intent(instrumentation.targetContext, EmailDetailActivity::class.java)
                .putExtra("email_preview", "body")
                .putExtra("email_suspicious", suspicious),
        )

    private val raw = "https://bank.example@evil.example/a b"

    @Test
    fun cancelSendsNothingAndOpenSendsTheParsedAddress() {
        launch().use { scenario ->
            scenario.onActivity { it.openLinkForTest(raw) }
            assertEquals(0, views.started.size)
            onView(withText(android.R.string.cancel)).inRoot(isDialog()).perform(click())
            assertEquals(0, views.started.size)

            scenario.onActivity { it.openLinkForTest(raw) }
            onView(withText(R.string.email_link_confirm_open)).inRoot(isDialog()).perform(click())
            instrumentation.waitForIdleSync()
            assertEquals(listOf("https://bank.example@evil.example/a%20b"), views.started.map { it.dataString })
        }
    }

    @Test
    fun theDialogShowsTheRealHostInMonoAndThePalette() {
        launch().use { scenario ->
            scenario.onActivity { it.openLinkForTest(raw) }
            onView(withId(android.R.id.message)).inRoot(isDialog()).check { view, _ ->
                val message = view as TextView
                val text = message.text
                assertTrue(text.toString(), text.contains("evil.example"))
                val spans = (text as Spanned).getSpans(0, text.length, TypefaceSpan::class.java)
                val hostStart = text.indexOf("evil.example")
                assertTrue("the host is not in a monospace span", spans.any { text.getSpanStart(it) <= hostStart && text.getSpanEnd(it) > hostStart })
                assertEquals(Color.parseColor(getStoredThemePalette(view.context).ink), message.currentTextColor)
            }
            onView(withText(android.R.string.cancel)).inRoot(isDialog()).perform(click())
        }
    }

    @Test
    fun aPhishingFlaggedMessageWarnsInTheDialog() {
        launch(suspicious = true).use { scenario ->
            scenario.onActivity { it.openLinkForTest(raw) }
            onView(withId(android.R.id.message)).inRoot(isDialog()).check { view, _ ->
                val expected = view.context.getString(R.string.email_link_confirm_phishing)
                assertTrue((view as TextView).text.contains(expected))
            }
            onView(withText(android.R.string.cancel)).inRoot(isDialog()).perform(click())
        }
    }
}
