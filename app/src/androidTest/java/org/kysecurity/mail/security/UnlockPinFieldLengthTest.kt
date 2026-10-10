package org.kysecurity.mail.security

import android.widget.EditText
import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.closeSoftKeyboard
import androidx.test.espresso.action.ViewActions.typeText
import androidx.test.espresso.matcher.ViewMatchers.withId
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.R

@RunWith(AndroidJUnit4::class)
class UnlockPinFieldLengthTest {

    @Test
    fun unlockFieldHoldsAMaximumLengthPinAndNoMore() {
        runBlocking { withTimeout(30_000) { SecurityWipe.startupVerdict.await() } }
        ActivityScenario.launch(UnlockActivity::class.java).use { scenario ->
            onView(withId(R.id.unlockPinField))
                .perform(typeText("4".repeat(PinPolicy.MAX_LENGTH + 1)), closeSoftKeyboard())
            scenario.onActivity { activity ->
                val field = activity.findViewById<EditText>(R.id.unlockPinField)
                assertEquals(PinPolicy.MAX_LENGTH, field.text.length)
            }
        }
    }
}
