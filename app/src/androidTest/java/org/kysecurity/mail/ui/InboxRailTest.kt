package org.kysecurity.mail.ui

import android.content.Intent
import android.view.View
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry
import androidx.test.runner.lifecycle.Stage
import com.google.android.material.navigation.NavigationBarView
import com.google.android.material.navigationrail.NavigationRailView
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.EmailDetailActivity
import org.kysecurity.mail.InboxActivity
import org.kysecurity.mail.R

/** nav_is_rail and the layout share a qualifier, so this passes on both phone and tablet. */
@RunWith(AndroidJUnit4::class)
class InboxRailTest {

    @Test
    fun navWidgetMatchesTheBoolResource() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val expectRail = context.resources.getBoolean(R.bool.nav_is_rail)

        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val nav = activity.findViewById<NavigationBarView>(R.id.bottomNavigation)
                assertEquals(expectRail, nav is NavigationRailView)
                assertEquals(5, nav.menu.size())
                assertEquals(context.getString(R.string.nav_inbox), nav.menu.findItem(R.id.nav_inbox).title.toString())

                activity.setFolderForTest("Junk", "All")
                assertEquals(context.getString(R.string.nav_junk), nav.menu.findItem(R.id.nav_inbox).title.toString())
            }
        }
    }

    @Test
    fun leavingAScreenDoesNotChangeItsRememberedHighlight() {
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val nav = activity.findViewById<NavigationBarView>(R.id.bottomNavigation)

                nav.selectedItemId = R.id.nav_compose

                assertEquals(R.id.nav_inbox, nav.selectedItemId)
            }
        }
    }

    /** The rail is on the window's end edge, where the split's message pane keeps its own copy. */
    @Test
    fun railSitsOnTheEndEdge() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assumeTrue("needs a w600dp window", context.resources.getBoolean(R.bool.nav_is_rail))

        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val nav = activity.findViewById<View>(R.id.bottomNavigation)
                val location = IntArray(2).also { nav.getLocationInWindow(it) }
                val rtl = nav.layoutDirection == View.LAYOUT_DIRECTION_RTL
                if (rtl) {
                    assertEquals(0, location[0])
                } else {
                    assertEquals(activity.window.decorView.width, location[0] + nav.width)
                }
            }
        }
    }

    /** Outside a split the message screen has a rail exactly where a full-width screen would. */
    @Test
    fun messageScreenRailFollowsTheWidthOutsideASplit() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val expected = if (context.resources.getBoolean(R.bool.nav_is_rail)) View.VISIBLE else View.GONE
        val intent = Intent(context, EmailDetailActivity::class.java).putExtra("email_preview", "body")

        ActivityScenario.launch<EmailDetailActivity>(intent).use { scenario ->
            scenario.onActivity { activity ->
                assertEquals(expected, activity.findViewById<View>(R.id.detailRail).visibility)
            }
        }
    }

    /** Below the split width the pair is still reported, as an EXPAND split, which is not two
     *  panes: a message opened from the inbox on a phone must not grow a rail. */
    @Test
    fun messageOpenedFromTheInboxBelowTheSplitWidthFollowsTheWidth() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        assumeTrue("needs a window below the 840dp split", context.resources.configuration.screenWidthDp < 840)
        val expected = if (context.resources.getBoolean(R.bool.nav_is_rail)) View.VISIBLE else View.GONE

        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity {
                it.startActivity(Intent(it, EmailDetailActivity::class.java).putExtra("email_preview", "body"))
            }
            var detail: EmailDetailActivity? = null
            // Generous: on a paired device the inbox is also refreshing real mail.
            repeat(150) {
                if (detail == null) {
                    instrumentation.runOnMainSync {
                        detail = ActivityLifecycleMonitorRegistry.getInstance()
                            .getActivitiesInStage(Stage.RESUMED).filterIsInstance<EmailDetailActivity>().firstOrNull()
                    }
                    if (detail == null) Thread.sleep(100)
                }
            }
            assertNotNull("message screen never resumed", detail)
            // Let the split flow deliver its first value.
            Thread.sleep(500)
            instrumentation.runOnMainSync {
                assertEquals(expected, detail!!.findViewById<View>(R.id.detailRail).visibility)
                detail!!.finish()
            }
        }
    }
}
