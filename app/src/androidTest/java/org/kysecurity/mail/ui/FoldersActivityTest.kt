package org.kysecurity.mail.ui

import android.app.Activity
import android.content.Intent
import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onIdle
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.action.ViewActions.replaceText
import androidx.test.espresso.assertion.ViewAssertions.doesNotExist
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.RootMatchers.isPlatformPopup
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withContentDescription
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
import org.kysecurity.mail.FoldersActivity
import org.kysecurity.mail.R
import org.kysecurity.mail.afterSplash
import org.kysecurity.mail.mail.FolderInfo
import org.kysecurity.mail.mail.FolderListResult
import org.kysecurity.mail.mail.MailOutcome
import org.kysecurity.mail.mail.MailRuntime
import java.util.concurrent.atomic.AtomicInteger

/** The folders screen against a relay the test controls: what the row menu offers, and what each
 *  dialog sends. */
@RunWith(AndroidJUnit4::class)
class FoldersActivityTest {

    private val source = FakeMailSource()
    private val archiveListings = AtomicInteger()
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Before
    fun installRelay() {
        MailRuntime.invalidate()
        MailRuntime.sourceForTest = source
        source.folders = { parent ->
            if (parent == "Archive") archiveListings.incrementAndGet()
            val folders = when (parent) {
                null -> listOf(FolderInfo("Work", deletable = false))
                "Archive" -> listOf(FolderInfo("Archive/Old", deletable = true))
                else -> emptyList()
            }
            MailOutcome.Success(FolderListResult(parent.orEmpty(), folders))
        }
    }

    @After
    fun releaseRelay() {
        MailRuntime.sourceForTest = null
        MailRuntime.invalidate()
    }

    @Test
    fun aTopLevelFolderOffersNoRenameOrDelete() {
        launch(FoldersActivity.intentFor(context)).use {
            eventually { onView(withText("Archive")).check(matches(isDisplayed())) }
            onView(withContentDescription("More options for Work")).perform(click())

            onView(withText(R.string.folders_subfolders)).inRoot(isPlatformPopup()).check(matches(isDisplayed()))
            onView(withText(R.string.folders_rename)).inRoot(isPlatformPopup()).check(doesNotExist())
            onView(withText(R.string.folders_delete)).inRoot(isPlatformPopup()).check(doesNotExist())
        }
    }

    @Test
    fun tappingAFolderReturnsItsPath() {
        launchForResult(FoldersActivity.intentFor(context)).use { scenario ->
            eventually { onView(withText("Work")).perform(click()) }

            assertEquals(Activity.RESULT_OK, scenario.result.resultCode)
            assertEquals("Work", scenario.result.resultData.getStringExtra(FoldersActivity.EXTRA_FOLDER))
        }
    }

    @Test
    fun aTopLevelFolderIsCreatedOnlyAfterTheWarningAndAValidName() {
        launch(FoldersActivity.intentFor(context)).use {
            eventually { onView(withText("Work")).check(matches(isDisplayed())) }
            onView(withId(R.id.foldersNew)).perform(click())
            onView(withText(R.string.folders_top_level_note)).inRoot(isDialog()).check(matches(isDisplayed()))

            onView(withId(R.id.foldersNameInput)).perform(replaceText("a/b"))
            onView(withId(android.R.id.button1)).perform(click())
            onIdle()
            assertEquals(emptyList<List<String>>(), source.folderCalls.toList())

            // Still open, so the name is fixed in place rather than retyped.
            onView(withId(R.id.foldersNameInput)).perform(replaceText("Receipts"))
            onView(withId(android.R.id.button1)).perform(click())
            assertTrue(awaitCall(listOf("create", "", "Receipts")))
        }
    }

    @Test
    fun renameSendsTheNewLeaf() {
        launch(FoldersActivity.intentFor(context, "Archive")).use {
            eventually { onView(withContentDescription("More options for Old")).perform(click()) }
            onView(withText(R.string.folders_rename)).inRoot(isPlatformPopup()).perform(click())
            onView(withId(R.id.foldersNameInput)).perform(replaceText("Older"))
            onView(withId(android.R.id.button1)).perform(click())

            assertTrue(awaitCall(listOf("rename", "Archive/Old", "Older")))
        }
    }

    @Test
    fun renamingTheInboxsOpenFolderSendsTheInboxToItsNewPath() {
        val intent = FoldersActivity.intentFor(context, "Archive", open = "Archive/Old")
        launchForResult(intent).use { scenario ->
            eventually { onView(withContentDescription("More options for Old")).perform(click()) }
            onView(withText(R.string.folders_rename)).inRoot(isPlatformPopup()).perform(click())
            onView(withId(R.id.foldersNameInput)).perform(replaceText("Older"))
            onView(withId(android.R.id.button1)).perform(click())
            assertTrue(awaitCall(listOf("rename", "Archive/Old", "Older")))
            // The screen relists after setting the result, on the same main-thread turn.
            eventually { assertTrue(archiveListings.get() >= 2) }
            scenario.onActivity { it.onBackPressedDispatcher.onBackPressed() }

            assertEquals(Activity.RESULT_OK, scenario.result.resultCode)
            assertEquals("Archive/Older", scenario.result.resultData.getStringExtra(FoldersActivity.EXTRA_FOLDER))
        }
    }

    @Test
    fun deleteSaysWhereTheMailGoesBeforeDeleting() {
        launch(FoldersActivity.intentFor(context, "Archive")).use {
            eventually { onView(withContentDescription("More options for Old")).perform(click()) }
            onView(withText(R.string.folders_delete)).inRoot(isPlatformPopup()).perform(click())

            val message = context.getString(R.string.folders_delete_confirm, "Old", "Archive")
            eventually { onView(withText(message)).inRoot(isDialog()).check(matches(isDisplayed())) }
            assertEquals(emptyList<List<String>>(), source.folderCalls.toList())
            onView(withId(android.R.id.button1)).perform(click())

            assertTrue(awaitCall(listOf("delete", "Archive/Old")))
        }
    }

    private fun launch(intent: Intent): ActivityScenario<FoldersActivity> =
        ActivityScenario.launch<FoldersActivity>(intent).afterSplash()

    private fun launchForResult(intent: Intent): ActivityScenario<FoldersActivity> =
        ActivityScenario.launchActivityForResult<FoldersActivity>(intent).afterSplash()

    private fun awaitCall(call: List<String>): Boolean {
        val deadline = System.nanoTime() + 10_000_000_000L
        while (System.nanoTime() < deadline) {
            if (call in source.folderCalls.toList()) return true
            Thread.sleep(20)
        }
        return false
    }

    /** The list loads on a worker Espresso does not watch. */
    private fun eventually(check: () -> Unit) {
        val deadline = System.nanoTime() + 10_000_000_000L
        while (true) {
            try {
                return check()
            } catch (e: Throwable) {
                if (System.nanoTime() > deadline) throw e
                Thread.sleep(50)
            }
        }
    }
}
