package org.kysecurity.mail

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** Unbounded keywords could OOM InboxActivity.onCreate permanently, so the set is capped. */
@RunWith(AndroidJUnit4::class)
class KeywordSettingsBoundsTest {

    private lateinit var context: Context

    @Before
    fun clearStore() {
        context = ApplicationProvider.getApplicationContext()
        context.deleteSharedPreferences(KeywordSettings.PREFS_NAME)
        org.kysecurity.mail.security.HostileLocationSettings(context).setEnabled(false)
    }

    @Test
    fun rememberKeywords_capsTheRememberedSetSize() {
        val settings = KeywordSettings(context)
        settings.rememberKeywords((1..5_000).map { "label-$it" }.toSet())

        assertEquals(KeywordSettings.MAX_REMEMBERED_KEYWORDS, settings.getAllKeywords().size)
    }

    @Test
    fun rememberKeywords_dropsOverlongLabels() {
        val settings = KeywordSettings(context)
        val overlong = "x".repeat(KeywordSettings.MAX_KEYWORD_LENGTH + 1)
        settings.rememberKeywords(setOf("Work", overlong))

        val stored = settings.getAllKeywords()
        assertTrue("expected the normal label to survive", stored.contains("Work"))
        assertFalse("expected the overlong label to be dropped", stored.contains(overlong))
    }

    /** Eviction keeps the most recently seen labels, so an attacker flooding the set cannot push out
     *  the user's real ones and then have them silently reappear in a different order. */
    @Test
    fun rememberKeywords_evictsOldestFirst() {
        val settings = KeywordSettings(context)
        settings.rememberKeywords(setOf("first-label"))
        settings.rememberKeywords((1..KeywordSettings.MAX_REMEMBERED_KEYWORDS).map { "flood-$it" }.toSet())

        val stored = settings.getAllKeywords()
        assertEquals(KeywordSettings.MAX_REMEMBERED_KEYWORDS, stored.size)
        assertFalse("expected the oldest entry to be evicted", stored.contains("first-label"))
    }

    @Test
    fun keywordOrder_persistsAndAppendsNewKeywords() {
        val settings = KeywordSettings(context)
        settings.rememberKeywords(linkedSetOf("Alpha", "Beta", "Gamma"))
        settings.setKeywordOrder(listOf("Gamma", "Alpha", "Beta"))

        assertEquals(listOf("Gamma", "Alpha", "Beta"), settings.getOrderedKeywords())

        settings.rememberKeywords(setOf("Delta"))
        assertEquals(listOf("Gamma", "Alpha", "Beta", "Delta"), settings.getOrderedKeywords())
    }

    /** The inbox remembers every keyword a row carries, IMAP flags included; those are not tabs. */
    @Test
    fun rememberKeywords_dropsImapSystemKeywords() {
        val settings = KeywordSettings(context)
        settings.rememberKeywords(setOf("\$Phishing", "\\Seen", "Work"))

        assertEquals(listOf("Work"), settings.getOrderedKeywords())
    }

    /** An install that stored them before the write-side filter must not keep their chips. */
    @Test
    fun getOrderedKeywords_hidesSystemKeywordsAlreadyStored() {
        context.getSharedPreferences(KeywordSettings.PREFS_NAME, Context.MODE_PRIVATE).edit()
            .putStringSet("all_keywords", setOf("\$Phishing", "Work"))
            .putString("keyword_order", """["${'$'}Phishing","Work"]""")
            .commit()

        assertEquals(listOf("Work"), KeywordSettings(context).getOrderedKeywords())
    }

    /** Under Hostile Location Protection the labels describe the user's mail and must not reach this
     *  plaintext file at all. */
    @Test
    fun rememberKeywords_writesNothingUnderHostileLocationProtection() {
        org.kysecurity.mail.security.HostileLocationSettings(context).setEnabled(true)
        try {
            val settings = KeywordSettings(context)
            settings.rememberKeywords(setOf("Payroll", "Legal"))

            assertTrue(settings.getAllKeywords().isEmpty())
        } finally {
            org.kysecurity.mail.security.HostileLocationSettings(context).setEnabled(false)
        }
    }
}
