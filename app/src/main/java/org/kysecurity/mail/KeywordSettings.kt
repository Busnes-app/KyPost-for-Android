package org.kysecurity.mail

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONArray

class KeywordSettings(context: Context) {
    private val prefs: SharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    private val hostileLocationSettings = org.kysecurity.mail.security.HostileLocationSettings(context)

    fun getAllKeywords(): Set<String> = prefs.getStringSet(KEY_ALL_KEYWORDS, emptySet()) ?: emptySet()

    fun getOrderedKeywords(): List<String> {
        val all = getAllKeywords()
        val saved = runCatching {
            val array = JSONArray(prefs.getString(KEY_KEYWORD_ORDER, "[]"))
            List(array.length()) { array.getString(it) }
        }.getOrDefault(emptyList())
        // Filtered on read as well as on write: an install that stored the label before the
        // write-side filter existed must not keep a relay-made All chip.
        return (saved.filter { it in all } + all.sortedBy { it.lowercase() })
            .filterNot { it.isAllTab() }
            .distinct()
    }

    /** Bounded both ways: keywords are unvalidated relay input rendered as un-recycled Chips. */
    fun rememberKeywords(keywords: Set<String>) {
        if (keywords.isEmpty()) return
        // Labels describe the user's mail: never persist them to this plaintext file in hostile mode.
        if (hostileLocationSettings.isEnabled()) return
        // The All tab is app-owned; a relay label spelt the same must not become a second one.
        val cleaned = keywords.asSequence()
            .map { it.trim() }
            .filter { it.isNotBlank() && it.length <= MAX_KEYWORD_LENGTH }
            .filterNot { it.isAllTab() }
            .toSet()
        if (cleaned.isEmpty()) return
        // LinkedHashSet: insertion-ordered, so takeLast() drops the oldest entries.
        val merged = LinkedHashSet(getOrderedKeywords()).apply { addAll(cleaned) }
        val capped = if (merged.size <= MAX_REMEMBERED_KEYWORDS) {
            merged
        } else {
            LinkedHashSet(merged.toList().takeLast(MAX_REMEMBERED_KEYWORDS))
        }
        prefs.edit()
            .putStringSet(KEY_ALL_KEYWORDS, capped)
            .putString(KEY_KEYWORD_ORDER, JSONArray(capped.toList()).toString())
            .apply()
    }

    fun setKeywordOrder(keywords: List<String>) {
        val all = getAllKeywords()
        val ordered = (keywords.filter { it in all } + getOrderedKeywords()).distinct()
        prefs.edit().putString(KEY_KEYWORD_ORDER, JSONArray(ordered).toString()).apply()
    }

    /** Its own key, not `keyword_visible_All`: that namespace is fed by unvalidated relay labels. */
    fun isAllTabVisible(): Boolean = prefs.getBoolean(KEY_ALL_TAB_VISIBLE, true)

    fun setAllTabVisible(visible: Boolean) {
        prefs.edit().putBoolean(KEY_ALL_TAB_VISIBLE, visible).apply()
    }

    fun isKeywordVisible(keyword: String): Boolean = prefs.getBoolean(keyForVisibility(keyword), true)

    fun setKeywordVisible(keyword: String, visible: Boolean) {
        prefs.edit().putBoolean(keyForVisibility(keyword), visible).apply()
    }

    fun filterVisible(keywords: Set<String>): Set<String> {
        return keywords.filter { isKeywordVisible(it) }.toSet()
    }

    private fun keyForVisibility(keyword: String): String = "keyword_visible_$keyword"

    private fun String.isAllTab(): Boolean = equals(KeywordTabs.ALL, ignoreCase = true)

    companion object {
        const val PREFS_NAME = "org.kysecurity.mail.keyword_settings"
        private const val KEY_ALL_KEYWORDS = "all_keywords"
        private const val KEY_KEYWORD_ORDER = "keyword_order"
        private const val KEY_ALL_TAB_VISIBLE = "all_tab_visible"

        /** Long enough for any real mail label, short enough that the widest possible chip still
         *  measures cheaply. */
        internal const val MAX_KEYWORD_LENGTH = 64

        /** Chips are inflated one-per-entry with no recycling, on the main thread. */
        internal const val MAX_REMEMBERED_KEYWORDS = 200
    }
}
