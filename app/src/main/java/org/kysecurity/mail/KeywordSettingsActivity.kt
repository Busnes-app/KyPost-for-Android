package org.kysecurity.mail

import android.os.Bundle
import android.view.ViewGroup
import android.widget.CheckBox
import android.widget.LinearLayout
import android.widget.TextView
import androidx.recyclerview.widget.ItemTouchHelper
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import org.kysecurity.mail.security.LockedActivity

class KeywordSettingsActivity : LockedActivity() {

    private lateinit var keywordSettings: KeywordSettings

    override fun onCreateUnlocked(savedInstanceState: Bundle?) {
        keywordSettings = KeywordSettings(this)
        setTitle(R.string.keyword_settings_title)

        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dpToPx(20), dpToPx(20), dpToPx(20), dpToPx(20))
        }

        applyTopInsetWithHeader(this, container)

        val intro = TextView(this).apply {
            text = getString(R.string.keyword_settings_intro)
            textSize = 14f
        }
        container.addViewSpaced(intro, bottomDp = 16)

        val allTab = CheckBox(this).apply {
            text = KeywordTabs.ALL
            textSize = 15f
            minHeight = dpToPx(48)
            isChecked = keywordSettings.isAllTabVisible()
            setOnCheckedChangeListener { _, checked -> keywordSettings.setAllTabVisible(checked) }
        }
        applyCheckBoxTheme(this, allTab)
        container.addViewSpaced(allTab, bottomDp = 4)

        val allKeywords = keywordSettings.getOrderedKeywords().toMutableList()
        if (allKeywords.isEmpty()) {
            val emptyView = TextView(this).apply {
                text = getString(R.string.keyword_settings_empty)
                textSize = 14f
            }
            applyEmptyStateBackground(this, emptyView)
            container.addViewSpaced(emptyView, bottomDp = 12)
        } else {
            val adapter = KeywordAdapter(allKeywords)
            val list = RecyclerView(this).apply {
                layoutManager = LinearLayoutManager(this@KeywordSettingsActivity)
                this.adapter = adapter
                clipToPadding = false
            }
            ItemTouchHelper(object : ItemTouchHelper.SimpleCallback(
                ItemTouchHelper.UP or ItemTouchHelper.DOWN,
                0,
            ) {
                override fun onMove(
                    recyclerView: RecyclerView,
                    viewHolder: RecyclerView.ViewHolder,
                    target: RecyclerView.ViewHolder,
                ): Boolean {
                    val from = viewHolder.bindingAdapterPosition
                    val to = target.bindingAdapterPosition
                    if (from == RecyclerView.NO_POSITION || to == RecyclerView.NO_POSITION) return false
                    allKeywords.add(to, allKeywords.removeAt(from))
                    adapter.notifyItemMoved(from, to)
                    return true
                }

                override fun onSwiped(viewHolder: RecyclerView.ViewHolder, direction: Int) = Unit

                override fun clearView(recyclerView: RecyclerView, viewHolder: RecyclerView.ViewHolder) {
                    super.clearView(recyclerView, viewHolder)
                    keywordSettings.setKeywordOrder(allKeywords)
                }
            }).attachToRecyclerView(list)
            container.addView(list, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                0,
                1f,
            ))
        }

        setContentView(container)
        applyThemeToActivity(this)
    }

    private inner class KeywordAdapter(private val keywords: List<String>) :
        RecyclerView.Adapter<KeywordAdapter.ViewHolder>() {

        inner class ViewHolder(val checkbox: CheckBox) : RecyclerView.ViewHolder(checkbox)

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
            return ViewHolder(CheckBox(parent.context).apply {
                textSize = 15f
                minHeight = dpToPx(48)
            })
        }

        override fun onBindViewHolder(holder: ViewHolder, position: Int) {
            val keyword = keywords[position]
            holder.checkbox.setOnCheckedChangeListener(null)
            holder.checkbox.text = keyword
            holder.checkbox.isChecked = keywordSettings.isKeywordVisible(keyword)
            applyCheckBoxTheme(this@KeywordSettingsActivity, holder.checkbox)
            holder.checkbox.setOnCheckedChangeListener { _, isChecked ->
                keywordSettings.setKeywordVisible(keyword, isChecked)
            }
        }

        override fun getItemCount(): Int = keywords.size
    }
}
