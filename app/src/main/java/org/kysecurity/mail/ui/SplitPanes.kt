package org.kysecurity.mail.ui

import android.app.Activity
import androidx.activity.ComponentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.window.embedding.ActivityEmbeddingController
import androidx.window.embedding.SplitAttributes
import androidx.window.embedding.SplitController
import androidx.window.layout.WindowMetricsCalculator
import kotlinx.coroutines.launch

/**
 * Calls [onChange] with whether [activity] is one pane of an Activity Embedding split: once now,
 * then on every change while it is started.
 *
 * A pane can't be told from a phone by width (a ~373dp pane resolves the phone layout), so the
 * screens that move the navigation between panes ask this instead.
 */
fun observeSplitPane(activity: ComponentActivity, onChange: (Boolean) -> Unit) {
    onChange(isSplitPaneNow(activity))
    activity.lifecycleScope.launch {
        activity.repeatOnLifecycle(Lifecycle.State.STARTED) {
            SplitController.getInstance(activity).splitInfoList(activity).collect { splits ->
                // Below splitMinWidthDp the pair is still reported, as an EXPAND split: one pane at a time.
                onChange(splits.any { it.splitAttributes.splitType != SplitAttributes.SplitType.SPLIT_TYPE_EXPAND })
            }
        }
    }
}

/** isActivityEmbedded alone is not enough: an Activity the rule keeps full width (a message
 *  below the split width) is embedded too, in a container as wide as the window. */
private fun isSplitPaneNow(activity: Activity): Boolean {
    if (!ActivityEmbeddingController.getInstance(activity).isActivityEmbedded(activity)) return false
    val metrics = WindowMetricsCalculator.getOrCreate()
    return metrics.computeCurrentWindowMetrics(activity).bounds.width() <
        metrics.computeMaximumWindowMetrics(activity).bounds.width()
}
