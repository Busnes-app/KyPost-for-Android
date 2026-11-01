package org.kysecurity.mail.ui

import android.annotation.SuppressLint
import android.content.Context
import androidx.startup.Initializer
import androidx.window.WindowSdkExtensions
import androidx.window.embedding.RuleController
import androidx.window.embedding.SplitAttributes
import androidx.window.embedding.SplitController
import androidx.window.layout.FoldingFeature
import org.kysecurity.mail.R

// Rules must be registered before the pair they describe launches; androidx.startup runs earliest.
class SplitInitializer : Initializer<RuleController> {

    // RequiresWindowSdk: lint does not follow the extensionVersion guard just below.
    @SuppressLint("RequiresWindowSdk")
    override fun create(context: Context): RuleController {
        // The calculator needs vendor extensions 2+; below that the rules' own 0.4 ratio stands.
        if (WindowSdkExtensions.getInstance().extensionVersion >= 2) {
            SplitController.getInstance(context).setSplitAttributesCalculator { params ->
                val fold = params.parentWindowLayoutInfo.displayFeatures.filterIsInstance<FoldingFeature>().firstOrNull()
                when {
                    !params.areDefaultConstraintsSatisfied ->
                        SplitAttributes.Builder().setSplitType(SplitAttributes.SplitType.SPLIT_TYPE_EXPAND).build()
                    splitsAtHinge(fold) -> SplitAttributes.Builder()
                        .setSplitType(SplitAttributes.SplitType.SPLIT_TYPE_HINGE)
                        .setLayoutDirection(params.defaultSplitAttributes.layoutDirection)
                        .build()
                    else -> params.defaultSplitAttributes
                }
            }
        }
        return RuleController.getInstance(context).apply {
            setRules(RuleController.parseRules(context, R.xml.split_config))
        }
    }

    override fun dependencies(): List<Class<out Initializer<*>>> = emptyList()
}

/** A fold that separates the panes (half open like a book, or an occluding hinge) and runs top to
 *  bottom gets the list on one side and the message on the other, never across it. A flat,
 *  non-occluding fold keeps the 40/60 split: nothing there to avoid. */
internal fun splitsAtHinge(fold: FoldingFeature?): Boolean =
    fold != null && fold.isSeparating && fold.orientation == FoldingFeature.Orientation.VERTICAL
