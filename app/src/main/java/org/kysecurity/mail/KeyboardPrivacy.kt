package org.kysecurity.mail

import android.view.inputmethod.EditorInfo
import android.widget.TextView

/** Asks the keyboard not to learn from this field (Gboard's incognito mode). A request a keyboard
 *  may ignore. XML fields say `flagNoPersonalizedLearning`; `KeyboardPrivacyTest` checks both. */
fun TextView.noPersonalizedLearning() {
    imeOptions = imeOptions or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
}
