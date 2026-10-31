package org.kysecurity.mail.push

/** The Play review login's hidden entry: [REQUIRED] taps on "Use Firebase" before the first pairing.
 *
 *  Hiding it is not what protects it. The relay answers `/api/notifications/review-pairing` only
 *  when its `REVIEW_PAIRING_USERNAME` names one disposable account; the taps keep the login off
 *  the screen of a live app. Play Console's App access instructions tell reviewers the sequence. */
internal class ReviewLoginTaps(private val required: Int = REQUIRED) {
    private var count = 0

    /** Counts one tap. True on the tap that completes the sequence, which then starts over. */
    fun tap(): Boolean {
        count++
        if (count < required) return false
        count = 0
        return true
    }

    companion object {
        const val REQUIRED = 10

        /** Play only, and only on an install that has never paired. F-Droid and GitHub builds never arm. */
        fun armed(flavor: String, everPaired: Boolean): Boolean = flavor == "play" && !everPaired
    }
}
