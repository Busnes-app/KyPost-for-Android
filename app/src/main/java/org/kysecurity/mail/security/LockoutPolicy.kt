package org.kysecurity.mail.security

/** Attempts 1-2 are free; the delay ladder tops out at an hour, and the wipe is opt-out. */
object LockoutPolicy {
    private val DELAYS_MS = longArrayOf(
        30_000L,
        60_000L,
        300_000L,
        900_000L,
        1_800_000L,
        3_600_000L,
    )
    private const val FIRST_DELAYED_ATTEMPT = 3

    val WIPE_THRESHOLD_CHOICES = listOf(10, 20, 30)

    const val DEFAULT_WIPE_THRESHOLD = 30

    fun delayMillisFor(attemptCount: Int): Long {
        if (attemptCount < FIRST_DELAYED_ATTEMPT) return 0L
        val index = (attemptCount - FIRST_DELAYED_ATTEMPT).coerceAtMost(DELAYS_MS.size - 1)
        return DELAYS_MS[index]
    }

    /** @param wipeAfterAttempts null when the user has turned the wipe off. */
    fun shouldWipe(attemptCount: Int, wipeAfterAttempts: Int?): Boolean =
        wipeAfterAttempts != null && attemptCount >= wipeAfterAttempts

    /** More attempts before the wipe, or none at all, is the weaker setting. */
    fun weakensWipe(from: Int?, to: Int?): Boolean =
        from != null && (to == null || to > from)

    fun timeToWipeMillis(wipeAfterAttempts: Int): Long =
        (1..wipeAfterAttempts).sumOf { delayMillisFor(it) }
}
