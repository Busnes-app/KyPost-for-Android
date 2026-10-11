package org.kysecurity.mail

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** A token captured before a session boundary must read as expired from the moment the reset begins. */
class SessionGenerationTest {

    /** resetAll seals the process-wide draft cache; only take() unseals it. Left sealed, a later
     *  test class's save() silently does nothing. */
    @After
    fun unsealTheDraftCache() {
        ComposeDraftCache.take()
    }

    @Test
    fun aTokenIsCurrentUntilTheNextReset() {
        val token = ProcessState.generation()
        assertTrue(ProcessState.isCurrent(token))

        ProcessState.resetAll()

        assertFalse(ProcessState.isCurrent(token))
        assertTrue(ProcessState.isCurrent(ProcessState.generation()))
    }

    /** A teardown advances first and resets holders later; a token must be stale from the first. */
    @Test
    fun advancingExpiresATokenBeforeAnyReset() {
        val token = ProcessState.generation()

        ProcessState.advanceGeneration()

        assertFalse(ProcessState.isCurrent(token))
    }

    /** Holders run after the bump, so a callback racing the reset already sees its token expired. */
    @Test
    fun theGenerationAdvancesBeforeAnyHolderIsReset() {
        val before = ProcessState.generation()
        var seenDuringReset = before
        ProcessState.register(
            object : ProcessScopedState {
                override fun resetForNewSession() {
                    seenDuringReset = ProcessState.generation()
                }
            },
        )

        ProcessState.resetAll()

        assertEquals(before + 1, seenDuringReset)
    }
}
