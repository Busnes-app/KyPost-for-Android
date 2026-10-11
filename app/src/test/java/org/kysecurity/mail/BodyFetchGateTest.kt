package org.kysecurity.mail

import android.provider.CalendarContract
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class BodyFetchGateTest {

    @Test
    fun createEventTappedDuringTheFetchCarriesTheBodyOnceItLands() {
        val gate = BodyFetchGate()
        var body: String? = null
        var launched: Map<String, Any>? = null

        gate.whenSettled { launched = emailEventExtras("Lunch", body, "plain") }
        assertNull(launched, "must not launch subject-only while the body is still loading")

        body = "See you at noon"
        gate.settle()

        assertEquals("See you at noon", launched?.get(CalendarContract.Events.DESCRIPTION))
    }

    @Test
    fun aTapAfterTheFetchRunsAtOnceAndOnlyOnce() {
        val gate = BodyFetchGate()
        var runs = 0
        gate.settle()
        gate.whenSettled { runs++ }
        gate.settle()
        assertEquals(1, runs)
    }

    @Test
    fun repeatedTapsWhileLoadingLaunchOnce() {
        val gate = BodyFetchGate()
        var runs = 0
        gate.whenSettled { runs++ }
        gate.whenSettled { runs++ }
        gate.settle()
        assertEquals(1, runs)
    }
}
