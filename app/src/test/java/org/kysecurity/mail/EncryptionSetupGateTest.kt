package org.kysecurity.mail

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.kysecurity.mail.mail.MailOutcome

class EncryptionSetupGateTest {

    @Test
    fun theSetup403EntersTheStateWithTheServersWording() {
        val gate = EncryptionSetupGate()

        assertTrue(gate.record(MailOutcome.EncryptionSetupRequired("server words")))

        assertTrue(gate.blocked)
        assertEquals("server words", gate.serverMessage)
    }

    /** No retry loop: a second 403 is not a change, so nothing re-arms the poll. */
    @Test
    fun aRepeated403IsNotAChange() {
        val gate = EncryptionSetupGate()
        gate.record(MailOutcome.EncryptionSetupRequired(null))

        assertFalse(gate.record(MailOutcome.EncryptionSetupRequired(null)))
        assertTrue(gate.blocked)
    }

    /** Offline or a 502 says nothing about setup, so neither clears nor enters the state. */
    @Test
    fun otherFailuresLeaveTheStateAsItWas() {
        val gate = EncryptionSetupGate()
        gate.record(MailOutcome.EncryptionSetupRequired("held"))

        assertFalse(gate.record(MailOutcome.UpstreamFailure("Network error")))
        assertFalse(gate.record(MailOutcome.Unauthorized("Bad secret")))
        assertTrue(gate.blocked)
        assertEquals("held", gate.serverMessage)

        val fresh = EncryptionSetupGate()
        assertFalse(fresh.record(MailOutcome.UpstreamFailure("Network error")))
        assertFalse(fresh.blocked)
    }

    @Test
    fun aLaterSuccessClearsTheState() {
        val gate = EncryptionSetupGate()
        gate.record(MailOutcome.EncryptionSetupRequired("held"))

        assertTrue(gate.record(MailOutcome.Success(Unit)))

        assertFalse(gate.blocked)
        assertNull(gate.serverMessage)
        assertFalse(gate.record(MailOutcome.Success(Unit)))
    }
}
