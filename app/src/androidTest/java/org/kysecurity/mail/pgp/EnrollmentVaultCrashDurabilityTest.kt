package org.kysecurity.mail.pgp

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Two phases around a real unclean shutdown, driven by `scripts/vault-crash-check.sh`: phase one
 * seals a known record and returns, the host crashes the kernel through sysrq, and phase two
 * runs after boot. Not part of the ordinary suite: each phase is selected by name, and phase two
 * fails on its own because nothing was sealed.
 */
@RunWith(AndroidJUnit4::class)
class EnrollmentVaultCrashDurabilityTest {

    private val vault = EnrollmentVault(ApplicationProvider.getApplicationContext())

    /** Skipped, not failed, inside the ordinary suite: the phases only mean something with a crash
     *  between them, and JUnit's method order would otherwise run phase two first. */
    @Before
    fun onlyUnderTheScript() {
        assumeTrue(
            "run through scripts/vault-crash-check.sh",
            InstrumentationRegistry.getArguments().getString("crashCheck") == "true",
        )
    }

    @Test
    fun phase1SealsAKnownRecord() {
        vault.destroy()
        assertTrue(vault.store(ByteArray(12) { 0x55 }, ByteArray(48) { 0x66 }))
        assertArrayEquals(ByteArray(48) { 0x66 }, vault.stored()!!.second)
    }

    @Test
    fun phase2ReadsItBackAfterTheCrash() {
        val (iv, ct) = vault.stored() ?: throw AssertionError("the sealed record did not survive the crash")
        assertArrayEquals(ByteArray(12) { 0x55 }, iv)
        assertArrayEquals(ByteArray(48) { 0x66 }, ct)
        assertEquals(emptyList<String>(), vault.destroy())
        assertNull(vault.stored())
    }
}
