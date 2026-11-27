package org.kysecurity.mail.pgp

import androidx.test.ext.junit.runners.AndroidJUnit4
import java.security.KeyStore
import javax.crypto.Cipher
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class XWingEnrollmentKeysTest {
    @After fun cleanup() { XWingEnrollmentKeys.deleteWrapKey() }

    @Test fun unAuthenticatedOrCancelledCipherCannotPublishAKey() = runBlocking {
        // A returned cipher without CryptoObject authentication must not be sufficient. On a
        // software-only emulator preparation must instead fail before offering any prompt.
        for (cancel in listOf(false, true)) {
            val keys = XWingEnrollmentKeys { cipher -> if (cancel) null else cipher }
            assertFalse(keys.prepare())
            assertNull(keys.rawPublicKey())
            assertNull(keys.encodedPublicKey())
            assertTrue(keys.deleteKeyPair())
        }
    }

    @Test fun teardownRevokesEveryOwnedWrapAlias() {
        // Use a software key only as a deletion target, never as an enrollment key.
        val alias = XWingEnrollmentKeys.ALIAS + ".test"
        val spec = android.security.keystore.KeyGenParameterSpec.Builder(alias,
            android.security.keystore.KeyProperties.PURPOSE_ENCRYPT or android.security.keystore.KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(256).setBlockModes("GCM").setEncryptionPaddings("NoPadding").build()
        javax.crypto.KeyGenerator.getInstance("AES", "AndroidKeyStore").apply { init(spec) }.generateKey()
        assertTrue(XWingEnrollmentKeys.deleteWrapKey())
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertFalse(store.containsAlias(alias))
    }
}
