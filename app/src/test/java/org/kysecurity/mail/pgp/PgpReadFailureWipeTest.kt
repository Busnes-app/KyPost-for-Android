package org.kysecurity.mail.pgp

import java.io.IOException
import java.io.InputStream
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.test.assertFailsWith

class PgpReadFailureWipeTest {
    @Test fun streamingAuthenticationFailureScrubsTheCollectedPlaintext() {
        var exposedBuffer: ByteArray? = null
        val input = object : InputStream() {
            override fun read(): Int = error("bulk read expected")
            override fun read(target: ByteArray, offset: Int, length: Int): Int {
                if (exposedBuffer != null) throw IOException("AEAD tag verification failed")
                exposedBuffer = target
                "private text".toByteArray().copyInto(target, offset)
                return 12
            }
        }
        assertFailsWith<IOException> { PgpDecryptor.readAllWithLimit(input, 1024) }
        assertTrue(requireNotNull(exposedBuffer).all { it == 0.toByte() })
    }
}
