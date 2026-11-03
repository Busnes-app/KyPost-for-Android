package org.kysecurity.mail.security

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** A missing key deletes only a database it can never open: an encrypted one. A plaintext file is a
 *  pre-encryption install, and deleting it before DatabaseMigration converts it lost its rows. */
class DatabaseKeyDiscardTest {
    @get:Rule val tmp = TemporaryFolder()

    @Test
    fun aPlaintextDatabaseIsKeptForConversion() {
        val file = tmp.newFile("kypost_mail.db")
        file.writeBytes("SQLite format 3".toByteArray(Charsets.US_ASCII) + 0 + ByteArray(100))
        assertFalse(DatabaseKey.unopenableWithoutKey(file))
    }

    @Test
    fun anEncryptedDatabaseWithNoKeyIsDiscarded() {
        val file = tmp.newFile("kypost_mail.db")
        file.writeBytes(ByteArray(116) { (it * 37 + 11).toByte() })
        assertTrue(DatabaseKey.unopenableWithoutKey(file))
    }

    @Test
    fun noFileIsNothingToDiscard() {
        assertFalse(DatabaseKey.unopenableWithoutKey(tmp.root.resolve("absent.db")))
    }
}
