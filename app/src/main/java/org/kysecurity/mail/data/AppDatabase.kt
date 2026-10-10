package org.kysecurity.mail.data

import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

@Database(
    entities = [
        EmailEntity::class,
        FolderEntity::class,
        ContactEntity::class,
        PendingContactChangeEntity::class,
        DeviceContactLinkEntity::class,
        GroupEntity::class,
        GroupLinkEntity::class,
        ContactSyncStateEntity::class,
        RecipientPinEntity::class,
    ],
    version = 13,
    exportSchema = true,
)
@TypeConverters(Converters::class)
abstract class AppDatabase : RoomDatabase() {
    abstract fun emailDao(): EmailDao
    abstract fun folderDao(): FolderDao
    abstract fun contactDao(): ContactDao
    abstract fun pendingContactChangeDao(): PendingContactChangeDao
    abstract fun deviceContactLinkDao(): DeviceContactLinkDao
    abstract fun groupDao(): GroupDao
    abstract fun groupLinkDao(): GroupLinkDao
    abstract fun contactSyncStateDao(): ContactSyncStateDao
    abstract fun recipientPinDao(): RecipientPinDao

    companion object {
        val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS `device_contact_links` (" +
                        "`uid` TEXT NOT NULL, `rawContactId` INTEGER NOT NULL, " +
                        "`deviceUpdatedAtEpochMs` INTEGER NOT NULL, PRIMARY KEY(`uid`))",
                )
            }
        }

        val MIGRATION_2_3 = object : Migration(2, 3) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "ALTER TABLE `emails` ADD COLUMN `hasAttachments` INTEGER NOT NULL DEFAULT 0",
                )
            }
        }

        val MIGRATION_3_4 = object : Migration(3, 4) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE `contacts` ADD COLUMN `groupIDsJson` TEXT NOT NULL DEFAULT '[]'")
                db.execSQL("ALTER TABLE `contacts` ADD COLUMN `photoRef` TEXT")
                db.execSQL("ALTER TABLE `contacts` ADD COLUMN `pgpKey` TEXT")
                db.execSQL("ALTER TABLE `contacts` ADD COLUMN `imsJson` TEXT NOT NULL DEFAULT '[]'")
                db.execSQL("ALTER TABLE `contacts` ADD COLUMN `websitesJson` TEXT NOT NULL DEFAULT '[]'")
                db.execSQL("ALTER TABLE `contacts` ADD COLUMN `relationsJson` TEXT NOT NULL DEFAULT '[]'")
                db.execSQL("ALTER TABLE `contacts` ADD COLUMN `eventsJson` TEXT NOT NULL DEFAULT '[]'")
                db.execSQL("ALTER TABLE `contacts` ADD COLUMN `phoneticGivenName` TEXT")
                db.execSQL("ALTER TABLE `contacts` ADD COLUMN `phoneticFamilyName` TEXT")
                db.execSQL("ALTER TABLE `contacts` ADD COLUMN `department` TEXT")
                db.execSQL("ALTER TABLE `contacts` ADD COLUMN `customFieldsJson` TEXT NOT NULL DEFAULT '[]'")
                db.execSQL("ALTER TABLE `contacts` ADD COLUMN `pronouns` TEXT")
            }
        }

        val MIGRATION_4_5 = object : Migration(4, 5) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS `groups` (" +
                        "`id` TEXT NOT NULL, `name` TEXT NOT NULL, `rev` INTEGER NOT NULL, " +
                        "PRIMARY KEY(`id`))",
                )
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS `group_links` (" +
                        "`groupId` TEXT NOT NULL, `androidGroupRowId` INTEGER NOT NULL, " +
                        "PRIMARY KEY(`groupId`))",
                )
            }
        }

        val MIGRATION_5_6 = object : Migration(5, 6) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE `contacts` ADD COLUMN `isSelf` INTEGER NOT NULL DEFAULT 0")
            }
        }

        val MIGRATION_6_7 = object : Migration(6, 7) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE `contacts` ADD COLUMN `pgpKeyFingerprint` TEXT")
                db.execSQL("ALTER TABLE `contacts` ADD COLUMN `pgpKeyNeedsReverification` INTEGER NOT NULL DEFAULT 0")
            }
        }

        val MIGRATION_7_8 = object : Migration(7, 8) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE `emails` ADD COLUMN `pgpEncrypted` INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE `emails` ADD COLUMN `pgpSigned` INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE `emails` ADD COLUMN `pgpVerified` INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE `emails` ADD COLUMN `pgpSignerFingerprint` TEXT NOT NULL DEFAULT ''")
                db.execSQL("ALTER TABLE `emails` ADD COLUMN `pgpDecryptError` TEXT NOT NULL DEFAULT ''")
            }
        }

        val MIGRATION_8_9 = object : Migration(8, 9) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS `contact_sync_state` (" +
                        "`subscriberId` TEXT NOT NULL, `cursor` INTEGER NOT NULL, " +
                        "PRIMARY KEY(`subscriberId`))",
                )
            }
        }

        // Not backfilled from pgpKeyNeedsReverification: the next sync re-raises a real alarm.
        val MIGRATION_9_10 = object : Migration(9, 10) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "ALTER TABLE `contacts` ADD COLUMN `identityNeedsReview` INTEGER NOT NULL DEFAULT 0",
                )
            }
        }

        val MIGRATION_10_11 = object : Migration(10, 11) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE `emails` ADD COLUMN `bodyMode` TEXT NOT NULL DEFAULT ''")
            }
        }

        /** `emails` re-keyed on (folder, messageId) — see [EmailEntity]. SQLite cannot alter a
         *  primary key, so the table is rebuilt. Copying is safe without a dedup pass: the old key
         *  was `messageId` alone, so every (folder, messageId) pair is already unique. Cached rows
         *  are carried over rather than dropped — a wipe would cost the user their offline mail to
         *  fix a collision most mailboxes never hit. */
        val MIGRATION_11_12 = object : Migration(11, 12) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS `emails_new` (" +
                        "`messageId` TEXT NOT NULL, `folder` TEXT NOT NULL, `sender` TEXT NOT NULL, " +
                        "`sentTo` TEXT NOT NULL, `cc` TEXT NOT NULL, `bcc` TEXT NOT NULL, " +
                        "`subject` TEXT NOT NULL, `preview` TEXT NOT NULL, `body` TEXT, " +
                        "`bodyMode` TEXT NOT NULL, `label` TEXT NOT NULL, `keywordsJson` TEXT NOT NULL, " +
                        "`status` TEXT NOT NULL, `atUtc` TEXT, `hasAttachments` INTEGER NOT NULL, " +
                        "`sourceMode` TEXT NOT NULL, `pgpEncrypted` INTEGER NOT NULL, " +
                        "`pgpSigned` INTEGER NOT NULL, `pgpVerified` INTEGER NOT NULL, " +
                        "`pgpSignerFingerprint` TEXT NOT NULL, `pgpDecryptError` TEXT NOT NULL, " +
                        "PRIMARY KEY(`folder`, `messageId`))",
                )
                db.execSQL(
                    "INSERT INTO `emails_new` SELECT `messageId`, `folder`, `sender`, `sentTo`, " +
                        "`cc`, `bcc`, `subject`, `preview`, `body`, `bodyMode`, `label`, " +
                        "`keywordsJson`, `status`, `atUtc`, `hasAttachments`, `sourceMode`, " +
                        "`pgpEncrypted`, `pgpSigned`, `pgpVerified`, `pgpSignerFingerprint`, " +
                        "`pgpDecryptError` FROM `emails`",
                )
                db.execSQL("DROP TABLE `emails`")
                db.execSQL("ALTER TABLE `emails_new` RENAME TO `emails`")
            }
        }

        /** Recorded keys kept when sync removes the contact that held them. */
        val MIGRATION_12_13 = object : Migration(12, 13) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS `recipient_pins` (`address` TEXT NOT NULL, " +
                        "`fingerprint` TEXT NOT NULL, `publicKey` TEXT NOT NULL, `confirmed` INTEGER NOT NULL, " +
                        "PRIMARY KEY(`address`, `fingerprint`))",
                )
            }
        }
    }
}
