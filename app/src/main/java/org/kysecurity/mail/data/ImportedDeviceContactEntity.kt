package org.kysecurity.mail.data

import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query

/** Another account's raw contact the import already took, or found already in KyPost. It is
 *  never imported again, so a contact deleted in KyPost stays deleted. Cleared with the account. */
@Entity(tableName = "imported_device_contacts")
data class ImportedDeviceContactEntity(@PrimaryKey val sourceKey: String)

@Dao
interface ImportedDeviceContactDao {
    @Query("SELECT sourceKey FROM imported_device_contacts")
    suspend fun allKeys(): List<String>

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insert(row: ImportedDeviceContactEntity)

    @Query("DELETE FROM imported_device_contacts")
    suspend fun clearAll()
}
