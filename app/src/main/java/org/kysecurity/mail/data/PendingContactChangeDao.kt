package org.kysecurity.mail.data

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query

@Dao
interface PendingContactChangeDao {
    @Query("SELECT * FROM pending_contact_changes ORDER BY createdAtEpochMs ASC")
    suspend fun getAllPending(): List<PendingContactChangeEntity>

    @Insert
    suspend fun enqueue(change: PendingContactChangeEntity): Long

    @Query("SELECT * FROM pending_contact_changes WHERE localUid = :uid")
    suspend fun getByUid(uid: String): List<PendingContactChangeEntity>

    @Query("DELETE FROM pending_contact_changes WHERE id IN (:ids)")
    suspend fun clearFlushed(ids: List<Long>)

    @Query("DELETE FROM pending_contact_changes")
    suspend fun clearAll()
}
