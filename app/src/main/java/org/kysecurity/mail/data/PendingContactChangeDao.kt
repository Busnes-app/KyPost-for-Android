package org.kysecurity.mail.data

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

/** Contacts with unsent changes, and when the oldest was queued. */
data class PendingContactSummary(val count: Int, val oldestAtEpochMs: Long?)

@Dao
interface PendingContactChangeDao {
    @Query("SELECT * FROM pending_contact_changes ORDER BY createdAtEpochMs ASC")
    suspend fun getAllPending(): List<PendingContactChangeEntity>

    @Query("SELECT COUNT(DISTINCT localUid) AS count, MIN(createdAtEpochMs) AS oldestAtEpochMs FROM pending_contact_changes")
    fun observeSummary(): Flow<PendingContactSummary>

    @Insert
    suspend fun enqueue(change: PendingContactChangeEntity): Long

    @Query("DELETE FROM pending_contact_changes WHERE id IN (:ids)")
    suspend fun clearFlushed(ids: List<Long>)

    @Query("DELETE FROM pending_contact_changes")
    suspend fun clearAll()
}
