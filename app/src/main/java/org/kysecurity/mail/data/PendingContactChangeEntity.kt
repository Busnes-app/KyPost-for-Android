package org.kysecurity.mail.data

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "pending_contact_changes")
data class PendingContactChangeEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    /** The contact's uid. A create mints it locally and the server keeps it. */
    val localUid: String,
    val rev: Long = 0,
    /** "create" | "update" | "delete" */
    val changeType: String,
    /** Full Contact field snapshot at edit time (empty/ignored for delete). */
    val payloadJson: String = "",
    val createdAtEpochMs: Long,
)
