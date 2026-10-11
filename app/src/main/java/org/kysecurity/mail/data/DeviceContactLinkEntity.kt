package org.kysecurity.mail.data

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(tableName = "device_contact_links", indices = [Index("rawContactId")])
data class DeviceContactLinkEntity(
    @PrimaryKey val uid: String,
    val rawContactId: Long,
    val deviceUpdatedAtEpochMs: Long,
)
