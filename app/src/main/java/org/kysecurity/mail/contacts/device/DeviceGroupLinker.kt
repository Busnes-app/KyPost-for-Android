package org.kysecurity.mail.contacts.device

import android.content.ContentValues
import android.content.Context
import android.provider.ContactsContract
import org.kysecurity.mail.data.AppDatabase
import org.kysecurity.mail.data.GroupEntity
import org.kysecurity.mail.data.GroupLinkEntity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

// One direction only: a backend group is materialized onto the device, never the reverse.
class DeviceGroupLinker(
    private val context: Context,
    private val db: AppDatabase,
) {
    private val contentResolver = context.contentResolver

    /** Reuses the link, else matches an on-device group by TITLE, and only then creates a row. */
    suspend fun ensureAndroidGroupRowId(groupId: String, groupName: String): Long? = withContext(Dispatchers.IO) {
        val existingLink = db.groupLinkDao().getByGroupId(groupId)
        if (existingLink != null) {
            renameIfNeeded(existingLink.androidGroupRowId, groupName)
            return@withContext existingLink.androidGroupRowId
        }

        val rowId = findExistingGroupRowId(queryAccountGroups(), groupName) ?: createAndroidGroup(groupName)
        if (rowId != null) {
            db.groupLinkDao().upsert(GroupLinkEntity(groupId = groupId, androidGroupRowId = rowId))
        }
        rowId
    }

    private fun queryAccountGroups(): List<Pair<Long, String>> {
        val projection = arrayOf(ContactsContract.Groups._ID, ContactsContract.Groups.TITLE)
        val selection = "${ContactsContract.Groups.ACCOUNT_TYPE} = ? AND " +
            "${ContactsContract.Groups.ACCOUNT_NAME} = ? AND ${ContactsContract.Groups.DELETED} = 0"
        val selectionArgs = arrayOf(DeviceContactAccount.ACCOUNT_TYPE, DeviceContactAccount.ACCOUNT_NAME)

        val results = mutableListOf<Pair<Long, String>>()
        contentResolver.query(
            ContactsContract.Groups.CONTENT_URI,
            projection,
            selection,
            selectionArgs,
            null,
        )?.use { cursor ->
            while (cursor.moveToNext()) {
                val id = cursor.getLong(cursor.getColumnIndexOrThrow(ContactsContract.Groups._ID))
                val title = cursor.getString(cursor.getColumnIndexOrThrow(ContactsContract.Groups.TITLE)) ?: ""
                results.add(id to title)
            }
        }
        return results
    }

    private fun createAndroidGroup(groupName: String): Long? {
        val uri = ContactsContract.Groups.CONTENT_URI.buildUpon()
            .appendQueryParameter(ContactsContract.CALLER_IS_SYNCADAPTER, "true")
            .build()
        val values = ContentValues().apply {
            put(ContactsContract.Groups.ACCOUNT_TYPE, DeviceContactAccount.ACCOUNT_TYPE)
            put(ContactsContract.Groups.ACCOUNT_NAME, DeviceContactAccount.ACCOUNT_NAME)
            put(ContactsContract.Groups.TITLE, groupName)
            put(ContactsContract.Groups.GROUP_VISIBLE, 1)
        }
        val resultUri = runCatching { contentResolver.insert(uri, values) }.getOrNull() ?: return null
        return resultUri.lastPathSegment?.toLongOrNull()
    }

    /** Deletes the device group of a backend group that no longer exists. Ownership is checked:
     *  as the sync adapter CP2 would delete any account's group. The link goes only on success. */
    suspend fun removeAndroidGroup(link: GroupLinkEntity) = withContext(Dispatchers.IO) {
        val uri = ContactsContract.Groups.CONTENT_URI.buildUpon()
            .appendQueryParameter(ContactsContract.CALLER_IS_SYNCADAPTER, "true")
            .build()
        runCatching {
            contentResolver.delete(
                uri,
                "${ContactsContract.Groups._ID} = ? AND ${ContactsContract.Groups.ACCOUNT_TYPE} = ?",
                arrayOf(link.androidGroupRowId.toString(), DeviceContactAccount.ACCOUNT_TYPE),
            )
        }.onSuccess { db.groupLinkDao().deleteByGroupId(link.groupId) }
            .onFailure { android.util.Log.e("DeviceContactSync", "Could not delete group ${link.androidGroupRowId}", it) }
        Unit
    }

    /** Public so the full-refresh cycle can rename already-linked groups, not just new ones. */
    suspend fun renameIfNeeded(androidGroupRowId: Long, groupName: String) = withContext(Dispatchers.IO) {
        val currentTitle = contentResolver.query(
            ContactsContract.Groups.CONTENT_URI,
            arrayOf(ContactsContract.Groups.TITLE),
            "${ContactsContract.Groups._ID} = ?",
            arrayOf(androidGroupRowId.toString()),
            null,
        )?.use { cursor ->
            if (cursor.moveToFirst()) cursor.getString(cursor.getColumnIndexOrThrow(ContactsContract.Groups.TITLE)) else null
        }

        if (currentTitle != null && currentTitle != groupName) {
            val uri = ContactsContract.Groups.CONTENT_URI.buildUpon()
                .appendQueryParameter(ContactsContract.CALLER_IS_SYNCADAPTER, "true")
                .build()
            val values = ContentValues().apply { put(ContactsContract.Groups.TITLE, groupName) }
            runCatching {
                contentResolver.update(uri, values, "${ContactsContract.Groups._ID} = ?", arrayOf(androidGroupRowId.toString()))
            }
        }
    }
}

/** Links whose backend group is gone, each with whether its device row goes too. Title matching
 *  can link two backend groups to one row, so a row a live group still links to is kept. */
internal fun groupRemovals(links: List<GroupLinkEntity>, groups: List<GroupEntity>): List<Pair<GroupLinkEntity, Boolean>> {
    val live = groups.mapTo(HashSet()) { it.id }
    val (kept, gone) = links.partition { it.groupId in live }
    val stillUsed = kept.mapTo(HashSet()) { it.androidGroupRowId }
    return gone.map { it to (it.androidGroupRowId !in stillUsed) }
}

/** A link whose backend group is gone is skipped — there is no fresh name to rename to. */
internal fun groupRenameTargets(links: List<GroupLinkEntity>, groups: List<GroupEntity>): List<Pair<Long, String>> {
    val groupsById = groups.associateBy { it.id }
    return links.mapNotNull { link -> groupsById[link.groupId]?.let { link.androidGroupRowId to it.name } }
}

/** Does any existing on-device group, scoped to our account, already have this exact title? */
internal fun findExistingGroupRowId(existingGroups: List<Pair<Long, String>>, groupName: String): Long? =
    existingGroups.firstOrNull { it.second == groupName }?.first
