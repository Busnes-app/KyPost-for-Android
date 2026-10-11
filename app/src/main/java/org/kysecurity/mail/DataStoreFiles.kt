package org.kysecurity.mail

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import java.io.File

/** Empties [store] through DataStore, cache included, then deletes its file. True when no file is
 *  left. Deleting only the file is not enough: DataStore keeps serving its cache, and a later edit
 *  re-reads the empty file, sees no change, and never refreshes it. */
internal suspend fun clearAndDelete(context: Context, name: String, store: DataStore<Preferences>): Boolean {
    store.edit { it.clear() }
    val file = File(context.filesDir, "datastore/$name.preferences_pb")
    return !file.exists() || file.delete()
}
