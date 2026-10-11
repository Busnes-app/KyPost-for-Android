package org.kysecurity.mail

import android.app.Activity
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import org.kysecurity.mail.mail.MailOutcome
import org.kysecurity.mail.mail.MailRepository
import org.kysecurity.mail.mail.userFacingMessage
import java.util.concurrent.Executor

/** INBOX, every top-level folder and every Archive subfolder, minus the one the mail is in. The
 *  relay's top-level list omits INBOX and Archive, so both are added back here. */
internal fun moveTargets(current: String, topLevel: List<String>, archiveChildren: List<String>): List<String> =
    (listOf("INBOX") + topLevel + archiveChildren)
        .distinctBy { it.lowercase() }
        .filterNot { it.equals(current, ignoreCase = true) }

/** Lists folders on [executor], asks which one, and calls [onPicked] on the main thread. */
internal fun pickMoveTarget(
    activity: Activity,
    repository: MailRepository,
    executor: Executor,
    current: String,
    onPicked: (String) -> Unit,
) {
    executor.execute {
        val topLevel = repository.listFolders(null)
        // Best effort: an account with no Archive folder still has the top level to offer.
        val archive = (repository.listFolders("Archive") as? MailOutcome.Success)?.value?.folders.orEmpty()
        activity.runOnUiThread {
            if (activity.isFinishing || activity.isDestroyed) return@runOnUiThread
            if (topLevel !is MailOutcome.Success) {
                topLevel.userFacingMessage()?.let { Toast.makeText(activity, it, Toast.LENGTH_LONG).show() }
                return@runOnUiThread
            }
            val targets = moveTargets(current, topLevel.value.folders.map { it.path }, archive.map { it.path })
            AlertDialog.Builder(activity)
                .setTitle(R.string.move_to_title)
                .setItems(targets.toTypedArray()) { _, which -> onPicked(targets[which]) }
                .setNegativeButton(android.R.string.cancel, null)
                .showThemed()
        }
    }
}
