package org.kysecurity.mail

import android.content.Context
import android.content.DialogInterface
import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.text.InputType
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.ImageButton
import android.widget.LinearLayout
import android.widget.PopupMenu
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.StringRes
import androidx.appcompat.app.AlertDialog
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import org.kysecurity.mail.mail.FolderInfo
import org.kysecurity.mail.mail.MailOutcome
import org.kysecurity.mail.mail.MailRepository
import org.kysecurity.mail.mail.MailRuntime
import org.kysecurity.mail.mail.userFacingMessage
import org.kysecurity.mail.security.LockedActivity
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/** One level of the account's folders. Tapping a row returns its path as [EXTRA_FOLDER]; the row's
 *  menu drills in, creates a subfolder, or renames and deletes what the server allows. A rename or
 *  delete that moves the inbox's open folder also returns [EXTRA_FOLDER], its new path, so the
 *  inbox never keeps refreshing a mailbox that is gone. */
class FoldersActivity : LockedActivity() {

    // Reads only. Mutations go to MailBackgroundExecutor, which outlives this screen.
    private val ioExecutor: ExecutorService = Executors.newSingleThreadExecutor()
    private lateinit var repository: MailRepository
    private lateinit var status: TextView
    private val adapter = FolderAdapter()

    /** "" is the top level. */
    private val parentPath: String get() = intent.getStringExtra(EXTRA_PARENT).orEmpty()

    /** The inbox's open folder, kept current across renames made here. */
    private var openFolder: String? = null

    private val subfolderLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        val folder = it.data?.getStringExtra(EXTRA_FOLDER)
        if (it.resultCode != RESULT_OK || folder == null) return@registerForActivityResult
        if (it.data?.getBooleanExtra(EXTRA_PICKED, false) == true) {
            setResult(RESULT_OK, it.data)
            finish()
        } else {
            redirect(folder)
        }
    }

    override fun onCreateUnlocked(savedInstanceState: Bundle?) {
        repository = MailRuntime.graph(this).repository
        openFolder = intent.getStringExtra(EXTRA_OPEN)
        // A recreated Activity has lost its result; put the redirect back.
        savedInstanceState?.getString(STATE_REDIRECT)?.let(::redirect)
        setTitle(if (parentPath.isEmpty()) getString(R.string.folders_title) else displayName(parentPath))

        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dpToPx(20), dpToPx(20), dpToPx(20), dpToPx(20))
        }
        applyTopInsetWithHeader(this, container)

        val newFolder = Button(this).apply {
            id = R.id.foldersNew
            setText(R.string.folders_new)
            setOnClickListener { promptCreate(parentPath) }
        }
        applyGhostButtonTheme(this, newFolder)
        container.addViewSpaced(newFolder, bottomDp = 12)

        status = TextView(this).apply {
            textSize = 14f
            accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE
        }
        container.addViewSpaced(status, bottomDp = 8)

        val list = RecyclerView(this).apply {
            layoutManager = LinearLayoutManager(this@FoldersActivity)
            adapter = this@FoldersActivity.adapter
        }
        container.addView(list, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f))

        setContentView(container)
        applyThemeToActivity(this)
        load()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        if (openFolder != intent.getStringExtra(EXTRA_OPEN)) outState.putString(STATE_REDIRECT, openFolder)
    }

    override fun onDestroy() {
        super.onDestroy()
        ioExecutor.shutdownNow()
    }

    private fun load() {
        status.setText(R.string.folders_loading)
        status.visibility = View.VISIBLE
        read({ repository.listFolders(parentPath.ifEmpty { null }) }) { outcome ->
            if (outcome !is MailOutcome.Success) {
                status.text = outcome.userFacingMessage()
                adapter.submit(emptyList())
                return@read
            }
            val folders = withArchive(parentPath, outcome.value.folders)
            adapter.submit(folders)
            if (folders.isEmpty()) status.setText(R.string.folders_empty) else status.visibility = View.GONE
        }
    }

    private fun pick(folder: FolderInfo) {
        setResult(RESULT_OK, Intent().putExtra(EXTRA_FOLDER, folder.path).putExtra(EXTRA_PICKED, true))
        finish()
    }

    private fun redirect(folder: String) {
        openFolder = folder
        setResult(RESULT_OK, Intent().putExtra(EXTRA_FOLDER, folder))
    }

    private fun showRowMenu(anchor: View, folder: FolderInfo) {
        val menu = PopupMenu(this, anchor)
        menu.menu.add(0, MENU_SUBFOLDERS, 0, R.string.folders_subfolders)
        menu.menu.add(0, MENU_NEW_SUBFOLDER, 1, R.string.folders_new_subfolder)
        if (folder.deletable) {
            menu.menu.add(0, MENU_RENAME, 2, R.string.folders_rename)
            menu.menu.add(0, MENU_DELETE, 3, R.string.folders_delete)
        }
        menu.setOnMenuItemClickListener { item ->
            when (item.itemId) {
                MENU_SUBFOLDERS -> subfolderLauncher.launch(intentFor(this, folder.path, openFolder))
                MENU_NEW_SUBFOLDER -> promptCreate(folder.path)
                MENU_RENAME -> promptRename(folder)
                MENU_DELETE -> checkThenConfirmDelete(folder)
            }
            true
        }
        menu.show()
    }

    private fun promptCreate(parent: String) {
        // The server refuses to rename or delete a top-level folder, so say so before making one.
        val note = if (parent.isEmpty()) getString(R.string.folders_top_level_note) else null
        promptName(R.string.folders_new, "", note, emptyList()) { name ->
            mutate(R.string.folders_new, { repository.createFolder(parent, name) })
        }
    }

    private fun promptRename(folder: FolderInfo) {
        val leaf = mailboxLeaf(folder.path)
        // The server's "already exists" is a 502 that reads as a mail server fault.
        val siblings = adapter.folders.map { mailboxLeaf(it.path) }.filterNot { it.equals(leaf, ignoreCase = true) }
        promptName(R.string.folders_rename, leaf, null, siblings) { name ->
            val parent = mailboxParent(folder.path)
            val renamed = parent + folder.path[parent.length] + name
            mutate(R.string.folders_rename, { repository.renameFolder(folder.path, name) }) {
                movedOpenFolder(openFolder, folder.path, renamed)?.let(::redirect)
            }
        }
    }

    private fun promptName(@StringRes title: Int, initial: String, message: String?, taken: List<String>, onName: (String) -> Unit) {
        val input = EditText(this).apply {
            id = R.id.foldersNameInput
            noPersonalizedLearning()
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_WORDS
            isSingleLine = true
            setHint(R.string.folders_name_hint)
            setText(initial)
        }
        val pad = dpToPx(20)
        val frame = FrameLayout(this).apply {
            setPadding(pad, pad / 2, pad, 0)
            addView(input)
        }
        val dialog = AlertDialog.Builder(this)
            .setTitle(title)
            .setMessage(message)
            .setView(frame)
            .setPositiveButton(R.string.save, null)
            .setNegativeButton(android.R.string.cancel, null)
            .showThemed()
        // Replaces the auto-dismissing listener, so a bad name keeps what was typed.
        dialog.getButton(DialogInterface.BUTTON_POSITIVE).setOnClickListener {
            val name = input.text.toString().trim()
            val problem = folderNameProblem(name, taken)
            if (problem != null) {
                input.error = getString(problem)
            } else {
                dialog.dismiss()
                onName(name)
            }
        }
    }

    // The server refuses a folder with subfolders, in words that read as a mail server fault.
    private fun checkThenConfirmDelete(folder: FolderInfo) {
        read({ repository.listFolders(folder.path) }) { outcome ->
            when {
                outcome !is MailOutcome.Success ->
                    outcome.userFacingMessage()?.let { Toast.makeText(this, it, Toast.LENGTH_LONG).show() }
                outcome.value.folders.isNotEmpty() -> Toast.makeText(
                    this, getString(R.string.folders_has_subfolders, displayName(folder.path)), Toast.LENGTH_LONG,
                ).show()
                else -> confirmDelete(folder)
            }
        }
    }

    private fun confirmDelete(folder: FolderInfo) {
        val parent = mailboxParent(folder.path)
        AlertDialog.Builder(this)
            .setTitle(R.string.folders_delete)
            .setMessage(getString(R.string.folders_delete_confirm, displayName(folder.path), displayName(parent)))
            .setPositiveButton(R.string.folders_delete) { _, _ ->
                mutate(R.string.folders_delete, { repository.deleteFolder(folder.path) }) {
                    movedOpenFolder(openFolder, folder.path, parent)?.let(::redirect)
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .showThemed()
    }

    /** Failures toast from MailBackgroundExecutor; a live screen repaints either way. */
    private fun mutate(@StringRes label: Int, call: () -> MailOutcome<Unit>, onSuccess: () -> Unit = {}) {
        MailBackgroundExecutor.submitReporting(this, getString(label)) {
            call().also { outcome ->
                runOnUiThread {
                    if (isDestroyed) return@runOnUiThread
                    if (outcome is MailOutcome.Success) onSuccess()
                    load()
                }
            }
        }
    }

    private fun <T> read(call: () -> T, onResult: (T) -> Unit) {
        ioExecutor.execute {
            val result = call()
            runOnUiThread { if (!isFinishing && !isDestroyed) onResult(result) }
        }
    }

    private fun displayName(path: String): String =
        if (path.equals("INBOX", ignoreCase = true)) getString(R.string.nav_inbox) else mailboxLeaf(path)

    private inner class FolderAdapter : RecyclerView.Adapter<FolderAdapter.Row>() {
        var folders: List<FolderInfo> = emptyList()
            private set

        @android.annotation.SuppressLint("NotifyDataSetChanged")
        fun submit(next: List<FolderInfo>) {
            folders = next
            notifyDataSetChanged()
        }

        inner class Row(view: LinearLayout, val label: TextView, val more: ImageButton) : RecyclerView.ViewHolder(view)

        override fun onCreateViewHolder(group: ViewGroup, viewType: Int): Row {
            val context = group.context
            val ink = Color.parseColor(getStoredThemePalette(context).inkStrong)
            val label = TextView(context).apply {
                textSize = 16f
                setTextColor(ink)
                gravity = Gravity.CENTER_VERTICAL
                minHeight = dpToPx(48)
                setBackgroundResource(themeAttr(context, android.R.attr.selectableItemBackground))
            }
            val more = ImageButton(context).apply {
                setImageResource(R.drawable.ic_more_vert)
                setBackgroundResource(themeAttr(context, android.R.attr.selectableItemBackgroundBorderless))
                minimumWidth = dpToPx(48)
                minimumHeight = dpToPx(48)
            }
            applyIconButtonTheme(context, more)
            val row = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                layoutParams = RecyclerView.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
                addView(label, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
                addView(more)
            }
            return Row(row, label, more)
        }

        override fun onBindViewHolder(holder: Row, position: Int) {
            val folder = folders[position]
            val name = displayName(folder.path)
            holder.label.text = name
            holder.label.setOnClickListener { pick(folder) }
            holder.more.contentDescription = getString(R.string.folders_more, name)
            holder.more.setOnClickListener { showRowMenu(it, folder) }
        }

        override fun getItemCount(): Int = folders.size
    }

    companion object {
        const val EXTRA_FOLDER = "folders_folder"
        private const val EXTRA_PICKED = "folders_picked"
        private const val EXTRA_PARENT = "folders_parent"
        private const val EXTRA_OPEN = "folders_open"
        private const val STATE_REDIRECT = "folders_redirect"
        private const val MENU_SUBFOLDERS = 1
        private const val MENU_NEW_SUBFOLDER = 2
        private const val MENU_RENAME = 3
        private const val MENU_DELETE = 4

        /** [open] is the inbox's folder, followed if a rename or delete here moves it. */
        fun intentFor(context: Context, parent: String = "", open: String? = null): Intent =
            Intent(context, FoldersActivity::class.java).putExtra(EXTRA_PARENT, parent).putExtra(EXTRA_OPEN, open)
    }
}

private fun themeAttr(context: Context, attr: Int): Int =
    TypedValue().also { context.theme.resolveAttribute(attr, it, true) }.resourceId

/** The relay's top-level list omits Archive, which is where most user folders live. */
internal fun withArchive(parent: String, folders: List<FolderInfo>): List<FolderInfo> =
    if (parent.isNotEmpty() || folders.any { it.path.equals("Archive", ignoreCase = true) }) folders
    else listOf(FolderInfo("Archive", deletable = false)) + folders

/** Mirrors the server's own refusals (`client_folders.go`): one level, so no delimiter, and a
 *  rename onto a sibling's name. */
@StringRes
internal fun folderNameProblem(name: String, taken: List<String>): Int? = when {
    name.isBlank() -> R.string.folders_name_blank
    name.any { it == '/' || it == '.' } -> R.string.folders_name_delimiter
    taken.any { it.equals(name, ignoreCase = true) } -> R.string.folders_name_taken
    else -> null
}

/** "" for a top-level path. */
internal fun mailboxParent(path: String): String = path.substring(0, maxOf(path.lastIndexOfAny(charArrayOf('/', '.')), 0))

/** Where [open] lives once [from] becomes [to]; null when [open] is outside [from]. */
internal fun movedOpenFolder(open: String?, from: String, to: String): String? = when {
    open == null -> null
    open.equals(from, ignoreCase = true) -> to
    open.startsWith("$from/", ignoreCase = true) || open.startsWith("$from.", ignoreCase = true) ->
        to + open.substring(from.length)
    else -> null
}
