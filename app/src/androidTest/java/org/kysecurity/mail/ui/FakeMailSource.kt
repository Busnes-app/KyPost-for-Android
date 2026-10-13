package org.kysecurity.mail.ui

import org.kysecurity.mail.Email
import org.kysecurity.mail.mail.AttachmentInfo
import org.kysecurity.mail.mail.ClientEncryptedDraft
import org.kysecurity.mail.mail.ClientEncryptedMessage
import org.kysecurity.mail.mail.DownloadedAttachment
import org.kysecurity.mail.mail.FolderListResult
import org.kysecurity.mail.mail.MailAccount
import org.kysecurity.mail.mail.MailAction
import org.kysecurity.mail.mail.MailActionOutcome
import org.kysecurity.mail.mail.MailDraft
import org.kysecurity.mail.mail.MailFetchResult
import org.kysecurity.mail.mail.MailMessageBody
import org.kysecurity.mail.mail.MailOutcome
import org.kysecurity.mail.mail.MailPage
import org.kysecurity.mail.mail.MailSendOutcome
import org.kysecurity.mail.mail.MailSource
import java.util.Collections
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** A relay the test controls. Inbox refreshes fail (so they never rewrite the rows a test seeds),
 *  bodies are empty, and every action is recorded in the order it completes. */
internal class FakeMailSource : MailSource {
    /** Each READ/UNREAD takes the next gate, if any, and waits on it before answering. */
    val readGates = ArrayBlockingQueue<CountDownLatch>(8)
    val unreadGates = ArrayBlockingQueue<CountDownLatch>(8)
    val completed: MutableList<MailAction> = Collections.synchronizedList(mutableListOf())
    val sends: MutableList<MailDraft> = Collections.synchronizedList(mutableListOf())
    val wakeAts: MutableList<java.time.Instant> = Collections.synchronizedList(mutableListOf())
    val sendOutcomes = ArrayBlockingQueue<MailOutcome<MailSendOutcome>>(8)

    /** Folder mutations always succeed and land here with their arguments. */
    val folderCalls: MutableList<List<String>> = Collections.synchronizedList(mutableListOf())

    @Volatile
    var folders: (String?) -> MailOutcome<FolderListResult> = { MailOutcome.UpstreamFailure("test relay") }

    @Volatile
    var actionOutcome: (MailAction) -> MailOutcome<MailActionOutcome> =
        { MailOutcome.Success(MailActionOutcome(processed = 1, failed = emptyList())) }

    fun awaitCompleted(action: MailAction, count: Int = 1, seconds: Long = 10): Boolean {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds)
        while (System.nanoTime() < deadline) {
            // The relay thread appends while this reads: iterate under the list's own lock.
            if (synchronized(completed) { completed.count { it == action } } >= count) return true
            Thread.sleep(20)
        }
        return false
    }

    override fun performAction(
        action: MailAction,
        messageIds: List<String>,
        mailbox: String,
        targetMailbox: String?,
        account: MailAccount?,
        wakeAt: java.time.Instant?,
    ): MailOutcome<MailActionOutcome> {
        if (wakeAt != null) wakeAts += wakeAt
        val gate = when (action) {
            MailAction.READ -> readGates.poll()
            MailAction.UNREAD -> unreadGates.poll()
            else -> null
        }
        gate?.await(10, TimeUnit.SECONDS)
        return actionOutcome(action).also { completed += action }
    }

    override fun currentAccount(): MailAccount? = null

    override fun sendMail(
        draft: MailDraft,
        account: MailAccount?,
        onCall: (okhttp3.Call) -> Unit,
    ): MailOutcome<MailSendOutcome> {
        sends += draft
        return sendOutcomes.poll(10, TimeUnit.SECONDS) ?: MailOutcome.UpstreamFailure("no stubbed send outcome")
    }

    override fun fetchInbox(mailbox: String, limit: Int, forceFullResync: Boolean): MailOutcome<MailFetchResult> =
        MailOutcome.UpstreamFailure("test relay")
    override fun fetchOlder(mailbox: String, limit: Int, before: String): MailOutcome<MailPage> =
        MailOutcome.UpstreamFailure("test relay")
    override fun fetchMessageBody(messageId: String, folder: String): MailOutcome<MailMessageBody> =
        MailOutcome.Success(MailMessageBody(html = "", toAddresses = emptyList(), ccAddresses = emptyList()))
    override fun listAttachments(messageId: String, folder: String): MailOutcome<List<AttachmentInfo>> =
        MailOutcome.Success(emptyList())
    override fun searchMail(query: String, mailbox: String, limit: Int): MailOutcome<List<Email>> =
        MailOutcome.UpstreamFailure("test relay")
    override fun listFolders(parent: String?): MailOutcome<FolderListResult> = folders(parent)
    override fun createFolder(parent: String, name: String): MailOutcome<Unit> =
        MailOutcome.Success(Unit).also { folderCalls += listOf("create", parent, name) }
    override fun renameFolder(folder: String, name: String): MailOutcome<Unit> =
        MailOutcome.Success(Unit).also { folderCalls += listOf("rename", folder, name) }
    override fun deleteFolder(folder: String): MailOutcome<Unit> =
        MailOutcome.Success(Unit).also { folderCalls += listOf("delete", folder) }
    override fun saveDraft(draft: MailDraft): MailOutcome<Unit> = MailOutcome.UpstreamFailure("test relay")
    override fun saveClientEncryptedDraft(draft: ClientEncryptedDraft): MailOutcome<Unit> =
        MailOutcome.UpstreamFailure("test relay")
    override fun sendClientEncrypted(message: ClientEncryptedMessage): MailOutcome<MailSendOutcome> =
        MailOutcome.UpstreamFailure("test relay")
    override fun downloadAttachment(messageId: String, folder: String, index: Int): MailOutcome<DownloadedAttachment> =
        MailOutcome.UpstreamFailure("test relay")
}
