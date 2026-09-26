package org.kysecurity.mail.push

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import org.kysecurity.mail.MainActivity
import org.kysecurity.mail.R

object PushNotificationDispatcher : org.kysecurity.mail.ProcessScopedState {
    private const val CHANNEL_ID = "kypost_push"
    private const val MFA_CHANNEL_ID = "kypost_mfa"
    private const val MFA_GROUP_KEY = "org.kysecurity.mail.push.MFA"

    /** Repeat challenges in this window post silently — the client half of MFA-fatigue resistance. */
    private const val MFA_ALERT_COOLDOWN_MS = 30 * 1000L

    /** Past this many live challenges, individual rows collapse into one summary. */
    private const val MFA_BURST_THRESHOLD = 3

    /** Fixed id, so a burst overwrites one row instead of accumulating. */
    private val MFA_BURST_NOTIFICATION_ID = stableNotificationId("mfa-burst")

    /** The notification id each challenge was actually posted under; bounded. */
    private val postedNotificationIds = object : LinkedHashMap<String, Int>(16, 0.75f, false) {
        override fun removeEldestEntry(eldest: Map.Entry<String, Int>): Boolean = size > MAX_TRACKED_CHALLENGES
    }

    /** The challenge the burst summary points at, or null when no burst row is showing. */
    @Volatile
    private var burstChallengeId: String? = null

    init {
        // Account-scoped bookkeeping in a process AppRestart no longer kills — see [ProcessScopedState].
        org.kysecurity.mail.ProcessState.register(this)
    }

    override fun resetForNewSession() {
        synchronized(postedNotificationIds) {
            postedNotificationIds.clear()
            burstChallengeId = null
        }
    }

    const val EXTRA_MFA_CHALLENGE_ID = "challengeId"
    const val EXTRA_MFA_IP = "mfaIpAddress"
    const val EXTRA_MFA_USER_AGENT = "mfaUserAgent"
    const val EXTRA_MFA_ISSUED_AT = "mfaIssuedAt"
    const val EXTRA_MFA_MATCH_DIGITS = "mfaMatchDigits"
    const val EXTRA_MFA_DECOY_DIGITS = "mfaDecoyDigits"
    const val EXTRA_MESSAGE_ID = "org.kysecurity.mail.push.EXTRA_MESSAGE_ID"

    /** See [NotificationIntentToken]. Present only on PendingIntents this object builds. */
    const val EXTRA_INTENT_TOKEN = "org.kysecurity.mail.push.EXTRA_INTENT_TOKEN"
    const val EXTRA_SENDER = "org.kysecurity.mail.push.EXTRA_SENDER"
    const val EXTRA_SUBJECT = "org.kysecurity.mail.push.EXTRA_SUBJECT"

    /** Channel ids from before the KyPost rename; a [NotificationChannel] outlives its constant. */
    private val LEGACY_CHANNEL_IDS = listOf("llama_labels_push", "llama_labels_mfa")

    /** [pruneLegacyChannels] runs once per process — see its doc. */
    private val legacyChannelsPruned = java.util.concurrent.atomic.AtomicBoolean(false)

    /** Deletes [LEGACY_CHANNEL_IDS]; once per process only because it is a binder call per id. */
    private fun pruneLegacyChannels(manager: NotificationManager) {
        if (!legacyChannelsPruned.compareAndSet(false, true)) return
        LEGACY_CHANNEL_IDS.forEach { manager.deleteNotificationChannel(it) }
    }

    fun ensureChannel(context: Context) {
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        pruneLegacyChannels(manager)
        if (manager.getNotificationChannel(CHANNEL_ID) != null) return

        val channel = NotificationChannel(
            CHANNEL_ID,
            "KyPost",
            NotificationManager.IMPORTANCE_DEFAULT,
        ).apply {
            description = "Push notifications for labeled email events"
        }
        manager.createNotificationChannel(channel)
    }

    fun ensureMfaChannel(context: Context) {
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        pruneLegacyChannels(manager)
        if (manager.getNotificationChannel(MFA_CHANNEL_ID) != null) return

        val channel = NotificationChannel(
            MFA_CHANNEL_ID,
            "Sign-in approvals",
            NotificationManager.IMPORTANCE_HIGH,
        ).apply {
            description = "Approve or deny sign-in attempts to your account"
        }
        manager.createNotificationChannel(channel)
    }

    /** Posts a new-mail notification. Ordinary lock-screen redaction is delegated to
     *  setPublicVersion; [contentSuppressed] is the stronger gate that withholds content from the
     *  notification altogether. */
    fun show(context: Context, payload: PushPayload) {
        ensureChannel(context)
        if (!notificationsAllowed(context)) return

        // The redacted form as the WHOLE notification: the framework's setPublicVersion swap keys
        // off the keyguard, and neither reason below is the keyguard. See [contentSuppressed].
        if (contentSuppressed(context)) {
            postNotification(
                context,
                uniqueNotificationId("mail-${payload.messageId}"),
                redactedNotification(context, payload),
            )
            return
        }

        val notificationId = uniqueNotificationId("mail-${payload.messageId}")
        val pendingIntent = mailPendingIntent(context, payload, notificationId)

        val body = PushPayloadParser.body(payload)

        val redacted = redactedNotification(context, payload)

        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(PushPayloadParser.title(payload))
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            // PRIVATE, not SECRET: SECRET suppresses the row on the lock screen outright, which
            // also suppresses the public version there and leaves nothing to swap in.
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setPublicVersion(redacted)
            .setContentIntent(pendingIntent)
            .build()

        postNotification(context, notificationId, notification)
    }

    /** The tap target for a mail notification. Both forms of the row carry the same one — the
     *  unlock gate is on the Activity, not on which form was tapped. */
    private fun mailPendingIntent(context: Context, payload: PushPayload, notificationId: Int): PendingIntent {
        val launchIntent = Intent(context, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            // MainActivity is exported; without this any app could hand it these three extras.
            .putExtra(EXTRA_INTENT_TOKEN, NotificationIntentToken.current(context))
            .putExtra(EXTRA_MESSAGE_ID, payload.messageId)
            .putExtra(EXTRA_SENDER, payload.senderName)
            .putExtra(EXTRA_SUBJECT, payload.emailSubject)
        return PendingIntent.getActivity(
            context,
            notificationId,
            launchIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
    }

    /** That something arrived, and nothing about what. Used as the lock-screen public version
     *  always, and as the entire notification when [contentSuppressed]. */
    private fun redactedNotification(context: Context, payload: PushPayload): android.app.Notification {
        val notificationId = uniqueNotificationId("mail-${payload.messageId}")
        return NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(context.getString(R.string.app_name))
            .setContentText(context.getString(R.string.notification_hidden_while_locked))
            .setAutoCancel(true)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setContentIntent(mailPendingIntent(context, payload, notificationId))
            .build()
    }

    /** Whether sender and subject must be withheld from the notification entirely.
     *
     *  Two independent reasons, and the second is NOT a lock check. Posting a notification hands
     *  its title and text to system_server, which persists them in Notification History and echoes
     *  them in `dumpsys notification` — an on-disk record in another UID that no wipe step here can
     *  reach. Under Hostile Location Protection the app promises nothing about this mail touches
     *  disk, so the content may not be posted at all, locked or not, foregrounded or not. */
    private fun contentSuppressed(context: Context): Boolean = runCatching {
        val graph = org.kysecurity.mail.security.SecurityRuntime.graph(context)
        // Checked first and unconditionally: this one does not depend on the lock's state.
        if (graph.hostileLocationSettings.isEnabled()) return@runCatching true
        val gated = graph.appLockStore.isLockEnabled() || graph.appLockStore.isCredentialPinGateEnabled()
        gated && graph.appLockManager.isLockedNow()
    }.getOrElse {
        android.util.Log.e("PushNotificationDispatcher", "Could not read the notification posture; redacting", it)
        true
    }

    /** No Approve/Deny actions on purpose: they fire from the lock screen with no authentication. */
    fun showMfaChallenge(context: Context, payload: MfaChallengePayload) {
        val tracker = PushRuntime.graph(context).mfaChallengeTracker
        val burst = tracker.liveCount() >= MFA_BURST_THRESHOLD
        val alert = tracker.shouldSuppressAlert(MFA_ALERT_COOLDOWN_MS)
        // Tracked only once a notification is actually on screen; the cooldown rolls back on failure.
        val notificationId = postMfaNotification(context, payload, burst, alert.suppress)
            ?: return tracker.restoreAlertCooldown(alert.previousAlertAtEpochMs)

        synchronized(postedNotificationIds) {
            if (burst) {
                // The summary points at one challenge; revoke the one it used to point at.
                burstChallengeId
                    ?.takeIf { it != payload.challengeId }
                    ?.let { superseded ->
                        tracker.clear(superseded)
                        postedNotificationIds.remove(superseded)
                    }
                burstChallengeId = payload.challengeId
            }
            postedNotificationIds[payload.challengeId] = notificationId
        }
        tracker.markDelivered(payload.challengeId)
    }

    /** Re-posts the row after a failed response; never re-marks, which would extend the window. */
    fun repostMfaChallenge(context: Context, payload: MfaChallengePayload) {
        // Only what is still answerable: a wrong match burns the challenge before the deny is sent.
        if (!PushRuntime.graph(context).mfaChallengeTracker.isPending(payload.challengeId)) return
        val burst = synchronized(postedNotificationIds) { burstChallengeId == payload.challengeId }
        postMfaNotification(context, payload, burst, silent = true)
    }

    /** Builds and posts the row, returning its id, or null if nothing was posted. */
    private fun postMfaNotification(
        context: Context,
        payload: MfaChallengePayload,
        burst: Boolean,
        silent: Boolean,
    ): Int? {
        ensureMfaChannel(context)
        val notificationId = if (burst) MFA_BURST_NOTIFICATION_ID else mfaNotificationId(payload.challengeId)
        val tapPendingIntent = PendingIntent.getActivity(
            context,
            notificationId,
            mfaApprovalIntent(context, payload),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val notification = NotificationCompat.Builder(context, MFA_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(
                context.getString(
                    if (burst) R.string.mfa_notification_burst_title else R.string.mfa_notification_title,
                ),
            )
            .setContentText(
                context.getString(
                    if (burst) R.string.mfa_notification_burst_body else R.string.mfa_notification_body,
                ),
            )
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_STATUS)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .setAutoCancel(true)
            .setGroup(MFA_GROUP_KEY)
            .setSilent(silent)
            .setContentIntent(tapPendingIntent)
            .build()

        return if (postNotification(context, notificationId, notification)) notificationId else null
    }

    /** Rebuilds the payload an [mfaApprovalIntent] was assembled from; kept next to its inverse. */
    fun payloadFrom(intent: Intent): MfaChallengePayload? {
        val id = intent.getStringExtra(EXTRA_MFA_CHALLENGE_ID).orEmpty()
        if (!MfaChallengePayloadParser.isValidChallengeId(id)) return null
        return MfaChallengePayload(
            challengeId = id,
            ipAddress = intent.getStringExtra(EXTRA_MFA_IP).orEmpty(),
            userAgent = intent.getStringExtra(EXTRA_MFA_USER_AGENT).orEmpty(),
            issuedAtEpochMs = intent.getLongExtra(EXTRA_MFA_ISSUED_AT, 0L),
            matchDigits = intent.getStringExtra(EXTRA_MFA_MATCH_DIGITS).orEmpty(),
            decoyDigits = intent.getStringArrayExtra(EXTRA_MFA_DECOY_DIGITS)?.toList().orEmpty(),
        )
    }

    /** Every field matters: a partial intent does not degrade the approval screen, it disables it. */
    private fun mfaApprovalIntent(context: Context, payload: MfaChallengePayload): Intent =
        Intent(context, MfaApprovalActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            .putExtra(EXTRA_MFA_CHALLENGE_ID, payload.challengeId)
            .putExtra(EXTRA_MFA_IP, payload.ipAddress)
            .putExtra(EXTRA_MFA_USER_AGENT, payload.userAgent)
            .putExtra(EXTRA_MFA_ISSUED_AT, payload.issuedAtEpochMs)
            .putExtra(EXTRA_MFA_MATCH_DIGITS, payload.matchDigits)
            .putExtra(EXTRA_MFA_DECOY_DIGITS, payload.decoyDigits.toTypedArray())

    /** Single exit point: POST_NOTIFICATIONS can be revoked between the check and this call. */
    private fun postNotification(context: Context, id: Int, notification: android.app.Notification): Boolean {
        if (!notificationsAllowed(context)) return false
        return try {
            NotificationManagerCompat.from(context).notify(id, notification)
            true
        } catch (e: SecurityException) {
            android.util.Log.w("PushNotifications", "POST_NOTIFICATIONS revoked; dropping notification", e)
            false
        }
    }

    /** Cancels the id the challenge was posted under — during a burst that is the shared summary id. */
    fun cancelMfaChallenge(context: Context, challengeId: String) {
        val notificationId = synchronized(postedNotificationIds) {
            if (burstChallengeId == challengeId) burstChallengeId = null
            postedNotificationIds.remove(challengeId)
        } ?: mfaNotificationId(challengeId)
        NotificationManagerCompat.from(context).cancel(notificationId)
    }

    private fun notificationsAllowed(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return true
        return ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
    }

    internal fun mfaNotificationId(challengeId: String): Int = stableNotificationId("mfa-$challengeId")

    /** Ids handed out so far, so a hash collision is detected rather than silently replacing a row. */
    private val assignedIds = object : LinkedHashMap<Int, String>(16, 0.75f, false) {
        override fun removeEldestEntry(eldest: Map.Entry<Int, String>): Boolean = size > MAX_TRACKED_CHALLENGES * 8
    }

    /** How many times [uniqueNotificationId] re-probes before accepting a collision. */
    private const val MAX_ID_PROBES = 8

    /** Records [key] against [id] and returns an id no other live key is using. */
    private fun uniqueNotificationId(key: String): Int = synchronized(assignedIds) {
        // A bounded loop, not `while (true)`: the latter needed an unreachable expression and a
        // @Suppress to typecheck, which is a compiler argument standing in for a terminating bound.
        for (attempt in 0..MAX_ID_PROBES) {
            // Deterministic probe, so the same key keeps resolving to the same id for as long as
            // the colliding one is still tracked — cancelling a notification has to find it again.
            val id = if (attempt == 0) stableNotificationId(key) else stableNotificationId("$key#$attempt")
            val existing = assignedIds[id]
            if (existing == null || existing == key) {
                assignedIds[id] = key
                return id
            }
        }
        // Every probe collided with a different live key. Reuse the last one rather than inventing
        // an unbounded search: the row it replaces is one this process posted and still tracks.
        val fallback = stableNotificationId("$key#$MAX_ID_PROBES")
        android.util.Log.e("PushNotificationDispatcher", "Could not find a free notification id for $key")
        assignedIds[fallback] = key
        fallback
    }

    internal fun stableNotificationId(key: String): Int {
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(key.toByteArray())
        return ((digest[0].toInt() and 0x7F) shl 24) or
            ((digest[1].toInt() and 0xFF) shl 16) or
            ((digest[2].toInt() and 0xFF) shl 8) or
            (digest[3].toInt() and 0xFF)
    }

}
