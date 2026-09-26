package org.kysecurity.mail.push

/** What an arriving push turned out to be. */
sealed interface IncomingPush {
    data class Mfa(val payload: MfaChallengePayload) : IncomingPush
    data class Mail(val payload: PushPayload) : IncomingPush
}

/** Decides what an arriving push is, for every transport.
 *
 *  This is one object rather than a branch in each messaging service because the two copies
 *  drifted. The Firebase service checked for an MFA challenge first; the UnifiedPush service
 *  went straight to [PushPayloadParser], so a challenge arriving over UnifiedPush was read as
 *  mail, failed to parse, and was dropped with nothing shown. That was invisible for as long as
 *  the server refused to send challenges over UnifiedPush at all — it stopped being invisible
 *  when the server started encrypting those payloads and lifted the exclusion.
 *
 *  MFA is tried first, and the order is load-bearing: a challenge misread as mail renders the
 *  sign-in context as a sender and subject, with no approve or deny button anywhere. */
object IncomingPushRouter {
    fun route(data: Map<String, String>): IncomingPush? =
        MfaChallengePayloadParser.parse(data)?.let(IncomingPush::Mfa)
            ?: PushPayloadParser.parse(data)?.let(IncomingPush::Mail)

    /** A pulled entry is the same relay message with its `data` map intact, so it takes the same
     *  MFA-first decision. Mail keeps [PullNotification.toPushPayload]: the entry's title, body
     *  and `createdAt` are what a bare-content account has. */
    fun route(notification: PullNotification, nowEpochMs: Long): IncomingPush =
        notification.data?.let(MfaChallengePayloadParser::parse)?.let(IncomingPush::Mfa)
            ?: IncomingPush.Mail(notification.toPushPayload(nowEpochMs))
}
