# Content-free native pushes (wake, then pull)

**Status:** Planned, not implemented. Documentation only.
**Repos:** KyPost-Server (payload) and kypost-android (receivers).
**Baseline:** Android `9bcaeb9`; server `origin/main` `a9e8028`.

## Problem

Native pushes already omit correspondence by default. `includeContent` is
`settings.ContentPreview && !msg.PGPEncrypted` (`backend/internal/processor/poller.go:2020-2022`).
Without it, the data map is `{messageId, url}` and the title and body are generic
(`:2031-2075`). Some metadata still rides the push route (backend, relay Worker, FCM):

- **Mail with ContentPreview on:** sender, subject and keywords (`poller.go:2066-2073`).
- **Every MFA challenge:** `type`, `challengeId`, `issuedAt`, `matchDigits` and `decoyDigits`.
  `ipAddress` and `userAgent` are added under ContentPreview
  (`backend/internal/api/push_mfa_handlers.go:280-306`).
- **All mail pushes:** a per-message reference.

The goal is a single wake message carrying nothing message-specific. The app then fetches the
details over its TLS-pinned, device-authenticated pull channel.

## What exists

- **Server queue.** Every native message is already enqueued for pull in both delivery modes,
  with its full `Title/Body/Data` (`processor/push_dispatch.go:267-288`). The queue is capped at
  100 entries (`state/store.go:39`). The pull route is
  `GET /api/notifications/native/pull` with device auth (`api/server.go:826`). The pull path
  therefore already carries everything the push does.
- **FCM.** Delivery is data-only with `priority: HIGH` (`worker/src/fcm.ts:243-274`).
  UnifiedPush payloads are RFC 8291-encrypted end to end to the app
  (server spec `docs/superpowers/specs/2026-07-13-unifiedpush-encryption-design.md`).
- **App receivers.** These cover `play`/`github` through FCM (`src/gms`) and every flavor
  through UnifiedPush (`src/main`). Both receivers route the data map straight to a notification:
  - `gms/.../KyPostFirebaseMessagingService.kt:35-55`
  - `main/.../KyPostUnifiedPushService.kt:98-134`
  - `IncomingPushRouter.route(data)`, MFA first (`IncomingPushRouter.kt:21-23`)
- **App pull.** It is pinned: `PullNotificationClient(callFactory = pinnedOrFallbackCallFactory)`
  (`PushRuntime.kt:26`). It is serialized by `pullGate`, dedupes mail through `appendPayload`,
  and routes MFA first (`PullSyncCoordinator.kt:37-45,120-126`; `IncomingPushRouter.kt:28-30`).
- **Catch.** A PUSH-mode `pullOnce()` returns `PushHealthy` without fetching when a push arrived
  within 3 h (`PullSyncCoordinator.kt:57-58`). Both receivers stamp `markPushReceived` first, so
  a wake-triggered pull would always short-circuit. It needs an explicit "woken" entry.

## Recommended design

**Server.**
1. **Capability.** The device advertises it at registration, for example
   `payloadModes: ["wake"]`, the way `envelopeVersions` is advertised for enrollment. It is
   stored per device, and absent means legacy behaviour, so installed apps keep working.
2. **Payload.** For a capable device, `SendNativePushToDevices` keeps enqueueing the full
   message unchanged, but transmits `Data = {"type":"wake"}` with empty Title and Body.
   - Use an FCM `collapse_key` of `wake`, so a backlog delivers one wake rather than N.
   - Keep HIGH priority, which MFA latency needs.
   - Send the same wake on UnifiedPush. It is already encrypted there, but one payload shape
     keeps a single code path and gives the distributor nothing either.
3. **ContentPreview.** It then only governs what the pulled entry contains, and that travels
   over the pinned channel. Whether to turn it on by default for native devices is open
   question 2. Leave the default alone in this plan.

**App.**
1. **Router.** `IncomingPushRouter.route(data)` recognises `type == "wake"` as `IncomingPush.Wake`.
   It comes after the MFA check and is matched exactly. Anything else keeps today's parsing, so a
   legacy server still works.
2. **Receivers.** On `Wake`, both receivers call a new
   `PullSyncCoordinator.pullNow(reason = Woken)`. It is the same `pullGate`, minus the
   `PushHealthy` skip. Run it **synchronously inside the receiver** with a ~8 s timeout:
   FCM gives `onMessageReceived` a short execution window (around 20 s for high priority,
   **UNPROVEN** for current Play services). If the pull times out or fails as retryable,
   enqueue an expedited one-time `PullWorker`, deduped by unique work name.
3. **Notifications.** They come only from pulled entries, through the existing
   `notifier` → `PushNotificationDispatcher`. That keeps the lock-screen redaction, the MFA
   channel, the tap-to-open-only MFA rule, and the `EXTRA_MESSAGE_ID` forced resync contract
   unchanged.
4. **Advertising.** Advertise `payloadModes: ["wake"]` at registration only from the build
   that ships 1–3.

## Battery and latency trade-off

- **Latency:** one extra pinned HTTPS round trip after the wake. The radio is already up for
  the push, but a TLS handshake after Doze is likely (no warm pooled connection). Expect
  hundreds of ms to about 2 s added before the notification, and the same for the MFA prompt.
  **UNPROVEN:** measure on a device in Doze.
- **Battery:** one short request per wake. Collapsing wakes caps it during bursts. Steady-state
  cost should be marginal against today's heartbeat (a 15-minute `PullWorker` floor).
  **UNPROVEN:** measure with Battery Historian before default-on.
- **Failure mode:** if the relay is reachable by push but not by pull, the user gets nothing
  rather than a notification. The expedited-worker fallback and the existing heartbeat bound
  the delay. Show the existing sync error in Pairing.
- **FCM quota:** Android can deprioritise high-priority messages that produce no visible
  notification. A deduped wake (the mail was already seen) produces none. **UNPROVEN** at our
  volumes; the collapse key limits the count.

## Migration and rollback

- Capability-gated in both directions. Rollback on the app side means not advertising
  `wake`, after which the server sends legacy payloads on the next registration. Rollback on the
  server side means ignoring the capability.
- The pull queue format is untouched, so no data migration is needed.

## Tests

- **Server:** a capable device receives exactly `{"type":"wake"}` on FCM and UnifiedPush; the
  queue still holds the full entry; a legacy device is unchanged; MFA follows the same rule.
- **App JVM:**
  - Router: `wake` is recognised; an MFA payload still wins; an unknown type falls through
    unchanged.
  - `PullSyncCoordinator`: `Woken` bypasses `PushHealthy`; overlapping wake plus worker
    notifies once (extend `PullHeartbeatTest`).
  - Timeout falls back to an expedited worker.
- **App instrumentation:** an end-to-end check against the disposable relay fixture added in
  PR #133, in both FCM-less (UnifiedPush) and FCM configurations where CI allows.

## Risks

- **MFA approval now depends on the pull path being reachable.** That is the pinned relay
  connection the approval POST needs anyway, so no new dependency is added.
- **Pull-queue cap of 100.** A long-offline device still loses the oldest entries, as it does
  today.

## Open questions for Yoshi

1. Should wake-only become the only native mode once adopted, removing the legacy payload, or
   remain capability-negotiated indefinitely?
2. With content moved to the pinned pull, should sender/subject previews become default-on for
   native devices? That is a default change, and it needs your sign-off.
3. Is the added MFA prompt latency acceptable, or should MFA keep its current payload and only
   mail go wake-only?
4. Should UnifiedPush also go wake-only (recommended, for one code path), or keep its encrypted
   content?
