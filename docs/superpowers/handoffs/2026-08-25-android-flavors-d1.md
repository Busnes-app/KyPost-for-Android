# Handoff: D1 — Android product flavors for three channels

Written 2026-08-25 from the **server** repo, revised the same day once the
Android checkout was located at `/home/yoshi/busness.app/kypost-android`. Both
repos were read; every claim below carries a citation and was verified against
the file it names.

**Copy.** The original lives in the server repo at
`kypost-server/docs/superpowers/handoffs/`, whose `docs/superpowers/` is
gitignored — which is why this was not visible from here. If the two disagree,
the server copy is authoritative, because its citations are checked against the
files they name.

**Path convention below:** paths starting `app/` are in THIS repo. Paths starting
`backend/`, `frontend/`, `push-relay-shared/` or `worker/` are in
`kypost-server` (locally at `/home/yoshi/busness.app/kypost-server`).

Read `kypost-server/docs/PLATFORM_BASELINE.md` first — it is the contract this
client implements against, and it is a **tracked** file, so it is also readable
at
<https://github.com/Busnes-app/KyPost-Server/blob/main/docs/PLATFORM_BASELINE.md>.

---

## The goal, and why it is not optional

Three distribution channels, three signing identities:

- **Play** re-signs with Google's key under Play App Signing.
- **GitHub APK** carries the upload key.
- **F-Droid** signs with F-Droid's own key.

Android identifies an app by `applicationId` **and** signature. One
`applicationId` across three channels means a user who installed from one cannot
update from another without uninstalling — which destroys local data. No flag
fixes this.

Different `applicationId` values dissolve the problem rather than working around
it: Play App Signing is scoped to a package name, so a build under a different id
is a different app, outside Play's jurisdiction, and installs side by side.

### Target state

| Flavor | `applicationId` | Push | Signing |
| --- | --- | --- | --- |
| `play` | `org.kysecurity.mail` | FCM | Play App Signing |
| `github` | `org.kysecurity.mail.github` | FCM | upload key |
| `fdroid` | `org.kysecurity.mail.fdroid` | **UnifiedPush** (decided) | F-Droid key |

D1 is the flavors themselves. D2 (Firebase registration), D3 (no-Firebase fdroid
build) and D4 (`kypost://` disambiguation) follow as separate items.

---

## Three questions this handoff previously asked — now answered

### ✅ `deviceId` is SERVER-assigned. Flavors cannot break device identity.

This was flagged as the blocking risk, on the theory that `deviceId` might be
derived from `BuildConfig.APPLICATION_ID`. **It is not.**

The client sends `deviceId = null` when it parses a pairing QR
(`app/src/main/java/org/kysecurity/mail/push/PairingModels.kt:124`), and the
server returns the assigned id in `NativeRegistrationResponse.deviceId`
(`push/NativeRegistration.kt:44`), which is then persisted to prefs under
`pair_device_id` (`push/SecurePairingStore.kt:27,133`).

So changing `applicationId` per flavor does **not** change any device's identity,
does not disturb the enrollment-code preimage, and does not orphan sealed
envelopes. This axis is safe — proceed without special handling.

### ✅ Current `applicationId` is `org.kysecurity.mail`

`app/build.gradle.kts:80`. The `play` flavor **must** keep exactly this, or the
in-flight closed test breaks.

### ✅ RESOLVED 2026-08-26 — UnifiedPush encryption now works end to end

*This section originally reported a gap. Server PR #149 closed it; the finding
is kept because the reasoning still explains why Decision 1 changed.*

The client always implemented RFC 8291 key exchange: `NativeRegistrationRequest`
carries `p256dh` and `auth`, commented *"present only for
transport=unifiedpush"* (`push/NativeRegistration.kt:32-34`). The server had
nowhere to put them, so Go's decoder discarded them and
`UnifiedPushSender.Send` POSTed plaintext to the broker.

Both halves are fixed. `nativeRegisterRequest` now carries `P256DH` and `Auth`
(`backend/internal/api/server_notifications.go:417-418`), payloads are
encrypted, and `MFATransportEligible`
(`backend/internal/api/push_mfa_handlers.go:56-61`) now returns true for a
UnifiedPush device **that has those keys** — push-MFA follows encryption rather
than being blanket-excluded.

**Consequence for Decision 1:** UnifiedPush no longer costs confidentiality or
push-MFA. The table below is updated accordingly.

---

## Server-side facts an Android-only session cannot discover

### The server has no knowledge of `applicationId` at all

`nativeRegisterRequest` carries `subscriberId`, `pairingToken`, `deviceToken`,
`deviceId`, `platform`, `transport`, `deviceName`, `appVersion`,
`encryptionEnrolled` — **no package name**. A grep for `org.kysecurity`,
`applicationId` and `packageName` across `backend/`, `frontend/`,
`push-relay-shared/` and `worker/` returns nothing.

**D1 and D2 need no server change.** The relay is unaffected — FCM tokens are per
install, not per package id.

### The `kypost://` scheme is hardcoded in three places — D4 cannot use per-flavor schemes

The tempting fix for D4 is `kypost-github://`, `kypost-fdroid://`. **It does not
work, and it fails unsafely:**

1. The server builds the pairing URI as a literal —
   `` return `kypost://native-pair?${params.toString()}` ``
   (`frontend/src/pages/security/pairingLink.ts:42`). Not configurable. A flavor
   listening on another scheme would not match the QR the server emits.
2. The phishing scanner hardcodes the same string
   (`backend/internal/processor/phish_scan.go:20-50`) to catch
   `<a href="kypost://native-pair?srv=https://evil.example&pt=...">` in received
   mail — a one-tap account takeover. **A new scheme would not be caught.**
3. The HTML sanitizer's allowlist refuses it by the same name
   (`frontend/src/lib/emailHtml.ts:64-65`).

D4 must be solved **inside the intent filter** — host, path, or
`android:priority` — or by handling the chooser in-app. Changing the scheme needs
a coordinated server change plus a security review of items 2 and 3.

### UnifiedPush and push-MFA (updated)

`transport` accepts `"fcm"`, `"apns"`, `"unifiedpush"`
(`backend/internal/state/store.go:84-86`, `server_notifications.go:737`). Empty
derives from `platform`: `ios`/`macos` → `apns`, **everything else → `fcm`**.

`MFATransportEligible` (`backend/internal/api/push_mfa_handlers.go:56-61`) used
to exclude UnifiedPush outright: a challenge carries the sign-in IP, user agent
and the match digits, which must not cross an unencrypted broker. Since server
#149 it admits a UnifiedPush device **that presents RFC 8291 keys**, so the
restriction now tracks whether the payload is actually encrypted.

⚠️ **Verify:** if the fdroid build registers without naming a transport,
`platform: "android"` derives `"fcm"` — making it MFA-eligible server-side while
having no FCM token to receive anything. The fdroid flavor must send `transport`
**explicitly**.

### `deviceId` charset still constrains the server-assigned value

ASCII `[a-zA-Z0-9._:-]`, max 128 bytes (`device_auth.go:21`, `validDeviceID` at
`device_auth.go:226`). The id feeds the normative enrollment preimage and the
`device:<deviceId>` envelope slot. Nothing to do for D1 given the id is
server-assigned, but do not introduce a client-chosen id without re-reading this.

---

## Decisions — BOTH RESOLVED 2026-08-26

**Decision 1 — fdroid push mechanism: UNIFIEDPUSH.**

Chosen once server #149 put RFC 8291 encryption on the channel. That removed the
two objections (plaintext payloads, and push-MFA being excluded outright), and
what remains is real push latency and battery behaviour that polling cannot
match. The client already ships both paths — `KyPostUnifiedPushService.kt` and
the `unifiedpush.connector` dependency alongside `PullWorker` — so **D3 is Gradle
work (keeping Firebase out of this flavor), not new push code**.

Three obligations follow, and the first two are silent failures if missed:

1. **Send `transport` explicitly as `"unifiedpush"`.** Unset with
   `platform: "android"` the server derives `"fcm"` — the device then passes the
   MFA gate with no FCM token behind it.
2. **Send the `p256dh`/`auth` keys.** `MFATransportEligible`
   (`backend/internal/api/push_mfa_handlers.go:56-61`) admits a UnifiedPush
   device *only* when they are present. Without them the flavor quietly loses
   push-MFA — the exact capability #149 restored.
3. **Decide the no-distributor case.** UnifiedPush requires a distributor app;
   a user with none gets no push at all. Pull is the obvious fallback and the
   client already has it. Answer this before F-Droid users discover it.

**Decision 2 — `kypost://` chooser: MAKE IT LEGIBLE, do not try to remove it.**

Eliminating the chooser is not reachable. Per-flavor schemes fail unsafely (the
server emits the scheme as a literal and the phishing scanner matches it by
name, so a new scheme is neither matched nor caught); per-flavor host/path needs
the server to know which flavor is installed, and it cannot; `android:priority`
does not suppress a chooser across separate apps; App Links need a verifiable
domain that self-hosters do not have.

So give each flavor a distinct `android:label` — "KyPost", "KyPost (GitHub)",
"KyPost (F-Droid)" — and the chooser becomes a clear question rather than two
identical icons. Only someone who deliberately installed two variants ever sees
it.

---

## Suggested order

1. Add the flavor dimension with the three ids. `play` keeps
   `org.kysecurity.mail` exactly.
2. Verify all three install side by side on one device.
3. Then D2 / D3 / D4 as separate changes.

The `google-services` Gradle plugin applies project-wide, so D3's "no Firebase
dependency at all" means flavor-scoped dependencies plus conditional plugin
application — not merely disabling FCM at runtime. A flavor that still carries the
proprietary dependency will be flagged by F-Droid.

## Acceptance criteria for D1

- [ ] Three flavors build.
- [ ] `play` produces exactly `org.kysecurity.mail`.
- [ ] All three install simultaneously on one device, each with its own data.
- [ ] Pairing still works on `play` against a 0.3.0 server, including `pin=`.
- [ ] Enrollment codes still match the browser — 14 characters, `4-3-4-3`
      grouping (`deviceEnrollment.ts:204`, and `DeviceEnrollmentCode.kt:14` on
      the client).

## What was not checked

The existing intent filters, the full Gradle structure, whether the client
already sends `transport` explicitly, and whether pull-mode devices are
MFA-eligible in practice. Each is called out above as a question rather than an
assumption.
