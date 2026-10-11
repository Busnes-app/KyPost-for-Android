# Conversation (thread) view

**Status:** Planned, not implemented. Blocked on server work. Documentation only.
**Repos:** kypost-android, plus KyPost-Server for the list fields.
**Baseline:** Android `9bcaeb9`; server `origin/main` `a9e8028`.

## Problem

The app shows a flat list per folder. Threading needs the RFC 5322 identifiers, and the relay
exposes none of them today.

- **List items carry no threading headers.** `inboxEmail` (`backend/internal/api/server_inbox.go:24-62`)
  has no Message-ID, In-Reply-To, References or thread id. Its `messageId` is the IMAP UID
  wrapped as a message reference, not the header (`mailcache/mailcache.go:66-70`).
- **The IMAP overview drops the identifiers.** The fetch uses `ALL`, so the ENVELOPE (which
  includes Message-ID and In-Reply-To) is fetched, but `overviewFromEmail`
  (`adapters/imap/client.go:651-700`) maps neither.
- **References is never fetched.** The generic `FetchHeaderFields`
  (`adapters/imap/auth_results.go:25`) could fetch it.
- **`/api/mail/body` returns only `{body, bodyMode}`** (`mail_body.go:78-81`).
- **The send request cannot thread a reply.** `mailRequest` (`api/server.go:1344-1365`) has no
  reply fields.
- **Pending server PR.** A parallel server PR is adding reply-threading send headers. It was not
  on `origin/main` at `a9e8028`, and its field names are **UNPROVEN** here.
- **App side.**
  - `RelayEmailDto` (`mail/RelayModels.kt:27-55`) and `EmailEntity` (`data/EmailEntity.kt:15-38`,
    key `(folder, messageId)`) have nowhere to put these fields.
  - The schema is at version 12 (`data/AppDatabase.kt:20`).
  - Reply only prefixes `Re:` (`EmailDetailActivity.kt:228,244`), and `MailDraft`
    (`mail/MailSource.kt:113-127`) has no reply fields.

## Constraints

- **The window is narrow.** At most 500 rows per folder (`server_inbox.go:275`). Native sources
  always return full snapshots (`:360-364`). A thread can therefore span folders (INBOX and Sent)
  and fall partly outside the window. The view shows what is cached and never implies the
  thread is complete.
- **List rows never carry bodies** (`bodies=0`). A thread screen fetches bodies on demand
  through the existing `fetchBody` path.
- **Trust never flows through a thread.** Anyone can set In-Reply-To to land inside an existing
  conversation. Each message keeps its own sender line and `PgpSignatureState` badge, and the
  thread header never shows a verified state.
- **No client-side `From` or header parsing that decides trust** (`app/src/main/AGENTS.md`,
  PGP signature bullet). Threading ids are display grouping only.

## Recommended design

**Server (prerequisite).**
- Add three `omitempty` fields to `inboxEmail` and `mailcache.Entry`: `rfcMessageId`,
  `inReplyTo` and `references`. Fill the first two from the ENVELOPE already fetched, and fetch
  `References` in the same batch through `FetchHeaderFields`.
- Bound them on the server: 998 bytes per id, and keep the last 20 References.
- Native-source parity is **UNPROVEN**: which store holds native headers was not traced.

**App.**
1. **Data.** Add `rfcMessageId`, `inReplyTo`, `referencesJson` and `threadKey` to `RelayEmailDto`
   and `EmailEntity`. Add `MIGRATION_12_13`, which is additive and needs no rebuild. Bound
   strings at the parse boundary, as `PushPayloadParser.sanitize` does for push.
2. **Thread key, as one pure function.** `threadKeyOf(rfcMessageId, inReplyTo, references)` =
   `references.first() ?: inReplyTo ?: rfcMessageId ?: "uid:" + folder + messageId`. That is the
   root id, computed on write.
   - `ponytail:` this is not full JWZ threading. Truncated References chains split threads.
     The upgrade path is a union-find pass over cached rows.
   - Rows from an older server have no ids, so they fall back to one thread per message, which
     is today's behaviour.
3. **Inbox.** Behind a setting, group the folder list by `threadKey`. Show the newest row, a
   count, and unread if any member is unread. Folder actions apply to the visible row only, as
   today, until the "act on thread" question below is decided. That avoids silently archiving
   rows the user never saw.
4. **Thread screen.** Query `emails WHERE threadKey = ?` across cached folders (INBOX and Sent),
   ordered by `atUtc`. Render collapsed cards that expand through the existing detail renderer
   and its sanitizer. There is no new WebView configuration.
5. **Reply.** Pass `inReplyTo = rfcMessageId` and
   `references = (references + rfcMessageId).takeLast(20)` through `MailDraft.toSendWireDto()`,
   and only once the server PR's field names are fixed.
   - For client-side encrypted send, `OutgoingEnvelope` has a closed header set. Adding
     In-Reply-To and References there exposes thread linkage in cleartext outer headers. Keep
     them out unless Yoshi decides otherwise.

## Migration and rollback

- `MIGRATION_12_13` is additive. Existing rows get null ids and their own `uid:` thread key
  until the next snapshot refresh fills them. The daily self-heal snapshot covers that.
- Rollback: turn off the grouping setting. The columns stay unused. A Room downgrade remains
  unsupported, as it is today.

## Tests

- **JVM:** `threadKeyOf` truth table (no ids, only In-Reply-To, References order, oversized and
  hostile values); grouping and unread aggregation; reply header construction.
- **Android tests:** a `MigrationTest` case for 12→13; `EmailDaoFolderScopeTest` extended so
  thread queries never collide across `(folder, messageId)`.
- **Server:** header extraction bounds; `omitempty` absent for messages without ids; native
  parity.

## Risks

- A thread that spans folders is only as complete as the cached folders. Sent may never have
  been opened. The thread screen should name that ("Showing N cached messages").
- Inbox actions on a grouped row are a behaviour change with data-loss weight. See question 3.

## Open questions for Yoshi

1. Should the server expose ids on the list (recommended), or should the app derive them
   from a new per-message headers endpoint?
2. Should grouping be on by default, or opt-in for the first release?
3. Should archive, delete or move on a grouped row act on the whole thread? That needs explicit
   confirmation per CONTRIBUTING ("Does not archive, delete, or move mail without an explicit
   user action").
4. Should client-side encrypted replies carry In-Reply-To and References in the outer
   headers?
5. What field names will the parallel server reply-threading PR use?
