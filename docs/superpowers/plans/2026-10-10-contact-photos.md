# Contact photos

**Status:** Planned, not implemented. Documentation only.
**Repos:** kypost-android, plus KyPost-Server for device-authenticated upload.
**Baseline:** Android `9bcaeb9`; server `origin/main` `a9e8028`.

## Problem

The app carries `photoRef` but shows initials only.

**App side.**
- **Round trip already works.** `ContactEntity.photoRef` exists (`data/ContactEntity.kt:29`,
  added in `data/AppDatabase.kt:56`) and survives sync and edits:
  - `contacts/ContactSyncModels.kt:28`
  - `contacts/ContactMappers.kt:48,89`
  - `contacts/ContactEditActivity.kt:578`
- **No UI shows it.** Avatars are initials only, from `bindAvatar` (`AppTheme.kt:469`), used at
  `ContactAdapter.kt:44`, `ContactDetailActivity.kt:120` and `ContactEditActivity.kt:345`.
- **No CP2 photo row.** `DeviceContactRepository` writes ten mimetypes and no `Photo`
  (`contacts/device/DeviceContactRepository.kt:468-614`).
- **No image decoding anywhere.** The app uses no `BitmapFactory` or `ImageDecoder` today.

**Server side.**
- **`photoRef` is server-owned.** It is `<sha256hex>.<ext>`, content-addressed, and the sync
  endpoint ignores it on push (`contacts/contacts.go:51`; `api/contacts_handlers.go:39,94`).
- **Routes** (`api/server.go:702-704`):
  - `GET /api/contacts/{id}/photo` accepts device auth (`withMailAuth`).
  - `POST` and `DELETE` are **web-session only** (`withAuth`).
- **Upload validation** (`api/contacts_photo.go`):
  - 5 MiB per photo (`:23`) and 200 MiB per user (`:34`).
  - Type is sniffed with `DetectContentType`, and only JPEG, PNG and GIF are allowed (`:142`).
  - Only the header is checked with `image.DecodeConfig` (`:147`). Original bytes are stored
    as-is, metadata included.

## Constraints

- **Photos are personal data at rest.** The mail and contacts DB is SQLCipher-encrypted.
  Plaintext image files in `cacheDir` would be the one unencrypted copy of address-book
  content, and they would survive Hostile Location Protection (which only makes Room
  in-memory).
- **Every byte is untrusted.** Photos come from the relay, and through it from CardDAV clients
  and anyone who mailed a vCard. The server does not re-encode. Decoding must be bounded before
  allocation.
- **Same-origin, pinned client, bounded reads.** Use `pairingHttpClient()` and its
  `BodySizeLimitInterceptor`, plus a per-call cap, like attachment download.
- **CP2 replaces destroy what they do not re-emit** (`app/src/main/AGENTS.md`, CP2 bullet). The
  photo row needs its own diff, not a delete-and-reinsert per sync.

## Recommended design (three increments, each shippable)

**1. Download and display (app only).**
- **Fetch.** For each contact whose `photoRef` is not in the local photo table, fetch
  `GET /api/contacts/{uid}/photo` on the pinned client, with a hard read cap of 5 MiB (the
  server's own cap). Run it in the contact-sync worker after the delta applies, rate-limited,
  never on the UI thread.
- **Decode** with `ImageDecoder` (`minSdk` 31):
  - In `OnHeaderDecodedListener`, reject a MIME type other than jpeg, png or gif, and reject
    any side above 8192 or a pixel count above 40 MP, before any pixels are allocated.
  - `setTargetSize` to at most 256 px on the long side, `ALLOCATOR_SOFTWARE`, and
    `decodeBitmap` (first frame only for GIF).
- **Re-encode** to JPEG at quality 85 at most. That strips EXIF and GPS, normalises the format,
  and bounds the stored size (about 20–40 KB).
- **Store** the result in a new Room table `contact_photos(photoRef TEXT PK, jpeg BLOB)`. It is
  encrypted by SQLCipher, in-memory under Hostile Location Protection, and removed by the
  existing `database` wipe step. Add `contactPhotoDao().clearAll()` to
  `PushRepository.purgeAccountScopedData` (`push/PushRepository.kt:190-199`).
- **Clean up.** Prune rows whose `photoRef` no longer appears on any contact.
- **Display.** `bindAvatar` gains an optional bitmap and keeps initials as the fallback.
- `ponytail:` no in-memory LRU at first. A 256 px JPEG decodes in well under a frame for list
  sizes. The upgrade path is `LruCache` keyed on `photoRef`.

**2. Push to device contacts.**
- Write `Photo.CONTENT_ITEM_TYPE` with `Photo.PHOTO` set to the stored 256 px JPEG. CP2 builds
  its own thumbnail; a display-size photo is not needed.
- Record the written `photoRef` on the device link row. Rewrite only when it changes, and
  delete the row when `photoRef` becomes null.
- Keep it one-way (Room → device). A device-side photo edit is not imported, because import
  implies upload (increment 3).

**3. Upload from the app (needs server change).**
- **Server:** a device-auth `PUT /api/contacts/{id}/photo`, metered like other device writes
  (`meterDeviceWrite`), reusing `storeContactPhoto` unchanged.
- **App:** pick through the system photo picker (no storage permission), then run the same
  bounded decode and re-encode to at most 1024 px JPEG before upload. The relay never receives
  the original bytes or their metadata. On success, the next sync delta delivers the new
  `photoRef`, and the local table is filled from the bytes just encoded.

## Size caps

| Item | Cap | Where |
| --- | --- | --- |
| Download | 5 MiB read | per-call, on top of `BodySizeLimitInterceptor` |
| Header | ≤ 8192 px per side, ≤ 40 MP | `OnHeaderDecodedListener`, before pixel allocation |
| Stored | 256 px JPEG, about 40 KB | `contact_photos` |
| Upload | 1024 px JPEG, ≤ 5 MiB | app, before POST; server cap unchanged |

## Migration and rollback

- An additive Room migration adds `contact_photos`, with a `MigrationTest` case. Rollback hides
  the bitmap, and the table becomes inert.
- The CP2 photo rows are removed with the sync account on unpair and wipe, as today
  (`SecurityWipe.kt:255-262`).

## Tests

- **JVM:** the decode-gate pure function (dimensions, pixel count, MIME type); `photoRef`
  pruning; the "rewrite CP2 only on change" decision.
- **Android tests:**
  - Decode real fixtures: a valid JPEG, PNG and GIF; a header claiming 60000×60000; a
    truncated file; a non-image with an image extension; an EXIF-GPS JPEG. Assert the GPS data
    is absent after re-encode.
  - Room migration.
  - CP2 photo row written and removed, asserted through `Contacts.PHOTO_THUMBNAIL_URI`.
  - Purge removes `contact_photos`.
- **Server (increment 3):** the device-auth route accepts device headers, rejects a missing
  pairing, and is metered.

## Risks

- **Platform image codecs run in-process on untrusted input.** The header gate and the
  downscaling decode bound memory, not codec bugs. Decoding in an `isolatedProcess` service is
  the stronger option, at the cost of a service and IPC. See question 2.
- **First sync of a large address book downloads many photos.** Rate-limit the fetches and
  run them on unmetered networks only (WorkManager constraint).

## Open questions for Yoshi

1. Is upload from the app (increment 3, with a new device-auth server route) wanted, or are
   display and device push enough?
2. Should decoding run in an `isolatedProcess` service, or is the in-process bounded
   `ImageDecoder` acceptable?
3. Should photo download be limited to unmetered networks, or allowed on any network?
4. Should the server also re-encode uploads (strip metadata for CardDAV and web uploads too)?
   That is a server-side follow-up outside this plan.
