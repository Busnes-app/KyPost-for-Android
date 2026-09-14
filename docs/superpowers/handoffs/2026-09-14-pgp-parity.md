# Android PGP parity implementation record

**Repo:** kypost-android

**Branch:** worktree-pgp-parity

**Worktree:** /home/yoshi/busness.app/kypost-android/.claude/worktrees/pgp-parity

**Plan:** [2026-09-13-pgp-parity.md](../plans/2026-09-13-pgp-parity.md)

## Delivered behavior

- Decrypted MIME attachments stay in memory and can be opened through the existing ephemeral content provider or explicitly saved through the existing download sink. Raster CID images render through the sanitized encrypted-message path. Decrypted bytes never enter Room, cached fetched HTML, or the attachments used by Forward.
- Attachment retention is capped at 4 MiB total, with one owned save snapshot. Queued snapshots are wiped on teardown; an already-started save finishes with its own stable bytes and then wipes them. The modeled read allocation peak, including decoding growth and save/open copies, remains 128 MiB. This is an allocation model, not a measured whole-process peak.
- Successfully decrypted unsigned messages say “Encrypted, not signed,” including messages without a resolved sender. Existing signed-only verification behavior remains.
- Re-enrollment preserves retired keys and missing historical subkeys, restores usable private packets when the new same-fingerprint packet is an empty stub, and keeps current public metadata and packet order for signing and own-key selection. Failed unlocks or refused merges leave the stored vault unchanged; only genuine first enrollment can seal current-only material.
- Merge limits are 256 KiB current input, 384 KiB previous input/output, and 32 rings. Invalid, incomplete, or excessive key material is refused. The separately modeled enrollment buffer peak is 3,940,352 bytes; it does not claim to measure Bouncy Castle's object heap.
- Destroying the enrollment Activity resolves its pending old-vault prompt as cancelled, including during rotation. Stale callbacks cannot repopulate the key session.
- Webmail handoff explains that it transfers no composition, makes no draft request, and leaves the Android composer available. Server PR #185 rejects client-custody plaintext draft uploads. Full self-encrypted draft saving is **not implemented here**; it has a [separate follow-up plan](../plans/2026-09-14-encrypted-draft-handoff.md).
- Regression coverage pins encrypted bodyless delta rows and tolerance of unknown resolver tiers and signer sources.

## Verification

Final full-suite, release-build, and whole-branch review results are being collected.

Focused checks completed during implementation include MIME/CID parsing, attachment ownership and filename handling, unsigned display, delta sync, real retired-key decryption/current-key signing, invalid and over-limit merge refusal, and enrollment buffer/session cleanup. Deliberate mutations were used to prove the affected regression assertions.

Device checks on a disposable API 36 emulator:

- 12 attachment download cleanup and ephemeral-provider tests passed.
- ComposeDraftSurvivesTeardownTest passed.
- DeviceEnrollmentOpenLifecycleTest passed after waiting for an actual pending biometric prompt. Removing destroy cancellation made it fail after five seconds with a stranded-open assertion; restoring cancellation passed.

The old pre-existing emulator was credential-locked and could not access shared storage. Those attachment setup failures were reproduced and resolved by using a new unlocked disposable AVD; the original AVD was not wiped.

## Not run / follow-up

- No paired live relay/account was available for the encrypted-message attachment/CID roundtrip, Proton interoperability, changed-relay delta run, or full device key-retirement/re-enrollment roundtrip.
- No production signing identity is available in this session. Local release packaging uses a disposable verification identity, matching CI's approach; these APKs are not production releases.
- Implement the separate encrypted-draft plan before claiming encrypted draft-save parity.

## Decisions made during execution

The original plan below remains a historical implementation recipe. The following ledger rulings record deviations and their reasons; later rulings supersede earlier ones where stated. In particular PlayDebug became available, attachment retention was lowered, and the server draft decision was resolved.

- Ruling: a `message/rfc822` leaf inside the ciphertext is collected as an attachment (bytes of the nested message) rather than walked — the old walk dropped it; a file is strictly better and YAGNI on nested rendering. Costs if wrong: a forwarded-as-attachment message shows as a `.eml` chip instead of inline text.

- Ruling: tests run on the fdroid flavor because the worktree command guard refuses the github flavor's task name and play needs a secret file. Costs if wrong: a flavor-specific source set difference goes untested here; PR CI covers all flavors.

- Ruling: dropped the unused `count` parameter from `decryptedAttachmentNotice` (YAGNI). Costs if wrong: nothing downstream used it.

- Ruling: text/html and text/plain leaves are body candidates unless Content-Disposition is `attachment`; a name= parameter or a Content-ID on a text part does not make it a file (multipart/related mailers stamp Content-ID on the HTML body; Outlook-lineage senders put name= on body text). Non-text, non-multipart leaves stay attachments. Costs if wrong: an inline `.txt` attachment lacking a disposition is read as a body candidate and, when a body already exists, is dropped.

- Ruling: `blockExternalResources` keeps raster data: `img` sources only when a new parameter `keepInlineDataImages: Boolean = false` is true; `renderableBody` gains the same parameter and forwards it; Task 4 passes true only from the Decrypted branch. Plaintext mail keeps today's behaviour, the "Show images" consent gate is unchanged there, and the only kept data: bytes are the ones `INLINE_IMAGE_BYTES` already counts (sender-authored data: images inside a decrypted body sit in the plaintext term). Costs if wrong: a legitimate inline data: image in ordinary mail stays hidden, as it is today.

- Ruling: break-proof is required for the two tests whose assertions could survive a broken implementation (the inline budget test and the new srcset test); the remaining new tests assert a single direct property whose only break is deleting the feature, and the SVG break already covered two. Costs if wrong: a subtly weak assertion among those slips through to the final review.

- Ruling: rename `anUnparseableFragmentComesBackUntouched` to `anEmptyFragmentComesBackUntouched`; the jsoup-failure fallback stays untested because the sanitiser downstream is the control. Costs if wrong: none beyond an honest name.

- Ruling: Task 5 question is answered; do not post a stale question. Its encrypted-save follow-up requires a new focused plan as Task 5 explicitly says. Existing Android handoff is offered on unenrolled devices, which do not have the key required to encrypt; preserve the composer and never send plaintext to discover custody.

- Ruling: Task 7 fixture is changeType=new and its expected updatedMessageIds is empty; the comment saying it must be updated contradicts both. Keep the wire distinction, cover new and updated encrypted rows with accurate assertions.

- Ruling: Task 9 must fail closed on a failed previous-vault open or invalid new merge instead of overwriting a potentially recoverable vault. OpenOutcome.Failed does not prove permanent key invalidation. Cost: transient failures need retry; historical keys are preserved.

- Ruling: Task 8 merge must bound input/output and reject empty or invalid current rings; enrollment must distinguish merge failure from no previous key. The suggested unbounded serialization and nullable fallback violate preservation/allocation contracts.

- Ruling: Task 4 fixes may revise the plan's byte ceiling downward and account for both bounded attachment decoding growth and one in-flight save/open copy. Preserve 128 MiB heap assumption, prevent unbounded queued copies, zero owned save buffers on completion or scheduling failure, and pass raw filenames to the existing sanitizing sink.

- Task 6: implemented at 75904dc; 477 focused tests pass, unsigned mapping deliberate-break fails as expected. Review pending. Fixture ruling: ARMORED_MIME_MESSAGE is actually signed, so generate a genuinely unsigned encrypted payload for the new regression.

- Ruling Task5: implement current no-upload webmail fallback, preserving Android composer; full encrypted saver remains separately planned as original Task5 explicitly requires. Enrolled missing-recipient handoff exists but most handoffs lack private key; no ordinary save-draft UI exists. This closes now-rejected plaintext upload without adding an unreachable draft feature. Cost: webmail receives no composition until encrypted saver followup is implemented; UI must state this explicitly.

- Task8 additional ruling: invalid nonempty previous key material must fail merging, rather than silently drop a partially recoverable prior collection. Task9 treats that failure as preservation/retry, never fallback to sealing current-only. A first enrollment has no previous material and follows its separate branch. Add size/ring-count limits in MemoryBudget with a separately tested enrollment peak, since merge and mail-read are distinct operations; do not pretend every enrollment allocation is concurrent with reader allocations.

- Task8 library ruling: BC collection iteration is map order; include shared packet-order parsing in merge and PgpEncryptor own-key/sign selection. Original serialization-order assumption disproved by deliberate mutation. Also previous input cap must accept max successful merged output. Details task-8-rulings.md.

- Task9 UI ruling: cancellation may remain ReadyToFinish; failed vault open and malformed/over-limit merge should use honest generic failure (existing SEAL_FAILED) rather than Almost done/authentication-only copy, while never altering old vault. Agreement-key teardown on true failure is acceptable; user can restart ceremony.

- Ruling: final release packaging may use a disposable verification signing key, matching CI; production signing credentials are unavailable. Artifacts are verification-only and must not be published as a production release. Cost if wrong: no production-signature validation is claimed.
