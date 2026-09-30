# KyPost for Android

KyPost for Android is an Android email client backed by a self-hosted KyPost relay, with keyword-based inbox tabs and two-way contact sync authenticated through native-push pairing. See [app/AGENTS.md](app/AGENTS.md).

For any UI/theming/visual work, read [STYLE_GUIDE.md](STYLE_GUIDE.md) first — it defines
how this app's look should align with the sibling web app (`../llama labels/frontend`)
while staying native Android, and is binding for colors, shape, typography, and
component patterns.

# Pairing paths

- Besides QR/deep link and the review-only password path, "Sign in with KyIdentity" (`signon/`) pairs through KyAuth's `org.kysecurity.identity` account. The button shows only when `AuthenticatorPin.trustedAuthenticator` sees exactly one such authenticator, from `org.kysecurity.authenticator`, with a pinned signing certificate. The flow reads `GET /api/auth/sso-config` (`issuerUrl`, `clientId`), requires the account's `server_url` to match `issuerUrl`, calls `AccountManager.getAuthToken(account, clientId, ...)` (KyAuth prompts and returns a short-lived ID token) and posts it to `POST /api/auth/native/signon`. The reply is the same `kypost://native-pair` deep link the password path gets, so everything after is the normal pairing pipeline. The token is never stored. KyAuth pins only `org.kysecurity.mail`, so the `github` and `fdroid` flavors are refused until pinned and hide the button.

# Distribution channels

Three product flavors on the `channel` dimension, in `app/build.gradle.kts`:

| Flavor | `applicationId` | Ships as |
| --- | --- | --- |
| `play` | `org.kysecurity.mail` | Play bundle, `bundlePlayRelease` |
| `github` | `org.kysecurity.mail.github` | sideload APK, `assembleGithubRelease` |
| `fdroid` | `org.kysecurity.mail.fdroid` | built by F-Droid from source |

`play` must keep `org.kysecurity.mail`; it is the id in the Play listing, and Play App
Signing is scoped to it. `play` is the default variant because it sets `isDefault = true`
in `productFlavors` — declaration order does **not** determine this. Without it, AGP picks
alphabetically, so `fdroid` would win and bare `./gradlew lint` (and CI's `lint`) would
analyse `fdroidDebug` instead of `play`.

`namespace` stays `org.kysecurity.mail` on every flavor — Kotlin packages, `BuildConfig`
and manifest class names are flavor-independent, and `allowedExportedComponents` in
`app/build.gradle.kts` lists them by their fixed names.

Anything that identifies this app to the *device* must derive from `applicationId`, or
the three installs collide. Today that is the two provider authorities (already
`${applicationId}`-interpolated in the manifest) and the contacts `accountType` (the
`contact_account_type` resValue, mirrored by `DeviceContactAccount.ACCOUNT_TYPE`).
Adding another such identifier means adding it to that list.

Variant-named Gradle tasks: use `…PlayDebug`, not `…Debug`.

# Ponytail, lazy senior dev mode

Use the smallest correct change.

1. Reuse what already exists.
2. Prefer stdlib and native platform APIs.
3. Add dependencies only when they remove meaningful code.
4. Fix shared root causes, not one caller.
5. If a shortcut has a limit, mark it with `ponytail:` and name the upgrade path.

Non-trivial logic must include one runnable check (unit test or minimal self-check).

# DOX framework

## Core Contract

- AGENTS.md files are binding contracts for their subtree.
- Read from root to nearest AGENTS.md before editing.
- The nearest AGENTS.md controls local details; parent docs keep global rules.

## Update After Editing

- Run a DOX pass for every meaningful change.
- Update nearest owning AGENTS.md when behavior, responsibilities, or verification changes.
- Keep Child DOX Index entries current and delete stale rules.

## User Preferences

- Best-effort 90-second keyword refresh policy (foreground cadence; background catch-up on resume).
- DOX hierarchy scope is app-only.

## Child DOX Index

- `app/` — Android application module, runtime code, resources, tests, and app-level verification contracts. See [app/AGENTS.md](app/AGENTS.md).
