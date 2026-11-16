# Troubleshooting

- **QR scanned but app remains unpaired:** registration must succeed; check connectivity, fresh pairing token and matching HTTPS origins.
- **Wrong app opens the link:** select the intended channel in Android's chooser.
- **No notification on Android 13+:** check runtime permission, delivery mode and background restrictions.
- **FCM absent in pull mode:** this is expected; verify the app's direct polling instead.
- **Encrypted mail opens webmail:** complete the account's separate device key enrollment if local decryption is required.
- **Old sideload cannot update:** follow the documented GitHub package-ID migration. Uninstalling erases that copy's local data.

When reporting a problem, include the product version, platform, failed task and a redacted error. Exclude pairing links, device secrets, recovery codes, custodian shares and private content.
