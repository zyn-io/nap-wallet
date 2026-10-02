# napvault — Face ID / fingerprint unlock for Nap (DECISIONS §151)

One secret, the kept wallet's password, behind this device's biometrics:

- **iOS:** a Keychain item with `.biometryCurrentSet` access control,
  `WhenPasscodeSetThisDeviceOnly` (no backup, no iCloud). `unlock` asks for the
  face explicitly (`LAContext.evaluatePolicy`) and reads the item with that
  context; enrolling a new face invalidates it.
- **Android:** an AES-256-GCM key in the Android Keystore that needs a strong
  biometric for every use (`BiometricPrompt` + `CryptoObject`), invalidated when
  fingerprints change; the ciphertext is in the app's private preferences.

Commands (`plugin:napvault|…`): `status` → `{available, kind, stored}`,
`store {secret}`, `unlock {reason}` → `{secret}`, `forget`. The web wallet
(`apps/nap-web/src/app.js`, phone app only) offers it once after the password
opens the wallet, and puts "Open with Face ID" first on the unlock screen.

Checked 25 Sep 2026: Android 16 emulator end to end (10 checks); iOS 26.2
simulator — waits for a face, a match releases the secret, a wrong face does
not. The simulator's Keychain does not enforce biometric access control on its
own, which is why `unlock` checks the face explicitly.
