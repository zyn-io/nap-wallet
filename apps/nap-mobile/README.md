# Nap Wallet for iOS and Android

The same wallet as nap.zyn-network.com and the browser extension, in a native
shell: `apps/nap-web` built with `--mode mobile` (endpoints on
nap.zyn-network.com, see `apps/nap-web/src/origin.js`) inside Tauri 2's web view.
The Rust side is only the shell — no commands, no plugins — so the app is
exactly the wallet: keys made and sealed on the phone, chain reads and signed
transactions to Nap's server. Nap's server answers the app's origins
(`tauri://localhost` on iOS, `http://tauri.localhost` on Android) and no other
cross-origin page (`apps/nap-web/functions/_middleware.js`).

Identifier: `io.infinityteam.napwallet` (both stores). Version: `version` in
`src-tauri/tauri.conf.json`.

## Build and run

```sh
npm install
. scripts/android-env.sh            # Android only: SDK, NDK, JDK, short target dir

npm run ios:sim                     # simulator build → src-tauri/gen/apple/build/arm64-sim/Nap Wallet.app
xcrun simctl install booted "src-tauri/gen/apple/build/arm64-sim/Nap Wallet.app"
xcrun simctl launch booted io.infinityteam.napwallet

npm run android:apk                 # debug APK (WebView debuggable) → gen/android/app/build/outputs/apk/…
adb install -r src-tauri/gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk
```

Debug builds are inspectable: Safari → Develop → Simulator on iOS;
`chrome://inspect` (or `adb forward tcp:9333 localabstract:webview_devtools_remote_<pid>`
and Playwright's `connectOverCDP`) on Android.

Checked 25 Sep 2026: iOS 26.2 simulator (iPhone 17 Pro) and Android 16
emulator — secure context, the chain read (mainnet epoch; testnet wallet
restored, coins named, Zcash address derived and the block scan running in the
app's WebAssembly), safe areas.

## Release

**iOS** (App Store Connect):

1. Apple Developer Program, **enrolled as an organization** (App Review
   guideline 3.1.5: crypto wallets must come from an organization; needs a
   D-U-N-S number).
2. Put the team id in `src-tauri/tauri.conf.json` → `bundle.iOS.developmentTeam`,
   then `npm run ios:release` (archive + export for App Store Connect).
3. Upload the `.ipa` with Xcode's Organizer or Transporter; fill the listing from
   `store/LISTING.md`; screenshots in `store/ios/` (6.9", 1320×2868).

**Android** (Google Play):

1. `sh scripts/make-upload-key.sh` — creates the upload key under
   `~/.nap-release/` and writes `src-tauri/gen/android/keystore.properties`
   (both ignored by git). Back the key up; Play App Signing holds the app
   signing key, this one only uploads.
2. `npm run android:release` → `src-tauri/gen/android/app/build/outputs/bundle/universalRelease/app-universal-release.aab`.
3. Play Console: listing from `store/LISTING.md`, graphics in `store/play/`.

Native libraries are linked for 16 KB pages (`src-tauri/.cargo/config.toml`),
which Play requires for new apps targeting Android 15+.

## The Nap browser

`plugins/napbrowser` (DECISIONS §152, its README): sites in their own web view,
finding Nap through its provider, approvals in native sheets. The wallet menu's
"Browser" opens it; outside links from the wallet open there too. Android test:
`tests/browser.android.e2e.mjs` (header says how to run it).

## Face ID / fingerprint

`plugins/napvault` keeps the kept wallet's password behind the device's
biometrics (DECISIONS §151, its README). iOS needs `NSFaceIDUsageDescription`
(in `gen/apple/project.yml`; run `xcodegen generate` in `gen/apple` after
editing it). The app's pages reach it through `withGlobalTauri` and the
`capabilities/default.json` grant.

## Local toolchain note

On 25 Sep 2026 this machine's NDK 27.1 wrappers `aarch64-linux-android24-clang`
and `…-clang++` called themselves instead of `clang` ("Argument list too
long"). They were restored to the NDK's own wrapper (the broken copies are kept
beside them as `*.broken-bak-20260925`). `scripts/android-env.sh` still detects
and works around the broken form if it comes back.
