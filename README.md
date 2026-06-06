<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./assets/provii-logo-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="./assets/provii-logo-light.png">
    <img alt="Provii" src="./assets/provii-logo-light.png" width="200">
  </picture>
</p>

<h1 align="center">provii-mobile-sdk</h1>

<p align="center">On device age verification for iOS and Android. Zero knowledge proofs with no personal data on your servers.</p>

<p align="center">
  <a href="https://github.com/provii/provii-mobile-sdk/actions/workflows/ci.yml"><img src="https://github.com/provii/provii-mobile-sdk/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/provii/provii-mobile-sdk/actions/workflows/security-audit.yml"><img src="https://github.com/provii/provii-mobile-sdk/actions/workflows/security-audit.yml/badge.svg" alt="Security audit"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/licence-Apache--2.0-blue" alt="Licence"></a>
  <img src="https://img.shields.io/badge/iOS-17.6+-000000?logo=apple" alt="iOS 17.6+">
  <img src="https://img.shields.io/badge/Android-API%2029+-3DDC84?logo=android&logoColor=white" alt="Android API 29+">
</p>

## Install

Releases ship as prebuilt native libraries with generated Swift and Kotlin bindings. Grab the latest bundle from [GitHub Releases](https://github.com/provii/provii-mobile-sdk/releases), then verify its signature with [cosign](https://docs.sigstore.dev/signing/quickstart/).

```bash
gh release download --repo provii/provii-mobile-sdk \
  --pattern 'provii-mobile-sdk-bundle.tar.gz*'

cosign verify-blob \
  --bundle provii-mobile-sdk-bundle.cosign-bundle \
  --certificate-identity-regexp="https://github.com/provii/provii-mobile-sdk/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  provii-mobile-sdk-bundle.tar.gz

tar -xzf provii-mobile-sdk-bundle.tar.gz
```

### iOS (Swift Package Manager)

Copy the XCFramework and generated Swift source into your project.

```bash
cp -R release-artifacts/ios/ProviiSDK.xcframework YourApp/Frameworks/
cp release-artifacts/bindings/swift/ProviiSDK.swift YourApp/Sources/
```

Link `ProviiSDK.xcframework` in your target's "Frameworks, Libraries, and Embedded Content" section. Set embed mode to "Embed & Sign".

### Android (Gradle)

Copy the native `.so` files into your JNI directory structure and drop the Kotlin bindings into your source tree.

```bash
cp -R release-artifacts/android/* app/src/main/jniLibs/
cp -R release-artifacts/bindings/kotlin/* walletsdk/src/main/java/
```

Add the JNA dependency to your module's `build.gradle.kts`:

```kotlin
dependencies {
    implementation("net.java.dev.jna:jna:5.17.0@aar")
}
```

Every release ships binaries for arm64-v8a and armeabi-v7a (physical devices) plus x86_64 (emulators), so you can target all common configurations from one artifact.

## Quick start

### iOS

```swift
import ProviiSDK

// device_model and os_version are optional
let appInfo = AppInfo(
    version: "1.0.0",
    buildNumber: "42",
    platform: "iOS",
    deviceModel: "iPhone15,2",
    osVersion: "17.6"
)

let wallet = ProviiWallet(appInfo: appInfo)
let store = try createDefaultSecureStore()
try wallet.setStorageHandle(handle: store)

// Download and initialise the Groth16 proving key (first launch only)
let filesDir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0].path
if !provingKeyIsAvailable(appFilesDir: filesDir) {
    try provingKeyDownload(appFilesDir: filesDir, progressListener: self)
}
try provingKeyInit(appFilesDir: filesDir)

// Scan a QR code, generate a proof, submit it
let challengeId = try wallet.processQrChallenge(qrContent: scannedString)
let proofJson = try wallet.createAgeProofAuto(challengeId: challengeId)
let accepted = try wallet.submitProof(proofJson: proofJson)
```

### Android

```kotlin
import app.provii.wallet.sdk.*

// device_model and os_version are optional
val appInfo = AppInfo(
    version = "1.0.0",
    buildNumber = "42",
    platform = "Android",
    deviceModel = Build.MODEL,
    osVersion = Build.VERSION.RELEASE
)

initAndroidLogging()
val wallet = ProviiWallet(appInfo)
val store = createDefaultSecureStore()
wallet.setStorageHandle(store)

// Download and initialise the Groth16 proving key (first launch only)
val filesDir = context.filesDir.absolutePath
if (!provingKeyIsAvailable(filesDir)) {
    provingKeyDownload(filesDir, progressListener)
}
provingKeyInit(filesDir)

// Scan a QR code, generate a proof, submit it
val challengeId = wallet.processQrChallenge(scannedString)
val proofJson = wallet.createAgeProofAuto(challengeId)
val accepted = wallet.submitProof(proofJson)
```

## What happens under the hood

Everything is Rust. The SDK compiles to native code for each target platform, and [UniFFI](https://mozilla.github.io/uniffi-rs/) generates idiomatic Swift and Kotlin bindings from the Rust source. The platform storage backends (iOS Keychain, Android Keystore) use native APIs directly. No C bridging code to maintain.

When a user scans a verifier's QR code, the SDK parses the challenge, pulls the stored credential and its secret blinding randomness from the platform keychain, then generates a Groth16 zero knowledge proof over the BLS12-381 curve entirely on device. The proof attests that the holder's date of birth satisfies the verifier's age threshold. Nothing else is revealed. Rayon parallelises the proving computation across available cores. A Pixel 6 generates a proof in about 5 seconds. Newer hardware is faster still.

One network call. The device POSTs the proof to the verifier API over HTTP/3 (QUIC via Quinn). Secret key material is wrapped in `zeroize` types and scrubbed from memory the moment the proof is built.

## Requirements

| Platform | Minimum version | Notes |
|----------|----------------|-------|
| iOS | 17.6 | Xcode 15+, arm64 device and simulator targets |
| Android | API 29 (10.0) | NDK r26d, ships arm64-v8a, armeabi-v7a, x86_64 |
| Rust (contributors) | Edition 2021 | Only needed if building from source |
| Sigstore cosign | Latest | Only needed to verify release signatures |

Full working examples for both platforms live in [provii-demos](https://github.com/provii/provii-demos).

## Licence

Apache License 2.0. See [LICENSE](LICENSE) for the full text.
