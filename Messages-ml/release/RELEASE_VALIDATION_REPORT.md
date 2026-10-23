# Release validation report

## Decision

**BLOCKED**. The release build succeeds and the V4.3 integration gates pass in automated tests. The APK is unsigned, and a device was not available for an on-device notification/action smoke.

## Model and baseline

The immutable V4.3 Candidate-D artifact set reproduced directly. It uses 19 structural + 1500 word TF-IDF + 2500 char_wb TF-IDF features (4019 total), HistGradientBoostingClassifier, 111 effective iterations, class order BENIGN / SUSPICIOUS_SPAM / MALICIOUS, and τ=0.61. Hashes are in the release manifest.

| Split | Malicious recall | Benign FPR |
|---|---:|---:|
| VAL | 2222/2316 = 95.94% | 16/807 = 1.98% |
| TEST | 1510/1556 = 97.04% | 2/520 = 0.38% |
| OOD | 761/794 = 95.84% | 1/255 = 0.39% |

## Android parity and tests

V4.3 parity passed on 130 / 130 golden records (100% label parity). Maximum preprocessing delta was None; maximum probability delta was None. Threshold tests passed at all seven requested probabilities. Full unit suite: 377 tests in 49 suites, zero failures/errors/skips.

The nine-case Robolectric smoke used the actual packaged V4.3 and V8 assets and traversed model inference, message/URL evidence generation, and risk fusion. Existing notification parser/listener and coordinator tests also passed. No emulator/device was attached; therefore Android system notification capture, warning dispatch, and action behavior were not verified on-device.

## Model wiring and packaging

Runtime explicitly requests the four V4.3 assets and verifies each SHA-256 plus version, dimensions, class order, and iteration count. Load or parse errors produce an unavailable scanner that raises into the existing critical unavailable-evidence path; no V4.4/V2 fallback remains. The APK was inspected as a ZIP: it contains exactly the four V4.3 message assets, all matching the declared hashes; V4.4/V2 message assets are absent. URL model V8.0.0 is packaged and hashed.

The APK also contains `model.tflite` and `scaler.json`; repository search found no production call sites for the old `MLInferenceManager` outside that class. Their hashes are recorded as additional packaged assets, separate from the selected message model.

## Build artifact

- Application: `com.sentinel.ai`
- Version: `2.1.0` (version code 1)
- APK: `sentinel-ml/Messages-ml/release/apk/SentinelAI-2.1.0-release-unsigned.apk`
- SHA-256: `a79f290d37ad625eef6600774a26eda2d44569e17365c7df321da32675f65398`
- Signing: **unsigned** (`app-release-unsigned.apk`; no release signing configuration/key found)
- Source commit: `85da31ca364b0a38c2265442d3919e11fc858390`; checkout was dirty (112 status entries). The Android build-input tree fingerprint is recorded in the manifest.

## Release blockers

1. The artifact is unsigned. The APK does not verify with `apksigner`; no release signing configuration/key is set. I did not sign with a debug key.
2. No Android device/emulator was attached (`adb devices` returned no devices). On-device notification capture through final user notification/action remains unverified.
