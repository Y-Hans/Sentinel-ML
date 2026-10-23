# Reproduction commands

Run from the workspace root unless otherwise noted.

## Frozen V4.3 ML baseline

```powershell
Set-Location sentinel-ml/Messages-ml
python scripts/reproduce_frozen_v43.py
```

Expected summary: VAL malicious 2222/2316 and benign FP 16/807; TEST 1510/1556 and benign FP 2/520; OOD 761/794 and benign FP 1/255. The script records artifact SHA-256s and per-split metrics under `messages_v4_3/evaluation/reproduction_20260930/`.

## Android parity and threshold checks

```powershell
Set-Location sentinel-ai/android-app
.\gradlew.bat :core:testDebugUnitTest --tests 'com.sentinel.ai.core.ml.messages.MessageParityTest' --tests 'com.sentinel.ai.core.ml.messages.MessageAdjudicatorBoundaryTest'
```

V4.3 must report 115/115 label parity; max preprocessing delta <= 0.045 and max probability delta <= 0.03.

## Full Android unit suite

```powershell
.\gradlew.bat testDebugUnitTest
```

Recorded final run: 377 tests in 49 suites, 0 failures, 0 errors, 0 skipped. Includes nine-case `MessageReleaseSmokeTest`.

## Release APK build

```powershell
.\gradlew.bat clean :app:assembleRelease
```

The current output is unsigned at `app/build/outputs/apk/release/app-release-unsigned.apk`. Do not treat this as a distributable release. The archived copy is `sentinel-ml/Messages-ml/release/apk/SentinelAI-2.1.0-release-unsigned.apk`.

## Verify APK assets and hashes

```powershell
Set-Location sentinel-ml/Messages-ml/release
python verify_release_apk.py apk/SentinelAI-2.1.0-release-unsigned.apk
```
