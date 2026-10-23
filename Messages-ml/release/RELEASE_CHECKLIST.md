# Sentinel release checklist

| Gate | Result | Evidence |
|---|---|---|
| Frozen V4.3 artifacts loaded directly | PASS | SHA-256s in manifest; 4019 features, 111 iterations |
| VAL / TEST / OOD reproduction | PASS | 2222/2316 & 16/807; 1510/1556 & 2/520; 761/794 & 1/255 |
| V4.3 Android golden parity | PASS | 115/115 labels; max preprocessing delta 2.2888e-7; max probability delta 1.8585e-4 |
| Threshold boundaries | PASS | 0.59, 0.60, 0.609, 0.610, 0.611, 0.62, 0.704 covered |
| Explicit V4.3 selection / no version fallback | PASS | Single MessageReleaseConfig; load/hash failure returns unavailable scanner and logs critical error |
| APK message assets | PASS | APK contains only the four expected V4.3 message assets; byte hashes match exporter |
| URL model asset | PASS | V8.0.0; asset hash recorded |
| Full Android unit suite | PASS | 377 tests across 49 suites, 0 failures/errors |
| Nine fixed pipeline smoke cases | PASS (Robolectric) | Message/URL inference, evidence extraction, and risk fusion |
| Clean release APK build | PASS | `clean :app:assembleRelease`; version 2.1.0 (code 1) |
| APK SHA-256 | PASS | See `APK_HASHES.txt` |
| Release signing | BLOCKED | APK is unsigned; no release key/configuration |
| On-device notification/action flow | BLOCKED | No attached Android device/emulator; only Robolectric and unit tests ran |

**Decision: BLOCKED.** The APK is a reproducible unsigned release build, not an installable signed release. Do not distribute as a release until signed with the authorized release key and the on-device notification/action path is smoke-tested.
