# Simulation run evidence


Evidence vocabulary: **OBSERVED** = inspected/computed in this pass; **REPORTED** = earlier document or user statement, not reproduced here; **ASSUMED** = proposed design, hypothesis, or conditional calculation, not measured behavior.

**Disposition: STOPPED AT PREFLIGHT. Neither simulation nor sealed final exam was frozen. No model inference, training, calibration, threshold change, export, promotion, Android execution, or Phase 2–7 implementation occurred.** The requested zero-overlap and evidence sufficiency conditions were not met. These are blocker/conditional-design documents, not completed baseline results or an approval-ready training authorization.

## Integrity and environment

**OBSERVED:** workspace `C:\Users\user\Programing files\Yajat\Projects\sentinel`. Environment: `Windows-11-10.0.26200-SP0`; Python `C:\Users\user\AppData\Local\Programs\Python\Python314\python.exe`, `3.14.4 (tags/v3.14.4:23116f9, Apr  7 2026, 14:10:54) [MSC v.1944 64 bit (AMD64)]`. User-facing date October 22, 2026, Asia/Calcutta. See `environment.json` for exact executable/platform/argv. No external packages, project-code imports, network calls, Kotlin/JVM/Gradle runs or Git mutations. Scripts were invoked with `-B`; Git status subprocesses set `GIT_OPTIONAL_LOCKS=0`.

**OBSERVED:** 294 selected existing artifact/data/manifest files hashed before substantive audit and after it, then again at report completion. Changed files: []. Additional training/replay source hash changes: []. Before/after Git exit codes [0, 0]; file-by-file porcelain identical = True; 93 pre-existing porcelain lines. “Identical” means complete status strings, not count equality. Initial reconnaissance also read Git status before the persisted baseline; no mutations occurred between them. Hash collection excludes venv/.git/build/.gradle/node_modules caches and is not a claim of a whole-disk content audit.

| Primary artifact | Before SHA-256 | Final SHA-256 |
|---|---|---|
| `sentinel-ml/6sep/messages/final/champion_v2_model.pkl` | `d10108f3e38e53b0c93185a2544327c7a06ed320109e6c219a5184e9bd8ca887` | `d10108f3e38e53b0c93185a2544327c7a06ed320109e6c219a5184e9bd8ca887` |
| `sentinel-ml/Messages-ml/messages_v4_3/models/candidate_d/model.pkl` | `2ca29457acd27bf93d6967d8f9d64778b8ba0e404030175465c802fe1a138a7d` | `2ca29457acd27bf93d6967d8f9d64778b8ba0e404030175465c802fe1a138a7d` |
| `sentinel-ml/URL-ml/models/v7_champion.joblib` | `d414bf668484ea5ba6056b626f0d8e674e0085208ba23d964522b09557affdaa` | `d414bf668484ea5ba6056b626f0d8e674e0085208ba23d964522b09557affdaa` |
| `sentinel-ml/URL-ml/models/v8_champion.joblib` | `073e70f215c0c3279288ec69a692ed5cab7e99a443ed7b4f87da51ae67cf0e58` | `073e70f215c0c3279288ec69a692ed5cab7e99a443ed7b4f87da51ae67cf0e58` |

**OBSERVED:** all companion scaler/vectorizer/portable/APK files selected by the audit are listed individually in `hashes_before.json`, `hashes_after.json`, and `hashes_final.json`, with sizes. These primary hashes match the master plan's reported primary identities; duplicates remain separately listed. `reference_hashes.json` commits the inspected source documents, not proof their claims are true. Data hashes and matched row indices are in `schema_recovery_findings.json`. Derived CP437 byte hashes are labeled derived in `oem_recovery_findings.json`; originals were never rewritten.

## Substantive commands, results and counts

**OBSERVED:** all commands below ran from `C:\Users\user\Programing files\Yajat\Projects\sentinel` in PowerShell; exit code 0 for each. Expected data-format exceptions were caught within successful audit scripts and are retained in JSON. Commands are exact (no model call is hidden inside them); inspect the adjacent scripts for full procedure.

```powershell
python -B reports/simulation_diagnosis/20261022_preflight_01/audit_preflight.py before
python -B reports/simulation_diagnosis/20261022_preflight_01/audit_schema_and_recovery.py
python -B reports/simulation_diagnosis/20261022_preflight_01/audit_oem_recovery.py
python -B reports/simulation_diagnosis/20261022_preflight_01/audit_preflight.py after
python -B reports/simulation_diagnosis/20261022_preflight_01/write_deliverables.py
```

**OBSERVED commands inside scripts:** `git -C "C:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ai" status --porcelain` (three persisted snapshots); standard-library SHA-256 streaming, JSONL parsing, read-only immutable SQLite metadata/count queries, and in-memory deserialization/tar reads. SQL statements and exact subprocess argv/cwd/exit codes are retained in scripts and Git JSON. Counts: 21 training JSONL files screened, 294 replay rows (291/3 labels), 562 recovered-history rows (562 security labels absent), old parsed rows 34/26 rejected, 3 raw UTF-16 inputs probed, 2 reconstructed DB query failures, no inferred labels, zero simulation/exam rows frozen, zero models invoked. Model artifacts were hashed, never unpickled.

**OBSERVED audit correction:** the first script expected `text`/`label` and failed to recognize `raw_text`/`security_label`. Its training-label and zero-replay-overlap fields in `preflight_findings.json` are INVALID. The schema-aware second script supersedes those fields, yielding 9/294 and 6/562 normalized overlaps. That error does not affect first-script byte hashes, file counts, database headers or caught DB errors. A negative Latin-1 recovery test did not prove irreversible corruption: subsequent strict CP437 tests round-tripped and found a tar member; database completeness is still unvalidated. All attempts were retained, none overwritten.

## Complete before/after Git porcelain

**OBSERVED before** (unmodified source strings from `git_before.json`):

```text
 M README.md
 M android-app/agents/src/main/java/com/sentinel/ai/agents/sender/SenderClassifier.kt
 M android-app/agents/src/main/java/com/sentinel/ai/agents/whatsapp/NotificationAgentCoordinator.kt
 M android-app/agents/src/main/java/com/sentinel/ai/agents/whatsapp/NotificationEventBuilder.kt
 M android-app/agents/src/main/java/com/sentinel/ai/agents/whatsapp/NotificationParser.kt
 M android-app/agents/src/main/java/com/sentinel/ai/agents/whatsapp/NotificationThreatAnalyzer.kt
 M android-app/agents/src/main/java/com/sentinel/ai/agents/whatsapp/WhatsAppModels.kt
 M android-app/agents/src/test/java/com/sentinel/ai/agents/whatsapp/NotificationThreatAnalyzerTest.kt
 M android-app/agents/src/test/java/com/sentinel/ai/agents/whatsapp/WhatsAppEventBuilderTest.kt
 M android-app/agents/src/test/java/com/sentinel/ai/agents/whatsapp/WhatsAppNotificationParserTest.kt
 M android-app/app/build.gradle.kts
 D android-app/app/src/main/assets/champion_v2_char_vocab_idf.json
 D android-app/app/src/main/assets/champion_v2_scaler.json
 D android-app/app/src/main/assets/champion_v2_trees.json
 D android-app/app/src/main/assets/champion_v2_word_vocab_idf.json
 D android-app/app/src/main/assets/v7_champion_portable.json
 M android-app/app/src/main/java/com/sentinel/ai/contacts/AndroidContactResolver.kt
 M android-app/app/src/main/java/com/sentinel/ai/listeners/SentinelNotificationListener.kt
 M android-app/app/src/main/java/com/sentinel/ai/protection/intent/IntentThreatAnalyzerImpl.kt
 M android-app/app/src/main/java/com/sentinel/ai/protection/intent/ScanLoadingActivity.kt
 M android-app/app/src/main/java/com/sentinel/ai/ui/settings/SettingsActivity.kt
 M android-app/app/src/main/java/com/sentinel/ai/warning/WarningModule.kt
 M android-app/app/src/main/res/drawable/ic_launcher.xml
 M android-app/app/src/main/res/values/themes.xml
 M android-app/app/src/test/java/com/sentinel/ai/protection/intent/IntentThreatAnalyzerImplTest.kt
 M android-app/app/src/test/java/com/sentinel/ai/protection/intent/ScanLoadingActivityTest.kt
 D android-app/app/src/test/java/com/sentinel/ai/protection/intent/link/BrowserLauncherTest.kt
 D android-app/app/src/test/java/com/sentinel/ai/protection/intent/link/BrowserSelectionPolicyTest.kt
 D android-app/core/src/main/java/com/sentinel/ai/core/browser/BrowserLauncher.kt
 D android-app/core/src/main/java/com/sentinel/ai/core/browser/BrowserSelectionPolicy.kt
 M android-app/core/src/main/java/com/sentinel/ai/core/di/MlModule.kt
 M android-app/core/src/main/java/com/sentinel/ai/core/fusion/RiskFusionEngine.kt
 M android-app/core/src/main/java/com/sentinel/ai/core/fusion/RiskFusionModels.kt
 M android-app/core/src/main/java/com/sentinel/ai/core/ml/messages/DualTfidfVectorizer.kt
 M android-app/core/src/main/java/com/sentinel/ai/core/ml/messages/FeatureScaler.kt
 M android-app/core/src/main/java/com/sentinel/ai/core/ml/messages/MessageAdjudicator.kt
 M android-app/core/src/main/java/com/sentinel/ai/core/ml/messages/MessageAssetLoader.kt
 M android-app/core/src/main/java/com/sentinel/ai/core/ml/messages/MessageFeatureExtractor.kt
 M android-app/core/src/main/java/com/sentinel/ai/core/ml/messages/MessageScanner.kt
 M android-app/core/src/main/java/com/sentinel/ai/core/ml/messages/MultiClassTreeEvaluator.kt
 M android-app/core/src/main/java/com/sentinel/ai/core/ml/url/HistGbmTreeEvaluator.kt
 M android-app/core/src/main/java/com/sentinel/ai/core/ml/url/SafeDomainAdjudicator.kt
 M android-app/core/src/main/java/com/sentinel/ai/core/ml/url/UrlFeatureExtractor.kt
 M android-app/core/src/main/java/com/sentinel/ai/core/ml/url/UrlScanner.kt
 D android-app/core/src/main/java/com/sentinel/ai/core/preferences/BrowserPreferenceRepository.kt
 M android-app/core/src/test/java/com/sentinel/ai/core/fusion/RiskFusionEngineTest.kt
 M android-app/core/src/test/java/com/sentinel/ai/core/ml/messages/MessageParityTest.kt
 M android-app/core/src/test/java/com/sentinel/ai/core/ml/url/UrlParityTest.kt
 D android-app/core/src/test/java/com/sentinel/ai/core/preferences/BrowserPreferenceRepositoryTest.kt
 M android-app/ui/src/main/java/com/sentinel/ai/ui/navigation/Screen.kt
 M android-app/ui/src/main/java/com/sentinel/ai/ui/navigation/SentinelNavGraph.kt
 M android-app/ui/src/main/java/com/sentinel/ai/ui/screens/dashboard/DashboardScreen.kt
 M android-app/ui/src/main/java/com/sentinel/ai/ui/screens/dashboard/DashboardUiState.kt
 M android-app/ui/src/main/java/com/sentinel/ai/ui/screens/dashboard/DashboardViewModel.kt
 M android-app/ui/src/main/java/com/sentinel/ai/ui/screens/permissions/PermissionOnboardingScreen.kt
 M android-app/ui/src/main/java/com/sentinel/ai/ui/screens/scanner/ScannerViewModel.kt
 M android-app/ui/src/main/java/com/sentinel/ai/ui/screens/settings/SettingsScreen.kt
 M android-app/ui/src/main/java/com/sentinel/ai/ui/screens/settings/SettingsViewModel.kt
 M android-app/ui/src/test/java/com/sentinel/ai/ui/ScannerViewModelTest.kt
 M docs/DEVELOPMENT.md
 M docs/SECURITY.md
 M docs/architecture.md
 M docs/features.md
 M docs/ml-integration-contract.md
?? android-app/app/src/test/java/com/sentinel/ai/ml/MessageReleaseSmokeTest.kt
?? android-app/core/src/main/assets/
?? android-app/core/src/main/java/com/sentinel/ai/core/ml/messages/MessageReleaseConfig.kt
?? android-app/core/src/main/java/com/sentinel/ai/core/sender/SenderIdentifierNormalizer.kt
?? android-app/core/src/main/java/com/sentinel/ai/core/url/
?? android-app/core/src/test/java/com/sentinel/ai/core/ml/messages/MessageAdjudicatorBoundaryTest.kt
?? android-app/core/src/test/java/com/sentinel/ai/core/ml/url/SafeDomainAdjudicationTest.kt
?? android-app/core/src/test/java/com/sentinel/ai/core/ml/url/UrlCanonicalizationTest.kt
?? android-app/core/src/test/java/com/sentinel/ai/core/ml/url/UrlV8ParityTest.kt
?? android-app/core/src/test/resources/golden_messages_v4_3.json
?? android-app/core/src/test/resources/golden_messages_v4_4.json
?? android-app/core/src/test/resources/golden_urls_v8.json
?? android-app/core/src/test/resources/messages_v4_3_char_vocab_idf.json
?? android-app/core/src/test/resources/messages_v4_3_scaler.json
?? android-app/core/src/test/resources/messages_v4_3_trees.json
?? android-app/core/src/test/resources/messages_v4_3_word_vocab_idf.json
?? android-app/core/src/test/resources/messages_v4_4_char_vocab_idf.json
?? android-app/core/src/test/resources/messages_v4_4_scaler.json
?? android-app/core/src/test/resources/messages_v4_4_trees.json
?? android-app/core/src/test/resources/messages_v4_4_word_vocab_idf.json
?? android-app/core/src/test/resources/v8_champion_portable.json
?? docs/EXPERIMENT_REPORT.md
?? docs/PROJECT_CONTEXT_DOSSIER.md
?? docs/PROJECT_STATE.md
?? docs/RELEASE_DECISION.md
?? docs/REPRODUCTION_COMMANDS.md
?? docs/ROOT_CAUSE_ANALYSIS.md
?? installed-sentinel.apk
?? ml-artifacts/message-model-archive/
```

**OBSERVED final** (unmodified source strings from `git_final.json`):

```text
 M README.md
 M android-app/agents/src/main/java/com/sentinel/ai/agents/sender/SenderClassifier.kt
 M android-app/agents/src/main/java/com/sentinel/ai/agents/whatsapp/NotificationAgentCoordinator.kt
 M android-app/agents/src/main/java/com/sentinel/ai/agents/whatsapp/NotificationEventBuilder.kt
 M android-app/agents/src/main/java/com/sentinel/ai/agents/whatsapp/NotificationParser.kt
 M android-app/agents/src/main/java/com/sentinel/ai/agents/whatsapp/NotificationThreatAnalyzer.kt
 M android-app/agents/src/main/java/com/sentinel/ai/agents/whatsapp/WhatsAppModels.kt
 M android-app/agents/src/test/java/com/sentinel/ai/agents/whatsapp/NotificationThreatAnalyzerTest.kt
 M android-app/agents/src/test/java/com/sentinel/ai/agents/whatsapp/WhatsAppEventBuilderTest.kt
 M android-app/agents/src/test/java/com/sentinel/ai/agents/whatsapp/WhatsAppNotificationParserTest.kt
 M android-app/app/build.gradle.kts
 D android-app/app/src/main/assets/champion_v2_char_vocab_idf.json
 D android-app/app/src/main/assets/champion_v2_scaler.json
 D android-app/app/src/main/assets/champion_v2_trees.json
 D android-app/app/src/main/assets/champion_v2_word_vocab_idf.json
 D android-app/app/src/main/assets/v7_champion_portable.json
 M android-app/app/src/main/java/com/sentinel/ai/contacts/AndroidContactResolver.kt
 M android-app/app/src/main/java/com/sentinel/ai/listeners/SentinelNotificationListener.kt
 M android-app/app/src/main/java/com/sentinel/ai/protection/intent/IntentThreatAnalyzerImpl.kt
 M android-app/app/src/main/java/com/sentinel/ai/protection/intent/ScanLoadingActivity.kt
 M android-app/app/src/main/java/com/sentinel/ai/ui/settings/SettingsActivity.kt
 M android-app/app/src/main/java/com/sentinel/ai/warning/WarningModule.kt
 M android-app/app/src/main/res/drawable/ic_launcher.xml
 M android-app/app/src/main/res/values/themes.xml
 M android-app/app/src/test/java/com/sentinel/ai/protection/intent/IntentThreatAnalyzerImplTest.kt
 M android-app/app/src/test/java/com/sentinel/ai/protection/intent/ScanLoadingActivityTest.kt
 D android-app/app/src/test/java/com/sentinel/ai/protection/intent/link/BrowserLauncherTest.kt
 D android-app/app/src/test/java/com/sentinel/ai/protection/intent/link/BrowserSelectionPolicyTest.kt
 D android-app/core/src/main/java/com/sentinel/ai/core/browser/BrowserLauncher.kt
 D android-app/core/src/main/java/com/sentinel/ai/core/browser/BrowserSelectionPolicy.kt
 M android-app/core/src/main/java/com/sentinel/ai/core/di/MlModule.kt
 M android-app/core/src/main/java/com/sentinel/ai/core/fusion/RiskFusionEngine.kt
 M android-app/core/src/main/java/com/sentinel/ai/core/fusion/RiskFusionModels.kt
 M android-app/core/src/main/java/com/sentinel/ai/core/ml/messages/DualTfidfVectorizer.kt
 M android-app/core/src/main/java/com/sentinel/ai/core/ml/messages/FeatureScaler.kt
 M android-app/core/src/main/java/com/sentinel/ai/core/ml/messages/MessageAdjudicator.kt
 M android-app/core/src/main/java/com/sentinel/ai/core/ml/messages/MessageAssetLoader.kt
 M android-app/core/src/main/java/com/sentinel/ai/core/ml/messages/MessageFeatureExtractor.kt
 M android-app/core/src/main/java/com/sentinel/ai/core/ml/messages/MessageScanner.kt
 M android-app/core/src/main/java/com/sentinel/ai/core/ml/messages/MultiClassTreeEvaluator.kt
 M android-app/core/src/main/java/com/sentinel/ai/core/ml/url/HistGbmTreeEvaluator.kt
 M android-app/core/src/main/java/com/sentinel/ai/core/ml/url/SafeDomainAdjudicator.kt
 M android-app/core/src/main/java/com/sentinel/ai/core/ml/url/UrlFeatureExtractor.kt
 M android-app/core/src/main/java/com/sentinel/ai/core/ml/url/UrlScanner.kt
 D android-app/core/src/main/java/com/sentinel/ai/core/preferences/BrowserPreferenceRepository.kt
 M android-app/core/src/test/java/com/sentinel/ai/core/fusion/RiskFusionEngineTest.kt
 M android-app/core/src/test/java/com/sentinel/ai/core/ml/messages/MessageParityTest.kt
 M android-app/core/src/test/java/com/sentinel/ai/core/ml/url/UrlParityTest.kt
 D android-app/core/src/test/java/com/sentinel/ai/core/preferences/BrowserPreferenceRepositoryTest.kt
 M android-app/ui/src/main/java/com/sentinel/ai/ui/navigation/Screen.kt
 M android-app/ui/src/main/java/com/sentinel/ai/ui/navigation/SentinelNavGraph.kt
 M android-app/ui/src/main/java/com/sentinel/ai/ui/screens/dashboard/DashboardScreen.kt
 M android-app/ui/src/main/java/com/sentinel/ai/ui/screens/dashboard/DashboardUiState.kt
 M android-app/ui/src/main/java/com/sentinel/ai/ui/screens/dashboard/DashboardViewModel.kt
 M android-app/ui/src/main/java/com/sentinel/ai/ui/screens/permissions/PermissionOnboardingScreen.kt
 M android-app/ui/src/main/java/com/sentinel/ai/ui/screens/scanner/ScannerViewModel.kt
 M android-app/ui/src/main/java/com/sentinel/ai/ui/screens/settings/SettingsScreen.kt
 M android-app/ui/src/main/java/com/sentinel/ai/ui/screens/settings/SettingsViewModel.kt
 M android-app/ui/src/test/java/com/sentinel/ai/ui/ScannerViewModelTest.kt
 M docs/DEVELOPMENT.md
 M docs/SECURITY.md
 M docs/architecture.md
 M docs/features.md
 M docs/ml-integration-contract.md
?? android-app/app/src/test/java/com/sentinel/ai/ml/MessageReleaseSmokeTest.kt
?? android-app/core/src/main/assets/
?? android-app/core/src/main/java/com/sentinel/ai/core/ml/messages/MessageReleaseConfig.kt
?? android-app/core/src/main/java/com/sentinel/ai/core/sender/SenderIdentifierNormalizer.kt
?? android-app/core/src/main/java/com/sentinel/ai/core/url/
?? android-app/core/src/test/java/com/sentinel/ai/core/ml/messages/MessageAdjudicatorBoundaryTest.kt
?? android-app/core/src/test/java/com/sentinel/ai/core/ml/url/SafeDomainAdjudicationTest.kt
?? android-app/core/src/test/java/com/sentinel/ai/core/ml/url/UrlCanonicalizationTest.kt
?? android-app/core/src/test/java/com/sentinel/ai/core/ml/url/UrlV8ParityTest.kt
?? android-app/core/src/test/resources/golden_messages_v4_3.json
?? android-app/core/src/test/resources/golden_messages_v4_4.json
?? android-app/core/src/test/resources/golden_urls_v8.json
?? android-app/core/src/test/resources/messages_v4_3_char_vocab_idf.json
?? android-app/core/src/test/resources/messages_v4_3_scaler.json
?? android-app/core/src/test/resources/messages_v4_3_trees.json
?? android-app/core/src/test/resources/messages_v4_3_word_vocab_idf.json
?? android-app/core/src/test/resources/messages_v4_4_char_vocab_idf.json
?? android-app/core/src/test/resources/messages_v4_4_scaler.json
?? android-app/core/src/test/resources/messages_v4_4_trees.json
?? android-app/core/src/test/resources/messages_v4_4_word_vocab_idf.json
?? android-app/core/src/test/resources/v8_champion_portable.json
?? docs/EXPERIMENT_REPORT.md
?? docs/PROJECT_CONTEXT_DOSSIER.md
?? docs/PROJECT_STATE.md
?? docs/RELEASE_DECISION.md
?? docs/REPRODUCTION_COMMANDS.md
?? docs/ROOT_CAUSE_ANALYSIS.md
?? installed-sentinel.apk
?? ml-artifacts/message-model-archive/
```

## New files created

**OBSERVED:** all new files are under `reports/simulation_diagnosis/20261022_preflight_01/`; no existing output filename was reused. This is `reports/` under the supplied sentinel workspace root, not a second nested sentinel directory. No experiment files were needed because freeze/inference stopped. All writes use exclusive creation or new-file patches. Created-file hashes are in `created_files_sha256.json`; that manifest excludes itself to avoid a circular self-hash. This list includes the evidence file and final hash manifest:

- `FAILURE_DIAGNOSIS.md`
- `FROM_SCRATCH_TRAINING_PLAN.md`
- `PLAN_AMENDMENT_TO_MASTER_PLAN.md`
- `SIMULATION_BASELINE_RESULTS.md`
- `SIMULATION_DESIGN.md`
- `SIMULATION_RUN_EVIDENCE.md`
- `audit_oem_recovery.py`
- `audit_preflight.py`
- `audit_schema_and_recovery.py`
- `created_files_sha256.json`
- `environment.json`
- `final_integrity_comparison.json`
- `git_after.json`
- `git_before.json`
- `git_final.json`
- `hashes_after.json`
- `hashes_before.json`
- `hashes_final.json`
- `integrity_comparison.json`
- `oem_recovery_findings.json`
- `preflight_findings.json`
- `reference_hashes.json`
- `schema_recovery_findings.json`
- `write_deliverables.py`

## Stop disposition and remaining requirements

**OBSERVED:** six requested document names exist as preflight-stop/conditional-design deliverables; the requested complete simulation, all-model deployment measurements, sealed final exam, exhaustive historical reconciliation and baseline-derived approved-ready gates were not achieved. The user-specified insufficient-evidence stop condition was applied before any model execution. This is not an approval request and no training is scheduled. Exact Kotlin/fusion/severity/device work **requires authorization**; raw data validation, provenance, independent labels, complete grouping and an independently held exam are the missing prerequisites.
