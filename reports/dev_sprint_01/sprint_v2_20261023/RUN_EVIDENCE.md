# Run evidence — Messages sprint v2 through Stage4

OBSERVED date23 October2026, Asia/Calcutta. Workdir `C:\Users\user\Programing files\Yajat\Projects\sentinel`. Outputs only under `C:\Users\user\Programing files\Yajat\Projects\sentinel\reports\dev_sprint_01\sprint_v2_20261023`. Zero candidate/calibration/vocabulary/scaler fits; no GPU request, installs, export, Android/Kotlin/Gradle execution, Git mutation or existing-file overwrite. datasets_v5/user_data never opened. URL-ml was not written. Protected file hashing deliberately uses the fixed run_02/protected_v2_before.json list, not a fresh directory walk.

## Integrity

OBSERVED: all 1750 fixed protected files match before/after byte counts and SHA256; historical manifest also matched at entry. Full maps: protected_before.json and protected_after.json. File-list SHA is in environment.json. Git status file-by-file identical, both commands exit0. Frozen file hashes unchanged. V1 SHA remains c28521e5fd7c5f55240176a10ffa416a7dc6e5cdb1843fab604a1018db563e44. Final integrity command `python -B reports/dev_sprint_01/sprint_v2_20261023/sprintlib.py validation` exited0; integrity_checks.json gives every check. Existing uncommitted Git state was preserved.

OBSERVED: freeze_manifest.json timestamp precedes inference process stdout-log creation, verified using filesystem nanosecond timestamps and source order. Reproduction gate was asserted before any probe scoring. probe_v2.csv final SHA `b57438c786d163068844486d620a3617216ac5fa11564206bbf97ab607a86d48`; frozen design SHA `6a2fc5b3c71b70278dff210fd05f3ca4188b51e901bb1c2c6d0ae7adae750245`. The root probe_v2.csv/REVIEW_SAMPLE_v2.csv are preserved rejected-channel-balance drafts; the canonical deliverables are in frozen/. No text/label changed in the corrected version.

## Execution environment and provenance

OBSERVED Python `C:\Users\user\AppData\Local\Programs\Python\Python314\python.exe`: 3.14.4 (tags/v3.14.4:23116f9, Apr  7 2026, 14:10:54) [MSC v.1944 64 bit (AMD64)]. numpy 2.5.2; sklearn 1.9.0; unpickle warnings in inference_manifest.json. All eight bundles loaded. CUDA_VISIBLE_DEVICES=-1, OMP/OPENBLAS/MKL threads1, PYTHONDONTWRITEBYTECODE=1, Python-B. Native Windows CPU topology reports 10 physical cores, future-fit cap 5; all current inference used1 thread. Initial CIM discovery was denied and psutil was absent; no installation/escalation occurred. CPU topology was subsequently read via GetLogicalProcessorInformationEx and recorded separately, preserving the original fallback record.

OBSERVED: 1,375 frozen v2 rows =600/400/100 Hinglish +150/100/25 English. All1,100 Hinglish texts have7–29 words;240/600 attacks URL-less;834 URL-containing and242 phone-containing rows across languages match legacy regexes. Eight persona batches, maximal normalized-Jaccard connected component3. Lexical audit85 sources,42,660 normalized texts,43 overlaps tagged. Final review120 random class-stratified rows, blank user fields. Earlier review202 rows has0marks. Synthetic labels ASSUMED, natural-traffic conclusions PROVISIONAL.

OBSERVED: 32,120 new predictions, eight models ×(1,320v1 +1,320normalized v1 +1,375v2). All10,560 original v1 text-only predictions reproduce prior classes and probabilities within1e-10; zero MALICIOUS-only alert invariant errors. V4.3 TEST1510/1556 and2/520 reproduced. English metadata TEST1506/1551 and92/707 combined false alerts; full TEST1510/1556 and92/708. Historical spam confusion90/188 reproduced. No historical number was substituted for a failed measured gate.

OBSERVED:6,089 input ledger entries;315 prediction-only permutations on588 historical heldout rows. Every run/seed and source hash saved. Permutation is diagnostic sensitivity, not training or independent future validation. New-feature candidates are design only. Training log records0fits. Data audit remains pending authorized handoff. Pre-registration plus execution clarification in approval_bundle.json require user approval; no continuation into Stage5.

## Errors and limitations preserved

OBSERVED: audit_freeze.py exited1 because the first generation assigned206/194 benign channels. repair_channel.py created corrected new files by changing six metadata rows; no model had seen either draft. audit_freeze_02.py passed. Failed source/log/draft remain. The normalized v1 transform jointly changes URLs/phones and removes scenario words from URLs; it cannot isolate each causal factor. Reused benign/context phrases and one author limit independence. Invented Indian-format numeric patterns are not verified unassigned; no call/resolution was made. Two JSON audit documents >=1MB were skipped and named in corpus_audit_manifest.json. Source review/probe labels are not human-adjudicated. V1 blind71 malicious disagreements split46 Hinglish/25English, contradicting any interpretation that all71 were Hinglish.

OBSERVED shell discovery issues: initial multi-file Get-Content/Get-ChildItem command exited1 because the optional messages_v5_sprint path was absent and its combined console output was truncated; relevant files were read in bounded follow-ups. CIM discovery command exited1 with access denied. An optional candidate_d/config.json read exited1 because that file is absent (V4.3 threshold comes from the frozen loader/.61 reproduction, not an invented config). None changed files. Numeric scientific evidence is captured by the script commands below. Discovery outputs are in this conversation tool transcript; they are not mislabeled as successful scientific commands.

## Exact scientific commands

OBSERVED commands launched with `python -B reports/dev_sprint_01/sprint_v2_20261023/sprintlib.py <target>`; table records resolved child argv, cwd, exit and wall time. Each has stdout/stderr files plus hashes, source hash and environment in <target>.command.json. Failed audit is included. No candidate fit command exists.

| Command argv | CWD | Exit | Wall seconds |
| --- | --- | --- | --- |
| "C:\Users\user\AppData\Local\Programs\Python\Python314\python.exe" "-B" "C:\Users\user\Programing files\Yajat\Projects\sentinel\reports\dev_sprint_01\sprint_v2_20261023\analyze_probe.py" | C:\Users\user\Programing files\Yajat\Projects\sentinel | 0 | 0.946 |
| "C:\Users\user\AppData\Local\Programs\Python\Python314\python.exe" "-B" "C:\Users\user\Programing files\Yajat\Projects\sentinel\reports\dev_sprint_01\sprint_v2_20261023\audit_freeze.py" | C:\Users\user\Programing files\Yajat\Projects\sentinel | 1 | 1.363 |
| "C:\Users\user\AppData\Local\Programs\Python\Python314\python.exe" "-B" "C:\Users\user\Programing files\Yajat\Projects\sentinel\reports\dev_sprint_01\sprint_v2_20261023\audit_freeze_02.py" | C:\Users\user\Programing files\Yajat\Projects\sentinel | 0 | 57.729 |
| "C:\Users\user\AppData\Local\Programs\Python\Python314\python.exe" "-B" "C:\Users\user\Programing files\Yajat\Projects\sentinel\reports\dev_sprint_01\sprint_v2_20261023\feature_analysis.py" | C:\Users\user\Programing files\Yajat\Projects\sentinel | 0 | 65.137 |
| "C:\Users\user\AppData\Local\Programs\Python\Python314\python.exe" "-B" "C:\Users\user\Programing files\Yajat\Projects\sentinel\reports\dev_sprint_01\sprint_v2_20261023\generate_v2.py" | C:\Users\user\Programing files\Yajat\Projects\sentinel | 0 | 0.772 |
| "C:\Users\user\AppData\Local\Programs\Python\Python314\python.exe" "-B" "C:\Users\user\Programing files\Yajat\Projects\sentinel\reports\dev_sprint_01\sprint_v2_20261023\inference_02.py" | C:\Users\user\Programing files\Yajat\Projects\sentinel | 0 | 99.728 |
| "C:\Users\user\AppData\Local\Programs\Python\Python314\python.exe" "-B" "C:\Users\user\Programing files\Yajat\Projects\sentinel\reports\dev_sprint_01\sprint_v2_20261023\repair_channel.py" | C:\Users\user\Programing files\Yajat\Projects\sentinel | 0 | 0.267 |
| "C:\Users\user\AppData\Local\Programs\Python\Python314\python.exe" "-B" "C:\Users\user\Programing files\Yajat\Projects\sentinel\reports\dev_sprint_01\sprint_v2_20261023\snapshot.py" | C:\Users\user\Programing files\Yajat\Projects\sentinel | 0 | 25.936 |
| "C:\Users\user\AppData\Local\Programs\Python\Python314\python.exe" "-B" "C:\Users\user\Programing files\Yajat\Projects\sentinel\reports\dev_sprint_01\sprint_v2_20261023\summarize_evidence.py" | C:\Users\user\Programing files\Yajat\Projects\sentinel | 0 | 0.321 |
| "C:\Users\user\AppData\Local\Programs\Python\Python314\python.exe" "-B" "C:\Users\user\Programing files\Yajat\Projects\sentinel\reports\dev_sprint_01\sprint_v2_20261023\validation.py" | C:\Users\user\Programing files\Yajat\Projects\sentinel | 0 | 5.677 |
| "C:\Users\user\AppData\Local\Programs\Python\Python314\python.exe" "-B" "C:\Users\user\Programing files\Yajat\Projects\sentinel\reports\dev_sprint_01\sprint_v2_20261023\write_plans.py" | C:\Users\user\Programing files\Yajat\Projects\sentinel | 0 | 0.535 |


OBSERVED final evidence command: `python -B reports/dev_sprint_01/sprint_v2_20261023/finish_evidence.py`, cwd `C:\Users\user\Programing files\Yajat\Projects\sentinel`. It validates output hashes and prints COMPLETION digest; its actual exit is in the shell tool result and final_command.json upon successful completion.

## Model bundle hashes (before and after)

| Model | Artifact | Before SHA256 | After SHA256 |
| --- | --- | --- | --- |
| V2 | sentinel-ml/6sep/messages/final/champion_v2_model.pkl | d10108f3e38e53b0c93185a2544327c7a06ed320109e6c219a5184e9bd8ca887 | d10108f3e38e53b0c93185a2544327c7a06ed320109e6c219a5184e9bd8ca887 |
| V2 | sentinel-ml/6sep/messages/final/champion_v2_scaler.pkl | 6b5ecf4e4df650494b87e659a2479141d88fc28fa6f05fcbe09d2d5fe50fe999 | 6b5ecf4e4df650494b87e659a2479141d88fc28fa6f05fcbe09d2d5fe50fe999 |
| V2 | sentinel-ml/6sep/messages/final/champion_v2_tfidf_word.pkl | b1244fba45db377986d2ba1b25c525051c6e2552e103c11676cfdc05da3f1495 | b1244fba45db377986d2ba1b25c525051c6e2552e103c11676cfdc05da3f1495 |
| V2 | sentinel-ml/6sep/messages/final/champion_v2_tfidf_char.pkl | 19308b9e48529704127d8102e54ec844681c2310dcc3d71d2a5d5bd33fdd4701 | 19308b9e48529704127d8102e54ec844681c2310dcc3d71d2a5d5bd33fdd4701 |
| V4.3 | sentinel-ml/Messages-ml/messages_v4_3/models/candidate_d/model.pkl | 2ca29457acd27bf93d6967d8f9d64778b8ba0e404030175465c802fe1a138a7d | 2ca29457acd27bf93d6967d8f9d64778b8ba0e404030175465c802fe1a138a7d |
| V4.3 | sentinel-ml/Messages-ml/messages_v4_3/models/candidate_d/scaler.pkl | aab17413541b12804b70677161a540fa384b0ec0eeebed8be308de3c3c0a21b9 | aab17413541b12804b70677161a540fa384b0ec0eeebed8be308de3c3c0a21b9 |
| V4.3 | sentinel-ml/Messages-ml/messages_v4_3/models/candidate_d/word_vec.pkl | 10403d9e8b5f641fd3d200a5e08f5c65e3fdcd7afca65613d47d0f4cfbe96aac | 10403d9e8b5f641fd3d200a5e08f5c65e3fdcd7afca65613d47d0f4cfbe96aac |
| V4.3 | sentinel-ml/Messages-ml/messages_v4_3/models/candidate_d/char_vec.pkl | fa56cf5548f3ae17f0ccc5c7e8b7ba801e27be8bcd522887ea5af8bae68468b1 | fa56cf5548f3ae17f0ccc5c7e8b7ba801e27be8bcd522887ea5af8bae68468b1 |
| V4.4_candidate_a_corrected | sentinel-ml/Messages-ml/messages_v4_4/models/candidate_a_corrected/model.pkl | 08bfcf6a3da137ae1752cf74c08a39bfb26231435cca9427a6f472420e1d82a7 | 08bfcf6a3da137ae1752cf74c08a39bfb26231435cca9427a6f472420e1d82a7 |
| V4.4_candidate_a_corrected | sentinel-ml/Messages-ml/messages_v4_4/models/candidate_a_corrected/scaler.pkl | 04a9c525de01d64027774cdca55dd96cb09d061692fa4d9f243db884a12779b7 | 04a9c525de01d64027774cdca55dd96cb09d061692fa4d9f243db884a12779b7 |
| V4.4_candidate_a_corrected | sentinel-ml/Messages-ml/messages_v4_4/models/candidate_a_corrected/word_vec.pkl | e3f1868a602c9cda0340070919d4e7547f44ab234db49e1518878b96f5f0d7fd | e3f1868a602c9cda0340070919d4e7547f44ab234db49e1518878b96f5f0d7fd |
| V4.4_candidate_a_corrected | sentinel-ml/Messages-ml/messages_v4_4/models/candidate_a_corrected/char_vec.pkl | 089dcd906b0f5d7c77f9c54b45160a9fad37e0fbe203d29e9ca4bc78c235c163 | 089dcd906b0f5d7c77f9c54b45160a9fad37e0fbe203d29e9ca4bc78c235c163 |
| V4.4_candidate_b_refined | sentinel-ml/Messages-ml/messages_v4_4/models/candidate_b_refined/model.pkl | 7b6d137bc623635c132840b79e41cac6cfed8134952491ad9563730b5f9fea34 | 7b6d137bc623635c132840b79e41cac6cfed8134952491ad9563730b5f9fea34 |
| V4.4_candidate_b_refined | sentinel-ml/Messages-ml/messages_v4_4/models/candidate_b_refined/scaler.pkl | 6fae3b169a7a6d885970f80e3876007b2ae1648882ccdd1c795cf021f6012fac | 6fae3b169a7a6d885970f80e3876007b2ae1648882ccdd1c795cf021f6012fac |
| V4.4_candidate_b_refined | sentinel-ml/Messages-ml/messages_v4_4/models/candidate_b_refined/word_vec.pkl | 5a1fd2c62cd5b28426091a69be44c6a871887e875ef7317d8388d9e5991ab277 | 5a1fd2c62cd5b28426091a69be44c6a871887e875ef7317d8388d9e5991ab277 |
| V4.4_candidate_b_refined | sentinel-ml/Messages-ml/messages_v4_4/models/candidate_b_refined/char_vec.pkl | f75f0c5ae63baa26f8702d014a01826c002c1a4803f6d1a8a26656bcdc6a4abe | f75f0c5ae63baa26f8702d014a01826c002c1a4803f6d1a8a26656bcdc6a4abe |
| V4.4_candidate_c_balanced | sentinel-ml/Messages-ml/messages_v4_4/models/candidate_c_balanced/model.pkl | 633357c366da6ef389097f5fc4af91692f06057bcd60af41a7ddb3d617afec21 | 633357c366da6ef389097f5fc4af91692f06057bcd60af41a7ddb3d617afec21 |
| V4.4_candidate_c_balanced | sentinel-ml/Messages-ml/messages_v4_4/models/candidate_c_balanced/scaler.pkl | 55db1580c1aa59822f9cef622b337fa860dbd22d23f2db3844dcd4368845b2f9 | 55db1580c1aa59822f9cef622b337fa860dbd22d23f2db3844dcd4368845b2f9 |
| V4.4_candidate_c_balanced | sentinel-ml/Messages-ml/messages_v4_4/models/candidate_c_balanced/word_vec.pkl | dcdeb955a1804be9f322d93502468c205c8bc6c2dd1509f224ff8aa6649fe1f1 | dcdeb955a1804be9f322d93502468c205c8bc6c2dd1509f224ff8aa6649fe1f1 |
| V4.4_candidate_c_balanced | sentinel-ml/Messages-ml/messages_v4_4/models/candidate_c_balanced/char_vec.pkl | 2c4604d288aaeaf5f8344971406f2efcd79dcfa8bca7b9d534b4024d68fba985 | 2c4604d288aaeaf5f8344971406f2efcd79dcfa8bca7b9d534b4024d68fba985 |
| V4.4_rc2_experiment_1 | sentinel-ml/Messages-ml/messages_v4_4/models/rc2_experiment_1/model.pkl | c408eb8d99b854eedb9133cb841d00db2c49e49eec162ca87d2d8f48be047f73 | c408eb8d99b854eedb9133cb841d00db2c49e49eec162ca87d2d8f48be047f73 |
| V4.4_rc2_experiment_1 | sentinel-ml/Messages-ml/messages_v4_4/models/rc2_experiment_1/scaler.pkl | 9f2fa9fe3058d14240b3920b4641b5242ba1e12c45c5f05623be434152b2ab69 | 9f2fa9fe3058d14240b3920b4641b5242ba1e12c45c5f05623be434152b2ab69 |
| V4.4_rc2_experiment_1 | sentinel-ml/Messages-ml/messages_v4_4/models/rc2_experiment_1/word_vec.pkl | 1d4a34147563c4ea74af5250e5fbf0f01917c04b8ecfefa19b51afc0c67398be | 1d4a34147563c4ea74af5250e5fbf0f01917c04b8ecfefa19b51afc0c67398be |
| V4.4_rc2_experiment_1 | sentinel-ml/Messages-ml/messages_v4_4/models/rc2_experiment_1/char_vec.pkl | 7d48cb01bc993c4d4089ff878b1b6110e674742c837edbe28d41040780645508 | 7d48cb01bc993c4d4089ff878b1b6110e674742c837edbe28d41040780645508 |
| V4.4_rc2_experiment_2 | sentinel-ml/Messages-ml/messages_v4_4/models/rc2_experiment_2/model.pkl | 3cad1d9aa70a3bb4d145a40ef9d4b18bab3aece32c42efc3c859aad3f7080cf5 | 3cad1d9aa70a3bb4d145a40ef9d4b18bab3aece32c42efc3c859aad3f7080cf5 |
| V4.4_rc2_experiment_2 | sentinel-ml/Messages-ml/messages_v4_4/models/rc2_experiment_2/scaler.pkl | 6db5f8b7df2261a7fb6e9a1f93b2e743171d42b7b04d083f7158b97d9b90a695 | 6db5f8b7df2261a7fb6e9a1f93b2e743171d42b7b04d083f7158b97d9b90a695 |
| V4.4_rc2_experiment_2 | sentinel-ml/Messages-ml/messages_v4_4/models/rc2_experiment_2/word_vec.pkl | 41aa2ee88ae2393a5ae3761e8828a36b7cdf861b1187f49d2e09c98e3f50ef8f | 41aa2ee88ae2393a5ae3761e8828a36b7cdf861b1187f49d2e09c98e3f50ef8f |
| V4.4_rc2_experiment_2 | sentinel-ml/Messages-ml/messages_v4_4/models/rc2_experiment_2/char_vec.pkl | f81b1b62f497709e612b65eff36391f35e562c3b1478b917fa461f9c52032d78 | f81b1b62f497709e612b65eff36391f35e562c3b1478b917fa461f9c52032d78 |
| V4.4_rc2_experiment_3 | sentinel-ml/Messages-ml/messages_v4_4/models/rc2_experiment_3/model.pkl | 6449e7720eebf6f70a8a23d405fc8a3890da164417aa47c982c1a19157ae79f3 | 6449e7720eebf6f70a8a23d405fc8a3890da164417aa47c982c1a19157ae79f3 |
| V4.4_rc2_experiment_3 | sentinel-ml/Messages-ml/messages_v4_4/models/rc2_experiment_3/scaler.pkl | 7c8e9b21a01b60120373e5b637f689e235ac071c2531de622009512a9610386c | 7c8e9b21a01b60120373e5b637f689e235ac071c2531de622009512a9610386c |
| V4.4_rc2_experiment_3 | sentinel-ml/Messages-ml/messages_v4_4/models/rc2_experiment_3/word_vec.pkl | 87be636122faaa43f7b78c5ee385dd875e3749b9d377712cb11ca3e71c3919b6 | 87be636122faaa43f7b78c5ee385dd875e3749b9d377712cb11ca3e71c3919b6 |
| V4.4_rc2_experiment_3 | sentinel-ml/Messages-ml/messages_v4_4/models/rc2_experiment_3/char_vec.pkl | 6f5865df37105b38e09619a44bfbb848506febba6853d34161c91637cbfe7d23 | 6f5865df37105b38e09619a44bfbb848506febba6853d34161c91637cbfe7d23 |


## Git before — exact porcelain lines

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

## Git after — exact porcelain lines

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

## Newly created files

OBSERVED list below records files present before this evidence/manifest finalization; output_manifest.json adds final evidence/command files. COMPLETION.json commits the manifest hash; its digest is emitted to stdout to avoid circular self-hashing. No prior output was overwritten. Progress uses immutable stage subdirectories plus a final PROGRESS.md snapshot.

- DATA_AUDIT.md
- DECISION.md
- English_TEST_baselines.json
- FEATURE_CANDIDATES.md
- FEATURE_LEDGER.csv
- FEATURE_LEDGER.md
- FEATURE_POLICY_LEDGER.csv
- PRE_REGISTRATION.md
- PRE_REGISTRATION.sha256
- PRE_REGISTRATION_EXECUTION_CLARIFICATIONS.md
- PROBE_V2_DESIGN.md
- PROBE_V2_RESULTS.md
- PROBE_V2_RESULTS_SUPPLEMENT.md
- PROGRESS.md
- QUESTIONS_FOR_USER.md
- RESULTS.md
- REVIEW_SAMPLE_v2.csv
- TRAINING_LOG.md
- V43_reproduction_gate.json
- analyze_probe.command.json
- analyze_probe.py
- analyze_probe.stderr.txt
- analyze_probe.stdout.txt
- approval_bundle.json
- audit_freeze.command.json
- audit_freeze.py
- audit_freeze.stderr.txt
- audit_freeze.stdout.txt
- audit_freeze_02.command.json
- audit_freeze_02.py
- audit_freeze_02.stderr.txt
- audit_freeze_02.stdout.txt
- command_ledger.json
- corpus_audit_manifest.json
- cpu_topology.json
- diagnostic_summary.json
- environment.json
- feature_analysis.command.json
- feature_analysis.py
- feature_analysis.stderr.txt
- feature_analysis.stdout.txt
- feature_definitions.json
- feature_evidence.json
- feature_regexes.json
- finish_evidence.py
- freeze_manifest.json
- frozen/PROBE_V2_DESIGN.md
- frozen/REVIEW_SAMPLE_v2.csv
- frozen/probe_v2.csv
- frozen/probe_v2.sha256
- gate_projection_arithmetic.json
- generate_v2.command.json
- generate_v2.py
- generate_v2.stderr.txt
- generate_v2.stdout.txt
- generation_manifest.json
- git_after.json
- git_before.json
- importance_summary.json
- inference.py
- inference_02.command.json
- inference_02.py
- inference_02.stderr.txt
- inference_02.stdout.txt
- inference_manifest.json
- integrity_checks.json
- intra_probe_audit.json
- intra_probe_audit_audit02.json
- overlap_tags.jsonl
- paired_English.json
- paired_feature_activation.csv
- permutation_baseline.json
- permutation_importance.csv
- permutation_sample.json
- probe_cells.jsonl
- probe_predictions.jsonl
- probe_quality.json
- probe_summary.jsonl
- probe_v1_normalized.csv
- probe_v2.csv
- proposed_gate_table.json
- protected_after.json
- protected_before.json
- repair_channel.command.json
- repair_channel.py
- repair_channel.stderr.txt
- repair_channel.stdout.txt
- repair_manifest.json
- review_marks.json
- runtime.py
- sample_size_arithmetic.json
- sender_code_tests.json
- sender_file_totals.json
- sender_missing_by_file_label_source.csv
- sender_training_files.json
- snapshot.command.json
- snapshot.py
- snapshot.stderr.txt
- snapshot.stdout.txt
- sprintlib.py
- stage_0B/PROGRESS.md
- stage_1/PROGRESS.md
- stage_2/PROGRESS.md
- stage_3_pending/PROGRESS.md
- stage_4/PROGRESS.md
- summarize_evidence.command.json
- summarize_evidence.py
- summarize_evidence.stderr.txt
- summarize_evidence.stdout.txt
- validation.command.json
- validation.py
- validation.stderr.txt
- validation.stdout.txt
- verdicts.json
- worst_failures.csv
- write_plans.command.json
- write_plans.py
- write_plans.stderr.txt
- write_plans.stdout.txt

- RUN_EVIDENCE.md
- final_command.json
- output_manifest.json
- COMPLETION.json
