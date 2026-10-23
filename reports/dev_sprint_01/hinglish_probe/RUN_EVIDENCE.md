# Stage 0 run evidence — CPU only

Date: October 22, 2026 (Asia/Calcutta). **OBSERVED:** all requested artifacts are written under `C:\Users\user\Programing files\Yajat\Projects\sentinel\reports\dev_sprint_01\hinglish_probe`. No files outside this new folder were written, no candidate training/calibrator/tokenizer fit was run, no GPU was requested, no model/threshold was changed/exported/promoted, no Android/Kotlin/Gradle was executed, and no Git mutation was performed. Neither `sentinel-ml/datasets_v5/` nor `user_data/` was opened. Stage1 is NOT started; the user will supply it after Stage0, and the recall-also verdict requires stopping here.

## Design, generation and freeze order

**OBSERVED:** DESIGN_PREREGISTERED.md was written before generation. `generate.py` uses author-written family action/benign contrasts and forty author-written framing/English translation patterns, eight personas in forty27-rowHinglish batches, deterministic noise/style variation and seed202610220. No model imports/scores occur during generation. All1,320rows are ASSUMED single-author synthetic intent, not real user reports or independent human adjudication. Counts are480M/480B/120S Hinglish and120M/120B English. SMS/WhatsApp are50/50 per Hinglish class;288/480attacks are URL-less. Actual word bins:190short,539medium,351long among1,080Hinglish rows. Domains end.invalid and are defangedhxxps; phone numbers use fictionalNANP55501xx. No network access, DNS or executable payload is present.

**OBSERVED:** score-free intraprobe audit has8Jaccard≥.85edges,maxcomponent2,cap3passes. Corpus audit covers79text-bearing sources,23training-role sources,normalizedexact andtokenJaccard≥.85;crosscorpusflags0. Full manifests list sourcepaths/hashes,errors andlexical/provenance limitations. Blind process sees onlyopaque text/channel/header/language fields,noexpected/family/pairs;80disagreements preserved,notrelabeled. REVIEW_SAMPLE.csvcontains202rows:base50M/50B/25S plusallremainingdisagreements,emptyuser_agree/user_note. Blindrulepass isfile-level blindbutnotindependenthumanreview; grammar isknownbythesameauthor.

**OBSERVED immutable freeze:** probe_set.csv SHA-256 `c28521e5fd7c5f55240176a10ffa416a7dc6e5cdb1843fab604a1018db563e44`; rows1,320; freeze timeUTC `2026-10-22T17:19:36.231371+00:00`. Frozen design SHA-256 `a1a78e72720f6fc36da5c978e2d906a57056eafc37adf60ec738e2f1fd335f13`. Final design wascreated once frompreregistereddesign plusfreezecommitment BEFORE infer.py. Datasetanddesign hashesremainunchanged afterscores. No score-ledregeneration,modelselection,thresholdtuningortraining occurred. Thissetremainsexam materialandmustnotenterlatertraining. Draftretainedunderitsownfilename;actualfrozenCSVbytesareidenticalto theauditeddraft,notareplacementforahistoricalartifact.

## Runtime and reproduction

**OBSERVED:** interpreter`C:\Users\user\AppData\Local\Programs\Python\Python314\python.exe`,Python`3.14.4 (tags/v3.14.4:23116f9, Apr  7 2026, 14:10:54) [MSC v.1944 64 bit (AMD64)]`;numpy`2.5.2`,sklearn`1.9.0`. EnvironmentCUDA_VISIBLE_DEVICES=-1,OMP/OPENBLAS/MKLthreads1,PYTHONDONTWRITEBYTECODE=1;Python-B. OnlyCPU sklearn frozen tree inference wasused;nottorch/tensorflow/GPUinference. All eightfrozenmodel bundles loaded;unpicklewarningsandartifact/scaler/vectorizerhashesarelistedininference_manifest.json. Reusedrun_02paths,featureorderingandthresholds(V2.704,V4.3.61,V4.4configs),withoutimportingoldscriptsthatwritefiles.

**OBSERVED gate:** V4.3 fullTESTmalicious-class1510/1556andbenignanyalert2/520at.61reproducedBEFOREprobescores. TEST/OODmetadata languagecountsandhashesareinreport_input_counts.json;bothcontain3hinglish-taggedrecords. English-onlymetadatasubsetandfullTESTMALICIOUS-onlycountsarekeptseparateinEnglish_TEST_comparison.json. No reproductiontargetwasmadeconvenientbychoosinganotherthreshold.

**OBSERVED:**11,220predictionrows=8×1,320text-only +660V2SMS-header rows. All preserveP(B),P(S),P(M),p(non-benign),rawargmax,finalthresholdedclass,andMALICIOUS-onlyalert. assert(SPAM⇒noalert)passes. V4.3/V4.4arenotgivenafakesendercondition;theirtext-onlyfeaturecontractdoesnotacceptheaders. V2headersareinventedmetadata,notverifiedrealDLTidentity. Allper-modelsourcehashes,conditions,exactτsandwarningsareininference_manifest.json.

## Commands, working directory, exit codes

**OBSERVED exactscientificchildcommands:** workingdirectory`C:\Users\user\Programing files\Yajat\Projects\sentinel`. Eachcommandhasadjacentstdout/stderr,anindividual.command.jsonrecordwithexitcode/duration/environment/outputhashes,andthisconsolidatedcommand_ledger.json. Allsuccessfulscientificstepsbelowexit0.

| Exact command argv | CWD | Exit | Seconds |
| --- | --- | --- | --- |
| "C:\Users\user\AppData\Local\Programs\Python\Python314\python.exe" "-B" "C:\Users\user\Programing files\Yajat\Projects\sentinel\reports\dev_sprint_01\hinglish_probe\analyze.py" | C:\Users\user\Programing files\Yajat\Projects\sentinel | 0 | 1.29 |
| "C:\Users\user\AppData\Local\Programs\Python\Python314\python.exe" "-B" "C:\Users\user\Programing files\Yajat\Projects\sentinel\reports\dev_sprint_01\hinglish_probe\audit.py" | C:\Users\user\Programing files\Yajat\Projects\sentinel | 0 | 58.07 |
| "C:\Users\user\AppData\Local\Programs\Python\Python314\python.exe" "-B" "C:\Users\user\Programing files\Yajat\Projects\sentinel\reports\dev_sprint_01\hinglish_probe\blind_pass.py" | C:\Users\user\Programing files\Yajat\Projects\sentinel | 0 | 0.512 |
| "C:\Users\user\AppData\Local\Programs\Python\Python314\python.exe" "-B" "C:\Users\user\Programing files\Yajat\Projects\sentinel\reports\dev_sprint_01\hinglish_probe\freeze.py" | C:\Users\user\Programing files\Yajat\Projects\sentinel | 0 | 0.525 |
| "C:\Users\user\AppData\Local\Programs\Python\Python314\python.exe" "-B" "C:\Users\user\Programing files\Yajat\Projects\sentinel\reports\dev_sprint_01\hinglish_probe\generate.py" | C:\Users\user\Programing files\Yajat\Projects\sentinel | 0 | 0.474 |
| "C:\Users\user\AppData\Local\Programs\Python\Python314\python.exe" "-B" "C:\Users\user\Programing files\Yajat\Projects\sentinel\reports\dev_sprint_01\hinglish_probe\historical_and_qa.py" | C:\Users\user\Programing files\Yajat\Projects\sentinel | 0 | 0.503 |
| "C:\Users\user\AppData\Local\Programs\Python\Python314\python.exe" "-B" "C:\Users\user\Programing files\Yajat\Projects\sentinel\reports\dev_sprint_01\hinglish_probe\infer.py" | C:\Users\user\Programing files\Yajat\Projects\sentinel | 0 | 39.873 |
| "C:\Users\user\AppData\Local\Programs\Python\Python314\python.exe" "-B" "C:\Users\user\Programing files\Yajat\Projects\sentinel\reports\dev_sprint_01\hinglish_probe\snapshot_before.py" | C:\Users\user\Programing files\Yajat\Projects\sentinel | 0 | 6.836 |
| "C:\Users\user\AppData\Local\Programs\Python\Python314\python.exe" "-B" "C:\Users\user\Programing files\Yajat\Projects\sentinel\reports\dev_sprint_01\hinglish_probe\write_results.py" | C:\Users\user\Programing files\Yajat\Projects\sentinel | 0 | 0.763 |


**OBSERVED directfinalcommand:**

```powershell
python -B reports/dev_sprint_01/hinglish_probe/finish.py
```

Itperformsfinalhash/Git/freezechecks,writesthisevidenceandoutputmanifest,validatesalllistedoutputs,printscompletiondigest,andmustexit0forevidencecompletion.final_command.jsonrecordsoriginalargv,cwd,interpreterandchecktime;thetool'sshellresultconfirmsexitcode. Read-onlyGet-Content,rgandGet-ChildItemdiscoverycommandsprecededscientificscripts;everyreportednumericclaimwasthenrederivedbytheloggedscriptsorREPORTEDfromhash-listedhistoricalsources.Noerrorrecoverychangedthesetorlabels.

## Primary protected model hashes

| Model artifact | Before SHA-256 | After SHA-256 |
| --- | --- | --- |
| sentinel-ml/6sep/messages/final/champion_v2_model.pkl | d10108f3e38e53b0c93185a2544327c7a06ed320109e6c219a5184e9bd8ca887 | d10108f3e38e53b0c93185a2544327c7a06ed320109e6c219a5184e9bd8ca887 |
| sentinel-ml/Messages-ml/messages_v4_3/models/candidate_d/model.pkl | 2ca29457acd27bf93d6967d8f9d64778b8ba0e404030175465c802fe1a138a7d | 2ca29457acd27bf93d6967d8f9d64778b8ba0e404030175465c802fe1a138a7d |
| sentinel-ml/Messages-ml/messages_v4_4/models/candidate_a_corrected/model.pkl | 08bfcf6a3da137ae1752cf74c08a39bfb26231435cca9427a6f472420e1d82a7 | 08bfcf6a3da137ae1752cf74c08a39bfb26231435cca9427a6f472420e1d82a7 |
| sentinel-ml/Messages-ml/messages_v4_4/models/candidate_b_refined/model.pkl | 7b6d137bc623635c132840b79e41cac6cfed8134952491ad9563730b5f9fea34 | 7b6d137bc623635c132840b79e41cac6cfed8134952491ad9563730b5f9fea34 |
| sentinel-ml/Messages-ml/messages_v4_4/models/candidate_c_balanced/model.pkl | 633357c366da6ef389097f5fc4af91692f06057bcd60af41a7ddb3d617afec21 | 633357c366da6ef389097f5fc4af91692f06057bcd60af41a7ddb3d617afec21 |
| sentinel-ml/Messages-ml/messages_v4_4/models/rc2_experiment_1/model.pkl | c408eb8d99b854eedb9133cb841d00db2c49e49eec162ca87d2d8f48be047f73 | c408eb8d99b854eedb9133cb841d00db2c49e49eec162ca87d2d8f48be047f73 |
| sentinel-ml/Messages-ml/messages_v4_4/models/rc2_experiment_2/model.pkl | 3cad1d9aa70a3bb4d145a40ef9d4b18bab3aece32c42efc3c859aad3f7080cf5 | 3cad1d9aa70a3bb4d145a40ef9d4b18bab3aece32c42efc3c859aad3f7080cf5 |
| sentinel-ml/Messages-ml/messages_v4_4/models/rc2_experiment_3/model.pkl | 6449e7720eebf6f70a8a23d405fc8a3890da164417aa47c982c1a19157ae79f3 | 6449e7720eebf6f70a8a23d405fc8a3890da164417aa47c982c1a19157ae79f3 |


**OBSERVED:** all1750inventoriedexistingML/Androidsource/model/datafileshaveidenticalbefore/afterSHA-256andbytecounts;fullper-filemapsareprotected_before.json/protected_after.json. Companionweights/scalers/vectorizers,data,schemas,APKsandmodelconfigsareincluded. Exclusions:hidden/build/tool/venv/cachefolders,newpermittedexperimentfolders,andexplicitprohibiteddatasets_v5/user_data. Thisisascope-definedaudit,notawhole-disksnapshot. Noneoftheprohibitedinputfolderswastraversedorhashed.Theoldsource/master/reportsremainunchanged;allnewwriteswereguardedtoallowedprobeoutputs.

## Git status, file by file

**OBSERVED before:**

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

**OBSERVED after:**

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

**OBSERVED:** exactporcelainstringsandexitcodesmatch;integrity_checks.jsonalsoenumerateseachpath'sbefore/aftertwo-characterstatus.Noadd/commit/reset/revert/checkout/stash/clean/buildwasused.GIT_OPTIONAL_LOCKS=0.

## Metrics, QA and corrected analysis

**OBSERVED decisions / ASSUMED labels:** allratiosuseMALICIOUS-onlyalerts. 95%Wilsonintervalsusez1.959963984540054;N<30flaggedindicativeonly. Wilsonintervalsdescribeeventrows,notindependentscenario/populationuncertainty. Family/channel/URL-like/density/noise/actual-lengthandpersona/batchcellsareprobe_breakdowns.jsonlandPROBE_BREAKDOWNS.csv. All/unflaggedsource-overlap/intraprobe-near-neighborversionsarepreserved,withoutalteringtheprimaryverdict.PairedEnglishusesmatchedtwinsforbothlabels,retainingdiscordantcasesandtexts.No50/50sampleshareisreportedasanaturaldeploymentprevalence.

**OBSERVED:** originalandcorrected_user_reviewscopescoincidewithzerouserexclusionsbecauseuser_agree/user_notearestillblank.Thatdoesnotmeanlabelsarevalidated;80blinddisagreementsareNOTusedasautomaticcorrections.Whenuserreviewarrives,createnewimmutableexclusion/metricfilesandreportwronglabelsseparately,retainingthisoriginalset/report.WorstmissandfalsealertCSVscontain25permodel/conditionwhereavailable;fewererrorsarereportedhonestly.

**OBSERVED attribution / REPORTED oldoutcomes:** master§6.2's87.1%leadmisattributesV3two-stage453/520toV2;embedded520auditreportsV2327/520(62.885%). Older100rowHinglishslicealreadyexists,withreportedV27/50(14%). Sourcehashes,embeddedrecordschemaandcountsarehistorical_87_1_lead.json.Nooldreportedscoreisrepresentedasanewreproductionorusedtotunethisprobe.

**PROVISIONAL limitations:**singleauthor/grammarandstylecorrelation;file-levelruleblindnessnotindependentreview;unreviewedlabel/benign-versus-spam/legit-secret-handoffboundaries;translatedEnglish/noiseconfounds;nonfunctionalhxxpsURLsnotlegacyhttp(s)featureinputs;fictionalnon-Indianphoneformat;fictitioussenderheadersnotauthenticatedsenders;lexicalzerooverlapnotsemanticindependence.NoAndroidfusedpolicyorreal-worldrateisclaimed.Afailisinformative,apasswouldnotprovereal-worldrecall.

## Files created and completion

**OBSERVED:** allnewfilesareunderreports/dev_sprint_01/hinglish_probe/. Nofilenamethatexistedbeforethispasswasoverwritten.output_manifest.jsonlistsper-fileSHA-256andbytecountsforalloutputsbesidesitselfandthecompletionanchor.COMPLETION.jsoncommitstheoutputmanifestdigest;itsownhashisprintedinthefinalcommandoutputtoavoidacircularself-hash.

- `COMPLETION.json`
- `DESIGN_PREREGISTERED.md`
- `English_TEST_comparison.json`
- `HINGLISH_PROBE_DESIGN.md`
- `HINGLISH_PROBE_RESULTS.md`
- `PROBE_BREAKDOWNS.csv`
- `REVIEW_SAMPLE.csv`
- `RUN_EVIDENCE.md`
- `V43_reproduction_gate.json`
- `analysis_counts.json`
- `analyze.command.json`
- `analyze.py`
- `analyze.stderr.txt`
- `analyze.stdout.txt`
- `audit.command.json`
- `audit.py`
- `audit.stderr.txt`
- `audit.stdout.txt`
- `blind_QA_summary.json`
- `blind_classification.csv`
- `blind_disagreements.csv`
- `blind_id_map.json`
- `blind_input.csv`
- `blind_pass.command.json`
- `blind_pass.py`
- `blind_pass.stderr.txt`
- `blind_pass.stdout.txt`
- `blind_pass_evidence.json`
- `command_ledger.json`
- `corpus_audit_manifest.json`
- `draft_probe_set.csv`
- `environment.json`
- `final_command.json`
- `finish.py`
- `freeze.command.json`
- `freeze.py`
- `freeze.stderr.txt`
- `freeze.stdout.txt`
- `freeze_manifest.json`
- `generate.command.json`
- `generate.py`
- `generate.stderr.txt`
- `generate.stdout.txt`
- `generation_manifest.json`
- `git_after.json`
- `git_before.json`
- `historical_87_1_lead.json`
- `historical_and_qa.command.json`
- `historical_and_qa.py`
- `historical_and_qa.stderr.txt`
- `historical_and_qa.stdout.txt`
- `infer.command.json`
- `infer.py`
- `infer.stderr.txt`
- `infer.stdout.txt`
- `inference_manifest.json`
- `integrity_checks.json`
- `intra_probe_audit.json`
- `launch.py`
- `output_manifest.json`
- `overlap_tags.jsonl`
- `paired_English_comparisons.jsonl`
- `probe_breakdowns.jsonl`
- `probe_lib.py`
- `probe_metrics.jsonl`
- `probe_predictions.jsonl`
- `probe_set.csv`
- `probe_set.sha256`
- `protected_after.json`
- `protected_before.json`
- `quality_checks.json`
- `raw_argmax_metrics.jsonl`
- `report_input_counts.json`
- `review_correction_status.json`
- `review_sample_manifest.json`
- `snapshot_before.command.json`
- `snapshot_before.py`
- `snapshot_before.stderr.txt`
- `snapshot_before.stdout.txt`
- `stage0_disposition.json`
- `verdicts.json`
- `worst_25_false_alerts_per_model.csv`
- `worst_25_misses_per_model.csv`
- `write_results.command.json`
- `write_results.py`
- `write_results.stderr.txt`
- `write_results.stdout.txt`

**STOP/disposition:** Stage0complete,all8text-onlymodels“Recallisalsoaproblem”undertheunchangedproposedrules;Stage1notstarted.NoGPUrequestedandnotrainingqueued.UsermustreviewREVIEW_SAMPLE.csv(especiallyall80blinddisagreements),confirm/correctsyntheticintentlabels,thenprovidethenextinstruction.Thisexamanditsresultsarefrozenandmustnotbeusedfortrainingortuning.
