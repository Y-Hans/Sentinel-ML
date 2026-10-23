# Audit corrections and supplemental evidence

**OBSERVED:** this append-only supplement completes comparisons and diagnostic detail after the six main analysis/design documents were written. It does not modify those files, frozen sets, labels, model weights or thresholds. Every number below comes from the cited new JSON outputs.

## Legacy recovered databases and raw decoded-row files

**OBSERVED:** `legacy_all_inputs_comparison.json` covers the older investigation recovered DBs and `*_rows.jsonl`, in addition to the parsed/562 comparisons already reported. The strict SCAN_RESULT/UUID/11-column/timestamp/content validator accepts none of their candidate records; thus no valid ID/time/content-hash row match is asserted. Empty strict-comparison JSONL files indicate rejected/absent valid candidates, not proof original historical rows did not exist. The legacy byte hashes remain preserved; these files cannot independently certify the new salvage. Nonconforming raw-row counts are record-structure rejection counts, not lost threat-record totals.

| REPORTED legacy input | Strict candidates | Raw-row count (if JSONL) | Rejected raw rows | Exact new-row matches | SHA-256 |
| --- | --- | --- | --- | --- | --- |
| sentinel-ml/investigation/sentinel_db.recovered.db | 0 | NA | NA | 0 | f7704248a91699e55a06a5b8ffa2c8e83aff69232aba6804f28cd89cb5898a80 |
| sentinel-ml/investigation/sentinel_db(1).recovered.db | 0 | NA | NA | 0 | c06c2efe7be012407415a0bdb9016beb573a3238a5f126a13304f1959b55ea54 |
| sentinel-ml/investigation/sentinel_db_rows.jsonl | 0 | 161 | 161 | 0 | d4880b83464a5c7d1b236c750c79fa6aada08182e37e438f9285661b830f0652 |
| sentinel-ml/investigation/sentinel_db1_rows.jsonl | 0 | 212 | 212 | 0 | aeb964ca09f3847528d29f66a78bab96d3e1f351cdbff33e9529a0c087a89f17 |

## URL form mechanism trace

**OBSERVED:** `url_form_feature_trace.json` re-extracts features only for already frozen authored simulation inputs. Explicit HTTPS www, schemeless www and protocol-relative www have identical current-source vectors; bare apex differs in six features and explicit HTTP in three. This is current pipeline evidence, not proof of the historically installed APK parser. **PROVISIONAL:** these are authored benign assumptions, not new site verification.

| Already frozen input | Different features vs HTTPS www | V8 raw | V8 adjudicated |
| --- | --- | --- | --- |
| https://www.instagram.com | 0 | 0.001927708488996153 | 0.0010000000474974513 |
| www.instagram.com | 0 | 0.001927708488996153 | 0.0010000000474974513 |
| //www.instagram.com | 0 | 0.001927708488996153 | 0.0010000000474974513 |
| instagram.com | 6 | 0.6093701932473308 | 0.6093701720237732 |
| http://www.instagram.com | 3 | 0.969637230630553 | 0.9696372151374817 |

## Calibration summary

**OBSERVED computed / PROVISIONAL validity:** all-labeled, unweighted diagnostic ECE/Brier, not deployment-calibration guarantees. Ten-bin reliability curves and all prevalence-weighted variants are in `calibration_reliability.jsonl`. For Messages the score is p(non-benign), so treating authored attacks as the positive class does not measure spam-aware production calibration. For URLs adjudicated output is a policy decision score, not a calibrated posterior.

| Model | Path | N | ECE | Brier |
| --- | --- | --- | --- | --- |
| Messages_V2 | raw | 888 | 0.07028326589212909 | 0.06067365276156664 |
| Messages_V2 | adjudicated | 888 | 0.07028326589212909 | 0.06067365276156664 |
| Messages_V4.3 | raw | 888 | 0.07605900947237507 | 0.06987223196265507 |
| Messages_V4.3 | adjudicated | 888 | 0.07605900947237507 | 0.06987223196265507 |
| Messages_V4.4_candidate_a_corrected | raw | 888 | 0.1389548870713562 | 0.08211536371934272 |
| Messages_V4.4_candidate_a_corrected | adjudicated | 888 | 0.1389548870713562 | 0.08211536371934272 |
| Messages_V4.4_candidate_b_refined | raw | 888 | 0.11397054060060768 | 0.0667313710172667 |
| Messages_V4.4_candidate_b_refined | adjudicated | 888 | 0.11397054060060768 | 0.0667313710172667 |
| Messages_V4.4_candidate_c_balanced | raw | 888 | 0.12913079393953344 | 0.07987106863276354 |
| Messages_V4.4_candidate_c_balanced | adjudicated | 888 | 0.12913079393953344 | 0.07987106863276354 |
| Messages_V4.4_rc2_experiment_1 | raw | 888 | 0.12356482748128075 | 0.07500483330762883 |
| Messages_V4.4_rc2_experiment_1 | adjudicated | 888 | 0.12356482748128075 | 0.07500483330762883 |
| Messages_V4.4_rc2_experiment_2 | raw | 888 | 0.1257768479794368 | 0.07214345070185688 |
| Messages_V4.4_rc2_experiment_2 | adjudicated | 888 | 0.1257768479794368 | 0.07214345070185688 |
| Messages_V4.4_rc2_experiment_3 | raw | 888 | 0.12359590470809428 | 0.07015392722512899 |
| Messages_V4.4_rc2_experiment_3 | adjudicated | 888 | 0.12359590470809428 | 0.07015392722512899 |
| URL_V7 | raw | 16 | 0.4118535263838767 | 0.36143687997502966 |
| URL_V7 | adjudicated | 16 | 0.3642196966942404 | 0.33746808439873843 |
| URL_V8 | raw | 16 | 0.4118535263838767 | 0.36143687997502966 |
| URL_V8 | adjudicated | 16 | 0.30152870745951077 | 0.2881197613657929 |

**OBSERVED fallback:** matplotlib is unavailable in the selected Messages interpreter (`calibration_plot_evidence.json` records the import failure). Complete curve points, bin counts, confidence and positive fractions are delivered as tables; no interpolation/smoothed or publication-ready figure is fabricated. No installation or protected-cache write was attempted.

## Logged production comparison detail

**OBSERVED:** these are logged non-green app outcomes versus current model-only any-alert outcomes. **PROVISIONAL:** salvage may alter input fields; no historical model generation or human truth follows from agreement. Extracted-URL comparisons use the parent record's logged risk, which may be message/fusion evidence rather than a URL verdict. Exact original fused severity cannot be inferred without separately authorized runtime work.

| Track/model | Path | Pull | N | Logged non-green | Current model alerts | Disagreements |
| --- | --- | --- | --- | --- | --- | --- |
| messages/Messages_V2 | raw | pull_1 | 40 | 3 | 3 | 0 |
| messages/Messages_V2 | raw | pull_2 | 38 | 12 | 11 | 7 |
| messages/Messages_V2 | raw | pull_3 | 480 | 31 | 55 | 60 |
| messages/Messages_V2 | raw | reported_replay_294 | 267 | 29 | 24 | 5 |
| messages/Messages_V2 | adjudicated | pull_1 | 40 | 3 | 3 | 0 |
| messages/Messages_V2 | adjudicated | pull_2 | 38 | 12 | 7 | 7 |
| messages/Messages_V2 | adjudicated | pull_3 | 480 | 31 | 46 | 55 |
| messages/Messages_V2 | adjudicated | reported_replay_294 | 267 | 29 | 16 | 13 |
| messages/Messages_V4.3 | raw | pull_1 | 40 | 3 | 4 | 3 |
| messages/Messages_V4.3 | raw | pull_2 | 38 | 12 | 6 | 12 |
| messages/Messages_V4.3 | raw | pull_3 | 480 | 31 | 44 | 13 |
| messages/Messages_V4.3 | raw | reported_replay_294 | 267 | 29 | 17 | 26 |
| messages/Messages_V4.3 | adjudicated | pull_1 | 40 | 3 | 3 | 2 |
| messages/Messages_V4.3 | adjudicated | pull_2 | 38 | 12 | 6 | 12 |
| messages/Messages_V4.3 | adjudicated | pull_3 | 480 | 31 | 32 | 1 |
| messages/Messages_V4.3 | adjudicated | reported_replay_294 | 267 | 29 | 16 | 25 |
| messages/Messages_V4.4_candidate_a_corrected | raw | pull_1 | 40 | 3 | 5 | 4 |
| messages/Messages_V4.4_candidate_a_corrected | raw | pull_2 | 38 | 12 | 7 | 11 |
| messages/Messages_V4.4_candidate_a_corrected | raw | pull_3 | 480 | 31 | 70 | 45 |
| messages/Messages_V4.4_candidate_a_corrected | raw | reported_replay_294 | 267 | 29 | 28 | 23 |
| messages/Messages_V4.4_candidate_a_corrected | adjudicated | pull_1 | 40 | 3 | 3 | 2 |
| messages/Messages_V4.4_candidate_a_corrected | adjudicated | pull_2 | 38 | 12 | 5 | 13 |
| messages/Messages_V4.4_candidate_a_corrected | adjudicated | pull_3 | 480 | 31 | 59 | 46 |
| messages/Messages_V4.4_candidate_a_corrected | adjudicated | reported_replay_294 | 267 | 29 | 25 | 24 |
| messages/Messages_V4.4_candidate_b_refined | raw | pull_1 | 40 | 3 | 4 | 3 |
| messages/Messages_V4.4_candidate_b_refined | raw | pull_2 | 38 | 12 | 7 | 11 |
| messages/Messages_V4.4_candidate_b_refined | raw | pull_3 | 480 | 31 | 52 | 35 |
| messages/Messages_V4.4_candidate_b_refined | raw | reported_replay_294 | 267 | 29 | 15 | 22 |
| messages/Messages_V4.4_candidate_b_refined | adjudicated | pull_1 | 40 | 3 | 3 | 2 |
| messages/Messages_V4.4_candidate_b_refined | adjudicated | pull_2 | 38 | 12 | 5 | 11 |
| messages/Messages_V4.4_candidate_b_refined | adjudicated | pull_3 | 480 | 31 | 28 | 29 |
| messages/Messages_V4.4_candidate_b_refined | adjudicated | reported_replay_294 | 267 | 29 | 13 | 22 |
| messages/Messages_V4.4_candidate_c_balanced | raw | pull_1 | 40 | 3 | 3 | 2 |
| messages/Messages_V4.4_candidate_c_balanced | raw | pull_2 | 38 | 12 | 6 | 12 |
| messages/Messages_V4.4_candidate_c_balanced | raw | pull_3 | 480 | 31 | 56 | 47 |
| messages/Messages_V4.4_candidate_c_balanced | raw | reported_replay_294 | 267 | 29 | 15 | 24 |
| messages/Messages_V4.4_candidate_c_balanced | adjudicated | pull_1 | 40 | 3 | 3 | 2 |
| messages/Messages_V4.4_candidate_c_balanced | adjudicated | pull_2 | 38 | 12 | 3 | 13 |
| messages/Messages_V4.4_candidate_c_balanced | adjudicated | pull_3 | 480 | 31 | 44 | 41 |
| messages/Messages_V4.4_candidate_c_balanced | adjudicated | reported_replay_294 | 267 | 29 | 11 | 24 |
| messages/Messages_V4.4_rc2_experiment_1 | raw | pull_1 | 40 | 3 | 3 | 2 |
| messages/Messages_V4.4_rc2_experiment_1 | raw | pull_2 | 38 | 12 | 5 | 13 |
| messages/Messages_V4.4_rc2_experiment_1 | raw | pull_3 | 480 | 31 | 48 | 33 |
| messages/Messages_V4.4_rc2_experiment_1 | raw | reported_replay_294 | 267 | 29 | 18 | 29 |
| messages/Messages_V4.4_rc2_experiment_1 | adjudicated | pull_1 | 40 | 3 | 0 | 3 |
| messages/Messages_V4.4_rc2_experiment_1 | adjudicated | pull_2 | 38 | 12 | 4 | 12 |
| messages/Messages_V4.4_rc2_experiment_1 | adjudicated | pull_3 | 480 | 31 | 21 | 26 |
| messages/Messages_V4.4_rc2_experiment_1 | adjudicated | reported_replay_294 | 267 | 29 | 12 | 25 |
| messages/Messages_V4.4_rc2_experiment_2 | raw | pull_1 | 40 | 3 | 3 | 2 |
| messages/Messages_V4.4_rc2_experiment_2 | raw | pull_2 | 38 | 12 | 6 | 12 |
| messages/Messages_V4.4_rc2_experiment_2 | raw | pull_3 | 480 | 31 | 52 | 37 |
| messages/Messages_V4.4_rc2_experiment_2 | raw | reported_replay_294 | 267 | 29 | 18 | 25 |
| messages/Messages_V4.4_rc2_experiment_2 | adjudicated | pull_1 | 40 | 3 | 2 | 1 |
| messages/Messages_V4.4_rc2_experiment_2 | adjudicated | pull_2 | 38 | 12 | 5 | 11 |
| messages/Messages_V4.4_rc2_experiment_2 | adjudicated | pull_3 | 480 | 31 | 22 | 29 |
| messages/Messages_V4.4_rc2_experiment_2 | adjudicated | reported_replay_294 | 267 | 29 | 12 | 21 |
| messages/Messages_V4.4_rc2_experiment_3 | raw | pull_1 | 40 | 3 | 4 | 3 |
| messages/Messages_V4.4_rc2_experiment_3 | raw | pull_2 | 38 | 12 | 5 | 11 |
| messages/Messages_V4.4_rc2_experiment_3 | raw | pull_3 | 480 | 31 | 55 | 44 |
| messages/Messages_V4.4_rc2_experiment_3 | raw | reported_replay_294 | 267 | 29 | 15 | 22 |
| messages/Messages_V4.4_rc2_experiment_3 | adjudicated | pull_1 | 40 | 3 | 2 | 1 |
| messages/Messages_V4.4_rc2_experiment_3 | adjudicated | pull_2 | 38 | 12 | 4 | 12 |
| messages/Messages_V4.4_rc2_experiment_3 | adjudicated | pull_3 | 480 | 31 | 14 | 31 |
| messages/Messages_V4.4_rc2_experiment_3 | adjudicated | reported_replay_294 | 267 | 29 | 12 | 23 |
| urls/URL_V7 | raw | pull_1 | 2 | 2 | 2 | 0 |
| urls/URL_V7 | raw | pull_2 | 14 | 8 | 8 | 4 |
| urls/URL_V7 | raw | pull_3 | 50 | 7 | 11 | 18 |
| urls/URL_V7 | raw | reported_replay_294 | 18 | 12 | 11 | 5 |
| urls/URL_V7 | adjudicated | pull_1 | 2 | 2 | 2 | 0 |
| urls/URL_V7 | adjudicated | pull_2 | 14 | 8 | 3 | 7 |
| urls/URL_V7 | adjudicated | pull_3 | 50 | 7 | 11 | 18 |
| urls/URL_V7 | adjudicated | reported_replay_294 | 18 | 12 | 6 | 8 |
| urls/URL_V8 | raw | pull_1 | 2 | 2 | 2 | 0 |
| urls/URL_V8 | raw | pull_2 | 14 | 8 | 8 | 4 |
| urls/URL_V8 | raw | pull_3 | 50 | 7 | 11 | 18 |
| urls/URL_V8 | raw | reported_replay_294 | 18 | 12 | 11 | 5 |
| urls/URL_V8 | adjudicated | pull_1 | 2 | 2 | 2 | 0 |
| urls/URL_V8 | adjudicated | pull_2 | 14 | 8 | 8 | 4 |
| urls/URL_V8 | adjudicated | pull_3 | 50 | 7 | 11 | 18 |
| urls/URL_V8 | adjudicated | reported_replay_294 | 18 | 12 | 11 | 5 |

## Disclosed own errors and retained attempts

**OBSERVED:** initial integrity inventory traversed a disappearing/deep Gradle cache file and exited1 before its inventory was saved. The corrected inventory excludes hidden/build/tool/venv caches and commits1,750 existing source/model/data files. Its before snapshot and Git status were written before later model imports; an environment platform query then hit the guard false positive described below. The completed before hash snapshot remains valid; final integrity checks compare those exact paths.

**OBSERVED:** one dispatcher invocation omitted snapshot's required phase argument, producing a recorded IndexError. No hash/source modification resulted. The initial Python write guard incorrectly rejected the Windows OS NUL device during standard-library platform/sklearn/pandas import. These were guarded null-device operations, not writes to a protected source/model/data path, and no protected file was changed. `safe_entry.py` is a NEW append-only correction allowing only the OS null device while retaining protected-filesystem write rejection. Failed stderr/exit codes and successful retries are preserved separately. No actual protected-write or protected-hash hard stop occurred.

**OBSERVED:** the first recovery selection heuristic and page scanner missed data; its zero rows did not mean zero records. The revised independent serialized-row carver yielded provisional candidates, not a certified table recovery. The first URL-overlap implementation masked whole URLs like message text; its URL exact/Jaccard counts were invalid. A new version preserves URL content and broadens Messages training discovery from name-prefix to name-substring, resulting in21 corpora,28 flagged message rows and66 flagged URLs. The final freeze was committed before successful reproduction/inference; no prior output was overwritten.

**OBSERVED:** a later exploratory shell read omitted UTF-8 and failed decoding a Unicode JSONL after printing some summaries. All production readers use explicit UTF-8; rate/coverage QA succeeded. The independent QA checks denominators, frozen hashes, model coverage and known reproduction counts, not label truth. Supplementary malicious-class metrics use true class2 decisions; their companion non-benign calibration/sensitivity outputs are diagnostics of the original score, not a fitted malicious-probability calibrator.

**PROVISIONAL scope:** all explicitly named Step7 baselines were scored (V2,V4.3,six V4.4 variants,V7,V8raw/adjudicated). V4.5 artifacts are historical reference material; frozen encoder/classifier dependency closure is not certified and no V4.5 inference result is invented. The provisional sealed-for-this-pass exam is not represented as an independently certified final exam. Exact missing original-row totals and historical pull model generations remain UNKNOWN/UNRESOLVED rather than guessed. These limitations do not prevent finishing the authorized analysis/design deliverables.
