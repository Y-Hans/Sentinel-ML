from runlib import *
protect()
def table(h,rr):return '| '+' | '.join(h)+' |\n| '+' | '.join('---' for _ in h)+' |\n'+'\n'.join('| '+' | '.join(str(x).replace('|','/').replace('\n',' ') for x in r)+' |' for r in rr)+'\n'
legacy=jload('legacy_all_inputs_comparison.json'); trace=jload('url_form_feature_trace.json'); curve=readrows(OUT/'calibration_reliability.jsonl'); logs=jload('logged_comparison_summary.json')
s='''# Audit corrections and supplemental evidence

**OBSERVED:** this append-only supplement completes comparisons and diagnostic detail after the six main analysis/design documents were written. It does not modify those files, frozen sets, labels, model weights or thresholds. Every number below comes from the cited new JSON outputs.

## Legacy recovered databases and raw decoded-row files

**OBSERVED:** `legacy_all_inputs_comparison.json` covers the older investigation recovered DBs and `*_rows.jsonl`, in addition to the parsed/562 comparisons already reported. The strict SCAN_RESULT/UUID/11-column/timestamp/content validator accepts none of their candidate records; thus no valid ID/time/content-hash row match is asserted. Empty strict-comparison JSONL files indicate rejected/absent valid candidates, not proof original historical rows did not exist. The legacy byte hashes remain preserved; these files cannot independently certify the new salvage. Nonconforming raw-row counts are record-structure rejection counts, not lost threat-record totals.

'''+table(['REPORTED legacy input','Strict candidates','Raw-row count (if JSONL)','Rejected raw rows','Exact new-row matches','SHA-256'],[[r['path'],r['strict_candidates'],r.get('source_rows','NA'),r.get('rejected_nonconforming','NA'),r['exact_matching_candidates'],r['sha256']] for r in legacy])+'''
## URL form mechanism trace

**OBSERVED:** `url_form_feature_trace.json` re-extracts features only for already frozen authored simulation inputs. Explicit HTTPS www, schemeless www and protocol-relative www have identical current-source vectors; bare apex differs in six features and explicit HTTP in three. This is current pipeline evidence, not proof of the historically installed APK parser. **PROVISIONAL:** these are authored benign assumptions, not new site verification.

'''+table(['Already frozen input','Different features vs HTTPS www','V8 raw','V8 adjudicated'],[[r['url'],len(r['feature_differences_vs_https_www']),next(p['raw_score'] for p in r['predictions'] if p['model']=='URL_V8'),next(p['adjudicated_score'] for p in r['predictions'] if p['model']=='URL_V8')] for r in trace['trace']])+'''
## Calibration summary

**OBSERVED computed / PROVISIONAL validity:** all-labeled, unweighted diagnostic ECE/Brier, not deployment-calibration guarantees. Ten-bin reliability curves and all prevalence-weighted variants are in `calibration_reliability.jsonl`. For Messages the score is p(non-benign), so treating authored attacks as the positive class does not measure spam-aware production calibration. For URLs adjudicated output is a policy decision score, not a calibrated posterior.

'''+table(['Model','Path','N','ECE','Brier'],[[r['model'],r['mode'],r['n'],r['ECE'],r['Brier']] for r in curve if r['scope']=='all_labeled' and r['assumed_prior'] is None])+'''
**OBSERVED fallback:** matplotlib is unavailable in the selected Messages interpreter (`calibration_plot_evidence.json` records the import failure). Complete curve points, bin counts, confidence and positive fractions are delivered as tables; no interpolation/smoothed or publication-ready figure is fabricated. No installation or protected-cache write was attempted.

## Logged production comparison detail

**OBSERVED:** these are logged non-green app outcomes versus current model-only any-alert outcomes. **PROVISIONAL:** salvage may alter input fields; no historical model generation or human truth follows from agreement. Extracted-URL comparisons use the parent record's logged risk, which may be message/fusion evidence rather than a URL verdict. Exact original fused severity cannot be inferred without separately authorized runtime work.

'''+table(['Track/model','Path','Pull','N','Logged non-green','Current model alerts','Disagreements'],[[r['track']+'/'+r['model'],r['mode'],r['pull_id'],r['n'],r['logged_alerts'],r['current_alerts'],r['disagreements']] for r in logs])+'''
## Disclosed own errors and retained attempts

**OBSERVED:** initial integrity inventory traversed a disappearing/deep Gradle cache file and exited1 before its inventory was saved. The corrected inventory excludes hidden/build/tool/venv caches and commits1,750 existing source/model/data files. Its before snapshot and Git status were written before later model imports; an environment platform query then hit the guard false positive described below. The completed before hash snapshot remains valid; final integrity checks compare those exact paths.

**OBSERVED:** one dispatcher invocation omitted snapshot's required phase argument, producing a recorded IndexError. No hash/source modification resulted. The initial Python write guard incorrectly rejected the Windows OS NUL device during standard-library platform/sklearn/pandas import. These were guarded null-device operations, not writes to a protected source/model/data path, and no protected file was changed. `safe_entry.py` is a NEW append-only correction allowing only the OS null device while retaining protected-filesystem write rejection. Failed stderr/exit codes and successful retries are preserved separately. No actual protected-write or protected-hash hard stop occurred.

**OBSERVED:** the first recovery selection heuristic and page scanner missed data; its zero rows did not mean zero records. The revised independent serialized-row carver yielded provisional candidates, not a certified table recovery. The first URL-overlap implementation masked whole URLs like message text; its URL exact/Jaccard counts were invalid. A new version preserves URL content and broadens Messages training discovery from name-prefix to name-substring, resulting in21 corpora,28 flagged message rows and66 flagged URLs. The final freeze was committed before successful reproduction/inference; no prior output was overwritten.

**OBSERVED:** a later exploratory shell read omitted UTF-8 and failed decoding a Unicode JSONL after printing some summaries. All production readers use explicit UTF-8; rate/coverage QA succeeded. The independent QA checks denominators, frozen hashes, model coverage and known reproduction counts, not label truth. Supplementary malicious-class metrics use true class2 decisions; their companion non-benign calibration/sensitivity outputs are diagnostics of the original score, not a fitted malicious-probability calibrator.

**PROVISIONAL scope:** all explicitly named Step7 baselines were scored (V2,V4.3,six V4.4 variants,V7,V8raw/adjudicated). V4.5 artifacts are historical reference material; frozen encoder/classifier dependency closure is not certified and no V4.5 inference result is invented. The provisional sealed-for-this-pass exam is not represented as an independently certified final exam. Exact missing original-row totals and historical pull model generations remain UNKNOWN/UNRESOLVED rather than guessed. These limitations do not prevent finishing the authorized analysis/design deliverables.
'''
with (OUT/'AUDIT_CORRECTIONS_AND_COMPLETENESS.md').open('x',encoding='utf-8') as f:f.write(s)
print('wrote append-only supplemental evidence')
