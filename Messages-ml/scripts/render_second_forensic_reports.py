"""Render human-readable second-pass reports from full-corpus audit JSON."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
A=json.load(open(ROOT/"DATASET_COMPOSITION_AUDIT.json",encoding="utf-8"))
CF=json.load(open(ROOT/"COUNTERFACTUAL_METHOD_AUDIT.json",encoding="utf-8"))

def pct(x): return "—" if x is None else f"{x:.2f}%"
def val(x): return "—" if x is None else f"{x:.4f}"
def mdtable(headers,rows):
    return "| "+" | ".join(headers)+" |\n|"+"|".join(["---"]*len(headers))+"|\n"+"\n".join("| "+" | ".join(str(v) for v in r)+" |" for r in rows)+"\n"
def disttable(d):
    rows=[(k,v["count"],pct(v.get("percent"))) for k,v in d.items()]
    return mdtable(["Value","Count","Percent"],rows)
def qa(s): return A["composition"][s]

lines=["# Dataset Composition Audit — Full-Corpus V4.3\n",
"Status tags: **REPRODUCED** means counted from the complete named JSONL file or inferred directly from frozen V4.3 outputs; **VERIFIED** means metadata/code checked. No counts below were estimated from error rows. Threshold fixed at 0.61.\n",
"Source JSON includes file/artifact SHA-256, raw counts, percentages, label-conditioned distributions, and all row-level dimensions. Percentages for threat_vectors use flattened multi-label assignments and can sum above 100%. The project taxonomy documents primary_type as an intent category independent of security status. The category and intent tables both map to that one stored field; they are not independent labels. Source scam_type is shown separately.\n"]
for split in ["TRAIN","VAL","TEST","OOD"]:
 c=qa(split); lines += [f"## {split} — N={c['N']}\n", "### Labels\n",disttable(c["label_distribution"])]
 for field in ["source_id","source_type","language","script","category","intent","source_scam_type","threat_vector"]:
  lines += [f"### {field}\n",disttable(c[field+"_distribution"])]
 lines += ["### URL and phone presence\n",
  "Counts are reported both for the frozen model's raw regex and the normalized placeholder visible to lexical vectorizers.\n",
  "URL raw-regex: "+", ".join(f"{k} {v['count']} ({pct(v['percent'])})" for k,v in c['url_presence']['raw_model_regex'].items())+". URL token: "+", ".join(f"{k} {v['count']} ({pct(v['percent'])})" for k,v in c['url_presence']['normalized_url_placeholder'].items())+".\n",
  "Phone raw-regex: "+", ".join(f"{k} {v['count']} ({pct(v['percent'])})" for k,v in c['phone_presence']['raw_model_regex'].items())+". Phone token: "+", ".join(f"{k} {v['count']} ({pct(v['percent'])})" for k,v in c['phone_presence']['normalized_phone_placeholder'].items())+".\n",
  "### Message length (characters)\n",
  mdtable(["Group","N","p0","p25","p50","p75","p90","p95","p99","max"],[(lab,c['by_label'][lab]['N'],*[f"{c['by_label'][lab]['message_length_chars'].get(k,0):.1f}" for k in ['p0','p25','p50','p75','p90','p95','p99','p100']]) for lab in ['BENIGN','SUSPICIOUS_SPAM','MALICIOUS']])]
lines += ["## Annotation schema and taxonomy agreement\n",
"**VERIFIED:** canonical schema allows 8 primary_type values; taxonomy lists 10; V4.3 train uses 28 distinct values. Twenty distinct V4.3 training values (3,817 rows, all generated additions) are outside both enumerations: 2,177 BENIGN and 1,640 MALICIOUS. The test/validation/OOD records remain within schema values. This is an annotation-schema mismatch; the categories themselves may still be semantically useful.\n",
"**VERIFIED:** source_type values CONTROLLED_CONTRASTIVE (3,817 train rows) and INTERNAL_CURATED (230 train + 107 evaluation rows) are outside the schema enum. The 3,817 controlled additions have no threat_vectors field (UNANNOTATED); schema default NONE is distinct from a positive NONE annotation. Nineteen rows use language UNKNOWN uppercase, while schema enum uses lowercase unknown. Details and per-split counts are in annotation_taxonomy_audit in the JSON.\n",
"## Directly verified source concentration\n",
"**REPRODUCED:** TEST has 1,649/2,264 = 72.84% IMC25; OOD has 818/1,132 = 72.26% IMC25. Mendeley contributes 25.09% and 24.20%, respectively. This materially supports source concentration. The evidence is direct count data; whether the split procedure intended source independence is a separate unknown.\n",
"The raw regex columns also show zero raw URL/phone matches in VAL, TEST, and OOD. TEST nevertheless contains 742 `<URL>` placeholders (32.77%) and 268 phone placeholders (11.84%); OOD has 354 (31.27%) and 121 (10.69%). The structural raw-pattern features are therefore zero on all held-out records, while lexical features can still see placeholders.\n",
"## Row and artifact integrity\n",
f"**REPRODUCED:** inference used class order {A['artifact_properties']['class_order']}, {A['artifact_properties']['n_features_in']} features, and {A['artifact_properties']['n_iter']} stored boosting iterations. VAL/TEST/OOD metric counts are in the JSON under `split_metrics`; they match the prior V4.3 reproduction.\n",
"Full aggregate tables, class-conditioned source/language/category/intent-proxy/threat-vector distributions, quantiles, hashes, and probabilities: [DATASET_COMPOSITION_AUDIT.json](DATASET_COMPOSITION_AUDIT.json).\n"]
(ROOT/"DATASET_COMPOSITION_AUDIT.md").write_text("\n".join(lines),encoding="utf-8")

err=["# TEST/OOD Error Stratification\n","**REPRODUCED** from all TEST/OOD rows and frozen model predictions at τ=.61. Groups with zero BENIGN or MALICIOUS examples show FPR or recall as N/A, not zero. Project taxonomy defines primary_type as intent categories; category and intent strata are the same underlying annotation. source_scam_type is included as a separate descriptive proxy. URL/phone groups distinguish raw model-regex matches from placeholders.\n"]
for split in ["TEST","OOD"]:
 err += [f"## {split}\n", "| Group | N | B/S/M | benign FP/FPR | M recall | S→M | M→S | M→B |\n|---|---:|---:|---:|---:|---:|---:|---:|\n"]
 for dim in ["source_id","language","category","intent","source_scam_type","threat_vector","url_presence","phone_presence"]:
  err += [f"### {dim}\n","| Value | N | B/S/M | B FP/FPR | M recall | S→M | M→S | M→B |\n|---|---:|---:|---:|---:|---:|---:|---:|\n"]
  for k,v in A["error_stratification"][split][dim].items():
   err += [f"| {k} | {v['N']} | {v['BENIGN']}/{v['SUSPICIOUS_SPAM']}/{v['MALICIOUS']} | {v['benign_FP']}/{pct(100*v['benign_FPR']) if v['benign_FPR'] is not None else 'N/A'} | {v['malicious_correct']}/{v['MALICIOUS']} ({pct(100*v['malicious_recall']) if v['malicious_recall'] is not None else 'N/A'}) | {v['spam_to_malicious']} | {v['malicious_to_spam']} | {v['malicious_to_benign']} |\n"]
err += ["## Distribution findings\n",
"- **REPRODUCED:** all 90 TEST and 31 OOD SPAM→MALICIOUS errors are category PROMOTIONAL and threat vector COMMERCIAL_SPAM. They are spread across sources: TEST IMC25 68/131 spam rows (51.9%), Mendeley 20/51 (39.2%), UCI 2/6 (33.3%); OOD IMC25 28/58 (48.3%), Mendeley 3/23 (13.0%), UCI 0/2. Small non-IMC denominators limit comparison.",
"- **REPRODUCED:** TEST malicious misses: 42/1,518 IMC25 malicious (2.77%), 4/38 Mendeley (10.53%); OOD: 31/760 IMC25 (4.08%), 1/22 Mendeley (4.55%), 1/12 curated (8.33%). OOD/secondary-source strata are small.",
"- **REPRODUCED:** TEST malicious misses concentrate in UNKNOWN category (33/480; 18 M→B and 15 M→S), then SERVICE_UPDATE (6/171), DELIVERY (5/143), BANKING_TRANSACTIONAL (2/640). OOD: UNKNOWN 23/238, BANKING_TRANSACTIONAL 2/327, GOVERNMENT_INFO 3/74, plus small residual groups.",
"- **REPRODUCED:** three Hinglish rows occur in each TEST/OOD split and none carries a reported target-class error. This is not evidence of language robustness; group size is inadequate.",
"- **INFERENCE:** SPAM→MALICIOUS errors are more category/semantic-class-specific than source-exclusive. Malicious misses are distributed among source and category strata, with UNKNOWN metadata accounting for much of the miss count.",
"- **VERIFIED:** raw URL and phone feature presence is zero throughout TEST/OOD. Placeholder-conditioned counts and rates are still shown in the full tables; lexical representation remains exposed to the placeholder token.\n",
"Complete exact-count tables with class-conditional probability means: [DATASET_COMPOSITION_AUDIT.json](DATASET_COMPOSITION_AUDIT.json).\n"]
(ROOT/"ERROR_STRATIFICATION.md").write_text("\n".join(err),encoding="utf-8")

cc=["# Three-Class Confusion and Probability Analysis\n","**REPRODUCED** using the frozen V4.3 class probabilities; τ is unchanged. Class order is BENIGN, SUSPICIOUS_SPAM, MALICIOUS.\n",
"## Full confusion summary\n",mdtable(["Split","B FP","S→M","M→S","M→B","Malicious recall"],[(s,A['split_metrics'][s]['benign_FP'],A['split_metrics'][s]['spam_to_malicious'],A['split_metrics'][s]['malicious_to_spam'],A['split_metrics'][s]['malicious_to_benign'],f"{A['split_metrics'][s]['malicious_correct']}/{A['split_metrics'][s]['MALICIOUS']}") for s in ['VAL','TEST','OOD']]),
"## Confidence among three important confusion groups\n","| Split / true→predicted | N | Mean P(B/S/M) | Median P(B/S/M) | Median P(non-benign) |\n|---|---:|---|---|---:|\n"]
for split in ["TEST","OOD"]:
 for key in ["SUSPICIOUS_SPAM_pred_MALICIOUS","MALICIOUS_pred_SUSPICIOUS_SPAM","MALICIOUS_pred_BENIGN"]:
  v=A["class_confusion_probability_distributions"][split][key]
  means=", ".join("%.3f"%z for z in v["mean_probabilities"])
  medians=", ".join("%.3f"%v[k]["p50"] for k in ["p_benign_quantiles","p_spam_quantiles","p_malicious_quantiles"])
  cc += [f"| {split} {key.replace('_pred_','→')} | {v['N']} | {means} | {medians} | {v['p_nonbenign_quantiles']['p50']:.4f} |\n"]
cc += ["\n**Interpretation:** TEST SPAM→MALICIOUS has mean P(M)=.770 and median P(M)=.786; median P(non-benign)=.9993. OOD is similar (mean P(M)=.771). This is high-confidence *class assignment*, not a threshold miss. All these rows have the PROMOTIONAL / COMMERCIAL_SPAM metadata label. Threshold changes cannot fix this boundary because P(non-benign) is already near 1.\n",
"MALICIOUS→SPAM errors are also above the non-benign threshold: TEST mean P(S/M)=.673/.324; OOD .711/.280. These are three-way class errors, not BENIGN threshold misses.\n",
"For MALICIOUS→BENIGN, TEST mean P(B/S/M)=.720/.023/.257 and maximum P(non-benign)=.5913; OOD means=.686/.025/.289 and maximum=.5654. These are below τ=.61, so the binary gate contributes directly to those 24 TEST and 17 OOD misses. No alternate threshold was applied.\n",
"## Training separability and semantic overlap\n",
"**VERIFIED:** train contains 1,169 SPAM vs 12,612 MALICIOUS. Source distributions differ: 812/1,169 SPAM are IMC25, 310 Mendeley, 47 UCI; MALICIOUS is 10,531 IMC25, 393 Mendeley, with the remainder largely controlled V4.3 security examples. Promotional terminology occurs in 482 SPAM and 1,232 MALICIOUS examples; account/security terminology in 54 SPAM vs 4,460 MALICIOUS. These are strongly label-associated patterns, not clean separability proof.\n",
"**REPRODUCED:** the high TEST/OOD P(non-benign) median (.999642/.999608) largely reflects class mix and confident separation of most labeled non-benign rows: TEST has 77.0% SPAM+MALICIOUS and OOD 77.5%. Yet the class gate saturates while the SPAM/MALICIOUS boundary fails on the promotional subset.\n",
"## Calibration and saturation — VAL only\n",
f"**REPRODUCED:** multiclass Brier={A['calibration_val_only']['multiclass_brier_mean_over_class_dimensions']:.4f}; multiclass log loss={A['calibration_val_only']['multiclass_log_loss']:.4f}; binary non-benign Brier={A['calibration_val_only']['binary_nonbenign_brier']:.4f}; non-benign log loss={A['calibration_val_only']['binary_nonbenign_log_loss']:.4f}; 10-bin ECE={A['calibration_val_only']['binary_nonbenign_ECE_10_equal_width_bins']:.4f}. One-vs-rest ECE: "+", ".join(f"{k} {v['one_vs_rest_ECE_10_bins']:.4f}" for k,v in A['calibration_val_only']['classwise_one_vs_rest_calibration'].items())+".\n",
f"VAL has {A['calibration_val_only']['probability_saturation']['p_nonbenign_ge_0_99']:.1%} P(non-benign)≥.99 and {A['calibration_val_only']['probability_saturation']['any_class_probability_ge_0_999']:.1%} records with a class probability≥.999. On TEST, {A['probability_distributions']['TEST']['all']['fraction_p_nonbenign_ge_0_999']:.1%} have P(non-benign)≥.999; OOD {A['probability_distributions']['OOD']['all']['fraction_p_nonbenign_ge_0_999']:.1%}.\n",
"**INFERENCE:** the aggregate median is not evidence by itself of good calibration or HGB failure. It arises in a dataset with roughly 77% labeled non-benign plus near-saturated scores on most of those rows. HGB tree-ensemble probabilities are visibly concentrated near 0/1; VAL multiclass/log-loss and classwise ECE show non-zero calibration error, especially MALICIOUS ECE. Calibration diagnostics are validation-only; no calibration or threshold change was performed. The exact share attributable to leaf purity, class weights/prior, feature separation and preprocessing is **UNKNOWN**.\n",
"Full conditional quantiles and VAL reliability bins: [DATASET_COMPOSITION_AUDIT.json](DATASET_COMPOSITION_AUDIT.json).\n"]
(ROOT/"CLASS_CONFUSION_ANALYSIS.md").write_text("\n".join(cc),encoding="utf-8")

ls=["# Label Semantics Audit — V4.3 Training Corpus\n","**VERIFIED** counts are literal regex/metadata intersections over all 19,672 V4.3 training rows. These are descriptive screens, not adjudications or relabeling. Duplicate records remain counted because training rows are what the model saw.\n",
"## Security label definitions\n",
"**VERIFIED:** data/schemas/taxonomy.json defines BENIGN as safe/legitimate communications (including OTPs, bank alerts and delivery notices); SUSPICIOUS_SPAM as unsolicited commercial messages, telemarketing and nuisance/unverified offers without credential theft or severe threat payloads; MALICIOUS as severe threats including phishing, credential theft, reverse OTP, fake KYC/PAN suspension, electricity scams, UPI collect fraud, APK droppers and extortion. The distinction between a nuisance offer and malicious prize/credential lure therefore depends on action and threat intent, not promotional vocabulary alone.\n",
"## Label composition and source association\n",mdtable(["Label","N","Percent"],[(k,v['count'],pct(v['percent'])) for k,v in A['composition']['TRAIN']['label_distribution'].items()]),
"Label-conditioned source/language/category/intent/threat-vector/URL/phone/length distributions are in the TRAIN by_label object in DATASET_COMPOSITION_AUDIT.json. Category and intent both map to primary_type by taxonomy; source-supplied scam_type is distinct.\n",
"## Keyword association counts\n","Counts below overlap across terms and are not a bag-of-words feature attribution.\n",
mdtable(["Term family","Rows","BENIGN","SPAM","MALICIOUS","P(M) among hits"],[(k,v['N'],v['label_counts']['BENIGN'],v['label_counts']['SUSPICIOUS_SPAM'],v['label_counts']['MALICIOUS'],pct(v['label_rates_among_hits'].get('MALICIOUS',0)*100)) for k,v in A['training_keyword_audit'].items()]),
"**VERIFIED:** 'hello' occurs in 332 rows (263 MALICIOUS; 79.2% of hits); 'hi' in 566 (408 M; 72.1%); electricity 422 (339 M; 80.3%); bill 770 (543 M; 70.5%); OTP 1,142 (692 M; 60.6%); literal `.apk` 150 (all M); institutional vocabulary 682 (340 M /333 B); promotional vocabulary 1,817 (1,232 M /482 S /103 B); account/security vocabulary 4,931 (4,460 M /417 B /54 S). 'Phone/call/contact' matches are 2,777 M /503 B /258 S.\n",
"**Caveat:** these regexes are intentionally broad and count benign text such as “Do not share OTP” as security wording; an occurrence is not a threat intent. Category mix and label associations vary by source, so these numbers demonstrate skew/overlap, not causality.\n",
"## Label-semantic ambiguity screens\n"]
for key,title in [("malicious_promotional_without_raw_url_or_phone","MALICIOUS promotional wording with no raw URL/phone"),("malicious_security_terms","Security/account terms by label"),("url_less_malicious_conversational_short_le_8_words","URL/phone-less messages of at most 8 words by label")]:
 ls += [f"### {title}\n",mdtable(["Label","N","Example text"],[(lab,d['N'],"; ".join(e['text'].replace('|','/')[:140] for e in d['examples'][:3])) for lab,d in A['label_semantics_heuristics'][key].items()])]
ls += ["\n**REPRODUCED:** 1,189 MALICIOUS rows match promotional words without raw URL or phone; examples include prizes, data boosters, free testing kits, plus contextually diverse messages. This is meaningful surface overlap, but some still contain URLs as `<URL>` or coercive/action context; it does not prove mislabeled marketing.\n",
"**REPRODUCED:** 714 BENIGN rows match broad account/security/OTP terms. Many are legitimate safety warnings or transactional alerts, e.g. “Do not share OTP … to prevent fraud.” These show that security vocabulary is not sufficient to call MALICIOUS.\n",
"**REPRODUCED:** 1,124 MALICIOUS rows are <=8 whitespace tokens and lack raw URL/phone; this heuristic includes promotional or clipped texts as well as conversational items. Source examples include greetings and ordinary-looking acknowledgements in held-out error files. It cannot distinguish social engineering from source label/taxonomy noise.\n",
"## Finding\n",
"**VERIFIED:** the training dataset's primary_type annotation does not conform to the schema/taxonomy enumerations: 20 distinct values (3,817 controlled-addition rows) are outside both allowed sets. source_type also has 4,154 out-of-enum rows; controlled additions omit threat_vectors.\n",
"**INFERENCE:** topic words alone cannot define the three security labels. Metadata has overlapping promotional/security topics; primary_type provides a coarse intent category but not full action intent/channel trust. This establishes annotation-schema inconsistency and ambiguity, but **does not establish that the security labels themselves are incorrect** without provenance-aware human review. Actual SPAM→MALICIOUS prediction evidence is in CLASS_CONFUSION_ANALYSIS.md.\n"]
(ROOT/"LABEL_SEMANTICS_AUDIT.md").write_text("\n".join(ls),encoding="utf-8")

cf=["# Counterfactual Method Audit — Explicit-Intent Matrix\n","**REPRODUCED** by running frozen V4.3 over twenty manually authored pairs. This is analysis-only and not a benchmark, performance estimate, training data, or independent evidence. τ=.61 remained unchanged.\n",
"## Label contract and construction\n",CF["label_policy"]+"\n\n"+CF["construction_rule"]+"\n",
"Every pair keeps its message frame and domain fixed, changing one action clause/property. The rationale records the intended semantic distinction. A MALICIOUS intended label does not mean every similar lexical string is malicious in all real contexts.\n",
"## Pair-level scores\n","| ID | Domain | Changed property | Intended B / M | Predicted B / M | P(non-benign) B / M | Intended score order? | Rationale |\n|---|---|---|---|---|---:|---|---|\n"]
for p in CF['pairs']:
 a,b=p['scores']; cf += [f"| {p['id']} | {p['domain']} | {p['changed_property']} | B / M | {a['predicted_label']} / {b['predicted_label']} | {a['p_nonbenign']:.3f} / {b['p_nonbenign']:.3f} | {'yes' if p['intended_order_correct'] else '**no**'} | {p['rationale']} |\n"]
ordering=sum(p['intended_order_correct'] for p in CF['pairs']); exact=sum(p['scores'][0]['predicted_label']=='BENIGN' and p['scores'][1]['predicted_label']=='MALICIOUS' for p in CF['pairs'])
cf += [f"\n**REPRODUCED:** intended score ordering is correct on {ordering}/20 pairs; exact intended labels at τ=.61 are correct on {exact}/20 complete pairs. A pair counts as exact only when benign text predicts BENIGN and malicious text predicts MALICIOUS. CF06 reverses score order (doorstep OTP BENIGN scores above remote pre-arrival OTP MALICIOUS). Several pairs order correctly but classify both texts MALICIOUS, showing ranking and operating-point decision are different.\n",
"## Method limits\n",
"- All texts and rationales were created for this analysis; there is no independent authorship or sample population.",
"- Wording, token frequency, and sometimes message length change as part of the one substituted action clause; this is not a strict one-token intervention.",
"- Intended ground truth is scenario-level and assumes an unsolicited contact where stated; actual sender/channel provenance is not represented to the model.",
"- This matrix measures model response, not real-world accuracy. It must not be added to training or represented as a held-out benchmark.",
"- Machine-readable pairs, rationales and all three probabilities: [COUNTERFACTUAL_METHOD_AUDIT.json](COUNTERFACTUAL_METHOD_AUDIT.json).\n"]
(ROOT/"COUNTERFACTUAL_METHOD_AUDIT.md").write_text("\n".join(cf),encoding="utf-8")

rep=["# Second ML Forensic Report\n","Scope: sentinel-ml/Messages-ml only. No training, data edits, threshold changes, V2/V4.3 artifact changes, or Android work.\n",
"## Evidence-status summary\n",
"- **VERIFIED:** frozen artifact architecture/hashes and full-dataset metadata were checked directly.",
"- **REPRODUCED:** V4.3 VAL/TEST/OOD predictions, aggregate composition, per-group error counts, class probabilities, VAL-only reliability diagnostics, training keyword/source distributions, and twenty authored counterfactual probes.",
"- **INFERENCE:** data/source skew is real; the dominant actionable failure pattern in observed classifications is a high-confidence SPAM/MALICIOUS boundary failure on promotional/commercial-spam rows. The full diagnosis is multi-layer.",
"- **UNKNOWN:** true human label correctness, temporal/real-world generalization, causal feature contributions on natural messages, and whether more representative data alone would remedy the class boundary.\n",
"## Seven final questions\n",
"1. **Is source/data skew actually demonstrated? — YES (VERIFIED).** TEST: IMC25 1,649/2,264 (72.84%), Mendeley 568 (25.09%); OOD: IMC25 818/1,132 (72.26%), Mendeley 274 (24.20%). BENIGN TEST is mostly Mendeley (479/520); MALICIOUS TEST mostly IMC25 (1,518/1,556). TEST/OOD language flag Hinglish is 3 records each. V4.3 train is 64.11% MALICIOUS.",
"2. **Is three-class SPAM/MALICIOUS confusion a major bottleneck? — YES (REPRODUCED).** TEST has 90/188 SPAM→MALICIOUS (47.9%) and 22 MALICIOUS→SPAM; OOD 31/83 (37.3%) and 16. The 90/31 errors all fall under PROMOTIONAL / COMMERCIAL_SPAM metadata and have median P(M) about .786/.783, with P(non-benign) near .999. This is not a threshold problem.",
"3. **Is representation failure demonstrated? — PARTLY (VERIFIED/REPRODUCED, bounded).** Candidate-D lacks explicit intent, source-authenticity, callback, APK, or negation-scope features, and held-out raw URL/phone features are zero because values were placeholder-normalized. A controlled authored OTP/delivery-code pair reverses or fails absolute labels. Broader natural-data representation failure as the main root cause remains UNKNOWN.",
"4. **Is label-semantic inconsistency demonstrated? — YES AT THE ANNOTATION SCHEMA; SECURITY MISLABELS NOT PROVEN.** The schema/taxonomy does not accept 20 distinct primary_type values used on 3,817 training rows (2,177 B /1,640 M); source_type has 4,154 out-of-enum rows, and the controlled additions omit threat_vectors. The corpus also has 1,232 MALICIOUS promotional-word hits and 714 BENIGN security-word hits. No human relabeling was performed, so incorrect security labels are not proven.",
"5. **Is thresholding the main problem? — NO (INFERENCE from reproduced score paths).** Threshold policy accounts for 24 TEST and 17 OOD MALICIOUS→BENIGN errors whose maximum P(non-benign) remains below .61. It does not account for 90/31 SPAM→MALICIOUS or 22/16 MALICIOUS→SPAM, all of which are above threshold.",
"6. **Is there evidence that more training data alone will solve this? — NO.** There is no causal evidence for volume alone. V4.4 historical targeted additions reportedly improved probes while worsening global metrics; that history cautions against treating more examples as a remedy. Future data design must improve independent source/label coverage, not merely increase N.",
"7. **What single technical hypothesis now has the strongest evidence? — INFERENCE.** V4.3 learns a strong non-benign signal but an unstable three-class boundary where promotional/commercial-spam rows are often mapped to MALICIOUS; class/source associations, nonconforming controlled-addition labels, and lack of explicit action-intent/transaction-channel features make the SPAM/MALICIOUS distinction unreliable. The cross-source 90/31 error concentration under one target category is the strongest model-error evidence.\n",
"## Decision\n","# G. MULTI-LAYER PROBLEM\n",
"**Why:** source/class skew is quantitatively demonstrated (TEST/OOD source mixes, TRAIN label balance and language coverage); the dominant three-class error is high-confidence and category-specific; input representation omits normalized intent and raw URL/phone cues in held-out files; the MALICIOUS→BENIGN component is partly threshold-gated; and class-label semantics are underdocumented. No single threshold or capacity explanation accounts for all of these. This is a layered diagnosis, not proof every layer is equally causal.\n",
"Decision work is analysis only. No candidate experiment or model recommendation is made. Supporting artifacts: DATASET_COMPOSITION_AUDIT.json, ERROR_STRATIFICATION.md, CLASS_CONFUSION_ANALYSIS.md, LABEL_SEMANTICS_AUDIT.md, COUNTERFACTUAL_METHOD_AUDIT.md.\n"]
(ROOT/"SECOND_FORENSIC_REPORT.md").write_text("\n".join(rep),encoding="utf-8")
print("Rendered six forensic Markdown reports.")
