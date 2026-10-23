# Sentinel Message Security ML Dossier

Research pass: 2026-09-30. Primary scope: sentinel-ml/Messages-ml. Baseline reproduced; full source and provenance audit remains open.

Tags: **VERIFIED** = inspected directly; **REPRODUCED** = recomputed; **HISTORICAL** = existing report claim not independently rerun; **INFERENCE** = interpretation; **UNKNOWN** = unresolved.

## Executive finding

- **REPRODUCED** V4.3 exactly matches its VAL, TEST, and OOD headline counts at tau=0.61.
- **VERIFIED** TEST/OOD are source-concentrated: 1,649/2,264 TEST rows and 818/1,132 OOD rows identify SRC_IMC25_FISHING_SMISHING. Mendeley is the next-largest source. OOD is not a wholly unseen collection source.
- **VERIFIED** training is 64.1% MALICIOUS and manifest-labeled 9.13% Hinglish, while held-out splits contain only 18 VAL, 3 TEST, and 3 OOD Hinglish rows. Script scan finds 69 Devanagari train rows, 17 VAL, 15 TEST, and 4 OOD; the language flag and script distribution are distinct.
- **REPRODUCED** TEST error types include 90 SPAM→MALICIOUS, 24 MALICIOUS→BENIGN, 22 MALICIOUS→SPAM, 3 SPAM→BENIGN, 2 BENIGN→MALICIOUS. OOD counts are 31,17,16,4,1 respectively.
- **INFERENCE** primary bottleneck is the data/evaluation contract (label validity, source shift, target-language coverage), then three-class confusion and representation. Aggregate scores are real for these files but do not establish intended field performance.
- **UNKNOWN** candidate-changing training is justified before independent, adjudicated data exists. This pass ran no training.

## 1. Frozen V4.3 architecture

- **VERIFIED** artifact directory: messages_v4_3/models/candidate_d. 19 structural values + 1,500 word TF-IDF + 2,500 char_wb TF-IDF = 4,019 dimensions. Word n-grams 1–2; char n-grams 2–5; sublinear TF enabled.
- **VERIFIED** HistGradientBoostingClassifier; class order [0,1,2] = BENIGN, SUSPICIOUS_SPAM, MALICIOUS; learning_rate=.08, max_leaf_nodes=31, l2=1, class_weight={0:1.5,1:1,2:1}, seed 20260914, max_iter=300.
- **VERIFIED** stored n_features_in_=4019, n_iter_=111, scaler width=4019; early_stopping=auto, validation_fraction=.1, n_iter_no_change=10, tol=1e-7. **INFERENCE** 111 is consistent with intended early stopping, not an artifact defect. Retraining for byte equality was not done.
- **VERIFIED** policy: if P(spam)+P(malicious) < .61 return BENIGN; otherwise choose SPAM vs MALICIOUS by their relative probabilities.
- **VERIFIED** ordered structural inputs: text length, whitespace word count, mean word length, digit count/ratio, uppercase count/ratio, special count/ratio, URL count/presence, phone count/presence, question mark, short text, naked URL, suspicious TLD, IP/hex URL, suspicious naked URL.

## 2. Current artifacts and hashes

**REPRODUCED**, SHA-256:

| File | SHA-256 |
|---|---|
| model.pkl | 2ca29457acd27bf93d6967d8f9d64778b8ba0e404030175465c802fe1a138a7d |
| scaler.pkl | aab17413541b12804b70677161a540fa384b0ec0eeebed8be308de3c3c0a21b9 |
| word_vec.pkl | 10403d9e8b5f641fd3d200a5e08f5c65e3fdcd7afca65613d47d0f4cfbe96aac |
| char_vec.pkl | fa56cf5548f3ae17f0ccc5c7e8b7ba801e27be8bcd522887ea5af8bae68468b1 |

**VERIFIED** corpus manifest hash d01d4d36144e8c4d09f4c0fd21eb15b02e10f1be4d488bebb07ce7eba9c11c11 matches train_v4_3.jsonl.

## 3. Corpora

- **VERIFIED** V4.3 train: 19,672 rows; 12,612 MALICIOUS (64.11%), 5,891 BENIGN (29.95%), 1,169 SPAM (5.94%). 15,855 base + 3,817 controlled additions.
- **VERIFIED** source counts: 11,343 IMC25, 4,095 Mendeley, 230 curated hard negatives, 187 UCI plus 3,817 V4.3 controlled examples across institutional, utility, OTP, Hinglish, short-chat, URL, delivery, and telco categories.
- **VERIFIED** manifest language: 17,861 English, 1,797 Hinglish, 14 unknown. Most split rows are public research sources; TEST has 1,649 IMC25 / 568 Mendeley / 27 UCI / 20 curated; OOD has 818 / 274 / 17 / 23.
- **VERIFIED** split sizes: VAL 3,397 (807 B /274 S /2,316 M); TEST 2,264 (520/188/1,556); OOD 1,132 (255/83/794).
- **VERIFIED** focused benchmarks exist in data/benchmarks, but multiple security slices are tiny: electricity scam n=3, legitimate banking n=3, Hinglish smishing n=3.
- **HISTORICAL** V4.4 has seven authored holdouts, 712 total; V4.5 reports classify them as targeted regression probes, not independent OOD.
- **UNKNOWN** full license, acquisition lineage, date, and human adjudication method for every public-source record.

## 4. Reproduced baseline

**REPRODUCED** by direct pickle loading and evaluation, without writing to protected data or frozen artifacts. Outputs: messages_v4_3/evaluation/reproduction_20260930/reproduction.json and val_errors.json/test_errors.json/ood_errors.json. Script: scripts/reproduce_frozen_v43.py.

| Split | Malicious recall | Benign FPR | Confusion matrix rows B / S / M |
|---|---:|---:|---|
| VAL | 2222/2316 = 95.94% | 16/807 = 1.98% | [791,0,16] / [8,133,133] / [57,37,2222] |
| TEST | 1510/1556 = 97.04% | 2/520 = .38% | [518,0,2] / [3,95,90] / [24,22,1510] |
| OOD | 761/794 = 95.84% | 1/255 = .39% | [254,0,1] / [4,48,31] / [17,16,761] |

**VERIFIED** these figures match reports. This alone does not validate labels, representativeness, source independence, or probability calibration.

## 5. Error forensics and failure taxonomy

- **REPRODUCED** per-error exports include raw text, label/prediction, class probabilities, p_nonbenign, source/category/language, structural vector, length, URL/phone presence, and strongest active word/char terms for VAL/TEST/OOD errors. All TEST and OOD errors are inspectable in the exports.
- **REPRODUCED** TEST 46 malicious FN = 24 BENIGN + 22 SPAM; 90/188 spam are predicted MALICIOUS. Two benign FPs, both MALICIOUS. OOD 33 malicious FN = 17 BENIGN + 16 SPAM; 31/83 SPAM predicted MALICIOUS; one benign FP.
- **VERIFIED** some labeled MALICIOUS errors are bare or ordinary conversational text (e.g. “Hey 👋”, “Are you busy now?”, “Congratulations!!!”) and ordinary-looking delivery/service text. Could be genuine social engineering, label taxonomy, or data noise; no relabeling was performed.
- **INFERENCE** hello suspicion plausibly reflects training prior: 336 train messages containing “hello” are labeled MALICIOUS 265, BENIGN 36, SPAM 35. This broad contextual count does not establish unigram causality.
- **VERIFIED** utility word counts are skewed: electricity 339 M /82 B /1 S among 422 occurrences; bijli 53 M /28 B among 81; meter 12 M /8 B among 20. Small support plus skew can create wording sensitivity.
- **VERIFIED** dedicated structural features do not represent OTP intent, callback intent, coercion, negation, sender trust, APK/download intent, or utility/campus semantics. Phone regex is narrowly Indian 10-digit format and can be neutralized by data placeholders.
- **VERIFIED** word unigrams/bigrams and char 2–5 grams can encode local “not share” patterns when seen in vocabulary; they do not represent broad negation scope. **UNKNOWN** counterfactual causal effects for bare greetings, OTP polarity, brands, institutions, provider wording, URLs, and punctuation were not swept in this pass.
- **HISTORICAL** V4.4 forensic report found utility/system false positives, “Hello” false positive, institutional recall regression, and holdout co-construction; RC2 report notes threshold movement .63→.74 and global class-confusion regression. Every V4.4 artifact is not independently reproduced here.
- **HISTORICAL** MiniLM V4.5 reports worse broad primary/OOD behavior. Complementarity postmortem reports few unique recoveries. Asymmetric sieve audit reports 101 M/147 B/55 S; both models at 88/101 M correct and 36/147 benign FP, 13 shared wrong, no exclusive wins. This rejects that setup only, not transformers generally.

## 6. Experiment history (current evidence state)

- **HISTORICAL** V2 used about 70 deterministic features plus word/char TF-IDF, HGB, threshold around .704. V3 used downstream contextual dampening. Full artifact/report reconciliation is **UNKNOWN**.
- **HISTORICAL** V4 expanded contrastive data and retained a 70-feature model; reports show around 89% TEST recall and severe weak-slice regressions, so it was rejected.
- **VERIFIED/HISTORICAL** V4.3 Candidate D is the frozen 19-feature model reproduced above. Its training script, generator, manifest, evaluation and reports exist; full candidate A-C artifact correspondence remains unverified.
- **HISTORICAL** V4.4 RC1 selected candidate claims were retracted by its own final audit; RC2 successive utility/greeting/institution additions improved targeted probes but caused threshold creep and global recall/class-confusion regressions. Reports identify co-generated holdouts and exact-only leakage criteria as methodological failures.
- **HISTORICAL** V4.5 MiniLM and V4.3+MiniLM asymmetric sieve were rejected. No conclusion about all transformer methods follows.
- **UNKNOWN** full per-experiment training hashes, all V2/V3 hyperparameters, protected-data split creation provenance and exact report-to-pickle mapping require deeper historical reconstruction.

## 7. Threshold, leakage, and source-shift

- **REPRODUCED** tau=.61 gives the stated counts. **HISTORICAL** selection used VAL at benign FPR <=2%; no TEST/OOD tuning is implied by the reproduced policy.
- **VERIFIED** V4.3 generator includes a lowercase/trimmed protected-text exact check and manifest claims 7,156 protected texts, zero leakage. **UNKNOWN** complete near-duplicate/template/Jaccard/source identity audit against the final immutable evaluation versions.
- **HISTORICAL** V4.4/V4.5 audits document exact-only checks missing normalized/template overlaps and co-constructed targeted probes. This is a caution, not proof V4.3 itself leaked.
- **INFERENCE** primary data bottleneck is source shift and label quality/definition, followed by class confusion and representation coverage. V4.3 TEST/OOD are both mostly same research sources; Hinglish is nearly absent from test; utility/campus/callback slices are synthetic/tiny.
- **UNKNOWN** calibration by source/class, contemporary safety precision/recall, acceptable SPAM↔MALICIOUS action tradeoff, and Android parity of current production assets.

## 8. Current failure hypotheses

- **INFERENCE** Electricity: class/source skew and limited authentic wording coverage are more likely than simply lacking the word “electricity.”
- **INFERENCE** Greetings: skewed label prior, source taxonomy, threshold/feature interaction may all contribute; token-only cause unverified.
- **INFERENCE** Hinglish: evaluation/data coverage and domain shift are currently more evidenced than representation capacity.
- **INFERENCE** Campus/institution: genuine behavioral discrimination requires channel/destination/action context; institution or brand allowlists are unsafe.
- **VERIFIED** callback phone presence is basic only; no number type/reputation/callback-intent feature.
- **VERIFIED** no explicit APK feature; direct string-only gate is unsafe without benign software context and URL analysis.
- **VERIFIED** spam and malicious are distinct classes; primary split shows material cross-confusion in both directions.

## 9. Bottleneck and selected experiment

- **INFERENCE** bottleneck category **J (multiple)**: A data quality, B source/coverage, H evaluation design; then E class confusion and C representation. This is evidence-based and not a capacity diagnosis.
- **EXPERIMENT_REPORT** one selected family: **F data redesign**. Main variable is independent source/adjudication; immutable V4.3 parent, threshold fixed, and source-held-out evaluation. Hypothesis: current observed weaknesses and headline success are materially confounded by label/source composition. This is **designed but not run** because no qualifying independently collected, adjudicated corpus exists in this workspace. No model training or augmentation was justified.

## 10. Ten important unanswered technical questions

**REPRODUCED counterfactual diagnostic (not independent evidence):** scripts/probe_counterfactuals_v43.py evaluates ten authored pairs; results are in messages_v4_3/evaluation/reproduction_20260930/counterfactual_probes.json. Bare “Hello” scores .9914 non-benign; punctuation-only “Hello.” scores .8044; “Hi” scores .6497. OTP polarity probes remain MALICIOUS and change score only modestly in one short pair. Provider/institution substitutions barely move scores; URL insertion raises score in the tested context. Adding a phone number to a utility disconnection text flips p_nonbenign .115→.763, but both text tokens and structural phone flag change, so this does not isolate phone-feature causality. These results motivate source-independent matched evaluation only.

1. **UNKNOWN** What are source acquisition dates, rights, and label protocols for each dataset?
2. **UNKNOWN** How many MALICIOUS records are ordinary chat, legitimate service, spam, or non-actionable descriptions after expert adjudication?
3. **UNKNOWN** How does V4.3 perform on contemporary source-disjoint Indian SMS/WhatsApp traffic?
4. **UNKNOWN** Performance by Romanized Hindi, code-switch rate, Devanagari, other scripts, and dialect?
5. **UNKNOWN** Matched-pair causal impact of “Hello”, “Hi”, OTP negation, and wording changes?
6. **UNKNOWN** Which utility/institution/callback signals persist after controlling for action, channel, URL and source?
7. **UNKNOWN** How should SPAM↔MALICIOUS errors map to user-facing action and risk?
8. **UNKNOWN** Do OTP/callback/download/negation failures generalize beyond co-generated synthetic probes?
9. **UNKNOWN** Which features/models survive grouped, temporal and source-held-out evaluation?
10. **UNKNOWN** Does the current Android runtime reproduce current V4.3 probabilities/assets?

See ROOT_CAUSE_ANALYSIS.md, EXPERIMENT_REPORT.md, RELEASE_DECISION.md, and REPRODUCTION_COMMANDS.md for concise decision records.
