# Baseline results — CPU only, frozen models
OBSERVED measurements; authored-probe labels are PROVISIONAL. No fit or threshold selection was performed. A score is never treated as a factual URL label. Models loaded directly from the required Python 3.11 venv, with hashes verified before inference; no portable-model fallback. V7 threshold is 0.22588719359679843; V8 is 0.28. Sources, split hash, environment and row scores accompany this report.

Reproduction: the clean group split exactly reproduces 22,835/23,158 attacks and 263/27,353 benign false alerts with URL strings: 98.605% recall / 0.962% FPR. Without URL strings: 22,825 TP and 207 FP, 98.562% / 0.757%. Thus URL adjudication adds 10 TP and 56 FP. No-URL fallback matches raw alert decisions, but is a different runtime path. Report both, never substitute fallback for production URL adjudication.

Clean test (OBSERVED against existing REPORTED dataset labels; data label truth was not reverified):

| Mode | FP / benign | FPR (Wilson 95%) | TP / attack | Recall (Wilson 95%) | False alerts / 1,000 benign | ASSUMED false alerts / day at 30 benign URLs |
|---|---|---|---|---|---|---|
| v7_raw | 267/27353 | 0.976% [0.866%, 1.100%] | 22880/23158 | 98.800% [98.651%, 98.932%] | 9.76 | 0.293 |
| v8_raw | 207/27353 | 0.757% [0.661%, 0.867%] | 22825/23158 | 98.562% [98.400%, 98.708%] | 7.57 | 0.227 |
| v8_url_adjudicated | 263/27353 | 0.962% [0.853%, 1.084%] | 22835/23158 | 98.605% [98.446%, 98.748%] | 9.62 | 0.288 |
| v8_no_url_fallback | 207/27353 | 0.757% [0.661%, 0.867%] | 22825/23158 | 98.562% [98.400%, 98.708%] | 7.57 | 0.227 |
| prior | 263/27353 | 0.962% [0.853%, 1.084%] | 22853/23158 | 98.683% [98.528%, 98.822%] | 9.62 | 0.288 |

ASSUMED prevalence calculations applied to clean-test rates:

| Mode | ASSUMED PPV at 0.1% attacks | at 1% | at 5% |
|---|---|---|---|
| v7_raw | 9.200% | 50.553% | 84.195% |
| v8_raw | 11.533% | 56.814% | 87.269% |
| v8_url_adjudicated | 9.310% | 50.881% | 84.369% |
| v8_no_url_fallback | 11.533% | 56.814% | 87.269% |
| prior | 9.317% | 50.901% | 84.379% |

New probe, SHA-256 `635cbda6f0728ae837536b7caec54444ee8d13c1f7c61dea6eb5898d9849e03b`, 600 provisional benign / 300 authored attack scenarios:

| Mode | FP / benign | FPR (Wilson 95%) | TP / attack | Recall (Wilson 95%) | False alerts / 1,000 benign | ASSUMED false alerts / day at 30 benign URLs |
|---|---|---|---|---|---|---|
| v7_raw | 408/600 | 68.000% [64.163%, 71.608%] | 270/300 | 90.000% [86.083%, 92.905%] | 680.00 | 20.400 |
| v8_raw | 385/600 | 64.167% [60.251%, 67.902%] | 270/300 | 90.000% [86.083%, 92.905%] | 641.67 | 19.250 |
| v8_url_adjudicated | 387/600 | 64.500% [60.590%, 68.226%] | 300/300 | 100.000% [98.736%, 100.000%] | 645.00 | 19.350 |
| v8_no_url_fallback | 385/600 | 64.167% [60.251%, 67.902%] | 270/300 | 90.000% [86.083%, 92.905%] | 641.67 | 19.250 |
| prior | 354/600 | 59.000% [55.019%, 62.866%] | 300/300 | 100.000% [98.736%, 100.000%] | 590.00 | 17.700 |

ASSUMED PPV under deployment prevalences (not the probe's 1/3 attack mix):

| Mode | ASSUMED PPV at 0.1% attacks | at 1% | at 5% |
|---|---|---|---|
| v7_raw | 0.132% | 1.319% | 6.512% |
| v8_raw | 0.140% | 1.397% | 6.875% |
| v8_url_adjudicated | 0.155% | 1.542% | 7.544% |
| v8_no_url_fallback | 0.140% | 1.397% | 6.875% |
| prior | 0.169% | 1.683% | 8.190% |

PPV = prevalence*recall / (prevalence*recall + (1-prevalence)*FPR). At 30 total URLs/day rather than 30 benign URLs/day, false alerts/day = 30*(1-prevalence)*FPR. The table's conservative shorthand assumes all 30 opportunities are benign. These are scenario calculations, not measured traffic forecasts. All Wilson intervals use row counts and are descriptive; correlated template examples and uncertain labels prevent a deployment-level inference. Zero misses among 300 authors' syntax-rich attack scenarios is not proof of perfect recall. The attack set overrepresents explicit credential/payload/redirect cues and lacks an adequate low-signal malicious-root cohort. A separately sourced untouched exam is necessary.

Probe prior effect: 387 -> 354 benign false alerts (8.53% relative reduction); clean attack recall 98.605% -> 98.683%. The frozen 0.25 cap does not eliminate high-score roots; no cap/threshold is tuned after observing this result. There are 246 KNOWN_SAFE_SHAPE rows; state membership does not promise a below-threshold outcome.

Per-form/category/platform and joint attributes: probe_breakdowns.csv/.json contain counts, confusion matrices, Wilson intervals and indicative-only markers for class denominator N<30. Missing class denominators are N/A. has_payload and tenant_hosted are authored attributes, not web observations. probe_failures.csv contains every false alert/missed attack, ranked worst first per model. Sample worst cases are below; no examples are selected to tune the policy.

v8_url_adjudicated, highest benign alerts:

- `https://t.co/6e69f9eb9bda3330262efbf3` — score 1.0000, shortener / deep_path.
- `https://tinyurl.com/2f1e02bc7426d98df1af0771` — score 1.0000, shortener / deep_path.
- `https://t.co/c49e5f8ba34cd4f3ec7b9e3c` — score 1.0000, shortener / deep_path.
- `https://t.co/2ae698b357e16f1a6fe3c9ba` — score 1.0000, shortener / deep_path.
- `https://amzn.to/35c91a70360223a8693b7ab5` — score 0.9999, shortener / deep_path.
- `https://bit.ly/54ff8192b55c178be913e6c2` — score 0.9999, shortener / deep_path.
- `https://tinyurl.com/17c3bc13b9d752f98c44c04f` — score 0.9999, shortener / deep_path.
- `https://bit.ly/bc7c823ed8f7d946b6711998` — score 0.9999, shortener / deep_path.

Authored attack misses: none.

prior, highest benign alerts:

- `https://t.co/6e69f9eb9bda3330262efbf3` — score 1.0000, shortener / deep_path.
- `https://tinyurl.com/2f1e02bc7426d98df1af0771` — score 1.0000, shortener / deep_path.
- `https://t.co/c49e5f8ba34cd4f3ec7b9e3c` — score 1.0000, shortener / deep_path.
- `https://t.co/2ae698b357e16f1a6fe3c9ba` — score 1.0000, shortener / deep_path.
- `https://amzn.to/35c91a70360223a8693b7ab5` — score 0.9999, shortener / deep_path.
- `https://bit.ly/54ff8192b55c178be913e6c2` — score 0.9999, shortener / deep_path.
- `https://tinyurl.com/17c3bc13b9d752f98c44c04f` — score 0.9999, shortener / deep_path.
- `https://bit.ly/bc7c823ed8f7d946b6711998` — score 0.9999, shortener / deep_path.

Authored attack misses: none.

REPORTED Phase 1C.1 comparison, reference only: burned benchmark FPR 84.00% (420/500), bare apex 100% (200/200), repo paths 96.67% (145/150), search 50% (75/150). This benchmark has a different deliberately difficult mixture from both clean data and the new probe; do not interpret a cross-corpus percentage difference as a model improvement. Historical B1 numbers differ; see HISTORICAL_EVIDENCE_NOTES.md.

Regression reports scored last, after freezing the policy: burned_regression_results.json, golden_regression_report.csv and burned_500_regression_report.csv. The 174 golden labels are frozen expected outputs, not established malicious/benign truth. Here “correct-to-wrong” means a new mismatch to that fixture contract. Do not use the fixture probabilities or labels as training targets. Changes that could represent a semantic correction still fail strict output parity. No policy revision follows these reports.

| Gate | Observed value | Status |
|---|---|---|
| Probe false-alert reduction >=20% relative | 0.0852713178294574 | FAIL |
| Clean attack recall loss <=0.2 percentage points | -0.0777269194230934 | PASS |
| Red-team bypass=0 and no discount | {"n": 160, "bypass": 0, "discounted": 0} | PASS |
| Golden correctness regressions=0 (REPORT ONLY) | 1 | FAIL |
| 500 false alerts no worse and no newly introduced (REPORT ONLY) | {"baseline_fp": 420, "candidate_fp": 422, "new_fp": 2} | FAIL |

Strict golden output parity: FAIL; 1 fixture-output disagreements. Golden baseline output disagreements: 0. Overall prototype verdict: REJECT for promotion; preserve frozen candidate and failures. No fit/deployment was performed.
