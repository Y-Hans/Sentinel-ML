# Three-Class Confusion and Probability Analysis

**REPRODUCED** using the frozen V4.3 class probabilities; τ is unchanged. Class order is BENIGN, SUSPICIOUS_SPAM, MALICIOUS.

## Full confusion summary

| Split | B FP | S→M | M→S | M→B | Malicious recall |
|---|---|---|---|---|---|
| VAL | 16 | 133 | 37 | 57 | 2222/2316 |
| TEST | 2 | 90 | 22 | 24 | 1510/1556 |
| OOD | 1 | 31 | 16 | 17 | 761/794 |

## Confidence among three important confusion groups

| Split / true→predicted | N | Mean P(B/S/M) | Median P(B/S/M) | Median P(non-benign) |
|---|---:|---|---|---:|

| TEST SUSPICIOUS_SPAM→MALICIOUS | 90 | 0.020, 0.210, 0.770 | 0.001, 0.173, 0.786 | 0.9993 |

| TEST MALICIOUS→SUSPICIOUS_SPAM | 22 | 0.003, 0.673, 0.324 | 0.001, 0.652, 0.344 | 0.9993 |

| TEST MALICIOUS→BENIGN | 24 | 0.720, 0.023, 0.257 | 0.724, 0.011, 0.254 | 0.2763 |

| OOD SUSPICIOUS_SPAM→MALICIOUS | 31 | 0.020, 0.209, 0.771 | 0.001, 0.211, 0.783 | 0.9992 |

| OOD MALICIOUS→SUSPICIOUS_SPAM | 16 | 0.010, 0.711, 0.280 | 0.002, 0.712, 0.286 | 0.9976 |

| OOD MALICIOUS→BENIGN | 17 | 0.686, 0.025, 0.289 | 0.597, 0.005, 0.341 | 0.4031 |


**Interpretation:** TEST SPAM→MALICIOUS has mean P(M)=.770 and median P(M)=.786; median P(non-benign)=.9993. OOD is similar (mean P(M)=.771). This is high-confidence *class assignment*, not a threshold miss. All these rows have the PROMOTIONAL / COMMERCIAL_SPAM metadata label. Threshold changes cannot fix this boundary because P(non-benign) is already near 1.

MALICIOUS→SPAM errors are also above the non-benign threshold: TEST mean P(S/M)=.673/.324; OOD .711/.280. These are three-way class errors, not BENIGN threshold misses.

For MALICIOUS→BENIGN, TEST mean P(B/S/M)=.720/.023/.257 and maximum P(non-benign)=.5913; OOD means=.686/.025/.289 and maximum=.5654. These are below τ=.61, so the binary gate contributes directly to those 24 TEST and 17 OOD misses. No alternate threshold was applied.

## Training separability and semantic overlap

**VERIFIED:** train contains 1,169 SPAM vs 12,612 MALICIOUS. Source distributions differ: 812/1,169 SPAM are IMC25, 310 Mendeley, 47 UCI; MALICIOUS is 10,531 IMC25, 393 Mendeley, with the remainder largely controlled V4.3 security examples. Promotional terminology occurs in 482 SPAM and 1,232 MALICIOUS examples; account/security terminology in 54 SPAM vs 4,460 MALICIOUS. These are strongly label-associated patterns, not clean separability proof.

**REPRODUCED:** the high TEST/OOD P(non-benign) median (.999642/.999608) largely reflects class mix and confident separation of most labeled non-benign rows: TEST has 77.0% SPAM+MALICIOUS and OOD 77.5%. Yet the class gate saturates while the SPAM/MALICIOUS boundary fails on the promotional subset.

## Calibration and saturation — VAL only

**REPRODUCED:** multiclass Brier=0.1124; multiclass log loss=0.2010; binary non-benign Brier=0.0178; non-benign log loss=0.0675; 10-bin ECE=0.0109. One-vs-rest ECE: BENIGN 0.0109, SUSPICIOUS_SPAM 0.0198, MALICIOUS 0.0277.

VAL has 68.3% P(non-benign)≥.99 and 30.1% records with a class probability≥.999. On TEST, 60.3% have P(non-benign)≥.999; OOD 59.5%.

**INFERENCE:** the aggregate median is not evidence by itself of good calibration or HGB failure. It arises in a dataset with roughly 77% labeled non-benign plus near-saturated scores on most of those rows. HGB tree-ensemble probabilities are visibly concentrated near 0/1; VAL multiclass/log-loss and classwise ECE show non-zero calibration error, especially MALICIOUS ECE. Calibration diagnostics are validation-only; no calibration or threshold change was performed. The exact share attributable to leaf purity, class weights/prior, feature separation and preprocessing is **UNKNOWN**.

Full conditional quantiles and VAL reliability bins: [DATASET_COMPOSITION_AUDIT.json](DATASET_COMPOSITION_AUDIT.json).
