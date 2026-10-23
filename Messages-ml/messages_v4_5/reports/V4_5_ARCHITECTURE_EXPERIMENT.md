# SENTINEL MESSAGES V4.5 — ARCHITECTURE EXPERIMENT REPORT

**Author**: Lead ML/Repository Engineer  
**Date**: September 23, 2026  
**Status**: EXPERIMENT COMPLETED — EVIDENCE-BASED DISPOSITION ASSIGNED  
**Final Disposition**: **`V4.5 REJECTED — RETAIN V4.3`**  
**Active Production Model**: Sentinel V4.3 remains the sole production engine.  

---

## 1. Executive Summary & Purpose

The purpose of the Sentinel V4.5 experiment was to empirically test the following scientific hypothesis:

> *"Contextual/sequential text representations may resolve some of the contextual and lexical ambiguities observed in Candidate-D's V4.4 regression analysis that sparse TF-IDF features do not resolve reliably."*

Per governance guidelines, this hypothesis was **not assumed to be true**. The experiment was designed with strict offline controls capable of falsifying or verifying it.

### Empirical Findings:
1. **Targeted Semantic Probes (Hypothesis Supported Locally)**:
   - On the 7 targeted diagnostic regression suites, contextual representations achieved dramatic improvements:
     - **Greetings**: False positive rate dropped from 12.7% (V4.3) to **0.0%** (V4.5).
     - **Electricity / Utility**: Benign FPR plummeted from 50.9% to **5.5%**, while malicious recall reached **100.0%**.
     - **Institutional Callbacks**: Benign FPR decreased from 40.0% to **3.3%**, with malicious recall improving to **93.3%**.
     - **Counterfactual Semantic Pairs**: Benign FPR dropped from 40.0% to **3.6%** while maintaining 83.6% recall.
     - **System Notifications**: Benign FPR dropped from 50.9% to **0.0%**.
2. **Global Production Benchmarks (Hypothesis Rejected Globally for Frozen Contextual Representations)**:
   - On the primary un-curated benchmarks (`test.jsonl` and `ood.jsonl`), V4.5 suffered a **severe security regression**:
     - **Primary TEST Malicious Recall**: Collapsed from **97.04%** (V4.3) to **77.70%** (V4.5 Ablation C), missing **301 primary malicious records** (307 missed vs 6 recovered).
     - **Primary TEST Benign FPR**: Jumped from **0.38%** (V4.3) to **3.08%** (V4.5).
     - **Clean OOD Recall**: Dropped from **95.72%** to **71.89%**.
3. **Core Mechanism of Regression**:
   - Generic frozen `all-MiniLM-L6-v2` embeddings fail to cleanly separate commercial spam from active malicious smishing.
   - 54.1% of missed malicious records were misclassified as `SUSPICIOUS_SPAM` rather than `MALICIOUS`.
   - The remaining 45.9% were pushed below the decision boundary because validation benign score creep forced the threshold to $\tau=0.8600$ (vs V4.3's $\tau=0.6100$).

---

## 2. Dataset Provenance & Boundary Audit

The primary V4.5 training corpus was strictly isolated to `train_v4_4_b.jsonl` (20,257 rows), completely avoiding the sequential ad-hoc RC2 additions.

| Dataset Component | File Path | SHA-256 Checksum | Row Count | Label Breakdown (B / S / M) |
|:---|:---|:---|:---:|:---:|
| **Training Corpus** | `messages_v4_4/data/train_v4_4_b.jsonl` | `28bdb8c81e538c8a49cd7b56e9da89e5b206bbe2297e12f8b245fcf50c329ab0` | 20,257 | 6,311 / 1,169 / 12,777 |
| **Validation Split** | `data/processed/val.jsonl` | `5c343ef10bc9a1e1e072b22ecf41d927282cb979d35bcfaae3cc0d5bfa53e4c4` | 3,397 | 807 / 274 / 2,316 |
| **Primary TEST** | `data/processed/test.jsonl` | `988ca27e6c283c683b516ad0f531aa7728aa0aa37e8c3b6f00e9efbb1ddda787` | 2,264 | 520 / 188 / 1,556 |
| **Primary OOD** | `data/processed/ood.jsonl` | `34cd57b5252fcc6f5c8ecbe6ad76ffb68c783dbad8c65f80b2d3587e91d575c3` | 1,132 | 255 / 83 / 794 |
| **Clean OOD** | Dynamically filtered from OOD | Zero training normalized overlap | 1,075 | 249 / 79 / 747 |

**Leakage Audit Result**: 0 exact collisions, 0 ID collisions, and 0 case/whitespace collisions between training and any evaluation dataset. Complete audit documented in `messages_v4_5/reports/V4_5_PROVENANCE_AUDIT.md`.

---

## 3. Sequence Length & Truncation Audit

Using the `all-MiniLM-L6-v2` tokenizer without truncation across 27,762 total messages:

| Dataset | Count | Max Tokens | p50 | p90 | p95 | p99 | % Truncated (>128) |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Train (`train_v4_4_b`)** | 20,257 | 536 | 33 | 61 | 78 | 136 | **1.20%** |
| **Validation** | 3,397 | 298 | 35 | 67 | 89 | 154 | **1.88%** |
| **Primary TEST** | 2,264 | 321 | 35 | 67 | 89 | 156 | **1.63%** |
| **Primary OOD** | 1,132 | 300 | 35 | 69 | 89 | 159 | **2.21%** |
| **Targeted Holdouts (All 7)** | 712 | 53 | 24 | 35 | 39 | 44 | **0.00%** |
| **Overall Combined** | 27,762 | 536 | 33 | 62 | 80 | 142 | **1.33%** |

*Conclusion*: Maximum sequence length of 128 preserves 100% of targeted holdout probes and 98.67% of all benchmark messages without truncation.

---

## 4. Frozen Baseline Reproduction Verification

Before training V4.5, frozen baselines were reproduced on the exact benchmark sets:

| Model | Calibrated Threshold ($\tau$) | Validation FPR | Primary TEST Malicious Recall | Clean OOD Recall | Verification Status |
|:---|:---:|:---:|:---:|:---:|:---:|
| **V4.3 Production Baseline** | 0.610 | 1.98% (16/807) | **97.04%** (1510/1556) | 95.72% (715/747) | **EXACT PASS** |
| **V4.4-RC1 / Candidate B** | 0.630 | 1.86% (15/807) | **97.11%** (1511/1556) | 95.85% (716/747) | **EXACT PASS** |
| **RC2-Exp3** | 0.740 | 1.98% (16/807) | **96.02%** (1494/1556) | 95.72% (715/747) | **EXACT PASS** |

Baseline reproduction results saved in `messages_v4_5/reports/baseline_reproduction.json`.

---

## 5. V4.5 Architecture & Required Ablations

Three parallel architectures were evaluated on identical splits:
- **Ablation A (Contextual Only)**: Frozen 384-dimensional `all-MiniLM-L6-v2` dense embeddings $\to$ 3-class classification head (`class_weight='balanced'`).
- **Ablation B (Candidate-D Baseline)**: Sparse TF-IDF word (1-3 ngrams) + char (3-5 ngrams) + 19 structural signals $\to$ HistGradientBoosting (`messages_v4_3/models/candidate_d/`).
- **Ablation C (Contextual + Structural)**: 384-dim MiniLM embeddings + 19 standard-scaled deterministic structural features (403 dims) $\to$ 3-class classification head (`class_weight='balanced'`).

### Threshold Calibration on `val.jsonl` (Target $\text{FPR} \le 2.0\%$):
- **Ablation A**: Selected $\tau = 0.8650$ (Validation FPR = 1.2%, Malicious Recall = 73.0%, Benign p98 = 0.8601)
- **Ablation C**: Selected $\tau = 0.8600$ (Validation FPR = 2.0%, Malicious Recall = 75.5%, Benign p98 = 0.8564)
- *Ablation C (HistGradientBoosting comparison)*: Selected $\tau = 0.9450$ (Benign p98 = 0.9445)

---

## 6. Comprehensive 32-Suite Performance Comparison Table

| Evaluation Suite | Suite Type | Metric | V4.3 Baseline ($\tau=0.61$) | Ablation A (Contextual, $\tau=0.86$) | Ablation C (Hybrid, $\tau=0.86$) |
|:---|:---|:---|:---:|:---:|:---:|
| **Validation Split** | Internal Validation | Benign FPR | 2.0% (16/807) | 1.2% (10/807) | 2.0% (16/807) |
| **Validation Split** | Internal Validation | Malicious Recall | **95.9%** (2222/2316) | 73.0% (1690/2316) | 75.5% (1749/2316) |
| **Primary TEST** | Primary Benchmark | Benign FPR | **0.4%** (2/520) | 2.3% (12/520) | 3.1% (16/520) |
| **Primary TEST** | Primary Benchmark | Malicious Recall | **97.0%** (1510/1556) | 75.5% (1175/1556) | 77.7% (1209/1556) |
| **Primary OOD** | Primary Benchmark | Benign FPR | **0.4%** (1/255) | 0.8% (2/255) | 1.6% (4/255) |
| **Primary OOD** | Primary Benchmark | Malicious Recall | **95.8%** (761/794) | 72.5% (576/794) | 73.4% (583/794) |
| **Clean OOD (Zero Overlap)** | Independent OOD | Benign FPR | **0.4%** (1/249) | 0.8% (2/249) | 1.6% (4/249) |
| **Clean OOD (Zero Overlap)** | Independent OOD | Malicious Recall | **95.7%** (715/747) | 71.1% (531/747) | 71.9% (537/747) |
| **Real Mobile Simulation** | Hardware Field Test | Benign FPR | 4.8% (14/291) | **3.8%** (11/291) | 4.5% (13/291) |
| **Real Mobile Simulation** | Hardware Field Test | Malicious Recall | **100.0%** (3/3) | 0.0% (0/3) | **100.0%** (3/3) |
| `holdout_apk_payload` | Targeted Probe | Benign FPR | 20.0% (6/30) | 40.0% (12/30) | 36.7% (11/30) |
| `holdout_apk_payload` | Targeted Probe | Malicious Recall | **100.0%** (30/30) | 66.7% (20/30) | **100.0%** (30/30) |
| `holdout_conversational` | Targeted Probe | Benign FPR | 5.7% (6/105) | **1.0%** (1/105) | **1.0%** (1/105) |
| `holdout_conversational` | Targeted Probe | Malicious Recall | **64.7%** (66/102) | 27.5% (28/102) | 44.1% (45/102) |
| `holdout_counterfactual` | Targeted Probe | Benign FPR | 40.0% (22/55) | **3.6%** (2/55) | **3.6%** (2/55) |
| `holdout_counterfactual` | Targeted Probe | Malicious Recall | **83.6%** (46/55) | 41.8% (23/55) | **83.6%** (46/55) |
| `holdout_electricity` | Targeted Probe | Benign FPR | 50.9% (28/55) | 12.7% (7/55) | **5.5%** (3/55) |
| `holdout_electricity` | Targeted Probe | Malicious Recall | 54.5% (30/55) | 41.8% (23/55) | **100.0%** (55/55) |
| `holdout_greetings` | Targeted Probe | Benign FPR | 12.7% (7/55) | **0.0%** (0/55) | **0.0%** (0/55) |
| `holdout_greetings` | Targeted Probe | Malicious Recall | **83.6%** (46/55) | 54.5% (30/55) | **83.6%** (46/55) |
| `holdout_institutional` | Targeted Probe | Benign FPR | 40.0% (12/30) | 6.7% (2/30) | **3.3%** (1/30) |
| `holdout_institutional` | Targeted Probe | Malicious Recall | 76.7% (23/30) | 46.7% (14/30) | **93.3%** (28/30) |
| `holdout_notifications` | Targeted Probe | Benign FPR | 50.9% (28/55) | 1.8% (1/55) | **0.0%** (0/55) |

---

## 7. Answers to the 10 Specific Security Interpretation Questions

1. **Does contextual representation improve counterfactual/contextual ambiguity?**
   **YES**. On `holdout_counterfactual_semantic`, benign false positives dropped from 40.0% (V4.3) to 3.6% (V4.5) while matching 83.6% malicious recall. The sequential encoder successfully distinguishes "Never share your OTP" from "Share your OTP".
2. **Does it improve greeting behavior?**
   **YES**. On `holdout_greetings`, false positives dropped from 12.7% to **0.0%**. Single-token greetings ("Hello", "Hi") are correctly classified as BENIGN.
3. **Does it improve legitimate-vs-malicious utility language?**
   **YES**. On `holdout_electricity`, false positives dropped from 50.9% to **5.5%**, while malicious recall reached **100.0%**.
4. **Does it improve institutional/callback phishing?**
   **YES**. On `holdout_institutional_callback`, false positives fell from 40.0% to **3.3%**, and malicious recall improved from 76.7% to **93.3%**.
5. **Does it preserve strong malicious recall?**
   **NO**. On the primary TEST benchmark, malicious recall dropped catastrophically from **97.04% to 77.70%** (-301 missed records). On Clean OOD, recall dropped from **95.72% to 71.89%**.
6. **Does it introduce new BENIGN $\to$ MALICIOUS false positives?**
   **YES**. On primary TEST, benign FPR increased from 0.38% to 3.08%, introducing 15 new false positives on standard conversational messages.
7. **Does it introduce MALICIOUS $\to$ SPAM or MALICIOUS $\to$ BENIGN regressions?**
   **YES, MASSIVELY**. 166 malicious test records were misclassified as `SUSPICIOUS_SPAM` (54.1% of missed records), and 141 were misclassified as `BENIGN` (45.9% of missed records) due to threshold creep.
8. **Does clean OOD support the observed improvement?**
   **NO**. Clean OOD malicious recall dropped by **23.83%** (from 95.72% to 71.89%).
9. **Does the improvement remain when evaluated without the targeted holdouts?**
   **NO**. The improvement is strictly confined to the targeted regression probes. On raw production benchmarks, V4.5 fails decisively.
10. **Does adding deterministic structural features provide measurable additional security value?**
    **YES**. Ablation C (Contextual + Structural) recovered APK payload recall from 66.7% to 100.0% and improved test recall from 75.5% to 77.7% over Ablation A (Contextual Only). Structural signals remain strictly necessary.

---

## 8. Final Disposition

In accordance with Section 15 of the Final Implementation Directive:

### **Disposition**: `V4.5 REJECTED — RETAIN V4.3`

**Rationale**:
While the pretrained contextual representation confirmed the hypothesis on specific semantic slices (counterfactuals, greetings, utilities), the Stage 1 frozen representation introduces a **massive, unacceptable security regression** on primary production benchmarks:
- **-301 primary malicious records missed** (-19.34% recall drop).
- **-178 clean OOD malicious records missed** (-23.83% recall drop).
- **8x increase in benign test false positive rate** (0.38% $\to$ 3.08%).

Therefore:
1. **Sentinel V4.3 remains the sole active production champion.**
2. **Android integration remains pinned exclusively to V4.3.**
3. **No V4.5 artifact will be promoted or deployed.**
4. Stage 2 (end-to-end fine-tuning) is **NOT recommended for immediate deployment** without a domain-adapted smishing backbone capable of preserving broad-spectrum SMS recall.
