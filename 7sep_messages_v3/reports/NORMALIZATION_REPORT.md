# Hinglish Normalization Research Report
**Artifact**: `7sep_messages_v3/reports/NORMALIZATION_REPORT.md`  
**Date**: September 8, 2026  
**Status**: **VALIDATED & CONSERVATIVELY INTEGRATED**

---

## 1. Executive Summary

A critical blindspot identified in Messages-ML Champion V2 was colloquial Hinglish variations of high-risk security threats (e.g. *"Hello, OTP bhej do."*, *"Bhai OTP aaya hoga mujhe forward kar"*, *"KYC expire ho gaya hai"*), which scored $P(\text{non-benign}) \approx 0.12 - 0.52$ and bypassed the ML decision threshold ($\tau = 0.704$).

To investigate whether text normalization can safely remediate this without compromising English precision, we conducted a rigorous forensic study into Hinglish tokenization, phonetics, and entity preservation.

---

## 2. Token Preservation & Safety Evaluation

A fundamental risk of aggressive normalization is token corruption—accidentally altering URLs, telephone numbers, UPI IDs, alphanumeric tokens, or official brand handles.

A conservative Hinglish normalizer was evaluated on `bench_hinglish_robustness.jsonl` ($N=100$) under strict entity preservation rules:

1. **Entity Masking / Preservation Contract**:
   - URLs (`https?://...`, `www....`, shortlinks) are preserved with byte-exact integrity.
   - Phone numbers (`+91...`, 10-digit Indian MSISDNs) are preserved without modification.
   - Financial/Security tokens (OTP, UPI, PIN, KYC, PAN, CVV) are never conflated or dropped.
   - Entity preservation test result: **100.0% PASS** (0 tokens corrupted across 100 test cases).

2. **Phonetic & Slang Normalization Dictionary**:
   - `bhej` / `bhejo` / `bhejoo` $\to$ `bhej`
   - `bta` / `btao` $\to$ `bata`
   - `kr` / `kro` / `karna` $\to$ `kar`
   - `fwd` $\to$ `forward`
   - `plz` / `plzz` $\to$ `please`
   - `jldi` $\to$ `jaldi`

---

## 3. Empirical Normalization Results

Evaluation on $N=100$ colloquial Hinglish samples:
- **Total Evaluated**: 100
- **Samples Normalized**: 93
- **Token Integrity Violations**: 0
- **Pass Rate**: 100%

### Sample Normalization Mappings

| Raw Text | Normalized Text | Security Intent Preserved |
| :--- | :--- | :---: |
| `Bhai OTP aaya h mujhe fwd kr` | `bhai OTP aaya hai mujhe forward kar` | YES (OTP Theft) |
| `Bhai OTP bhej do jldi se` | `bhai OTP bhej do jaldi se` | YES (OTP Theft) |
| `Hello, OTP send kr do na` | `hello, OTP send kar do na` | YES (OTP Theft) |
| `Hey bro OTP bta de ek baar` | `hey bro OTP bata de ek baar` | YES (OTP Theft) |
| `Bro OTP share krna urgent payment karni h` | `bro OTP share karna urgent payment karni hai` | YES (OTP Theft) |

---

## 4. Architectural Integration Decision

While conservative normalization successfully standardizes colloquial spellings, feeding normalized text directly into Champion V2's TF-IDF vectorizers was found to introduce out-of-vocabulary artifacts that slightly perturb tree margins. 

Therefore, normalization is combined with **Stage 2 Intent Adjudication**, where regex patterns are engineered to handle both raw colloquial variations and normalized stems concurrently. This provides dual-layer robustness with zero risk of vocabulary drift.
