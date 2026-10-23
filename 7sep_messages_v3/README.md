# Sentinel-ML: Messages V3 Autonomous Optimization Loop
**Release**: Messages V3 Two-Stage Champion  
**Date**: September 8, 2026  
**Status**: **PRODUCTION READY**

---

## Overview

This directory (`7sep_messages_v3/`) contains the complete, autonomous Messages V3 optimization loop, forensic evaluation, benchmark datasets, and deployment artifacts for Sentinel-ML.

Messages V3 addresses the two primary operational challenges identified on real-device deployments:
1. **The Real-Device "Hello" False Warning**: Caused by an uncalibrated probability mapping in Android's `NotificationThreatAnalyzer.kt`, where $P \ge 0.40$ was hardcoded to `EvidenceSeverity.MEDIUM` with weight $0.95$, triggering a 49/100 YELLOW alert on benign greetings from unknown senders.
2. **The Hinglish Attack Blindspot**: Where colloquial Indian text attacks (e.g. *"Hello, OTP bhej do."*, *"Bhai OTP aaya hoga, mujhe forward kar."*, *"Bijli kat jayegi aaj raat"*) bypassed Champion V2's English-centric TF-IDF features.

---

## Directory Structure

- `data/`: 9 specialized benchmark datasets ($N=649$ total records) constructed for rigorous adversarial and contextual stress testing:
  - `bench_unknown_benign.jsonl` ($N=50$)
  - `bench_unknown_malicious.jsonl` ($N=50$)
  - `bench_hinglish_robustness.jsonl` ($N=100$)
  - `bench_adversarial_semantic_pairs.jsonl` ($N=80$)
  - `bench_system_notifications.jsonl` ($N=45$)
  - `bench_trusted_sender_malicious.jsonl` ($N=40$)
  - `bench_group_context_benign.jsonl` ($N=40$)
  - `bench_group_context_malicious.jsonl` ($N=40$)
  - `bench_sentinel_replay.jsonl` ($N=294$, real-device `sentinel.db` extraction)
- `models/`:
  - `candidate_single_stage/`: Experimental retrained HistGBM model artifacts evaluated as comparison baseline.
- `reports/`:
  - `V2_BASELINE_REPRODUCTION.json`: Exact metrics reproduction of frozen Champion V2 baseline.
  - `TWO_STAGE_EVALUATION.json`: Complete metrics for Two-Stage V3 across all 16 benchmark slices.
  - `SINGLE_STAGE_CANDIDATE_EVALUATION.json`: Complete metrics for Candidate V3-Single.
  - `NORMALIZATION_EVALUATION.json`: Token preservation and normalization audit results.
  - `SENTINEL_DB_REPLAY_V2.json`: Forensic analysis of real-device alerts and replay verification.
  - `NORMALIZATION_REPORT.md`: Hinglish tokenization and phonetic normalization study.
  - `HINGLISH_ROBUSTNESS_REPORT.md`: Comprehensive multilingual robustness benchmark.
  - `SENTINEL_REPLAY_REPORT.md`: Real-device database forensic and replay audit.
  - `UNKNOWN_SENDER_REPORT.md`: Invariant specification and unknown sender analysis.
  - `SYSTEM_NOTIFICATION_REPORT.md`: Dedicated classifier interface and sync alert suppression.
  - `TRUST_CONTEXT_REPORT.md`: User trust modeling and non-bypass security invariants.
  - `GROUP_CONTEXT_REPORT.md`: Multi-party chat context and non-whitelisting invariants.
  - `TRAINING_REPORT.md`: Exploration, hyperparameter optimization, and candidate comparison.
  - `EVALUATION_REPORT.md`: 16-slice benchmark evaluation and release gate matrix.
  - `ANDROID_PARITY_REPORT.md`: Cross-language bit-for-bit parity and test verification.
  - `PERFORMANCE_REPORT.md`: OpenJDK / Android runtime latency and memory benchmarks.
- `DATASET_MANIFEST.json`: Cryptographic SHA256 hashes and record counts for all benchmark datasets.
- `EXPERIMENT_MANIFEST.json`: Complete experiment tracking, software versions, and artifact lineage.
- `FINAL_DECISION.md`: Production gate audit, release scorecard, and deployment recommendations.

---

## Architectural Breakthrough: Two-Stage Contextual Adjudication

```
Incoming Message Notification
            │
            ▼
┌─────────────────────────────────────────────────────────────┐
│ Stage 1: Primary ML Threat Detector (Champion V2, τ = 0.704)│
│ - 70 Deterministic Regex & Linguistic Features              │
│ - 1,500 Word TF-IDF + 500 Char_wb TF-IDF                    │
│ - 309 Binary Decision Trees (HistGradientBoosting)          │
│ Output: P(BENIGN), P(SUSPICIOUS_SPAM), P(MALICIOUS)         │
└─────────────────────────────────────────┬───────────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────────┐
│ Stage 2: Contextual & Intent Adjudicator                    │
│                                                             │
│ [Hard Malicious Escalation]                                 │
│ - OTP Solicitation / Forward Theft                          │
│ - Bank / KYC Deactivation Phishing                          │
│ - Power / Electricity Disconnection Extortion               │
│ - UPI PIN / Collect Request Fraud                           │
│ - APK / Remote Access Malware Download                      │
│ -> Escalate to P = 0.92, Decision = BLOCK                   │
│                                                             │
│ [Benign Conversational & System Dampening]                  │
│ (Active only when P_ML <= 0.75 and No Threat Intent)        │
│ - Standalone Greetings ("Hello", "Hi", "Kaise ho") -> P<=0.05│
│ - Conversational Questions ("OTP kya hota hai?")   -> P<=0.10│
│ - Background Progress (WhatsApp backup, sync)       -> P<=0.05│
│ - Academic / Hackathon Collaboration                -> P<=0.15│
│ - Delivery OTP Legitimate Handover                  -> ALLOW  │
│                                                             │
│ [Context Invariants]                                        │
│ - UNKNOWN Sender: Never creates threat risk alone           │
│ - SAVED / Trusted Sender: NEVER bypasses explicit threats   │
│ - Group Chat: Never whitelists malicious content            │
└─────────────────────────────────────────┬───────────────────┘
                                          │
                                          ▼
                         Final Android Action:
                     ALLOW (GREEN) / BLOCK (RED)
```

---

## Summary of Results

- **"Hello" False Warning**: Fully eliminated on device ($0/100$ GREEN).
- **Hinglish Attack Recall**: Improved from $14.0\%$ (V2) to **$54.0\%$** ($3.85\times$ gain).
- **Electricity Scam Recall**: Improved from $66.7\%$ (V2) to **$100.0\%$**.
- **TEST Malicious Recall**: **$90.36\%$** (exceeds $90.0\%$ gate).
- **TEST Benign FPR**: **$1.92\%$** (zero regression from baseline).
- **Android Inference Latency**: **$0.5275\text{ ms}$** mean ($< 1\text{ ms}$ P95).
- **Cross-Language Parity**: **$100.0\%$ match** ($0$ label mismatches across all test suites).
