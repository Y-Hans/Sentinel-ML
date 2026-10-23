# Sentinel — Phase 1 Evidence and Requirements Master Matrix

**Date:** 2026-10-21  
**Document Identifier:** `PHASE_1_EVIDENCE_AND_REQUIREMENTS_MATRIX.md`  
**Governing Standard:** `SENTINEL_MASTER_PLAN.md` Version `3.1.0-EVIDENCE-FIRST-CALIBRATED`  
**Classification:** LIVING PHASE 1 EXECUTION AND COMPLIANCE AUDIT LEDGER  

---

## 1. Phase 1 Master Requirements Inventory

| Req ID | Sub-Phase | Requirement Title | Target Files | Primary Verification Test | Acceptance Criterion | Dependencies | Current Status |
| :---: | :---: | :--- | :--- | :--- | :--- | :--- | :---: |
| **REQ-00** | Preflight | **Evidence & URL-ML Reconciliation** | All Phase 1D reports, `phase_1_reconciliation_ledger.json` | Python forensic checksum and mask audit | Reconcile Gate 5 recall ($4,170$ vs $4,248$), benign denominator ($42,941$), benchmark FPR ($84\%$), and live disk hashes. | None | **VERIFIED COMPLETE** |
| **REQ-1A** | Phase 1A | **Unified Schemeless URL Canonicalization** | `NotificationEventBuilder.kt`, `UrlFeatureExtractor.kt`, `v8_features.py` | `UrlCanonicalizationTest.kt`, `UrlParityTest.kt`, python parity test | Standardize missing-scheme handling across Kotlin & Python. Do not blindly prepend `https://`; distinguish missing scheme from explicit HTTP/HTTPS; preserve feature dimensionality (67 features) and frozen model. | REQ-00 | **READY FOR IMPLEMENTATION** |
| **REQ-1B** | Phase 1B | **Calibrated Safe-Brand Escalation Policy** | `NotificationThreatAnalyzer.kt`, `WhatsAppModels.kt` | `NotificationThreatAnalyzerTest.kt` | Suppress `CRITICAL` escalation ONLY when `isSafeBrandGated == true && hasThreat == false`. Active attack payloads (.apk, cred harvest, open redirect) MUST always escalate regardless of domain reputation. | REQ-1A | **PENDING 1A** |
| **REQ-1C** | Phase 1C | **WhatsApp Group Context & Security Invariants** | `NotificationParser.kt`, `NotificationAgentCoordinator.kt`, `RiskFusionModels.kt`, `RiskFusionEngine.kt` | `RiskFusionEngineTest.kt`, WhatsApp coordination tests | Propagate group context without creating a whitelist (`GROUP != WHITELIST`). Invariant: `PAYLOAD OVERRIDES CONTEXT` (`urlSeverity >= HIGH` is never suppressed by group context or friendly message text). | REQ-1B | **PENDING 1B** |
| **REQ-1D** | Phase 1D | **Integration & Full Regression Gate** | Android Gradle test suites (`:agents`, `:core`) | `gradlew.bat :agents:testDebugUnitTest`, `gradlew.bat :core:testDebugUnitTest` | Both Gradle test suites pass cleanly. All 12 end-to-end matrix scenarios pass. Zero regressions against frozen baselines. 90 porcelain lines preserved. | REQ-1A, 1B, 1C | **PENDING 1C** |
| **REQ-CL** | Closure | **Phase 1 Closure & Phase 2 Handoff Package** | Closure reports, evidence ledger, Git audit | Full repository integrity audit | Complete Phase 1 closure package with zero manufactured passes. Phase 2 remains unexecuted. | REQ-1D | **PENDING 1D** |

---

## 2. Live Task Progress & Status Ledger

```
════════════════════════════════════════════════════════════════════════════════
                        PHASE 1 PROGRESS CHECKLIST
════════════════════════════════════════════════════════════════════════════════
 [X] Step 0: Baseline Git & Workspace Audit (90 porcelain lines recorded)
 [X] Step 2: Phase 1 Preflight & Reconciliation Audit
     [X] 2.1 Master Plan Audit & Inventory
     [X] 2.2 Reconcile Phase 1D URL-ML Reports
     [X] 2.3 Mandatory Issue A: Gate 5 Recall Discrepancy Resolved (4170 vs 4248)
     [X] 2.3 Mandatory Issue B: Benign Denominator Resolved (42,941 URLs)
     [X] 2.3 Mandatory Issue C: Benchmark FPR Reconciled (84.00% vs 60.80%)
     [X] 2.3 Mandatory Issue D: Checksum Ledger Generated (22 items verified)
     [X] 2.3 Mandatory Issue E: Gate Policy Standardized (3-tier policy)
     [X] 2.4 Deliverables Generated: Ledger JSON & Reconciliation Report
 [ ] Step 3: Phase 1A — Unified Schemeless URL Canonicalization
     [ ] State A: Read-Only Investigation of Extraction & Parsing
     [ ] State B: Canonicalization Contract Formulation
     [ ] State C: Isolated Code Edits (Kotlin & Python parity)
     [ ] State D: Immediate Verification & Test Execution
     [ ] State E: Sub-Phase 1A Acceptance & Report
 [ ] Step 4: Phase 1B — Calibrated Safe-Brand Escalation Policy
     [ ] State A: Read-Only Investigation of Threat Analyzer & Severity
     [ ] State B: Policy Contract Verification
     [ ] State C: Isolated Code Edits
     [ ] State D: Immediate Verification (Dual Cases: Clean Brand vs Payload)
     [ ] State E: Sub-Phase 1B Acceptance & Report
 [ ] Step 5: Phase 1C — WhatsApp Group Context and Security Invariants
     [ ] State A: Read-Only Investigation of Parser & Fusion Context
     [ ] State B: Invariant Verification Pre-Gate
     [ ] State C: Isolated Code Edits
     [ ] State D: Immediate Verification (5 Security Invariants)
     [ ] State E: Sub-Phase 1C Acceptance & Report
 [ ] Step 6: Phase 1D — Integration Gate & Full Regression Suite
     [ ] Run :agents:testDebugUnitTest
     [ ] Run :core:testDebugUnitTest
     [ ] Verify End-to-End Decision Matrix
     [ ] Sub-Phase 1D Acceptance & Report
 [ ] Step 7: Phase 1 Closure & Phase 2 Handoff Package
════════════════════════════════════════════════════════════════════════════════
```
