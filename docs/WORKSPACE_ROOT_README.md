# Sentinel — Security Intelligence Workspace

Welcome to the **Sentinel** workspace. This repository houses the threat intelligence, machine learning models, runtime components, and architectural documentation for the Sentinel security ecosystem.

---

## 1. Safety Boundaries & Repository Policy

> [!IMPORTANT]
> **Boundary Rule: `sentinel-ai/` is Strictly Off-Limits and Excluded.**
> - Treat the entire `sentinel-ai/` directory as read-only and excluded from generic workspace reorganization, cleanup, scripts, and tooling.
> - Never read, write, rename, move, delete, or stage files inside `sentinel-ai/` during workspace-level maintenance.
> - `sentinel-ai/` contains the production Android application and maintains its own independent Git repository root.

---

## 2. Workspace Directory Map

```text
sentinel/
├── sentinel-ai/                 # [EXCLUDED] Android application & runtime (Git root)
├── sentinel-ml/                  # Machine Learning engineering workspace
│   ├── URL-ml/                   # URL threat classification project (V8 Champion)
│   │   ├── data/                 # Training, validation, and holdout datasets
│   │   ├── docs/                 # URL-ML architectural and technical guides
│   │   ├── experiments/          # Isolated evaluation suites & pre-registered gates
│   │   ├── model/                # Checkpoints and candidate models
│   │   ├── models/               # Frozen production champion models (v8_champion.joblib)
│   │   ├── reports/              # Phase audit reports, forensics, and test summaries
│   │   ├── scripts/              # Feature extraction, model inference, benchmarks, exporters
│   │   ├── tests/                # Automated regression and parity test suites
│   │   └── venv/                 # Project Python 3.11 virtual environment
│   ├── Messages-ml/              # Message / SMS / WhatsApp threat classification (V4/V4.5)
│   │   ├── data/                 # Phishing, smishing, and benign message corpora
│   │   ├── model/                # Model artifacts (champion_model.pkl, scalers, tfidf)
│   │   ├── reports/              # Messages forensic reports and evaluation metrics
│   │   ├── scripts/              # Tokenizers, TF-IDF vectorizers, and training scripts
│   │   └── tests/                # Message classification test suites
│   ├── android-runtime/          # Pure-Kotlin portable ML runtime assets & tools
│   │   ├── golden_test_data/     # Cross-language golden test corpora (golden_urls_v8.json)
│   │   ├── url/assets/           # Portable JSON model bundles (v8_champion_portable.json)
│   │   ├── messages/assets/      # Portable JSON message model assets
│   │   ├── tools/                # Corpus generation and validation tools
│   │   └── reports/              # Runtime parity verification reports
│   ├── 7sep_messages_v3/         # Replay datasets and baseline candidate models
│   ├── 6sep/                     # Historical behavior-driven optimization snapshots
│   ├── investigation/            # SQLite threat database recovery and forensic tools
│   ├── scratch/                  # ML evaluation scripts, ablation studies, test jars
│   ├── archive/                  # Historical model and dataset archives
│   └── New_history/              # Device replay message history logs
├── docs/                         # Workspace-level architectural and design documentation
├── reports/                      # Workspace-level audit, status, and verification reports
├── research/                     # Technical research notes, threat methodologies, planning
└── tools/                        # Shared workspace verification and auditing utilities
```

---

## 3. Projects Overview

### 3.1 URL Threat Classification (`sentinel-ml/URL-ml`)
- **Champion Model:** V8 Relational URL Classifier (`v8_champion.joblib`, SHA-256: `073e70f2...`).
- **Feature Vector:** Deterministic 67-dimensional lexical and structural representation (`V7_FEATURE_NAMES`).
- **Runtime:** Portable JSON bundle (`v8_champion_portable.json`, 350 HistGBM trees).
- **Adjudication Layer:** Deterministic security invariants enforcing zero route-shape suppression, brand typosquatting defense, malware download overrides, and locked safe-brand policies.

### 3.2 Message Threat Classification (`sentinel-ml/Messages-ml`)
- **Champion Model:** Messages V4 / V4.5 Dual TF-IDF + ExtraTrees Classifier (`champion_model.pkl`, `champion_v2_model.pkl`).
- **Feature Pipeline:** Word and character n-gram TF-IDF vectorization with sender profile classification.
- **Scope:** Real-time SMS, WhatsApp, and notification smishing / credential-harvesting defense.

### 3.3 Portable Android Runtime (`sentinel-ml/android-runtime`)
- **Architecture:** Zero external ML dependency, pure Kotlin tree traversal engine (`HistGbmTreeEvaluator`).
- **Assets:** Synchronized JSON models for offline, zero-network, sub-millisecond on-device inference.
- **Verification:** Golden corpus parity suites ensuring $< 10^{-4}$ mathematical parity against Python reference models.

---

## 4. Key References & Documentation Links

- **Workspace Architecture:** [`docs/WORKSPACE_ARCHITECTURE.md`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/docs/WORKSPACE_ARCHITECTURE.md)
- **Organization Audit Report:** [`reports/WORKSPACE_ORGANIZATION_REPORT.md`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/reports/WORKSPACE_ORGANIZATION_REPORT.md)
- **URL-ML Documentation:** [`sentinel-ml/URL-ml/docs/README.md`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/docs/README.md)
- **URL-ML Phase 1A Final Audit:** [`sentinel-ml/URL-ml/reports/PHASE_1A_PYTHON_KOTLIN_PARITY_FINAL_AUDIT.md`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/reports/PHASE_1A_PYTHON_KOTLIN_PARITY_FINAL_AUDIT.md)
- **V8 Promotion Gate Report:** [`sentinel-ml/URL-ml/V8_PROMOTION_GATE_REPORT.md`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/V8_PROMOTION_GATE_REPORT.md)
